#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare bashpython with the CPython it embeds and check the surrounding Bash.

Usage: python3 tests/bashpython.py [BINARY] [--reference PYTHON] [--module SO]
BINARY is a bash with bashpython compiled in (default out/bash-python), or,
with --module, any dynamic bash that loads SO with enable -f. The module is
installed into a temporary root beside the standard library, so it has to
find its home from its own location. PYTHON (default: the prefix's
bin/python3.X) is the standalone build of the same CPython.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('binary', nargs='?', type=Path, default=ROOT/'out/bash-python')
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--module', type=Path)
    parser.add_argument('--python-prefix', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    command = ['python3', str(ROOT/'config/build-python.py'), '--flags']
    if args.python_prefix:
        command += ['--prefix', str(args.python_prefix.resolve())]
    record = json.loads(subprocess.check_output(command, text=True))
    prefix = Path(record['flags']['home'])
    version = '.'.join(record['identity']['package']['version'].split('.')[:2])
    reference = (args.reference or prefix/'bin'/f'python{version}').resolve()
    modules = set(record['config']['modules'])
    env = {k: v for k, v in os.environ.items()
           if not k.startswith('PYTHON') and k not in ('BASH_ENV', 'ENV')}
    env.update(PATH='', LC_ALL='C.UTF-8')
    checks = 0
    with tempfile.TemporaryDirectory(prefix='bashpython-') as directory:
        work = Path(directory)
        prefix_script = ''
        if args.module:
            lib = work/'root/usr/lib/bash-os'
            (lib/'loadables').mkdir(parents=True)
            (lib/'share').mkdir()
            shutil.copy2(args.module.resolve(), lib/'loadables/bashpython.so')
            (lib/'share/bashpython').symlink_to(record['data']['root'] + '/share/bashpython')
            prefix_script = f'enable -f {shlex.quote(str(lib/"loadables/bashpython.so"))} bashpython || exit\n'

        def shell(script, data=b'', extra=None, timeout=60):
            return subprocess.run([str(binary), '--noprofile', '--norc', '-c', prefix_script+script,
                                   'bashpython-test'], input=data, capture_output=True, cwd=work,
                                  env={**env, **(extra or {})}, timeout=timeout)

        def check(script, output=b'', status=0, **kwargs):
            nonlocal checks
            p = shell(script, **kwargs)
            assert (p.returncode, p.stdout) == (status, output), (script, p)
            checks += 1

        def parity(arguments, data=b'', stderr=False, extra=None):
            nonlocal checks
            expected = subprocess.run([str(reference), *arguments], input=data, capture_output=True,
                                      cwd=work, env={**env, **(extra or {})}, timeout=60)
            actual = shell('bashpython '+shlex.join(arguments), data=data, extra=extra)
            assert (actual.returncode, actual.stdout) == (expected.returncode, expected.stdout), (
                arguments, actual, expected)
            if stderr:
                assert actual.stderr == expected.stderr, (arguments, actual.stderr, expected.stderr)
            checks += 1

        check('type -t bashpython', b'builtin\n')
        (work/'script.py').write_text('import sys\nprint(__name__, sys.argv[1:])\nsys.exit(len(sys.argv) - 1)\n')
        (work/'data.json').write_text('{"b": [1, 2], "a": "x"}')
        imports = ['json', 'zlib', 'bz2', 'lzma', 'sqlite3', 'decimal', 'hashlib', 'csv', 'datetime',
                   'pathlib', 'subprocess', 'asyncio', 'xml.etree.ElementTree', 'unicodedata', 'socket']
        for name, module in (('_ctypes', 'ctypes'), ('_ssl', 'ssl'), ('_uuid', 'uuid')):
            if name in modules:
                imports.append(module)
        cases = [
            (['-c', 'print(6 * 7)'], b''),
            (['-c', 'import sys; print(sys.argv)', 'an argument', '--flag'], b''),
            (['-c', 'import ' + ', '.join(imports) + '; print("imports")'], b''),
            (['-c', 'import zlib, bz2, lzma; d = b"abc" * 1000; '
                    'print(all(m.decompress(m.compress(d)) == d for m in (zlib, bz2, lzma)))'], b''),
            (['-c', 'import sqlite3; c = sqlite3.connect(":memory:"); '
                    'print(c.execute("select sqlite_version() >= \'3\', 6 * 7").fetchone())'], b''),
            (['-c', 'import decimal, hashlib; print(decimal.Decimal(1) / 7, '
                    'hashlib.sha256(b"abc").hexdigest(), hashlib.sha3_256(b"").hexdigest()[:8])'], b''),
            (['-c', 'import sys; print(sys.stdin.read().upper(), end="")'], b'standard input\n'),
            (['-m', 'json.tool', 'data.json'], b''),
            (['-m', 'json.tool'], b'{"z": null, "y": [true]}'),
            (['script.py', 'one', 'two'], b''),
            (['-'], b'print("program from standard input")\n'),
            ([], b'import sys\nprint("no arguments", sys.argv)\n'),
            (['-I', '-c', 'import sys; print(sys.flags.isolated, sys.flags.ignore_environment)'], b''),
            (['-c', 'raise SystemExit(7)'], b''),
            (['-c', 'import sys; sys.exit("failure message")'], b''),
            (['-c', 'import os; os._exit(3)'], b''),
            (['-V'], b''),
        ]
        if '_ctypes' in modules:
            cases.append((['-c', 'import ctypes; print(ctypes.c_int(41).value + 1)'], b''))
        if '_ssl' in modules:
            cases.append((['-c', 'import ssl; print(ssl.create_default_context().verify_mode)'], b''))
        for arguments, data in cases:
            parity(arguments, data)
        parity(['-c', '1 / 0'], stderr=True)
        parity(['-c', 'import sys; sys.exit("failure message")'], stderr=True)
        parity(['-c', 'import os; print(os.environ.get("BPY_EXPORTED"))'], extra={'BPY_EXPORTED': 'visible'})

        # The shell's state: variables, cwd and environment stay as they were.
        check('BPY_UNEXPORTED=1; export BPY_EXPORTED=1; '
              'bashpython -c \'import os; print("BPY_UNEXPORTED" in os.environ, os.environ["BPY_EXPORTED"])\'',
              b'False 1\n')
        check('export BPY_VALUE=shell; bashpython -c \'import os; os.environ["BPY_VALUE"] = "python"; '
              'os.putenv("BPY_OTHER", "1"); os.unsetenv("HOME"); print(os.getenv("BPY_VALUE"))\'; '
              'echo "$BPY_VALUE ${BPY_OTHER-unset}"', b'python\nshell unset\n')
        check('umask 022; bashpython -c \'import os; os.chdir("/"); os.umask(0o077)\'; '
              'd=$PWD; builtin cd .; [[ $PWD == "$d" && $(umask) == 0022 ]] && echo same', b'same\n')
        check('bashpython -c \'import os; print(os.getppid())\' > ppid; read -r p < ppid; '
              '[[ $p == "$$" ]] && echo parent', b'parent\n')
        check('for i in 1 2 3 4 5 6 7 8; do bashpython -c "import sys; sys.exit($i)"; s+=$?,; done; echo $s',
              b'1,2,3,4,5,6,7,8,\n')
        check('bashpython -c \'print("redirected")\' > out; read -r line < out; echo "$line"', b'redirected\n')
        check('x=$(bashpython -c \'print("substituted")\'); echo "$x"', b'substituted\n')

        # Interrupts, compared with the standalone build run as a command.
        def interrupt(program):
            p = subprocess.Popen([str(binary), '--noprofile', '--norc', '-c',
                                  prefix_script + program + '\necho "after $?"', 'bashpython-test'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work, env=env,
                                 start_new_session=True)
            ready = p.stdout.readline()
            assert ready == b'ready\n', (program, ready, p.stderr.read())
            os.killpg(p.pid, signal.SIGINT)
            out, err = p.communicate(timeout=30)
            return p.returncode, out, b'KeyboardInterrupt' in err

        sleeper = 'import time; print("ready", flush=True); time.sleep(30)'
        handled = ('import sys, time\ntry:\n    print("ready", flush=True); time.sleep(30)\n'
                   'except KeyboardInterrupt:\n    print("caught"); sys.exit(3)\n')
        for program in (sleeper, handled):
            ours = interrupt('bashpython -c ' + shlex.quote(program))
            theirs = interrupt(shlex.quote(str(reference)) + ' -c ' + shlex.quote(program))
            assert ours == theirs, (program, ours, theirs)
            checks += 1
    print(f'bashpython: {checks} checks passed ({reference.name}, {"module" if args.module else binary.name})')


if __name__ == '__main__':
    main()
