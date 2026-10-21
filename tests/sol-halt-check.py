#!/usr/bin/env python3
"""Check halt and its shared-wrapper siblings behind a closed libc boundary.

No compilation; requires the separately built shell and boundary.so. All
invocations preload the interceptor, including help and parser error checks.
"""
import argparse
import errno
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def environment(shim, asan=None):
    env = dict(os.environ, LC_ALL='C', PATH='')
    env.pop('BASH_ENV', None)
    env.pop('ENV', None)
    env['LD_PRELOAD'] = (str(asan) + ':' if asan else '') + str(shim)
    if asan:
        env.update(ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def preload_guard(*libraries):
    """Shell prefix that exits 93 before enable or any builtin runs unless the
    dynamic loader mapped every library at startup. ld.so ignores an object it
    cannot preload and continues, and enable -f would still load the fixture
    privately, leaving reboot/sync bound to libc; this guard fails closed."""
    code = "read -r -d '' maps < /proc/$$/maps\n"
    for library in map(str, libraries):
        if not library.startswith('/') or any(c in library for c in ': \t\n'):
            raise ValueError(f'LD_PRELOAD cannot carry this path verbatim: {library!r}')
        mapped = os.path.realpath(library)  # /proc maps names the resolved file
        code += f"[[ $maps$'\\n' == *' '{shlex.quote(mapped)}$'\\n'* ]] || exit 93\n"
    return code


def setup(shim, modules=None):
    asan = Path((modules / 'asan-path.txt').read_text().strip()) if modules else None
    code = preload_guard(*([asan] if asan else []), shim)
    code += f'enable -f {shlex.quote(str(shim))} halt_fixture || exit 90\n'
    if modules:
        for name in ('halt', 'reboot', 'poweroff'):
            code += f'enable -f {shlex.quote(str(modules / (name + "-sanitize.so")))} {name} || exit 91\n'
    return code + 'PATH=\nhalt_fixture reset\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--shim', type=Path, required=True)
    p.add_argument('--sanitize-dir', type=Path)
    a = p.parse_args()
    binary, shim = a.binary.resolve(), a.shim.resolve()
    modules = a.sanitize_dir.resolve() if a.sanitize_dir else None
    asan = Path((modules / 'asan-path.txt').read_text().strip()) if modules else None
    env, prefix = environment(shim, asan), setup(shim, modules)
    failures, count = [], 0

    def check(label, body, stdout, diagnostic=None):
        nonlocal count
        count += 1
        r = subprocess.run([str(binary), '--noprofile', '--norc', '-c', prefix + body],
                           env=env, capture_output=True, text=True, timeout=30)
        ok = (r.returncode == 0 and (stdout(r.stdout) if callable(stdout) else r.stdout == stdout) and
              (diagnostic in r.stderr if diagnostic else not r.stderr) and
              'AddressSanitizer' not in r.stderr and 'runtime error:' not in r.stderr)
        print(('PASS ' if ok else 'FAIL ') + label)
        if not ok:
            failures.append(label)
            print(f'  exit={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r} expected={stdout!r}')

    empty = 'sync=0 reboot=0 accounting=0 cmd=none order=\n'
    for name, cmd in [('halt', 'RB_HALT_SYSTEM'), ('reboot', 'RB_AUTOBOOT'), ('poweroff', 'RB_POWER_OFF')]:
        for opts in ('', '--', '-f', '-ff', '-f --'):
            synced = int('f' not in opts)
            trace = f'sync={synced} reboot=1 accounting=0 cmd={cmd} order={"S" if synced else ""}R\n'
            check(f'{name} {opts!r} success and request',
                  f'{name} {opts}; printf "status=%s\\n" "$?"; halt_fixture report', 'status=0\n' + trace)
        for opts in ('-n', '-fn', '-nf', '-n -f', '-nn', '-n --'):
            check(f'{name} {opts} dry run',
                  f'{name} {opts}; printf "status=%s\\n" "$?"; halt_fixture report',
                  f'{name}: would {name} (dry run)\nstatus=0\n' + empty)
        for opts in ('-x', '-w', '-d', '--bad', 'operand', '-- operand', '-n operand', '-f operand', '-n --bad', '-f -x', '-'):
            check(f'{name} rejects {opts}',
                  f'{name} {opts}; printf "status=%s\\n" "$?"; halt_fixture report',
                  'status=2\n' + empty, 'usage:')
        # Keep help output independent of its layout; assert identifying content and status.
        check(f'{name} help no mutation',
              f'{name} --help; printf "status=%s\\n" "$?"; '
              f'help {name} > /dev/null; printf "help=%s\\n" "$?"; halt_fixture report',
              lambda out: 'dry run' in out and 'skip sync' in out and
              out.endswith('status=2\nhelp=0\n' + empty))
        for err in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.EIO, errno.ENOSYS):
            for opts in ('', '-f'):
                synced = int(not opts)
                trace = f'sync={synced} reboot=1 accounting=0 cmd={cmd} order={"S" if synced else ""}R\n'
                check(f'{name} {opts} errno {err}',
                      f'halt_fixture errno {err}; {name} {opts}; printf "status=%s\\n" "$?"; halt_fixture report',
                      'status=1\n' + trace, os.strerror(err))
        check(f'{name} dry output failure and recovery',
              f'{name} -n > /dev/full; printf "status=%s\\n" "$?"; '
              f'{name} -n; printf "status=%s\\n" "$?"; halt_fixture report',
              f'status=1\n{name}: would {name} (dry run)\nstatus=0\n' + empty, 'write error')
        check(f'{name} closed stdout and recovery',
              f'{name} -n >&-; printf "status=%s\\n" "$?"; {name} -n; halt_fixture report',
              f'status=1\n{name}: would {name} (dry run)\n' + empty, 'write error')
        check(f'{name} persistent shell state and descriptors',
              f'''set -- first 'two words'; keep=value; export EXPORTED=sentinel
trap ':' USR1
umask 027
before_pwd=$PWD; before_options=$-; before_umask=$(umask); before_trap=$(trap -p USR1)
before_fds=(/proc/$$/fd/*)
exec 9<<<payload
for ((i=0;i<200;i++)); do
  halt_fixture reset
  {name} -n >/dev/null || exit 11
  {name} -x 2>/dev/null; [[ $? == 2 ]] || exit 12
  halt_fixture errno 1
  {name} -f 2>/dev/null; [[ $? == 1 ]] || exit 13
  halt_fixture reset
  {name} || exit 14
done
IFS= read -r -u 9 payload; [[ $payload == payload ]] || exit 15
exec 9<&-
after_fds=(/proc/$$/fd/*)
[[ $PWD == "$before_pwd" && $- == "$before_options" && $(umask) == "$before_umask" && $(trap -p USR1) == "$before_trap" && $keep == value && $EXPORTED == sentinel && $1 == first && $2 == 'two words' && $# == 2 && ${{#before_fds[@]}} == ${{#after_fds[@]}} ]] || exit 16
getopts a option -a; [[ $option == a ]] || exit 17
printf 'state preserved\\n'
halt_fixture report''',
              f'state preserved\nsync=1 reboot=1 accounting=0 cmd={cmd} order=SR\n')
    print(f'{count - len(failures)}/{count} passed')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
