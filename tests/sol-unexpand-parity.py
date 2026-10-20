#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact GNU byte comparisons, stream continuity and persistent-shell checks."""
import os
from itertools import product
from pathlib import Path
import pty
import random
import select
import subprocess
import sys
import tempfile
import termios

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = dict(os.environ, LC_ALL='C', PATH='')
prefix = '''if [[ -n ${UNEXPAND_MODULE:-} ]]; then
 enable -f "$UNEXPAND_MODULE" unexpand || exit
fi
[[ $(type -t unexpand) == builtin ]] || exit 99
'''
if env.get('UNEXPAND_PRELOAD'):
    env.update(LD_PRELOAD=env['UNEXPAND_PRELOAD'],
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
checks = 0
failures = []


def shell(script, args=(), data=b''):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        '_', *map(str, args)], input=data, capture_output=True,
                       env=env, timeout=20)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def compare(args=(), data=b'', file=False):
    global checks
    if file:
        fixture.write_bytes(data)
        args = [*args, fixture]
        data = b''
    want = subprocess.run(['/usr/bin/unexpand', *map(str, args)], input=data,
                          capture_output=True, env={'LC_ALL': 'C'}, timeout=20)
    got = shell('unexpand "$@"', args, data)
    checks += 1
    if (got.returncode, got.stdout) != (want.returncode, want.stdout):
        failures.append((list(map(str, args)), len(data), got.returncode,
                         want.returncode, got.stdout[:50].hex(), want.stdout[:50].hex()))
        if len(failures) <= 20:
            print('FAIL', failures[-1], flush=True)
    elif want.returncode:
        assert got.stderr, args
    else:
        assert not got.stderr, (args, got.stderr)


with tempfile.TemporaryDirectory(prefix='sol-unexpand-') as d:
    root = Path(d)
    fixture, first, second, empty = [root / s for s in ('fixture', 'first', 'second', 'empty')]
    empty.write_bytes(b'')
    rng = random.Random(20261019)
    data = [b'', b'x', b' ', b'\t', b'\n\n', b'        lead    mid        tail   ',
            b'1234567  X  \tY\n', b'      \b  X\n\b\b  \tY\n',
            b'a\r        b\v        c\f        d\n',
            bytes(range(256)) * 3, b' \0       \xff   \tend',
            b' ' * 300000 + b'X' * 300000 + b'        end',
            bytes(rng.choice(b'ab \t\n\b\r\0\xff') for _ in range(6000))]
    data.append(b'\n'.join(bytes(seq) for n in range(6)
                            for seq in product(b'x \t\b', repeat=n)))
    data += [b'X' * n + b'  \t\0\b        \n        end'
             for n in (4095, 4096, 4097, 65535, 65536, 65537)]
    opts = [[], ['-a'], ['--first-only'], ['-t1'], ['-t3'], ['-t8'],
            ['-t', '3,7,12'], ['-t', '3,7,/8'], ['-t', '3,7,+8'],
            ['--first-only', '-a'], ['--first-only', '-t4']]
    for opt, blob, wanted in [([], b'        X        Y\n', b'\tX        Y\n'),
                              (['-a'], b'1234567  ', b'1234567\t '),
                              (['-t4'], b'    X   Y\n', b'\tX\tY\n')]:
        result = shell('unexpand "$@"', opt, blob)
        assert result.returncode == 0 and result.stdout == wanted, result
        checks += 1
    for blob in data:
        for opt in opts:
            for file in (False, True):
                compare(opt, blob, file)
    for opt in [['--all'], ['-aa'], ['-at4'], ['-at', '4'], ['-4'],
                ['-4', '-8'], ['-48'], ['-t4', '-8'], ['-4', '-a', '-8'],
                ['-4,8'], ['-4a'], ['-a4'],
                ['--tabs', '4'], ['--tabs=4'], ['--tabs='], ['-t', ',,'],
                ['-t', ', 4, 9, +8'], ['-t', '4 9 /8'], ['-t', '/8'],
                ['-t', '+8'], ['-t4', '-t8'], ['-t3,7', '-t12'], ['-t', '8,'], ['-t', '8 '], ['-t', '3,/0'],
                ['-t', '3,+0'], ['-t', '2147483647'],
                ['-a', '--first-only', '-a'], ['--first-only', '-t', '4', '-a']]:
        compare(opt, b'        A        B\b        C\n        last')
    compare(['-t', ','.join(map(str, range(1, 65)))], b' ' * 100)
    for width in ('65537', '2147483647'):
        for file in (False, True):
            compare(['-t', width], b' ' * 200000 + b'\0end', file)
    for a, b in [(b'   ', b'     X'), (b'abc', b'        X\n'),
                 (b'abc\b', b'\b        X'), (b'abc\n', b'        X')]:
        first.write_bytes(a)
        second.write_bytes(b)
        for opt in ([], ['-a'], ['-t', '3,7,+8']):
            compare([*opt, first, empty, second])
            compare([*opt, first, '-', empty, second, '-'], b'        stdin')
    second.write_bytes(b'        valid        file\n')
    for args in ([root / 'missing'], [root], [root / 'missing', second],
                 [first, root, second], ['-', root / 'missing', second]):
        compare(args, b'        stdin')
    dash = root / '-file'
    dash.write_bytes(b'        X\n')
    compare(['--', dash])
    for opt in [['-t'], ['--tabs'], ['--bogus'], ['-t', '0'], ['-t', '-1'],
                ['-t', '3,2'], ['-t', '3,3'], ['-t', 'x'], ['-t', '3x4'],
                ['-t', '3+4'], ['-t', '3/4'], ['-4', '-t8'],
                ['-99999999999999999999999999999'],
                ['-t', '3,/8,12'], ['-t', '3,+8,/4'],
                ['-t', '99999999999999999999999999999999999']]:
        got = shell('unexpand "$@"', opt)
        assert got.returncode == 2 and got.stderr and not got.stdout, (opt, got)
        checks += 1
    # Deliberate bounds shared with expand: 64 stops and INT_MAX tab widths.
    for spec in ['2147483648', '3,/2147483648', ','.join(map(str, range(1, 66)))]:
        got = shell('unexpand -t "$1"', [spec])
        assert got.returncode == 2 and got.stderr, (spec, got)
        checks += 1
    first.write_bytes(b'alpha   beta    gamma\n' * 5000 + b'\0        end')
    wanted = subprocess.check_output(['/usr/bin/unexpand', '-a', str(first)])
    p = shell('for ((i=0;i<12;i++)); do unexpand -a < "$1" || exit; done', [first])
    assert p.returncode == 0 and p.stdout == wanted * 12, p
    checks += 1
    p = shell('IFS= read -r line; unexpand -a; :', data=b'skip\n        X\n')
    assert p.returncode == 0 and p.stdout == b'\tX\n', p
    checks += 1
    p = shell('''
printf before
unexpand -t0 2>/dev/null && exit 10
unexpand <&- 2>/dev/null; [[ $? == 1 ]] || exit 11
unexpand < "$2" || exit 12
unexpand -a < "$1" || exit 13
printf after
''', [first, empty])
    assert p.returncode == 0 and p.stdout == b'before' + wanted + b'after', p
    checks += 1
    p = shell('unexpand -a \"$1\" \"$2\" >/dev/full 2>\"$3\"; [[ $? == 1 ]]',
              [first, root / 'must-not-open', root / 'write-error'])
    errors = (root / 'write-error').read_bytes()
    assert p.returncode == 0 and b'write error' in errors and b'must-not-open' not in errors, p
    checks += 1
    for file in (first, second):
        p = shell('''
unexpand -a < "$1" >/dev/full 2>/dev/null; [[ $? == 1 ]] || exit 10
unexpand -a < "$1" >&- 2>/dev/null; [[ $? == 1 ]] || exit 11
unexpand -a < "$2" || exit 12
''', [file, first])
        assert p.returncode == 0 and p.stdout == wanted, p
        checks += 1
    r, w = os.pipe()
    os.close(r)
    try:
        p = subprocess.run([binary, '-c', prefix + '''trap '' PIPE
unexpand -a "$1" 2>/dev/null; [[ $? == 1 ]]
''', '_', str(first)], stdout=w, stderr=subprocess.PIPE, env=env, timeout=20)
        assert p.returncode == 0, p
        checks += 1
    finally:
        os.close(w)
    p = shell('''
old_pwd=$PWD; old_ifs=$IFS; old_umask=$(umask); old_options=$-
trap ':' USR1; old_trap=$(trap -p USR1)
before=(/proc/$$/fd/*)
for ((i=0;i<100;i++)); do
 unexpand --first-only -t3,7,+8 "$1" - "$2" </dev/null >/dev/null || exit 10
done
after=(/proc/$$/fd/*)
[[ ${before[*]} == "${after[*]}" && $PWD == "$old_pwd" && $IFS == "$old_ifs" &&
   $(umask) == "$old_umask" && $- == "$old_options" && $(trap -p USR1) == "$old_trap" ]]
''', [first, second])
    assert p.returncode == 0, p
    checks += 1
    # Reserving an input wrapper must not reopen a closed standard output,
    # even when fd 0 was explicitly opened for both reading and writing.
    rw = root / 'read-write-input'
    original = b'        X\n'
    rw.write_bytes(original)
    p = shell('unexpand -a 0<> "$1" >&- 2>/dev/null; [[ $? == 1 ]]', [rw])
    assert p.returncode == 0 and rw.read_bytes() == original, (p, rw.read_bytes())
    checks += 1
    # A failed pipe input must not leave stdio read-ahead attached to fd 0
    # when Bash redirects that descriptor to a new file on the next call.
    recovered = subprocess.check_output(['/usr/bin/unexpand', '-a', str(second)]) * 2
    for data in (b'A' * 100000, b' ' * 131072 + b'\n', b'abc   ' * 20000 + b'\n'):
        p = shell('''
trap '' PIPE
unexpand -a >/dev/full 2>/dev/null; [[ $? == 1 ]] || exit 10
unexpand -a < "$1" || exit 11
unexpand -a < "$1" || exit 12
''', [second], data)
        assert p.returncode == 0 and p.stdout == recovered and not p.stderr, (
            len(data), p.returncode, p.stdout[:100], p.stderr)
        checks += 1
    # Keep input open after enough blanks to fill a stdio output buffer.
    # A block-read/output strategy must still stop on the write failure.
    for implementation in ('builtin', 'GNU'):
        command = ([binary, '-c', prefix + 'unexpand -a'] if implementation == 'builtin'
                   else ['/usr/bin/unexpand', '-a'])
        with open('/dev/full', 'wb') as full:
            with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=full,
                                  stderr=subprocess.PIPE, env=env) as proc:
                try:
                    proc.stdin.write(b' ' * 131072 + b'\n')
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
                try:
                    code = proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
                    raise AssertionError(implementation + ' waited for EOF after output failure')
                errors = proc.stderr.read()
                assert code == 1 and b'write error' in errors, (implementation, code, errors)
        checks += 1
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[1] &= ~termios.ONLCR
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    try:
        with subprocess.Popen([binary, '-c', prefix + 'unexpand -a'], stdin=subprocess.PIPE,
                              stdout=slave, stderr=subprocess.PIPE, env=env) as proc:
            proc.stdin.write(b'        X\n'); proc.stdin.flush()
            assert select.select([master], [], [], 10)[0], 'terminal output waited for EOF'
            assert os.read(master, 1024) == b'\tX\n'
            _, errors = proc.communicate(timeout=10)
            assert proc.returncode == 0 and not errors, (proc.returncode, errors)
        checks += 1
    finally:
        os.close(master); os.close(slave)

for f in failures:
    print('FAIL', f)
print(f'unexpand: {checks} checks; {len(failures)} parity failures')
assert not failures
