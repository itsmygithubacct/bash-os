#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused expand parity, stream boundaries, errors and persistent-shell state.

GNU is the byte/option reference. BusyBox comparisons use its common subset:
positive uniform stops, ASCII records, and newline-terminated file boundaries.
BusyBox does not support explicit lists or /N extensions and differs on binary
input, backspaces and continuation across unterminated files.
"""
from pathlib import Path
import os
import pty
import random
import select
import shutil
import subprocess
import sys
import tempfile
import termios

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash-core').resolve())
environment = dict(os.environ, LC_ALL='C', PATH='')
if os.environ.get('EXPAND_PRELOAD'):
    environment['LD_PRELOAD'] = os.environ['EXPAND_PRELOAD']
    environment['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
prefix = '''if [[ -n ${EXPAND_MODULE:-} ]]; then
    enable -f "$EXPAND_MODULE" expand || exit
fi
[[ $(type -t expand) == builtin ]] || exit 99
'''
gnu = shutil.which('expand', path='/usr/bin:/bin')
busybox = shutil.which('busybox', path='/usr/bin:/bin')
assert gnu, 'GNU expand is required'
if busybox and 'expand' not in subprocess.check_output([busybox, '--list'], text=True).split():
    busybox = None
checks = {'GNU': 0, 'BusyBox': 0, 'state/error': 0}


def shell(script, args=(), data=b'', **kwargs):
    result = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                             'expand-test', *map(str, args)], input=data,
                            capture_output=True, env=environment, timeout=20, **kwargs)
    assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr, result.stderr
    return result


def compare(args=(), data=b'', reference='GNU'):
    actual = shell('expand "$@"', args, data)
    command = [gnu] if reference == 'GNU' else [busybox, 'expand']
    expected = subprocess.run([*command, *map(str, args)], input=data,
                              capture_output=True, env={'LC_ALL': 'C'}, timeout=20)
    assert (actual.returncode, actual.stdout) == (expected.returncode, expected.stdout), (
        reference, args, len(data), actual.returncode, expected.returncode,
        actual.stdout[:100], expected.stdout[:100], actual.stderr)
    if expected.returncode:
        assert actual.stderr, (args, 'missing error diagnostic')
    checks[reference] += 1


with tempfile.TemporaryDirectory(prefix='expand-parity-') as directory:
    root = Path(directory)
    first, second, empty = root / 'first', root / 'second', root / 'empty'
    empty.write_bytes(b'')
    rng = random.Random(20260908)
    datasets = [b'', b'x', b'\t', b'\n\n', b' \t\tlead\ttrail\n',
                b'abc\b\b\tX\n\b\b\tY\n', b' \b\tX\n',
                b'a\0\tb\n\0\t\n', bytes(range(256)) * 3,
                b'a\rb\t\f\t\v\tend', b'\t' * 1000,
                b'abc\t' * 300000 + b'\b\tend',
                bytes(rng.choice(b'abc \t\n\b\r\0\xff') for _ in range(5000))]
    # Input refill and output-buffer boundaries, including padding spanning
    # several flushes, NULs and control bytes immediately around the edges.
    for n in (4095, 4096, 4097, 16383, 16384, 16385, 65535, 65536, 65537):
        datasets.append(b'x' * n + b'\t\0\b\t\n\tend')
    options = [[], ['-i'], ['-t', '1'], ['-t', '3'], ['-t', '8'],
               ['-t', '3,7,12'], ['-t', '3,7,/8'], ['-t', '3,7,+8'],
               ['-i', '-t', '3,7,+8']]
    for data in datasets:
        for opts in options:
            compare(opts, data)
    for opts in [['--initial'], ['-ii'], ['-it4'], ['-it', '4'], ['-t4'], ['-4'],
                 ['--tabs', '4'], ['--tabs=4'], ['--tabs='], ['-t', ', 4, 9, +8'],
                 ['-t', '4 9 /8'], ['-t', '/8'], ['-t', '+8'], ['-t', '8,'],
                 ['-t', '8 '], ['-t', ',,'], ['--', '-']]:
        compare(opts, b' \tA\t\b\tB\n\t\t\t\tZ')
    compare(['-t', '65537'], b'\t\tx\n')
    compare(['-t', ','.join(str(i) for i in range(1, 65))], b'\t' * 70)

    # GNU concatenates files, carrying both the column and initial-only state.
    for a, b in [(b'abc', b'\tx\n'), (b' \t', b'\tX'),
                 (b'abc\b', b'\b\tX'), (b'abc\n', b'\tX')]:
        first.write_bytes(a)
        second.write_bytes(b)
        for opts in [[], ['-i'], ['-t', '3,7,+8']]:
            compare([*opts, first, empty, second])
            compare([*opts, first, '-', empty, second, '-'], b'\tstdin')
    dash = root / '-file'
    dash.write_bytes(b'\tx\n')
    compare(['--', dash])

    # Invalid options need failure and diagnostics; GNU's usage exit status
    # differs from Bash's EX_USAGE (2), so do not require identical numbers.
    for opts in [['-t'], ['--tabs'], ['--bogus'], ['-t', '0'], ['-t', '-1'],
                 ['-t', '3,2'], ['-t', '3,3'], ['-t', '3,0'], ['-t', 'x'],
                 ['-t', '3,/8,12'],
                 ['-t', '3,+8,/4'], ['-t', '3,/8,+4'],
                 ['-t', '99999999999999999999999999999999999']]:
        actual = shell('expand "$@"', opts)
        expected = subprocess.run([gnu, *opts], capture_output=True)
        assert actual.returncode == 2 and expected.returncode != 0 and actual.stderr, (opts, actual)
        checks['GNU'] += 1
    # Deliberate implementation limits: positive extension sizes (GNU accepts
    # zero as no extension), 64 explicit stops and INT_MAX widths.
    for stop in ['2147483648', '3,/2147483648', '3,+2147483648',
                 '3,/0', '3,+0',
                 ','.join(str(i) for i in range(1, 66))]:
        p = shell('expand -t "$1"', [stop])
        assert p.returncode == 2 and p.stderr, (stop, p)
        checks['state/error'] += 1
    for stop in ['2147483647', '3,/2147483647', '3,+2147483647']:
        compare(['-t', stop])  # no enormous output needed to validate parsing

    if busybox:
        for data in [b'', b'abc', b'\t', b' \t\tlead\ttrail\n',
                     b'alpha\tbeta\tgamma\n' * 20000, b'a' * 65537 + b'\tz']:
            for opts in [[], ['-i'], ['-t', '1'], ['-t', '3'], ['-t', '8'], ['-i', '-t', '4']]:
                compare(opts, data, 'BusyBox')
        first.write_bytes(b'a\tb\n')
        second.write_bytes(b'\tlast\n')
        compare([first, empty, second], reference='BusyBox')
    else:
        print('SKIP BusyBox: expand applet unavailable')

    first.write_bytes(b'alpha\tbeta\tgamma\n' * 2000 + b'\0\tend')
    second.write_bytes(b' \tstart\tend\n')
    for args in [[root / 'missing'], [root], [root / 'missing', second],
                 [first, root, second], ['-', root / 'missing', second]]:
        compare(args, b'abc\tstdin')
    expected = subprocess.check_output([gnu, str(first)])
    p = shell('for ((i=0;i<10;i++)); do expand -t 8 < "$1" || exit; done', [first])
    assert p.returncode == 0 and p.stdout == expected * 10, p
    checks['state/error'] += 1

    # Alternating EOF/error/options/redirections must not affect later calls.
    script = '''
printf before
expand -i -t 3 "$2" >/dev/null || exit 10
expand < "$1" || exit 11
expand < "$3" || exit 12
expand -t 0 2>/dev/null && exit 13
expand <&- 2>/dev/null && exit 14
expand < "$1" || exit 15
printf after
'''
    p = shell(script, [first, second, empty])
    assert p.returncode == 0 and p.stdout == b'before' + expected * 2 + b'after', p
    checks['state/error'] += 1
    p = shell('IFS= read -r first; expand; IFS= read -r end && exit 10; :',
              data=b'skip\nabc\tx\n')
    assert p.returncode == 0 and p.stdout == b'abc     x\n', p
    checks['state/error'] += 1

    # Output failures include buffered final output and a mid-buffer failure.
    for file in [first, second]:
        p = shell('''
expand < "$1" >/dev/full 2>/dev/null; rc=$?
[[ $rc == 1 ]] || exit 10
expand < "$2" || exit 13
expand < "$1" >&- 2>/dev/null; rc=$?
[[ $rc == 1 ]] || exit 11
printf before
expand < "$1" || exit 12
printf after
''', [file, second])
        wanted = subprocess.check_output([gnu, str(file)])
        next_output = subprocess.check_output([gnu, str(second)])
        assert p.returncode == 0 and p.stdout == next_output + b'before' + wanted + b'after', p
        checks['state/error'] += 1
    readfd, writefd = os.pipe()
    os.close(readfd)
    try:
        p = subprocess.run([binary, '-c', prefix + '''
trap '' PIPE
expand "$1" 2>/dev/null; [[ $? == 1 ]]
''', '_', str(first)], stdout=writefd, stderr=subprocess.PIPE,
                           env=environment, timeout=20)
        assert p.returncode == 0, p
        checks['state/error'] += 1
    finally:
        os.close(writefd)

    p = shell('''
set -- "$1" "$2"
original_pwd=$PWD; original_ifs=$IFS; original_umask=$(umask)
trap ':' USR1
original_trap=$(trap -p USR1); original_options=$-
before=(/proc/$$/fd/*)
for ((i=0;i<100;i++)); do
    expand -i -t 3,7,+8 "$1" - "$2" </dev/null >/dev/null || exit 10
done
after=(/proc/$$/fd/*)
[[ ${before[*]} == "${after[*]}" && $PWD == "$original_pwd" &&
   $IFS == "$original_ifs" && $(umask) == "$original_umask" &&
   $(trap -p USR1) == "$original_trap" && $- == "$original_options" && $# == 2 ]]
''', [first, second])
    assert p.returncode == 0, p
    checks['state/error'] += 1

    # Terminal output must arrive before EOF, even below the output block size.
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[1] &= ~termios.ONLCR
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    try:
        with subprocess.Popen([binary, '-c', prefix + 'expand'], env=environment,
                              stdin=subprocess.PIPE, stdout=slave, stderr=subprocess.PIPE) as proc:
            proc.stdin.write(b'a\tb\n')
            proc.stdin.flush()
            assert select.select([master], [], [], 10)[0], 'terminal output waited for EOF'
            assert os.read(master, 1024) == b'a       b\n'
            _, errors = proc.communicate(timeout=10)
            assert proc.returncode == 0 and not errors, (proc.returncode, errors)
        checks['state/error'] += 1
    finally:
        os.close(master)
        os.close(slave)

print('expand: ' + ', '.join(f'{value} {key}' for key, value in checks.items()) + ' checks passed')
