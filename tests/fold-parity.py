#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fold parity where options agree, plus builtin UTF-8 and shell contracts.

Run with a core/full binary. FOLD_MODULE optionally loads an instrumented fold.
GNU fold is required; BusyBox and a UTF-8 locale are checked when available.
"""
import locale
import os
from pathlib import Path
import pty
import random
import select
import shutil
import subprocess
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash-core').resolve())
gnu = shutil.which('fold', path='/usr/bin:/bin')
assert gnu, 'GNU fold is required'
busybox = shutil.which('busybox', path='/usr/bin:/bin')
references = {'GNU': [gnu]}
if busybox and 'fold' in subprocess.check_output([busybox, '--list'], text=True).split():
    references['BusyBox'] = [busybox, 'fold']
prefix = 'if [[ -n ${FOLD_MODULE:-} ]]; then enable -f "$FOLD_MODULE" fold || exit; fi\n'
environment = dict(os.environ, LC_ALL='C', PATH='')
for key in ('BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS'):
    environment.pop(key, None)
checks = 0


def shell(script, args=(), data=b'', loc='C', **kwargs):
    result = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                             'fold-test', *map(str, args)], input=data,
                            capture_output=True, env=dict(environment, LC_ALL=loc),
                            timeout=30, **kwargs)
    assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr, result.stderr
    return result


def builtin(args=(), data=b'', loc='C'):
    return shell('[[ $(type -t fold) == builtin ]] || exit 99; fold "$@"', args, data, loc)


def compare(args=(), data=b'', loc='C', refs=None):
    global checks
    actual = builtin(args, data, loc)
    assert actual.returncode == 0, (args, actual.returncode, actual.stderr)
    for name, command in (refs or references).items():
        expected = subprocess.run([*command, *map(str, args)], input=data, capture_output=True,
                                  env=dict(environment, LC_ALL=loc), timeout=30)
        assert expected.returncode == 0 and actual.stdout == expected.stdout, (
            name, args, loc, data[:80], actual.stdout[:200], expected.stdout[:200], expected.stderr)
        checks += 1


def contract(args, data, expected, loc='C'):
    global checks
    actual = builtin(args, data, loc)
    assert (actual.returncode, actual.stdout) == (0, expected), (args, loc, actual.stdout[:200], expected[:200], actual.stderr)
    checks += 1


def read_bytes(fd, length):
    data = b''
    deadline = time.monotonic() + 10
    while len(data) < length:
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([fd], [], [], remaining)[0], 'output timed out'
        chunk = os.read(fd, length - len(data))
        assert chunk, ('unexpected output EOF', data)
        data += chunk
    return data


locales = ['C']
for candidate in ('C.UTF-8', 'C.utf8', 'en_US.UTF-8'):
    try:
        locale.setlocale(locale.LC_CTYPE, candidate)
    except locale.Error:
        continue
    locales.append(candidate)
    break
locale.setlocale(locale.LC_CTYPE, 'C')

with tempfile.TemporaryDirectory(prefix='fold-parity-') as directory:
    root = Path(directory)
    first, second, empty = root/'first', root/'second', root/'empty'
    empty.write_bytes(b'')
    rng = random.Random(20260908)
    datasets = [b'', b'\n\n', b'a', b'abc', b'abcd\n', b'abc\ndef',
                b'alpha beta  gamma\tdelta\n', b'\b\babc\bD\tE\rFG\n',
                b'a \tbcdef\tZ\n', b'     \t    \n', b'\t\bX\rZ\n',
                b'\v\f\x1b\x7fabc\n', b'abc\xff\x80D\n', b'abc\xe2\x82']
    datasets += [bytes(rng.choice(b'abcde  \t\b\r\n') for _ in range(800)) for _ in range(5)]
    for loc in locales:
        for data in datasets:
            for width in (1, 2, 3, 7, 8, 9, 40, 80):
                for mode in ([], ['-b'], ['-s'], ['-bs']):
                    # BusyBox groups some invalid bytes in a UTF-8 locale.
                    refs = {'GNU': [gnu]} if loc != 'C' and any(c >= 128 for c in data) and mode in ([], ['-s']) else None
                    compare([*mode, '-w', width], data, loc, refs)
        compare([], b'a'*81 + b'\n', loc)

        # Binary parity is meaningful in byte mode even when column rules differ.
        for data in (bytes(range(256))*5, b'a\0bc\0def\n', 'é界e\u0301XYZ\n'.encode()):
            for width in (1, 3, 8, 40):
                compare(['-b', '-w', width], data, loc)
                compare(['-bs', '-w', width], data, loc)

        # -c is a builtin extension. Default mode uses wcwidth, including NUL=0.
        data = 'é界e\u0301XYZ\n'.encode()
        chars = 'é界e\n\u0301XY\nZ\n'.encode()
        columns = 'é界\ne\u0301XY\nZ\n'.encode() if loc != 'C' else chars
        contract(['-w3'], data, columns, loc)
        for mode in (['-c'], ['--characters'], ['-bc'], ['--bytes', '-c']):
            contract([*mode, '-w3'], data, chars, loc)
        for mode in (['-cb'], ['--characters', '--bytes']):
            contract([*mode, '-w3'], data, b'\xc3\xa9\xe7\n\x95\x8ce\n\xcc\x81X\nYZ\n', loc)
        contract(['-c', '-w3'], b'abc\bD\tE\rFG\n', b'abc\bD\n\t\nE\rFG\n', loc)
        contract(['-cs', '-w5'], 'é ab cd\n'.encode(), 'é ab \ncd\n'.encode(), loc)
        contract(['-w3'], b'a\0bc\0def\n', b'a\0bc\0\ndef\n', loc)
        contract(['-c', '-w3'], b'a\0bc\0def\n', b'a\0b\nc\0d\nef\n', loc)

        # Keep the existing permissive decoder contract explicit: overlong,
        # surrogate and out-of-range sequences are grouped, not rejected.
        malformed = b'A\xc0\x80B\xed\xa0\x80C\xf4\x90\x80\x80D\xe2\x82'
        contract(['-w3'], malformed, b'A\xc0\x80B\xed\xa0\x80\nC\xf4\x90\x80\x80D\n\xe2\x82', loc)
        contract(['-c', '-w3'], malformed, b'A\xc0\x80B\n\xed\xa0\x80C\xf4\x90\x80\x80\nD\xe2\x82', loc)
        for fragment in (b'\xc2', b'\xe2\x82', b'\xf0\x9f\x98', b'\xe2X\x82', b'\xff\x80'):
            contract(['-c', '-w3'], b'abc'+fragment, b'abc\n'+fragment, loc)
        if loc != 'C':
            contract(['-w3'], '界\bABC\n'.encode(), '界\bABC\n'.encode(), loc)
            contract(['-w1'], '界\n'.encode(), '界\n'.encode(), loc)

    # Refills and output buffer boundaries, long word-wrap remainders and
    # long records whose display column repeatedly returns to zero.
    for size in (8191, 8192, 8193, 65535, 65536, 65537, 262145):
        for mode in ([], ['-s'], ['-b']):
            compare([*mode, '-w40'], b'x'*size+b' yz\n')
        compare(['-s', '-w40'], (b'abc\b\r'*size)+b' end\n')
        contract(['-c', '-w1'], b'a'*size+'é界\n'.encode(), b'a\n'*size+'é\n界\n'.encode())
    for boundary in (8189, 8190, 8191, 8192, 16381):
        contract(['-c', '-w1'], b'a'*boundary+b'\xf0\x9f\x98\x80Z', b'a\n'*boundary+b'\xf0\x9f\x98\x80\nZ')
    compare(['-w', '2147483647'], b'small\tinput\n', refs={'GNU': [gnu]})

    # Exact option differences: GNU accepts long and historical width forms;
    # this BusyBox also accepts -N, but rejects the other extras below.
    for args in (['-3'], ['-s3'], ['--width=3'], ['--width', '3'], ['--spaces', '-w3'],
                 ['--bytes', '-w3'], ['-w', '+3']):
        compare(args, b'abc defgh\n', refs={'GNU': [gnu]})
        if 'BusyBox' in references:
            p = subprocess.run([busybox, 'fold', *args], input=b'abc\n', capture_output=True)
            assert (p.returncode == 0) == (args == ['-3']), ('BusyBox option behavior changed', args)
            checks += 1
    if 'BusyBox' in references:
        p = subprocess.run([busybox, 'fold', '-w10001'], input=b'x', capture_output=True)
        assert p.returncode != 0, 'BusyBox width limit changed'
        checks += 1
    for name, command in references.items():
        for mode in ('-c', '--characters'):
            p = subprocess.run([*command, mode], input=b'abc\n', capture_output=True)
            assert p.returncode != 0, (name, 'character option behavior changed')
            checks += 1
    first.write_bytes(b'ab'); second.write_bytes(b'cdef\n')
    compare(['-w3', first, second])
    compare(['-sw3', first, empty, '-', second, '-'], b'ghi jk\n')
    dash = root/'-literal'; dash.write_bytes(b'abcde\n')
    p = shell('cd "$1"; shift; fold -w3 -- "$@"', [root, '-literal'])
    assert p.returncode == 0 and p.stdout == b'abc\nde\n', p
    checks += 1
    for args in (['-w'], ['--width'], ['-w0'], ['-w-1'], ['-w2147483648'], ['--width=x'],
                 ['--unknown'], ['-x'], ['-0'], [first, '--width'], [first, '--unknown']):
        p = builtin(args)
        assert p.returncode == 2 and p.stderr, (args, p)
        checks += 1
    for args in ([root], [root/'missing'], [root/'missing', first, second]):
        p = builtin(['-w3', *args])
        assert p.returncode == 1 and p.stderr, (args, p)
        if len(args) == 3:
            assert p.stdout == b'abcde\nf\n', p.stdout
        checks += 1

    first.write_bytes(b'abc\ndef\0gh\n')
    expected = subprocess.check_output([gnu, '-b', '-w3', str(first)])
    p = shell('''
before_fds=(/proc/self/fd/*)
IFS= read -r marker; [[ $marker == marker ]] || exit 40
for ((i=0;i<9;i++)); do fold -b -w3 < "$1" || exit; done
fold < "$2" || exit
fold -b -w3 < "$1" || exit
fold < "$3" 2>/dev/null; [[ $? == 1 ]] || exit 41
fold <&- 2>/dev/null; [[ $? == 1 ]] || exit 47
fold -b -w3 < "$1" || exit
after_fds=(/proc/self/fd/*)
[[ ${before_fds[*]} == "${after_fds[*]}" ]] || exit 42
IFS= read -r marker; [[ $marker == after ]] || exit 43
printf 'shell-ok\n'
''', [first, empty, root], b'marker\nafter\n')
    assert p.returncode == 0 and p.stdout == expected*11+b'shell-ok\n', (p.returncode, p.stdout[:200], p.stderr)
    checks += 1

    for size in (3, 150000):
        first.write_bytes(b'x'*size)
        p = shell('''
printf before
fold -w3 < "$1" >/dev/full 2>/dev/null; [[ $? == 1 ]] || exit 44
fold -w3 < "$1" 1>&- 2>/dev/null; [[ $? == 1 ]] || exit 45
printf after
fold -w3 <<<abc
''', [first])
        assert p.returncode == 0 and p.stdout == b'beforeafterabc\n', (p.returncode, p.stdout, p.stderr)
        checks += 1
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        p = subprocess.run([binary, '-c', prefix+'''trap '' PIPE
fold -w3 < "$1"; [[ $? == 1 ]] || exit 46
printf survived >&2
''', '_', str(first)], stdout=write_fd, stderr=subprocess.PIPE, env=environment, timeout=30)
        assert p.returncode == 0 and p.stderr.endswith(b'survived'), p.stderr
        checks += 1
    finally:
        os.close(write_fd)

    # Input lookahead uses fread, so feed complete blocks while keeping input
    # open. Each output line must still be flushed to a terminal before EOF.
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[1] &= ~termios.ONLCR
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    proc = None
    try:
        proc = subprocess.Popen([binary, '-c', prefix+'fold -w3'], env=environment,
                                stdin=subprocess.PIPE, stdout=slave, stderr=subprocess.PIPE)
        proc.stdin.write(b'a\n'*4096); proc.stdin.flush()
        assert select.select([master], [], [], 10)[0], 'terminal output waited for EOF'
        assert os.read(master, 1024).startswith(b'a\n')
        proc.stdin.close()
        deadline = time.monotonic() + 10
        while proc.poll() is None:
            assert time.monotonic() < deadline, 'terminal drain timed out'
            if select.select([master], [], [], 1)[0]:
                os.read(master, 65536)
        assert proc.returncode == 0 and not proc.stderr.read()
        checks += 1
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill(); proc.wait()
        os.close(master); os.close(slave)
    # Later Bash printf still flushes a line while read waits on open input.
    first.write_bytes(b'abc\n')
    proc = subprocess.Popen([binary, '-c', prefix+'fold "$1"; printf "ready\\n"; read -r x',
                             '_', str(first)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=environment)
    try:
        assert read_bytes(proc.stdout.fileno(), 10) == b'abc\nready\n'
        _, errors = proc.communicate(b'done\n', timeout=10)
        assert proc.returncode == 0 and not errors, errors
        checks += 1
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait()

print(f'fold: {checks} parity, option, UTF-8 and shell-state checks passed ({", ".join(locales)})')
