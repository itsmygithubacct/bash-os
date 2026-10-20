#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent option, byte-column and display-column oracles for expand.

Display columns are zero based and refer to the position immediately before X.
The explicit UTF-8 widths below do not depend on the host expand implementation.
"""
import os
import locale as locale_api
from pathlib import Path
import random
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C')
if os.environ.get('EXPAND_PRELOAD'):
    env.update(LD_PRELOAD=os.environ['EXPAND_PRELOAD'],
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
prefix = 'if [[ -n ${EXPAND_MODULE:-} ]]; then enable -f "$EXPAND_MODULE" expand || exit; fi; '
checks = 0
locales = ['C']
for candidate in ['C.utf8', 'en_US.utf8']:
    try:
        locale_api.setlocale(locale_api.LC_CTYPE, candidate)
    except locale_api.Error:
        print(f'SKIP locale {candidate}: unavailable')
    else:
        locales.append(candidate)
locale_api.setlocale(locale_api.LC_CTYPE, 'C')


def run(args, data=b'', locale='C', script='expand "$@"'):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        '_', *map(str, args)], input=data, capture_output=True,
                       env=dict(env, LC_ALL=locale), timeout=20)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def oracle(args, data, expected, locale='C'):
    global checks
    p = run(args, data, locale)
    assert (p.returncode, p.stdout, p.stderr) == (0, expected, b''), (args, data[:80], p)
    checks += 1


def fixture_display_column(output):
    """A fixed display model, not terminal probing: control bytes take no cells,
    BS backs up, CR/LF reset; invalid bytes render as one replacement cell each.
    UTF-8 fixture widths are explicit (no dependency on libc's Unicode tables).
    """
    col = 0
    widths = {'é': 1, '界': 2, '\u0301': 0, '\u200b': 0, '😀': 2}
    for ch in output.decode('utf-8', 'surrogateescape'):
        if ch in '\r\n': col = 0
        elif ch == '\b': col = max(0, col - 1)
        elif ord(ch) < 32 or ord(ch) == 127: pass
        else: col += widths.get(ch, 1)
    return col

# Explicit padding, independent of the external command.
for args, padding in [(['-t3', '-t7'], 10), (['-3', '-7'], 10),
                      (['-t3', '--tabs=7', '-t+4'], 19),
                      (['-t3,/8', '-t12'], 32),
                      (['-t3,+8', '-t12'], 36),
                      (['-t3,/0'], 15), (['-t3,+0'], 15),
                      (['-t/0'], 40), (['-t+0'], 40),
                      (['-t3,/0,/8'], 32), (['-t3,/0,+8'], 35),
                      (['-t3', '--tabs='], 15),
                      (['--ta=4'], 20), (['--t', '4'], 20),
                      (['-iit4'], 20), (['-i4'], 20)]:
    oracle(args, b'\t' * 5, b' ' * padding)
for n in [65, 257, 4097]:
    oracle(['-t', ','.join(map(str, range(1, n + 1)))], b'\t' * (n + 3), b' ' * (n + 3))
    oracle(['-t', ','.join(map(str, range(1, n + 1))) + ',+4'],
           b'\t' * (n + 3), b' ' * (n + 12))
for width in ['2147483648', '9223372036854775807']:
    oracle(['-i', '-t', width], b'x\tX', b'x\tX')
    oracle(['-t', '3,' + width], b'\tX', b'   X')
    oracle(['-t', '3,/' + width], b'\tX', b'   X')

# Byte count is deliberately distinct from Unicode display width.
# (input prefix, expected spaces, width of that prefix in UTF-8 display cells).
widths = [(b'abc', 5, 3, 8), ('é'.encode(), 6, 1, 7), ('界'.encode(), 5, 2, 7),
          ('e\u0301'.encode(), 5, 1, 6), ('\u0301'.encode(), 6, 0, 6),
          ('\u200b'.encode(), 5, 0, 5), ('😀'.encode(), 4, 2, 6)]
for locale in locales:
    for prefix_bytes, spaces, cells, expected_display in widths:
        expected = prefix_bytes + b' ' * spaces + b'X'
        oracle([], prefix_bytes + b'\tX', expected, locale)
        byte_column = len(expected) - 1
        assert byte_column == 8
        if locale != 'C':
            # Explicit fixture width map: tab replacement positions X here.
            display_column = fixture_display_column(expected[:-1])
            assert display_column == expected_display
    for blank in ['\u00a0', '\u2003', '\u3000']:
        data = blank.encode() + b'\tX'
        oracle(['-i'], data, data, locale)
    # Control bytes each consume one algorithmic column except BS and LF.
    for c in [0, 1, 7, 11, 12, 13, 27, 127]:
        oracle([], bytes([c]) + b'\tX', bytes([c]) + b' ' * 7 + b'X', locale)
        assert fixture_display_column(bytes([c]) + b' ' * 7) == 7
        oracle(['--ini'], bytes([c]) + b'\tX', bytes([c]) + b'\tX', locale)
    for data, expected in [(b'\b\b\tX', b'\b\b' + b' ' * 8 + b'X'),
                           (b'ab\b\tX', b'ab\b' + b' ' * 7 + b'X'),
                           (b'aa\n\tX', b'aa\n' + b' ' * 8 + b'X')]:
        oracle([], data, expected, locale)
        assert fixture_display_column(expected[:-1]) == 8
    # Invalid sequences: each byte consumes exactly one column; bytes survive.
    for bad in [b'\xff', b'\xc0\xaf', b'\xe2\x82', b'\xed\xa0\x80',
                b'\xf4\x90\x80\x80', b'\x80\xbf', b'\xe2(\xa1']:
        oracle([], bad + b'\tX', bad + b' ' * (8 - len(bad)) + b'X', locale)
        assert fixture_display_column(bad + b' ' * (8 - len(bad))) == 8
        # Decoder-like input boundaries must not cause byte loss or joining.
        for n in [4095, 4096, 16383, 16384]:
            data = b'a' * n + bad
            oracle([], data + b'\tX', data + b' ' * (8 - len(data) % 8) + b'X', locale)

invalid = [['-t3/8'], ['-t3+8'], ['-t3,-8'], ['-t3,\v8'], ['-t3,\r8'],
           ['-t3,/8,12'], ['-t3,+8,12'], ['-t3', '-t3'], ['-3', '-2'],
           ['-t3,/8', '-t/0'], ['-t3,+8', '-t+0'], ['-t3,/8', '-t+4'],
           ['--initial=x'], ['--tabsx=4'], ['-t9223372036854775808'],
           ['-t18446744073709551616'], ['-4i']]
for args in invalid:
    p = run(args, b'\tX')
    assert p.returncode == 2 and p.stderr and not p.stdout, (args, p)
    checks += 1
# Random valid repeated-option forms with an independent stop calculation.
rng = random.Random(20261019)
for _ in range(100):
    stops = sorted(rng.sample(range(1, 90), rng.randrange(2, 12)))
    args = [arg for n in stops for arg in ['-t', str(n)]]
    data = bytes(rng.choice(b'ab \t\b\n\0\xff') for _ in range(200))
    col = 0
    expected = bytearray()
    for c in data:
        if c == 9:
            n = next((s - col for s in stops if s > col), 1)
            expected.extend(b' ' * n)
            col += n
        else:
            expected.append(c)
            col = 0 if c == 10 else max(0, col - 1) if c == 8 else col + 1
    oracle(args, data, bytes(expected))
with tempfile.TemporaryDirectory() as directory:
    f = Path(directory) / 'input'
    f.write_bytes(b'\t\t\tX')
    oracle([f, '-t3', '-t7'], b'', b'        X')
    p = run([f, '9223372036854775807'], script='expand -t "$2" "$1" >/dev/full 2>/dev/null; [[ $? == 1 ]] || exit 10; expand -t4 "$1"')
    assert (p.returncode, p.stdout) == (0, b'            X'), p
    checks += 1
    (Path(directory) / '-t3').write_bytes(b'\tY')
    p = run([directory], script='cd "$1"; export POSIXLY_CORRECT=1; expand input -t3')
    assert (p.returncode, p.stdout) == (0, b' ' * 24 + b'X' + b' ' * 7 + b'Y'), p
    checks += 1
    p = run([directory], script='cd "$1"; expand -- -t3')
    assert (p.returncode, p.stdout) == (0, b' ' * 8 + b'Y'), p
    checks += 1
    for locale in locales[1:]:
        a, b = Path(directory) / 'a', Path(directory) / 'b'
        a.write_bytes(b'\xe2'); b.write_bytes(b'\x82\xac\tX')
        oracle([a, b], b'', b'\xe2\x82\xac     X', locale)
    p = run([f], script='for ((i=0;i<100;i++)); do expand -t3 -t3 2>/dev/null; [[ $? == 2 ]] || exit 10; done; expand -t4 "$1"')
    assert (p.returncode, p.stdout) == (0, b'            X'), p
    checks += 1
# Pipeline redirections and repeated locale changes in one persistent shell.
p = run([], script="set -o pipefail; printf 'a\\tb\\n' | expand -t4 | expand -t8")
assert (p.returncode, p.stdout) == (0, b'a   b\n'), p
checks += 1
p = run([*locales, 'C'], script="for LC_ALL in \"$@\"; do export LC_ALL; printf '\\303\\251\\tX' | expand || exit; done")
assert (p.returncode, p.stdout) == (0, b'\xc3\xa9      X' * (len(locales) + 1)), p
checks += 1
for arg in ['--help', '--h', '--version', '--v']:
    p = run([arg])
    assert p.returncode == 0 and b'expand' in p.stdout and not p.stderr, p
    if arg in ['--version', '--v']:
        assert any(48 <= c <= 57 for c in p.stdout), p
    checks += 1
p = run([], script="expand --help >/dev/full 2>/dev/null; [[ $? == 1 ]] || exit 10; expand --version >&- 2>/dev/null; [[ $? == 1 ]] || exit 11; printf 'a\\tX' | expand -t4")
assert (p.returncode, p.stdout) == (0, b'a   X'), p
checks += 1
print(f"sol-expand-options: {checks} independent option/byte/display checks passed ({', '.join(locales)})")
