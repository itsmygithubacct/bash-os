#!/usr/bin/env python3
"""ASCII direct-match repeats in C, C.UTF-8 and en_US.UTF-8.

Usage: grok-sed-fix-locale.py BASH [BASH ...]

GNU sed 4.9 finishes these patterns at once except the case-insensitive
row, which does not return. The builtin must print the same bytes in each
locale, including a finite-repeat address.
A pattern-space byte at or above 0x80 is refused for a word or
case-insensitive direct match, because that matcher classifies bytes.
"""
import os
from pathlib import Path
import subprocess
import sys

if len(sys.argv) < 2:
    print('usage: grok-sed-fix-locale.py BASH [BASH ...]', file=sys.stderr)
    sys.exit(2)
binaries = [str(Path(p).resolve()) for p in sys.argv[1:]]
GNU = '/usr/bin/sed'
locales = ('C', 'C.UTF-8', 'en_US.UTF-8')
# (args, data, expect). expect is None when GNU sed's stdout is the oracle.
rows = [
    (['-E', r's/(|\<b)+/x/g'], b'.b\n', b'x.x\n'),
    (['-E', r's/(|\>b)+/[&]/g'], b'ab\n', b'[]a[b]\n'),
    (['-E', r's/(|\bb)+/x/g'], b'.b\n', b'x.x\n'),
    (['-E', r's/(|\Bb)+/[&]/g'], b'ab\n', b'[]a[b]\n'),
    (['-E', r's/(|^\s)+/X/'], b' abc\n', b'Xabc\n'),
    (['-E', r's/(|^b)+/x/gI'], b'.B\n', b'x.xBx\n'),
    # Finite-repeat addresses match. GNU sed's address uses no registers.
    (['-E', r'/(|^b){1,3}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|^b){2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|^b){0,2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\`b){1,3}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\`b){2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\`b){0,2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\<b){1,3}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\<b){2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\<b){0,2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\>b){1,3}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\>b){2}/p'], b'bb\n', b'bb\nbb\n'),
    (['-E', r'/(|\>b){0,2}/p'], b'bb\n', b'bb\nbb\n'),
    # A star does not consume a failed \> between word characters.
    (['-E', r's/(|\>b)*/[&]/g'], b'ab\n', b'[]a[]b[]\n'),
    (['-E', r's/(|\>b)*/[&]/g'], b'bb\n', b'[]b[]b[]\n'),
    (['-E', r's/(|\>b)*/[&]/g'], b'xb\n', b'[]x[]b[]\n'),
    (['-E', r's/(|\>b)*/[&]/g'], b' abc\n', b'[] []a[]b[]c[]\n'),
    (['-E', r's/(|\>b)*/x/g'], b'ab\n', b'xaxbx\n'),
    (['-E', r's/(|\>b)*/x/g'], b'bb\n', b'xbxbx\n'),
    (['-E', r's/(|\>b)*/x/g'], b'xb\n', b'xxxbx\n'),
    (['-E', r's/(|\>b)*/x/g'], b' abc\n', b'x xaxbxcx\n'),
    (['-E', r's/(|\>b){0,2}/[&]/g'], b'ab\n', b'[]a[b]\n'),
    (['-E', r's/(|\>b){0,2}/x/g'], b'ab\n', b'xax\n'),
    (['-E', r's/(|\<b)*/[&]/g'], b'ab\n', b'[]a[]b[]\n'),
    (['-E', r's/(|\bb)*/[&]/g'], b'ab\n', b'[]a[]b[]\n'),
    (['-E', r's/(|\Bb)*/[&]/g'], b'.b\n', b'[].[]b[]\n'),
]
# Word and icase direct matches. The engine path (word-boundary repeats)
# is compared with GNU sed instead, including when the subject is multibyte.
high = [
    (['-E', r's/(|\<b)+/x/g'], b'\xc3\xa9b\n'),
    (['-E', r's/(|^b)+/x/gI'], b'\xc3\xa9\n'),
    (['-E', r's/(|^\s)+/X/'], b'\xc3\xa9\n'),
]
engine_high = [
    (['-E', r's/(|\bb)+/[&]/g'], b'\xc3\xa9b\n'),
]
checks = failures = 0


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:300], 'expected', repr(expected)[:300], flush=True)


def invoke(prog, args, data, loc, timeout):
    env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL=loc)
    limit = '' if os.environ.get('ASAN_OPTIONS') else 'ulimit -v 524288; '
    try:
        p = subprocess.run([prog, '--noprofile', '--norc', '-c',
                            limit + 'sed "$@"', '_', *args],
                           input=data, capture_output=True, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 'timeout', b'', b''
    err = p.stderr
    if b'AddressSanitizer' in err or b'runtime error:' in err:
        return 'sanitizer', p.stdout, err
    return p.returncode, p.stdout, err


def gnu(args, data, loc):
    env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL=loc)
    try:
        p = subprocess.run([GNU, *args], input=data, capture_output=True, env=env, timeout=2)
    except subprocess.TimeoutExpired:
        return 'timeout', b''
    return p.returncode, p.stdout


def one(binary):
    name = Path(binary).name
    for loc in locales:
        for args, data, expect in rows:
            rc, out, err = invoke(binary, args, data, loc, 4)
            if rc == 'sanitizer':
                check((name, loc, 'sanitizer', args), err[:80], b'')
                continue
            if args[-1].endswith('I') or args[-1].endswith('i'):
                # GNU sed does not return for this pattern. The direct matcher does.
                check((name, loc, args, data), (rc, out), (0, expect))
            else:
                grc, gout = gnu(args, data, loc)
                check((name, loc, 'gnu', args), (grc, gout), (0, expect))
                check((name, loc, args, data), (rc, out), (0, expect))
            if isinstance(err, bytes) and b'refusing pattern' in err:
                check((name, loc, 'unexpected refuse', args), err[:80], b'')
        for args, data in high:
            rc, out, err = invoke(binary, args, data, loc, 4)
            if loc == 'C':
                grc, gout = gnu(args, data, loc)
                check((name, loc, 'high-run', args), (rc, out), (grc, gout))
            else:
                check((name, loc, 'high-refuse', args),
                      (rc not in (0, 'timeout'), out, b'refusing pattern' in err),
                      (True, b'', True))
        for args, data in engine_high:
            rc, out, err = invoke(binary, args, data, loc, 4)
            grc, gout = gnu(args, data, loc)
            check((name, loc, 'engine-high', args), (rc, out), (grc, gout))


for binary in binaries:
    one(binary)

print(f'{checks - failures}/{checks} passed')
sys.exit(1 if failures else 0)
