#!/usr/bin/env python3
"""Repeated empty-capable anchor groups must not loop in set_regs.

Usage: grok-sed-fix-regex-hang.py BASH [BASH ...]
Each binary is a dynamic or static build. Patterns GNU sed finishes are
compared with it. Patterns that make GNU sed time out have a fixed result:
the whole-pattern form is matched directly, and any other shape is refused.
"""
import os
from pathlib import Path
import subprocess
import sys

if len(sys.argv) < 2:
    print('usage: grok-sed-fix-regex-hang.py BASH [BASH ...]', file=sys.stderr)
    sys.exit(2)
binaries = [str(Path(p).resolve()) for p in sys.argv[1:]]
GNU = '/usr/bin/sed'
env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C')
checks = failures = 0


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:300], 'expected', repr(expected)[:300], flush=True)


def invoke(prog, args, data, timeout):
    # A tight address-space limit keeps a missed hang from filling tmpfs.
    # ASan maps far more than that and aborts while starting, so a sanitizer
    # run keeps only the process timeout.
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


def gnu(args, data):
    try:
        p = subprocess.run([GNU, *args], input=data, capture_output=True, env=env, timeout=2)
    except subprocess.TimeoutExpired:
        return 'timeout', b''
    return p.returncode, p.stdout


# (args, data, expected or None). None means "whatever GNU returns, if it returns".
cases = [
    (['-E', r's/(|^b)+/x/g'], b'.b\n', b'x.xbx\n'),
    (['-E', r's/(|^b)+/x/'], b'.b\n', None),
    (['-E', r's/(|^b)+/x/g'], b'b\n', None),
    ([r's/\(\|^b\)\+/x/g'], b'.b\n', b'x.xbx\n'),
    ([r's/\(\|^b\)\+/x/'], b'.b\n', None),
    (['-E', r's/(|\`b)+/x/g'], b'.b\n', b'x.xbx\n'),
    (['-E', r's/(|\`b)+/x/'], b'.b\n', None),
    (['-E', r's/(|\<b)+/X/g'], b'ab\n', b'XaXbX\n'),
    (['-E', r's/(|\<b)+/X/g'], b'b\n', None),
    (['-E', r's/(|\b)+/X/g'], b'ab\n', None),
    (['-E', r's/($)+/X/g'], b'ab\n', None),
    (['-E', r's/(|$)+/X/g'], b'ab\n', None),
    (['-E', r's/(^)+/X/g'], b'ab\n', None),
    (['-E', r's/(^)*/X/g'], b'ab\n', None),
    (['-E', r's/(^b|$)+/X/g'], b'ab\n', None),
    (['-E', r's/(^b|$)+/X/g'], b'b\n', None),
    (['-E', r's/(a|^)+/X/g'], b'aa\n', None),
    (['-E', r's/(a|^)+/X/g'], b'b\n', None),
    (['-E', r's/(b|^)+/X/g'], b'bbb\n', None),
    (['-E', r's/(^a)+/X/g'], b'aa\n', None),
    (['-E', r's/(^a)*/X/g'], b'aa\n', None),
    ([r's/\(a\)\+/X/'], b'aaa\n', None),
    (['-E', r's/(a|b)*/X/'], b'ab\n', None),
    (['-E', r's/(a*)+/X/g'], b'aa\n', None),
    (['-E', r's/(|^b)+/<\1>/'], b'b\n', None),
    (['-E', r's/(|^b){1,3}/<\1>/'], b'b\n', None),
    (['-E', r'/(|^b)+/s//x/g'], b'.b\n', b'x.xbx\n'),
]

refused = [
    (['-E', r's/a(|^b)+/X/g'], b'ab\n'),
    (['-E', r's/((|^b))+/X/g'], b'.b\n'),
    ([r's/a\(\|^b\)\+/X/g'], b'ab\n'),
    (['-E', r'/a(|^b)+/p'], b'ab\n'),
]


def one(binary):
    name = Path(binary).name
    for args, data, expect in cases:
        rc, out, err = invoke(binary, args, data, 4)
        if rc == 'sanitizer':
            check((name, 'sanitizer', args), err[:80], b'')
            continue
        grc, gout = gnu(args, data)
        if grc == 'timeout':
            check((name, args, data), (rc, out), (0, expect))
        else:
            want = (grc, gout) if expect is None else (grc, gout)
            if expect is not None and (grc, gout) != (0, expect):
                check((name, 'oracle', args), (0, expect), (grc, gout))
            check((name, args, data), (rc, out), want if expect is None else (0, expect))
        if isinstance(err, bytes) and b'refusing pattern' in err and expect is not None:
            check((name, 'unexpected refuse', args), err[:80], b'')
    for args, data in refused:
        rc, out, err = invoke(binary, args, data, 4)
        check((name, 'refused', args),
              (rc not in (0, 'timeout'), out, b'refusing pattern' in err),
              (True, b'', True))


for binary in binaries:
    one(binary)

print(f'{checks - failures}/{checks} passed')
sys.exit(1 if failures else 0)
