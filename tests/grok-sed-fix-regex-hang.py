#!/usr/bin/env python3
"""Repeated empty-capable anchor groups must not loop in set_regs.

Usage: grok-sed-fix-regex-hang.py BASH [BASH ...]
Each binary is a dynamic or static build. Patterns GNU sed finishes are
compared with it. A whole-pattern group of anchors, literals and GNU
classes is matched directly when an anchor is followed by a consumer,
including on subjects where GNU sed times out. \' is left to the engine.
A repeated anchor with no consumer in that alternative is left to the
engine too. \\b and \\B are left to the engine: re_search returns, and the
direct matcher does not reproduce its spans. A hanging shape that is not
direct-matched is searched with one register. No match is kept, because
set_regs cannot run. A one-register hit is refused. Addresses pass no
registers and run.
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
    # \b and \B return from re_search. The direct matcher does not.
    (['-E', r's/(|\bb)+/[&]/g'], b'ab\n', b'[]a[b]\n'),
    (['-E', r's/(|\bb)+/[&]/g'], b'abc\n', b'[]a[b]c[]\n'),
    (['-E', r's/(|\bb)+/X/g'], b'ab\n', b'XaX\n'),
    ([r's/\(\|\bb\)\+/[&]/g'], b'ab\n', b'[]a[b]\n'),
    (['-E', r's/(|\Bb)+/[&]/g'], b'.b\n', b'[].[b]\n'),
    (['-E', r's/(|\Bb)+/[&]/g'], b'a.b\n', b'[]a[].[b]\n'),
    (['-E', r's/(|\Bb)+/[&]/g'], b'a b\n', b'[]a[] [b]\n'),
    (['-E', r's/(|\Bb)+/X/g'], b'.b\n', b'X.X\n'),
    ([r's/\(\|\Bb\)\+/[&]/g'], b'.b\n', b'[].[b]\n'),
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
    # A finite repeat does not keep an empty completion on a consumer the
    # anchor rejected, and a substitution stops. An address asks for no
    # registers, so the same pattern still matches. Unlimited +/* stay.
    (['-E', r's/(|^b){1,3}/<\1>/'], b'bb\n', b'bb\n'),
    (['-E', r's/(|^b){1,3}/<\1>/g'], b'bb\n', b'bb\n'),
    (['-E', r's/(|^b){1,3}/[&]/g'], b'bb\n', b'bb\n'),
    (['-E', r's/(|^b){2}/<\1>/'], b'bb\n', b'bb\n'),
    (['-E', r's/(|^b){2}/<\1>/g'], b'bb\n', b'bb\n'),
    (['-E', r's/(|^b){1,3}/<\1>/g'], b'bbb\n', b'bbb\n'),
    (['-E', r's/(|^b){0,2}/<\1>/'], b'bb\n', b'bb\n'),
    (['-E', r's/(|^b){3}/<\1>/g'], b'bbb\n', b'bbb\n'),
    (['-E', r's/(|^b){1,3}/<\1>/g'], b'.b\n', b'<>.b\n'),
    (['-E', r's/(|^b){1,3}/<\1>/g'], b'xb\n', b'<>xb\n'),
    (['-E', r's/(|^b){1,3}/<\1>/g'], b'bx\n', b'<>x<>\n'),
    (['-E', r's/(|^\s){1,3}/[&]/g'], b'  a\n', b'  a\n'),
    (['-E', r's/(|^\s){1,3}/[&]/'], b' a\n', b'[ ]a\n'),
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
    # A star does not consume a failed \> between word characters. The group
    # matches empty there. + and {0,2} still consume. \<, \b and \B under *
    # already match GNU sed.
    (['-E', r's/(|\>b)*/[&]/g'], b'ab\n', b'[]a[]b[]\n'),
    (['-E', r's/(|\>b)*/[&]/g'], b'bb\n', b'[]b[]b[]\n'),
    (['-E', r's/(|\>b)*/[&]/g'], b'xb\n', b'[]x[]b[]\n'),
    (['-E', r's/(|\>b)*/[&]/g'], b' abc\n', b'[] []a[]b[]c[]\n'),
    (['-E', r's/(|\>b)*/x/g'], b'ab\n', b'xaxbx\n'),
    (['-E', r's/(|\>b)*/x/g'], b'bb\n', b'xbxbx\n'),
    (['-E', r's/(|\>b)*/x/g'], b'xb\n', b'xxxbx\n'),
    (['-E', r's/(|\>b)*/x/g'], b' abc\n', b'x xaxbxcx\n'),
    (['-E', r's/(|\>b){0,2}/[&]/g'], b'ab\n', None),
    (['-E', r's/(|\>b){0,2}/x/g'], b'ab\n', None),
    (['-E', r's/(|\<b)*/[&]/g'], b'ab\n', None),
    (['-E', r's/(|\bb)*/[&]/g'], b'ab\n', None),
    (['-E', r's/(|\Bb)*/[&]/g'], b'.b\n', None),
    (['-E', r'/(|^b)+/s//x/g'], b'.b\n', b'x.xbx\n'),
    # \' is an end anchor the engine can finish. It must not be a literal.
    (['-E', r"s/(|\'b)+/[&]/g"], b'.b\n', None),
    (['-E', r"s/(|\'b)+/X/g"], b'.b\n', None),
    (['-E', r"s/(|\'b)+/[&]/g"], b'ab\n', None),
    (['-E', r"s/((|\'b))+/[&]/g"], b'.b\n', None),
    # GNU classes. Finishing subjects match GNU sed. \d and \D stay literals.
    (['-E', r's/(|^\s)+/X/'], b' abc\n', None),
    (['-E', r's/(|^\s)+/[&]/g'], b' abc\n', None),
    (['-E', r's/(|^\s)+/X/'], b'ab\n', None),
    (['-E', r's/(|^\w)+/X/'], b'a\n', None),
    (['-E', r's/(|^\w)+/[&]/g'], b'a\n', None),
    (['-E', r's/(|^\S)+/X/'], b'a\n', None),
    (['-E', r's/(|^\W)+/X/'], b'.a\n', None),
    (['-E', r's/(|^\W)+/[&]/g'], b'.a\n', None),
    (['-E', r's/(|^\d)+/X/'], b'12\n', None),
    (['-E', r's/(|^\D)+/X/'], b'ab\n', None),
    # These subjects make GNU sed time out. One class byte is consumed, which
    # is not the result of treating the escape as a literal.
    (['-E', r's/(|^\w)+/X/'], b'abc\n', b'Xbc\n'),
    (['-E', r's/(|^\S)+/X/'], b'ab c\n', b'Xb c\n'),
    (['-E', r's/(|^\s)+/X/'], b'  a\n', b'X a\n'),
    # A consumer in another alternative still finishes under nmatch 10.
    (['-E', r's/([a]|^)+/X/g'], b'ab\n', None),
    (['-E', r's/(.|^)+/X/'], b'ab\n', None),
    (['-E', r's/([[:alpha:]]|^)+/X/'], b'ab\n', None),
    (['-E', r's/b(|^)+/X/g'], b'ba\n', None),
    (['-E', r's/([^]a]|^)+/X/'], b']\n', None),
    ([r's/b\(\|^\)\+/X/g'], b'ba\n', None),
    # \> followed by a literal uses the span glibc returns when it returns.
    (['-E', r's/(|\>b)+/[&]/g'], b'ab\n', None),
    (['-E', r's/(|\>b)+/X/g'], b'ab\n', None),
    (['-E', r's/(|\>b)+/X/g'], b'abc\n', None),
    (['-E', r's/(|\>b)+/[&]/g'], b'abb\n', None),
    (['-E', r's/(|\>b)+/<&\1>/g'], b'ab\n', None),
    (['-E', r's/(|\>b)+/<&\1>/g'], b'abb\n', None),
    (['-E', r's/(|\>)+/[&]/g'], b'ab\n', None),
    # \> on .b makes nmatch 10 hang. The direct matcher still has to return.
    (['-E', r's/(|\>b)+/X/g'], b'.b\n', b'X.XbX\n'),
    # One register misses, so the register walk cannot run. GNU sed prints
    # the line. A hit, including on ab, stays in the refused list.
    (['-E', r's/a(|^b)+/X/'], b'.b\n', b'.b\n'),
    (['-E', r's/a(|^b)+/X/g'], b'.b\n', b'.b\n'),
    (['-E', r's/a(|^b)+/X/'], b'b\n', b'b\n'),
    ([r's/a\(\|^b\)\+/X/'], b'.b\n', b'.b\n'),
    ([r's/a\(\|^b\)\+/X/g'], b'.b\n', b'.b\n'),
    # An address passes no registers. GNU sed prints the line twice.
    (['-E', r'/a(|^b)+/p'], b'ab\n', b'ab\nab\n'),
]

refused = [
    (['-E', r's/a(|^b)+/X/g'], b'ab\n'),
    (['-E', r's/((|^b))+/X/g'], b'.b\n'),
    ([r's/a\(\|^b\)\+/X/g'], b'ab\n'),
    ([r's/a\(\|^b\)\+/X/'], b'ab\n'),
    (['-E', r's/(|^.)+/X/'], b'ab\n'),
    # One register matches here. Filling the others does not return on ab,
    # and this span is not the substitution GNU sed prints for a or aa.
    (['-E', r's/a(|^b)+/X/'], b'a\n'),
    (['-E', r's/a(|^b)+/X/'], b'aa\n'),
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
