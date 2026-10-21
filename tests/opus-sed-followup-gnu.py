#!/usr/bin/env python3
"""GNU sed 4.9 parity for delimiters, custom-delimiter addresses, -z,
--sandbox, --follow-symlinks, z/v/e COMMAND and documented option limits.

Usage: opus-sed-followup-gnu.py BASH_BINARY
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
GNU = '/usr/bin/sed'
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = 'if [[ -n ${HEAD_SED_MODULE:-} ]]; then enable -f "$HEAD_SED_MODULE" sed || exit; fi\n'
checks = failures = 0


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:500], 'expected', repr(expected)[:500], flush=True)


def run(args, data=b'', script='sed "$@"', extra_env=None, cwd=None):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix+script, '_', *map(str, args)],
                       input=data, capture_output=True, env={**env, **(extra_env or {})},
                       timeout=15, cwd=cwd)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def gnu(args, data=b'', extra_env=None, cwd=None):
    return subprocess.run([GNU, *map(str, args)], input=data, capture_output=True,
                          env={**env, **(extra_env or {})}, timeout=15, cwd=cwd)


def parity(args, data=b'', extra_env=None):
    """Exact stdout; success/failure agreement (the builtin keeps 1/2/4)."""
    a, g = run(args, data, extra_env=extra_env), gnu(args, data, extra_env)
    check((args, data[:40]), (a.returncode == 0, a.stdout), (g.returncode == 0, g.stdout))
    if a.returncode and g.returncode:
        check(('error status', args), a.returncode, g.returncode if g.returncode in (1, 4) else a.returncode)


# 1. An escaped delimiter is the plain delimiter character in regexes,
#    replacements and y sets, taking precedence over \n, \t, \xHH, \cX,
#    backreferences and case conversion (GNU match_slash).
delimiters = [
    (['st\\ttXt'], b'atb\n'), (['st\\ttXt'], b'a\tb\n'),
    (['sn\\nnXn'], b'anb\n'), (['N;sn\\nnXn'], b'a\nb\n'),
    (['sx\\x41xXx'], b'ax41b\n'), (['sx\\x41xXx'], b'aAb\n'),
    (['s&a\\&b&X&'], b'a&b\n'), (['s&a&[\\&]&'], b'ab\n'), (['s|a|[\\|]|'], b'ab\n'),
    (['s1a1[\\1]1'], b'ab\n'), (['s1\\(a\\)\\11X1'], b'aab\n'), (['s1\\(a\\)1[\\1]1'], b'ab\n'),
    (['sca\\cbcXc'], b'ab\n'), (['sca\\cbcXc'], b'acb\n'),
    (['sxax\\x41x'], b'ab\n'), (['snan[\\n]n'], b'ab\n'), (['stat[\\t]t'], b'ab\n'),
    (['srar[\\r]r'], b'ab\n'), (['sUaU\\UbU'], b'ab\n'), (['sLaL\\LbL'], b'ab\n'),
    (['sEaE\\EbE'], b'ab\n'), (['s.a\\.b.X.'], b'axb\n'), (['s.a\\.b.X.'], b'a.b\n'),
    (['s*a\\*b*X*'], b'aab\n'), (['-E', 's|a\\|b|X|g'], b'a|b ab\n'),
    (['-E', 's+a\\+b+X+g'], b'a+b aab\n'), (['s/a\\/b/X/'], b'a/b\n'), (['s,a\\,b,X,'], b'a,b\n'),
    (['s\\a\\b\\'], b'a\n'), (['y,a\\,,b;,'], b'a,\n'), (['ynanbn'], b'a\n'),
    (['yna\\nnbbn'], b'an\n'), (['yta\\ttbbt'], b'at\n'), (['y/a\\nb/x\\ty/'], b'a\nb\n'),
    ([r's/a\n/X/;N;s/a\nb/Y/'], b'a\nb\n'),
]
for args, data in delimiters:
    parity(args, data)

# 2. \cREGEXc addresses, with flags, ranges, negation, blocks, empty-regex
#    reuse, escaped delimiters and malformed forms.
addresses = [
    ['-n', '\\,a,p'], ['-n', '\\,a,,\\%b%p'], ['-n', '\\,a\\,b,p'], ['-n', '\\.a\\.b.p'],
    ['-n', '\\na\\nnp'], ['-n', '\\,a,Ip'], ['-n', '\\,a,Mp'], ['-n', '\\,a,IMp'], ['\\,a,d'],
    ['-n', '\\|x|,$p'], ['-n', '/a/{\\,,p}'], ['-n', '\\,a,!p'], ['-n', '1,\\,b,p'],
    ['-n', '0,\\,a,p'], ['-n', '\\,a,,+1p'], ['-n', '\\;a;p'], ['-n', '\\ a p'], ['-n', '\\\\a\\p'],
    ['-n', '\\,a,I,\\,c,p'], ['-n', '\\,a,s,,X,p'], ['-E', '-n', '\\|a+|p'], ['-n', '\\|a\\+|p'],
    ['-n', '\\x\\x41xp'], ['\\,a,{s,,[&],}'],
]
for args in addresses:
    parity(args, b'a\nA\nb\naa\nx\na,b\na.b\naxb\nc\nan\n')
for bad in (['-n', '\\'], ['-n', '\\,a'], ['-n', '\\,,p'], ['-n', '\\,a,Xp'], ['-n', '\\\na\np'],
            ['-n', '\\pap'], ['s\na\nb\n'], ['y\na\nb\n']):
    a, g = run(bad, b'a\n'), gnu(bad, b'a\n')
    check(('bad address/delimiter', bad), (a.returncode != 0, a.stdout), (g.returncode != 0, g.stdout))

# 3. -z: NUL-separated records join and split N/G/H/P/D/W on NUL, and =, l,
#    i, c and F end with NUL; a text stays newline-terminated.
zscripts = ['p', 'N;P;D', 'N', 'H;$!d;x', 'G', '=', 'l', 'l 5', 'a X', 'i X', '$c X', 'F',
            's/^/>/gm', 's/$/</g', '$!d', '$p', 'Q', 'q', '$a X', 'W /dev/stdout',
            'y/\\n/X/', 'x;G', 's/\\x00/Z/g', 'n;d', '$!N;s/\\n/+/', '1~2d', '2q', 's/b/&\\n/']
zdata = [b'a\0b', b'a\0b\0', b'a\nb\0c\nd\0', b'a\nb\0c\nd', b'', b'\0', b'\0\0', b'aaaaaaaaaa\0b\0']
for script in zscripts:
    for data in zdata:
        parity(['-z', script], data)
        parity(['-nz', script], data) if script in ('p', '$p', 'l') else None
for spelling in ('--null-data', '--zero-terminated'):
    parity([spelling, 'p'], b'a\0b\0')
with tempfile.TemporaryDirectory(prefix='opus-sed-z-') as tmp:
    d = Path(tmp)
    (d/'one').write_bytes(b'a\0b'); (d/'two').write_bytes(b'c\nd\0e\0')
    (d/'r').write_bytes(b'r1\0r2\0')
    for script in ('F', '$p', 'N;N;s/\\x00/|/g', '1h;$G', 'R ' + str(d/'r'), 'r ' + str(d/'r')):
        for opts in (['-z'], ['-z', '-s']):
            parity([*opts, script, d/'one', d/'two'])
    # -i -z edits records in place; backup bytes are the original operands.
    left, right = d/'left', d/'right'
    for data in (b'a\0b', b'x\ny\0z\0'):
        left.write_bytes(data); right.write_bytes(data)
        a = run(['-z', '-i.orig', 's/^/</;$a end', left])
        g = gnu(['-z', '-i.orig', 's/^/</;$a end', right])
        check(('-z -i', data), (a.returncode, left.read_bytes(), Path(str(left)+'.orig').read_bytes()),
              (g.returncode, right.read_bytes(), Path(str(right)+'.orig').read_bytes()))

# 4. -z keeps exact consumption on a pipe whose producer stays open: $ looks
#    ahead without removing the next NUL-terminated record's first byte.
for data, script, consumed in [(b'a\0b\0c\0', '$p;1q', 2), (b'a\0\nb\0', '$!q', 2),
                               (b'a\0b\0c', 'N;$!q', 4), (b'a\0\0', '1q', 2)]:
    readfd, writefd = os.pipe()
    os.write(writefd, data)
    proc = subprocess.Popen([binary, '-c', prefix+'sed -z "$1"', '_', script], stdin=readfd,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        out, err = proc.communicate(timeout=5)
        os.set_blocking(readfd, False)
        rest = os.read(readfd, 65536)
        check(('-z pipe consumption', script, data), (proc.returncode, rest), (0, data[consumed:]))
    finally:
        if proc.poll() is None: proc.kill(); proc.wait()
        os.close(readfd); os.close(writefd)

# 5. --sandbox rejects e, r, R, w, W and the s///e and s///w flags before any
#    output file is opened; other commands still run.
with tempfile.TemporaryDirectory(prefix='opus-sed-sandbox-') as tmp:
    d = Path(tmp)
    for i, script in enumerate(['w {}', 'W {}', 's/a/b/w {}', 'r {}', 'R {}', 'e echo', 's/a/b/e',
                                'p;w {}', '1{w {}\n}']):
        target = d/f'out{i}'
        a = run(['--sandbox', script.replace('{}', str(target))], b'a\n')
        a_created = target.exists()
        g = gnu(['--sandbox', script.replace('{}', str(target))], b'a\n')
        check(('sandbox', script), (a.returncode, a.stdout, a_created, b'sandbox' in a.stderr),
              (g.returncode, g.stdout, target.exists(), True))
    for script in ('p', 's/a/b/g', 'y/a/b/', 'N;P;D', '$=', 'l'):
        parity(['--sandbox', script], b'a\nb\n')

# 6. --follow-symlinks edits the final target and names it like GNU sed
#    (a relative target is relative to the link's directory). Without it,
#    -i reads through a symlink and replaces the link itself.
def tree(root):
    root.mkdir()
    (root/'t').write_bytes(b'a\n'); (root/'u').write_bytes(b'u\n')
    (root/'sub').mkdir()
    os.symlink('t', root/'l'); os.symlink('../t', root/'sub/rel'); os.symlink('l', root/'chain')
    os.symlink('missing', root/'dangling'); os.symlink('loop1', root/'loop2'); os.symlink('loop2', root/'loop1')


def state(root):
    out = {}
    for path in sorted(root.rglob('*')):
        rel = str(path.relative_to(root))
        out[rel] = ('link', os.readlink(path)) if path.is_symlink() else \
                   ('dir',) if path.is_dir() else ('file', path.read_bytes(), oct(path.stat().st_mode & 0o777))
    return out


cases = [['-n', '--follow-symlinks', 'F', 'l', 'sub/rel', 'chain', 'u'], ['-n', 'F', 'l', 'sub/rel'],
         ['-s', '-n', '--follow-symlinks', '$F', 'chain', 'u'],
         ['-i', 's/a/b/', 'l'], ['-i.bak', 's/a/b/', 'sub/rel'],
         ['-i', '--follow-symlinks', 's/a/c/', 'l'], ['-i.bak', '--follow-symlinks', 's/a/c/;F', 'sub/rel'],
         ['-i', '--follow-symlinks', 's/a/c/', 'chain', 'u'],
         ['-i', '--follow-symlinks', 'p', 'dangling'], ['-i', '--follow-symlinks', 'p', 'loop1'],
         ['-n', '--follow-symlinks', 'p', 'dangling'], ['-i', 'p', 'dangling'], ['-i', 'p', 'sub']]
for args in cases:
    with tempfile.TemporaryDirectory(prefix='opus-sed-links-') as tmp:
        left, right = Path(tmp)/'left', Path(tmp)/'right'
        tree(left); tree(right)
        a, g = run(args, cwd=left), gnu(args, cwd=right)
        check(('symlinks', args), (a.returncode == 0, a.stdout, state(left)),
              (g.returncode == 0, g.stdout, state(right)))
        if g.returncode == 4:
            check(('symlink error status', args), a.returncode, 4)

# 7. z empties the pattern space; v accepts versions up to 4.9; e COMMAND
#    output precedes the cycle (execution remains gated).
for script in ('z;s/^$/E/', 'z', '$!z', 'v', 'v 4.2', 'v 4.9;p', 'v4.2.2', 'v 4.10', 'v 5', 'v x',
               'v 4.9.1', '1{v\n}', 'z5'):
    parity([script], b'a\nb\n')
allow = {'BASHSED_ALLOW_EXEC': '1'}
for script in ('e printf X', 'e echo hi', '1e echo hi; echo there', 'e   ', '1{e\n}', '$!e printf "[%s]" one',
               'e printf X\np', 's/^/echo /e', 'e', 's/^//e', 'x;s/^/echo/e', 'N;s/^//e',
               's/$//e', 's/a$//e', 's/^/ /e', 's/x*//e', 's/x*//2e', 's/^//ge', 's/echo//e'):
    for opts in ([], ['-n'], ['-z']):
        for data in (b'echo a\necho b\n', b'echo a', b'printf a\n', b'echo;echo\n', b'echo a\0',
                     b'printf "a\\0"\0', b'printf "a\\0"'):
            parity([*opts, script], data, allow)
a = run(['e echo hi'], b'a\n')
check('e COMMAND stays gated', (a.returncode, a.stdout), (1, b''))

# 8. w /dev/stdout keeps its own pending-newline state, as in GNU sed.
for script in ('p;w /dev/stdout', 'W /dev/stdout', 'w /dev/stdout', '$!d;w /dev/stdout'):
    for data in (b'a', b'a\nb', b'a\nb\n'):
        parity([script], data)
        parity(['-z', script], data.replace(b'\n', b'\0'))

# 9. Option surface: -b/--binary is a no-op, --version succeeds, and --posix
#    and --debug are explicit, tested limits: rejected with status 1.
for args in (['-b', 'p'], ['--binary', 'p'], ['-nbz', 'p']):
    parity(args, b'a\nb\0')
a = run(['--version'])
check('--version', (a.returncode, a.stdout.split(b'\n')[0].startswith(b'sed ')), (0, True))
for option in ('--posix', '--debug', '--no-such-option'):
    a = run([option, 'p'], b'a\n')
    check(('unsupported option', option), (a.returncode, a.stdout, b'unsupported option' in a.stderr), (1, b'', True))

# 10. One persistent shell, empty PATH: -z, --sandbox and --follow-symlinks
#     never leak into later calls; failures in between recover cleanly.
with tempfile.TemporaryDirectory(prefix='opus-sed-state-') as tmp:
    d = Path(tmp)
    (d/'t').write_bytes(b'a\nb\n'); os.symlink('t', d/'l')
    got = run([d], script='''cd "$1" || exit 9
ulimit -n 32
for ((i=0;i<64;i++)); do
  printf 'a\\0b\\0' | sed -z '$!d' > z || exit 10
  [[ $(sed -n l z) == 'b\\000$' ]] || exit 11
  [[ $(printf 'a\\nb\\n' | sed '$!d') == b ]] || exit 12
  sed --sandbox 'w out' t 2>/dev/null && exit 13
  sed -n 'w out' t || exit 14
  [[ -f out ]] || exit 15; rm out
  sed -n --follow-symlinks F l >/dev/null || exit 16
  [[ $(sed -n 1F l) == l ]] || exit 17
  sed -n '\\,a,p' t >/dev/null || exit 18
  sed --posix p t >/dev/null 2>&1 && exit 19
  sed 's1a1[\\1]1' t >/dev/null || exit 20
  printf 'a\\0b' | sed -z p >/dev/full 2>/dev/null; [[ $? == 4 ]] || exit 22
  BASHSED_ALLOW_EXEC=1 sed 'e printf X' t >/dev/full 2>/dev/null; [[ $? == 4 ]] || exit 23
  sed --follow-symlinks -n 'F;p' l >/dev/full 2>/dev/null; [[ $? == 4 ]] || exit 24
done
[[ -L l ]] || exit 21
sed -n '\\,b,p' l''')
    check('persistent state', (got.returncode, got.stdout), (0, b'b\n'))

print(f'opus-sed-followup-gnu: {checks} checks, {failures} failures', flush=True)
raise SystemExit(bool(failures))
