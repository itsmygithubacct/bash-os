#!/usr/bin/env python3
"""Byte-preserving join regression and deterministic GNU differential checks."""
import itertools
import os
from pathlib import Path
import random
import re
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(PATH='', LC_ALL='C')
checks = 0
native = os.environ.get('SOL_JOIN_NATIVE') == '1'

def run(args, script='join "$@"', data=None):
    if native:
        assert script == 'join "$@"'
        return subprocess.run([binary, *args], input=data, capture_output=True,
                              env=dict(env, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                       UBSAN_OPTIONS='halt_on_error=1'), timeout=10)
    return subprocess.run([binary, '--noprofile', '--norc', '-c', script, '_', *args],
                          input=data, capture_output=True, env=env, timeout=10)

with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    def case(label, left, right, opts=(), expected=None):
        global checks
        Path('left').write_bytes(left)
        Path('right').write_bytes(right)
        args = [*opts, 'left', 'right']
        ref = subprocess.run(['/usr/bin/join', *args], capture_output=True, env=env)
        got = run(args)
        assert ref.returncode == 0 and not ref.stderr, (label, ref.stderr)
        if expected is not None:
            assert ref.stdout == expected, (label, 'independent oracle', ref.stdout[:100])
        assert (got.returncode, got.stdout, got.stderr) == (0, ref.stdout, b''), (
            label, got.returncode, got.stderr, got.stdout[:100], ref.stdout[:100])
        checks += 1

    case('both empty', b'', b'', expected=b'')
    case('one empty', b'a L\n', b'', ['-a1'], expected=b'a L\n')
    case('Cartesian 3 by 2 plus next group', b'a L1\na L2\na L3\nb L4\n',
         b'a R1\na R2\nb R3\n', expected=b''.join(
             b'a '+l+b' '+r+b'\n' for l, r in itertools.product(
                 [b'L1', b'L2', b'L3'], [b'R1', b'R2']))+b'b L4 R3\n')
    for opts in ([], ['-a1'], ['-a2'], ['-a1', '-a2'], ['-v1'], ['-v2'],
                 ['-v1', '-v2'], ['-a1', '-v2'],
                 ['-a1', '-a2', '-e', '_', '-o', '0,1.2,2.2,1.8,2.8'],
                 ['-a1', '-a2', '-o', 'auto', '-e', '_']):
        case('empty/missing '+str(opts), b'\n\na L\nb\nd D\n', b'\na R\nc C\n', opts)
        case('delimiter '+str(opts), b':L:\n:L2\na::\nb:B\nd:D:\n',
             b':R:\na:R:\nc::\n', ['-t:', *opts])
    for sep in (b':', b'\t', b'\xff'):
        case('byte delimiter', b'a'+sep+b'L'+sep+b'\nb'+sep+b'B\n',
             b'a'+sep+b'R\n', ['-t', os.fsdecode(sep), '-a1', '-e', '_'])
    case('NUL in fields and keys', b'a\x00x L\na\x00y M\nb B\n',
         b'a\x00x R\na\x00y S\n', ['-a1'])
    case('binary custom fields', b'a:L\x00X:\nb:B:\n', b'a:R\x00Y:\n',
         ['-t:', '-a1', '-e', '_', '-o', '0,1.2,2.2,1.3'])
    case('CR preserved', b'a L\r\n', b'a R\r\n', expected=b'a L\r R\r\n')
    case('unterminated long fields', b'a '+b'x'*262144, b'a '+b'y'*131073,
         expected=b'a '+b'x'*262144+b' '+b'y'*131073+b'\n')
    longkey = b'k'*131072
    case('long keys with differing suffixes', longkey+b'a L\n'+longkey+b'b M\n',
         longkey+b'a R\n'+longkey+b'b S\n',
         expected=longkey+b'a L R\n'+longkey+b'b M S\n')
    case('many fields', b' '.join([b'a']+[b'L']*150)+b'\n',
         b' '.join([b'a']+[b'R']*160)+b'\n')
    case('auto many fields', b' '.join([b'a']+[b'L']*150)+b'\n',
         b' '.join([b'a']+[b'R']*160)+b'\n', ['-o', 'auto'])
    case('large join index', b' '.join([b'L']*100+[b'key'])+b'\n',
         b'key R\n', ['-1', '101', '-o', '0,1.100,2.2'])
    fmt = ','.join(['1.2']*150)
    case('many output fields', b'a L\n', b'a R\n', ['-o', fmt])
    case('huge join index means missing', b'a L\n', b'a R\n',
         ['-j', '999999999999999999999'], expected=b' a L a R\n')
    case('huge output index means missing', b'a L\n', b'a R\n',
         ['-o', '1.2147483648,2.999999999999999999999', '-e', '_'], expected=b'_ _\n')
    case('header and casefold', b'Key L\na X\nB Y\n', b'Other R\nA Z\nb W\n',
         ['--header', '-i'])
    rng = random.Random(20261019)
    for i in range(160):
        sep = rng.choice([b' ', b':', b'\t'])
        left, right = [], []
        for k in range(8):
            for dest in (left, right):
                for n in range(rng.randrange(6)):
                    dest.append(sep.join([str(k).encode()]+[
                        rng.choice([b'', b'v', b'\x00x', b'q\r', b'x'*200])
                        for _ in range(rng.randrange(5))])+b'\n')
        opts = ['-t', sep.decode(), '-a1', '-a2']
        if i % 2:
            opts += ['-e', '_', '-o', '0,1.2,2.2,1.7']
        case('seeded '+str(i), b''.join(left), b''.join(right), opts)

    for opts, left, right in [
        (['--check-order'], b'b L\na M\x00tail\n', b'a R\nb S\n'),
        (['--check-order', '-t:', '-j2'], b'L:b\nM:a\n', b'R:a\nS:b\n'),
        (['--check-order'], b'a\nb\na\n', b'a\nb\nc\n'),
        ([], b'b L\na M\x00tail\n', b'a R\nb S\n')]:
        Path('left').write_bytes(left)
        Path('right').write_bytes(right)
        args = [*opts, 'left', 'right']
        ref = subprocess.run(['/usr/bin/join', *args], capture_output=True, env=env)
        got = run(args)
        norm = lambda data: re.sub(rb'^.*?: line [0-9]+: ', b'',
                                  data.replace(b'/usr/bin/join: ', b'join: '), flags=re.M)
        assert (got.returncode, got.stdout, norm(got.stderr)) == (
            ref.returncode, ref.stdout, norm(ref.stderr)), (
                'binary order error', opts, got.returncode, ref.returncode,
                got.stdout, ref.stdout, got.stderr, ref.stderr)
        checks += 1

    Path('left').write_bytes(b'a L\nb B\n')
    Path('right').write_bytes(b'a R\n')
    # All invocations share the same shell; stdin EOF and failed stdout must reset.
    args = ['left', 'right']
    script = '''before=(/proc/$$/fd/*)
for ((i=0;i<80;i++)); do
  join left nonexistent 2>error && exit 93
  join . right 2>error && exit 94
  join - right <left || exit
  join left - <right || exit
  join left right || exit
done
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]] || exit 90
join left right >/dev/full 2>error && exit 91
join left right
join -a1 - /dev/null < <(printf 'z Z\n') >/dev/full 2>error && exit 92
join left right
'''
    if native:
        got = subprocess.run([binary, *args], capture_output=True,
                             env=dict(env, SOL_JOIN_REPEAT='80', ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                      UBSAN_OPTIONS='halt_on_error=1'))
        assert (got.returncode, got.stdout, got.stderr) == (0, b'a L R\n'*80, b''), got
    else:
        got = run(args, script)
        assert (got.returncode, got.stdout, got.stderr) == (0, b'a L R\n'*242, b''), (
            'repeated streams/FDs/output recovery', got.returncode, got.stderr, len(got.stdout))
    checks += 1
    for opts in (['-1', '0'], ['-j', '-1'], ['-2', '12bad'],
                 ['-o', '1.0'], ['-o', '1.2garbage'], ['-o', '1.2,,2.2'], ['-o', ''],
                 ['-t', 'ab'], ['-a', '3'], ['-v'], ['--unknown']):
        got = run([*opts, *args])
        assert got.returncode != 0 and got.stderr, (opts, got.returncode, got.stderr)
        checks += 1
    got = run(['.', 'right'])
    assert got.returncode != 0 and got.stderr, ('input read failure', got.returncode)
    checks += 1
print(f'sol-join-check: {checks} checks passed ('+
      ('native sanitizer; repeated calls' if native else 'empty PATH; repeated streams, FDs and output recovery')+')')
