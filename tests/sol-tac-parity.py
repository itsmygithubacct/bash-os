#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded backward reads, GNU regex semantics, spool ownership and FD state."""
import argparse
import os
from pathlib import Path
import random
import resource
import subprocess
import tempfile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=lambda s: str(Path(s).resolve()))
    ap.add_argument('--module', help='Optional replacement for sanitizer runs')
    args = ap.parse_args()
    env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
    prefix = 'enable -f "$TAC_MODULE" tac || exit; ' if args.module else ''
    if args.module:
        env['TAC_MODULE'] = str(Path(args.module).resolve())
    checks = 0
    with tempfile.TemporaryDirectory(prefix='sol-tac-') as directory:
        root = Path(directory)
        env['TMPDIR'] = str(root / 'spools')
        Path(env['TMPDIR']).mkdir()
        source = root / 'input'

        def run(tool, options, data=None, script='"$@"', **kw):
            p = subprocess.run([args.binary, '--noprofile', '--norc', '-c', prefix+script,
                                '_', tool, *map(str, options)], input=data, env=env,
                               capture_output=True, timeout=60, **kw)
            assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
            return p

        def compare(options, data, mode='pipe'):
            nonlocal checks
            source.write_bytes(data)
            opts = [*options, source] if mode == 'file' else options
            actual = run('tac', opts, data if mode == 'pipe' else None)
            expected = run('/usr/bin/tac', opts, data if mode == 'pipe' else None)
            assert (actual.returncode, actual.stdout) == (expected.returncode, expected.stdout), (
                options, mode, len(data), actual.returncode, expected.returncode,
                actual.stdout[:100], expected.stdout[:100], actual.stderr)
            assert not list(Path(env['TMPDIR']).iterdir())
            checks += 1

        # Check every alignment of several overlapping separators at the read
        # edges; include separators longer than the scanner block itself.
        for sep in ['::END::', 'ababa', 'x'*65539+'!']:
            raw = sep.encode()
            for shift in [-2,-1,0,1,2]:
                data = b'A'*(65536+shift) + raw + b'B'*65535 + raw + b'tail'
                for before in [[], ['-b']]:
                    for mode in ['file', 'pipe']:
                        compare([*before, '-s', sep], data, mode)

        # Put the separator across the exact left edge of the first search
        # window: base = input_size - separator_size - block_size + 1.
        # No other separator can cause a cache refill before this split.
        for sep in ['::END::', 'ababa']:
            raw = sep.encode()
            size = 2*65536+13
            base = size-len(raw)-65536+1
            for split in range(1,len(raw)):
                pos = base-split
                data = b'A'*pos + raw + b'B'*(size-pos-len(raw))
                for before in [[], ['-b']]:
                    for mode in ['file','pipe']:
                        compare([*before,'-s',sep],data,mode)

        # GNU Emacs syntax, reverse matching, empty matches, newline anchors,
        # NUL and character classes all have distinct byte-level oracles.
        patterns = ['[,:]+', '.', '.+', '.*', '.?', '[^x]', '[,:]*', '[,:]?',
                    '\\(ab\\|a\\)', 'a|b', '[[:alpha:]]', '^', '$', 'x*',
                    'a.*z', 'a\\(b*\\)\\1', '\\`', "\\'", '\\b', '\\w+',
                    'a{2}', 'a\\{2\\}', 'ab?', '']
        datasets = [b'', b'a,b::c', b'a\nb\0c\n\xfftail', b'aaaabbbabbbz',
                    b'\0\0\n', b'A'*65534+b'\n::x,\0abz\n'+b'z'*20]
        for pattern in patterns:
            for data in datasets:
                for before in [[], ['-b']]:
                    for mode in ['file', 'pipe']:
                        compare([*before, '-r', '-s', pattern], data, mode)
        other = root / 'other'
        other.write_bytes(b'A'*50000+b'\nBBBB\nCCCC')
        for pattern in ['^','$','\\`',"\\'",'a.*z','\\(a\\|b\\)']:
            for before in [[], ['-b']]:
                compare([*before,'-r','-s',pattern,other], b'a\nbbb\nccc', 'file')
        rng = random.Random(20261019)
        for _ in range(100):
            data = bytes(rng.choice(b'abx\n\0,:z') for _ in range(rng.randrange(300)))
            compare(['-r','-s',rng.choice(patterns[:-1])], data)

        # Individual records much larger than the read buffer must not require
        # retaining the growing record. Byte-compare both disk and pipe paths.
        for options in [[], ['-s','::'], ['-r','-s','[,:]+'], ['-r','-s','z']]:
            data = b'A'*(8*1024*1024)+b'::'+b'B'*(8*1024*1024)+b',tail'
            for mode in ['file','pipe']:
                compare(options, data, mode)

        source.write_bytes(b'a\nb\n')
        # GNU seeks to the start of seekable stdin on every '-' operand,
        # regardless of its incoming file offset. Pipes are consumed once.
        for script in ['exec 0<"$2"; "$1" - -',
                       'exec 0<"$2"; IFS= read -r line; "$1" -']:
            got = run('tac', [source], script=script)
            ref = run('/usr/bin/tac', [source], script=script)
            assert (got.returncode,got.stdout)==(ref.returncode,ref.stdout), (got,ref)
            checks += 1
        script = '\n'.join([
            'for ((i=0;i<10;i++)); do',
            '  "$1" -r -s "[,:]+" "$2" || exit',
            '  "$1" -r -s "\\\\(a\\\\|b\\\\)" "$2" || exit',
            '  "$1" -r -s "[" "$2" >/dev/null 2>/dev/null; [[ $? != 0 ]] || exit 41',
            '  [[ aa =~ ^a+$ ]] || exit 42',
            'done'])
        got = run('tac',[source],script=script)
        ref = run('/usr/bin/tac',[source],script=script)
        assert (got.returncode,got.stdout)==(ref.returncode,ref.stdout),(got,ref)
        checks += 1
        # Closed fd 0 may be reused by an owned file or spool. Never confuse
        # descriptor number with ownership, or retain an invocation's FD.
        script = '''exec 0<&-
for ((i=0;i<80;i++)); do
  "$1" "$2" >/dev/null || exit
  [[ ! -e /proc/self/fd/0 ]] || exit 40
done
'''
        assert run('tac',[source],script=script).returncode == 0
        checks += 1
        script = '''before=(/proc/$$/fd/*)
for ((i=0;i<40;i++)); do
  exec 8< <(printf 'a\\nb\\n')
  tac <&8 >/dev/null || exit
  exec 8<&-
  [[ a =~ a ]] || exit 43
done
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]]
'''
        assert run('tac',[],script=script).returncode == 0
        checks += 1
        # Temp creation failure, recovery, read error and output failure all
        # leave the spool directory empty and the persistent shell usable.
        script = '''saved=$TMPDIR; export TMPDIR=$saved/missing
exec 8< <(printf 'a\\nb\\n')
tac <&8 >/dev/null 2>/dev/null; rc=$?; exec 8<&-
[[ $rc == 1 ]] || exit 42
export TMPDIR=$saved
exec 8< <(printf 'a\\nb\\n')
tac <&8 || exit; exec 8<&-
'''
        p = run('tac',[],script=script)
        assert (p.returncode,p.stdout)==(0,b'b\na\n'),p
        checks += 1
        p = run('tac',[], b'x'*10000, script='trap "" XFSZ; ulimit -Sf 1; tac >/dev/null 2>/dev/null; [[ $? == 1 ]]')
        assert p.returncode == 0,p
        checks += 1
        for redirect in ['>/dev/full', '1>&-']:
            p = run('tac',[],b'a\nb\n',script=f'trap "" PIPE; tac {redirect} 2>/dev/null; [[ $? == 1 ]]')
            assert p.returncode == 0,p
            checks += 1
        p = run('tac',[],script='exec 0<&-; tac 2>/dev/null; [[ $? == 1 ]]')
        assert p.returncode == 0,p
        checks += 1
        assert not list(Path(env['TMPDIR']).iterdir())
        # Literal massive input under a strict address-space limit: an
        # independent GNU output oracle is calculated without the limit.
        if not args.module:
            source.write_bytes(b'A'*(48*1024*1024)+b'\nB\n')
            def limit_memory():
                resource.setrlimit(resource.RLIMIT_AS,(32*1024*1024,)*2)
            for options in [[], ['-r','-s','[,:]+']]:
                expected = run('/usr/bin/tac',[*options,source])
                actual = run('tac',[*options,source],preexec_fn=limit_memory)
                assert (actual.returncode,actual.stdout)==(0,expected.stdout),actual.stderr
                checks += 1
                actual = run('tac',options,source.read_bytes(),preexec_fn=limit_memory)
                assert (actual.returncode,actual.stdout)==(0,expected.stdout),actual.stderr
                assert not list(Path(env['TMPDIR']).iterdir())
                checks += 1
    print(f'sol-tac: {checks} GNU-byte, boundary, ownership and memory checks passed')


if __name__ == '__main__':
    main()
