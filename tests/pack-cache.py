#!/usr/bin/env python3
"""Check repeated pack reads using ordinary Git-produced private fixtures."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
git_binary = shutil.which('git')
move_binary = shutil.which('mv')
assert git_binary and move_binary, 'pack-cache requires git and mv'
checks = 0


def quote(value):
    return shlex.quote(str(value))


def git(root, *args, data=None):
    env = {**os.environ, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull}
    result = subprocess.run([git_binary, '-C', str(root), '-c', 'pack.threads=1',
                             *map(str, args)], input=data, capture_output=True,
                            timeout=30, env=env)
    assert result.returncode == 0, (args, result.stderr[:2000])
    return result.stdout


def make_pack(root, name, bodies):
    shas = [git(root, 'hash-object', '-w', '--stdin', data=body).strip().decode()
            for body in bodies]
    prefix = root/name
    digest = git(root, 'pack-objects', '--compression=0', '--window=0', prefix,
                 data=('\n'.join(shas)+'\n').encode()).strip().decode()
    return Path(f'{prefix}-{digest}.pack'), Path(f'{prefix}-{digest}.idx'), shas


def cat(pack, index, sha, output):
    return f'pack cat {quote(pack)} {quote(index)} {quote(sha)} > {quote(output)}\n'


def run(root, script, expected):
    global checks
    # Each scenario keeps all its reads in one Bash process, exercising reuse.
    script = '[ "$(type -t pack)" = builtin ]\n'+script
    result = subprocess.run([binary, '--noprofile', '--norc', '-e', '-o',
                             'pipefail', '-c', script], cwd=root,
                            capture_output=True, timeout=40,
                            env={**os.environ, 'LC_ALL': 'C'})
    assert result.returncode == 0, (result.returncode, result.stderr[:4000])
    assert result.stdout == b'', result.stdout[:1000]
    assert b'AddressSanitizer' not in result.stderr, result.stderr[:4000]
    assert b'runtime error:' not in result.stderr, result.stderr[:4000]
    checks += 1
    for path, content in expected.items():
        assert (root/path).read_bytes() == content, path
        checks += 1


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    git(root, 'init', '-q', '--object-format=sha1')
    a = [b'first alpha\n'*128, b'second beta\n'*128, bytes(range(256))*16]
    b = [b'first ALPHA\n'*128, b'second BETA\n'*128,
         bytes(reversed(range(256)))*16]
    pa, ia, sa = make_pack(root, 'a', a)
    pb, ib, sb = make_pack(root, 'b', b)
    assert pa.stat().st_size == pb.stat().st_size

    alias = root/'alias.pack'
    shutil.copyfile(pa, alias)
    script = cat(pa, ia, sa[0], 'first')+cat(pa, ia, sa[1], 'second')
    script += cat(alias, ia, sa[2], 'alias')+cat(pa, ia, sa[0], 'again')
    run(root, script, {'first': a[0], 'second': a[1], 'alias': a[2], 'again': a[0]})

    # Replace the same path with equal-sized valid content and preserve mtime.
    stamp = 1700000000000000000
    for path in [pa, ia, pb, ib]:
        os.utime(path, ns=(stamp, stamp))
    for source, name in [(pa, 'active.pack'), (ia, 'active.idx'),
                         (pb, 'next.pack'), (ib, 'next.idx'),
                         (pa, 'last.pack'), (ia, 'last.idx')]:
        shutil.copy2(source, root/name)
    active, index = root/'active.pack', root/'active.idx'
    script = cat(active, index, sa[0], 'before')
    script += f'{quote(move_binary)} -f next.pack active.pack\n'
    script += f'{quote(move_binary)} -f next.idx active.idx\n'
    script += cat(active, index, sb[0], 'replaced')+cat(active, index, sb[1], 'reused')
    script += f'{quote(move_binary)} -f last.pack active.pack\n'
    script += f'{quote(move_binary)} -f last.idx active.idx\n'
    script += cat(active, index, sa[2], 'restored')
    run(root, script, {'before': a[0], 'replaced': b[0], 'reused': b[1],
                       'restored': a[2]})
    assert active.stat().st_mtime_ns == index.stat().st_mtime_ns == stamp
    checks += 1

    # Valid, mismatched indexes still fail before and after a successful read.
    mismatch = (f'if {cat(pa, ib, sa[0], "mismatch").strip()}; then exit 90; '
                'else status=$?; [ "$status" -eq 1 ]; fi\n')
    script = mismatch+cat(pa, ia, sa[0], 'matched')+mismatch
    script += cat(pa, ia, sa[1], 'after-mismatch')
    run(root, script, {'mismatch': b'', 'matched': a[0], 'after-mismatch': a[1]})

    # Exercise the uncached path above the 8 MiB snapshot cap, then a small pack.
    # Compression is disabled so this ordinary payload remains above the cap.
    large = bytes(range(256))*(8*1024*1024//256+17)
    pl, il, sl = make_pack(root, 'large', [large])
    assert pl.stat().st_size > 8*1024*1024
    script = cat(pa, ia, sa[0], 'small-before')
    script += cat(pl, il, sl[0], 'large-first')+cat(pl, il, sl[0], 'large-again')
    script += cat(pa, ia, sa[1], 'small-after')
    run(root, script, {'small-before': a[0], 'large-first': large,
                       'large-again': large, 'small-after': a[1]})

print(f'pack-cache: {checks} checks passed')
