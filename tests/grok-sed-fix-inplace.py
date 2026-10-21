#!/usr/bin/env python3
"""In-place edits stay on the directory that was opened.

An injected open/openat moves the parent directory after it is opened, and a
second run replaces the directory entry before the final rename. The edit must
land in the original directory, or fail without changing the replacement.
Pathname rename follows the moved path and fails these checks.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
here = Path(__file__).resolve().parent
env_base = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C')
checks = failures = 0


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:400], 'expected', repr(expected)[:400], flush=True)


so = Path(tempfile.mkdtemp(prefix='grok-sed-preload-')) / 'inplace.so'
built = subprocess.run(
    ['gcc', '-shared', '-fPIC', '-O2', '-o', str(so), str(here / 'grok-sed-fix-inplace-preload.c'), '-ldl'],
    capture_output=True, text=True)
if built.returncode != 0:
    print(built.stderr)
    sys.exit(1)


def sed_i(root, script, rel, mode, parent):
    env = dict(env_base, LD_PRELOAD=str(so), BS_INPLACE_PARENT=str(parent),
               BS_INPLACE_FILE='payload.dat', BS_INPLACE_MODE=mode)
    return subprocess.run(
        [binary, '--noprofile', '--norc', '-c',
         ('' if os.environ.get('ASAN_OPTIONS') else 'ulimit -v 524288; ')
         + 'sed -i "$1" "$2"', '_', script, rel],
        cwd=root, capture_output=True, env=env, timeout=15)


token = os.urandom(4).hex()
root = Path(tempfile.mkdtemp(prefix='grok-sed-inplace-'))
parent = root / f'bsedir-{token}'
parent.mkdir()
payload = parent / 'payload.dat'
payload.write_bytes(b'old\n')
renamed = sed_i(root, 's/old/EDIT/', str(payload.relative_to(root)), 'rename-parent', parent)
moved = Path(str(parent) + '.moved') / 'payload.dat'
decoy = parent / 'payload.dat'
check('rename-parent status', renamed.returncode, 0)
check('rename-parent original', moved.read_bytes() if moved.exists() else None, b'EDIT\n')
check('rename-parent decoy', decoy.read_bytes() if decoy.exists() else None, b'DECOY\n')
if renamed.returncode != 0:
    print('rename-parent stderr', renamed.stderr[-400:])

root2 = Path(tempfile.mkdtemp(prefix='grok-sed-inplace-'))
parent2 = root2 / f'bsedir-{token}'
parent2.mkdir()
payload2 = parent2 / 'payload.dat'
payload2.write_bytes(b'old\n')
swapped = sed_i(root2, 's/old/EDIT/', str(payload2.relative_to(root2)), 'swap-entry', parent2)
check('swap-entry status', swapped.returncode != 0, True)
check('swap-entry bytes', payload2.read_bytes() if payload2.exists() else None, b'SAFE\n')
leftover = [p.name for p in parent2.iterdir() if p.name.startswith('.bsed')]
check('swap-entry temp removed', leftover, [])
if swapped.returncode == 0:
    print('swap-entry unexpectedly succeeded', swapped.stderr[-200:])

# Ordinary replacement and follow behavior stay aligned with GNU sed.
gnu_env = dict(env_base)
link_root = Path(tempfile.mkdtemp(prefix='grok-sed-links-'))
for side in ('L', 'R'):
    d = link_root / side
    d.mkdir()
    (d / 't').write_bytes(b'a\n')
    (d / 'sub').mkdir()
    os.symlink('t', d / 'l')
    os.symlink('../t', d / 'sub' / 'rel')


def tree_state(d):
    out = []
    for path in sorted(d.rglob('*')):
        rel = str(path.relative_to(d))
        if path.is_symlink():
            out.append((rel, 'link', os.readlink(path)))
        elif path.is_file():
            out.append((rel, 'file', path.read_bytes()))
    return out


for args in (['-i', 's/a/Z/', 'l'], ['-i.bak', '--follow-symlinks', 's/a/Z/;F', 'sub/rel']):
    for side, prog in (('L', [binary, '--noprofile', '--norc', '-c', 'sed "$@"', '_', *args]),
                       ('R', ['/usr/bin/sed', *args])):
        subprocess.run(prog, cwd=link_root / side, capture_output=True, env=gnu_env, timeout=10)
check('symlink parity', tree_state(link_root / 'L'), tree_state(link_root / 'R'))

print(f'{checks - failures}/{checks} passed')
sys.exit(1 if failures else 0)
