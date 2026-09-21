#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""bench/git-scale.py [FILES] [COMMITS] — the git builtin at real scale.

A repository of the shape a long-lived one has — a few thousand files, a
few thousand commits over them — built from sha1 and zlib alone, so no git
is needed to make it. Each command then runs through this build and
through git, with wall time and peak resident memory for both; a clone
runs over the protocol on both sides, since a local clone git is allowed
to hardlink measures nothing.

It writes a few hundred megabytes into a temporary directory and takes a
minute or two, which is why it is here and not in the test suite.
"""
import hashlib
import os
from pathlib import Path
import random
import resource
import shutil
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
BINARY = str(ROOT/'out'/'bash')
GIT = shutil.which('git')
WORDS = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta']
ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1', 'PATH': '/usr/bin:/bin',
       'GIT_AUTHOR_NAME': 'Scale Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Scale Committer',
       'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def build(root, files, commits):
    work = root/'repo'
    store = work/'.git'/'objects'
    local = random.Random(20260921)
    stamp = 1750000000

    def keep(kind, body):
        raw = kind+b' '+str(len(body)).encode()+b'\0'+body
        sha = hashlib.sha1(raw).hexdigest()
        directory = store/sha[:2]
        directory.mkdir(parents=True, exist_ok=True)
        target = directory/sha[2:]
        if not target.exists():
            target.write_bytes(zlib.compress(raw, 1))
        return sha

    def tree_of(entries):
        body = b''
        for name in sorted(entries, key=lambda n: n.encode()
                           + (b'/' if entries[n][0] == '40000' else b'')):
            mode, sha = entries[name]
            body += mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)
        return keep(b'tree', body)

    def text():
        return ''.join(' '.join(local.choice(WORDS) for _ in range(9))+'\n'
                       for _ in range(14))

    print(f'building {files} files and {commits} commits...', flush=True)
    started = time.monotonic()
    directories = {}
    for i in range(files):
        where, name = 'dir%02d' % (i % 64), 'file-%05d.txt' % i
        (work/where).mkdir(parents=True, exist_ok=True)
        body = text()
        (work/where/name).write_text(body)
        directories.setdefault(where, {})[name] = ('100644', keep(b'blob', body.encode()))
    subtrees = {name: ('40000', tree_of(entries))
                for name, entries in directories.items()}
    tree = tree_of(subtrees)

    parent = None
    for n in range(commits):
        if n:
            which = local.randrange(files)
            where, name = 'dir%02d' % (which % 64), 'file-%05d.txt' % which
            body = text()
            (work/where/name).write_text(body)
            directories[where][name] = ('100644', keep(b'blob', body.encode()))
            subtrees[where] = ('40000', tree_of(directories[where]))
            tree = tree_of(subtrees)
        when = stamp+n*60
        commit = 'tree %s\n' % tree
        if parent:
            commit += 'parent %s\n' % parent
        commit += ('author Scale Author <author@bash-os.test> %d +0000\n'
                   'committer Scale Committer <committer@bash-os.test> %d +0000\n'
                   '\ncommit number %d\n' % (when, when, n))
        parent = keep(b'commit', commit.encode())
    (work/'.git'/'refs'/'heads').mkdir(parents=True, exist_ok=True)
    (work/'.git'/'HEAD').write_text('ref: refs/heads/main\n')
    (work/'.git'/'refs'/'heads'/'main').write_text(parent+'\n')

    for where, entries in directories.items():
        for name in entries:
            os.utime(work/where/name, (stamp, stamp))
    listing = sorted((f'{where}/{name}', sha)
                     for where, entries in directories.items()
                     for name, (mode, sha) in entries.items())
    body = b'DIRC'+struct.pack('>II', 2, len(listing))
    for path, sha in listing:
        info = os.stat(work/path)
        entry = struct.pack('>10I', int(info.st_ctime), info.st_ctime_ns % 10**9,
                            int(info.st_mtime), info.st_mtime_ns % 10**9,
                            info.st_dev & 0xffffffff, info.st_ino & 0xffffffff,
                            0o100644, info.st_uid, info.st_gid,
                            info.st_size & 0xffffffff)
        raw = path.encode()
        entry += bytes.fromhex(sha)+struct.pack('>H', min(len(raw), 0xfff))+raw
        entry += b'\0'*(8-(len(entry) % 8))
        body += entry
    body += hashlib.sha1(body).digest()
    (work/'.git'/'index').write_bytes(body)
    os.utime(work/'.git'/'index', (stamp+10, stamp+10))
    # A few files moved on, so status and diff have something to report.
    for i in range(0, files, files//20 or 1):
        path = work/('dir%02d' % (i % 64))/('file-%05d.txt' % i)
        path.write_text(path.read_text().replace('alpha', 'OMEGA'))
        os.utime(path, (stamp+20, stamp+20))
    print(f'  built in {time.monotonic()-started:.1f}s; '
          f'{sum(1 for _ in (work/".git"/"objects").rglob("*") if _.is_file())} '
          f'objects, {sum(f.stat().st_size for f in (work/".git").rglob("*") if f.is_file())/1e6:.0f} MB',
          flush=True)
    return work


def run(argv, cwd, label):
    """Wall time and peak resident memory for one command."""
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    started = time.monotonic()
    result = subprocess.run(argv, cwd=str(cwd), capture_output=True,
                            env={**ENV, 'HOME': str(cwd)}, timeout=3600)
    elapsed = time.monotonic()-started
    after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    peak = max(after, before)/1024
    assert result.returncode == 0, (label, result.returncode, result.stderr[:300])
    return elapsed, peak, len(result.stdout)


def main():
    files = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    commits = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    import tempfile
    holder = tempfile.mkdtemp(prefix='git-scale-')
    root = Path(holder)
    work = build(root, files, commits)

    ours = [BINARY, '--noprofile', '--norc', '-c', 'PATH=; git "$@"', 'git']
    theirs = [GIT]
    cases = [
        ('status --porcelain', ['status', '--porcelain']),
        ('log --oneline', ['log', '--oneline']),
        ('diff --stat', ['diff', '--stat']),
        ('add -A', ['add', '-A']),
        ('rev-list --count HEAD', ['rev-list', '--count', 'HEAD']),
    ]
    print(f'\n{"case":<24} {"bash-os":>10} {"git":>10} {"ratio":>7} '
          f'{"peak bash-os":>14} {"peak git":>10}')
    index = (work/'.git'/'index').read_bytes()
    for label, argv in cases:
        (work/'.git'/'index').write_bytes(index)
        mine, my_peak, my_out = run(ours+argv, work, 'ours '+label)
        (work/'.git'/'index').write_bytes(index)
        theirs_time, their_peak, their_out = run(theirs+argv, work, 'git '+label)
        print(f'{label:<24} {mine*1000:>9.0f}ms {theirs_time*1000:>9.0f}ms '
              f'{mine/theirs_time:>6.2f}x {my_peak:>13.0f}MB {their_peak:>9.0f}MB'
              + ('' if my_out == their_out else f'   (output {my_out} vs {their_out} bytes)'))
    (work/'.git'/'index').write_bytes(index)

    # And a clone, which is the protocol, a pack and an index over all of it.
    for label, argv, where in (
            ('clone (bash-os)', ours+['clone', '-q', str(work), str(root/'clone-ours')], root),
            ('clone (git)', theirs+['clone', '-q', '--no-local', str(work),
                                     str(root/'clone-git')], root)):
        elapsed, peak, _ = run(argv, where, label)
        packs = sorted((root/('clone-ours' if 'bash-os' in label else 'clone-git')
                        / '.git'/'objects'/'pack').glob('*.pack'))
        size = sum(p.stat().st_size for p in packs)/1e6
        print(f'{label:<24} {elapsed*1000:>9.0f}ms {"":>10} {"":>7} '
              f'{peak:>13.0f}MB    pack {size:.0f} MB')


if __name__ == '__main__':
    if not GIT:
        raise SystemExit('git-scale: real git is required to compare with')
    main()
