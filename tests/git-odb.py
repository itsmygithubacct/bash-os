#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""obj reads objects wherever git keeps them, and agrees with git about them.

Usage: python3 tests/git-odb.py [BINARY]

Builds repositories with real git — loose objects, then packed by `git gc`,
a linked worktree, a bare clone, and a repository whose objects live in an
alternate — and checks obj against `git cat-file` in each. Also checks that
what obj writes lands where git looks for it.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash')
if not binary.is_absolute():
    binary = (ROOT/binary).resolve()
GIT = shutil.which('git')
if not GIT:
    raise SystemExit('git-odb: real git is required as the reference')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Odb Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Odb Committer', 'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


def git(directory, *args, check_status=True, env=None):
    result = subprocess.run([GIT, '-C', str(directory), *map(str, args)],
                            capture_output=True, timeout=120,
                            env={**os.environ, **ENV, 'HOME': str(directory), **(env or {})})
    if check_status:
        assert result.returncode == 0, (args, result.returncode, result.stderr[:400])
    return result


def obj(*args, cwd=None, status=0, env=None):
    """Run the obj builtin with an empty PATH, as a bash-os user would."""
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; obj "$@"', 'obj', *map(str, args)],
        capture_output=True, timeout=120, cwd=cwd,
        env={'LC_ALL': 'C', 'HOME': str(cwd or ROOT), **(env or {})})
    assert result.returncode == status, (args, result.returncode, result.stdout[:200], result.stderr[:400])
    return result


def agrees(repo, ids, label, cwd=None, extra=()):
    """obj must say what git says about each object.

    The reference is `git cat-file <type>`, the object's own bytes. `-p`
    pretty-prints a tree instead of emitting it, which is a different thing.
    """
    for name in ids:
        kind = git(repo, 'cat-file', '-t', name).stdout.strip().decode()
        size = git(repo, 'cat-file', '-s', name).stdout.strip().decode()
        reference = git(repo, 'cat-file', kind, name).stdout
        check(obj('cat', name, *extra, cwd=cwd).stdout == reference, label, 'cat', name)
        check(obj('type', name, *extra, cwd=cwd).stdout.decode().strip() == kind, label, 'type', name)
        check(obj('size', name, *extra, cwd=cwd).stdout.decode().strip() == size, label, 'size', name)
        if kind == 'tree':
            # parse-tree against ls-tree, which names the same entries. obj
            # prints the mode as the tree stores it, so 40000 for a directory;
            # ls-tree pads that to 040000, which `git ls-tree` will have to do
            # when the porcelain lands.
            entries = [line.replace('\t', ' ').split() for line in
                       git(repo, 'ls-tree', name).stdout.decode().splitlines()]
            expected = '\n'.join(f'{mode.lstrip("0")} {path} {sha}'
                                 for mode, _type, sha, path in entries)
            got = obj('parse-tree', name, *extra, cwd=cwd).stdout.decode().strip()
            check(got == expected, label, 'parse-tree', name, got, expected)


with tempfile.TemporaryDirectory(prefix='git-odb-') as directory:
    tmp = Path(directory)
    repo = tmp/'repo'
    repo.mkdir()
    git(repo, 'init', '-q', '-b', 'main')
    (repo/'a.txt').write_text('first file\n')
    (repo/'sub').mkdir()
    (repo/'sub/b.txt').write_text('second file\n' * 100)
    git(repo, 'add', '.')
    git(repo, 'commit', '-q', '-m', 'first commit')
    (repo/'a.txt').write_text('first file, edited\n')
    git(repo, 'commit', '-q', '-a', '-m', 'second commit')
    git(repo, 'tag', '-a', 'v1', '-m', 'annotated tag')

    head = git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
    tree = git(repo, 'rev-parse', 'HEAD^{tree}').stdout.decode().strip()
    blob = git(repo, 'rev-parse', 'HEAD:a.txt').stdout.decode().strip()
    tag = git(repo, 'rev-parse', 'v1').stdout.decode().strip()
    ids = [head, tree, blob, tag]

    # Loose objects, the state obj could always read.
    agrees(repo, ids, 'loose', cwd=repo)
    check(obj('parse-commit', head, cwd=repo).stdout.decode().startswith(f'tree {tree}\n'), 'parse-commit')

    # An abbreviation, resolved the way git resolves it.
    short = head[:8]
    check(obj('cat', short, cwd=repo).stdout == git(repo, 'cat-file', '-p', short).stdout, 'abbreviated id')

    # Packed: after gc there are no loose objects left to read.
    git(repo, 'gc', '-q', '--aggressive')
    loose = [path for path in (repo/'.git/objects').iterdir()
             if path.is_dir() and len(path.name) == 2 and any(path.iterdir())]
    check(not loose, 'gc left loose objects', loose)
    agrees(repo, ids, 'packed', cwd=repo)
    check(obj('cat', short, cwd=repo).stdout == git(repo, 'cat-file', '-p', short).stdout,
          'abbreviated id in a pack')
    # --batch-check over ids and a name that is not there.
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; obj --batch-check'],
        input='\n'.join(ids + ['0' * 40]).encode() + b'\n',
        capture_output=True, cwd=repo, timeout=120, env={'LC_ALL': 'C', 'HOME': str(repo)})
    lines = result.stdout.decode().splitlines()
    check(len(lines) == len(ids) + 1, 'batch-check lines', lines)
    check(lines[-1] == '0' * 40 + ' missing', 'batch-check missing', lines[-1])
    for name, line in zip(ids, lines):
        kind = git(repo, 'cat-file', '-t', name).stdout.strip().decode()
        size = git(repo, 'cat-file', '-s', name).stdout.strip().decode()
        check(line == f'{name} {kind} {size}', 'batch-check record', line)

    # A linked worktree: .git is a file pointing into the main repository.
    tree_dir = tmp/'linked'
    git(repo, 'worktree', 'add', '-q', str(tree_dir), '-b', 'side')
    check((tree_dir/'.git').is_file(), 'worktree .git is a file')
    agrees(repo, ids, 'linked worktree', cwd=tree_dir)
    agrees(repo, ids, 'linked worktree by -r', cwd=tmp, extra=('-r', str(tree_dir)))

    # A bare repository, named directly.
    bare = tmp/'bare.git'
    git(tmp, 'clone', '-q', '--bare', str(repo), str(bare))
    agrees(bare, [head, tree, blob], 'bare', cwd=tmp, extra=('-r', str(bare)))

    # An alternate: the objects live in the first repository.
    borrower = tmp/'borrower'
    borrower.mkdir()
    git(borrower, 'init', '-q', '-b', 'main')
    (borrower/'.git/objects/info').mkdir(parents=True, exist_ok=True)
    (borrower/'.git/objects/info/alternates').write_text(f'{repo}/.git/objects\n')
    agrees(repo, ids, 'alternate', cwd=borrower)

    # GIT_ALTERNATE_OBJECT_DIRECTORIES does the same without the file.
    plain = tmp/'plain'
    plain.mkdir()
    git(plain, 'init', '-q', '-b', 'main')
    env = {'GIT_ALTERNATE_OBJECT_DIRECTORIES': f'{repo}/.git/objects', 'HOME': str(plain)}
    check(obj('cat', head, cwd=plain, env=env).stdout == git(repo, 'cat-file', '-p', head).stdout,
          'GIT_ALTERNATE_OBJECT_DIRECTORIES')

    # GIT_DIR names the repository directly.
    check(obj('cat', head, cwd=tmp, env={'GIT_DIR': str(repo/'.git'), 'HOME': str(tmp)}).stdout
          == git(repo, 'cat-file', '-p', head).stdout, 'GIT_DIR')

    # What obj writes, git reads — in the repository obj found, not the cwd.
    (tmp/'payload.txt').write_text('written by obj\n')
    written = obj('blob', str(tmp/'payload.txt'), cwd=repo).stdout.decode().strip()
    check(git(repo, 'cat-file', '-p', written).stdout == b'written by obj\n', 'obj blob', written)
    check(git(repo, 'cat-file', '-t', written).stdout.strip() == b'blob', 'obj blob type')
    from_worktree = obj('blob', str(tmp/'payload.txt'), cwd=tree_dir).stdout.decode().strip()
    check(from_worktree == written, 'same blob id from a linked worktree')
    check(git(repo, 'cat-file', '-e', written).returncode == 0, 'linked worktree wrote to the main repo')

    # Outside a repository, obj says so.
    outside = tmp/'outside'
    outside.mkdir()
    result = obj('cat', head, cwd=outside, status=128)
    check(b'not in a git repo' in result.stderr, 'outside a repository', result.stderr[:200])

print(f'git-odb: {checks} checks passed')
