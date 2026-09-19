#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""bash-os and git read and write each other's refs, packed or loose.

Usage: python3 tests/git-refs.py [BINARY]

Real git builds a repository, packs its refs away into packed-refs, and
bash-os's git must still resolve, list and delete them. Then bash-os writes
refs and reflog entries, and git must read those back and pass fsck.
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
    raise SystemExit('git-refs: real git is required as the reference')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Refs Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Refs Committer', 'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


def git(directory, *args, status=0):
    result = subprocess.run([GIT, '-C', str(directory), *map(str, args)],
                            capture_output=True, timeout=120,
                            env={**os.environ, **ENV, 'HOME': str(directory)})
    assert result.returncode == status, (args, result.returncode, result.stderr[:400])
    return result.stdout.decode()


def bgit(directory, *args, status=0):
    """bash-os's git, with an empty PATH so only its own builtins answer."""
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; git "$@"', 'git', *map(str, args)],
        capture_output=True, timeout=120, cwd=directory,
        env={**ENV, 'HOME': str(directory)})
    assert result.returncode == status, (args, result.returncode, result.stdout[:200], result.stderr[:400])
    return result.stdout.decode()


with tempfile.TemporaryDirectory(prefix='git-refs-') as directory:
    tmp = Path(directory)
    repo = tmp/'repo'
    repo.mkdir()
    git(repo, 'init', '-q', '-b', 'main')
    (repo/'a.txt').write_text('one\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-q', '-m', 'first commit')
    git(repo, 'branch', 'topic')
    git(repo, 'tag', 'light')
    git(repo, 'tag', '-a', 'annotated', '-m', 'an annotated tag')
    (repo/'a.txt').write_text('two\n')
    git(repo, 'commit', '-q', '-a', '-m', 'second commit')

    head = git(repo, 'rev-parse', 'HEAD').strip()
    first = git(repo, 'rev-parse', 'HEAD~1').strip()

    # Loose refs first.
    check(bgit(repo, 'rev-parse', 'HEAD').strip() == head, 'rev-parse HEAD')
    check(bgit(repo, 'show-ref') == git(repo, 'show-ref'), 'show-ref, loose')
    check(bgit(repo, 'for-each-ref') == git(repo, 'for-each-ref'), 'for-each-ref, loose')

    # git packs the refs away; the loose files are gone.
    git(repo, 'pack-refs', '--all')
    check((repo/'.git/packed-refs').is_file(), 'packed-refs written')
    loose = [p for p in (repo/'.git/refs').rglob('*') if p.is_file()]
    check(not loose, 'refs still loose after pack-refs', loose)

    check(bgit(repo, 'show-ref') == git(repo, 'show-ref'), 'show-ref, packed')
    check(bgit(repo, 'for-each-ref') == git(repo, 'for-each-ref'), 'for-each-ref, packed')
    check(bgit(repo, 'rev-parse', 'topic').strip() == git(repo, 'rev-parse', 'topic').strip(),
          'rev-parse a packed branch')
    check(bgit(repo, 'rev-parse', 'light').strip() == git(repo, 'rev-parse', 'light').strip(),
          'rev-parse a packed lightweight tag')
    check(bgit(repo, 'rev-parse', 'annotated^{commit}').strip()
          == git(repo, 'rev-parse', 'annotated^{commit}').strip(), 'peel a packed annotated tag')
    check(bgit(repo, 'show-ref', '--verify', 'refs/heads/topic')
          == git(repo, 'show-ref', '--verify', 'refs/heads/topic'), 'show-ref --verify, packed')

    # bash-os updates a packed ref: the new value wins, and git sees it.
    bgit(repo, 'update-ref', 'refs/heads/topic', first)
    check(git(repo, 'rev-parse', 'topic').strip() == first, 'git reads a ref bash-os updated')
    check((repo/'.git/refs/heads/topic').is_file(), 'the update is a loose ref')

    # bash-os deletes one that is only packed, and git agrees it is gone.
    bgit(repo, 'update-ref', '-d', 'refs/tags/light')
    git(repo, 'rev-parse', 'light', status=128)
    check('refs/tags/light' not in git(repo, 'show-ref'), 'deleted from packed-refs')
    check(git(repo, 'fsck', '--strict', '--no-progress') == '', 'fsck after the deletions')

    # A reflog bash-os wrote, read by git.
    bgit(repo, 'update-ref', '-m', 'moved by bash-os', 'refs/heads/topic', head)
    entries = git(repo, 'log', '-g', '--format=%gd %gn %ge %gs', 'refs/heads/topic').splitlines()
    check(any('moved by bash-os' in line for line in entries), 'git reads the reflog message', entries)
    check(any('Refs Committer' in line and 'committer@bash-os.test' in line for line in entries),
          'the identity is the configured one', entries)
    check(bgit(repo, 'reflog', 'topic').splitlines()[0].endswith('moved by bash-os'),
          'bash-os reads its own reflog')
    check(git(repo, 'rev-parse', 'topic@{1}').strip() == first, 'git resolves the previous value')
    check(bgit(repo, 'rev-parse', 'topic@{1}').strip() == first, 'bash-os resolves it too')

    # A symbolic ref written by bash-os, and HEAD still resolving for both.
    bgit(repo, 'symbolic-ref', 'HEAD', 'refs/heads/topic')
    check(git(repo, 'symbolic-ref', 'HEAD').strip() == 'refs/heads/topic', 'git reads the symref')
    check(git(repo, 'rev-parse', 'HEAD').strip() == head, 'HEAD resolves through it')
    check(bgit(repo, 'rev-parse', '--abbrev-ref', 'HEAD').strip() == 'topic', 'abbrev-ref')

    # A locked ref is refused, with git's message.
    (repo/'.git/refs/heads/topic.lock').write_text('')
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c',
         'PATH=; git update-ref refs/heads/topic "$1"', 'git', first],
        capture_output=True, cwd=repo, env={**ENV, 'HOME': str(repo)}, timeout=60)
    check(result.returncode == 128, 'a held lock fails', result.returncode)
    check(b'File exists' in result.stderr, 'the message names the lock', result.stderr[:200])
    (repo/'.git/refs/heads/topic.lock').unlink()
    check(git(repo, 'rev-parse', 'topic').strip() == head, 'the ref is unchanged')

print(f'git-refs: {checks} checks passed')
