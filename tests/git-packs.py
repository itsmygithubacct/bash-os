#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The pack commands, against packs real git made and packs git has to read.

Usage: python3 tests/git-packs.py [BINARY]

`tests/git/packs.sh` compares the two implementations on a pack this build
wrote. This goes further, in both directions: a pack git wrote with `git
repack` is indexed, verified and unpacked here and every answer compared
with git's own, and a pack written here — deltas and all — must be one
git can index to the same bytes, verify and unpack.
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
    raise SystemExit('git-packs: real git is required as the reference')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Pack Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Pack Committer', 'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


def git(directory, *args, check_status=True):
    result = subprocess.run([GIT, '-C', str(directory), *map(str, args)],
                            capture_output=True, timeout=300,
                            env={**os.environ, **ENV, 'HOME': str(directory)})
    if check_status:
        assert result.returncode == 0, (args, result.returncode, result.stderr[:400])
    return result


def bgit(*args, cwd, status=0, stdin=b''):
    """Run the git builtin with an empty PATH, as a bash-os user would."""
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; git "$@"', 'git', *map(str, args)],
        input=stdin, capture_output=True, timeout=300, cwd=str(cwd),
        env={**ENV, 'HOME': str(cwd), 'PATH': ''})
    assert result.returncode == status, (args, result.returncode,
                                         result.stdout[:200], result.stderr[:400])
    return result


def long_file(revision):
    """A file long enough, and alike enough between revisions, to delta."""
    lines = [f'line {i} of a file that barely changes from one commit to the next\n'
             for i in range(200 + revision * 5)]
    lines[revision % len(lines)] = f'line changed in revision {revision}\n'
    return ''.join(lines)


with tempfile.TemporaryDirectory(prefix='git-packs-') as name:
    tmp = Path(name)
    repo = tmp/'repo'
    repo.mkdir()
    git(repo, 'init', '-q', '-b', 'main')
    for revision in range(1, 13):
        (repo/'big.txt').write_text(long_file(revision))
        (repo/'small.txt').write_text(f'small file, revision {revision}\n')
        git(repo, 'add', '.')
        git(repo, 'commit', '-q', '-m', f'commit {revision}')
    git(repo, 'repack', '-a', '-d', '-q', '--window=50', '--depth=50')

    packs = sorted((repo/'.git/objects/pack').glob('*.pack'))
    check(len(packs) == 1, 'repack left one pack', packs)
    pack = packs[0]
    reference_idx = pack.with_suffix('.idx')

    # git's own listing of the pack, which says how many deltas are in it.
    listing = git(repo, 'verify-pack', '-v', reference_idx).stdout.decode()
    chains = [line for line in listing.splitlines() if line.startswith('chain length')]
    check(chains, 'the reference pack carries deltas', listing[-400:])

    # Indexing git's pack must give git's index, byte for byte. Resolving
    # every delta in it is the only way to know the ids it is built from.
    mine = tmp/'mine.idx'
    result = bgit('index-pack', '-o', mine, pack, cwd=tmp)
    check(mine.read_bytes() == reference_idx.read_bytes(), 'index-pack bytes')
    check(result.stdout.decode().strip() == pack.stem.removeprefix('pack-'),
          'index-pack prints the pack checksum', result.stdout[:80])

    # And the listing of it must be git's listing: type, sizes, offset, and
    # for a delta the chain depth and the id of what it is a delta against.
    check(bgit('verify-pack', '-v', reference_idx, cwd=tmp).stdout.decode() == listing,
          'verify-pack -v')
    check(bgit('verify-pack', '-s', reference_idx, cwd=tmp).stdout
          == git(repo, 'verify-pack', '-s', reference_idx).stdout, 'verify-pack -s')
    check(bgit('verify-pack', reference_idx, cwd=tmp).stdout == b'',
          'verify-pack says nothing when it is sound')
    check(bgit('verify-pack', '-s', pack, cwd=tmp).stdout
          == git(repo, 'verify-pack', '-s', reference_idx).stdout,
          'the pack can be named instead of the index')

    # A damaged pack is refused, not indexed into a wrong answer. git's
    # statuses differ between the two: a failed verification is 1, and a
    # pack that cannot be indexed is fatal.
    broken = tmp/'broken.pack'
    bytes_of = bytearray(pack.read_bytes())
    bytes_of[len(bytes_of)//2] ^= 0xff
    broken.write_bytes(bytes_of)
    shutil.copy(reference_idx, tmp/'broken.idx')
    bgit('verify-pack', broken, cwd=tmp, status=1)
    result = bgit('index-pack', '-o', tmp/'other.idx', broken, cwd=tmp, status=128)
    check(b'fatal:' in result.stderr, 'a damaged pack is refused', result.stderr[:200])
    result = bgit('verify-pack', tmp/'nothing.idx', cwd=tmp, status=1)
    check(b"fatal: Cannot open existing pack file" in result.stderr,
          'a pack that is not there', result.stderr[:200])

    # Unpacking git's pack writes every object out loose, with the content
    # git reads from the pack.
    unpacked = tmp/'unpacked'
    unpacked.mkdir()
    git(unpacked, 'init', '-q', '-b', 'main')
    bgit('unpack-objects', cwd=unpacked, stdin=pack.read_bytes())
    ids = [line.split()[0] for line in listing.splitlines()
           if len(line.split()) > 2 and len(line.split()[0]) == 40]
    check(len(ids) > 20, 'the pack holds a useful number of objects', len(ids))
    for name_of in ids:
        kind = git(repo, 'cat-file', '-t', name_of).stdout
        check(git(unpacked, 'cat-file', '-t', name_of).stdout == kind, 'unpacked type', name_of)
        check(git(unpacked, 'cat-file', kind.decode().strip(), name_of).stdout
              == git(repo, 'cat-file', kind.decode().strip(), name_of).stdout,
              'unpacked content', name_of)
    check(git(unpacked, 'fsck', '--no-progress', '--strict').returncode == 0, 'unpacked fsck')

    # The other direction: a pack this build wrote, read by real git.
    made = tmp/'made'
    made.mkdir()
    name_of = bgit('pack-objects', made/'out', cwd=repo,
                   stdin=('\n'.join(ids) + '\n').encode()).stdout.decode().strip()
    mine_pack = made/f'out-{name_of}.pack'
    check(mine_pack.is_file(), 'pack-objects wrote its pack', sorted(p.name for p in made.iterdir()))
    check(git(made, 'verify-pack', '-s', made/f'out-{name_of}.idx').returncode == 0,
          'git verifies the pack this build wrote')
    check(git(made, 'index-pack', '-o', made/'again.idx', mine_pack).returncode == 0,
          'git indexes the pack this build wrote')
    check((made/'again.idx').read_bytes() == (made/f'out-{name_of}.idx').read_bytes(),
          "git's index of it is the index this build wrote")

    # Objects that are nearly the same go in as the difference between
    # them, which is what makes a pack worth the name. git's own listing
    # says how long the delta chains are and what each delta stands on.
    listing = git(made, 'verify-pack', '-v',
                  made/f'out-{name_of}.idx').stdout.decode()
    rows = [line.split() for line in listing.splitlines()]
    deltas = [row for row in rows if len(row) >= 7 and len(row[0]) == 40]
    check(any(line.startswith('chain length') for line in listing.splitlines()),
          'the pack this build wrote carries deltas', listing[-300:])
    check(deltas, 'git can see which objects are deltas')
    check(all(row[6] in ids for row in deltas),
          'every delta stands on a base the pack itself holds')
    whole = sum(int(row[2]) for row in rows if len(row) >= 3 and len(row[0]) == 40)
    packed = mine_pack.stat().st_size
    check(packed < whole, 'the pack is smaller than what it holds',
          packed, whole)

    back = tmp/'back'
    back.mkdir()
    git(back, 'init', '-q', '-b', 'main')
    with mine_pack.open('rb') as stream:
        result = subprocess.run([GIT, '-C', str(back), 'unpack-objects'], stdin=stream,
                                capture_output=True, timeout=300,
                                env={**os.environ, **ENV, 'HOME': str(back)})
    check(result.returncode == 0, 'git unpacks the pack this build wrote', result.stderr[:200])
    for name_of in ids:
        check(git(back, 'cat-file', '-t', name_of).stdout
              == git(repo, 'cat-file', '-t', name_of).stdout, 'round trip type', name_of)
    check(git(back, 'fsck', '--no-progress', '--strict').returncode == 0, 'round trip fsck')

print(f'git-packs: {checks} checks passed')
