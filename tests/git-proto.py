#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The two ends of protocol v2, each checked against the other implementation.

Usage: python3 tests/git-proto.py [BINARY]

`tests/git/ls-remote.sh` runs this build's client against this build's
server, which agrees with git about the answer but proves nothing about
the conversation. So here git's client asks this build's upload-pack, this
build's client asks git's upload-pack, and the packets themselves are read
off the wire and compared with what git sends.
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
    raise SystemExit('git-proto: real git is required as the reference')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Proto Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Proto Committer', 'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}

# What git runs to reach this build's server, and what this build runs to
# reach git's. Either side takes a command line, the path being added to it.
OURS = f'{binary} --noprofile --norc -c \'builtin git upload-pack "$@"\' git-upload-pack'
THEIRS = f'{GIT} upload-pack'


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


def git(directory, *args, check_status=True, env=None):
    result = subprocess.run([GIT, '-C', str(directory), *map(str, args)],
                            capture_output=True, timeout=300,
                            env={**os.environ, **ENV, 'HOME': str(directory), **(env or {})})
    if check_status:
        assert result.returncode == 0, (args, result.returncode, result.stderr[:400])
    return result


def bgit(*args, cwd, status=0, env=None):
    """Run the git builtin with an empty PATH, as a bash-os user would."""
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; git "$@"', 'git', *map(str, args)],
        capture_output=True, timeout=300, cwd=str(cwd),
        env={**ENV, 'HOME': str(cwd), 'PATH': '', **(env or {})})
    assert result.returncode == status, (args, result.returncode,
                                         result.stdout[:200], result.stderr[:400])
    return result


def raw_packets(data):
    """Split a pkt-line stream into payloads, with markers named."""
    out = []
    at = 0
    while at < len(data):
        length = int(data[at:at+4], 16)
        if length == 0:
            out.append('FLUSH')
            at += 4
        elif length in (1, 2):
            out.append('DELIM' if length == 1 else 'END')
            at += 4
        else:
            out.append(data[at+4:at+length])
            at += length
    return out


def packets(data):
    """The same, as text: the packets of a conversation are lines."""
    return [line if isinstance(line, str) else line.decode()
            for line in raw_packets(data)]


def pkt(text):
    body = text.encode()
    return b'%04x' % (len(body) + 4) + body


def answers(stream):
    """The packets after the advertisement, which is the part compared."""
    lines = packets(stream)
    return lines[lines.index('FLUSH') + 1:]


def converse(server, directory, request):
    """Send REQUEST to a server started on DIRECTORY, and read it all back."""
    child = subprocess.Popen([str(binary), '--noprofile', '--norc', '-c',
                              f'{server} "$@"', 'git-upload-pack', str(directory)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             env={**ENV, 'HOME': str(directory), 'PATH': os.environ['PATH'],
                                  'GIT_PROTOCOL': 'version=2'})
    out, _ = child.communicate(request, timeout=120)
    return out


with tempfile.TemporaryDirectory(prefix='git-proto-') as name:
    tmp = Path(name)
    repo = tmp/'repo'
    repo.mkdir()
    git(repo, 'init', '-q', '-b', 'main')
    (repo/'a.txt').write_text('one\n')
    git(repo, 'add', 'a.txt')
    git(repo, 'commit', '-q', '-m', 'the first commit')
    git(repo, 'branch', 'other')
    git(repo, 'tag', 'light')
    git(repo, 'tag', '-a', 'heavy', '-m', 'an annotated tag')
    reference = git(repo, 'ls-remote', str(repo)).stdout

    # git's client, this build's server, and the other way round: each must
    # give the listing git gives itself.
    for label, upload_pack in (('ours under git', OURS), ('theirs under git', THEIRS)):
        got = git(repo, 'ls-remote', f'--upload-pack={upload_pack}', str(repo)).stdout
        check(got == reference, 'git ls-remote', label, got[:200])
    for label, upload_pack in (('ours under this build', OURS),
                               ('theirs under this build', THEIRS)):
        got = bgit('ls-remote', f'--upload-pack={upload_pack}', repo,
                   cwd=tmp, env={'PATH': os.environ['PATH']}).stdout
        check(got == reference, 'ls-remote', label, got[:200])

    # The advertisement: the same first line, the same object format, and
    # the commands this build has are a subset of git's.
    theirs = packets(converse(THEIRS, repo, b'0000'))
    ours = packets(converse(OURS, repo, b'0000'))
    check(ours[0] == theirs[0] == 'version 2\n', 'version line', ours[:1], theirs[:1])
    check(ours[-1] == theirs[-1] == 'FLUSH', 'advertisement ends with a flush')
    check('object-format=sha1\n' in ours, 'object format', ours)
    check(any(line.startswith('agent=') for line in ours), 'agent', ours)
    check('ls-refs\n' in ours or 'ls-refs=unborn\n' in ours, 'ls-refs offered', ours)
    named = {line.split('=')[0].strip() for line in ours if line != 'FLUSH'}
    check(named <= {line.split('=')[0].strip() for line in theirs} | {'version 2'},
          'nothing offered that git does not have', named)

    # One ls-refs, asked for exactly as git asks: the same answer, packet
    # for packet, including what HEAD points at and what a tag points at.
    request = (pkt('command=ls-refs\n') + pkt('object-format=sha1\n') + b'0001'
               + pkt('peel\n') + pkt('symrefs\n') + pkt('ref-prefix refs/\n')
               + pkt('ref-prefix HEAD\n') + b'0000' + b'0000')
    mine = answers(converse(OURS, repo, request))
    check(mine == answers(converse(THEIRS, repo, request)), 'ls-refs packets', mine)

    # A prefix narrows the answer, and two commands fit in one conversation.
    narrowed = (pkt('command=ls-refs\n') + pkt('object-format=sha1\n') + b'0001'
                + pkt('ref-prefix refs/tags/\n') + b'0000')
    both = converse(OURS, repo, narrowed + narrowed + b'0000')
    answered = [line for line in answers(both) if line != 'FLUSH']
    check(len(answered) == 4, 'two answers of two tags each', answered)
    check(all('refs/tags/' in line for line in answered[-4:]), 'the prefix narrowed it',
          answered[-4:])

    # A fetch over the connection, both ways round. git's client must be
    # able to clone through this build's upload-pack, and this build's
    # fetch must work against git's — with the same history either way.
    reference_log = git(repo, 'log', '--format=%H %s').stdout
    for label, upload_pack in (('ours', OURS), ('theirs', THEIRS)):
        into = tmp/f'clone-{label}'
        git(tmp, 'clone', '-q', f'--upload-pack={upload_pack}', str(repo), str(into))
        check(git(into, 'log', '--format=%H %s').stdout == reference_log,
              'git clone through upload-pack', label)
        check(git(into, 'fsck', '--no-progress', '--strict').returncode == 0,
              'what it cloned is sound', label)

    for label, upload_pack in (('ours', OURS), ('theirs', THEIRS)):
        into = tmp/f'fetch-{label}'
        into.mkdir()
        git(into, 'init', '-q', '-b', 'main')
        bgit('remote', 'add', 'origin', repo, cwd=into, env={'PATH': os.environ['PATH']})
        bgit('fetch', f'--upload-pack={upload_pack}', 'origin', cwd=into,
             env={'PATH': os.environ['PATH']})
        check(git(into, 'log', '--format=%H %s', 'refs/remotes/origin/main').stdout
              == reference_log, 'fetch through upload-pack', label)
        check(git(into, 'fsck', '--no-progress', '--strict').returncode == 0,
              'what it fetched is sound', label)

    # What the far end sends is only what the asking end lacks.
    head = git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
    (repo/'a.txt').write_text('one\ntwo\n')
    git(repo, 'commit', '-q', '-am', 'the second commit')
    now = git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()

    def objects_in_pack(request):
        """How many objects the far end put in the pack it sent back."""
        pack = b''
        started = False
        for line in raw_packets(converse(OURS, repo, request)):
            if isinstance(line, str):
                continue
            if line.startswith(b'packfile'):
                started = True
            elif started and line[:1] == b'\x01':
                pack += line[1:]
        return int.from_bytes(pack[8:12], 'big') if len(pack) >= 12 else -1

    everything = (pkt('command=fetch\n') + pkt('object-format=sha1\n') + b'0001'
                  + pkt('ofs-delta\n') + pkt(f'want {now}\n') + pkt('done\n')
                  + b'0000' + b'0000')
    incremental = (pkt('command=fetch\n') + pkt('object-format=sha1\n') + b'0001'
                   + pkt('ofs-delta\n') + pkt(f'want {now}\n') + pkt(f'have {head}\n')
                   + pkt('done\n') + b'0000' + b'0000')
    whole, part = objects_in_pack(everything), objects_in_pack(incremental)
    check(whole > part > 0, 'a have shrinks the pack', whole, part)
    check(part == 3, 'one commit is a commit, a tree and a blob', part)

    # Without being told which protocol to speak, the server says so rather
    # than answering in one the caller did not ask for.
    refused = subprocess.run([str(binary), '--noprofile', '--norc', '-c',
                              'PATH=; git upload-pack "$@"', 'git-upload-pack', str(repo)],
                             capture_output=True, timeout=120, input=b'0000',
                             env={**ENV, 'HOME': str(repo), 'PATH': ''})
    check(refused.returncode == 128, 'upload-pack without a protocol', refused.returncode)
    check(b'version 2' in refused.stderr, 'and says which one it speaks', refused.stderr[:200])

print(f'git-proto: {checks} checks passed')
