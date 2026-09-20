#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Commits and tags signed with an ssh key, which real git must believe.

Usage: python3 tests/git-signing.py [BINARY]

A signature is only worth anything if somebody else accepts it, so what
this build signs is handed to git's own `verify-commit` and `verify-tag`
with the key in an allowed-signers file. The key is made by ssh-keygen,
which is also what says whether the format is right.
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
KEYGEN = shutil.which('ssh-keygen')
if not GIT or not KEYGEN:
    raise SystemExit('git-signing: real git and ssh-keygen are required')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Sign Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Sign Committer', 'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


def git(directory, *args, check_status=True, config=()):
    settings = []
    for pair in config:
        settings += ['-c', pair]
    result = subprocess.run([GIT, '-C', str(directory), *settings, *map(str, args)],
                            capture_output=True, timeout=300,
                            env={**os.environ, **ENV, 'HOME': str(directory)})
    if check_status:
        assert result.returncode == 0, (args, result.returncode, result.stderr[:400])
    return result


def bgit(*args, cwd, status=0, config=()):
    """Run the git builtin with an empty PATH, as a bash-os user would."""
    settings = []
    for pair in config:
        settings += ['-c', pair]
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; git "$@"', 'git',
         *settings, *map(str, args)],
        capture_output=True, timeout=300, cwd=str(cwd),
        env={**ENV, 'HOME': str(cwd), 'PATH': ''})
    assert result.returncode == status, (args, result.returncode,
                                         result.stdout[:200], result.stderr[:400])
    return result


with tempfile.TemporaryDirectory(prefix='git-signing-') as name:
    tmp = Path(name)
    key = tmp/'signing-key'
    subprocess.run([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-C',
                    'signer@bash-os.test', '-f', str(key)], check=True, timeout=120)
    public = (tmp/'signing-key.pub').read_text().split()
    allowed = tmp/'allowed-signers'
    allowed.write_text(f'signer@bash-os.test {public[0]} {public[1]}\n')
    verifying = (f'gpg.format=ssh', f'gpg.ssh.allowedSignersFile={allowed}')
    signing = (f'gpg.format=ssh', f'user.signingKey={key}')

    repo = tmp/'repo'
    repo.mkdir()
    bgit('init', '-q', '-b', 'main', '.', cwd=repo)
    (repo/'a.txt').write_text('one\n')
    bgit('add', 'a.txt', cwd=repo)
    bgit('commit', '-q', '-S', '-m', 'a signed commit', cwd=repo, config=signing)

    # The object carries the signature the way git writes one: a gpgsig
    # header whose lines after the first are indented by one space.
    body = git(repo, 'cat-file', 'commit', 'HEAD').stdout.decode()
    check('gpgsig -----BEGIN SSH SIGNATURE-----' in body, 'the header is there',
          body[:200])
    check('\n -----END SSH SIGNATURE-----\n' in body, 'and is indented as a header',
          body[:400])

    # And git believes it.
    verified = git(repo, 'verify-commit', 'HEAD', config=verifying)
    check(b'Good "git" signature' in verified.stderr, 'git verifies the commit',
          verified.stderr[:200])
    check(b'signer@bash-os.test' in verified.stderr, 'and says whose it is',
          verified.stderr[:200])
    shown = git(repo, 'log', '--show-signature', '-1', config=verifying)
    check(b'Good "git" signature' in shown.stdout, 'and shows it in the log',
          shown.stdout[:200])

    # A key that is not allowed is not believed, which is the other half
    # of the check being worth anything.
    stranger = tmp/'stranger'
    stranger.write_text('somebody ssh-ed25519 '
                        'AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                        'AAAAAAAAAAAAAAAA\n')
    refused = git(repo, 'verify-commit', 'HEAD', check_status=False,
                  config=(f'gpg.format=ssh', f'gpg.ssh.allowedSignersFile={stranger}'))
    check(refused.returncode != 0, 'a key nobody vouches for is refused',
          refused.returncode)

    # A tag signs the same way, with the signature after the message.
    bgit('tag', '-s', '-m', 'a signed tag', 'v1', cwd=repo, config=signing)
    tag = git(repo, 'cat-file', 'tag', 'v1').stdout.decode()
    check(tag.index('a signed tag') < tag.index('-----BEGIN SSH SIGNATURE-----'),
          'the signature stands after the message')
    verified = git(repo, 'verify-tag', 'v1', config=verifying)
    check(b'Good "git" signature' in verified.stderr, 'git verifies the tag',
          verified.stderr[:200])

    # The configuration can ask for it standing, without -S.
    (repo/'a.txt').write_text('one\ntwo\n')
    bgit('commit', '-q', '-am', 'signed because the configuration says so',
         cwd=repo, config=signing + ('commit.gpgsign=true',))
    verified = git(repo, 'verify-commit', 'HEAD', config=verifying)
    check(b'Good "git" signature' in verified.stderr, 'commit.gpgsign signs too',
          verified.stderr[:200])

    # What this build cannot sign with, it says so about rather than
    # writing something that will not verify.
    (repo/'a.txt').write_text('one\ntwo\nthree\n')
    result = bgit('commit', '-q', '-S', '-am', 'no key for this one', cwd=repo,
                  status=128, config=('gpg.format=ssh',))
    check(b'user.signingKey' in result.stderr, 'a signature with no key named',
          result.stderr[:200])
    result = bgit('commit', '-q', '-S', '-am', 'no key for this one', cwd=repo,
                  status=128, config=('gpg.format=openpgp', f'user.signingKey={key}'))
    check(b'ssh keys' in result.stderr, 'a format this build has not got',
          result.stderr[:200])

    locked = tmp/'locked-key'
    subprocess.run([KEYGEN, '-q', '-t', 'ed25519', '-N', 'a passphrase', '-f',
                    str(locked)], check=True, timeout=120)
    result = bgit('commit', '-q', '-S', '-am', 'no key for this one', cwd=repo,
                  status=128, config=('gpg.format=ssh', f'user.signingKey={locked}'))
    check(b'passphrase' in result.stderr, 'a key that is locked away',
          result.stderr[:200])

print(f'git-signing: {checks} checks passed')
