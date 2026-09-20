#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetching, cloning and pushing over ssh, against real git at both ends.

Usage: python3 tests/git-ssh.py [BINARY]

What ssh carries is a command run on another machine with its input and
output wired to a pipe, so a stand-in named ssh proves the transport
without a server: it takes the arguments git's ssh takes, writes down
what it was told, and runs the command here instead of there. The line it
writes down is held against the line real git makes for the same address,
word for word, and the far end it runs is real git's — or this build's,
when the direction is the other way about.
"""

import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash')
if not binary.is_absolute():
    binary = (ROOT/binary).resolve()
GIT = shutil.which('git')
if not GIT:
    raise SystemExit('git-ssh: real git is required')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Ssh Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Ssh Committer',
       'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


with tempfile.TemporaryDirectory(prefix='git-ssh-') as name:
    tmp = Path(name)
    log = tmp/'ssh.log'
    home = {'HOME': str(tmp)}

    def git(directory, *args, check_status=True, env=()):
        result = subprocess.run([GIT, '-C', str(directory), *map(str, args)],
                                capture_output=True, timeout=300,
                                env={**os.environ, **ENV, **home, **dict(env)})
        if check_status:
            assert result.returncode == 0, (args, result.returncode,
                                            result.stderr[:400])
        return result

    def bgit(*args, cwd, status=0, env=()):
        """The git builtin, with only the stand-in ssh to reach out with."""
        result = subprocess.run(
            [str(binary), '--noprofile', '--norc', '-c', 'git "$@"', 'git',
             *map(str, args)],
            capture_output=True, timeout=300, cwd=str(cwd),
            env={**ENV, **home, 'PATH': f'{tmp}/bin:/usr/bin:/bin',
                 **dict(env)})
        assert result.returncode == status, (args, result.returncode,
                                             result.stdout[:200],
                                             result.stderr[:400])
        return result

    def lines():
        text = log.read_text() if log.exists() else ''
        log.write_text('')
        return [line for line in text.splitlines() if line]

    # --- the stand-ins ---------------------------------------------------
    # One is called ssh, which is how git knows it takes -p and can be
    # asked to carry GIT_PROTOCOL; the other is called something else,
    # which git calls the simple variant and hands nothing but the host.
    (tmp/'bin').mkdir()
    (tmp/'far').mkdir()
    for named, path in (('ssh', tmp/'bin'/'ssh'), ('simple', tmp/'simple')):
        path.write_text(
            '#!/bin/sh\n'
            f'printf \'%s\\n\' "{named} $*" >> "{log}"\n'
            'while [ $# -gt 1 ]; do shift; done\n'
            'exec /bin/sh -c "$1"\n')
        path.chmod(0o755)
    # A stand-in that runs this build's far end rather than git's, for the
    # direction where git is the one reaching out.
    for verb in ('upload-pack', 'receive-pack'):
        shim = tmp/'far'/f'git-{verb}'
        shim.write_text(f'#!/bin/sh\nexec {binary} --noprofile --norc '
                        f'-c \'PATH=; git {verb} "$@"\' git-{verb} "$@"\n')
        shim.chmod(0o755)
    to_ours = tmp/'bin'/'ssh-to-bash-os'
    to_ours.write_text('#!/bin/sh\n'
                       f'PATH="{tmp}/far:$PATH"; export PATH\n'
                       'GIT_PROTOCOL=version=2; export GIT_PROTOCOL\n'
                       'while [ $# -gt 1 ]; do shift; done\n'
                       'exec /bin/sh -c "$1"\n')
    to_ours.chmod(0o755)
    ours = {'GIT_SSH_COMMAND': str(tmp/'bin'/'ssh')}
    simple = {'GIT_SSH_COMMAND': str(tmp/'simple')}
    theirs = {'GIT_SSH_COMMAND': str(to_ours)}

    # --- something to fetch ----------------------------------------------
    origin = tmp/'origin.git'
    git(tmp, 'init', '-q', '-b', 'main', '--bare', str(origin))
    work = tmp/'work'
    work.mkdir()
    git(work, 'init', '-q', '-b', 'main', '.')
    (work/'a.txt').write_text('one\n')
    git(work, 'add', 'a.txt')
    git(work, 'commit', '-q', '-m', 'the first commit')
    git(work, 'push', '-q', str(origin), 'main')
    log.write_text('')

    # --- the line ssh is given -------------------------------------------
    # Every shape of address, and what git makes of it, held against what
    # this build makes of it.
    for address in (f'example.com:{origin}',
                    f'user@example.com:{origin}',
                    f'ssh://example.com{origin}',
                    f'ssh://user@example.com:2222{origin}',
                    'example.com:~/repo.git',
                    'ssh://example.com/~/repo.git',
                    f'[2001:db8::1]:{origin}'):
        bgit('ls-remote', address, cwd=tmp, status=0 if origin.name in address
             else 128, env=ours)
        mine = lines()
        git(tmp, 'ls-remote', address, check_status=False, env=ours)
        check(mine == lines(), 'the same line for the same address', address,
              mine)

    # A port needs an ssh that takes one, and git says so in as many words.
    refused = bgit('ls-remote', f'ssh://example.com:2222{origin}', cwd=tmp,
                   status=128, env=simple)
    check(b"ssh variant 'simple' does not support setting port"
          in refused.stderr, 'a port the stand-in cannot set',
          refused.stderr[:200])
    check(refused.stderr == git(tmp, 'ls-remote',
                                f'ssh://example.com:2222{origin}',
                                check_status=False, env=simple).stderr,
          'refused in git\'s words')
    log.write_text('')

    # --- this build reaching out -----------------------------------------
    cloned = tmp/'cloned'
    bgit('clone', f'example.com:{origin}', str(cloned), cwd=tmp, env=ours)
    check((cloned/'a.txt').read_text() == 'one\n',
          'a clone over ssh brings the work with it')
    check(git(cloned, 'rev-parse', 'HEAD').stdout
          == git(work, 'rev-parse', 'HEAD').stdout, 'and the same commit')
    check(any('git-upload-pack' in line for line in lines()),
          'by asking for upload-pack on the other machine')

    # What the far end gains, this build fetches over the same transport.
    (work/'a.txt').write_text('one\ntwo\n')
    git(work, 'commit', '-q', '-am', 'the second commit')
    git(work, 'push', '-q', str(origin), 'main')
    fetched = bgit('fetch', 'origin', cwd=cloned, env=ours)
    check(b'main' in fetched.stderr, 'a fetch over ssh says what moved',
          fetched.stderr[:200])
    check(git(cloned, 'rev-parse', 'origin/main').stdout
          == git(work, 'rev-parse', 'HEAD').stdout, 'and has it')
    git(cloned, 'merge', '-q', '--ff-only', 'origin/main')
    log.write_text('')

    # And pushes back, which is receive-pack on the other machine.
    (cloned/'b.txt').write_text('pushed over ssh\n')
    git(cloned, 'add', 'b.txt')
    git(cloned, 'commit', '-q', '-m', 'the third commit')
    pushed = bgit('push', 'origin', 'main', cwd=cloned, env=ours)
    check(b'main -> main' in pushed.stderr, 'a push over ssh reports it',
          pushed.stderr[:200])
    check(git(origin, 'rev-parse', 'main').stdout
          == git(cloned, 'rev-parse', 'HEAD').stdout, 'and it landed')
    check(any('git-receive-pack' in line for line in lines()),
          'by asking for receive-pack')

    # --- git reaching out, to this build's far end ------------------------
    from_ours = tmp/'from-ours'
    git(tmp, 'clone', '-q', f'example.com:{origin}', str(from_ours),
        env=theirs)
    check((from_ours/'b.txt').read_text() == 'pushed over ssh\n',
          'git clones through this build\'s upload-pack over ssh')
    (from_ours/'c.txt').write_text('git pushed this\n')
    git(from_ours, 'add', 'c.txt')
    git(from_ours, 'commit', '-q', '-m', 'the fourth commit')
    git(from_ours, 'push', '-q', 'origin', 'main', env=theirs)
    check(git(origin, 'rev-parse', 'main').stdout
          == git(from_ours, 'rev-parse', 'HEAD').stdout,
          'and pushes through its receive-pack')
    log.write_text('')

    # --- which ssh gets used ---------------------------------------------
    # core.sshCommand says it standing, and the environment says it louder.
    git(cloned, 'config', 'core.sshCommand', str(tmp/'simple'))
    bgit('ls-remote', 'origin', cwd=cloned)
    check(lines()[0].startswith('simple '), 'core.sshCommand is used')
    bgit('ls-remote', 'origin', cwd=cloned, env=ours)
    check(lines()[0].startswith('ssh '),
          'and GIT_SSH_COMMAND is used over it')
    git(cloned, 'config', '--unset', 'core.sshCommand')

    # --- what the far end is asked to run --------------------------------
    bgit('ls-remote', '--upload-pack=/some/other/upload-pack', 'origin',
         cwd=cloned, status=128, env=ours)
    mine = lines()
    git(cloned, 'ls-remote', '--upload-pack=/some/other/upload-pack', 'origin',
        check_status=False, env=ours)
    check(mine == lines(), 'a far end named by --upload-pack', mine)

    # --- and over this build's own ssh, to this build's own sshd ---------
    # No stand-in and nothing else on the machine: the client is the ssh
    # builtin, the server is the sshd builtin, and what runs over there is
    # a far end asked for by name. A command that talks back while it runs
    # is the whole of it — both ends have to carry a live stream.
    if b'sshd' in subprocess.run([str(binary), '--noprofile', '--norc', '-c',
                                  'PATH=; enable -a'], capture_output=True,
                                 timeout=60).stdout:
        (tmp/'.ssh').mkdir(exist_ok=True)
        identity = tmp/'.ssh'/'id_ed25519'
        hostkey = tmp/'hostkey'
        keygen = shutil.which('ssh-keygen')
        if not keygen:
            raise SystemExit('git-ssh: ssh-keygen is required')
        for path in (identity, hostkey):
            subprocess.run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f',
                            str(path)], check=True, timeout=120)
        # The far end learns which protocol version is meant from the
        # environment, and a server only passes on what it is told to.
        (tmp/'sshd.conf').write_text('AcceptEnv GIT_PROTOCOL\n')
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        user = pwd.getpwuid(os.getuid()).pw_name
        known = tmp/'known-hosts'
        server = subprocess.Popen(
            [str(binary), '--noprofile', '--norc', '-c',
             'sshd run --encrypted -F "$1" -a 127.0.0.1 -p "$2" -k "$3"',
             '_', str(tmp/'sshd.conf'), str(port), str(hostkey)],
            env={**os.environ, 'LC_ALL': 'C',
                 'BASHSSHD_RUN_DIR': str(tmp/'sshd-run'),
                 'BASHSSHD_AUTHORIZED_KEYS': str(identity)+'.pub'},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        try:
            said = bytearray()
            deadline = time.monotonic() + 20
            while b'listening' not in said:
                assert time.monotonic() < deadline and server.poll() is None, said
                said.extend(os.read(server.stderr.fileno(), 4096))
            over_ssh = {'BASHSSH_KNOWN_HOSTS': str(known),
                        'GIT_SSH_COMMAND': ''}
            address = f'ssh://{user}@127.0.0.1:{port}{origin}'

            live = tmp/'over-ours'
            bgit('clone', address, str(live), cwd=tmp, env=over_ssh)
            check((live/'c.txt').read_text() == 'git pushed this\n',
                  'a clone with nothing but this build between the ends')
            check(git(live, 'rev-parse', 'HEAD').stdout
                  == git(origin, 'rev-parse', 'main').stdout, 'and the commit')

            # What the far end gains afterwards, fetched the same way.
            (work/'a.txt').write_text('one\ntwo\nthree\n')
            git(work, 'commit', '-q', '-am', 'the fifth commit')
            git(work, 'push', '-q', str(origin), '+main:main')
            bgit('fetch', 'origin', cwd=live, env=over_ssh)
            check(git(live, 'rev-parse', 'origin/main').stdout
                  == git(work, 'rev-parse', 'HEAD').stdout,
                  'a fetch over the same')

            # And a push, which is the direction that sends a pack.
            git(live, 'reset', '-q', '--hard', 'origin/main')
            (live/'d.txt').write_text('and back again\n')
            git(live, 'add', 'd.txt')
            git(live, 'commit', '-q', '-m', 'the sixth commit')
            bgit('push', 'origin', 'main', cwd=live, env=over_ssh)
            check(git(origin, 'rev-parse', 'main').stdout
                  == git(live, 'rev-parse', 'HEAD').stdout,
                  'and a push that lands')
        finally:
            if server.poll() is None:
                os.killpg(server.pid, signal.SIGTERM)
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.wait()

print(f'git-ssh: {checks} checks passed')
