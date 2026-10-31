#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guarded VM-only SSH-shaped SFTP adapter whose server side is confined to the fixture tree.

The OpenSSH client (-S) and the candidate (BASHSSH_OPENSSH_BIN) both start this
program in place of ssh.  It runs the remote side (the OpenSSH sftp-server for
the reference, the command-stream shell for the candidate) inside a bubblewrap
mount namespace whose only visible writable path is the fixture's ``remote``
directory, bind-mounted at /srv.  Everything else is the read-only /usr tree,
a private /proc and /dev, and a tmpfs root, so a path escape cannot reach the
case directory, the private home or any other guest file.
"""
import json
import os
from pathlib import Path
import sys
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
BWRAP = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent',
         '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
         '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/sbin', '/sbin',
         '--ro-bind', '/etc/passwd', '/etc/passwd', '--ro-bind', '/etc/group', '/etc/group',
         '--proc', '/proc', '--dev', '/dev']


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        cwd = Path.cwd().resolve()
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(HOME)
                or not (cwd == CASE or CASE in cwd.parents)
                or CASE.stat().st_uid != 2000 or HOME.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def record(event, **detail):
    with (HOME / 'sftp-invocations.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'event': event, **detail}, sort_keys=True) + '\n')


def main():
    args = sys.argv[1:]
    record('invoked', argv=args)
    root = CASE / 'remote'
    if not root.is_dir() or root.is_symlink():
        raise ValueError('invalid fixture root')
    confine = BWRAP + ['--bind', str(root), '/srv', '--chdir', '/srv']
    record('confined', bwrap=confine)
    env = dict(os.environ, PATH='/usr/bin:/bin')
    if len(args) >= 2 and args[-1] == 'sftp' and '-s' in args:
        if args[-2] != 'fixture':
            raise ValueError('unexpected OpenSSH target')
        record('sftp-server', argv=args)
        os.execve(confine[0], confine + ['/usr/lib/openssh/sftp-server', '-d', '/srv', '-e', '-l', 'VERBOSE'], env)
    if len(args) < 2 or args[-2] != 'fixture':
        raise ValueError('unexpected command-stream target')
    record('command', command=args[-1], argv=args)
    os.execve(confine[0], confine + ['/bin/sh', '-c', args[-1]], env)


if __name__ == '__main__':
    require_guest()
    try:
        sys.exit(main())
    except (KeyError, TypeError, OSError, ValueError) as exc:
        try:
            record('error', error=repr(exc))
        except OSError:
            pass
        print('fixture transport: ' + str(exc), file=sys.stderr)
        sys.exit(90)
