#!/usr/bin/python3
"""Guarded VM-only SSH-shaped SFTP adapter with file-backed configuration."""
import json
import os
from pathlib import Path
import stat
import sys
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')


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


def config():
    path = HOME / 'sftp-config.json'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_size > 1024:
        raise ValueError('invalid SFTP configuration file')
    result = json.loads(path.read_text(encoding='utf-8'))
    if (set(result) != {'phase', 'deny'} or result['phase'] not in ('control', 'case')
            or type(result['deny']) is not bool):
        raise ValueError('invalid SFTP configuration fields')
    return result


def main():
    args = sys.argv[1:]
    # Write this before opening or interpreting configuration, including failures.
    record('invoked', argv=args)
    conf = config()
    record('configured', phase=conf['phase'], deny=conf['deny'])
    root = HOME / 'control-remote' if conf['phase'] == 'control' else CASE / 'remote'
    if not root.is_dir() or root.is_symlink():
        raise ValueError('invalid fixture root')
    log = HOME / ('control-peer.jsonl' if conf['phase'] == 'control' else 'peer.jsonl')
    with log.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(args, ensure_ascii=True) + '\n')
    if conf['deny']:
        record('denied', argv=args)
        print('fixture transport denied', file=sys.stderr)
        return 255
    os.chdir(root)
    env = dict(os.environ, PATH='/usr/bin:/bin')
    if len(args) >= 2 and args[-1] == 'sftp' and '-s' in args:
        if args[-2] != 'fixture':
            raise ValueError('unexpected OpenSSH target')
        record('sftp-server', argv=args)
        os.execve('/usr/lib/openssh/sftp-server',
                  ['sftp-server', '-d', str(root), '-e', '-l', 'VERBOSE'], env)
    if len(args) < 2 or args[-2] != 'fixture':
        raise ValueError('unexpected command-stream target')
    record('command', command=args[-1], argv=args)
    os.execve('/bin/sh', ['sh', '-c', args[-1]], env)


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
