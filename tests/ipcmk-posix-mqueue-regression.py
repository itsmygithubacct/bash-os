#!/usr/bin/env python3
"""Guest-only contract check: pass the candidate Bash path as argv[1]."""
import ctypes
import errno
import os
import secrets
import stat
import subprocess
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.mq_open.restype = ctypes.c_int
libc.mq_close.argtypes = [ctypes.c_int]
libc.mq_unlink.argtypes = [ctypes.c_char_p]


class Attr(ctypes.Structure):
    _fields_ = [(name, ctypes.c_long) for name in
                ('flags', 'maxmsg', 'msgsize', 'curmsgs')] + [('reserved', ctypes.c_long * 4)]


libc.mq_getattr.argtypes = [ctypes.c_int, ctypes.POINTER(Attr)]


def observe(name):
    fd = libc.mq_open(name.encode(), os.O_RDONLY)
    if fd < 0:
        err = ctypes.get_errno()
        if err == errno.ENOENT:
            return None
        raise OSError(err, os.strerror(err))
    try:
        attr = Attr()
        if libc.mq_getattr(fd, ctypes.byref(attr)) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        info = os.fstat(fd)
        return (attr.maxmsg, attr.msgsize, attr.curmsgs,
                stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid,
                info.st_dev, info.st_ino)
    finally:
        if libc.mq_close(fd) != 0:
            raise OSError(ctypes.get_errno(), 'mq_close')


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: ipcmk-posix-mqueue-regression.py CANDIDATE_BASH')
    if os.getuid() != 2000:
        raise RuntimeError('guest prerequisite: run as uid 2000')
    binary = os.path.abspath(sys.argv[1])
    name = '/ipcmk_mq_' + secrets.token_hex(12)
    assert observe(name) is None, 'fixture name already exists'
    owned = False

    def run(*args):
        return subprocess.run([binary, '--noprofile', '--norc', '-c',
                               '[[ $(type -t ipcmk) == builtin ]] || exit 90; '
                               'umask 027; ipcmk "$@"', 'fixture', *args],
                              capture_output=True, text=True,
                              env={**os.environ, 'LC_ALL': 'C'})

    try:
        first = run('-q', '--name', name, '-p', '0666')
        # Only remove a queue after this invocation reported successful creation.
        owned = first.returncode == 0
        assert first.returncode == 0, (first.returncode, first.stdout, first.stderr)
        assert first.stdout == 'Message queue name: %s\n' % name, first.stdout
        assert first.stderr == '', first.stderr
        initial = observe(name)
        defaults = tuple(int(open('/proc/sys/fs/mqueue/' + field).read())
                         for field in ('msg_default', 'msgsize_default'))
        assert initial is not None
        assert initial[:5] == (*defaults, 0, 0o640, 2000), initial
        collision = run('-q', '--name', name, '-p', '0600')
        assert collision.returncode == 1, collision.returncode
        assert collision.stdout == '', collision.stdout
        assert 'POSIX IPC creation failed' in collision.stderr, collision.stderr
        assert 'File exists' in collision.stderr, collision.stderr
        assert observe(name) == initial, 'collision changed original queue'
        for invalid in (name[1:] + '_invalid', '/', name + '/nested', '/' + name):
            result = run('-q', '--name', invalid)
            assert result.returncode == 1, (invalid, result.returncode)
            assert result.stdout == '', (invalid, result.stdout)
            assert 'POSIX resources require --name /name' in result.stderr, (invalid, result.stderr)
            assert observe('/' + name[1:] + '_invalid') is None, 'relative name created a queue'
            assert observe(name) == initial, 'invalid name changed original queue'
        assert libc.mq_unlink(name.encode()) == 0, ctypes.get_errno()
        owned = False
        assert observe(name) is None, 'queue remains after unlink'
        print('ipcmk-posix-mqueue-contract: PASS')
    finally:
        if owned:
            if libc.mq_unlink(name.encode()) != 0 and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), 'cleanup mq_unlink')


if __name__ == '__main__':
    main()
