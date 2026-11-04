#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run only in a disposable Linux VM with a private /dev/shm and uid 2000.

Usage: python3 tests/sol-ipcmk-posix-sem-regression.py BASH [IPCMK_SO]
The optional module selects the dynamic build; otherwise ipcmk must be static.
"""
import ctypes
import errno
import os
from pathlib import Path
import subprocess
import sys
import uuid

libc = ctypes.CDLL(None, use_errno=True)
libc.sem_open.restype = ctypes.c_void_p
libc.sem_close.argtypes = [ctypes.c_void_p]
libc.sem_getvalue.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
libc.sem_unlink.argtypes = [ctypes.c_char_p]
FAILED = None  # Linux glibc SEM_FAILED
name = '/ipcmk_reg_' + uuid.uuid4().hex
path = Path('/dev/shm/sem.' + name[1:])
created = False
binary = os.path.abspath(sys.argv[1])
module = os.path.abspath(sys.argv[2]) if len(sys.argv) == 3 else None
assert len(sys.argv) in (2, 3)
assert os.getuid() == 2000, 'fixture requires uid 2000'
assert not path.exists(), 'fixture name collision'


def run(*args):
    prefix = 'enable -f "$1" ipcmk || exit 99; shift; ' if module else ''
    command = prefix + 'umask 027; ipcmk "$@"'
    argv = [binary, '--noprofile', '--norc', '-c', command, 'fixture']
    if module:
        argv.append(module)
    return subprocess.run(argv + list(args), text=True, capture_output=True,
                          env={**os.environ, 'LC_ALL': 'C'})


def snapshot():
    st = path.stat()
    assert st.st_uid == 2000 and st.st_mode & 0o777 == 0o640
    sem = libc.sem_open(name.encode(), 0)
    assert sem != FAILED, ctypes.get_errno()
    value = ctypes.c_int(-1)
    try:
        assert libc.sem_getvalue(sem, ctypes.byref(value)) == 0
        assert value.value == 0
    finally:
        assert libc.sem_close(sem) == 0
    return st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode, st.st_size


try:
    result = run('-s', '--name', name, '-p', '0666')
    # Own the object only after a successful exclusive create.
    created = result.returncode == 0
    assert result.returncode == 0 and result.stdout == f'Semaphore name: {name}\n' and not result.stderr, result
    before = snapshot()
    result = run('-s', '--name', name, '-p', '0666')
    assert result.returncode == 1 and not result.stdout and 'POSIX IPC creation failed' in result.stderr, result
    assert snapshot() == before
    for invalid in (name[1:], name + '/child', '/'):
        result = run('-s', '--name', invalid)
        assert result.returncode == 1 and not result.stdout and result.stderr, (invalid, result)
        assert snapshot() == before
finally:
    if created:
        assert libc.sem_unlink(name.encode()) == 0, ctypes.get_errno()

assert not path.exists()
ctypes.set_errno(0)
sem = libc.sem_open(name.encode(), 0)
assert sem == FAILED and ctypes.get_errno() == errno.ENOENT
print('POSIX semaphore create, metadata, collision, invalid names and cleanup passed')
