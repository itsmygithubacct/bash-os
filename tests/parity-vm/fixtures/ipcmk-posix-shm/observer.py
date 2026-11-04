# SPDX-License-Identifier: MIT
# Independent kernel metadata and unlink observer; run only in a disposable VM.
import ctypes
import os
import stat
import sys

command, name = sys.argv[1:3]
if command == 'unlink':
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.shm_unlink(name.encode()) != 0:
        raise OSError(ctypes.get_errno(), 'shm_unlink')
elif command == 'check':
    path = '/dev/shm/' + name[1:]
    info = os.stat(path)
    assert (info.st_size, stat.S_IMODE(info.st_mode), info.st_uid) == (8192, 0o640, 2000), (info.st_size, oct(stat.S_IMODE(info.st_mode)), info.st_uid)
    if sys.argv[3] == 'initial':
        with open(path, 'r+b') as f:
            f.write(b't114 sentinel')
        with open('inode.txt', 'w') as f:
            f.write(str(info.st_ino))
    else:
        with open('inode.txt') as f:
            assert info.st_ino == int(f.read())
        with open(path, 'rb') as f:
            assert f.read(13) == b't114 sentinel'
else:
    raise ValueError(command)
