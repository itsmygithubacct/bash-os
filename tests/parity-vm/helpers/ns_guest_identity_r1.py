#!/usr/bin/env python3
"""Guest-only identity guard for uid 2000 or its one-id mapped userns."""
import os
from pathlib import Path
import stat
import subprocess
import uuid


def verify():
    if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
        raise RuntimeError('wrong fixture scratch context')
    uid, euid, gid, egid = os.getuid(), os.geteuid(), os.getgid(), os.getegid()
    if uid != euid or gid != egid:
        raise RuntimeError('credential mismatch')
    if uid == 2000:
        owner_uid, owner_gid = 0, 0
    elif uid == 0:
        umap = [list(map(int, x.split())) for x in Path('/proc/self/uid_map').read_text().splitlines()]
        gmap = [list(map(int, x.split())) for x in Path('/proc/self/gid_map').read_text().splitlines()]
        if umap != [[0, 2000, 1]] or gmap != [[0, 2000, 1]]:
            raise RuntimeError('unexpected mapped user namespace')
        owner_uid = int(Path('/proc/sys/kernel/overflowuid').read_text())
        owner_gid = int(Path('/proc/sys/kernel/overflowgid').read_text())
    else:
        raise RuntimeError('wrong guest uid')
    def read_identity(directory, name):
        dirfd=os.open(directory, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            parent=os.fstat(dirfd)
            if parent.st_uid!=owner_uid or parent.st_gid!=owner_gid or stat.S_IMODE(parent.st_mode)&0o022:
                raise RuntimeError('unprotected identity directory')
            fd=os.open(name, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=dirfd)
            try:
                before=os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner_uid or before.st_gid!=owner_gid or
                    stat.S_IMODE(before.st_mode)!=0o444 or before.st_nlink!=1 or before.st_size!=37):
                    raise RuntimeError('unprotected identity file')
                data=os.read(fd,38); after=os.fstat(fd)
                if ((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)):
                    raise RuntimeError('identity file changed during read')
            finally: os.close(fd)
        finally: os.close(dirfd)
        if len(data)!=37 or not data.endswith(b'\n'):
            raise RuntimeError('invalid identity bytes')
        value=data[:-1].decode('ascii')
        if str(uuid.UUID(value))!=value: raise RuntimeError('noncanonical identity')
        return value
    if read_identity('/etc','bashos-parity-vm') != read_identity('/run','bashos-parity-vm-identity'):
        raise RuntimeError('attested identity differs from marker')
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
        raise RuntimeError('unexpected guest vendor')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'): raise RuntimeError('unexpected virtualization')

if __name__=='__main__':
    verify()
