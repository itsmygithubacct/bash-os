#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Power-cut model for the rngseed durability fixture (guest root only).

Usage: mig-w6-powercut.py BASH
Builds an ext4 filesystem on a loop file, exposes it through a dm-flakey
device and mounts it.  A "power cut" switches the flakey device to silently
dropping every write (suspend / load / resume), then the filesystem is
dropped without any further write reaching the loop file, and the loop file
is mounted again directly (journal replay) to see what survived.

  control   a seed file is created and synced, then removed by a plain unlink
            with no fsync, then the power is cut: the removal is lost and the
            seed is back (proves the model discards unsynced metadata)
  load      the candidate runs `rngseed load SEED` with seccomp user
            notification on ioctl(RNDADDENTROPY): when the credit is about to
            happen the power is cut and the process is killed before the
            ioctl runs; after replay the seed must be gone

Prints one result line per phase.
"""
import ctypes, errno, fcntl, importlib.util, os, resource, select, signal, struct, subprocess, sys

D = '/tmp/parity-case'
IMG, MNT, MNT2 = D + '/pc.img', D + '/pcmnt', D + '/pcmnt2'
SEQ = '/opt/bashos-parity/harness/helpers/system-sequence.py'
RNDADD = 0x40085203
DM = ['/usr/sbin/dmsetup']
libc = ctypes.CDLL(None, use_errno=True)


def sh(*args, check=True):
    r = subprocess.run(list(args), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError('%s: %s' % (' '.join(args), r.stderr.strip()))
    return r


class Dev:
    def __init__(self):
        sh('/usr/sbin/modprobe', 'dm_flakey')
        resource.setrlimit(resource.RLIMIT_FSIZE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        with open(IMG, 'wb') as f:
            f.truncate(6 << 20)
        self.loop = sh('/usr/sbin/losetup', '-f', '--show', IMG).stdout.strip()
        name = os.path.basename(self.loop)
        if not os.path.exists(self.loop):
            major, minor = open('/sys/block/%s/dev' % name).read().strip().split(':')
            os.mknod(self.loop, 0o60600, os.makedev(int(major), int(minor)))
        sh('/usr/sbin/mkfs.ext4', '-q', '-F', self.loop)
        self.sectors = int(sh('/usr/sbin/blockdev', '--getsz', self.loop).stdout)
        os.makedirs(MNT, exist_ok=True)
        os.makedirs(MNT2, exist_ok=True)
        self.up()

    def table(self, down):
        if down:
            return '0 %d flakey %s 0 0 3600 1 drop_writes' % (self.sectors, self.loop)
        return '0 %d flakey %s 0 3600 0' % (self.sectors, self.loop)

    def up(self):
        sh(*DM, 'create', 'flk', '--noudevsync', '--noudevrules', '--table', self.table(False))
        info = sh(*DM, 'info', '-c', '--noheadings', '-o', 'major,minor', 'flk').stdout.split()[0].split(':')
        os.makedirs('/dev/mapper', exist_ok=True)
        try:
            os.unlink('/dev/mapper/flk')
        except FileNotFoundError:
            pass
        os.mknod('/dev/mapper/flk', 0o60600, os.makedev(int(info[0]), int(info[1])))
        sh('/usr/bin/mount', '-t', 'ext4', '/dev/mapper/flk', MNT)

    def cut(self):
        sh(*DM, 'suspend', 'flk', '--noudevsync', '--noflush', '--nolockfs')
        sh(*DM, 'load', 'flk', '--table', self.table(True))
        sh(*DM, 'resume', 'flk', '--noudevsync')

    def recover(self):
        """Drop the mounted filesystem, replay the journal from the loop file, return the file names."""
        sh('/usr/bin/umount', '-l', MNT, check=False)
        sh(*DM, 'remove', 'flk', '--noudevsync', '--force', check=False)
        sh('/usr/bin/mount', '-t', 'ext4', self.loop, MNT2)
        names = sorted(os.listdir(MNT2))
        sh('/usr/bin/umount', MNT2)
        return names

    def finish(self):
        sh('/usr/sbin/losetup', '-d', self.loop, check=False)


def control(dev):
    p = MNT + '/seed-control'
    with os.fdopen(os.open(p, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), 'wb') as f:
        f.write(os.urandom(512))
        f.flush()
        os.fsync(f.fileno())
    os.sync()
    os.unlink(p)
    dev.cut()
    names = dev.recover()
    print('control-plain-unlink: seed-present-after-power-cut=%d' % ('seed-control' in names))


def load(dev, bash):
    p = MNT + '/seed-load'
    with os.fdopen(os.open(p, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), 'wb') as f:
        f.write(os.urandom(512))
        f.flush()
        os.fsync(f.fileno())
    os.sync()
    spec = importlib.util.spec_from_file_location('seq', SEQ)
    seq = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seq)
    state = {'cut': 0}

    def supervise(lib, listener, child, replies, sequences, logargs, logstr, logmem, log):
        status = None
        try:
            while status is None:
                done, wstatus = os.waitpid(child, os.WNOHANG)
                if done:
                    status = wstatus
                    break
                if not select.select([listener], [], [], .05)[0]:
                    continue
                req = bytearray(80)
                try:
                    fcntl.ioctl(listener, seq.NOTIF_RECV, req, True)
                except OSError as e:
                    if e.errno in (errno.ENOENT, errno.EINTR):
                        continue
                    raise
                ident, pid, _, nr, _, _ = struct.unpack_from('<QIIiIQ', req)
                state['cut'] += 1
                dev.cut()
                os.kill(child, signal.SIGKILL)
        finally:
            if status is None:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)
        return status
    seq.supervise = supervise
    sys.argv = [SEQ, '--notify', 'ioctl:1=%d' % RNDADD, '--', bash, '--noprofile', '--norc', '-c', 'rngseed load "$1"', 'scn', p]
    try:
        seq.main()
    except SystemExit:
        pass
    names = dev.recover()
    print('rngseed-load: stopped-at-credit-ioctl=%d seed-present-after-power-cut=%d' % (state['cut'] == 1, 'seed-load' in names))


def main():
    dev = Dev()
    try:
        control(dev)
        dev.up()
        load(dev, sys.argv[1])
    finally:
        sh('/usr/bin/umount', '-l', MNT, check=False)
        sh(*DM, 'remove', 'flk', '--noudevsync', '--force', check=False)
        dev.finish()
    return 0


if __name__ == '__main__':
    sys.exit(main())
