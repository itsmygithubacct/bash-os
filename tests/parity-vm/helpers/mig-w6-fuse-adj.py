#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Private FUSE filesystem with fault injection for hwclock adjtime-file fixtures.

Usage (inside `unshare --user --map-root-user --mount`):
  mig-w6-fuse-adj.py BASH MODE
MODE is one of: ok | flush | write | create | rename
It mounts a tiny in-memory FUSE filesystem (the server runs in this process,
speaking the kernel FUSE protocol over /dev/fuse) holding a prior calibration
file `adjtime` (mode 0640) and a hard link `adjtime.lnk`, then runs the
candidate shell `hwclock --systohc --utc --adjfile MNT/adjtime` with a
synthetic RTC (helpers/mig-w6-hwclock-synth.py).  The server makes the
selected operation on the temporary file `adjtime.XXXXXX` fail for real:
  flush   FUSE_FLUSH -> EIO, so the kernel's close(2) of the temporary fails
  write   FUSE_WRITE -> EIO
  create  FUSE_CREATE -> EACCES (mkstemp fails)
  rename  FUSE_RENAME -> EIO
and prints one result line from the server's and the shell's own records.
"""
import ctypes, errno, os, re, stat, struct, subprocess, sys, threading

MNT = '/tmp/parity-case/mnt'
PRIOR = b'1.250000 1700000000 0.250000\n1700000000\nUTC\n'
SYNTH = '/opt/bashos-parity/harness/helpers/mig-w6-hwclock-synth.py'
OPS = {1: 'lookup', 2: 'forget', 3: 'getattr', 4: 'setattr', 10: 'unlink', 12: 'rename', 14: 'open', 15: 'read',
       16: 'write', 17: 'statfs', 18: 'release', 20: 'fsync', 25: 'flush', 26: 'init', 27: 'opendir', 28: 'readdir',
       29: 'releasedir', 34: 'access', 35: 'create', 36: 'interrupt', 38: 'destroy', 42: 'batch_forget', 45: 'rename2'}


class Node:
    def __init__(self, ino, mode, data=b''):
        self.ino, self.mode, self.data, self.nlink = ino, mode, bytearray(data), 1


class Server:
    def __init__(self, fd, mode):
        self.fd, self.mode = fd, mode
        self.nodes = {}
        self.names = {}
        self.next_ino = 2
        self.fh = {}
        self.next_fh = 1
        self.injected = 0
        self.at_marker = None
        self.ops = []
        n = Node(2, stat.S_IFREG | 0o640, PRIOR)
        n.nlink = 2
        self.next_ino = 3
        self.nodes[2] = n
        self.names['adjtime'] = 2
        self.names['adjtime.lnk'] = 2

    def attr(self, n):
        t = 1700000000
        return struct.pack('<QQQQQQIIIIIIIIII', n.ino, len(n.data), (len(n.data) + 511) // 512, t, t, t, 0, 0, 0,
                           n.mode, n.nlink, 0, 0, 0, 4096, 0)

    def root_attr(self):
        t = 1700000000
        return struct.pack('<QQQQQQIIIIIIIIII', 1, 4096, 8, t, t, t, 0, 0, 0, stat.S_IFDIR | 0o755, 2, 0, 0, 0, 4096, 0)

    def entry(self, n):
        return struct.pack('<QQQQII', n.ino, 0, 0, 0, 0, 0) + self.attr(n)

    def reply(self, unique, err=0, payload=b''):
        os.write(self.fd, struct.pack('<IiQ', 16 + len(payload), -err, unique) + payload)

    def is_temp(self, name):
        return name.startswith('adjtime.') and name != 'adjtime.lnk'

    def serve(self):
        while True:
            try:
                buf = os.read(self.fd, 1 << 21)
            except OSError:
                return
            ln, op, unique, nodeid, uid, gid, pid = struct.unpack_from('<IIQQIII', buf)
            body = buf[40:ln]
            name = OPS.get(op, str(op))
            if op in (2, 36, 38, 42):
                continue
            if op == 26:
                self.reply(unique, 0, struct.pack('<IIIIHHIIHHII6I', 7, 31, 65536, 0, 12, 9, 65536, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
                continue
            self.ops.append(name)
            try:
                self.handle(op, unique, nodeid, body)
            except OSError as e:
                self.reply(unique, e.errno)

    def lookup(self, nm):
        ino = self.names.get(nm)
        if ino is None:
            raise OSError(errno.ENOENT, 'x')
        return self.nodes[ino]

    def handle(self, op, unique, nodeid, body):
        if op == 1:
            self.reply(unique, 0, self.entry(self.lookup(body.split(b'\0')[0].decode())))
        elif op == 3:
            if nodeid == 1:
                self.reply(unique, 0, struct.pack('<QII', 0, 0, 0) + self.root_attr())
            else:
                self.reply(unique, 0, struct.pack('<QII', 0, 0, 0) + self.attr(self.nodes[nodeid]))
        elif op == 4:
            valid, _, fhh, size = struct.unpack_from('<IIQQ', body)
            mode, = struct.unpack_from('<I', body, 68)
            n = self.nodes[nodeid]
            if valid & 1:
                n.mode = (n.mode & ~0o7777) | (mode & 0o7777)
            if valid & 8:
                del n.data[size:]
                n.data.extend(b'\0' * (size - len(n.data)))
            self.reply(unique, 0, struct.pack('<QII', 0, 0, 0) + self.attr(n))
        elif op == 35:
            flags, mode, umask, _ = struct.unpack_from('<IIII', body)
            nm = body[16:].split(b'\0')[0].decode()
            if self.mode == 'create' and self.is_temp(nm):
                self.injected += 1
                raise OSError(errno.EACCES, 'x')
            if nm in self.names:
                raise OSError(errno.EEXIST, 'x')
            n = Node(self.next_ino, stat.S_IFREG | (mode & ~umask & 0o7777))
            self.next_ino += 1
            self.nodes[n.ino] = n
            self.names[nm] = n.ino
            fh = self.next_fh
            self.next_fh += 1
            self.fh[fh] = (nm, n.ino)
            if nm == 'marker':
                self.at_marker = len(self.fh) - 1
            self.reply(unique, 0, self.entry(n) + struct.pack('<QII', fh, 0, 0))
        elif op == 14:
            n = self.nodes[nodeid]
            fh = self.next_fh
            self.next_fh += 1
            self.fh[fh] = (next((k for k, v in self.names.items() if v == nodeid), '?'), nodeid)
            self.reply(unique, 0, struct.pack('<QII', fh, 0, 0))
        elif op == 15:
            fhh, off, size = struct.unpack_from('<QQI', body)
            self.reply(unique, 0, bytes(self.nodes[nodeid].data[off:off + size]))
        elif op == 16:
            fhh, off, size = struct.unpack_from('<QQI', body)
            nm = self.fh[fhh][0]
            if self.mode == 'write' and self.is_temp(nm):
                self.injected += 1
                raise OSError(errno.EIO, 'x')
            n = self.nodes[nodeid]
            data = body[40:40 + size]
            if len(n.data) < off:
                n.data.extend(b'\0' * (off - len(n.data)))
            n.data[off:off + size] = data
            self.reply(unique, 0, struct.pack('<II', size, 0))
        elif op == 25:
            fhh = struct.unpack_from('<Q', body)[0]
            nm = self.fh[fhh][0]
            if self.mode == 'flush' and self.is_temp(nm):
                self.injected += 1
                raise OSError(errno.EIO, 'x')
            self.reply(unique, 0)
        elif op == 18:
            fhh = struct.unpack_from('<Q', body)[0]
            self.fh.pop(fhh, None)
            self.reply(unique, 0)
        elif op == 10:
            nm = body.split(b'\0')[0].decode()
            n = self.lookup(nm)
            del self.names[nm]
            n.nlink -= 1
            self.reply(unique, 0)
        elif op in (12, 45):
            newdir = struct.unpack_from('<Q', body)[0]
            rest = body[16:] if op == 45 else body[8:]
            old, new = rest.split(b'\0')[0:2]
            old, new = old.decode(), new.decode()
            if self.mode == 'rename' and self.is_temp(old):
                self.injected += 1
                raise OSError(errno.EIO, 'x')
            n = self.lookup(old)
            if new in self.names:
                self.nodes[self.names[new]].nlink -= 1
            self.names[new] = self.names.pop(old)
            self.reply(unique, 0)
        elif op in (27, 28, 29):
            if op == 27:
                self.reply(unique, 0, struct.pack('<QII', 0, 0, 0))
            elif op == 28:
                self.reply(unique, 0)
            else:
                self.reply(unique, 0)
        elif op == 17:
            self.reply(unique, 0, struct.pack('<QQQQQIII', 1000, 500, 500, 100, 50, 4096, 255, 4096) + b'\0' * 28)
        elif op == 34:
            self.reply(unique, 0)
        else:
            self.reply(unique, errno.ENOSYS)


INNER = r'''fds() { local a=(/proc/$BASHPID/fd/*) f out=; for f in "${a[@]}"; do out="$out ${f##*/}"; done; echo "$out"; }
before=$(fds)
hwclock --systohc --utc --rtc /tmp/parity-case/rtc --adjfile /tmp/parity-case/mnt/adjtime 2>/tmp/parity-case/hw.err; rc=$?
after=$(fds)
: >/tmp/parity-case/mnt/marker
echo "I:rc=$rc fds-unchanged=$([[ $before == "$after" ]] && echo 1 || echo 0)"
while IFS= read -r l; do echo "E:$l"; done </tmp/parity-case/hw.err
'''


def main():
    bash, mode = sys.argv[1], sys.argv[2]
    os.makedirs(MNT, exist_ok=True)
    open('/tmp/parity-case/rtc', 'a').close()
    open('/tmp/parity-case/synth.json', 'w').write('{"rtc": [0,0,0,1,0,100,0,0,0]}\n')
    fd = os.open('/dev/fuse', os.O_RDWR)
    libc = ctypes.CDLL(None, use_errno=True)
    opts = ('fd=%d,rootmode=40000,user_id=0,group_id=0' % fd).encode()
    if libc.mount(b'mig', MNT.encode(), b'fuse', 6, opts) != 0:
        print('mount failed: ' + os.strerror(ctypes.get_errno()))
        return 1
    srv = Server(fd, mode)
    threading.Thread(target=srv.serve, daemon=True).start()
    res = subprocess.run(['/usr/bin/python3', SYNTH, bash, '--noprofile', '--norc', '-c', INNER],
                         capture_output=True, text=True, timeout=30)
    libc.umount2(MNT.encode(), 2)
    lines = res.stdout.splitlines()
    info = {l[2:].split('=')[0]: l[2:] for l in lines if l.startswith('I:')}
    rc = re.search(r'rc=(\d+)', ' '.join(info.values())).group(1) if info else 'none'
    fdsame = 'fds-unchanged=1' in ' '.join(info.values())
    diag = [l[2:] for l in lines if l.startswith('E:')]
    events = [l for l in lines if not l.startswith(('I:', 'E:'))]
    cur = srv.nodes[srv.names['adjtime']] if 'adjtime' in srv.names else None
    lnk = srv.nodes[srv.names['adjtime.lnk']] if 'adjtime.lnk' in srv.names else None
    prior_node = srv.nodes[2]
    temps = [k for k in srv.names if srv.is_temp(k)]
    out = ['%s: rc=%s' % (mode, rc),
           'fault-reached=%d' % (srv.injected >= 1 if mode != 'ok' else 1),
           'diag-names-adjfile=%d' % any('/tmp/parity-case/mnt/adjtime' in d for d in diag),
           'diag-strerror=%s' % ('|'.join(sorted({d.rsplit(': ', 1)[-1] for d in diag})) or 'none'),
           'temp-removed=%d' % (not temps),
           'fds-unchanged=%d' % fdsame,
           'handles-open-at-return=%d' % (srv.at_marker if srv.at_marker is not None else -1),
           'rtc-set=%d' % sum(1 for e in events if e.startswith('set ')),
           'link-shares-prior-inode=%d' % (lnk is prior_node and prior_node.nlink >= 1)]
    if mode == 'ok':
        out += ['content-replaced=%d' % bool(cur and re.fullmatch(rb'1\.250000 \d+ 0\.000000\n\d+\nUTC\n', bytes(cur.data))),
                'new-mode=%o' % (cur.mode & 0o7777 if cur else 0),
                'prior-bytes-kept-on-link=%d' % (bytes(prior_node.data) == PRIOR)]
    else:
        out += ['prior-bytes-kept=%d' % (cur is prior_node and bytes(cur.data) == PRIOR),
                'prior-mode=%o' % (cur.mode & 0o7777 if cur else 0),
                'prior-nlink=%d' % (cur.nlink if cur else 0)]
    print(' '.join(out))
    open('/tmp/parity-case/ops-%s.txt' % mode, 'w').write(','.join(srv.ops) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
