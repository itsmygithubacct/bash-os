#!/usr/bin/env python3
"""Guest-only ptrace proposal for private regular-file blockdev fixtures.

No entry point is safe outside the attested parity guest. The observer is the
parent of its single tracee and never forwards an ioctl to the kernel.
"""
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import sys
import time

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.restype = ctypes.c_long
LIBC.syscall.restype = ctypes.c_long
PTRACE_TRACEME, PTRACE_PEEKDATA, PTRACE_POKEDATA = 0, 2, 5
PTRACE_SYSCALL, PTRACE_SETOPTIONS, PTRACE_GETREGS, PTRACE_SETREGS = 24, 0x4200, 12, 13
PTRACE_GET_SYSCALL_INFO = 0x420e
OPTIONS = 1 | (1 << 20)  # TRACESYSGOOD | EXITKILL
HOME = Path('/tmp/parity-home')
CASE = Path('/tmp/parity-case')
SENTINEL = HOME / 'fd-mock-additive-truncate-sentinel'
SENTINEL_BYTES = b'fd-mock-truncate-sentinel-v1\n'
MODES = ('control', 'success', 'ioctl-eio', 'ioctl-eperm', 'close-eio', 'close-eperm')
LIMIT = 20000
JOURNAL_LIMIT = 512 * 1024
JOURNAL_RESERVE = 64 * 1024
EVENT_LIMIT = 32 * 1024
STREAM_LIMIT = 16 * 1024
REAP_SECONDS = 2
ARCH_X86_64 = 0xc000003e
GETSIZE, GETSS = 0x80081272, 0x1268
PIN_FIRST = 50

class Regs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi '
        'orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs').split()]

class Info(ctypes.Structure):
    _fields_ = [('op', ctypes.c_ubyte), ('pad', ctypes.c_ubyte * 3),
                ('arch', ctypes.c_uint), ('ip', ctypes.c_ulonglong),
                ('sp', ctypes.c_ulonglong), ('payload', ctypes.c_ubyte * 56)]

def ptrace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, ctypes.c_void_p(address),
                         data if not isinstance(data, int) else ctypes.c_void_p(data))
    if result == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result

def syscall(number, *args):
    ctypes.set_errno(0)
    result = LIBC.syscall(number, *(ctypes.c_long(x) for x in args))
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result

def readmem(pid, address, count):
    if not address or count < 0 or count > 4096:
        raise ValueError('invalid tracee memory range')
    out = bytearray()
    for off in range(0, count, 8):
        word = ptrace(PTRACE_PEEKDATA, pid, address + off) & ((1 << 64) - 1)
        out.extend(struct.pack('<Q', word))
    return bytes(out[:count])

def readstr(pid, address):
    out = bytearray()
    for off in range(0, 4096, 8):
        part = readmem(pid, address + off, 8)
        if b'\0' in part:
            return (out + part[:part.index(0)]).decode('utf-8', 'strict')
        out.extend(part)
    raise ValueError('unterminated path')

def writemem(pid, address, data):
    # Preserve surrounding bytes even when the destination is unaligned.
    for index, byte in enumerate(data):
        aligned = (address + index) & ~7
        shift = ((address + index) - aligned) * 8
        old = ptrace(PTRACE_PEEKDATA, pid, aligned) & ((1 << 64) - 1)
        ptrace(PTRACE_POKEDATA, pid, aligned, (old & ~(255 << shift)) | (byte << shift))

def statfd(pid, fd):
    path = Path('/proc') / str(pid) / 'fd' / str(fd)
    s = path.stat()
    return {'dev': s.st_dev, 'ino': s.st_ino, 'mode': s.st_mode,
            'target': os.readlink(path)}

def fdinfo(pid, fd):
    """Retain the stopped tracee's raw descriptor flags for channel binding."""
    with (Path('/proc') / str(pid) / 'fdinfo' / str(fd)).open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096: raise RuntimeError('descriptor info limit')
    flags = [line.split(b':', 1)[1].strip() for line in raw.splitlines()
             if line.startswith(b'flags:')]
    if len(flags) != 1: raise RuntimeError('descriptor flags missing')
    return {'flags': int(flags[0], 8), 'raw_base64': base64.b64encode(raw).decode('ascii')}

def sentinel_snapshot(fd):
    """Read a held private inode; retain even an invalid observation for review."""
    before = os.fstat(fd)
    named = SENTINEL.lstat()
    raw = os.pread(fd, 256, 0)
    after = os.fstat(fd)
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                        s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    valid = (fields(before) == fields(after) and stat.S_ISREG(after.st_mode) and
             after.st_uid == 2000 and stat.S_IMODE(after.st_mode) == 0o600 and
             after.st_nlink == 1 and (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino) and
             stat.S_ISREG(named.st_mode) and after.st_size == len(SENTINEL_BYTES) and
             raw == SENTINEL_BYTES)
    return {'valid': valid, 'dev': after.st_dev, 'ino': after.st_ino, 'mode': after.st_mode,
            'uid': after.st_uid, 'gid': after.st_gid, 'nlink': after.st_nlink,
            'size': after.st_size, 'mtime_ns': after.st_mtime_ns, 'ctime_ns': after.st_ctime_ns,
            'bytes': len(raw), 'base64': base64.b64encode(raw).decode('ascii'),
            'sha256': hashlib.sha256(raw).hexdigest()}

def evidence_inodes(held):
    """Find bounded named evidence and the currently held writable inodes."""
    found = {}
    def add(name, s):
        if not stat.S_ISREG(s.st_mode):
            raise RuntimeError('evidence inode is not regular: ' + name)
        found.setdefault((s.st_dev, s.st_ino), []).append(name)
    for name, fd in held.items():
        add(name, os.fstat(fd))
    names = ['fd-mock-additive-record.json', 'fd-mock-additive-record.tmp',
             'fd-mock-additive-index-error.json', SENTINEL.name]
    for mode in MODES:
        stem = 'fd-mock-additive-' + mode
        names.extend((stem + '.jsonl', stem + '-capture.json', stem + '.out', stem + '.err'))
    for name in names:
        try: s = (HOME / name).lstat()
        except FileNotFoundError: continue
        add(name, s)
    return found

def unrelated_private_truncate(path, evidence):
    """Allow only a provably distinct direct private regular scratch object."""
    if not isinstance(path, str) or path != str(CASE / Path(path).name):
        return None
    try: s = Path(path).lstat()
    except OSError: return None
    identity = (s.st_dev, s.st_ino)
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != 2000 or s.st_nlink != 1 or
            stat.S_IMODE(s.st_mode) & 0o022 or identity in evidence):
        return None
    return {'dev': s.st_dev, 'ino': s.st_ino, 'mode': s.st_mode,
            'uid': s.st_uid, 'nlink': s.st_nlink}

def regs(pid):
    value = Regs()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(value))
    return value

def setregs(pid, value):
    ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(value))

def reg_record(value):
    return {name: int(getattr(value, name)) for name, _ in Regs._fields_}

def process_start(pid):
    raw = (Path('/proc') / str(pid) / 'stat').read_bytes()
    if len(raw) > 4096:
        raise RuntimeError('process stat limit')
    fields = raw.rsplit(b')', 1)[1].split()
    return {'raw_base64': base64.b64encode(raw).decode(), 'starttime': int(fields[19])}

def protected_executable(path):
    """Only root-controlled paths may be executed by the guest tracee."""
    resolved, initial, chain = protected_resolution(path)
    if not resolved.is_absolute():
        raise RuntimeError('executable path must be absolute')
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise RuntimeError('executable changed before open')
        digest = hashlib.sha256()
        total = 0
        while True:
            data = os.read(fd, 131072)
            if not data: break
            total += len(data)
            if total > 128 * 1024 * 1024: raise RuntimeError('executable size limit')
            digest.update(data)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('executable changed during hashing')
    finally:
        os.close(fd)
    return {'requested': path, 'resolved': str(resolved), 'dev': before.st_dev,
            'ino': before.st_ino, 'size': before.st_size, 'uid': before.st_uid,
            'gid': before.st_gid, 'mode': before.st_mode, 'chain': chain,
            'sha256': digest.hexdigest()}

def argv_at(pid, address):
    result = []
    for index in range(16):
        pointer = struct.unpack('<Q', readmem(pid, address + index * 8, 8))[0]
        if not pointer: return result
        result.append(readstr(pid, pointer))
    raise RuntimeError('exec argument count limit')

def protected_resolution(path):
    """Resolve each link only through root-owned non-writable directories."""
    if not path.startswith('/'):
        raise RuntimeError('relative protected path')
    pending = list(Path(path).parts[1:])
    current = Path('/')
    root = current.lstat()
    if not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_mode & 0o022:
        raise RuntimeError('unprotected filesystem root')
    chain = [{'path': '/', 'dev': root.st_dev, 'ino': root.st_ino, 'mode': root.st_mode,
              'uid': root.st_uid, 'gid': root.st_gid}]
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            current = current.parent
            continue
        candidate = current / part
        entry = candidate.lstat()
        if entry.st_uid != 0:
            raise RuntimeError('untrusted protected path owner')
        component = {'path': str(candidate), 'dev': entry.st_dev, 'ino': entry.st_ino,
                     'mode': entry.st_mode, 'uid': entry.st_uid, 'gid': entry.st_gid}
        chain.append(component)
        if len(chain) > 128: raise RuntimeError('protected path component limit')
        if stat.S_ISLNK(entry.st_mode):
            links += 1
            if links > 32: raise RuntimeError('protected path link limit')
            target = os.readlink(candidate)
            component['link_target'] = target
            target_parts = list(Path(target).parts)
            if target.startswith('/'):
                current = Path('/')
                target_parts = target_parts[1:]
            pending = target_parts + pending
            continue
        if pending:
            if not stat.S_ISDIR(entry.st_mode) or entry.st_mode & 0o022:
                raise RuntimeError('unprotected path directory')
            current = candidate
        else:
            if not stat.S_ISREG(entry.st_mode) or entry.st_mode & 0o022:
                raise RuntimeError('protected target is not immutable regular file')
            return candidate, entry, chain
    raise RuntimeError('protected path has no regular target')

def trusted_startup_open(path, flags):
    """Only immutable root-owned regular runtime files can be opened at startup."""
    if not path.startswith('/') or flags & (os.O_ACCMODE | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        return None
    try:
        resolved, target, chain = protected_resolution(path)
        if not (str(resolved).startswith('/usr/') or str(resolved).startswith('/lib/') or
                str(resolved) == '/etc/ld.so.cache'):
            return None
        return {'resolved': str(resolved), 'dev': target.st_dev, 'ino': target.st_ino,
                'mode': target.st_mode, 'uid': target.st_uid, 'gid': target.st_gid,
                'chain': chain}
    except (OSError, ValueError, RuntimeError):
        return None

def inventory(pid):
    names = sorted(int(x) for x in os.listdir('/proc/%d/fd' % pid))
    if len(names) > 64:
        raise RuntimeError('descriptor inventory limit')
    return {str(n): statfd(pid, n) for n in names}

def snapshot(pid):
    """Keep pidfd duplicates for later OFD comparison; permission failure is explicit."""
    result = {'pid': pid, 'process': process_start(pid), 'monotonic_ns': time.monotonic_ns(),
              'inventory': inventory(pid), 'copies': {}, 'error': None}
    try:
        pfd = syscall(434, pid, 0)
        try:
            for name in result['inventory']:
                result['copies'][name] = syscall(438, pfd, int(name), 0)
        finally:
            os.close(pfd)
    except OSError as exc:
        result['error'] = {'errno': exc.errno, 'message': str(exc)}
    return result

def compare(before, after):
    result = {'before': before['inventory'], 'after': after['inventory'],
              'before_pid': before['pid'], 'after_pid': after['pid'],
              'before_process': before['process'], 'after_process': after['process'],
              'before_monotonic_ns': before['monotonic_ns'], 'after_monotonic_ns': after['monotonic_ns'],
              'before_error': before['error'], 'after_error': after['error'],
              'comparisons': {}, 'error': None}
    if before['error'] or after['error']:
        return result
    try:
        for key in before['copies'].keys() & after['copies'].keys():
            result['comparisons'][key] = syscall(312, os.getpid(), os.getpid(), 0,
                                                 before['copies'][key], after['copies'][key])
    except OSError as exc:
        result['error'] = {'errno': exc.errno, 'message': str(exc)}
    return result

def fd_controls(pinned_fd):
    """Distinguish a dup from a separate open of the same regular object."""
    pinned = os.fstat(pinned_fd)
    if not stat.S_ISREG(pinned.st_mode): raise RuntimeError('control object is not regular')
    a = os.dup(pinned_fd)
    b = os.dup(a)
    # /proc/self/fd is resolved while this single process owns the pinned fd.
    c = os.open('/proc/self/fd/%d' % pinned_fd, os.O_RDONLY | os.O_CLOEXEC)
    try:
        identities = {}
        for name, fd in (('original', a), ('dup', b), ('separate', c)):
            s = os.fstat(fd)
            identities[name] = {'fd': fd, 'dev': s.st_dev, 'ino': s.st_ino,
                                'mode': s.st_mode, 'flags': fcntl.fcntl(fd, fcntl.F_GETFL)}
        try:
            return {'same': syscall(312, os.getpid(), os.getpid(), 0, a, b),
                    'different': syscall(312, os.getpid(), os.getpid(), 0, a, c),
                    'pid': os.getpid(), 'identities': identities}
        except OSError as exc:
            return {'error': {'errno': exc.errno, 'message': str(exc)},
                    'pid': os.getpid(), 'identities': identities}
    finally:
        os.close(a); os.close(b); os.close(c)

def capture(fd):
    """Read the exclusively-created pinned output inode, never a new pathname."""
    chunks = []
    offset = 0
    failure = None
    before = after = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError('capture inode is not private regular file')
        remaining = STREAM_LIMIT + 1
        while remaining:
            data = os.pread(fd, min(remaining, 8192), offset)
            if not data: break
            chunks.append(data); remaining -= len(data); offset += len(data)
    except (OSError, RuntimeError) as exc:
        failure = {'type': type(exc).__name__, 'message': str(exc)}
    raw = b''.join(chunks)
    try:
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if before is not None and fields(before) != fields(after):
            failure = {'type': 'UnstableCapture', 'message': 'capture changed during read'}
    except OSError as exc:
        failure = {'type': type(exc).__name__, 'message': str(exc)}
    retained = raw[:STREAM_LIMIT]
    size = after.st_size if after is not None else None
    return {'bytes': len(retained), 'file_size': size, 'sha256': hashlib.sha256(retained).hexdigest(),
            'base64': base64.b64encode(retained).decode('ascii'),
            'at_limit': size is not None and size >= STREAM_LIMIT,
            'complete': failure is None and size is not None and len(raw) == size and size < STREAM_LIMIT,
            'error': failure, 'dev': after.st_dev if after else None, 'ino': after.st_ino if after else None,
            'mode': after.st_mode if after else None, 'nlink': after.st_nlink if after else None}

def save_capture(label, value):
    """One immutable bounded per-run capture, independent of the aggregate index."""
    name = 'fd-mock-additive-' + label + '-capture.json'
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(data) > 65536: raise RuntimeError('capture record limit')
    fd = os.open(HOME / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0: raise RuntimeError('short capture record write')
            offset += written
        os.fsync(fd)
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size != len(data):
            raise RuntimeError('capture record identity mismatch')
    finally:
        os.close(fd)
    return {'name': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'dev': s.st_dev, 'ino': s.st_ino}

class JournalLimit(Exception):
    pass

class Journal:
    """Per-run append-only checkpoints; same-UID integrity still needs a witness."""
    def __init__(self, label):
        self.name = 'fd-mock-additive-' + label + '.jsonl'
        self.fd = os.open(HOME / self.name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL |
                          os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.sequence = 0
        self.size = 0
        self.previous = '0' * 64
        self.limit_reported = False

    def emit(self, kind, data, critical=False):
        value = {'sequence': self.sequence + 1, 'kind': kind, 'data': data,
                 'previous_sha256': self.previous, 'monotonic_ns': time.monotonic_ns()}
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        ceiling = JOURNAL_LIMIT if critical else JOURNAL_LIMIT - JOURNAL_RESERVE
        if len(raw) > EVENT_LIMIT or self.size + len(raw) > ceiling:
            if not self.limit_reported and not critical:
                self.limit_reported = True
                self.emit('journal-limit', {'rejected_kind': kind, 'rejected_bytes': len(raw),
                          'rejected_sha256': hashlib.sha256(raw).hexdigest()}, critical=True)
            raise JournalLimit('journal event or size limit')
        before = os.fstat(self.fd)
        named = os.stat(HOME / self.name, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != self.size or
                (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError('journal identity or length changed')
        offset = 0
        while offset < len(raw):
            n = os.write(self.fd, raw[offset:])
            if n <= 0: raise OSError('short journal write')
            offset += n
        os.fsync(self.fd)
        self.sequence += 1
        self.size += len(raw)
        self.previous = hashlib.sha256(raw).hexdigest()

    def close(self):
        os.close(self.fd)

def stream_checkpoint(journal, streams, readers, offsets, eof, critical=False, barrier=None):
    """Drain nonblocking pipe reads into observer-only append files and journal."""
    drained = {}
    order = list(streams)
    if barrier is not None:
        first = 'stdout' if barrier['fd'] == 1 else 'stderr'
        order.remove(first)
        order.insert(0, first)
    for name in order:
        fd = streams[name]
        pipe = os.fstat(readers[name])
        if not stat.S_ISFIFO(pipe.st_mode): raise RuntimeError('stream pipe changed')
        if eof[name]:
            drained[name] = 'eof'
        while not eof[name]:
            if offsets[name] >= STREAM_LIMIT: raise JournalLimit('stream capture limit')
            try:
                data = os.read(readers[name], min(8192, STREAM_LIMIT - offsets[name]))
            except BlockingIOError:
                drained[name] = 'empty'
                break
            if not data:
                eof[name] = True
                journal.emit('stream-eof', {'name': name, 'offset': offsets[name],
                             'pipe_dev': pipe.st_dev, 'pipe_ino': pipe.st_ino}, critical=critical)
                drained[name] = 'eof'
                break
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_size != offsets[name] or
                    not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_APPEND):
                raise RuntimeError('observer stream inode, offset or append flag changed')
            written = 0
            while written < len(data):
                count = os.write(fd, data[written:])
                if count <= 0: raise OSError('short observer stream write')
                written += count
            after = os.fstat(fd)
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or
                    after.st_nlink != 1 or after.st_size != offsets[name] + len(data)):
                raise RuntimeError('observer stream changed during append')
            journal.emit('stream', {'name': name, 'offset': offsets[name], 'bytes': len(data),
                         'base64': base64.b64encode(data).decode('ascii'),
                         'sha256': hashlib.sha256(data).hexdigest(),
                         'dev': before.st_dev, 'ino': before.st_ino,
                         'pipe_dev': pipe.st_dev, 'pipe_ino': pipe.st_ino}, critical=critical)
            offsets[name] += len(data)
            if offsets[name] >= STREAM_LIMIT:
                journal.emit('stream-limit', {'name': name, 'retained_bytes': offsets[name]}, critical=True)
                raise JournalLimit('stream capture limit')
        if barrier is not None:
            journal.emit('stream-barrier', {**barrier, 'name': name, 'drained': drained[name],
                         'offset': offsets[name], 'pipe_dev': pipe.st_dev, 'pipe_ino': pipe.st_ino},
                         critical=critical)
    return drained

NATIVE = r'''import ctypes, errno, os, fcntl, json
L=ctypes.CDLL(None,use_errno=True); L.syscall.restype=ctypes.c_long
A='/tmp/parity-case/fd-mock-additive-a'; B='/tmp/parity-case/fd-mock-additive-b'; C='/tmp/parity-case/fd-mock-additive-c'
D='/tmp/parity-case/fd-mock-additive-d'; E='/tmp/parity-case/fd-mock-additive-e'
S='/tmp/parity-home/fd-mock-additive-truncate-sentinel'
def call(n,*a):
    ctypes.set_errno(0); r=L.syscall(n,*a); return (r,ctypes.get_errno())
def checkpoint(name,value):
    os.write(1,('FD_MOCK_NATIVE_'+name+'='+json.dumps(value,sort_keys=True)+'\n').encode())
os.write(2,b'FD_MOCK_BEGIN\n')
os.write(1,b'FD_MOCK_CAPTURE_SENTINEL\n')
try: os.ftruncate(1,0); ftruncate_errno=0
except OSError as e: ftruncate_errno=e.errno
try: os.truncate(S,0); truncate_errno=0
except OSError as e: truncate_errno=e.errno
checkpoint('TRUNCATE',dict(truncate_errno=truncate_errno,ftruncate_errno=ftruncate_errno))
def stream_error(fd,op):
 try:
  if op=='pwrite': os.pwrite(fd,b'X',0)
  else: os.lseek(fd,0,os.SEEK_SET)
  return 0
 except OSError as e: return e.errno
checkpoint('STREAM',dict(stdout_pwrite=stream_error(1,'pwrite'),stderr_pwrite=stream_error(2,'pwrite'),
                         stdout_seek=stream_error(1,'seek'),stderr_seek=stream_error(2,'seek')))
try: os.open('/tmp/parity-case/fd-mock-additive-unregistered',os.O_RDONLY); denied=False
except OSError as e: denied=(e.errno==errno.ENOENT)
def rejected(path):
 try: os.close(os.open(path,os.O_RDONLY)); return False
 except OSError as e: return e.errno==errno.EPERM
symlink_denied=rejected(D); replaced_denied=rejected(E)
checkpoint('PATHS',dict(denied=denied,symlink_denied=symlink_denied,replaced_denied=replaced_denied))
a=os.open(A,os.O_RDONLY); x=ctypes.c_int()
r1=call(16,a,0x1268,ctypes.byref(x)); r2=call(16,a,0x1268,ctypes.byref(x)); r3=call(16,a,0x1268,ctypes.byref(x))
checkpoint('IOCTL',dict(eio=r1,eperm=r2,success=r3,value=x.value))
cl=call(3,a)
try: fcntl.fcntl(a,fcntl.F_GETFD); closed=False
except OSError as e: closed=(e.errno==errno.EBADF)
c=os.open(C,os.O_RDONLY); reused=(c==a)
r4=call(16,c,0x1268,ctypes.byref(x)); os.close(c)
checkpoint('CLOSE_EIO',dict(close=cl,closed=closed,reused=reused,other=r4))
b=os.open(B,os.O_RDONLY); cb=call(3,b)
try: fcntl.fcntl(b,fcntl.F_GETFD); bclosed=False
except OSError as e: bclosed=(e.errno==errno.EBADF)
b2=os.open(B,os.O_RDONLY); breused=(b2==b); os.close(b2)
checkpoint('CLOSE_EPERM',dict(close_eperm=cb,bclosed=bclosed,breused=breused))
os.write(1,(json.dumps(dict(truncate_errno=truncate_errno,ftruncate_errno=ftruncate_errno,eio=r1,eperm=r2,success=r3,value=x.value,close=cl,closed=closed,reused=reused,other=r4,close_eperm=cb,bclosed=bclosed,breused=breused,denied=denied,symlink_denied=symlink_denied,replaced_denied=replaced_denied))+'\n').encode())
os.write(2,b'FD_MOCK_END\n')
'''

SHELL = r'''builtin printf 'FD_MOCK_BEGIN\n'
builtin blockdev --getsize64 --getss /tmp/parity-case/fd-mock-additive-a /tmp/parity-case/fd-mock-additive-b
r=$?
builtin printf 'FD_MOCK_RESULT=%s\n' "$r"
builtin printf 'FD_MOCK_END\n'
exit 0
'''

def trace(program, arguments, paths, pins, expected_exe, mode, label, sentinel_fd):
    output = HOME / ('fd-mock-additive-' + label + '.out')
    error = HOME / ('fd-mock-additive-' + label + '.err')
    journal = Journal(label)
    outfd = errfd = None
    readers, writers, pipe_setup = {}, {}, {}
    try:
        journal.emit('header', {'mode': mode, 'program': program, 'argv': [program] + arguments,
                                'expected_exe': expected_exe, 'registered': paths,
                                'pin_fds': {name: item['child_fd'] for name, item in pins.items()},
                                'journal_limit': JOURNAL_LIMIT, 'reserve': JOURNAL_RESERVE,
                                'stream_limit': STREAM_LIMIT, 'parent_pid': os.getpid()})
        capture_flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        outfd = os.open(output, capture_flags, 0o600)
        errfd = os.open(error, capture_flags, 0o600)
        for name, capture_fd in (('stdout', outfd), ('stderr', errfd)):
            readers[name], writers[name] = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(readers[name], False)
            read_stat, write_stat = os.fstat(readers[name]), os.fstat(writers[name])
            read_flags = fcntl.fcntl(readers[name], fcntl.F_GETFL)
            write_flags = fcntl.fcntl(writers[name], fcntl.F_GETFL)
            capture_stat = os.fstat(capture_fd)
            if (not stat.S_ISFIFO(read_stat.st_mode) or not stat.S_ISFIFO(write_stat.st_mode) or
                    (read_stat.st_dev, read_stat.st_ino) != (write_stat.st_dev, write_stat.st_ino) or
                    read_flags & os.O_ACCMODE != os.O_RDONLY or not read_flags & os.O_NONBLOCK or
                    write_flags & os.O_ACCMODE != os.O_WRONLY or write_flags & os.O_NONBLOCK or
                    not stat.S_ISREG(capture_stat.st_mode) or capture_stat.st_nlink != 1 or
                    capture_stat.st_uid != 2000 or stat.S_IMODE(capture_stat.st_mode) & 0o077 or
                    capture_stat.st_size != 0):
                raise RuntimeError('invalid stream pipe or capture setup')
            pipe_setup[name] = {'pipe_dev': read_stat.st_dev, 'pipe_ino': read_stat.st_ino,
                                'pipe_mode': read_stat.st_mode, 'read_fd': readers[name],
                                'write_fd': writers[name], 'read_flags': read_flags,
                                'write_flags': write_flags, 'capture_fd': capture_fd, 'capture_dev': capture_stat.st_dev,
                                'capture_ino': capture_stat.st_ino, 'capture_mode': capture_stat.st_mode,
                                'capture_uid': capture_stat.st_uid, 'capture_gid': capture_stat.st_gid,
                                'capture_nlink': capture_stat.st_nlink, 'capture_size': capture_stat.st_size,
                                'capture_flags': fcntl.fcntl(capture_fd, fcntl.F_GETFL)}
        if ((pipe_setup['stdout']['pipe_dev'], pipe_setup['stdout']['pipe_ino']) ==
                (pipe_setup['stderr']['pipe_dev'], pipe_setup['stderr']['pipe_ino'])):
            raise RuntimeError('stdout and stderr pipes must be distinct')
        journal.emit('stream-setup', {'channels': pipe_setup, 'capture_open_flags': capture_flags})
        sentinel_before = sentinel_snapshot(sentinel_fd)
        journal.emit('truncate-sentinel-before', sentinel_before)
        if not sentinel_before['valid']: raise RuntimeError('invalid truncate sentinel before trace')
        stop_deadline = time.monotonic() + 8
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        child = os.fork()
    except BaseException as exc:
        try: journal.emit('launch-error', {'type': type(exc).__name__, 'message': str(exc)}, critical=True)
        except Exception: pass
        for fd in (outfd, errfd, *readers.values(), *writers.values()):
            if fd is not None: os.close(fd)
        journal.close()
        raise
    if child == 0:
        try:
            os.dup2(pins[str(CASE / 'fd-mock-additive-c')]['fd'], 0)
            os.dup2(writers['stdout'], 1); os.dup2(writers['stderr'], 2)
            for item in pins.values():
                os.dup2(item['fd'], item['child_fd'], inheritable=True)
            os.closerange(3, PIN_FIRST)
            os.closerange(PIN_FIRST + len(pins), 1024)
            resource.setrlimit(resource.RLIMIT_FSIZE, (131072, 131072))
            ptrace(PTRACE_TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execve(program, [program] + arguments, {'HOME': str(HOME), 'PATH': '/empty', 'LC_ALL': 'C', 'BASH_ENV': '', 'ENV': '', 'HISTFILE': '/dev/null', 'PYTHONDONTWRITEBYTECODE': '1'})
        except BaseException:
            os._exit(125)
    parent_writer_close_errors, parent_writer_closes = [], {}
    for name, fd in writers.items():
        closed = {'fd': fd, 'close_returned': False, 'readback_errno': None}
        try:
            os.close(fd)
            closed['close_returned'] = True
        except OSError as exc:
            parent_writer_close_errors.append({'name': name, 'errno': exc.errno, 'message': str(exc)})
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as exc:
            closed['readback_errno'] = exc.errno
            if exc.errno != errno.EBADF:
                parent_writer_close_errors.append({'name': name, 'errno': exc.errno, 'message': str(exc)})
        else:
            parent_writer_close_errors.append({'name': name, 'message': 'parent writer still open'})
        parent_writer_closes[name] = closed
    events, owned, generations, closed_targets = [], {}, {}, set()
    pending = None
    active = False
    exec_seen = False
    before = after = None
    status = None
    exec_event = None
    start_identity = None
    awaiting_stop = None
    observer_error = None
    forced_cleanup = False
    reaped = False
    cleanup = {'pid': child, 'pidfd_opened': False, 'reap_pending': False}
    pidfd = None
    log_errors = []
    offsets = {'stdout': 0, 'stderr': 0}
    eof = {'stdout': False, 'stderr': False}
    streams = {'stdout': outfd, 'stderr': errfd}
    comparison = None
    syscall_sequence = 0
    violations = []
    truncate_control_seen = ftruncate_control_seen = False
    def terminal(kind, data):
        try: journal.emit(kind, data, critical=True)
        except Exception as exc:
            if len(log_errors) < 8: log_errors.append({'type': type(exc).__name__, 'message': str(exc)})
    def deny_guarded_syscall(event):
        value = regs(child)
        value.orig_rax = (1 << 64) - 1
        setregs(child, value)
        checked = regs(child)
        if checked.orig_rax != (1 << 64) - 1:
            raise RuntimeError('mutation guard syscall rewrite did not persist')
        event['guard_skip_regs'] = reg_record(checked)
        event['injected'] = -errno.EPERM
    def stream_bindings():
        result = {}
        for name, number in (('stdout', 1), ('stderr', 2)):
            try:
                result[name] = {'fd': number, 'identity': statfd(child, number),
                                'fdinfo': fdinfo(child, number)}
            except FileNotFoundError:
                result[name] = {'fd': number, 'missing': True}
        return result
    def reserved_child():
        nonlocal reaped, status
        try:
            waited, raw = os.waitpid(child, os.WNOHANG)
        except (ChildProcessError, OSError) as exc:
            cleanup['ownership_error'] = {'type': type(exc).__name__, 'message': str(exc)}
            return False
        if waited:
            cleanup['pre_signal_wait_status'] = raw
            terminal('cleanup-pre-signal-wait', {'pid': child, 'wait_status': raw})
            if os.WIFEXITED(raw) or os.WIFSIGNALED(raw):
                reaped = True
                status = {'exit': os.WEXITSTATUS(raw) if os.WIFEXITED(raw) else None,
                          'signal': os.WTERMSIG(raw) if os.WIFSIGNALED(raw) else None,
                          'raw_wait_status': raw}
                return False
        return True
    try:
        journal.emit('parent-pipe-writers-closed', {'writers': parent_writer_closes,
                                                   'errors': parent_writer_close_errors})
        if parent_writer_close_errors: raise RuntimeError('parent pipe writer close failed')
        start_identity = process_start(child)
        journal.emit('child-created', {'pid': child, 'start': start_identity,
                                      'stop_deadline_ns': int(stop_deadline * 1000000000)})
        try:
            pidfd = os.pidfd_open(child, 0)
            cleanup['pidfd_opened'] = True
            cleanup['pidfd_number'] = pidfd
            try:
                with (Path('/proc/self/fdinfo') / str(pidfd)).open('rb') as info:
                    raw = info.read(4097)
                if len(raw) > 4096: raise RuntimeError('pidfd info limit')
                cleanup['pidfd_info_b64'] = base64.b64encode(raw).decode()
            except (OSError, RuntimeError) as exc:
                cleanup['pidfd_info_error'] = {'type': type(exc).__name__, 'message': str(exc)}
        except (OSError, AttributeError) as exc:
            cleanup['pidfd_error'] = {'type': type(exc).__name__, 'message': str(exc)}
        journal.emit('pidfd', dict(cleanup))
        while True:
            stream_checkpoint(journal, streams, readers, offsets, eof)
            if time.monotonic() >= stop_deadline:
                raise TimeoutError('initial trace stop deadline')
            waited, st = os.waitpid(child, os.WNOHANG)
            if not waited:
                time.sleep(.001); continue
            journal.emit('initial-wait', {'pid': child, 'wait_status': st})
            if os.WIFEXITED(st) or os.WIFSIGNALED(st):
                reaped = True
                status = {'exit': os.WEXITSTATUS(st) if os.WIFEXITED(st) else None,
                          'signal': os.WTERMSIG(st) if os.WIFSIGNALED(st) else None,
                          'raw_wait_status': st}
                raise RuntimeError('tracee exited before initial stop')
            if not os.WIFSTOPPED(st) or os.WSTOPSIG(st) != signal.SIGSTOP:
                raise RuntimeError('unexpected initial trace stop')
            break
        initial_inventory = inventory(child)
        expected_fds = {'0', '1', '2'} | {str(item['child_fd']) for item in pins.values()}
        if set(initial_inventory) != expected_fds:
            raise RuntimeError('unexpected descriptor at initial trace stop')
        protected_ids = {(item['capture_dev'], item['capture_ino']) for item in pipe_setup.values()}
        for held in (journal.fd, sentinel_fd):
            held_stat = os.fstat(held)
            protected_ids.add((held_stat.st_dev, held_stat.st_ino))
        if any((item['dev'], item['ino']) in protected_ids for item in initial_inventory.values()):
            raise RuntimeError('tracee inherited observer evidence')
        pin_bindings = {}
        pin_targets = [(0, str(CASE / 'fd-mock-additive-c'))]
        pin_targets.extend((item['child_fd'], path) for path, item in pins.items())
        for number, path in pin_targets:
            observed = initial_inventory[str(number)]
            info = fdinfo(child, number)
            if (not stat.S_ISREG(observed['mode']) or
                    (observed['dev'], observed['ino']) != paths[path] or
                    info['flags'] & os.O_ACCMODE != os.O_RDONLY):
                raise RuntimeError('tracee read-only pin binding differs')
            pin_bindings[str(number)] = {'identity': observed, 'fdinfo': info, 'registered': path}
        binding = stream_bindings()
        for name, number in (('stdout', 1), ('stderr', 2)):
            observed = initial_inventory[str(number)]
            info = binding[name]['fdinfo']
            flags = info['flags']
            if (not stat.S_ISFIFO(observed['mode']) or
                    (observed['dev'], observed['ino']) != (pipe_setup[name]['pipe_dev'], pipe_setup[name]['pipe_ino']) or
                    flags & os.O_ACCMODE != os.O_WRONLY or flags & (os.O_NONBLOCK | os.O_CLOEXEC)):
                raise RuntimeError('tracee stream pipe binding differs')
        journal.emit('stream-binding', {'pid': child, 'inventory': initial_inventory,
                                        'channels': binding, 'pin_bindings': pin_bindings})
        ptrace(PTRACE_SETOPTIONS, child, 0, OPTIONS)
        journal.emit('trace-options', {'pid': child, 'options': OPTIONS})
        initial_resume = ptrace(PTRACE_SYSCALL, child)
        journal.emit('initial-resume', {'pid': child, 'result': initial_resume})
        while True:
            stream_checkpoint(journal, streams, readers, offsets, eof)
            if time.monotonic() > stop_deadline:
                raise TimeoutError('tracee timeout')
            waited, st = os.waitpid(child, os.WNOHANG)
            if not waited:
                time.sleep(.001); continue
            if awaiting_stop is not None:
                next_stop = {'pid': child, 'wait_status': st, 'monotonic_ns': time.monotonic_ns()}
                if os.WIFSTOPPED(st) and os.WSTOPSIG(st) == (signal.SIGTRAP | 0x80):
                    next_info = Info()
                    info_size = ptrace(PTRACE_GET_SYSCALL_INFO, child, ctypes.sizeof(next_info), ctypes.byref(next_info))
                    next_stop.update(op=next_info.op, arch=next_info.arch, ip=next_info.ip,
                                     info_size=info_size, payload_hex=bytes(next_info.payload).hex(),
                                     regs=reg_record(regs(child)))
                    if next_info.op == 1:
                        next_stop['syscall'] = struct.unpack_from('<Q', bytes(next_info.payload))[0]
                awaiting_stop['next_stop'] = next_stop
                journal.emit('next-stop', {'event_id': awaiting_stop['event_id'], 'stop': next_stop})
                awaiting_stop = None
            if os.WIFEXITED(st) or os.WIFSIGNALED(st):
                reaped = True
                status = {'exit': os.WEXITSTATUS(st) if os.WIFEXITED(st) else None,
                          'signal': os.WTERMSIG(st) if os.WIFSIGNALED(st) else None,
                          'raw_wait_status': st}
                journal.emit('subject-exit', {'pid': child, 'status': status})
                stream_checkpoint(journal, streams, readers, offsets, eof)
                if not all(eof.values()): raise RuntimeError('stream pipe EOF missing after subject exit')
                break
            if not os.WIFSTOPPED(st): raise RuntimeError('unexpected wait state')
            sig = os.WSTOPSIG(st)
            current_binding = stream_bindings()
            if current_binding != binding:
                journal.emit('stream-rebinding', {'pid': child, 'wait_status': st,
                             'previous': binding, 'channels': current_binding})
                binding = current_binding
            barrier_event = None
            if sig != (signal.SIGTRAP | 0x80):
                journal.emit('signal-stop', {'pid': child, 'wait_status': st, 'signal': sig,
                                             'monotonic_ns': time.monotonic_ns()})
            if sig == (signal.SIGTRAP | 0x80):
                info = Info()
                n = ptrace(PTRACE_GET_SYSCALL_INFO, child, ctypes.sizeof(info), ctypes.byref(info))
                if n < 24 or info.arch != ARCH_X86_64 or (info.op == 1 and n < 80) or (info.op == 2 and n < 33):
                    raise RuntimeError('unsupported syscall-info architecture')
                if info.op == 1:
                    syscall_sequence += 1
                    nr, *args = struct.unpack_from('<7Q', bytes(info.payload))
                    pending = {'syscall_id': syscall_sequence, 'nr': nr, 'args': args, 'entry_stop': {'pid': child,
                               'wait_status': st, 'op': info.op, 'arch': info.arch,
                               'ip': info.ip, 'sp': info.sp, 'info_size': n,
                               'payload_hex': bytes(info.payload).hex(), 'monotonic_ns': time.monotonic_ns(),
                               'regs': reg_record(regs(child))}}
                    # x32 shares AUDIT_ARCH_X86_64 but uses a distinct syscall
                    # number space; never let it bypass the x86-64 guards.
                    if nr & 0x40000000:
                        pending['mutation_guard'] = {'operation': 'unsupported-x32-abi',
                                                     'decision': 'deny-unsupported-abi',
                                                     'expected_control': False}
                        violations.append({'syscall': nr, 'reason': 'unsupported syscall ABI'})
                        deny_guarded_syscall(pending)
                    # No tracee descendants or replacement executables can escape supervision.
                    elif nr in (56, 57, 58, 435) or (nr in (59, 322) and exec_seen):
                        violations.append({'syscall': nr, 'reason': 'unsupported process operation'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr in (59, 322):
                        if nr != 59: raise RuntimeError('unexpected initial exec mechanism')
                        exec_seen = True
                        pending['exec_path'] = readstr(child, args[0])
                        pending['exec_argv'] = argv_at(child, args[1])
                        if pending['exec_path'] != program or pending['exec_argv'] != [program] + arguments:
                            raise RuntimeError('initial exec arguments differ')
                    # Never execute any ioctl, including startup attempts.
                    elif nr == 16:
                        fd, req, addr = args[:3]
                        item = owned.get(fd)
                        result = -errno.ENOTTY
                        if active and item:
                            now = statfd(child, fd)
                            if (now['dev'], now['ino']) != item['identity']:
                                raise RuntimeError('registered fd changed identity')
                            if item['name'].endswith('-a') and mode == 'control' and req == GETSS:
                                item['calls'] += 1
                                result = (-errno.EIO, -errno.EPERM, 0)[min(item['calls'] - 1, 2)]
                            elif item['name'].endswith('-a') and mode in ('ioctl-eio', 'ioctl-eperm') and req == GETSIZE:
                                result = -errno.EIO if mode == 'ioctl-eio' else -errno.EPERM
                            elif item['name'].endswith(('-a', '-b')) and req in (GETSIZE, GETSS):
                                result = 0
                            if result == 0:
                                writemem(child, addr, struct.pack('<Q' if req == GETSIZE else '<I', 4096 if req == GETSIZE else 512))
                        pending.update({'injected': result, 'owned': item.copy() if item else None})
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr in (2, 257):
                        path = readstr(child, args[0] if nr == 2 else args[1])
                        pending['path'] = path
                        flags = args[1] if nr == 2 else args[2]
                        if not active:
                            trusted = trusted_startup_open(path, flags)
                            if trusted is None:
                                pending['injected'] = -errno.ENOENT
                                pending['open_decision'] = 'startup-denied'
                                value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                            else:
                                pending['open_decision'] = 'protected-runtime-regular'
                                pending['startup_expected'] = trusted
                        elif path in paths and flags & ~(os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_LARGEFILE', 0)):
                            violations.append({'syscall': nr, 'reason': 'unsafe registered open flags'})
                            pending['injected'] = -errno.EPERM
                            pending['open_decision'] = 'flags-denied'
                            value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                        elif path not in paths:
                            pending['injected'] = -errno.ENOENT
                            pending['open_decision'] = 'unregistered-denied'
                            value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                        else:
                            try:
                                entry = Path(path).lstat()
                                current = (entry.st_dev, entry.st_ino)
                                valid = stat.S_ISREG(entry.st_mode) and current == paths[path]
                                pending['pathname_check'] = {'dev': entry.st_dev, 'ino': entry.st_ino,
                                                             'mode': entry.st_mode}
                            except FileNotFoundError:
                                valid = False
                                pending['pathname_check'] = {'missing': True}
                            if not valid:
                                pending['injected'] = -errno.EPERM
                                pending['open_decision'] = 'replaced-denied'
                                value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                            else:
                                pinned_fd = pins[path]['child_fd']
                                pinned = statfd(child, pinned_fd)
                                if not stat.S_ISREG(pinned['mode']) or (pinned['dev'], pinned['ino']) != paths[path]:
                                    raise RuntimeError('tracee pin changed')
                                value = regs(child)
                                value.orig_rax = 72  # fcntl(pin, F_DUPFD_CLOEXEC, 3)
                                value.rdi = pinned_fd; value.rsi = fcntl.F_DUPFD_CLOEXEC; value.rdx = 3
                                setregs(child, value)
                                rewritten = regs(child)
                                if (rewritten.orig_rax, rewritten.rdi, rewritten.rsi, rewritten.rdx) != (
                                        72, pinned_fd, fcntl.F_DUPFD_CLOEXEC, 3):
                                    raise RuntimeError('open rewrite did not persist')
                                pending.update(open_decision='pinned-fcntl', pin=pinned,
                                               pin_fd=pinned_fd, rewrite_regs=reg_record(rewritten))
                    elif nr in (76, 77):
                        # Resolve only direct, private regular scratch paths. Every
                        # alias or unprovable pathname is denied before the kernel;
                        # a distinct private file is outside the evidence channel.
                        evidence = evidence_inodes({'journal': journal.fd, 'stdout': outfd,
                                                   'stderr': errfd, 'sentinel': sentinel_fd})
                        guard = {'operation': 'truncate' if nr == 76 else 'ftruncate',
                                 'length': args[1], 'expected_control': False}
                        deny = True
                        if nr == 76:
                            try: path = readstr(child, args[0])
                            except (OSError, ValueError) as exc:
                                path = None
                                guard['path_error'] = {'type': type(exc).__name__, 'message': str(exc)}
                            guard['path'] = path
                            unrelated = unrelated_private_truncate(path, evidence)
                            if unrelated is not None:
                                deny = False
                                guard.update(decision='distinct-private-scratch', target=unrelated)
                            else:
                                expected = (mode == 'control' and active and not truncate_control_seen and
                                            path == str(SENTINEL) and args[1] == 0)
                                guard.update(decision='deny-evidence-or-unresolved', expected_control=expected)
                                if expected: truncate_control_seen = True
                        else:
                            # The kernel treats fd as an unsigned int, even when
                            # upper register bits are set by the tracee.
                            target_fd = args[0] & 0xffffffff
                            guard['fd'] = target_fd
                            try:
                                target = statfd(child, target_fd)
                            except FileNotFoundError:
                                target = None
                                deny = False  # a stopped single task has no such fd
                                guard['decision'] = 'absent-fd'
                            except OSError as exc:
                                target = None
                                guard.update(decision='deny-unresolved-fd',
                                             target_error={'errno': exc.errno, 'message': str(exc)})
                            else:
                                guard['target'] = target
                                matches = list(evidence.get((target['dev'], target['ino']), []))
                                for name, pipe_fd in readers.items():
                                    pipe_stat = os.fstat(pipe_fd)
                                    if (target['dev'], target['ino']) == (pipe_stat.st_dev, pipe_stat.st_ino):
                                        matches.append(name + '-pipe')
                                guard['evidence_matches'] = matches
                                deny = bool(matches)
                                guard['decision'] = 'deny-evidence-fd' if deny else 'distinct-fd'
                                stdout_stat = os.fstat(readers['stdout'])
                                expected = (mode == 'control' and active and not ftruncate_control_seen and
                                            target_fd == 1 and args[1] == 0 and deny and
                                            (target['dev'], target['ino']) == (stdout_stat.st_dev, stdout_stat.st_ino))
                                guard['expected_control'] = expected
                                if expected: ftruncate_control_seen = True
                        pending['mutation_guard'] = guard
                        if not guard['expected_control']:
                            violations.append({'syscall': nr, 'reason': 'unexpected truncate operation',
                                               'decision': guard['decision']})
                        if deny:
                            deny_guarded_syscall(pending)
                    elif nr in (41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 62, 85, 101,
                                155, 161, 165, 200, 234, 272, 288, 299, 304, 307, 308,
                                310, 311, 424, 425, 426, 427, 428, 429, 430, 433, 434,
                                436, 437, 438):
                        violations.append({'syscall': nr, 'reason': 'unsupported alternate open or namespace operation'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr in (33, 292) and args[1] in {x['child_fd'] for x in pins.values()}:
                        violations.append({'syscall': nr, 'reason': 'attempt to replace a pin'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif active and nr in (22, 32, 33, 213, 240, 253, 282, 283, 284,
                                           289, 290, 291, 292, 293, 294, 298, 300,
                                           319, 321, 323, 444, 447):
                        violations.append({'syscall': nr, 'reason': 'unsupported descriptor/process operation'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif active and nr == 72 and args[1] in (0, 1030):
                        violations.append({'syscall': nr, 'reason': 'unsupported descriptor duplication'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr == 72 and args[0] in {x['child_fd'] for x in pins.values()} and args[1] not in (fcntl.F_GETFD, fcntl.F_GETFL):
                        violations.append({'syscall': nr, 'reason': 'attempt to alter a pin'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr == 3 and args[0] in {x['child_fd'] for x in pins.values()}:
                        violations.append({'syscall': nr, 'reason': 'attempt to close a pin'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr in (82, 83, 84, 86, 87, 88, 133, 258, 259, 263, 264, 265, 266, 316):
                        violations.append({'syscall': nr, 'reason': 'pathname mutation denied'})
                        pending['injected'] = -errno.EPERM
                        value = regs(child); value.orig_rax = (1 << 64) - 1; setregs(child, value)
                    elif nr == 1 and args[0] in (1, 2) and args[2] <= 128:
                        data = readmem(child, args[1], args[2])
                        if data == b'FD_MOCK_BEGIN\n':
                            if active or before is not None: raise RuntimeError('duplicate begin')
                            before = snapshot(child); active = True
                            journal.emit('descriptor-before', {key: value for key, value in before.items() if key != 'copies'})
                        elif data == b'FD_MOCK_END\n':
                            if not active: raise RuntimeError('unexpected end')
                            after = snapshot(child); active = False
                            comparison = compare(before, after)
                            journal.emit('descriptor-after', {'snapshot': {key: value for key, value in after.items() if key != 'copies'},
                                                              'comparison': comparison})
                    if active and nr == 3 and args[0] in owned:
                        pending['closing'] = owned[args[0]].copy()
                    if (active or nr in (2, 257, 59, 322) or 'injected' in pending or
                            'closing' in pending or 'mutation_guard' in pending):
                        journal.emit('syscall-entry', pending)
                    else:
                        journal.emit('other-entry', {'syscall_id': syscall_sequence, 'nr': nr, 'args': args,
                                      'pid': child, 'wait_status': st, 'monotonic_ns': time.monotonic_ns()})
                elif info.op == 2:
                    if pending is None: raise RuntimeError('unpaired syscall')
                    actual = struct.unpack_from('<q', bytes(info.payload))[0]
                    nr, args = pending['nr'], pending['args']
                    if nr in (1, 20) and (args[0] & 0xffffffff) in (1, 2) and actual >= 0:
                        barrier_event = {'pid': child, 'wait_status': st, 'syscall_id': pending['syscall_id'],
                                         'nr': nr, 'fd': args[0] & 0xffffffff, 'actual': actual}
                    pending['exit_stop'] = {'pid': child, 'wait_status': st, 'op': info.op,
                                            'arch': info.arch, 'ip': info.ip, 'sp': info.sp,
                                            'info_size': n, 'payload_hex': bytes(info.payload).hex(),
                                            'monotonic_ns': time.monotonic_ns(),
                                            'regs': reg_record(regs(child))}
                    if 'exec_path' in pending:
                        proc_exe = Path('/proc') / str(child) / 'exe'
                        if actual != 0: raise RuntimeError('initial exec failed')
                        s = proc_exe.stat()
                        verified = protected_executable(program)
                        if (s.st_dev, s.st_ino) != (expected_exe['dev'], expected_exe['ino']) or verified != expected_exe:
                            raise RuntimeError('executed image differs from protected executable')
                        exec_event = {'pid': child, 'path': pending['exec_path'], 'argv': pending['exec_argv'],
                                      'actual': actual, 'proc_link': os.readlink(proc_exe),
                                      'proc_dev': s.st_dev, 'proc_ino': s.st_ino,
                                      'identity': verified, 'start': process_start(child),
                                      'entry_stop': pending['entry_stop'], 'exit_stop': pending['exit_stop']}
                        if exec_event['start']['starttime'] != start_identity['starttime']:
                            raise RuntimeError('tracee identity changed')
                        journal.emit('exec', exec_event)
                    if nr in (2, 257) and pending.get('open_decision') == 'protected-runtime-regular' and actual >= 0:
                        runtime_fd = statfd(child, actual)
                        expected_runtime = pending['startup_expected']
                        if (not stat.S_ISREG(runtime_fd['mode']) or
                            (runtime_fd['dev'], runtime_fd['ino']) != (expected_runtime['dev'], expected_runtime['ino'])):
                            raise RuntimeError('protected startup open identity mismatch')
                        pending['runtime_fd'] = runtime_fd
                    if pending.get('open_decision') == 'pinned-fcntl':
                        value = regs(child)
                        original = pending['entry_stop']['regs']
                        for name in ('rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'):
                            setattr(value, name, original[name])
                        setregs(child, value)
                        restored = regs(child)
                        if any(getattr(restored, name) != original[name] for name in ('rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9')):
                            raise RuntimeError('open argument register restore failed')
                        pending['restored_regs'] = reg_record(restored)
                    if active and nr in (2, 257) and pending.get('open_decision') == 'pinned-fcntl' and actual >= 0:
                        path = pending['path']; infofd = statfd(child, actual)
                        expected = paths[path]
                        if not stat.S_ISREG(infofd['mode']) or (infofd['dev'], infofd['ino']) != expected:
                            raise RuntimeError('open did not return registered regular object')
                        generations[actual] = generations.get(actual, 0) + 1
                        owned[actual] = {'name': path, 'identity': expected,
                                         'generation': generations[actual], 'calls': 0}
                        pending['opened'] = owned[actual].copy()
                    if 'closing' in pending:
                        item = pending['closing']
                        if actual == 0:
                            try: statfd(child, args[0]); raise RuntimeError('closed descriptor still present')
                            except FileNotFoundError: pass
                            del owned[args[0]]
                            if item['name'] not in closed_targets:
                                if item['name'].endswith('-a') and mode in ('control', 'close-eio', 'close-eperm'):
                                    pending['injected'] = -errno.EPERM if mode == 'close-eperm' else -errno.EIO
                                    closed_targets.add(item['name'])
                                elif item['name'].endswith('-b') and mode == 'control':
                                    pending['injected'] = -errno.EPERM
                                    closed_targets.add(item['name'])
                    if 'injected' in pending:
                        value = regs(child); value.rax = pending['injected'] & ((1 << 64) - 1); setregs(child, value)
                        checked = regs(child)
                        if checked.rax != value.rax: raise RuntimeError('return register readback mismatch')
                        pending['injected_readback'] = reg_record(checked)
                    if (active or 'closing' in pending or 'injected' in pending or
                            'mutation_guard' in pending or nr in (2, 257)):
                        event = {'event_id': pending['syscall_id'], 'nr': nr, 'args': args, 'actual': actual,
                                 'intended': pending.get('injected'),
                                 'path': pending.get('path'), 'opened': pending.get('opened'),
                                 'closing': pending.get('closing'), 'owned': pending.get('owned'),
                                 'open_decision': pending.get('open_decision'),
                                 'pathname_check': pending.get('pathname_check'),
                                 'runtime_fd': pending.get('runtime_fd'),
                                 'startup_expected': pending.get('startup_expected'),
                                 'pin': pending.get('pin'), 'pin_fd': pending.get('pin_fd'),
                                 'mutation_guard': pending.get('mutation_guard'),
                                 'guard_skip_regs': pending.get('guard_skip_regs'),
                                 'rewrite_regs': pending.get('rewrite_regs'),
                                 'restored_regs': pending.get('restored_regs'),
                                 'entry_stop': pending['entry_stop'], 'exit_stop': pending['exit_stop'],
                                 'return_readback': pending.get('injected_readback')}
                        events.append(event)
                        if len(events) > LIMIT: raise RuntimeError('event limit')
                        journal.emit('syscall-exit', event)
                        if 'injected' in pending or pending.get('open_decision') == 'pinned-fcntl':
                            awaiting_stop = event
                    else:
                        journal.emit('other-exit', {'syscall_id': pending['syscall_id'], 'nr': nr,
                                      'actual': actual, 'pid': child, 'wait_status': st,
                                      'monotonic_ns': time.monotonic_ns()})
                    pending = None
            stream_checkpoint(journal, streams, readers, offsets, eof, barrier=barrier_event)
            resume_signal = 0 if sig in (signal.SIGTRAP, signal.SIGTRAP | 0x80) else sig
            resumed = ptrace(PTRACE_SYSCALL, child, 0, resume_signal)
            if awaiting_stop is not None:
                awaiting_stop['resume'] = {'result': resumed, 'signal': resume_signal,
                                           'monotonic_ns': time.monotonic_ns()}
                journal.emit('resume', {'event_id': awaiting_stop['event_id'], 'resume': awaiting_stop['resume']})
    except BaseException as exc:
        observer_error = {'type': type(exc).__name__, 'message': str(exc)}
        terminal('observer-error', observer_error)
        if awaiting_stop is not None:
            terminal('interrupted-event', {'event_id': awaiting_stop.get('event_id'),
                     'resume': awaiting_stop.get('resume'), 'next_stop': awaiting_stop.get('next_stop')})
        if pending is not None:
            terminal('interrupted-syscall', {'syscall_id': pending.get('syscall_id'), 'nr': pending.get('nr'),
                     'entry_stop': pending.get('entry_stop')})
    finally:
        if not reaped:
            forced_cleanup = True
            cleanup['signal_requested_ns'] = time.monotonic_ns()
            terminal('cleanup-start', dict(cleanup))
            try:
                if pidfd is not None and hasattr(signal, 'pidfd_send_signal'):
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    cleanup['signal_method'] = 'pidfd'
                    cleanup['signal_result'] = 'sent'
                elif reserved_child():
                    # A WNOHANG wait proved the direct child remains unreaped.
                    os.kill(child, signal.SIGKILL)
                    cleanup['signal_method'] = 'unreaped-direct-child'
                    cleanup['signal_result'] = 'sent'
                else:
                    cleanup['signal_result'] = 'not-sent-no-owned-live-child'
            except OSError as exc:
                cleanup['signal_error'] = {'errno': exc.errno, 'message': str(exc)}
                if pidfd is not None and reserved_child():
                    try:
                        # The direct child has not been reaped; its PID cannot be reused.
                        os.kill(child, signal.SIGKILL)
                        cleanup['fallback_signal_result'] = 'sent-to-unreaped-direct-child'
                    except OSError as fallback:
                        cleanup['fallback_signal_error'] = {'errno': fallback.errno, 'message': str(fallback)}
            terminal('cleanup-signal', dict(cleanup))
            reap_deadline = time.monotonic() + REAP_SECONDS
            cleanup['reap_deadline_ns'] = int(reap_deadline * 1000000000)
            while not reaped and time.monotonic() < reap_deadline:
                try:
                    waited, final_status = os.waitpid(child, os.WNOHANG)
                except (ChildProcessError, OSError) as exc:
                    cleanup['wait_error'] = {'type': type(exc).__name__, 'message': str(exc)}
                    break
                if not waited:
                    time.sleep(.005); continue
                cleanup['last_wait_status'] = final_status
                if os.WIFEXITED(final_status) or os.WIFSIGNALED(final_status):
                    reaped = True
                    status = {'exit': os.WEXITSTATUS(final_status) if os.WIFEXITED(final_status) else None,
                              'signal': os.WTERMSIG(final_status) if os.WIFSIGNALED(final_status) else None,
                              'raw_wait_status': final_status}
                    break
                cleanup['stop_count'] = cleanup.get('stop_count', 0) + 1
                if cleanup['stop_count'] <= 8:
                    terminal('cleanup-stop', {'pid': child, 'wait_status': final_status})
                else:
                    cleanup['stop_records_truncated'] = True
            cleanup['reap_pending'] = not reaped
            cleanup['reaped'] = reaped
            cleanup['status'] = status
            terminal('cleanup-finished', dict(cleanup))
        else:
            cleanup.update(reaped=True, status=status, reap_pending=False)
            terminal('cleanup-natural', dict(cleanup))
        if pidfd is not None:
            try: os.close(pidfd)
            except OSError as exc:
                cleanup['pidfd_close_error'] = str(exc)
                if observer_error is None:
                    observer_error = {'type': 'PidfdCloseError', 'message': str(exc)}
        try:
            stream_checkpoint(journal, streams, readers, offsets, eof, critical=True)
        except Exception as exc:
            terminal('stream-checkpoint-error', {'type': type(exc).__name__, 'message': str(exc),
                                                 'offsets': dict(offsets)})
            if observer_error is None:
                observer_error = {'type': 'StreamCheckpointError', 'message': str(exc)}
        if not all(eof.values()):
            terminal('stream-eof-pending', {'eof': dict(eof), 'offsets': dict(offsets)})
            if observer_error is None:
                observer_error = {'type': 'StreamEofPending', 'message': 'pipe writer quiescence unproved'}
        for name, fd in readers.items():
            try: os.close(fd)
            except OSError as exc:
                terminal('pipe-close-error', {'name': name, 'errno': exc.errno, 'message': str(exc)})
                if observer_error is None:
                    observer_error = {'type': 'PipeCloseError', 'message': str(exc)}
    try:
        sentinel_after = sentinel_snapshot(sentinel_fd)
        terminal('truncate-sentinel-after', sentinel_after)
        if sentinel_after != sentinel_before:
            raise RuntimeError('truncate sentinel changed during trace')
    except Exception as exc:
        terminal('truncate-sentinel-error', {'type': type(exc).__name__, 'message': str(exc)})
        if observer_error is None:
            observer_error = {'type': 'SentinelError', 'message': str(exc)}
    for snap in (before, after):
        if snap:
            for fd in snap['copies'].values():
                try: os.close(fd)
                except OSError as exc:
                    terminal('snapshot-close-error', {'errno': exc.errno, 'message': str(exc)})
                    if observer_error is None:
                        observer_error = {'type': 'SnapshotCloseError', 'message': str(exc)}
    captures = {}
    for name, fd in streams.items():
        try:
            captures[name] = capture(fd)
            captures[name]['pipe_eof'] = eof[name]
            captures[name]['complete'] = captures[name]['complete'] and eof[name]
            if captures[name].get('error'):
                terminal('capture-partial', {'name': name, 'error': captures[name]['error'],
                                             'checkpointed_bytes': offsets[name],
                                             'retained_bytes': captures[name]['bytes']})
                if observer_error is None:
                    observer_error = {'type': 'CaptureError', 'message': name + ': partial capture'}
        except Exception as exc:
            captures[name] = {'error': {'type': type(exc).__name__, 'message': str(exc)},
                              'checkpointed_bytes': offsets[name]}
            terminal('capture-error', {'name': name, **captures[name]})
            if observer_error is None:
                observer_error = {'type': 'CaptureError', 'message': name + ': ' + str(exc)}
        finally:
            try: os.close(fd)
            except OSError as exc:
                terminal('stream-close-error', {'name': name, 'errno': exc.errno, 'message': str(exc)})
                if observer_error is None:
                    observer_error = {'type': 'StreamCloseError', 'message': str(exc)}
    if mode == 'control':
        try:
            if not captures['stdout'].get('complete') or not captures['stderr'].get('complete'):
                raise RuntimeError('incomplete native truncate control output')
            raw = base64.b64decode(captures['stdout']['base64'], validate=True)
            stderr_raw = base64.b64decode(captures['stderr']['base64'], validate=True)
            lines = raw.split(b'\n', 3)
            prefix = b'FD_MOCK_NATIVE_TRUNCATE='
            stream_prefix = b'FD_MOCK_NATIVE_STREAM='
            if (len(lines) < 4 or lines[0] != b'FD_MOCK_CAPTURE_SENTINEL' or
                    not lines[1].startswith(prefix) or not lines[2].startswith(stream_prefix)):
                raise RuntimeError('missing intact native capture sentinel or truncate checkpoint')
            result = json.loads(lines[1][len(prefix):])
            stream_result = json.loads(lines[2][len(stream_prefix):])
            if not isinstance(result, dict) or not isinstance(stream_result, dict):
                raise RuntimeError('invalid native truncate checkpoint')
            if (not truncate_control_seen or not ftruncate_control_seen or
                    result.get('truncate_errno') != errno.EPERM or result.get('ftruncate_errno') != errno.EPERM):
                raise RuntimeError('truncate sensitivity control failed')
            terminal('truncate-control-summary', {'truncate_errno': result['truncate_errno'],
                     'ftruncate_errno': result['ftruncate_errno'], 'capture_prefix_intact': True})
            terminal('stream-control-summary', {'errno': stream_result, 'stdout_prefix_intact': True,
                     'stderr_prefix_intact': stderr_raw.startswith(b'FD_MOCK_BEGIN\n'),
                     'stdout_sensitivity': all(stream_result.get(key) == errno.ESPIPE
                                               for key in ('stdout_pwrite', 'stdout_seek')),
                     'stderr_sensitivity': all(stream_result.get(key) == errno.ESPIPE
                                               for key in ('stderr_pwrite', 'stderr_seek'))})
        except (KeyError, ValueError, TypeError, RuntimeError) as exc:
            terminal('truncate-control-error', {'type': type(exc).__name__, 'message': str(exc)})
            if observer_error is None:
                observer_error = {'type': 'TruncateControlError', 'message': str(exc)}
    capture_record = None
    try:
        capture_record = save_capture(label, {'schema': 1, 'mode': mode, 'pid': child,
                                      'status': status, 'forced_cleanup': forced_cleanup,
                                      'cleanup': cleanup, 'streams': captures})
        terminal('capture-file', capture_record)
    except Exception as exc:
        terminal('capture-file-error', {'type': type(exc).__name__, 'message': str(exc)})
        if observer_error is None:
            observer_error = {'type': 'CaptureFileError', 'message': str(exc)}
    terminal('run-end', {'pid': child, 'status': status, 'observer_error': observer_error,
                         'forced_cleanup': forced_cleanup, 'cleanup': cleanup,
                         'event_count': len(events), 'stream_offsets': offsets,
                         'stream_eof': eof,
                         'markers_complete': before is not None and after is not None and not active,
                         'capture_file': capture_record,
                         'captures': {name: {k: v for k, v in item.items() if k != 'base64'}
                                      for name, item in captures.items()}, 'log_errors': log_errors})
    if log_errors and observer_error is None:
        observer_error = {'type': 'JournalError', 'message': 'terminal checkpoint failed'}
    journal_record = {'name': journal.name, 'bytes': journal.size, 'last_line_sha256': journal.previous,
                      'sequence': journal.sequence, 'limit_reported': journal.limit_reported,
                      'log_errors': log_errors}
    journal.close()
    return {'pid': child, 'start_identity': start_identity, 'exec_event': exec_event,
            'requested_program': program, 'requested_argv': [program] + arguments,
            'status': status, 'observer_error': observer_error, 'forced_cleanup': forced_cleanup,
            'cleanup': cleanup, 'journal': journal_record, 'capture_file': capture_record, 'event_count': len(events),
            'violations': violations, 'descriptors': comparison,
            'stdout': {k: v for k, v in captures['stdout'].items() if k != 'base64'},
            'stderr': {k: v for k, v in captures['stderr'].items() if k != 'base64'},
            'markers_complete': before is not None and after is not None and not active,
            'owned_at_end': owned}

def main():
    # This import and every fixture side effect occur after launching in the guest only.
    sys.path.insert(0, '/opt/bashos-parity/harness/helpers')
    import ns_guest_identity_r1
    ns_guest_identity_r1.verify()
    if os.getresuid() != (2000, 2000, 2000) or os.getresgid() != (2000, 2000, 2000):
        raise RuntimeError('requires unmapped unprivileged identity')
    if os.uname().machine != 'x86_64' or len(sys.argv) != 2:
        raise RuntimeError('requires x86_64 and candidate shell')
    shell = sys.argv[1]
    if shell != '/opt/bashos-parity/candidate' or os.path.realpath(shell) != shell:
        raise RuntimeError('unexpected candidate path')
    executables = {'candidate': protected_executable(shell),
                   'native': protected_executable('/usr/bin/python3')}
    for directory in (HOME, CASE):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 2000 or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError('fixture scratch is not private')
    paths, pins, registration = {}, {}, {}
    for index, suffix in enumerate('abcde'):
        path = CASE / ('fd-mock-additive-' + suffix)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1: raise RuntimeError('unsafe fixture')
            paths[str(path)] = (s.st_dev, s.st_ino)
            # Reopen the freshly created, still-held regular inode read-only;
            # never resolve an operand pathname to obtain a mock fd.
            readonly = os.open('/proc/self/fd/%d' % fd, os.O_RDONLY | os.O_CLOEXEC)
            try:
                check = os.fstat(readonly)
                if (check.st_dev, check.st_ino) != paths[str(path)] or not stat.S_ISREG(check.st_mode):
                    raise RuntimeError('pin identity mismatch')
                pins[str(path)] = {'fd': fcntl.fcntl(readonly, fcntl.F_DUPFD_CLOEXEC, 100),
                                   'child_fd': PIN_FIRST + index}
                registration[str(path)] = {
                    'creation_flags': os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                    'created': {'dev': s.st_dev, 'ino': s.st_ino, 'mode': s.st_mode,
                                'uid': s.st_uid, 'gid': s.st_gid, 'nlink': s.st_nlink},
                    'pinned': {'dev': check.st_dev, 'ino': check.st_ino, 'mode': check.st_mode,
                               'uid': check.st_uid, 'gid': check.st_gid, 'nlink': check.st_nlink},
                    'pin_flags': fcntl.fcntl(pins[str(path)]['fd'], fcntl.F_GETFL),
                    'child_fd': PIN_FIRST + index}
            finally:
                os.close(readonly)
        finally: os.close(fd)
    # Independently exercise path substitution without ever opening the link
    # target. Both originally registered inodes stay pinned.
    link_path = CASE / 'fd-mock-additive-d'
    replacement_path = CASE / 'fd-mock-additive-e'
    os.unlink(link_path); os.symlink('/dev/null', link_path)
    os.unlink(replacement_path)
    replacement_fd = os.open(replacement_path, os.O_CREAT | os.O_EXCL | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.close(replacement_fd)
    replacements = {}
    for path in (link_path, replacement_path):
        s = path.lstat()
        replacements[str(path)] = {'dev': s.st_dev, 'ino': s.st_ino, 'mode': s.st_mode,
                                   'link_target': os.readlink(path) if stat.S_ISLNK(s.st_mode) else None}
    sentinel_flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    sentinel_fd = os.open(SENTINEL, sentinel_flags, 0o600)
    try:
        if os.write(sentinel_fd, SENTINEL_BYTES) != len(SENTINEL_BYTES):
            raise RuntimeError('short truncate sentinel write')
        os.fsync(sentinel_fd)
        sentinel_initial = sentinel_snapshot(sentinel_fd)
        if not sentinel_initial['valid']: raise RuntimeError('invalid initial truncate sentinel')
    except BaseException:
        os.close(sentinel_fd)
        raise
    record = {'schema': 3, 'registered': paths, 'registration': registration, 'replacements': replacements,
              'pin_descriptors': {name: item['child_fd'] for name, item in pins.items()},
              'executables': executables, 'fd_controls': fd_controls(pins[next(iter(paths))]['fd']),
              'truncate_sentinel': {'path': str(SENTINEL), 'creation_flags': sentinel_flags,
                                    'initial': sentinel_initial},
              'runs': {}, 'complete': False}
    def save():
        raw = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
        if len(raw) > 512 * 1024: raise RuntimeError('index size limit')
        target = HOME / 'fd-mock-additive-record.json'
        temp = HOME / 'fd-mock-additive-record.tmp'
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            os.replace(temp, target)
        except BaseException:
            try: os.unlink(temp)
            except FileNotFoundError: pass
            raise
    index_failed = False
    def checkpoint(phase, mode):
        nonlocal index_failed
        try:
            save()
        except BaseException as exc:
            index_failed = True
            note = {'phase': phase, 'mode': mode, 'error_type': type(exc).__name__,
                    'message': str(exc)[:512], 'index_existed': (HOME / 'fd-mock-additive-record.json').exists(),
                    'journals': ['fd-mock-additive-' + name + '.jsonl' for name in
                                 ('control', 'success', 'ioctl-eio', 'ioctl-eperm', 'close-eio', 'close-eperm')]}
            try:
                fd = os.open(HOME / 'fd-mock-additive-index-error.json',
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write((json.dumps(note, sort_keys=True) + '\n').encode())
                    stream.flush(); os.fsync(stream.fileno())
            except OSError as note_error:
                print('index error note unavailable: ' + str(note_error), file=sys.stderr)
            raise
    mode = None
    try:
        checkpoint('initial', mode)
        for mode in MODES:
            program = '/usr/bin/python3' if mode == 'control' else shell
            args = ['-I', '-B', '-c', NATIVE] if mode == 'control' else ['--noprofile', '--norc', '-c', SHELL]
            expected_exe = executables['native' if mode == 'control' else 'candidate']
            record['runs'][mode] = trace(program, args, paths, pins, expected_exe, mode, mode, sentinel_fd)
            checkpoint('run', mode)
            if record['runs'][mode]['observer_error']:
                raise RuntimeError('trace incomplete: ' + mode)
        record['complete'] = True
        checkpoint('final', mode)
    except BaseException as exc:
        record['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        if not index_failed:
            try: checkpoint('error', mode)
            except BaseException: pass
        raise
    finally:
        os.close(sentinel_fd)
        for item in pins.values(): os.close(item['fd'])
    print('fd-mock-additive-observed')

if __name__ == '__main__':
    main()
