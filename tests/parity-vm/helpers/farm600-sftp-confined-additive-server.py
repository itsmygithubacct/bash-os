#!/usr/bin/python3
"""Guest-only, deliberately small SFTP v3 and BASHSSH1 transfer peer.

This file is source-only until run in an attested disposable parity guest. It
never executes received commands. All file access is relative to a pinned root
fd and rejects symlinks and multiply-linked files.
"""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import signal
import socket
import stat
import struct
import sys
import time

GUARD = '/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py'
GUARD_SHA = 'a74d97058d313388948010d1033f50dde7151c2d204d221ed3aeb4da3e9e1762'
CASE = '/tmp/parity-case'
HOME = '/tmp/parity-home'
CAP = 65536
FRAME_SECONDS = 4.0
SERVER_SECONDS = 24.0
ROOTS = {'control', 'remote'}


def guard():
    p = Path(GUARD)
    if hashlib.sha256(p.read_bytes()).hexdigest() != GUARD_SHA:
        raise ValueError('guest guard digest')
    runpy.run_path(str(p))['verify']()
    if os.getuid() != 2000 or os.geteuid() != 2000:
        raise ValueError('fixture requires uid 2000')
    for path in (CASE, HOME):
        s = os.lstat(path)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 2000 or s.st_mode & 0o022:
            raise ValueError('unsafe scratch directory')


def b64(data):
    return base64.b64encode(data).decode('ascii')


def current_umask():
    previous = os.umask(0o077); os.umask(previous)
    return format(previous, '04o')


def arm_parent_death():
    parent = int(os.environ['SFTP_CONFINED_EXPECTED_PID'])
    if parent <= 1 or os.getppid() != parent: raise ValueError('native peer parent mismatch')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'native peer parent-death setup')
    if os.getppid() != parent: raise ValueError('native peer parent exited during setup')
    value = ctypes.c_int(0)
    if libc.prctl(2, ctypes.byref(value), 0, 0, 0) != 0 or value.value != signal.SIGKILL:
        raise ValueError('native peer parent-death verification')
    return {'parent_pid': parent, 'signal': value.value, 'verified_ns': time.monotonic_ns()}


def log(event, **fields):
    name = os.environ['SFTP_CONFINED_LOG']
    if name not in ('control', 'candidate', 'reference', 'attribution',
                    'deadline-header', 'deadline-body', 'deadline-eof', 'deadline-limit', 'deadline-repeat'):
        raise ValueError('invalid log name')
    fd = os.open(HOME + '/sftp-confined-' + name + '.jsonl',
                 os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 2000 or st.st_nlink != 1 or st.st_size > 1048576:
            raise ValueError('unsafe or full log')
        row = json.dumps({'event': event, 'pid': os.getpid(), 'time_ns': time.monotonic_ns(), **fields}, sort_keys=True).encode() + b'\n'
        if len(row) > 200000: raise ValueError('record too large')
        written = 0
        while written < len(row):
            n = os.write(fd, row[written:])
            if n <= 0: raise OSError('short log write')
            written += n
    finally:
        os.close(fd)


class Tree:
    def __init__(self):
        name = os.environ['SFTP_CONFINED_ROOT']
        if name not in ROOTS: raise ValueError('invalid root')
        path = CASE + '/sftp-confined-' + name
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        st = os.fstat(self.fd)
        if st.st_uid != 2000 or stat.S_IMODE(st.st_mode) != 0o700:
            os.close(self.fd); raise ValueError('unsafe root')

    def parts(self, path):
        if not isinstance(path, str) or not path or path.startswith('/') or '\x00' in path:
            raise PermissionError('absolute or empty path')
        parts = path.split('/')
        if len(parts) > 16 or any(p == '..' or len(p.encode('utf-8')) > 255 for p in parts):
            raise PermissionError('path traversal or length')
        parts = [p for p in parts if p not in ('', '.')]
        if not parts: raise PermissionError('root is not a file')
        return parts

    def parent(self, path):
        parts = self.parts(path)
        fd = os.dup(self.fd)
        try:
            for name in parts[:-1]:
                nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = nxt
            return fd, parts[-1]
        except BaseException:
            os.close(fd); raise

    def open(self, path, flags):
        if flags & ~59 or not flags & 3 or flags & 4:
            raise PermissionError('unsupported open flags')
        writable = bool(flags & 2)
        if (flags & (8 | 16 | 32)) and not writable: raise PermissionError('invalid open flags')
        parent, name = self.parent(path)
        try:
            mode = os.O_RDWR if flags & 3 == 3 else os.O_WRONLY if writable else os.O_RDONLY
            mode |= os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if flags & 8: mode |= os.O_CREAT
            if flags & 32: mode |= os.O_EXCL
            fd = os.open(name, mode, 0o600, dir_fd=parent)
            try:
                s = os.fstat(fd)
                if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != 2000:
                    raise PermissionError('unsafe file')
                if flags & 16: os.ftruncate(fd, 0)
                return fd
            except BaseException:
                os.close(fd); raise
        finally:
            os.close(parent)

    def stat(self, path):
        if path in ('.', './'): return os.fstat(self.fd)
        parent, name = self.parent(path)
        try:
            s = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != 2000:
                raise PermissionError('unsafe file')
            return s
        finally:
            os.close(parent)


def u32(n): return struct.pack('>I', n)
def string(x): return u32(len(x)) + x
def attrs(st):
    return struct.pack('>IQIIIII', 15, st.st_size, st.st_uid, st.st_gid, st.st_mode,
                       int(st.st_atime), int(st.st_mtime))


class Reader:
    def __init__(self, data): self.data, self.pos = data, 0
    def take(self, n):
        if n < 0 or self.pos + n > len(self.data): raise ValueError('short packet')
        b = self.data[self.pos:self.pos+n]; self.pos += n; return b
    def number(self): return struct.unpack('>I', self.take(4))[0]
    def number64(self): return struct.unpack('>Q', self.take(8))[0]
    def string(self):
        n = self.number()
        if n > CAP: raise ValueError('string too long')
        return self.take(n)
    def path(self): return self.string().decode('utf-8', 'strict')
    def end(self):
        if self.pos != len(self.data): raise ValueError('trailing packet bytes')


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.read(count - len(data))
        if not part: break
        data.extend(part)
    return bytes(data)


def sftp(tree):
    handles = {}; serial = 0; initialized = False; count = 0
    try:
        while count < 128:
            header = exact(sys.stdin.buffer, 4)
            if not header: break
            if len(header) != 4: raise ValueError('short packet header')
            size = struct.unpack('>I', header)[0]
            if not 1 <= size <= CAP: raise ValueError('packet size')
            body = exact(sys.stdin.buffer, size)
            if len(body) != size: raise ValueError('short packet')
            count += 1; r = Reader(body); typ = r.take(1)[0]
            if not initialized:
                if typ != 1 or r.number() < 3: raise ValueError('bad init')
                r.end(); response = b'\x02' + u32(3); initialized = True
            else:
                ident = r.number()
                try:
                    if typ == 16:
                        path = r.path(); r.end()
                        if path not in ('.', './'): tree.parts(path)
                        st = tree.stat(path)
                        raw = ('.' if path in ('.', './') else path).encode()
                        response = b'\x68' + u32(ident) + u32(1) + string(raw) + string(raw) + attrs(st)
                    elif typ in (7, 17):
                        path = r.path(); r.end(); response = b'\x69' + u32(ident) + attrs(tree.stat(path))
                    elif typ == 3:
                        path = r.path(); flags = r.number(); aflags = r.number()
                        # Client-supplied metadata is parsed but never applied.
                        if aflags & ~15: raise PermissionError('open attributes unsupported')
                        if aflags & 1: r.number64()
                        if aflags & 2: r.number(); r.number()
                        if aflags & 4: r.number()
                        if aflags & 8: r.number(); r.number()
                        r.end()
                        if len(handles) >= 16: raise OSError('handle limit')
                        fd = tree.open(path, flags); serial += 1
                        key = str(serial).encode(); handles[key] = fd
                        response = b'\x66' + u32(ident) + string(key)
                    elif typ in (4, 5, 6, 8):
                        key = r.string()
                        if key not in handles: raise ValueError('invalid handle')
                        fd = handles[key]
                        if typ == 4:
                            r.end(); os.close(handles.pop(key)); response = status(ident, 0)
                        elif typ == 8:
                            r.end(); response = b'\x69' + u32(ident) + attrs(os.fstat(fd))
                        elif typ == 5:
                            offset, n = r.number64(), r.number(); r.end()
                            if n > 1048576 or offset > 1048576: raise ValueError('read limit')
                            data = os.pread(fd, min(n, CAP - 16), offset)
                            response = b'\x67' + u32(ident) + string(data) if data else status(ident, 1)
                        else:
                            offset, data = r.number64(), r.string(); r.end()
                            if offset + len(data) > 1048576: raise ValueError('write limit')
                            done = 0
                            while done < len(data):
                                n = os.pwrite(fd, data[done:], offset + done)
                                if n <= 0: raise OSError('short write')
                                done += n
                            response = status(ident, 0)
                    else:
                        response = status(ident, 8)
                except (OSError, ValueError, UnicodeError) as exc:
                    code = 2 if isinstance(exc, FileNotFoundError) else 3 if isinstance(exc, PermissionError) else 4
                    response = status(ident, code)
                    log('denied-or-error', operation=typ, reason=repr(exc))
            raw = u32(len(response)) + response
            log('sftp-packet', request=b64(header + body), response=b64(raw))
            sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()
        if count == 128: raise ValueError('packet count limit')
        log('sftp-finished', packets=count, open_handles=len(handles))
    finally:
        for fd in handles.values(): os.close(fd)


def status(ident, code): return b'\x65' + u32(ident) + u32(code) + string(b'') + string(b'')


def proc_identity(pid):
    fd = os.open('/proc/%d/stat' % pid, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: raw = os.read(fd, 4097)
    finally: os.close(fd)
    if len(raw) > 4096: raise ValueError('process stat limit')
    end = raw.rfind(b')'); parts = raw[end + 2:].split()
    if end < 0 or len(parts) < 20 or int(raw[:raw.find(b' ')]) != pid: raise ValueError('process stat')
    exe = '/proc/%d/exe' % pid
    target = os.readlink(exe); executable = os.stat(exe)
    if len(os.fsencode(target)) > 4096: raise ValueError('process executable link limit')
    return {'raw_base64': b64(raw), 'pid': pid, 'state': parts[0].decode('ascii'),
            'ppid': int(parts[1]), 'starttime': int(parts[19]),
            'exe_base64': b64(os.fsencode(target)), 'exe_dev': executable.st_dev, 'exe_ino': executable.st_ino,
            'observed_ns': time.monotonic_ns()}


def socket_witness(endpoint, seed, deadline):
    """Bounded proc snapshot while the client waits for its response."""
    row = {'status': 'incomplete', 'matched': False, 'started_ns': time.monotonic_ns(),
           'endpoint': endpoint, 'seed': seed, 'fd_links': []}
    old = signal.getsignal(signal.SIGALRM)
    old_timer = signal.getitimer(signal.ITIMER_REAL); timer_started = time.monotonic()
    installed = False; handler_installed = False
    def alarm(_sig, _frame): raise TimeoutError('attribution budget')
    try:
        if old_timer[1] != 0.0: raise ValueError('unexpected repeating timer')
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('frame deadline before attribution')
        signal.signal(signal.SIGALRM, alarm); handler_installed = True
        witness_budget = min(1.5, remaining, old_timer[0] if old_timer[0] > 0 else remaining)
        signal.setitimer(signal.ITIMER_REAL, witness_budget); installed = True
        pid = seed['pid']
        before = proc_identity(pid); row['identity_before'] = before
        def encoded(address):
            return ('%08X:%04X' % (struct.unpack('<I', socket.inet_aton(address[0]))[0], address[1])).encode()
        source = encoded(endpoint['remote']); destination = encoded(endpoint['local'])
        def tcp_sample(label):
            row[label + '_started_ns'] = time.monotonic_ns()
            fd = os.open('/proc/net/tcp', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            raw = bytearray()
            try:
                while len(raw) <= 16384:
                    part = os.read(fd, 16385 - len(raw))
                    if not part: break
                    raw.extend(part)
            finally: os.close(fd)
            row[label + '_base64'] = b64(bytes(raw[:16384])); row[label + '_truncated'] = len(raw) > 16384
            if len(raw) > 16384: raise ValueError('tcp table limit')
            matches = []
            for line in bytes(raw).splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10: raise ValueError('short tcp row')
                if fields[1] == source and fields[2] == destination and fields[3] in (b'01', b'04', b'05'):
                    matches.append({'line_base64': b64(line), 'inode': int(fields[9])})
            row[label + '_matches'] = matches
            if len(matches) != 1: raise ValueError('client socket tuple not unique')
            row[label + '_finished_ns'] = time.monotonic_ns()
            return matches[0]['inode']
        inode = tcp_sample('tcp_before')
        path = '/proc/%d/fd' % pid
        def fd_sample(label):
            row[label + '_started_ns'] = time.monotonic_ns()
            names = []
            with os.scandir(path) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 256: raise ValueError('fd count limit')
            links = []; total = 0
            for name in sorted(names, key=int):
                raw_target = os.fsencode(os.readlink(path + '/' + name)); total += len(raw_target)
                if len(raw_target) > 4096 or total > 32768: raise ValueError('fd link limit')
                links.append({'fd': int(name), 'target_base64': b64(raw_target)})
            row[label + '_finished_ns'] = time.monotonic_ns()
            return links
        row['fd_links'] = fd_sample('fd_before'); row['fd_links_after'] = fd_sample('fd_after')
        if row['fd_links'] != row['fd_links_after']: raise ValueError('fd table changed')
        if tcp_sample('tcp_after') != inode: raise ValueError('client socket inode changed')
        after = proc_identity(pid); row['identity_after'] = after
        if (pid != os.getppid() or before['starttime'] != seed['identity']['starttime'] or
                before['starttime'] != after['starttime'] or
                (before['exe_dev'], before['exe_ino']) != (after['exe_dev'], after['exe_ino']) or
                (before['exe_dev'], before['exe_ino']) != (seed['identity']['exe_dev'], seed['identity']['exe_ino']) or
                before['state'] in ('Z', 'X') or after['state'] in ('Z', 'X')):
            raise ValueError('client identity changed')
        if os.environ['SFTP_CONFINED_ROOT'] == 'remote':
            expected_exe = seed['candidate_executable']
            if (before['exe_dev'], before['exe_ino']) != (expected_exe['dev'], expected_exe['ino']):
                raise ValueError('client executable differs')
        target = ('socket:[%d]' % inode).encode()
        row['matched'] = any(base64.b64decode(x['target_base64']) == target for x in row['fd_links'])
        row['status'] = 'observed'
    except (OSError, ValueError, KeyError, TypeError, TimeoutError) as exc:
        row['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if installed: signal.setitimer(signal.ITIMER_REAL, 0)
        if handler_installed: signal.signal(signal.SIGALRM, old)
        if installed and old_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, old_timer[0] - (time.monotonic() - timer_started)))
        row['finished_ns'] = time.monotonic_ns()
    return row


def native_request(tree, conn, endpoint, seed, server_deadline):
    raw = bytearray(); header = bytearray(); trailing = bytearray(); sent = bytearray()
    deadline = min(server_deadline, time.monotonic() + FRAME_SECONDS); phase = 'header'
    def budget():
        left = deadline - time.monotonic()
        if left <= 0: raise TimeoutError('absolute frame or server deadline')
        conn.settimeout(left)
    try:
        while not header.endswith(b'\n\n'):
            budget()
            c = conn.recv(1)
            if not c: raise ValueError('short header')
            header.extend(c); raw.extend(c)
            if len(header) > 512: raise ValueError('header limit')
        lines = bytes(header[:-2]).split(b'\n')
        if len(lines) != 3 or lines[0] != b'BASHSSH1' or not lines[1].startswith(b'cmd-len ') or not lines[2].startswith(b'stdin-len '):
            raise ValueError('header format')
        a, b = lines[1][8:], lines[2][10:]
        if not a.isdigit() or not b.isdigit(): raise ValueError('header lengths')
        n, m = int(a), int(b)
        if n > 512 or m > CAP: raise ValueError('frame limit')
        body = bytearray(); phase = 'body'
        while len(body) < n + m:
            budget()
            part = conn.recv(n + m - len(body))
            if not part: raise ValueError('short body')
            body.extend(part); raw.extend(part)
        command = bytes(body[:n]); data = bytes(body[n:])
        phase = 'attribution'; witness = socket_witness(endpoint, seed, deadline)
        budget()
        log('native-attribution', endpoint=endpoint, witness=witness)
        tokens = shlex.split(command.decode('utf-8', 'strict'))
        rc, out, err = 0, b'', b''
        try:
            if os.environ['SFTP_CONFINED_ROOT'] == 'remote' and not (witness['status'] == 'observed' and witness['matched']):
                raise PermissionError('client ownership not established')
            if tokens == ['pwd'] and not data: out = b'/fixture\n'
            elif len(tokens) == 6 and tokens[:4] == ['cd', '/fixture', '&&', 'cat'] and tokens[4] == '>':
                fd = tree.open(tokens[5], 2 | 8 | 16)
                try:
                    written = 0
                    while written < len(data):
                        size = os.write(fd, data[written:])
                        if size <= 0: raise OSError('short write')
                        written += size
                finally: os.close(fd)
                out = b''
            elif len(tokens) == 6 and tokens[:5] == ['cd', '/fixture', '&&', 'cat', '--'] and not data:
                fd = tree.open(tokens[5], 1)
                try:
                    out = os.read(fd, CAP + 1)
                    if len(out) > CAP: raise ValueError('file limit')
                finally: os.close(fd)
            else: raise PermissionError('unsupported command')
        except (OSError, ValueError) as exc:
            rc, out, err = 1, b'', b'confined operation denied\n'
            log('denied-or-error', operation='native', reason=repr(exc))
        reply = b'BASHSSH1-RESP\nrc %d\nstdout-len %d\nstderr-len %d\n\n' % (rc, len(out), len(err)) + out + err
        phase = 'response'
        while len(sent) < len(reply):
            budget(); written = conn.send(reply[len(sent):])
            if written <= 0: raise OSError('short response write')
            sent.extend(reply[len(sent):len(sent) + written])
        phase = 'trailing'
        while True:
            budget()
            part = conn.recv(min(4096, CAP + 1 - len(trailing)))
            if not part: break
            trailing.extend(part)
            if len(trailing) > CAP: raise ValueError('trailing limit')
        log('native-request', endpoint=endpoint, raw=b64(bytes(raw)), command=b64(command), stdin=b64(data),
            response=b64(reply), trailing=b64(bytes(trailing)), eof=True, rc=rc,
            frame_deadline_ns=int(deadline * 1000000000), completed_ns=time.monotonic_ns())
    except (OSError, ValueError, UnicodeError) as exc:
        log('native-error', endpoint=endpoint, raw=b64(bytes(raw)), trailing=b64(bytes(trailing)),
            response_sent=b64(bytes(sent)), phase=phase, frame_deadline_ns=int(deadline * 1000000000),
            observed_ns=time.monotonic_ns(), reason=repr(exc), eof=False)
        raise


def native(tree, limit):
    budget_seconds = SERVER_SECONDS
    if 'SFTP_CONFINED_TEST_BUDGET' in os.environ:
        if os.environ['SFTP_CONFINED_ROOT'] != 'control' or os.environ['SFTP_CONFINED_TEST_BUDGET'] != '4':
            raise ValueError('test lifetime override not permitted')
        budget_seconds = 4.0
    server_deadline = time.monotonic() + budget_seconds
    old = signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0): raise ValueError('existing server timer')
    def alarm(_sig, _frame): raise TimeoutError('server lifetime hard limit')
    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, budget_seconds + .25)
    try:
        native_serve(tree, limit, server_deadline, budget_seconds)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def native_serve(tree, limit, server_deadline, budget_seconds):
    seed = {'pid': None, 'parent_pid': os.getppid()}
    try:
        pid = int(os.environ['SFTP_CONFINED_EXPECTED_PID'])
        if pid != os.getppid() or pid <= 1: raise ValueError('expected client is not peer parent')
        seed['pid'] = pid; seed['identity'] = proc_identity(pid)
        if os.environ['SFTP_CONFINED_ROOT'] == 'remote':
            info = os.stat('/opt/bashos-parity/candidate')
            seed['candidate_executable'] = {'dev': info.st_dev, 'ino': info.st_ino,
                                            'mode': info.st_mode, 'size': info.st_size}
    except (OSError, ValueError, KeyError) as exc:
        seed['error'] = type(exc).__name__ + ': ' + str(exc)
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0)); server.listen(4)
        log('native-ready', address='127.0.0.1', port=server.getsockname()[1], client_seed=seed,
            server_deadline_ns=int(server_deadline * 1000000000), server_budget_seconds=budget_seconds)
        print(server.getsockname()[1], flush=True)
        count = 0
        while count < limit:
            remaining = server_deadline - time.monotonic()
            if remaining <= 0: break
            server.settimeout(min(8, remaining))
            try: conn, address = server.accept()
            except socket.timeout: break
            with conn:
                if address[0] != '127.0.0.1': raise ValueError('nonlocal peer')
                endpoint = {'index': count, 'local': list(conn.getsockname()), 'remote': list(address),
                            'accepted_ns': time.monotonic_ns()}
                log('native-accepted', endpoint=endpoint, attribution='unwitnessed')
                native_request(tree, conn, endpoint, seed, server_deadline); count += 1
        log('native-finished', requests=count, limit_reached=count == limit,
            server_deadline_ns=int(server_deadline * 1000000000), finished_ns=time.monotonic_ns())


def main():
    guard()
    if len(sys.argv) < 2 or sys.argv[1] not in ('sftp', 'native'): raise ValueError('mode')
    if sys.argv[1] == 'sftp' and sys.argv[2:] and (sys.argv[-2:] != ['fixture', 'sftp'] or '-s' not in sys.argv[2:-2]):
        raise ValueError('unexpected transport arguments')
    if sys.argv[1] == 'native' and (len(sys.argv) not in (2, 3) or
                                  (len(sys.argv) == 3 and sys.argv[2] not in tuple(str(n) for n in range(1, 17)))):
        raise ValueError('native arguments')
    parent_death = arm_parent_death() if sys.argv[1] == 'native' else None
    tree = Tree()
    try:
        log('started', mode=sys.argv[1], argv=sys.argv[2:], root=os.environ['SFTP_CONFINED_ROOT'], umask=current_umask(), parent_death=parent_death,
            uid=os.getuid(), euid=os.geteuid(),
            cwd=os.getcwd(), home=os.environ.get('HOME'),
            token=Path('/etc/bashos-parity-vm').read_text().strip())
        if sys.argv[1] == 'sftp': sftp(tree)
        else: native(tree, int(sys.argv[2]) if len(sys.argv) == 3 else 16)
    finally: os.close(tree.fd)


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, UnicodeError, KeyError, RuntimeError) as exc:
        print('confined SFTP peer: ' + repr(exc), file=sys.stderr); sys.exit(125)
