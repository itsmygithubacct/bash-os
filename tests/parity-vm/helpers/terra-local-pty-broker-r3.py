#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only fixed broker children and an independently controlled protocol peer.

The peer exists solely for the partial-output write case. It sends one known
16 KiB event, so the kernel FIFO size and the number of resumed writes are
deterministic. It never contacts anything outside the private VM workspace.
"""
import base64
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import termios
import time
import tty

HOME = Path(os.environ.get('HOME', '/nonexistent'))
SIZE = 32768 + 45
BINARY = bytes((i * 73 + 19) % 256 for i in range(SIZE))
PARTIAL = bytes((i * 37 + 11) % 256 for i in range(16384))
HISTORY = b'old\x00\x80\x1b[6n\nraw\xff'
LIVE = b'live\x00\xfe\x01\n'
FINAL = b'final\x00\xf9\n'


def marker(name, content=b'1\n'):
    target = HOME / name
    temporary = HOME / (name + '.tmp')
    temporary.write_bytes(content)
    os.replace(temporary, target)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise RuntimeError('short output')
        view = view[n:]


def wait_file(name, seconds=10):
    end = time.monotonic() + seconds
    while not (HOME / name).is_file():
        if time.monotonic() >= end:
            raise TimeoutError('missing gate ' + name)
        time.sleep(0.02)


def size():
    rows, cols, _, _ = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8))
    return ('%d %d\n' % (rows, cols)).encode()


def quiet_until_deadline():
    end = time.monotonic() + 12
    while time.monotonic() < end:
        time.sleep(0.05)


def child(mode):
    if mode == 'tree':
        grandchild = os.fork()
        if grandchild == 0:
            marker('tree-grandchild', ('%d\n' % os.getpid()).encode())
            quiet_until_deadline()
            os._exit(0)
        marker('tree-child', ('%d\n' % os.getpid()).encode())
        quiet_until_deadline()
        return
    tty.setraw(0)
    if mode == 'binary':
        marker('binary-ready')
        data = bytearray()
        deadline = time.monotonic() + 10
        while len(data) < SIZE:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
                raise TimeoutError('binary child input')
            block = os.read(0, min(8192, SIZE - len(data)))
            if not block:
                raise RuntimeError('binary child EOF')
            data.extend(block)
            write_all(1, block)
        marker('binary-child-input', bytes(data))
        quiet_until_deadline()
    elif mode == 'geometry':
        def on_winch(_signum, _frame):
            marker('geometry-winch', size())
        signal.signal(signal.SIGWINCH, on_winch)
        marker('geometry-initial', size())
        quiet_until_deadline()
    elif mode == 'history':
        write_all(1, HISTORY)
        marker('history-ready')
        wait_file('history-release')
        write_all(1, LIVE)
        quiet_until_deadline()
    elif mode == 'exit':
        marker('exit-ready')
        wait_file('exit-release')
        write_all(1, FINAL)
        raise SystemExit(23)
    elif mode == 'roles':
        marker('roles-input', b'')
        marker('roles-ready')
        data = bytearray()
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            ready, _, _ = select.select([0], [], [], 0.1)
            if ready:
                block = os.read(0, 8192)
                if not block:
                    break
                data.extend(block)
                marker('roles-input', bytes(data))
                write_all(1, block)
    elif mode == 'quiet':
        marker('quiet-ready')
        quiet_until_deadline()
    else:
        raise ValueError('unknown child')


def packet(kind, payload=b'', offset=0):
    return struct.pack('=IIIIQ', 0x42505431, kind, len(payload), 0, offset) + payload


def peer():
    root = HOME / 'mock-root'
    root.mkdir(mode=0o700)
    session = root / 'one'
    session.mkdir(mode=0o700)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.bind(str(session / 'control.sock'))
    os.chmod(session / 'control.sock', 0o600)
    sock.listen(1)
    sock.settimeout(8)
    marker('mock-ready')
    log = {'received_hex': '', 'error': None}
    conn = None
    try:
        conn, _ = sock.accept()
        conn.settimeout(8)
        request = conn.recv(20000)
        log['received_hex'] = request.hex()
        if request != packet(6):
            raise ValueError('unexpected attach request')
        # Linux native struct pb_status: five int32, four uint32, alignment,
        # and two uint64 offsets. Only metadata; the output bytes are fixed.
        status = struct.pack('=iiiiiIIII4xQQ', os.getpid(), os.getpid(), 1, 0, -1,
                             24, 80, 1, 0, 0, 0)
        if len(status) != 56:
            raise ValueError('unexpected status size')
        conn.sendall(packet(6 + 32, status))
        conn.sendall(packet(65, status))
        conn.sendall(packet(64, PARTIAL, 0))
        while conn.recv(1024):
            raise ValueError('unexpected input on mock connection')
    except Exception as exc:
        log['error'] = '%s: %s' % (type(exc).__name__, exc)
    finally:
        if conn is not None:
            conn.close()
        sock.close()
        marker('mock-log.json', (json.dumps(log, sort_keys=True) + '\n').encode())
    if log['error'] is not None:
        raise SystemExit(1)


def observer_probe_peer():
    """Independently verify the shell sends one exact seqpacket on its FD."""
    root = HOME / 'observer-control'
    root.mkdir(mode=0o700)
    session = root / 'one'
    session.mkdir(mode=0o700)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(str(session / 'control.sock'))
    os.chmod(session / 'control.sock', 0o600)
    server.listen(1)
    server.settimeout(8)
    marker('observer-control-ready')
    log = {'attach_hex': '', 'received_hex': '', 'packet_matches': False, 'error': None}
    conn = None
    try:
        conn, _ = server.accept()
        conn.settimeout(8)
        request = conn.recv(20000)
        log['attach_hex'] = request.hex()
        if request != packet(7):
            raise ValueError('unexpected observer attach request')
        status = struct.pack('=iiiiiIIII4xQQ', os.getpid(), os.getpid(), 1, 0, -1,
                             24, 80, 0, 1, 0, 0)
        conn.sendall(packet(7 + 32, status))
        conn.sendall(packet(65, status))
        request = conn.recv(20000)
        log['received_hex'] = request.hex()
        log['packet_matches'] = request == packet(3, b'X')
        if not log['packet_matches']:
            raise ValueError('probe packet bytes or boundary differ')
        event = packet(66, status)
        log['response_hex'] = event.hex()
        conn.sendall(event)
        if conn.recv(1024):
            raise ValueError('unexpected extra control input')
    except Exception as exc:
        log['error'] = '%s: %s' % (type(exc).__name__, exc)
    finally:
        if conn is not None:
            conn.close()
        server.close()
        marker('observer-control-result.json', (json.dumps(log, indent=2, sort_keys=True) + '\n').encode())
    if log['error'] is not None:
        raise SystemExit(1)


def collect_roles():
    files = ['role-output-%d' % i for i in range(9)] + [
        'roles-input', 'observer-packet.raw', 'expected-observer-packet',
        'observer-control-result.json', 'observer-real-receive.err', 'observer-probe-status.txt']
    result = {}
    for name in files:
        path = HOME / name
        try:
            data = path.read_bytes()
            result[name] = {'size': len(data), 'base64': base64.b64encode(data[:16384]).decode(),
                            'truncated': len(data) > 16384}
        except FileNotFoundError:
            result[name] = {'missing': True}
    marker('roles-observations.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode())


def inject(fd):
    # A role connection is read-only: a raw PB_INPUT packet on an observer
    # must close that connection and never reach the fixture-owned child.
    sock = socket.socket(fileno=fd)
    sock.settimeout(3)
    sock.sendall(packet(3, b'X'))
    try:
        data = sock.recv(4096)
    except ConnectionResetError:
        data = b''
    if data:
        raise RuntimeError('observer socket was not rejected')


def drain(fd, path, count):
    end = time.monotonic() + 3
    data = bytearray()
    while len(data) < count:
        remaining = end - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError('FIFO short read: %d/%d' % (len(data), count))
        data.extend(os.read(fd, count - len(data)))
    Path(path).write_bytes(data)


def require_guest():
    # The root guest evaluator verifies the exact UUID; this unprivileged
    # guard checks the readable marker, QEMU vendor, uid and case scratch.
    import uuid
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture uid or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires disposable QEMU uid2000 fixture scratch') from exc


if __name__ == '__main__':
    require_guest()
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == 'child':
        child(args[1])
    elif args == ['prepare']:
        for name, value in [('expected-binary', BINARY), ('expected-history', HISTORY),
                            ('expected-live', LIVE), ('expected-final', FINAL),
                            ('expected-partial', PARTIAL), ('expected-roles', b'alpha')]:
            marker(name, value)
        marker('expected-observer-packet', packet(3, b'X'))
    elif args == ['peer']:
        peer()
    elif args == ['observer-probe-peer']:
        observer_probe_peer()
    elif args == ['collect-roles']:
        collect_roles()
    elif len(args) == 2 and args[0] == 'inject':
        inject(int(args[1]))
    elif len(args) == 2 and args[0] == 'pipe-size':
        fd = int(args[1])
        actual = fcntl.fcntl(fd, fcntl.F_SETPIPE_SZ, 4096)
        if actual != 4096 or fcntl.fcntl(fd, fcntl.F_GETPIPE_SZ) != 4096:
            raise RuntimeError('FIFO capacity is not 4096')
        marker('fifo-capacity', b'4096\n')
    elif len(args) == 4 and args[0] == 'drain':
        drain(int(args[1]), args[2], int(args[3]))
    elif args == ['clock-ms']:
        print(time.monotonic_ns() // 1000000)
    else:
        raise SystemExit('invalid fixture arguments')
