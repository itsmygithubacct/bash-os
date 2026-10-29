#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only protocol oracle and lifecycle observer for the cluster membership loadable.

Modes (always inside the disposable parity VM, as uid 2000, in the case scratch directory):
  setup SCENARIO    independent controls of the oracle and of the process driver; a failed control is invalid evidence (exit 97)
  SHELL SCENARIO    run the candidate "cluster" builtin in persistent shells and print one summary line per vector

Expected values never come from candidate output alone. The wire format is this file's own implementation of the packet
layout documented in docs/sol-cluster.md and loadables/cluster.c (1212 bytes, "BCLSTR2" magic, keyed BLAKE2b-256 over the
first 1180 bytes) using hashlib, which shares no code with the candidate's monocypher. Oracle peers, probes and decoys are
owned loopback UDP sockets of this process; every request they receive is validated field by field. Kernel facts come from
the operating system itself: /proc process and UDP socket tables, inotify events of the state directory, bind() collisions,
file modes and owners. Every vector evaluates every key (no early exit). A failed control, or an exception inside the
fixture, prints CONTROL-INVALID / ERROR and exits 97 instead of a candidate result.

r2 retention: the observation primitives and every datagram are also recorded in an ordered timeline (trace) per vector, with every key
evaluation interleaved; the assertions, keys and plan are exactly those of the frozen cluster-followup-113 helper.

Only processes started by this fixture are ever signaled: persistent candidate shells (each in its own session), the listener
pids those shells printed after verifying they are children of that shell, and one owned sentinel process. Nothing is selected
by name, no pid is read from a state file for signaling, and every process is reaped before the helper exits.
"""
import base64
import ctypes
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback
import uuid


PYTHON = '/usr/bin/python3'
REFERENCE_BASH = '/opt/bash-5.3.15/bin/bash'
CASE = Path('/tmp/parity-case')

# Wire format (loadables/cluster.c: bc_packet); all fields are byte arrays, the port is big endian.
MAGIC = b'BCLSTR2\0'
JOIN, BEAT, LEAVE, PING, STOP, ROSTER, PONG, ERROR = 1, 2, 3, 4, 5, 6, 7, 8
MAX_ROWS, ROW = 32, 34
ROWS_AT = 8 + 1 + 1 + 2 + 16 + 32 + 32
MAC_AT = ROWS_AT + MAX_ROWS * ROW
SIZE = MAC_AT + 32
ZERO32 = bytes(32)
STATE_FILES = ('cluster_id', 'node_id', 'port', 'listener_pid', 'private_key', 'members', 'state')
SCRATCH_FILES = tuple('.%s.tmp' % name for name in STATE_FILES)

# Diagnostics of loadables/cluster.c after the shell's own "bash: line N: " prefix.
MSG_PRIVATE = b'cluster: state directory must be owned and private (0700)'
MSG_LOCK = b'cluster: state directory already has a listener'
MSG_KEY = b'cluster: key must contain 64 lowercase hexadecimal digits'
MSG_TIMEOUT = b'cluster: invalid state path or timeout (50..5000 ms)'
MSG_JOIN_ENDPOINT = b'cluster: join needs 127.0.0.1:PORT'
MSG_JOIN_KEY = b'cluster: join requires -k KEYFILE'
MSG_HANDSHAKE = b'cluster: membership handshake failed or timed out'
MSG_ALREADY = b'cluster: already initialized; leave before joining again'
MSG_UNKNOWN = b'cluster: unknown node or invalid endpoint: '
MSG_NO_MEMBERSHIP = b'cluster: no initialized membership'
MSG_REQUEST_TIMEOUT = b'cluster: membership request timed out: '
MSG_START = b'cluster: cannot start membership: '

START_RE = re.compile(rb'(initialized|joined)\ncluster_id=([0-9a-f]{32})\nnode_id=([0-9a-f]{32})\nport=([0-9]+)\nlistener_pid=([0-9]+)\n')
ROW_RE = re.compile(rb'([0-9a-f]{32}) 127\.0\.0\.1:([0-9]{1,5})')


class FixtureError(Exception):
    """A fixture control failed: the observation is invalid evidence, not a candidate result."""


# r2 retention: the ordered observation timeline of the current vector. It is written next to the transcript and never
# influences a check; consecutive identical observations are run-length compressed (count, last).
TRACE = []
CURRENT = {'world': None}


def show(value, limit=600):
    if isinstance(value, bytes):
        return value[:limit].hex()
    if isinstance(value, dict):
        return {str(k): show(v, limit) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(show(v, limit) for v in value)
    if isinstance(value, (list, tuple)):
        return [show(v, limit) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def trace(kind, **data):
    try:
        entry = {'kind': kind}
        entry.update(show(data))
        if TRACE and {k: v for k, v in TRACE[-1].items() if k not in ('t', 'last', 'count')} == entry:
            TRACE[-1]['count'] = TRACE[-1].get('count', 1) + 1
            TRACE[-1]['last'] = round(time.monotonic(), 6)
        else:
            entry['t'] = round(time.monotonic(), 6)
            TRACE.append(entry)
    except Exception:
        pass


def sentinel_states():
    try:
        return [p.poll() for p in CURRENT['world'].sentinels]
    except Exception:
        return None


def refuse(reason):
    sys.stderr.write('cluster-followup-observer: refusing: %s\n' % reason)
    sys.exit(99)


def require_guest():
    # The root evaluator separately verifies the marker against the DMI UUID.
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
    except (OSError, ValueError):
        refuse('not inside the disposable parity VM')
    if vendor != 'QEMU':
        refuse('not a QEMU guest')
    if os.geteuid() != 2000:
        refuse('not uid 2000')
    if Path.cwd() != CASE:
        refuse('not in the case scratch directory')


def yes(flag):
    return 'yes' if flag else 'no'


def b64(data):
    return base64.b64encode(data).decode()


def ident(label):
    """A deterministic 32 lowercase hexadecimal digit identifier (cluster and node ids chosen by the fixture)."""
    return hashlib.sha256(b'cluster-followup-id:' + label.encode()).hexdigest()[:32].encode()


def secret(label):
    """A deterministic 32 byte group key chosen by the fixture."""
    return hashlib.sha256(b'cluster-followup-key:' + label.encode()).digest()


def write_key(path, key, newline=False):
    path = Path(path)
    path.write_bytes(key.hex().encode() + (b'\n' if newline else b''))
    os.chmod(path, 0o600)
    return path


def free_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def port_free(port):
    """True when 127.0.0.1:port can be bound by this process (no listener holds it)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(('127.0.0.1', port))
        return True
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            return False
        raise
    finally:
        probe.close()


def ephemeral_range():
    low, high = Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()
    return int(low), int(high)


# ---------------------------------------------------------------------------
# Wire codec: the oracle's own implementation of the documented packet format.
# ---------------------------------------------------------------------------

def mac(key, body):
    return hashlib.blake2b(body, key=key, digest_size=32).digest()


def build(key, kind, port, cluster, node, nonce, rows=(), count=None, magic=MAGIC):
    """One datagram: header, nonce, cluster and node ids, the row table padded with zeros, and the keyed MAC."""
    rows = list(rows)
    if count is None:
        count = len(rows)
    table = b''.join(row_node + struct.pack('!H', row_port) for row_node, row_port in rows)
    body = magic + bytes([kind, count]) + struct.pack('!H', port) + nonce + cluster + node + table + bytes(MAX_ROWS * ROW - len(table))
    return body + mac(key, body)


def parse(data):
    """Strict decoding of one datagram; None unless it has exactly the documented size."""
    if len(data) != SIZE:
        return None
    count = data[9]
    shown = min(count, MAX_ROWS)
    rows = [(data[ROWS_AT + i * ROW:ROWS_AT + i * ROW + 32], struct.unpack('!H', data[ROWS_AT + i * ROW + 32:ROWS_AT + i * ROW + 34])[0])
            for i in range(shown)]
    return {'magic': data[:8], 'type': data[8], 'count': count, 'port': struct.unpack('!H', data[10:12])[0], 'nonce': data[12:28],
            'cluster': data[28:60], 'node': data[60:92], 'rows': rows, 'tail': data[ROWS_AT + shown * ROW:MAC_AT], 'mac': data[MAC_AT:]}


def mac_ok(key, data):
    return len(data) == SIZE and hmac.compare_digest(mac(key, data[:MAC_AT]), data[MAC_AT:])


def flip(data, index):
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def validate_request(data, key, kind, cluster, node, port):
    """Field-by-field validation of a request the candidate sent (booleans; every field is checked)."""
    q = parse(data)
    checks = {'size': len(data) == SIZE, 'mac': mac_ok(key, data)}
    checks['magic'] = q is not None and q['magic'] == MAGIC
    checks['type'] = q is not None and q['type'] == kind
    checks['count'] = q is not None and q['count'] == 0
    checks['port'] = q is not None and q['port'] == port
    checks['cluster'] = q is not None and q['cluster'] == cluster
    checks['node'] = q is not None and q['node'] == node
    checks['nonce'] = q is not None and q['nonce'] != bytes(16)
    checks['rows_zero'] = q is not None and q['tail'] == bytes(len(q['tail'])) and len(q['tail']) == MAX_ROWS * ROW
    return checks


def valid_reply(data, key, kind, nonce, cluster, node, port, rows=()):
    q = parse(data)
    return (q is not None and mac_ok(key, data) and q['magic'] == MAGIC and q['type'] == kind and q['nonce'] == nonce and q['cluster'] == cluster
            and q['node'] == node and q['port'] == port and q['rows'] == list(rows) and q['count'] == len(rows)
            and q['tail'] == bytes(len(q['tail'])))


# ---------------------------------------------------------------------------
# Files: snapshots and independent parsing of what the candidate left on disk.
# ---------------------------------------------------------------------------

def listing(directory):
    try:
        return sorted(os.listdir(directory))
    except OSError:
        return None


def read_files(directory):
    found = {}
    for name in listing(directory) or []:
        path = os.path.join(directory, name)
        try:
            if stat.S_ISREG(os.lstat(path).st_mode):
                with open(path, 'rb') as handle:
                    found[name] = handle.read()
        except OSError:
            continue
    return found


def snapshot(directory):
    """Kind, mode, owner, inode, mtime, size and content digest of every entry: the oracle's view of a directory."""
    result = {}
    for name in listing(directory) or []:
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
        except OSError:
            continue
        record = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'ino': info.st_ino, 'mtime': info.st_mtime_ns, 'size': info.st_size}
        if stat.S_ISLNK(info.st_mode):
            record.update(kind='link', target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            record['kind'] = 'dir'
        elif stat.S_ISREG(info.st_mode):
            with open(path, 'rb') as handle:
                record.update(kind='file', digest=hashlib.sha256(handle.read()).hexdigest())
        else:
            record['kind'] = 'other'
        result[name] = record
    return result


def parse_roster(data):
    """List of (node id, port) from a members file, or None when a line does not have the documented shape."""
    if data is None:
        return None
    if data == b'':
        return []
    if not data.endswith(b'\n'):
        return None
    rows = []
    for line in data[:-1].split(b'\n'):
        match = ROW_RE.fullmatch(line)
        if match is None or not 1 <= int(match.group(2)) <= 65535:
            return None
        rows.append((match.group(1), int(match.group(2))))
    return rows


def parse_start(call):
    match = START_RE.fullmatch(call.out) if call is not None else None
    if match is None:
        return None
    return {'verb': match.group(1), 'cluster': match.group(2), 'node': match.group(3), 'port': int(match.group(4)), 'pid': int(match.group(5))}


def parse_status(call):
    fields = {}
    for line in call.out.decode('utf-8', 'replace').split('\n'):
        if '=' in line:
            name, _, value = line.partition('=')
            fields[name] = value
    return fields


UNRELATED = (('unrelated.txt', b'keep me\n', 0o640), ('members.bak', b'old roster copy\n', 0o644), ('.members.tmp.keep', b'look-alike scratch name\n', 0o600),
             ('state.old', b'x', 0o644))


def make_unrelated(directory):
    """Files a membership must never touch, including names that merely resemble its own."""
    directory = Path(directory)
    for name, data, mode in UNRELATED:
        (directory / name).write_bytes(data)
        os.chmod(directory / name, mode)
    os.mkdir(directory / 'unrelated.d', 0o750)
    (directory / 'unrelated.d' / 'inner').write_bytes(b'inner\n')
    os.symlink('unrelated.txt', directory / 'unrelated.link')
    return snapshot(directory)


def unrelated_kept(directory, baseline):
    now = snapshot(directory)
    return all(name in now and now[name] == record for name, record in baseline.items())


# ---------------------------------------------------------------------------
# Kernel observers: /proc process table, UDP socket table, inotify.
# ---------------------------------------------------------------------------

def _proc_stat(pid):
    try:
        data = Path('/proc/%d/stat' % pid).read_bytes()
        fields = data[data.rindex(b')') + 2:].split()
        return {'state': fields[0].decode(), 'ppid': int(fields[1]), 'pgrp': int(fields[2]), 'session': int(fields[3])}
    except (OSError, ValueError, IndexError):
        return None


def proc_stat(pid):
    return _proc_stat(pid)


def processes():
    found = {}
    for name in os.listdir('/proc'):
        if name.isdigit():
            info = _proc_stat(int(name))
            if info is not None:
                found[int(name)] = info
    return found


def alive(pid):
    info = _proc_stat(pid)
    return info is not None and info['state'] != 'Z'


def live_children(pid):
    return sorted(p for p, info in processes().items() if info['ppid'] == pid and info['state'] != 'Z')


def group_members(pgid):
    return sorted(p for p, info in processes().items() if info['pgrp'] == pgid and info['state'] != 'Z')


def kill_pid(pid, reason):
    trace('kill', pid=pid, reason=reason)
    os.kill(pid, signal.SIGKILL)


def kill_group(pgid):
    trace('killpg', pgid=pgid)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def reap_zombies(keep):
    """Reap exited orphans that were re-parented to this process (it is a child subreaper); never a tracked Popen child."""
    me = os.getpid()
    for pid, info in processes().items():
        if info['ppid'] == me and info['state'] == 'Z' and pid not in keep:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass


def set_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'prctl(PR_SET_CHILD_SUBREAPER)')


def socket_inodes(pid):
    found = set()
    try:
        names = os.listdir('/proc/%d/fd' % pid)
    except OSError:
        return found
    for name in names:
        try:
            target = os.readlink('/proc/%d/fd/%s' % (pid, name))
        except OSError:
            continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if match:
            found.add(int(match.group(1)))
    return found


def udp_rows():
    rows = []
    for line in Path('/proc/net/udp').read_text().splitlines()[1:]:
        f = line.split()
        if len(f) < 13:
            continue
        ip_hex, _, port_hex = f[1].partition(':')
        queues = f[4].partition(':')
        rows.append({'ip': socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1]), 'port': int(port_hex, 16), 'tx': int(queues[0], 16),
                     'rx': int(queues[2], 16), 'uid': int(f[7]), 'inode': int(f[9]), 'drops': int(f[12])})
    return rows


def udp_row(port, ip='127.0.0.1'):
    return next((row for row in udp_rows() if row['port'] == port and row['ip'] == ip), None)


IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE, IN_ONLYDIR = 0x2, 0x8, 0x40, 0x80, 0x100, 0x200, 0x01000000
IN_NONBLOCK, IN_CLOEXEC = 0o4000, 0o2000000


class Inotify:
    """Events of one directory; the kernel queues them synchronously with the file system operations."""

    def __init__(self, path):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify_init1')
        mask = IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_ONLYDIR
        if libc.inotify_add_watch(self.fd, os.fsencode(str(path)), mask) < 0:
            error = ctypes.get_errno()
            os.close(self.fd)
            raise OSError(error, 'inotify_add_watch')

    def read(self):
        events = []
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                if events:
                    trace('inotify', events=events)
                return events
            offset = 0
            while offset < len(data):
                _wd, mask, cookie, length = struct.unpack_from('iIII', data, offset)
                name = data[offset + 16:offset + 16 + length].split(b'\0', 1)[0].decode('utf-8', 'replace')
                events.append((mask, cookie, name))
                offset += 16 + length

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


def atomic_report(events):
    """The write-temp-then-rename invariants of the state files, from an ordered list of (mask, cookie, name) events."""
    stage, pending, created = {}, {}, set()
    renamed = {name: 0 for name in STATE_FILES}
    inplace, order = [], []
    for mask, cookie, name in events:
        if mask & IN_CREATE:
            created.add(name)
            if name in STATE_FILES:
                inplace.append(('create', name))
            else:
                stage[name] = 'created'
        if mask & IN_MODIFY and name in STATE_FILES:
            inplace.append(('modify', name))
        if mask & IN_CLOSE_WRITE:
            if name in STATE_FILES:
                inplace.append(('close-write', name))
            elif stage.get(name) == 'created':
                stage[name] = 'closed'
        if mask & IN_MOVED_FROM:
            if name in SCRATCH_FILES and stage.get(name) != 'closed':
                order.append(('renamed-before-closed', name))
            stage.pop(name, None)
            pending[cookie] = name
        if mask & IN_MOVED_TO:
            source = pending.pop(cookie, None)
            if name in STATE_FILES:
                renamed[name] += 1
                if source != '.%s.tmp' % name:
                    order.append(('final-name-not-from-its-scratch-file', name))
    return {'renamed': renamed, 'inplace': inplace, 'order': order, 'lock_created': 'lock' in created,
            'all_state_files_renamed_in': all(count >= 1 for count in renamed.values())}


# ---------------------------------------------------------------------------
# Event loop, owned UDP endpoints, persistent shells and the world that owns them.
# ---------------------------------------------------------------------------

class Reactor:
    """select()-based dispatch of sockets and pipes; waiting is always for an observable condition with a deadline."""

    def __init__(self):
        self.handlers = {}

    def add(self, fd, handler):
        self.handlers[fd] = handler

    def remove(self, fd):
        self.handlers.pop(fd, None)

    def pump(self, timeout=0.0):
        """Dispatch whatever is readable right now (datagrams that arrived while no wait was running)."""
        fds = list(self.handlers)
        if not fds:
            return
        for fd in select.select(fds, [], [], timeout)[0]:
            handler = self.handlers.get(fd)
            if handler is not None:
                handler()

    def wait(self, ready, timeout, interval=0.02):
        end = time.monotonic() + timeout
        while True:
            if ready():
                return True
            left = end - time.monotonic()
            if left <= 0:
                return False
            fds = list(self.handlers)
            try:
                readable = select.select(fds, [], [], min(left, interval))[0]
            except (OSError, ValueError):
                for fd in fds:
                    try:
                        os.fstat(fd)
                    except OSError:
                        self.handlers.pop(fd, None)
                continue
            for fd in readable:
                handler = self.handlers.get(fd)
                if handler is not None:
                    handler()


class Endpoint:
    """An owned UDP socket (oracle peer, probe or decoy); arriving datagrams are queued with their arrival time."""

    def __init__(self, world, label, ip='127.0.0.1', port=0, handler=None):
        self.world, self.label, self.handler = world, label, handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.setblocking(False)
        self.ip, self.port = ip, self.sock.getsockname()[1]
        self.fd = self.sock.fileno()
        self.received = []
        self.closed = False
        trace('endpoint', label=label, ip=ip, port=self.port)
        world.reactor.add(self.fd, self.readable)
        world.endpoints.append(self)

    def readable(self):
        while True:
            try:
                data, source = self.sock.recvfrom(65536)
            except BlockingIOError:
                return
            except OSError as exc:
                if exc.errno == errno.ECONNREFUSED:
                    continue
                raise
            entry = (time.monotonic(), data, source)
            self.received.append(entry)
            trace('recv', endpoint=self.label, port=self.port, source=source, size=len(data), sha=hashlib.sha256(data).hexdigest(), hex=data[:1300].hex() if len(data) <= 1300 else '')
            if self.handler is not None:
                self.handler(self, entry)

    def send(self, data, port, ip='127.0.0.1'):
        if not 1 <= port <= 65535:
            return  # the candidate never reported a usable port: there is nothing to send to
        trace('send', endpoint=self.label, from_port=self.port, to_port=port, ip=ip, size=len(data), sha=hashlib.sha256(data).hexdigest(),
              hex=data.hex() if len(data) <= 1300 else '')
        self.sock.sendto(data, (ip, port))

    def take(self):
        items, self.received = self.received, []
        return items

    def close(self):
        if not self.closed:
            self.closed = True
            self.world.reactor.remove(self.fd)
            self.sock.close()


class Call:
    """One command run in a persistent shell: raw status, stdout and stderr, and how long it took."""

    def __init__(self, node, script, rc, out, err, elapsed, timed_out):
        self.node, self.script, self.rc, self.out, self.err = node, script, rc, out, err
        self.elapsed, self.timed_out = elapsed, timed_out
        self.finished = time.monotonic()

    def record(self):
        return {'node': self.node.label, 'script': self.script, 'rc': self.rc, 'stdout': b64(self.out), 'stderr': b64(self.err),
                'elapsed': round(self.elapsed, 4), 'timed_out': self.timed_out, 'finished': round(self.finished, 6)}


class Node:
    """One persistent shell, in its own session, that owns whatever listeners its cluster commands start."""

    def __init__(self, world, label, directory, timeout=500, shell=None, env=None):
        self.world, self.label, self.directory = world, label, Path(directory)
        environment = dict(os.environ)
        environment['BASHCLUSTER_STATE_DIR'] = str(directory)
        environment['BASHCLUSTER_TIMEOUT_MS'] = str(timeout)
        environment.update(env or {})
        self.proc = subprocess.Popen([shell or world.shell, '--noprofile', '--norc'], cwd=str(CASE), env=environment, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
        self.pid = self.proc.pid
        self.buffers = {'out': bytearray(), 'err': bytearray()}
        self.eof = {'out': False, 'err': False}
        self.fds = {'out': self.proc.stdout.fileno(), 'err': self.proc.stderr.fileno()}
        self.sequence = 0
        self.dead = False
        self.closed = False
        for name in ('out', 'err'):
            os.set_blocking(self.fds[name], False)
            world.reactor.add(self.fds[name], lambda name=name: self.fill(name))
        world.nodes.append(self)

    def fill(self, name):
        try:
            data = os.read(self.fds[name], 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b''
        if data:
            self.buffers[name].extend(data)
        else:
            self.eof[name] = True
            self.world.reactor.remove(self.fds[name])

    def locate(self, mark):
        head = b'\n@@' + mark + b' '
        at = self.buffers['out'].find(head)
        end = self.buffers['out'].find(b'@@\n', at + len(head)) if at >= 0 else -1
        tail = b'\n@@' + mark + b'@@\n'
        at_err = self.buffers['err'].find(tail)
        if at >= 0 and end >= 0 and at_err >= 0:
            return at, end, at_err, len(head), len(tail)
        return None

    def call(self, script, timeout=8.0):
        self.sequence += 1
        mark = ('M%d_%d' % (self.pid, self.sequence)).encode()
        text = '%s\n__rc=$?\nprintf \'\\n@@%%s %%s@@\\n\' %s "$__rc"\nprintf \'\\n@@%%s@@\\n\' %s >&2\n' % (script, mark.decode(), mark.decode())
        started = time.monotonic()
        sent = not self.dead
        if sent:
            try:
                self.proc.stdin.write(text.encode())
                self.proc.stdin.flush()
            except (OSError, ValueError):
                sent = False
        if sent:
            self.world.reactor.wait(lambda: self.locate(mark) is not None or (self.eof['out'] and self.eof['err']), timeout)
        found = self.locate(mark)
        elapsed = time.monotonic() - started
        rc, timed_out = None, False
        if found:
            at, end, at_err, head, tail = found
            try:
                rc = int(bytes(self.buffers['out'][at + head:end]))
            except ValueError:
                rc = None
            out, err = bytes(self.buffers['out'][:at]), bytes(self.buffers['err'][:at_err])
            del self.buffers['out'][:end + 3]
            del self.buffers['err'][:at_err + tail]
        else:
            out, err = bytes(self.buffers['out']), bytes(self.buffers['err'])
            timed_out = sent and not (self.eof['out'] and self.eof['err'])
            self.dead = True
            kill_group(self.pid)
        call = Call(self, script, rc, out, err, elapsed, timed_out)
        self.world.transcript.append(call.record())
        return call

    def cluster(self, *args, env=None, timeout=8.0):
        prefix = ''.join('%s=%s ' % (name, shlex.quote(str(value))) for name, value in (env or {}).items())
        return self.call(prefix + 'cluster ' + ' '.join(shlex.quote(str(arg)) for arg in args), timeout)

    def children(self):
        return live_children(self.pid)

    def close(self):
        world = self.world
        if self.closed:
            return {'node': self.label, 'left_after_exit': [], 'killed': []}
        self.closed = True
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write(b'exit\n')
                self.proc.stdin.flush()
            except (OSError, ValueError):
                pass
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            world.reactor.wait(lambda: self.proc.poll() is not None, 3.0)
        if self.proc.poll() is None:
            kill_group(self.pid)
            world.reactor.wait(lambda: self.proc.poll() is not None, 3.0)
        self.proc.poll()
        left = group_members(self.pid)
        if left:
            world.reactor.wait(lambda: not group_members(self.pid), 3.0)
        killed = group_members(self.pid)
        if killed:
            kill_group(self.pid)
            world.reactor.wait(lambda: not group_members(self.pid), 3.0)
        reap_zombies(world.keep())
        for name in ('out', 'err'):
            world.reactor.remove(self.fds[name])
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
        return {'node': self.label, 'left_after_exit': left, 'killed': killed}


class World:
    """Everything one vector owns: shells, UDP endpoints, inotify watches and the sentinel; closed after every vector."""

    def __init__(self, shell):
        self.shell = shell
        self.reactor = Reactor()
        self.nodes, self.endpoints, self.sentinels, self.closers = [], [], [], []
        self.transcript, self.notes, self.label, self.counter = [], {}, '', 0
        self.failures = []

    def keep(self):
        return {n.pid for n in self.nodes if n.proc.returncode is None} | {s.pid for s in self.sentinels if s.returncode is None}

    def nonce(self):
        self.counter += 1
        return hashlib.sha256(b'cluster-followup-nonce:%d' % self.counter).digest()[:16]

    def node(self, label, directory, timeout=500, env=None):
        return Node(self, label, directory, timeout, env=env)

    def endpoint(self, label, ip='127.0.0.1', handler=None):
        return Endpoint(self, label, ip=ip, handler=handler)

    def decoy(self, label):
        """A socket on every local address: it receives whatever a mis-parsed 127.x.y.z target would have been sent."""
        return Endpoint(self, label, ip='0.0.0.0')

    def sentinel(self):
        process = subprocess.Popen([PYTHON, '-c', 'import sys; sys.stdin.buffer.read()'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
        self.sentinels.append(process)
        return process

    def inotify(self, path):
        watch = Inotify(path)
        self.closers.append(watch.close)
        return watch

    def note(self, key, value):
        self.notes[key] = value

    def begin(self, label):
        self.label, self.transcript, self.notes = label, [], {}
        TRACE.clear()

    def close_all(self):
        report = []
        for node in reversed(self.nodes):
            report.append(node.close())
        self.nodes = []
        for process in self.sentinels:
            if process.poll() is None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
                self.reactor.wait(lambda p=process: p.poll() is not None, 3.0)
            if process.poll() is None:
                try:
                    kill_pid(process.pid, 'sentinel')
                except ProcessLookupError:
                    pass
                self.reactor.wait(lambda p=process: p.poll() is not None, 3.0)
        self.sentinels = []
        for endpoint in self.endpoints:
            endpoint.close()
        self.endpoints = []
        for closer in self.closers:
            closer()
        self.closers = []
        reap_zombies(set())
        return report

    def finish(self, failure):
        problems = []
        try:
            report = self.close_all()
        except Exception:
            report = []
            problems.append(traceback.format_exc())
        row = {'vector': self.label, 'calls': self.transcript, 'notes': self.notes, 'trace': list(TRACE),
               'teardown': [item for item in report if item['left_after_exit'] or item['killed']]}
        if failure:
            row['exception'] = failure
        if problems:
            row['teardown_exception'] = problems
        with open('observations.jsonl', 'a') as stream:
            stream.write(json.dumps(row, sort_keys=True, default=lambda value: b64(value) if isinstance(value, bytes) else str(value)) + '\n')
        return bool(failure or problems)


class Vector:
    """The keys of one vector; every key is evaluated, and a key that never was evaluated prints ERROR."""

    def __init__(self, name, keys):
        self.name, self.keys, self.values = name, list(keys), {}

    def check(self, key, condition):
        if key not in self.keys or key in self.values:
            raise FixtureError('vector %s: unknown or repeated key %s' % (self.name, key))
        self.values[key] = bool(condition)
        trace('check', vector=self.name, key=key, value=bool(condition), sentinels=sentinel_states())
        return bool(condition)

    def line(self):
        return '%s %s' % (self.name, ' '.join('%s=%s' % (key, yes(self.values[key]) if key in self.values else 'ERROR') for key in self.keys))


def run_vector(world, plan, name, function):
    vector = Vector(name, plan[name])
    CURRENT['world'] = world
    world.begin(name)
    failure = None
    try:
        function(world, vector)
    except Exception:
        failure = traceback.format_exc()
    broken = world.finish(failure)
    return vector, broken


# ---------------------------------------------------------------------------
# Oracle peers, probes and the candidate members they talk to.
# ---------------------------------------------------------------------------

def is_reply_to(data, nonce):
    q = parse(data)
    return q is not None and q['nonce'] == nonce


def exchange(world, probe, port, packets, nonce, timeout=3.0):
    """Send packets to a listener, then wait for the reply carrying nonce; returns (that reply or None, every other reply).

    One socket receives replies in the order the listener sent them, and a listener handles datagrams in arrival order, so
    every reply to an earlier packet is already queued when the reply to the last one arrives."""
    if not 1 <= port <= 65535:
        return None, []
    for data in packets:
        probe.send(data, port)
    world.reactor.wait(lambda: any(is_reply_to(entry[1], nonce) for entry in probe.received), timeout)
    entries = probe.take()
    hit = next((entry for entry in entries if is_reply_to(entry[1], nonce)), None)
    others = [entry for entry in entries if entry is not hit]
    world.notes.setdefault('exchanges', []).append({'to_port': port, 'sent_sizes': [len(data) for data in packets], 'reply': hit[1].hex() if hit else None,
                                                    'other_replies': [entry[1].hex()[:2600] for entry in others]})
    return hit, others


def oracle_ping(world, probe, key, port, cluster, before=()):
    nonce = world.nonce()
    request = build(key, PING, probe.port, cluster, ident('probe-' + probe.label), nonce)
    hit, others = exchange(world, probe, port, list(before) + [request], nonce)
    return nonce, hit, others


def pong_ok(hit, key, nonce, cluster, node=None, port=None):
    if hit is None:
        return False
    q = parse(hit[1])
    return (q is not None and mac_ok(key, hit[1]) and q['magic'] == MAGIC and q['type'] == PONG and q['nonce'] == nonce and q['cluster'] == cluster
            and q['count'] == 0 and q['tail'] == bytes(len(q['tail'])) and (node is None or q['node'] == node) and (port is None or q['port'] == port))


def identity_on_wire(world, probe, key, port, cluster):
    """What a listener says about itself in an authenticated PONG: its node id, port and cluster id (independent of its stdout)."""
    nonce, hit, _others = oracle_ping(world, probe, key, port, cluster)
    if hit is None or not pong_ok(hit, key, nonce, cluster):
        return None
    q = parse(hit[1])
    return {'node': q['node'], 'port': q['port'], 'cluster': q['cluster']}


def wire_roster(world, probe, key, port, label):
    """JOIN as an owned probe node: the seed's ROSTER reply (rows read from the wire), then LEAVE. Returns (rows, cluster, left)."""
    node = ident('wire-' + label)
    nonce = world.nonce()
    hit, _others = exchange(world, probe, port, [build(key, JOIN, probe.port, ZERO32, node, nonce)], nonce)
    q = parse(hit[1]) if hit is not None else None
    if q is None or q['type'] != ROSTER or not mac_ok(key, hit[1]):
        return None, None, False
    leave_nonce = world.nonce()
    done, _others = exchange(world, probe, port, [build(key, LEAVE, probe.port, q['cluster'], node, leave_nonce)], leave_nonce)
    left = done is not None and pong_ok(done, key, leave_nonce, q['cluster'])
    return q['rows'], q['cluster'], left


class Peer:
    """An oracle protocol peer on its own UDP socket: validates every PING it receives and answers according to its mode."""

    def __init__(self, world, label, key, cluster, node, mode='echo', client=None):
        self.key, self.cluster, self.node, self.mode, self.client = key, cluster, node, mode, client
        self.requests = []
        self.alt = world.endpoint(label + '-alt') if mode == 'other-port' else None
        self.endpoint = world.endpoint(label, handler=self.on_datagram)
        self.port = self.endpoint.port

    def answer(self, nonce):
        key, port, cluster, node, mode = self.key, self.port, self.cluster, self.node, self.mode
        good = build(key, PONG, port, cluster, node, nonce)
        if mode in ('echo', 'other-port'):
            return good
        return {'garbage': lambda: b'garbage',
                'short': lambda: good[:-1],
                'long': lambda: good + b'X',
                'wrong-key': lambda: build(secret('peer-wrong-key'), PONG, port, cluster, node, nonce),
                'wrong-nonce': lambda: build(key, PONG, port, cluster, node, bytes(b ^ 0xff for b in nonce)),
                'wrong-type': lambda: build(key, ERROR, port, cluster, node, nonce),
                'bad-magic': lambda: build(key, PONG, port, cluster, node, nonce, magic=b'BCLSTR1\0'),
                'count33': lambda: build(key, PONG, port, cluster, node, nonce, count=33),
                'wrong-cluster': lambda: build(key, PONG, port, ident('peer-other-cluster'), node, nonce)}.get(mode, lambda: None)()

    def on_datagram(self, endpoint, entry):
        _when, data, source = entry
        record = {'from': source, 'raw': data.hex(), 'checks': validate_request(data, self.key, PING, *self.client) if self.client else None}
        self.requests.append(record)
        trace('peer-request', peer=self.endpoint.label, mode=self.mode, checks=record['checks'])
        q = parse(data)
        reply = self.answer(q['nonce']) if q is not None else None
        if reply is not None:
            (self.alt or endpoint).send(reply, source[1])

    def valid_requests(self):
        return [r for r in self.requests if r['checks'] and all(r['checks'].values())]


class Member:
    """One candidate shell with its own state directory and the group key the fixture chose for it."""

    def __init__(self, world, label, key_label, timeout=500, directory=None, env=None):
        self.world, self.label, self.timeout = world, label, timeout
        self.directory = Path(directory) if directory is not None else CASE / label
        self.key = secret(key_label)
        self.keyfile = write_key(CASE / ('%s.key' % key_label), self.key)
        self.node = world.node(label, self.directory, timeout, env=env)
        self.info, self.last = None, None

    @property
    def port(self):
        return self.info['port'] if self.info else 0

    @property
    def pid(self):
        return self.info['pid'] if self.info else 0

    @property
    def cluster(self):
        return self.info['cluster'] if self.info else ZERO32

    @property
    def node_id(self):
        return self.info['node'] if self.info else ZERO32

    def init(self, *extra, env=None):
        self.last = self.node.cluster('init', '-p', 0, '-k', self.keyfile, *extra, env=env)
        self.info = parse_start(self.last)
        return self.info

    def join(self, seed, keyfile=None, *extra, env=None):
        self.last = self.node.cluster('join', '127.0.0.1:%d' % seed.port, '-k', keyfile or seed.keyfile, *extra, env=env)
        self.info = parse_start(self.last)
        return self.info

    def files(self):
        return read_files(self.directory)

    def roster(self):
        return parse_roster(self.files().get('members'))

    def status(self):
        return parse_status(self.node.cluster('status'))

    def row(self):
        return (self.node_id, self.port)

    def ping(self, probe, key=None, cluster=None, before=()):
        """Authenticated PING from an owned probe; returns (nonce, reply, other replies)."""
        return oracle_ping(self.world, probe, key or self.key, self.port, cluster or self.cluster, before)

    def wire_identity(self, probe):
        return identity_on_wire(self.world, probe, self.key, self.port, self.cluster) if self.info else None


def kill_listener(world, member):
    """SIGKILL the listener a member printed, after verifying that it is a child of that member's own shell."""
    pid = member.pid
    info = proc_stat(pid) if pid else None
    if info is None or info['ppid'] != member.node.pid:
        return False
    kill_pid(pid, 'verified child listener')
    return world.reactor.wait(lambda: not alive(pid), 3.0)


def wait_roster(world, member, expected, timeout=5.0):
    return world.reactor.wait(lambda: member.roster() == expected, timeout)


def foreign_private_directory():
    """A directory this uid does not own and that has no group or other bits (the ownership branch of the private-directory check)."""
    for path in ('/root', '/var/lib/private', '/var/cache/private', '/var/log/private'):
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode) and info.st_uid != os.geteuid() and not info.st_mode & 0o077:
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                return path
            except OSError:
                continue
    raise FixtureError('no root-owned private directory (no group/other bits, mkdir answering EEXIST) exists in the guest')


def craft_state(directory, cluster, node, port, key, rows):
    """A private state directory as an initialized member would leave it (enough for ping and members), without any listener."""
    directory = Path(directory)
    os.mkdir(directory, 0o700)
    content = {'cluster_id': cluster, 'node_id': node, 'port': b'%d\n' % port, 'private_key': key.hex().encode(),
               'members': b''.join(b'%s 127.0.0.1:%d\n' % (row_node, row_port) for row_node, row_port in rows)}
    for name, data in content.items():
        (directory / name).write_bytes(data)
        os.chmod(directory / name, 0o600)
    return directory


# ---------------------------------------------------------------------------
# cluster/seed-initialization
# ---------------------------------------------------------------------------

def private_tree(directory):
    """True when directory is 0700 and owned by this uid and holds exactly the state files and the lock, all regular 0600 files."""
    try:
        info = os.lstat(directory)
    except OSError:
        return False
    shot = snapshot(directory)
    return (stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid() and set(shot) == set(STATE_FILES) | {'lock'}
            and all(r['kind'] == 'file' and r['mode'] == 0o600 and r['uid'] == os.geteuid() for r in shot.values()))


def v_seed_fresh(world, vec):
    base, other = CASE / 'seed-fresh', CASE / 'seed-second'
    node = world.node('seed', base)
    probe = world.endpoint('probe')
    typed = node.call('type -t cluster')
    vec.check('builtin', typed.rc == 0 and typed.out == b'builtin\n')
    first = node.cluster('init', '-p', 0)
    info = parse_start(first)
    port, pid = (info['port'], info['pid']) if info else (0, 0)
    files = read_files(base)
    low, high = ephemeral_range()
    vec.check('init-status', first.rc == 0 and not first.timed_out)
    vec.check('init-output', info is not None and info['verb'] == b'initialized')
    vec.check('stderr-empty', first.err == b'')
    vec.check('port-ephemeral', low <= port <= high)
    vec.check('port-file', info is not None and files.get('port') == b'%d\n' % port)
    row = udp_row(port) if port else None
    vec.check('port-bound', row is not None and row['uid'] == os.geteuid() and row['inode'] in socket_inodes(pid) and not port_free(port))
    key_text = files.get('private_key', b'')
    key_ok = re.fullmatch(rb'[0-9a-f]{64}\n?', key_text) is not None
    vec.check('key-format', key_ok)
    ids_ok = all(re.fullmatch(rb'[0-9a-f]{32}', files.get(name, b'')) for name in ('node_id', 'cluster_id'))
    vec.check('id-format', info is not None and ids_ok and files['node_id'] == info['node'] and files['cluster_id'] == info['cluster']
              and info['node'] != info['cluster'])
    members = node.cluster('members')
    wanted = b'%s 127.0.0.1:%d\n' % (info['node'], port) if info else None
    vec.check('roster-single', info is not None and files.get('members') == wanted and members.out == wanted and members.rc == 0)
    vec.check('private-modes', private_tree(base))
    child = proc_stat(pid) if pid else None
    vec.check('listener-child', info is not None and pid != node.pid and child is not None and child['ppid'] == node.pid and alive(pid))
    status = node.cluster('status')
    vec.check('status-running', info is not None and status.rc == 0 and parse_status(status) == {
        'state': 'initialized', 'state_dir': str(base), 'cluster_id': info['cluster'].decode(), 'node_id': info['node'].decode(),
        'port': str(port), 'listener_pid': str(pid)})
    key = bytes.fromhex(key_text.decode().strip()) if key_ok else None
    wire = identity_on_wire(world, probe, key, port, info['cluster']) if key and info else None
    vec.check('identity-on-wire', wire is not None and wire['node'] == info['node'] and wire['cluster'] == info['cluster'] and wire['port'] == port)
    second = node.cluster('init', '-p', 0, env={'BASHCLUSTER_STATE_DIR': str(other)})
    info2 = parse_start(second)
    key2 = read_files(other).get('private_key', b'')
    vec.check('fresh-generation', info is not None and info2 is not None and info2['node'] != info['node'] and info2['cluster'] != info['cluster']
              and bool(key2) and key2 != key_text and info2['port'] != port)
    killed = False
    child = proc_stat(pid) if pid else None
    if info is not None and child is not None and child['ppid'] == node.pid:
        kill_pid(pid, 'seed-fresh listener')
        killed = world.reactor.wait(lambda: not alive(pid), 3.0)
    stopped = parse_status(node.cluster('status'))
    vec.check('stopped-after-kill', killed and stopped.get('state') == 'stopped' and stopped.get('listener_pid') == str(pid))


def v_seed_umask(world, vec):
    node = world.node('umask', CASE / 'umask-unused')
    results = {}
    for mask, name in ((0o000, 'zero'), (0o077, 'private')):
        directory = CASE / ('umask-' + name)
        node.call('umask %04o' % mask)
        call = node.cluster('init', '-p', 0, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        results[name] = (call.rc == 0 and parse_start(call) is not None, private_tree(directory))
        node.cluster('leave', env={'BASHCLUSTER_STATE_DIR': str(directory)})
    node.call('umask 0022')
    vec.check('zero-init', results['zero'][0])
    vec.check('zero-modes', results['zero'][1])
    vec.check('private-init', results['private'][0])
    vec.check('private-modes', results['private'][1])


# ---------------------------------------------------------------------------
# cluster/private-state-recovery (r1, r2, r4, r5, r6; r3 is the key-syntax scenario)
# ---------------------------------------------------------------------------

def v_state_refusals(world, vec):
    decoy = world.decoy('decoy')
    node = world.node('refuse', CASE / 'refuse-unused')
    keyfile = write_key(CASE / 'refuse.key', secret('refuse'))
    refused, untouched = [], []
    for mode in (0o755, 0o750, 0o705, 0o770, 0o777):
        directory = CASE / ('mode-%04o' % mode)
        os.mkdir(directory)
        os.chmod(directory, mode)
        before = stat.S_IMODE(os.lstat(directory).st_mode)
        call = node.cluster('init', '-p', 0, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        refused.append(call.rc == 1 and MSG_PRIVATE in call.err and call.out == b'')
        untouched.append(stat.S_IMODE(os.lstat(directory).st_mode) == before and listing(directory) == [])
    vec.check('modes-refused', all(refused))
    vec.check('modes-untouched', all(untouched))
    target, link = CASE / 'link-target', CASE / 'link-state'
    os.mkdir(target, 0o700)
    os.symlink(target, link)
    call = node.cluster('init', '-p', 0, env={'BASHCLUSTER_STATE_DIR': str(link)})
    vec.check('symlink-refused', call.rc == 1 and MSG_PRIVATE in call.err)
    vec.check('symlink-untouched', listing(target) == [] and os.path.islink(link))
    plain = CASE / 'file-state'
    plain.write_bytes(b'not a directory\n')
    call = node.cluster('init', '-p', 0, env={'BASHCLUSTER_STATE_DIR': str(plain)})
    vec.check('file-refused', call.rc == 1 and MSG_PRIVATE in call.err)
    vec.check('file-untouched', plain.read_bytes() == b'not a directory\n' and stat.S_ISREG(os.lstat(plain).st_mode))
    foreign = foreign_private_directory()
    before = os.lstat(foreign)
    trace('lstat', when='before', path=foreign, fields=[before.st_ino, before.st_mode, before.st_uid, before.st_mtime_ns])
    call = node.cluster('init', '-p', 0, env={'BASHCLUSTER_STATE_DIR': foreign})
    after = os.lstat(foreign)
    trace('lstat', when='after', path=foreign, fields=[after.st_ino, after.st_mode, after.st_uid, after.st_mtime_ns])
    vec.check('not-owned-refused', call.rc == 1 and MSG_PRIVATE in call.err)
    vec.check('not-owned-untouched', (before.st_ino, before.st_mode, before.st_uid, before.st_mtime_ns) == (after.st_ino, after.st_mode, after.st_uid, after.st_mtime_ns))
    wide = CASE / 'join-mode-0755'
    os.mkdir(wide)
    os.chmod(wide, 0o755)
    call = node.cluster('join', '127.0.0.1:%d' % decoy.port, '-k', keyfile, env={'BASHCLUSTER_STATE_DIR': str(wide)})
    world.reactor.pump(0.05)
    vec.check('join-refused', call.rc == 1 and MSG_PRIVATE in call.err and listing(wide) == [])
    vec.check('join-no-traffic', decoy.take() == [])
    vec.check('no-listener-started', node.children() == [])
    good = CASE / 'private-ok'
    os.mkdir(good, 0o700)
    baseline = make_unrelated(good)
    call = node.cluster('init', '-p', 0, '-k', keyfile, env={'BASHCLUSTER_STATE_DIR': str(good)})
    vec.check('private-accepted', call.rc == 0 and parse_start(call) is not None and 'cluster_id' in read_files(good) and unrelated_kept(good, baseline))


def v_state_atomic(world, vec):
    base = CASE / 'atomic'
    os.mkdir(base, 0o700)
    key = secret('atomic')
    keyfile = write_key(CASE / 'atomic.key', key)
    watch = world.inotify(base)
    node = world.node('atomic', base)
    probe = world.endpoint('probe')
    start = node.cluster('init', '-p', 0, '-k', keyfile)
    info = parse_start(start)
    events = watch.read()
    vec.check('init-status', start.rc == 0 and info is not None)
    if info is not None:
        # a roster change must replace the existing members file atomically, twice: a join and a leave by an owned probe node
        member = ident('atomic-probe')
        nonce = world.nonce()
        exchange(world, probe, info['port'], [build(key, JOIN, probe.port, ZERO32, member, nonce)], nonce)
        nonce = world.nonce()
        exchange(world, probe, info['port'], [build(key, LEAVE, probe.port, info['cluster'], member, nonce)], nonce)
        events += watch.read()
    report = atomic_report(events)
    shot = snapshot(base)
    vec.check('watch-captured', report['lock_created'] and report['all_state_files_renamed_in'])
    vec.check('final-names-by-rename', not report['inplace'] and report['all_state_files_renamed_in'])
    vec.check('scratch-then-rename', not report['order'] and bool(events))
    vec.check('no-scratch-left', not [name for name in shot if name.startswith('.') and name.endswith('.tmp')])
    vec.check('roster-replaced-atomically', report['renamed']['members'] >= 3 and not report['inplace'])
    vec.check('files-private', set(STATE_FILES) <= set(shot) and all(shot[name]['mode'] == 0o600 and shot[name]['kind'] == 'file' for name in STATE_FILES if name in shot))


def v_state_lock(world, vec):
    base = CASE / 'lock'
    first = Member(world, 'lock-first', 'lock', directory=base)
    probe = world.endpoint('probe')
    info = first.init()
    vec.check('first-started', first.last.rc == 0 and info is not None)
    before = snapshot(base)
    second = world.node('lock-second', base)
    refused = second.cluster('init', '-p', 0)
    again = first.node.cluster('init', '-p', 0)
    vec.check('second-shell-refused', refused.rc == 1 and MSG_LOCK in refused.err)
    vec.check('same-shell-refused', again.rc == 1 and MSG_LOCK in again.err)
    vec.check('state-unchanged', snapshot(base) == before)
    vec.check('first-listener-alive', info is not None and alive(first.pid))
    nonce, hit, _others = first.ping(probe)
    vec.check('first-listener-serves', info is not None and pong_ok(hit, first.key, nonce, first.cluster, first.node_id, first.port))
    vec.check('no-second-listener', info is not None and second.children() == [] and first.node.children() == [first.pid])


def v_lock_extras(world, vec):
    base = CASE / 'lockx'
    first = Member(world, 'lockx-first', 'lockx', directory=base)
    first.init()
    before = snapshot(base)
    second = world.node('lockx-second', base)
    duplicate = second.cluster('join', '127.0.0.1:%d' % first.port, '-k', first.keyfile)
    vec.check('duplicate-join-refused', first.info is not None and duplicate.rc == 1 and MSG_ALREADY in duplicate.err and snapshot(base) == before)
    collide = CASE / 'lockx-collide'
    third = world.node('lockx-third', collide)
    clash = third.cluster('init', '-p', first.port)
    names = listing(collide)
    vec.check('bind-collision-clean', first.info is not None and clash.rc == 1 and MSG_START in clash.err and names is not None and set(names) <= {'lock'}
              and alive(first.pid) and snapshot(base) == before)


def make_stale(world, label):
    """A state directory abandoned by a SIGKILLed listener: scratch leftovers, a forged listener_pid and unrelated files."""
    directory = CASE / label
    os.mkdir(directory, 0o700)
    baseline = make_unrelated(directory)
    member = Member(world, label, label, directory=directory)
    info = member.init()
    killed = kill_listener(world, member) if info else False
    sentinel = world.sentinel()
    (directory / '.members.tmp').write_bytes(b'partial')
    (directory / '.state.tmp').write_bytes(b'junk')
    (directory / '.cluster_id.tmp').write_bytes(b'junk')
    (directory / 'listener_pid').write_bytes(b'%d\n' % sentinel.pid)
    trace('forged-pid', pid=sentinel.pid, directory=str(directory))
    return member, info, killed, sentinel, baseline


def v_stale_leave(world, vec):
    member, old, killed, sentinel, baseline = make_stale(world, 'stale-leave')
    directory = member.directory
    vec.check('setup-stale', old is not None and killed and (directory / 'cluster_id').exists())
    fields = parse_status(member.node.cluster('status'))
    vec.check('stale-status-stopped', fields.get('state') == 'stopped' and old is not None and fields.get('cluster_id') == old['cluster'].decode())
    leave = member.node.cluster('leave')
    names = listing(directory) or []
    vec.check('leave-status', leave.rc == 0 and leave.out == b'left cluster\n')
    vec.check('state-files-removed', not set(STATE_FILES) & set(names))
    vec.check('scratch-removed', not set(SCRATCH_FILES) & set(names))
    vec.check('lock-and-unrelated-kept', 'lock' in names and unrelated_kept(directory, baseline))
    vec.check('forged-pid-not-signaled', sentinel.poll() is None)
    vec.check('status-uninitialized', member.status().get('state') == 'uninitialized')


def v_stale_init(world, vec):
    member, old, killed, sentinel, baseline = make_stale(world, 'stale-init')
    directory = member.directory
    probe = world.endpoint('probe')
    vec.check('setup-stale', old is not None and killed)
    again = member.node.cluster('init', '-p', 0, '-k', member.keyfile)
    new = parse_start(again)
    names = listing(directory) or []
    vec.check('init-status', again.rc == 0 and new is not None)
    vec.check('ids-regenerated', new is not None and old is not None and new['node'] != old['node'] and new['cluster'] != old['cluster'])
    vec.check('scratch-removed', not set(SCRATCH_FILES) & set(names))
    vec.check('unrelated-kept', unrelated_kept(directory, baseline))
    vec.check('forged-pid-not-signaled', sentinel.poll() is None)
    fields = member.status()
    vec.check('status-initialized', new is not None and fields.get('state') == 'initialized' and fields.get('listener_pid') == str(new['pid']))
    nonce, hit, _others = oracle_ping(world, probe, member.key, new['port'] if new else 0, new['cluster'] if new else ZERO32)
    vec.check('serves-after-recovery', new is not None and pong_ok(hit, member.key, nonce, new['cluster'], new['node'], new['port']))


def v_state_symlinks(world, vec):
    base = CASE / 'symlinks'
    os.mkdir(base, 0o700)
    precious = base / 'precious.txt'
    precious.write_bytes(b'precious\n')
    baseline = snapshot(base)
    for name in ('members', 'private_key', '.cluster_id.tmp'):
        os.symlink('precious.txt', base / name)
    member = Member(world, 'symlinks', 'symlinks', directory=base)
    info = member.init()
    shot = snapshot(base)
    vec.check('init-status', member.last.rc == 0 and info is not None)
    vec.check('target-unchanged', precious.read_bytes() == b'precious\n' and unrelated_kept(base, baseline))
    vec.check('names-replaced-by-files', shot.get('members', {}).get('kind') == 'file' and shot.get('private_key', {}).get('kind') == 'file'
              and read_files(base).get('private_key') == member.key.hex().encode())
    vec.check('scratch-link-removed', '.cluster_id.tmp' not in shot)


# ---------------------------------------------------------------------------
# cluster/private-state-recovery r3 (key-file syntax) and cluster/argument-and-timeout-validation
# ---------------------------------------------------------------------------

def put(name, data, mode=0o600):
    path = CASE / name
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


def v_keys_accepted(world, vec):
    probe = world.endpoint('probe')
    node = world.node('keys-ok', CASE / 'keys-ok-unused')
    items = []
    key = secret('k-plain')
    items.append(('plain', key, put('key-plain.txt', key.hex().encode()), False))
    key = secret('k-newline')
    items.append(('newline', key, put('key-newline.txt', key.hex().encode() + b'\n'), False))
    key = secret('k-symlink')
    real = put('key-symlink-real.txt', key.hex().encode())
    os.symlink(real, CASE / 'key-symlink.txt')
    items.append(('symlink', key, CASE / 'key-symlink.txt', False))
    items.append(('zeros', bytes(32), put('key-zeros.txt', bytes(32).hex().encode()), False))
    items.append(('ones', b'\xff' * 32, put('key-ones.txt', (b'\xff' * 32).hex().encode()), False))
    key = secret('k-readonly')
    items.append(('readonly', key, put('key-readonly.txt', key.hex().encode(), 0o400), False))
    key = secret('k-long')
    items.append(('long-options', key, put('key-long.txt', key.hex().encode()), True))
    accepted, canonical, pings, silent, trees = [], [], [], [], []
    for label, key, path, long_form in items:
        directory = CASE / ('keys-ok-' + label)
        args = ('--port', 0, '--key', path) if long_form else ('-p', 0, '-k', path)
        call = node.cluster('init', *args, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        info = parse_start(call)
        accepted.append(call.rc == 0 and info is not None)
        canonical.append(read_files(directory).get('private_key') == key.hex().encode())
        trees.append(private_tree(directory))
        if info is not None:
            wrong = key[:-1] + bytes([key[-1] ^ 1])
            bad = build(wrong, PING, probe.port, info['cluster'], ident('probe-bad'), world.nonce())
            nonce, hit, others = oracle_ping(world, probe, key, info['port'], info['cluster'], before=[bad])
            pings.append(pong_ok(hit, key, nonce, info['cluster'], info['node'], info['port']))
            silent.append(others == [])
        else:
            pings.append(False)
            silent.append(False)
        node.cluster('leave', env={'BASHCLUSTER_STATE_DIR': str(directory)})
    vec.check('all-accepted', all(accepted))
    vec.check('private-key-canonical', all(canonical))
    vec.check('oracle-ping-ok', all(pings))
    vec.check('wrong-key-silent', all(silent))
    vec.check('no-extra-state', all(trees))


def rejected_key_paths():
    good = secret('k-bad').hex().encode()
    fifo = CASE / 'key-fifo.txt'
    os.mkfifo(fifo, 0o600)
    folder = CASE / 'key-folder.txt'
    os.mkdir(folder)
    return [('short63', put('key-short63.txt', good[:63])), ('long65', put('key-long65.txt', good + b'0')),
            ('crlf', put('key-crlf.txt', good + b'\r\n')), ('trailing-space', put('key-space.txt', good + b' ')),
            ('uppercase', put('key-upper.txt', good.upper())), ('non-hex', put('key-nonhex.txt', good[:10] + b'g' + good[11:])),
            ('empty', put('key-empty.txt', b'')), ('two-newlines', put('key-two-newlines.txt', good + b'\n\n')),
            ('leading-space', put('key-leading-space.txt', b' ' + good[:63])), ('prefix-0x', put('key-prefix.txt', b'0x' + good[:62])),
            ('nul-inside', put('key-nul.txt', good[:20] + b'\0' + good[21:])), ('extra-line', put('key-extra-line.txt', good + b'\nabc')),
            ('huge', put('key-huge.txt', good * 64)), ('unreadable', put('key-unreadable.txt', good, 0o000)),
            ('directory', folder), ('fifo', fifo), ('missing', CASE / 'key-missing.txt'), ('character-device', Path('/dev/zero'))]


def v_keys_rejected(world, vec):
    node = world.node('keys-bad', CASE / 'keys-bad-unused')
    status, message, nostate, nolistener = [], [], [], []
    for label, path in rejected_key_paths():
        directory = CASE / ('keys-bad-' + label)
        call = node.cluster('init', '-p', 0, '-k', path, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        status.append(call.rc == 1 and not call.timed_out and call.out == b'')
        message.append(MSG_KEY in call.err)
        nostate.append(not directory.exists())
        nolistener.append(node.children() == [])
    vec.check('all-rejected', all(status))
    vec.check('message', all(message))
    vec.check('no-state', all(nostate))
    vec.check('no-listener', all(nolistener))


def v_keys_join(world, vec):
    decoy = world.decoy('decoy')
    node = world.node('keys-join', CASE / 'keys-join-unused')
    good = secret('k-join').hex().encode()
    folder = CASE / 'kj-folder'
    os.mkdir(folder)
    paths = [('short63', put('kj-short63.txt', good[:63])), ('uppercase', put('kj-upper.txt', good.upper())), ('directory', folder),
             ('missing', CASE / 'kj-missing.txt')]
    rejected, quiet = [], []
    for label, path in paths:
        directory = CASE / ('keys-join-' + label)
        call = node.cluster('join', '127.0.0.1:%d' % decoy.port, '-k', path, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        rejected.append(call.rc == 1 and MSG_KEY in call.err and not call.timed_out)
        quiet.append(not directory.exists() and node.children() == [])
    world.reactor.pump(0.05)
    vec.check('join-rejected', all(rejected))
    vec.check('join-no-network', all(quiet) and decoy.take() == [])


# ---------------------------------------------------------------------------
# cluster/argument-and-timeout-validation
# ---------------------------------------------------------------------------

def v_args_init(world, vec):
    node = world.node('args-init', CASE / 'args-init-unused')
    good = secret('args-init').hex().encode()
    bad_key = put('args-bad.key', b'z' * 64)
    unreadable = put('args-unreadable.key', good, 0o000)
    folder = CASE / 'args-dir.key'
    os.mkdir(folder)
    cases = [(['-p', '-1'], 2, False), (['-p', '65536'], 2, False), (['-p', '1x'], 2, False), (['-p', ''], 2, False), (['-p'], 2, False),
             (['-p', '99999999999999999999'], 2, False), (['--port', 'abc'], 2, False), (['--bad'], 2, False), (['extra'], 2, False),
             (['-k'], 2, False), (['-k', str(CASE / 'args-missing.key')], 1, True), (['-k', str(bad_key)], 1, True),
             (['-k', str(folder)], 1, True), (['-k', str(unreadable)], 1, True)]
    codes, nostate, nolistener, keyed = [], [], [], []
    for index, (args, expected, is_key) in enumerate(cases):
        directory = CASE / ('args-init-%d' % index)
        call = node.cluster('init', *args, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        codes.append(call.rc == expected and not call.timed_out and call.out == b'')
        nostate.append(not directory.exists())
        nolistener.append(node.children() == [])
        if is_key:
            keyed.append(MSG_KEY in call.err)
    for index, args in enumerate((['-p', '-1'], ['-p', '1x'], ['-k', str(bad_key)])):
        directory = CASE / ('args-init-precreated-%d' % index)
        os.mkdir(directory, 0o700)
        call = node.cluster('init', *args, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        codes.append(call.rc in (1, 2) and not call.timed_out)
        nostate.append(listing(directory) == [])
        nolistener.append(node.children() == [])
    vec.check('status-codes', all(codes))
    vec.check('no-state-written', all(nostate))
    vec.check('no-listener-started', all(nolistener))
    vec.check('key-message', all(keyed))


def v_args_join(world, vec):
    decoy = world.decoy('decoy')
    port = decoy.port
    node = world.node('args-join', CASE / 'args-join-unused')
    keyfile = write_key(CASE / 'args-join.key', secret('args-join'))
    cases = [([], 'endpoint'), (['127.0.0.2:%d' % port, '-k', keyfile], 'endpoint'), (['localhost:%d' % port, '-k', keyfile], 'endpoint'),
             (['127.0.0.1', '-k', keyfile], 'endpoint'), (['127.0.0.1:', '-k', keyfile], 'endpoint'), (['127.0.0.1:0', '-k', keyfile], 'endpoint'),
             (['127.0.0.1:65536', '-k', keyfile], 'endpoint'), (['127.0.0.1:12x', '-k', keyfile], 'endpoint'),
             (['[::1]:%d' % port, '-k', keyfile], 'endpoint'), (['10.0.0.1:%d' % port, '-k', keyfile], 'endpoint'),
             (['127.0.0.1:%d ' % port, '-k', keyfile], 'endpoint'), (['127.0.0.1:%d' % port], 'key'),
             (['127.0.0.1:%d' % port, '-k'], None), (['127.0.0.1:%d' % port, '-p', 'x', '-k', keyfile], None),
             (['127.0.0.1:%d' % port, 'extra', '-k', keyfile], None)]
    codes, endpoint, keyed, nostate, nolistener = [], [], [], [], []
    for index, (args, kind) in enumerate(cases):
        directory = CASE / ('args-join-%d' % index)
        call = node.cluster('join', *args, env={'BASHCLUSTER_STATE_DIR': str(directory)})
        codes.append(call.rc == 2 and not call.timed_out and call.out == b'')
        if kind == 'endpoint':
            endpoint.append(MSG_JOIN_ENDPOINT in call.err)
        if kind == 'key':
            keyed.append(MSG_JOIN_KEY in call.err)
        nostate.append(not directory.exists())
        nolistener.append(node.children() == [])
    world.reactor.pump(0.05)
    vec.check('status-codes', all(codes))
    vec.check('endpoint-message', bool(endpoint) and all(endpoint))
    vec.check('key-message', bool(keyed) and all(keyed))
    vec.check('no-state-written', all(nostate))
    vec.check('no-listener-started', all(nolistener))
    vec.check('no-network-traffic', decoy.take() == [])


def v_args_ping(world, vec):
    decoy = world.decoy('decoy')
    port = decoy.port
    member = Member(world, 'args-ping', 'args-ping')
    info = member.init()
    before = snapshot(member.directory)
    targets = ['127.0.0.2:%d' % port, 'localhost:%d' % port, '127.0.0.1', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:12x', '', 'x',
               '[::1]:%d' % port, ident('absent').decode(), member.node_id.decode().upper()]
    status, message = [], []
    for target in targets:
        call = member.node.cluster('ping', target)
        status.append(call.rc == 1 and not call.timed_out and call.out == b'')
        message.append(MSG_UNKNOWN + target.encode() in call.err)
    arity = [member.node.cluster('ping'), member.node.cluster('ping', 'a', 'b')]
    empty = world.node('args-ping-empty', CASE / 'args-ping-empty')
    nothing = empty.cluster('ping', '127.0.0.1:%d' % port)
    world.reactor.pump(0.05)
    vec.check('malformed-status', info is not None and all(status))
    vec.check('message', info is not None and all(message))
    vec.check('no-packets', decoy.take() == [])
    vec.check('arity-status', all(call.rc == 2 and not call.timed_out for call in arity))
    vec.check('uninitialized-status', nothing.rc == 1 and MSG_NO_MEMBERSHIP in nothing.err)
    vec.check('membership-unchanged', info is not None and snapshot(member.directory) == before and alive(member.pid))


def v_args_timeout(world, vec):
    decoy = world.decoy('silent')
    keyfile = write_key(CASE / 'timeout.key', secret('timeout'))
    node = world.node('timeout', CASE / 'timeout-unused')
    values = ['49', '5001', '0', '', 'abc', '+100', '-50', ' 100', '100 ', '1e2', '0x64', '4294967346', '00049']
    verbs = [('init', ['-p', '0']), ('join', ['127.0.0.1:%d' % decoy.port, '-k', str(keyfile)]), ('ping', ['127.0.0.1:%d' % decoy.port]),
             ('leave', []), ('status', []), ('members', [])]
    rejected, quiet, count = [], [], 0
    for verb, args in verbs:
        for value in values:
            count += 1
            directory = CASE / ('timeout-%d' % count)
            call = node.cluster(verb, *args, env={'BASHCLUSTER_STATE_DIR': str(directory), 'BASHCLUSTER_TIMEOUT_MS': value})
            rejected.append(call.rc == 1 and MSG_TIMEOUT in call.err and call.out == b'' and not call.timed_out)
            quiet.append(not directory.exists())
    world.reactor.pump(0.05)
    vec.check('invalid-rejected', all(rejected))
    vec.check('no-state-created', all(quiet))
    vec.check('no-listener-or-traffic', node.children() == [] and decoy.take() == [])
    live = Member(world, 'timeout-live', 'timeout-live')
    info = live.init()
    before = snapshot(live.directory)
    call = live.node.cluster('leave', env={'BASHCLUSTER_TIMEOUT_MS': '49'})
    vec.check('leave-rejection-harmless', info is not None and call.rc == 1 and MSG_TIMEOUT in call.err and snapshot(live.directory) == before
              and alive(live.pid))
    accepted = []
    for value in ('50', '5000', '0050', '05000', '00500'):
        directory = CASE / ('boundary-%s' % value)
        call = live.node.cluster('status', env={'BASHCLUSTER_TIMEOUT_MS': value, 'BASHCLUSTER_STATE_DIR': str(directory)})
        accepted.append(call.rc == 0 and call.out == b'state=uninitialized\nstate_dir=%s\n' % str(directory).encode())
    vec.check('boundaries-accepted', all(accepted))
    starts = []
    for value in ('50', '5000'):
        env = {'BASHCLUSTER_TIMEOUT_MS': value, 'BASHCLUSTER_STATE_DIR': str(CASE / ('boundary-init-%s' % value))}
        call = live.node.cluster('init', '-p', 0, env=env)
        started = parse_start(call)
        starts.append(call.rc == 0 and started is not None and alive(started['pid']))
        live.node.cluster('leave', env=env)
    vec.check('init-boundaries-start', all(starts))
    decoy.take()
    call = live.node.cluster('ping', '127.0.0.1:%d' % decoy.port, env={'BASHCLUSTER_TIMEOUT_MS': '50'})
    world.reactor.pump(0.05)
    vec.check('ping-boundary-protocol', call.rc == 1 and MSG_REQUEST_TIMEOUT in call.err and call.elapsed >= 0.048 and len(decoy.take()) == 1)


# ---------------------------------------------------------------------------
# cluster/authenticated-join
# ---------------------------------------------------------------------------

def v_join_seed_key(world, vec):
    probe = world.endpoint('probe')
    seed_dir, b_dir = CASE / 'join-seed', CASE / 'join-b'
    seed_node = world.node('join-seed', seed_dir, 400)
    start = seed_node.cluster('init', '-p', 0)
    info = parse_start(start)
    keyfile = seed_dir / 'private_key'
    key_text = read_files(seed_dir).get('private_key', b'')
    key = bytes.fromhex(key_text.decode()) if re.fullmatch(rb'[0-9a-f]{64}', key_text) else None
    vec.check('seed-started', start.rc == 0 and info is not None and key is not None)
    wire_a = identity_on_wire(world, probe, key, info['port'], info['cluster']) if key and info else None
    b_node = world.node('join-b', b_dir, 400)
    joined = b_node.cluster('join', '127.0.0.1:%d' % info['port'], '-k', keyfile) if info else None
    b_info = parse_start(joined)
    vec.check('join-status', joined is not None and joined.rc == 0 and not joined.timed_out)
    vec.check('join-output', b_info is not None and b_info['verb'] == b'joined' and joined.err == b'')
    wire_b = identity_on_wire(world, probe, key, b_info['port'], b_info['cluster']) if key and b_info else None
    vec.check('cluster-id-from-wire', wire_a is not None and wire_b is not None and b_info['cluster'] == wire_a['cluster'] == wire_b['cluster']
              and read_files(b_dir).get('cluster_id') == wire_a['cluster'])
    vec.check('nodes-distinct', wire_a is not None and wire_b is not None and wire_a['node'] != wire_b['node'] and wire_b['node'] == b_info['node']
              and wire_b['port'] == b_info['port'])
    vec.check('key-file-copied', bool(key_text) and read_files(b_dir).get('private_key') == key_text)
    expected = [(wire_a['node'], wire_a['port']), (wire_b['node'], wire_b['port'])] if wire_a and wire_b else None
    world.reactor.wait(lambda: expected is not None and parse_roster(read_files(seed_dir).get('members')) == expected
                       and parse_roster(read_files(b_dir).get('members')) == expected, 3.0)
    vec.check('rosters-agree', expected is not None and parse_roster(read_files(seed_dir).get('members')) == expected
              and parse_roster(read_files(b_dir).get('members')) == expected)
    a_members, b_members = seed_node.cluster('members'), b_node.cluster('members')
    vec.check('members-commands', expected is not None and a_members.rc == 0 and b_members.rc == 0 and parse_roster(a_members.out) == expected
              and parse_roster(b_members.out) == expected)
    rows, cluster, left = wire_roster(world, probe, key, info['port'], 'join') if key and info else (None, None, False)
    restored = world.reactor.wait(lambda: expected is not None and parse_roster(read_files(seed_dir).get('members')) == expected, 3.0)
    vec.check('wire-roster', expected is not None and rows is not None and len(rows) == 3 and rows[:2] == expected
              and rows[2] == (ident('wire-join'), probe.port) and left and cluster == info['cluster'] and restored)


def v_join_wrong_key(world, vec):
    probe = world.endpoint('probe')
    a = Member(world, 'jw-a', 'jw-a', timeout=400)
    a.init()
    b = Member(world, 'jw-b', 'jw-b', timeout=400)
    b.join(a)
    expected = [a.row(), b.row()]
    world.reactor.wait(lambda: a.roster() == expected and b.roster() == expected, 3.0)
    before = (snapshot(a.directory), snapshot(b.directory))
    runs = []
    for label, wrong in (('other-key', secret('jw-wrong')), ('near-key', a.key[:-1] + bytes([a.key[-1] ^ 1]))):
        path = write_key(CASE / ('jw-%s.key' % label), wrong)
        node = world.node('jw-c-' + label, CASE / ('jw-c-' + label), 400)
        runs.append((node, node.cluster('join', '127.0.0.1:%d' % a.port, '-k', path)))
    vec.check('join-rejected', len(runs) == 2 and all(call.rc == 1 and MSG_HANDSHAKE in call.err and call.out == b'' and not call.timed_out for _n, call in runs))
    vec.check('waited-timeout', all(0.398 <= call.elapsed <= 4.0 for _n, call in runs))
    vec.check('joiner-state-empty', all(set(listing(node.directory) or []) <= {'lock'} for node, _c in runs))
    vec.check('joiner-no-listener', all(node.children() == [] for node, _c in runs))
    vec.check('seed-roster-unchanged', a.info is not None and b.info is not None and a.roster() == expected and snapshot(a.directory) == before[0])
    vec.check('peer-roster-unchanged', b.roster() == expected and snapshot(b.directory) == before[1])
    nonce, hit, _others = a.ping(probe)
    vec.check('seed-still-serves', a.info is not None and pong_ok(hit, a.key, nonce, a.cluster, a.node_id, a.port))


def v_join_misuse(world, vec):
    a = Member(world, 'jm-a', 'jm-a', timeout=400)
    a.init()
    b = Member(world, 'jm-b', 'jm-b', timeout=400)
    b.join(a)
    expected = [a.row(), b.row()]
    world.reactor.wait(lambda: a.roster() == expected and b.roster() == expected, 3.0)
    before = (snapshot(a.directory), snapshot(b.directory), b.pid)
    again = b.node.cluster('join', '127.0.0.1:%d' % a.port, '-k', a.keyfile)
    vec.check('duplicate-refused', again.rc == 1 and MSG_ALREADY in again.err)
    vec.check('duplicate-unchanged', (snapshot(a.directory), snapshot(b.directory), b.pid) == before and alive(b.pid))
    d_dir = CASE / 'jm-d'
    d_node = world.node('jm-d', d_dir, 400)
    leaf = d_node.cluster('join', '127.0.0.1:%d' % b.port, '-k', a.keyfile)
    vec.check('leaf-join-rejected', leaf.rc == 1 and MSG_HANDSHAKE in leaf.err)
    vec.check('leaf-unchanged', a.roster() == expected and b.roster() == expected and set(listing(d_dir) or []) <= {'lock'} and d_node.children() == [])


# ---------------------------------------------------------------------------
# cluster/ping-protocol
# ---------------------------------------------------------------------------

PING_MODES = ('silent', 'garbage', 'short', 'long', 'wrong-key', 'wrong-nonce', 'wrong-type', 'bad-magic', 'count33', 'other-port')


def v_ping_resolution(world, vec):
    key = secret('ping')
    cluster, own, own_port = ident('ping-cluster'), ident('ping-self'), free_port()
    peer = Peer(world, 'peer', key, cluster, ident('ping-peer'), 'echo', client=(cluster, own, own_port))
    craft_state(CASE / 'ping-state', cluster, own, own_port, key, [(own, own_port), (peer.node, peer.port)])
    shell = world.node('ping', CASE / 'ping-state', 300)
    by_node, by_endpoint = [], []
    for _ in range(3):
        by_node.append(shell.cluster('ping', peer.node.decode()))
        by_endpoint.append(shell.cluster('ping', '127.0.0.1:%d' % peer.port))
    world.reactor.pump(0.05)
    endpoint = b'127.0.0.1:%d' % peer.port
    vec.check('by-node', all(c.rc == 0 and c.out == b'ok %s\n' % peer.node and c.err == b'' for c in by_node))
    vec.check('by-endpoint', all(c.rc == 0 and c.out == b'ok %s\n' % endpoint and c.err == b'' for c in by_endpoint))
    checks = [r['checks'] for r in peer.requests]
    vec.check('requests-received', len(checks) == 6)
    vec.check('request-size', bool(checks) and all(c['size'] for c in checks))
    vec.check('request-header', bool(checks) and all(c['magic'] and c['type'] and c['count'] for c in checks))
    vec.check('request-identity', bool(checks) and all(c['cluster'] and c['node'] and c['port'] for c in checks))
    vec.check('request-rows-zero', bool(checks) and all(c['rows_zero'] for c in checks))
    vec.check('request-mac', bool(checks) and all(c['mac'] for c in checks))
    nonces = [q['nonce'] for q in (parse(bytes.fromhex(r['raw'])) for r in peer.requests) if q is not None]
    vec.check('nonces-fresh', len(nonces) == 6 and len(set(nonces)) == 6 and all(n != bytes(16) for n in nonces))
    vec.check('request-source', len(peer.requests) == 6 and all(r['from'][0] == '127.0.0.1' and r['from'][1] not in (peer.port, own_port) for r in peer.requests))


def v_ping_unknown(world, vec):
    key = secret('ping-unknown')
    cluster, own = ident('pu-cluster'), ident('pu-self')
    mine = world.decoy('self')
    peer = Peer(world, 'peer', key, cluster, ident('pu-peer'), 'echo', client=(cluster, own, mine.port))
    craft_state(CASE / 'pu-state', cluster, own, mine.port, key, [(own, mine.port), (peer.node, peer.port)])
    shell = world.node('pu', CASE / 'pu-state', 300)
    targets = [ident('pu-unknown-1').decode(), ident('pu-unknown-2').decode(), peer.node.decode().upper()]
    calls = [shell.cluster('ping', target) for target in targets]
    world.reactor.pump(0.05)
    vec.check('status', all(c.rc == 1 and c.out == b'' and not c.timed_out for c in calls))
    vec.check('message', all(MSG_UNKNOWN + t.encode() in c.err for t, c in zip(targets, calls)))
    vec.check('nothing-sent', peer.requests == [] and mine.take() == [])


def v_ping_nonprotocol(world, vec):
    key = secret('ping-np')
    cluster, own, own_port = ident('np-cluster'), ident('np-self'), free_port()
    craft_state(CASE / 'np-state', cluster, own, own_port, key, [(own, own_port)])
    shell = world.node('np', CASE / 'np-state', 300)
    failed, waited, bounded, single = [], [], [], []
    for mode in PING_MODES + ('wrong-cluster',):
        peer = Peer(world, 'np-' + mode, key, cluster, ident('np-peer-' + mode), mode, client=(cluster, own, own_port))
        target = '127.0.0.1:%d' % peer.port
        call = shell.cluster('ping', target)
        world.reactor.pump(0.02)
        failed.append(call.rc == 1 and MSG_REQUEST_TIMEOUT + target.encode() in call.err and call.out == b'' and not call.timed_out)
        if mode != 'wrong-cluster':
            waited.append(call.elapsed >= 0.298)
        bounded.append(call.elapsed <= 2.3)
        single.append(len(peer.requests) == 1 and len(peer.valid_requests()) == 1)
    good = Peer(world, 'np-echo', key, cluster, ident('np-peer-echo'), 'echo', client=(cluster, own, own_port))
    control = shell.cluster('ping', '127.0.0.1:%d' % good.port)
    silent = Peer(world, 'np-silent-2', key, cluster, ident('np-peer-silent-2'), 'silent', client=(cluster, own, own_port))
    target = '127.0.0.1:%d' % silent.port
    slow = shell.cluster('ping', target, env={'BASHCLUSTER_TIMEOUT_MS': '1000'})
    fast = shell.cluster('ping', target, env={'BASHCLUSTER_TIMEOUT_MS': '50'})
    vec.check('all-fail', all(failed))
    vec.check('waits-deadline', all(waited))
    vec.check('bounded', all(bounded))
    vec.check('one-valid-request', all(single))
    vec.check('echo-control', control.rc == 0 and control.out == b'ok 127.0.0.1:%d\n' % good.port)
    vec.check('deadline-follows', 0.998 <= slow.elapsed <= 3.0 and 0.048 <= fast.elapsed <= 1.5)


def v_ping_live(world, vec):
    probe = world.endpoint('probe')
    member = Member(world, 'ping-live', 'ping-live')
    member.init()
    by_node = member.node.cluster('ping', member.node_id.decode())
    by_endpoint = member.node.cluster('ping', '127.0.0.1:%d' % member.port)
    vec.check('ping-by-node', member.info is not None and by_node.rc == 0 and by_node.out == b'ok %s\n' % member.node_id)
    vec.check('ping-by-endpoint', member.info is not None and by_endpoint.rc == 0 and by_endpoint.out == b'ok 127.0.0.1:%d\n' % member.port)
    nonce, hit, others = member.ping(probe)
    vec.check('listener-pong-valid', member.info is not None and hit is not None and len(hit[1]) == SIZE and others == []
              and pong_ok(hit, member.key, nonce, member.cluster, member.node_id, member.port))
    q = parse(hit[1]) if hit is not None else None
    vec.check('pong-identity', q is not None and q['node'] == member.node_id and q['cluster'] == member.cluster and q['port'] == member.port
              and q['nonce'] == nonce and q['rows'] == [] and q['type'] == PONG)


# ---------------------------------------------------------------------------
# cluster/packet-rejection
# ---------------------------------------------------------------------------

def drained(world, member, timeout=3.0):
    return world.reactor.wait(lambda: (udp_row(member.port) or {'rx': 1})['rx'] == 0, timeout)


def flood(world, probe, member, packets):
    """Inject datagrams with flow control: the listener's receive queue is empty before more big ones are queued."""
    for index, data in enumerate(packets):
        probe.send(data, member.port)
        if len(data) > 4096 or index % 8 == 7:
            drained(world, member)
    drained(world, member)


def settle(world, probe, member):
    """Barrier: a valid PING after the injected datagrams; returns (PONG valid, replies to anything else)."""
    nonce, hit, others = member.ping(probe)
    return pong_ok(hit, member.key, nonce, member.cluster, member.node_id, member.port), others


def packets_size(world, member, probe):
    valid = build(member.key, PING, probe.port, member.cluster, ident('pr-size'), world.nonce())
    return [b'', b'\x00', MAGIC, valid[:600], valid[:MAC_AT], valid[:-1], valid + b'X', valid + bytes(100), valid * 2, bytes(4096), bytes(65507)]


def packets_format(world, member, probe):
    node = ident('pr-format')
    signed = [build(member.key, PING, probe.port, member.cluster, node, world.nonce(), magic=magic)
              for magic in (b'BCLSTR1\0', b'BCLSTR2\x01', b'bclstr2\0', bytes(8), b'BCLSTR2 ')]
    return signed + [bytes(SIZE), (hashlib.sha256(b'cluster-followup-garbage').digest() * 38)[:SIZE]]


def packets_mac(world, member, probe):
    key, node, nonce = member.key, ident('pr-mac'), world.nonce()
    base = build(key, PING, probe.port, member.cluster, node, nonce)
    body = base[:MAC_AT]
    near = key[:-1] + bytes([key[-1] ^ 1])
    return [build(secret('pr-other-key'), PING, probe.port, member.cluster, node, nonce), build(near, PING, probe.port, member.cluster, node, nonce),
            flip(base, SIZE - 1), flip(base, MAC_AT), body + bytes(32), flip(base, 10), flip(base, 60), flip(base, 12),
            body + hashlib.blake2b(body, digest_size=32).digest(), body + hashlib.blake2b(body, key=key, digest_size=64).digest()[:32]]


def packets_count_node(world, member, probe):
    key, cluster, port = member.key, member.cluster, probe.port
    node = ident('pr-count')
    out = [build(key, PING, port, cluster, node, world.nonce(), count=count) for count in (33, 34, 64, 128, 255)]
    out += [build(key, kind, port, cluster, node, world.nonce(), count=count) for count in (1, 5, 32) for kind in (PING, JOIN, BEAT)]
    bad_ids = (b'A' * 32, b'g' * 32, b'1' * 31 + b'\0', bytes(32), b'\xff' * 32, b'0' * 31 + b'G')
    out += [build(key, kind, port, cluster, bad, world.nonce()) for kind in (PING, JOIN, BEAT) for bad in bad_ids]
    return out


def violation_vector(world, vec, label, builder):
    probe = world.endpoint('probe')
    member = Member(world, 'pr-' + label, 'pr-' + label)
    info = member.init()
    before = read_files(member.directory).get('members')
    if info is not None:
        flood(world, probe, member, builder(world, member, probe))
    ok, others = settle(world, probe, member)
    vec.check('rejected-silently', info is not None and others == [])
    vec.check('roster-unchanged', info is not None and parse_roster(before) == [member.row()] and read_files(member.directory).get('members') == before)
    vec.check('later-ping-ok', info is not None and ok)
    row = udp_row(member.port)
    drops = row['drops'] if row else -1
    vec.check('no-queue-drops', drops == 0)
    if drops > 0:
        raise FixtureError('the listener receive queue dropped %s datagram(s): the flood outran the flow control' % drops)


def v_packets_size(world, vec):
    violation_vector(world, vec, 'size', packets_size)


def v_packets_format(world, vec):
    violation_vector(world, vec, 'format', packets_format)


def v_packets_mac(world, vec):
    violation_vector(world, vec, 'mac', packets_mac)


def v_packets_count_node(world, vec):
    violation_vector(world, vec, 'count-node', packets_count_node)


def v_packets_baseline(world, vec):
    probe = world.endpoint('probe')
    member = Member(world, 'pb', 'pb')
    info = member.init()
    vec.check('seed-up', info is not None and member.last.rc == 0 and member.roster() == [member.row()])
    nonce, hit, others = member.ping(probe)
    vec.check('ping-answered', hit is not None and others == [])
    vec.check('ping-reply-valid', pong_ok(hit, member.key, nonce, member.cluster, member.node_id, member.port))
    node, join_nonce = ident('pb-joiner'), world.nonce()
    joined, _others = exchange(world, probe, member.port, [build(member.key, JOIN, probe.port, ZERO32, node, join_nonce)], join_nonce)
    expected = [member.row(), (node, probe.port)]
    q = parse(joined[1]) if joined is not None else None
    vec.check('join-accepted', q is not None and q['type'] == ROSTER)
    vec.check('join-reply-valid', joined is not None and valid_reply(joined[1], member.key, ROSTER, join_nonce, member.cluster, member.node_id, member.port, expected))
    vec.check('member-visible', wait_roster(world, member, expected, 2.0))
    leave_nonce = world.nonce()
    left, _others = exchange(world, probe, member.port, [build(member.key, LEAVE, probe.port, member.cluster, node, leave_nonce)], leave_nonce)
    vec.check('leave-restores', left is not None and pong_ok(left, member.key, leave_nonce, member.cluster, member.node_id, member.port)
              and wait_roster(world, member, [member.row()], 2.0))


def v_packets_types(world, vec):
    probe = world.endpoint('probe')
    member = Member(world, 'pt', 'pt')
    info = member.init()
    before = read_files(member.directory).get('members')
    node, sent = ident('pt-node'), {}
    packets = []
    for kind in (0, 9, 255, ROSTER, PONG, ERROR, STOP):
        nonce = world.nonce()
        sent[nonce] = kind
        packets.append(build(member.key, kind, probe.port, member.cluster, node, nonce))
    if info is not None:
        flood(world, probe, member, packets)
    ok, others = settle(world, probe, member)
    replies = [parse(entry[1]) for entry in others]
    vec.check('no-member', info is not None and read_files(member.directory).get('members') == before and parse_roster(before) == [member.row()])
    vec.check('replies-authenticated-or-none', info is not None and all(
        q is not None and q['type'] == ERROR and q['count'] == 0 and q['nonce'] in sent and q['cluster'] == member.cluster for q in replies)
              and all(mac_ok(member.key, entry[1]) for entry in others))
    vec.check('later-ping-ok', info is not None and ok and alive(member.pid))


def v_packets_identity(world, vec):
    first, second = world.endpoint('first'), world.endpoint('second')
    member = Member(world, 'pi', 'pi')
    info = member.init()
    n1, n3, nx = ident('pi-one'), ident('pi-three'), ident('pi-x')
    one = [member.row(), (n1, first.port)]
    nonce = world.nonce()
    joined, _others = exchange(world, first, member.port, [build(member.key, JOIN, first.port, ZERO32, n1, nonce)], nonce)
    q = parse(joined[1]) if joined is not None else None
    vec.check('member-added', info is not None and q is not None and q['type'] == ROSTER and wait_roster(world, member, one, 2.0))

    def ignored(endpoint, packet):
        nonce, hit, extra = oracle_ping(world, endpoint, member.key, member.port, member.cluster, before=[packet])
        return info is not None and pong_ok(hit, member.key, nonce, member.cluster) and extra == [] and member.roster() == one

    wrong_port = first.port + 1 if first.port < 65535 else first.port - 1
    vec.check('source-port-mismatch-ignored', ignored(first, build(member.key, JOIN, wrong_port, ZERO32, nx, world.nonce())))
    vec.check('seed-identity-ignored', ignored(first, build(member.key, JOIN, first.port, ZERO32, member.node_id, world.nonce())))
    vec.check('moved-endpoint-ignored', ignored(second, build(member.key, BEAT, second.port, member.cluster, n1, world.nonce())))
    vec.check('duplicate-port-ignored', ignored(first, build(member.key, JOIN, first.port, ZERO32, n3, world.nonce())))
    leave_nonce = world.nonce()
    left, _others = exchange(world, first, member.port, [build(member.key, LEAVE, first.port, member.cluster, n1, leave_nonce)], leave_nonce)
    vec.check('roster-as-expected', info is not None and left is not None and wait_roster(world, member, [member.row()], 2.0))


def v_packets_combined(world, vec):
    probe = world.endpoint('probe')
    member = Member(world, 'pc', 'pc')
    info = member.init()
    before = snapshot(member.directory)
    pid = member.pid
    batches = [packets_size(world, member, probe), packets_format(world, member, probe), packets_mac(world, member, probe),
               packets_count_node(world, member, probe)]
    for packets in batches:
        if info is not None:
            flood(world, probe, member, packets)
    ok, others = settle(world, probe, member)
    row = udp_row(member.port)
    vec.check('all-silent', info is not None and others == [])
    vec.check('roster-unchanged', info is not None and member.roster() == [member.row()])
    vec.check('files-unchanged', info is not None and snapshot(member.directory) == before)
    vec.check('listener-alive', info is not None and alive(pid) and row is not None and row['drops'] == 0)
    own = member.node.cluster('ping', '127.0.0.1:%d' % member.port)
    vec.check('candidate-ping-ok', info is not None and own.rc == 0 and own.out == b'ok 127.0.0.1:%d\n' % member.port)
    vec.check('oracle-ping-ok', info is not None and ok)


# ---------------------------------------------------------------------------
# cluster/leave-and-owner-lifecycle
# ---------------------------------------------------------------------------

def v_leave_state(world, vec):
    base = CASE / 'leave-state'
    os.mkdir(base, 0o700)
    baseline = make_unrelated(base)
    member = Member(world, 'leave-state', 'leave-state', directory=base)
    info = member.init()
    port, pid = member.port, member.pid
    leave = member.node.cluster('leave')
    names = listing(base) or []
    vec.check('leave-status', info is not None and leave.rc == 0 and leave.out == b'left cluster\n' and leave.err == b'')
    vec.check('state-files-removed', not set(STATE_FILES) & set(names) and not set(SCRATCH_FILES) & set(names))
    vec.check('lock-kept', 'lock' in names)
    vec.check('unrelated-preserved', unrelated_kept(base, baseline))
    gone = bool(pid) and world.reactor.wait(lambda: not alive(pid), 3.0)
    vec.check('listener-gone', info is not None and gone and world.reactor.wait(lambda: port_free(port), 3.0))
    vec.check('status-after', parse_status(member.node.cluster('status')) == {'state': 'uninitialized', 'state_dir': str(base)})
    repeats = [member.node.cluster('leave') for _ in range(2)]
    later = listing(base) or []
    vec.check('repeat-leave', all(c.rc == 0 and c.out == b'left cluster\n' for c in repeats) and not set(STATE_FILES) & set(later)
              and unrelated_kept(base, baseline))
    never = world.node('leave-never', CASE / 'leave-never')
    call = never.cluster('leave')
    vec.check('never-initialized-leave', call.rc == 0 and call.out == b'left cluster\n' and not (CASE / 'leave-never').exists())


def v_leave_drops(world, vec):
    a = Member(world, 'ld-a', 'ld', timeout=2000)
    a.init()
    b = Member(world, 'ld-b', 'ld', timeout=2000)
    b.join(a)
    expected = [a.row(), b.row()]
    wait_roster(world, a, expected, 5.0)
    wait_roster(world, b, expected, 5.0)
    started = time.monotonic()
    leave = b.node.cluster('leave')
    dropped = world.reactor.wait(lambda: a.roster() == [a.row()], 4.0)
    seen = time.monotonic()
    vec.check('peer-left-status', a.info is not None and b.info is not None and leave.rc == 0 and leave.out == b'left cluster\n')
    vec.check('seed-dropped-member', dropped)
    vec.check('dropped-by-notice-not-expiry', dropped and seen - started < 3.0)
    vec.check('peer-state-removed', not set(STATE_FILES) & set(listing(b.directory) or []))
    vec.check('seed-listener-alive', a.info is not None and alive(a.pid) and a.status().get('state') == 'initialized')


def stop_owner(world, member, how):
    """End the owning shell either way: EOF after exit, or SIGKILL of the fixture's own shell; wait until it is reaped."""
    if how == 'exit':
        try:
            member.node.proc.stdin.write(b'exit\n')
            member.node.proc.stdin.flush()
            member.node.proc.stdin.close()
        except (OSError, ValueError):
            pass
    else:
        kill_pid(member.node.pid, 'owning shell')
    return world.reactor.wait(lambda: member.node.proc.poll() is not None, 3.0)


def v_owner_exit(world, vec):
    outcome = {}
    for how in ('exit', 'kill'):
        base = CASE / ('owner-' + how)
        os.mkdir(base, 0o700)
        baseline = make_unrelated(base)
        member = Member(world, 'owner-' + how, 'owner', directory=base)
        info = member.init()
        pid, port = member.pid, member.port
        child = proc_stat(pid) if pid else None
        held = info is not None and child is not None and child['ppid'] == member.node.pid and not port_free(port)
        ended = stop_owner(world, member, how)
        gone = bool(pid) and world.reactor.wait(lambda: not alive(pid), 3.0)
        released = bool(port) and world.reactor.wait(lambda: port_free(port), 3.0)
        names = listing(base) or []
        check = world.node('owner-check-' + how, base)
        outcome[how] = (held and ended and gone, released, not set(STATE_FILES) & set(names) and not set(SCRATCH_FILES) & set(names),
                        'lock' in names and unrelated_kept(base, baseline), check.cluster('status').out == b'state=uninitialized\nstate_dir=%s\n' % str(base).encode())
    vec.check('exit-listener-gone', outcome['exit'][0])
    vec.check('exit-port-released', outcome['exit'][1])
    vec.check('exit-state-cleaned', outcome['exit'][2])
    vec.check('exit-unrelated-kept', outcome['exit'][3])
    vec.check('exit-uninitialized', outcome['exit'][4])
    vec.check('kill-listener-gone', outcome['kill'][0])
    vec.check('kill-port-released', outcome['kill'][1])
    vec.check('kill-state-cleaned', outcome['kill'][2])
    vec.check('kill-unrelated-kept', outcome['kill'][3])
    vec.check('kill-uninitialized', outcome['kill'][4])
    a = Member(world, 'owner-seed', 'owner', timeout=2000)
    a.init()
    b = Member(world, 'owner-peer', 'owner', timeout=2000)
    b.join(a)
    expected = [a.row(), b.row()]
    wait_roster(world, a, expected, 5.0)
    pid = b.pid
    ended = stop_owner(world, b, 'kill')
    dropped = world.reactor.wait(lambda: a.roster() == [a.row()], 4.0)
    vec.check('peer-owner-death-notifies-seed', a.info is not None and b.info is not None and ended and dropped
              and world.reactor.wait(lambda: not alive(pid), 3.0))


# ---------------------------------------------------------------------------
# cluster/roster-heartbeats
# ---------------------------------------------------------------------------

def rows_of(member):
    return member.roster() or []


def v_roster_convergence(world, vec):
    probe = world.endpoint('probe')
    a, b, c = (Member(world, 'rc-' + name, 'rc', timeout=400) for name in 'abc')
    a.init()
    b.join(a)
    c.join(a)
    vec.check('joins-ok', all(m.info is not None and m.last.rc == 0 for m in (a, b, c)))
    wires = [m.wire_identity(probe) for m in (a, b, c)]
    expected = [(w['node'], w['port']) for w in wires] if all(wires) else None
    vec.check('identities-on-wire', expected is not None and len({w['cluster'] for w in wires}) == 1 and len({w['node'] for w in wires}) == 3)
    vec.check('rosters-converge', expected is not None and world.reactor.wait(lambda: all(m.roster() == expected for m in (a, b, c)), 5.0))
    outs = [m.node.cluster('members') for m in (a, b, c)]
    vec.check('members-commands-agree', expected is not None and all(o.rc == 0 and parse_roster(o.out) == expected for o in outs))
    leave = c.node.cluster('leave')
    survivors = expected[:2] if expected else None
    vec.check('c-left-status', leave.rc == 0 and leave.out == b'left cluster\n')
    vec.check('leave-removed-everywhere', survivors is not None and world.reactor.wait(lambda: a.roster() == survivors and b.roster() == survivors, 4.0))
    vec.check('survivors-intact', a.info is not None and b.info is not None and alive(a.pid) and alive(b.pid)
              and a.status().get('state') == 'initialized' and b.status().get('state') == 'initialized')
    vec.check('c-state-cleaned', not set(STATE_FILES) & set(listing(c.directory) or []))


def v_roster_expiry(world, vec):
    period = 400
    a = Member(world, 're-a', 're', timeout=period)
    a.init()
    b = Member(world, 're-b', 're', timeout=period)
    b.join(a)
    c = Member(world, 're-c', 're', timeout=period)
    c.join(a)
    silent, beating = world.endpoint('silent'), world.endpoint('beating')
    silent_node, beating_node = ident('re-silent'), ident('re-beating')

    def join(endpoint, node):
        nonce = world.nonce()
        sent = time.monotonic()
        hit, _others = exchange(world, endpoint, a.port, [build(a.key, JOIN, endpoint.port, ZERO32, node, nonce)], nonce)
        q = parse(hit[1]) if hit is not None else None
        return sent, q is not None and q['type'] == ROSTER

    t_silent, silent_in = join(silent, silent_node)
    t_beat, beating_in = join(beating, beating_node)
    vec.check('oracles-joined', all(m.info is not None for m in (a, b, c)) and silent_in and beating_in)
    expiry = 3 * period / 1000.0
    beat_every, stop_beating = period / 2000.0, t_beat + 5 * period / 1000.0
    next_beat, last_beat = t_beat + beat_every, t_beat
    silent_gone = beating_gone = None
    present, early = True, False
    end = stop_beating + expiry + 3.0
    while time.monotonic() < end and (silent_gone is None or beating_gone is None):
        now = time.monotonic()
        if next_beat <= now < stop_beating:
            beating.send(build(a.key, BEAT, beating.port, a.cluster, beating_node, world.nonce()), a.port)
            last_beat, next_beat = now, next_beat + beat_every
        beating.take()
        world.reactor.pump(0.01)
        nodes = {row[0] for row in rows_of(a)}
        if b.node_id not in nodes or c.node_id not in nodes:
            present = False
        if silent_gone is None and silent_node not in nodes:
            silent_gone = now
        if beating_node not in nodes and beating_gone is None:
            beating_gone = now
            early = now < stop_beating
    slack = period / 4000.0 + 1.5
    vec.check('silent-expires-not-early', silent_gone is not None and silent_gone - t_silent >= expiry - 0.002)
    vec.check('silent-expires-in-bound', silent_gone is not None and silent_gone - t_silent <= expiry + slack)
    vec.check('beating-oracle-retained', silent_gone is not None and not early and (beating_gone is None or beating_gone - silent_gone > 2 * period / 1000.0))
    vec.check('beating-peers-retained', present and alive(b.pid) and alive(c.pid))
    vec.check('retention-ends-after-last-beat', beating_gone is not None and expiry - 0.002 <= beating_gone - last_beat <= expiry + slack)
    gone = lambda m: world.reactor.wait(lambda: not {silent_node, beating_node} & {row[0] for row in rows_of(m)}, 2.0)
    vec.check('expiry-propagates-to-peers', silent_gone is not None and gone(b) and gone(c))


def v_roster_seed_loss(world, vec):
    period = 400
    a = Member(world, 'sl-a', 'sl', timeout=period)
    a.init()
    b = Member(world, 'sl-b', 'sl', timeout=period)
    b.join(a)
    expected = [a.row(), b.row()]
    vec.check('peers-joined', a.info is not None and b.info is not None and wait_roster(world, b, expected, 5.0))
    leave = a.node.cluster('leave')
    vec.check('seed-left-status', leave.rc == 0 and leave.out == b'left cluster\n')
    disconnected = world.reactor.wait(lambda: read_files(b.directory).get('state') == b'disconnected\n', 3 * period / 1000.0 + period / 4000.0 + 3.0)
    vec.check('leaf-disconnected', disconnected and b.status().get('state') == 'disconnected')
    vec.check('leaf-roster-self-only', b.roster() == [b.row()])
    vec.check('leaf-listener-alive', alive(b.pid) and b.status().get('listener_pid') == str(b.pid))
    killed = kill_listener(world, b)
    vec.check('leaf-stopped-after-kill', killed and b.status().get('state') == 'stopped')


# ---------------------------------------------------------------------------
# control: the documented behavior of the verbs that need no peers
# ---------------------------------------------------------------------------

def v_control_candidate(world, vec):
    base = CASE / 'control-state'
    node = world.node('control', base)
    typed = node.call('type -t cluster')
    version, extra, bare = node.cluster('--version'), node.cluster('--version', 'x'), node.cluster()
    unknown, status, members, leave = node.cluster('bogus'), node.cluster('status'), node.cluster('members'), node.cluster('leave')
    vec.check('builtin', typed.rc == 0 and typed.out == b'builtin\n')
    vec.check('version', version.rc == 0 and version.out == b'cluster 2.0 (bash-loadable)\n' and extra.rc == 2)
    vec.check('usage-no-verb', bare.rc == 2)
    vec.check('unknown-verb', unknown.rc == 2 and b'cluster: unknown verb: bogus' in unknown.err)
    vec.check('status-uninitialized', status.rc == 0 and parse_status(status) == {'state': 'uninitialized', 'state_dir': str(base)})
    vec.check('members-empty', members.rc == 0 and members.out == b'')
    vec.check('leave-uninitialized', leave.rc == 0 and leave.out == b'left cluster\n')


# ---------------------------------------------------------------------------
# Controls: the oracle and the process driver are validated without the candidate (failure = invalid evidence).
# ---------------------------------------------------------------------------

ABC512 = ('ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923')
ABC256 = 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'
EMPTY256 = '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'
KEYED512 = ('10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568')


def control_guest():
    set_subreaper()
    low, high = ephemeral_range()
    problems = []
    if os.geteuid() != 2000:
        problems.append('not uid 2000')
    if not 1024 <= low < high <= 65535:
        problems.append('implausible ephemeral port range %d-%d' % (low, high))
    if udp_rows() is None:
        problems.append('no UDP table')
    if SIZE != 1212 or ROWS_AT != 92 or MAC_AT != 1180:
        problems.append('packet geometry')
    return not problems, problems or 'uid 2000, subreaper set, ephemeral ports %d-%d, packet %d bytes' % (low, high, SIZE)


def control_kat():
    key = secret('kat')
    checks = {'rfc7693-abc-512': hashlib.blake2b(b'abc').hexdigest() == ABC512, 'abc-256': hashlib.blake2b(b'abc', digest_size=32).hexdigest() == ABC256,
              'empty-256': hashlib.blake2b(b'', digest_size=32).hexdigest() == EMPTY256,
              'keyed-512': hashlib.blake2b(b'', key=bytes(range(64)), digest_size=64).hexdigest() == KEYED512,
              'keyed-differs-from-unkeyed': mac(key, b'abc') != hashlib.blake2b(b'abc', digest_size=32).digest(),
              'mac-is-keyed-256': mac(key, b'abc') == hashlib.blake2b(b'abc', key=key, digest_size=32).digest() and len(mac(key, b'abc')) == 32}
    failed = [name for name, ok in checks.items() if not ok]
    return not failed, failed or 'BLAKE2b known answers hold'


def control_codec():
    key, cluster, node, nonce = secret('codec'), ident('codec-cluster'), ident('codec-node'), bytes(range(16))
    packet = build(key, PING, 1234, cluster, node, nonce)
    q = parse(packet)
    rows = [(ident('codec-row-%d' % i), 1000 + i) for i in range(32)]
    full = parse(build(key, ROSTER, 4321, cluster, node, nonce, rows=rows))
    ok = {'size': len(packet) == SIZE == 1212 and packet[:8] == b'BCLSTR2\0',
          'fields': q is not None and (q['type'], q['count'], q['port'], q['nonce'], q['cluster'], q['node']) == (PING, 0, 1234, nonce, cluster, node),
          'mac': mac_ok(key, packet) and not mac_ok(secret('codec-other'), packet) and not mac_ok(key, flip(packet, 3)) and not mac_ok(key, flip(packet, SIZE - 1)),
          'rows': full is not None and full['rows'] == rows and full['count'] == 32 and full['tail'] == b'',
          'strict-size': parse(packet[:-1]) is None and parse(packet + b'X') is None and parse(b'') is None,
          'request-validation': all(validate_request(packet, key, PING, cluster, node, 1234).values()),
          'request-validation-negative': not validate_request(packet, key, PING, ident('other'), node, 1234)['cluster']
          and not validate_request(packet, key, JOIN, cluster, node, 1234)['type'] and not validate_request(packet, key, PING, cluster, node, 4321)['port'],
          'reply-validation': valid_reply(build(key, PONG, 1, cluster, node, nonce), key, PONG, nonce, cluster, node, 1)
          and not valid_reply(build(key, PONG, 1, cluster, node, nonce), key, PONG, bytes(16), cluster, node, 1)}
    failed = [name for name, good in ok.items() if not good]
    return not failed, failed or 'codec round trips, strict sizes, MAC and validation hold'


def control_loopback():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind(('127.0.0.1', 0))
        address = server.getsockname()
        got = []
        for size in (0, 1, SIZE, 65507):
            client.sendto(bytes(size), address)
            if not select.select([server], [], [], 2.0)[0]:
                return False, 'a %d byte datagram was not delivered over loopback' % size
            data, _source = server.recvfrom(65536)
            got.append(len(data))
        return got == [0, 1, SIZE, 65507], 'delivered sizes %s' % got
    finally:
        server.close()
        client.close()


def control_udp_table():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    wild = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        receiver.bind(('127.0.0.1', 0))
        wild.bind(('0.0.0.0', 0))
        port = receiver.getsockname()[1]
        first = udp_row(port)
        sender.sendto(bytes(SIZE), ('127.0.0.1', port))
        queued = udp_row(port)
        receiver.recvfrom(65536)
        after = udp_row(port)
        problems = []
        if first is None or first['uid'] != os.geteuid() or first['inode'] not in socket_inodes(os.getpid()) or first['rx'] != 0:
            problems.append('socket row %r' % (first,))
        if queued is None or queued['rx'] <= 0:
            problems.append('receive queue did not grow: %r' % (queued,))
        if after is None or after['rx'] != 0 or after['drops'] != 0:
            problems.append('receive queue did not drain: %r' % (after,))
        if udp_row(wild.getsockname()[1], '0.0.0.0') is None:
            problems.append('wildcard socket row missing')
        return not problems, problems or 'UDP table rows, queues, drops and inodes are observable'
    finally:
        receiver.close()
        sender.close()
        wild.close()


def control_decoy():
    world = World(REFERENCE_BASH)
    world.begin('control-decoy')
    try:
        decoy = world.decoy('decoy')
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for address in ('127.0.0.1', '127.0.0.2'):
                sender.sendto(b'to ' + address.encode(), (address, decoy.port))
        finally:
            sender.close()
        world.reactor.wait(lambda: len(decoy.received) >= 2, 2.0)
        got = sorted(entry[1] for entry in decoy.received)
        return got == [b'to 127.0.0.1', b'to 127.0.0.2'], 'wildcard decoy saw %r' % got
    finally:
        world.close_all()


def control_peers():
    world = World(REFERENCE_BASH)
    world.begin('control-peers')
    problems = []
    try:
        key, cluster, own, own_port = secret('cp'), ident('cp-cluster'), ident('cp-own'), free_port()
        probe = world.endpoint('probe')
        for mode in PING_MODES + ('wrong-cluster', 'echo'):
            peer = Peer(world, 'cp-' + mode, key, cluster, ident('cp-peer'), mode, client=(cluster, own, own_port))
            nonce = world.nonce()
            probe.send(build(key, PING, own_port, cluster, own, nonce), peer.port)
            world.reactor.wait(lambda: bool(probe.received), 0.15 if mode == 'silent' else 2.0)
            got = probe.take()
            if len(peer.requests) != 1 or not all(peer.requests[0]['checks'].values()):
                problems.append('%s: the request was not validated' % mode)
            if mode == 'silent':
                if got:
                    problems.append('silent peer answered')
                continue
            if len(got) != 1:
                problems.append('%s: %d replies' % (mode, len(got)))
                continue
            data, source = got[0][1], got[0][2]
            q = parse(data)
            shape = {'echo': lambda: valid_reply(data, key, PONG, nonce, cluster, peer.node, peer.port) and source[1] == peer.port,
                     'other-port': lambda: valid_reply(data, key, PONG, nonce, cluster, peer.node, peer.port) and source[1] == peer.alt.port != peer.port,
                     'garbage': lambda: data == b'garbage', 'short': lambda: len(data) == SIZE - 1, 'long': lambda: len(data) == SIZE + 1,
                     'wrong-key': lambda: q is not None and not mac_ok(key, data) and mac_ok(secret('peer-wrong-key'), data),
                     'wrong-nonce': lambda: q is not None and q['nonce'] != nonce and mac_ok(key, data),
                     'wrong-type': lambda: q is not None and q['type'] == ERROR and q['nonce'] == nonce and mac_ok(key, data),
                     'bad-magic': lambda: q is not None and q['magic'] != MAGIC and mac_ok(key, data),
                     'count33': lambda: q is not None and q['count'] == 33 and mac_ok(key, data),
                     'wrong-cluster': lambda: q is not None and q['cluster'] != cluster and q['nonce'] == nonce and mac_ok(key, data)}[mode]
            if not shape():
                problems.append('%s: reply shape' % mode)
        return not problems, problems or 'every peer mode validates the request and answers as designed'
    finally:
        world.close_all()


def control_inotify():
    directory = CASE / 'control-inotify'
    os.mkdir(directory, 0o700)
    watch = Inotify(directory)
    try:
        for name in STATE_FILES:
            scratch = directory / ('.%s.tmp' % name)
            with open(scratch, 'wb') as handle:
                handle.write(b'x')
            os.rename(scratch, directory / name)
        good = atomic_report(watch.read())
        for name in STATE_FILES:
            with open(directory / name, 'wb') as handle:
                handle.write(b'y')
        with open(directory / 'direct-new', 'wb') as handle:
            handle.write(b'z')
        os.unlink(directory / 'node_id')
        with open(directory / 'node_id', 'wb') as handle:
            handle.write(b'w')
        bad = atomic_report(watch.read())
        problems = []
        if good['inplace'] or good['order'] or not good['all_state_files_renamed_in']:
            problems.append('atomic pattern misjudged: %r' % good)
        if not bad['inplace']:
            problems.append('in-place writes not detected')
        return not problems, problems or 'inotify events distinguish rename-into-place from in-place writes'
    finally:
        watch.close()


def control_foreign():
    return True, 'ownership probe directory %s' % foreign_private_directory()


def control_driver():
    world = World(REFERENCE_BASH)
    world.begin('control-driver')
    problems = []
    try:
        node = world.node('ref', CASE / 'control-driver-unused')
        first = node.call("printf 'out'; printf 'err' >&2; (exit 7)")
        second = node.call('printf "two\\n"')
        if (first.rc, first.out, first.err) != (7, b'out', b'err'):
            problems.append('call 1 gave %r' % ((first.rc, first.out, first.err),))
        if (second.rc, second.out, second.err) != (0, b'two\n', b''):
            problems.append('call 2 gave %r' % ((second.rc, second.out, second.err),))
        fifo = CASE / 'control-fifo'
        os.mkfifo(fifo)
        blocked = world.node('ref-blocked', CASE / 'control-blocked')
        hung = blocked.call('exec 8<> %s; read -t 20 -u 8 line' % shlex.quote(str(fifo)), timeout=0.4)
        if not hung.timed_out or not blocked.dead:
            problems.append('a blocked command was not reported as a timeout')
        leaver = world.node('ref-leaver', CASE / 'control-leaver')
        started = leaver.call('exec 7<> %s; (read -t 25 -u 7 line) & printf "%%s" "$!"' % shlex.quote(str(fifo)))
        child = int(started.out) if started.out.isdigit() else 0
        if not child or not alive(child):
            problems.append('the background child did not start')
        report = leaver.close()
        if report['killed'] != [child] or alive(child):
            problems.append('a child that outlived its shell was not removed: %r' % (report,))
    finally:
        world.close_all()
    live = [pid for pid in live_children(os.getpid())]
    if live:
        problems.append('live children remain: %r' % live)
    return not problems, problems or 'persistent shells: status/stdout/stderr extraction, deadline kill, orphan removal and reaping hold'


CONTROLS = {'guest': control_guest, 'kat': control_kat, 'codec': control_codec, 'loopback': control_loopback, 'udp-table': control_udp_table,
            'decoy': control_decoy, 'peers': control_peers, 'inotify': control_inotify, 'foreign': control_foreign, 'driver': control_driver}
NEEDS = {'seed-init': ['udp-table', 'driver'], 'state-private': ['udp-table', 'decoy', 'inotify', 'foreign', 'driver'],
         'key-syntax': ['udp-table', 'decoy', 'driver'], 'argument-validation': ['udp-table', 'decoy', 'driver'],
         'authenticated-join': ['udp-table', 'driver'], 'ping-protocol': ['udp-table', 'decoy', 'peers', 'driver'],
         'packet-rejection': ['udp-table', 'driver'], 'leave-lifecycle': ['udp-table', 'driver'], 'roster-heartbeats': ['udp-table', 'driver'],
         'extras': ['udp-table', 'driver'], 'control': ['driver']}


def setup(scenario):
    if scenario not in NEEDS:
        raise FixtureError('unknown scenario %s' % scenario)
    report = {'scenario': scenario, 'controls': [], 'details': {}}
    for name in ['guest', 'kat', 'codec', 'loopback'] + NEEDS[scenario]:
        try:
            ok, detail = CONTROLS[name]()
        except Exception as exc:
            raise FixtureError('control %s raised %s: %s' % (name, type(exc).__name__, exc))
        if not ok:
            raise FixtureError('control %s failed: %s' % (name, detail))
        report['controls'].append(name)
        report['details'][name] = detail if isinstance(detail, (str, list)) else str(detail)
    print(json.dumps(report, sort_keys=True), flush=True)


# ---------------------------------------------------------------------------
# The plan: every vector and every key of every scenario (the expected output is the same line with every key yes).
# ---------------------------------------------------------------------------

SCENARIOS = {
    'seed-init': [
        ('fresh-seed', ['builtin', 'init-status', 'init-output', 'stderr-empty', 'port-ephemeral', 'port-file', 'port-bound', 'key-format', 'id-format',
                        'roster-single', 'private-modes', 'listener-child', 'status-running', 'identity-on-wire', 'fresh-generation', 'stopped-after-kill']),
        ('umask-independence', ['zero-init', 'zero-modes', 'private-init', 'private-modes'])],
    'state-private': [
        ('refuse-unsafe-directory', ['modes-refused', 'modes-untouched', 'symlink-refused', 'symlink-untouched', 'file-refused', 'file-untouched',
                                     'not-owned-refused', 'not-owned-untouched', 'join-refused', 'join-no-traffic', 'no-listener-started', 'private-accepted']),
        ('atomic-state-writes', ['init-status', 'watch-captured', 'final-names-by-rename', 'scratch-then-rename', 'no-scratch-left',
                                 'roster-replaced-atomically', 'files-private']),
        ('lock-collision', ['first-started', 'second-shell-refused', 'same-shell-refused', 'state-unchanged', 'first-listener-alive', 'first-listener-serves',
                            'no-second-listener']),
        ('stale-recovery-leave', ['setup-stale', 'stale-status-stopped', 'leave-status', 'state-files-removed', 'scratch-removed', 'lock-and-unrelated-kept',
                                  'forged-pid-not-signaled', 'status-uninitialized']),
        ('stale-recovery-init', ['setup-stale', 'init-status', 'ids-regenerated', 'scratch-removed', 'unrelated-kept', 'forged-pid-not-signaled',
                                 'status-initialized', 'serves-after-recovery']),
        ('symlinked-state-names', ['init-status', 'target-unchanged', 'names-replaced-by-files', 'scratch-link-removed'])],
    'key-syntax': [
        ('accepted-keys', ['all-accepted', 'private-key-canonical', 'oracle-ping-ok', 'wrong-key-silent', 'no-extra-state']),
        ('rejected-keys', ['all-rejected', 'message', 'no-state', 'no-listener']),
        ('join-key-rejection', ['join-rejected', 'join-no-network'])],
    'argument-validation': [
        ('init-arguments', ['status-codes', 'no-state-written', 'no-listener-started', 'key-message']),
        ('join-arguments', ['status-codes', 'endpoint-message', 'key-message', 'no-state-written', 'no-listener-started', 'no-network-traffic']),
        ('ping-arguments', ['malformed-status', 'message', 'no-packets', 'arity-status', 'uninitialized-status', 'membership-unchanged']),
        ('timeout-lifecycle', ['invalid-rejected', 'no-state-created', 'no-listener-or-traffic', 'leave-rejection-harmless', 'boundaries-accepted',
                               'init-boundaries-start', 'ping-boundary-protocol'])],
    'authenticated-join': [
        ('join-with-seed-key', ['seed-started', 'join-status', 'join-output', 'cluster-id-from-wire', 'nodes-distinct', 'key-file-copied', 'rosters-agree',
                                'members-commands', 'wire-roster']),
        ('join-with-wrong-key', ['join-rejected', 'waited-timeout', 'joiner-state-empty', 'joiner-no-listener', 'seed-roster-unchanged',
                                 'peer-roster-unchanged', 'seed-still-serves'])],
    'ping-protocol': [
        ('ping-resolution', ['by-node', 'by-endpoint', 'requests-received', 'request-size', 'request-header', 'request-identity', 'request-rows-zero',
                             'request-mac', 'nonces-fresh', 'request-source']),
        ('ping-unknown-node', ['status', 'message', 'nothing-sent']),
        ('ping-non-protocol', ['all-fail', 'waits-deadline', 'bounded', 'one-valid-request', 'echo-control', 'deadline-follows']),
        ('ping-live-listener', ['ping-by-node', 'ping-by-endpoint', 'listener-pong-valid', 'pong-identity'])],
    'packet-rejection': [
        ('size-violations', ['rejected-silently', 'roster-unchanged', 'later-ping-ok', 'no-queue-drops']),
        ('format-violations', ['rejected-silently', 'roster-unchanged', 'later-ping-ok', 'no-queue-drops']),
        ('mac-violations', ['rejected-silently', 'roster-unchanged', 'later-ping-ok', 'no-queue-drops']),
        ('count-and-node-violations', ['rejected-silently', 'roster-unchanged', 'later-ping-ok', 'no-queue-drops']),
        ('combined-sequence', ['all-silent', 'roster-unchanged', 'files-unchanged', 'listener-alive', 'candidate-ping-ok', 'oracle-ping-ok'])],
    'leave-lifecycle': [
        ('leave-removes-owned-state', ['leave-status', 'state-files-removed', 'lock-kept', 'unrelated-preserved', 'listener-gone', 'status-after',
                                       'repeat-leave', 'never-initialized-leave']),
        ('leave-drops-member', ['peer-left-status', 'seed-dropped-member', 'dropped-by-notice-not-expiry', 'peer-state-removed', 'seed-listener-alive']),
        ('owner-exit', ['exit-listener-gone', 'exit-port-released', 'exit-state-cleaned', 'exit-unrelated-kept', 'exit-uninitialized', 'kill-listener-gone',
                        'kill-port-released', 'kill-state-cleaned', 'kill-unrelated-kept', 'kill-uninitialized', 'peer-owner-death-notifies-seed'])],
    'roster-heartbeats': [
        ('three-peer-convergence', ['joins-ok', 'identities-on-wire', 'rosters-converge', 'members-commands-agree', 'c-left-status', 'leave-removed-everywhere',
                                    'survivors-intact', 'c-state-cleaned']),
        ('expiry-and-refresh', ['oracles-joined', 'silent-expires-not-early', 'silent-expires-in-bound', 'beating-oracle-retained', 'beating-peers-retained',
                                'retention-ends-after-last-beat', 'expiry-propagates-to-peers']),
        ('seed-loss', ['peers-joined', 'seed-left-status', 'leaf-disconnected', 'leaf-roster-self-only', 'leaf-listener-alive', 'leaf-stopped-after-kill'])],
    'extras': [
        ('join-misuse', ['duplicate-refused', 'duplicate-unchanged', 'leaf-join-rejected', 'leaf-unchanged']),
        ('lock-collision-extras', ['duplicate-join-refused', 'bind-collision-clean']),
        ('baseline', ['seed-up', 'ping-answered', 'ping-reply-valid', 'join-accepted', 'join-reply-valid', 'member-visible', 'leave-restores']),
        ('unsupported-types', ['no-member', 'replies-authenticated-or-none', 'later-ping-ok']),
        ('identity-conflicts', ['member-added', 'source-port-mismatch-ignored', 'seed-identity-ignored', 'moved-endpoint-ignored', 'duplicate-port-ignored',
                                'roster-as-expected'])],
    'control': [
        ('candidate-basics', ['builtin', 'version', 'usage-no-verb', 'unknown-verb', 'status-uninitialized', 'members-empty', 'leave-uninitialized'])],
}

VECTORS = {
    'seed-init': [('fresh-seed', v_seed_fresh), ('umask-independence', v_seed_umask)],
    'state-private': [('refuse-unsafe-directory', v_state_refusals), ('atomic-state-writes', v_state_atomic), ('lock-collision', v_state_lock),
                      ('stale-recovery-leave', v_stale_leave), ('stale-recovery-init', v_stale_init), ('symlinked-state-names', v_state_symlinks)],
    'key-syntax': [('accepted-keys', v_keys_accepted), ('rejected-keys', v_keys_rejected), ('join-key-rejection', v_keys_join)],
    'argument-validation': [('init-arguments', v_args_init), ('join-arguments', v_args_join), ('ping-arguments', v_args_ping),
                            ('timeout-lifecycle', v_args_timeout)],
    'authenticated-join': [('join-with-seed-key', v_join_seed_key), ('join-with-wrong-key', v_join_wrong_key)],
    'ping-protocol': [('ping-resolution', v_ping_resolution), ('ping-unknown-node', v_ping_unknown), ('ping-non-protocol', v_ping_nonprotocol),
                      ('ping-live-listener', v_ping_live)],
    'packet-rejection': [('size-violations', v_packets_size), ('format-violations', v_packets_format), ('mac-violations', v_packets_mac),
                         ('count-and-node-violations', v_packets_count_node), ('combined-sequence', v_packets_combined)],
    'leave-lifecycle': [('leave-removes-owned-state', v_leave_state), ('leave-drops-member', v_leave_drops), ('owner-exit', v_owner_exit)],
    'roster-heartbeats': [('three-peer-convergence', v_roster_convergence), ('expiry-and-refresh', v_roster_expiry), ('seed-loss', v_roster_seed_loss)],
    'extras': [('join-misuse', v_join_misuse), ('lock-collision-extras', v_lock_extras), ('baseline', v_packets_baseline), ('unsupported-types', v_packets_types),
               ('identity-conflicts', v_packets_identity)],
    'control': [('candidate-basics', v_control_candidate)],
}


def sweep():
    """After the last vector: nothing may be left that this process started or inherited as an orphan."""
    me = os.getpid()
    left = [pid for pid, info in processes().items() if info['ppid'] == me and info['state'] != 'Z']
    for pid in left:
        try:
            kill_pid(pid, 'final sweep orphan')
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and any(alive(pid) for pid in left):
        select.select([], [], [], 0.01)
    reap_zombies(set())
    return left


def observe(shell, scenario):
    if scenario not in SCENARIOS or scenario not in VECTORS:
        raise FixtureError('unknown scenario %s' % scenario)
    plan = {name: keys for name, keys in SCENARIOS[scenario]}
    if [name for name, _keys in SCENARIOS[scenario]] != [name for name, _function in VECTORS[scenario]]:
        raise FixtureError('the plan and the vector registry of %s differ' % scenario)
    set_subreaper()
    world = World(shell)
    lines, broken = [], []
    for name, function in VECTORS[scenario]:
        vector, failed = run_vector(world, plan, name, function)
        lines.append(vector.line())
        if failed:
            broken.append(name)
    left = sweep()
    if left:
        with open('observations.jsonl', 'a') as stream:
            stream.write(json.dumps({'vector': 'final-sweep', 'killed_orphans': left}) + '\n')
    for line in lines:
        print(line, flush=True)
    if broken:
        raise FixtureError('vector(s) %s raised an exception (traceback in observations.jsonl)' % ', '.join(broken))


def main(argv):
    if len(argv) != 2:
        refuse('usage: setup SCENARIO | SHELL SCENARIO')
    require_guest()
    mode = 'setup' if argv[0] == 'setup' else 'observe'
    try:
        if mode == 'setup':
            setup(argv[1])
        else:
            observe(argv[0], argv[1])
    except FixtureError as exc:
        print('CONTROL-INVALID %s %s: %s' % (mode, argv[1], exc), flush=True)
        return 97
    return 0


def traced(function, kind):
    def wrapper(*args, **kwargs):
        result = function(*args, **kwargs)
        trace(kind, args=list(args), result=result)
        return result
    wrapper.__name__ = function.__name__
    return wrapper


for _name in ('proc_stat', 'alive', 'live_children', 'group_members', 'socket_inodes', 'udp_row', 'port_free', 'snapshot', 'read_files', 'listing'):
    globals()[_name] = traced(globals()[_name], _name)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
