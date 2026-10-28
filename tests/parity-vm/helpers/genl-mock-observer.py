#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only mock NETLINK_GENERIC controller and observer for the genl controller reader.

The guest kernel's generic-netlink table is small (one receive buffer) and never reports an operation without a capability
word, so two obligations of "genl ctrl list" cannot be exercised against it: the flag text "none" and multipart consumption
across several receive buffers. This helper supplies the controller instead, for the UNCHANGED candidate (static or dynamic):

  * the candidate shell runs under a seccomp user-notification filter that this helper installs (no privilege; no_new_privs);
  * socket(AF_NETLINK, ., NETLINK_GENERIC) is answered with SECCOMP_IOCTL_NOTIF_ADDFD, injecting one end of an AF_UNIX
    SOCK_SEQPACKET socketpair at the fixed descriptor number K, so the candidate never reaches the kernel's controller;
  * bind on K is answered with 0; sendmsg on K is answered by reading the request out of the owned, single-threaded child,
    handing it to a kernel-like controller and queueing the reply datagrams, each datagram being exactly one planned receive
    buffer; select, recvmsg and close then run natively on the injected socket (recvmsg is only counted, then continued);
  * every request the candidate sends is decoded with the frozen oracle parser and asserted (a dump request carries no
    attribute and NLM_F_DUMP, a lookup carries exactly one family attribute), which also proves that "ctrl list" issues a dump.

Modes (inside the disposable parity VM, as uid 2000, in the case scratch directory):
  setup SCENARIO     independent controls; a failed control is invalid evidence (exit 97)
  SHELL SCENARIO     run the candidate "genl" builtin against the mock and print one summary line per vector
  probe-child MODE   internal: a Python program making the candidate's syscalls, used to calibrate injection and decoding

Independence: replies are encoded by this file, decoded again by the frozen oracle (tests/parity-vm/helpers/genl-review-observer.py,
digest-checked and loaded as a library) and compared with the real guest kernel's bytes; the expected text is the documented print
contract of loadables/genl.c rendered by the frozen oracle from the synthetic table, never taken from candidate output.
"""
import base64
import collections
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time
import uuid


ROOT = Path('/opt/bashos-parity/harness/helpers')
SELF = ROOT / 'genl-mock-observer.py'
BASE_PATH = ROOT / 'genl-review-observer.py'
BASE_SHA256 = 'e81d3c76a034713ec914b44db65840f909f5a2c996f7e9ac5f1dfc39fbeb7ae6'
PYTHON = '/usr/bin/python3'
B = None            # the frozen oracle module, loaded by main()
LIB = None          # libseccomp, loaded by main()

K = 100             # descriptor number of the injected controller socket inside the supervised program (below RLIMIT_NOFILE 128)
AF_NETLINK, NETLINK_GENERIC = 16, 16
ALLOW, NOTIFY = 0x7fff0000, 0x7fc00000
CMP_MASKED_EQ = 7
NOTIF_RECV, NOTIF_SEND, NOTIF_ID_VALID, NOTIF_ADDFD = 0xc0502100, 0xc0182101, 0x40082102, 0x40182103
FLAG_CONTINUE = 1
ADDFD_SETFD, ADDFD_SEND = 1, 2
# (syscall, ((argument index, value), ...)): everything else, and every other descriptor, runs natively.
RULES = (('socket', ((0, AF_NETLINK), (2, NETLINK_GENERIC))), ('bind', ((0, K),)), ('sendmsg', ((0, K),)), ('recvmsg', ((0, K),)))
MAX_DATAGRAM = 60000
VECTOR_SECONDS = 10.0   # one supervised run takes well under a second; bounds the worst case below the case timeout
PROBE_SEQ = 0x70726f62
DUMP_FLAGS = 0x301  # NLM_F_REQUEST | NLM_F_DUMP


class ArgCmp(ctypes.Structure):
    _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int), ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]


# ---------------------------------------------------------------------------
# Guest guard and the frozen oracle.
# ---------------------------------------------------------------------------

def refuse(reason):
    sys.stderr.write('genl-mock-observer: refusing: %s\n' % reason)
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
    if Path.cwd() != Path('/tmp/parity-case'):
        refuse('not in the case scratch directory')


def load_base():
    """Load the frozen oracle (definitions only) after checking that it is the frozen file."""
    if hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA256:
        refuse('the frozen oracle helper is not the frozen file')
    spec = importlib.util.spec_from_file_location('genl_review_observer', str(BASE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_seccomp():
    lib = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
    return lib


def yes(flag):
    return 'yes' if flag else 'no'


# ---------------------------------------------------------------------------
# Synthetic tables and the kernel-like controller.
# ---------------------------------------------------------------------------

def make_family(name, number, version, hdrsize, maxattr, ops=None, groups=None):
    """A family in the shape the frozen parser returns; ops are (cmd, flags), groups are (id, name)."""
    return {'cmd': 1, 'name': name, 'id': number, 'version': version, 'hdrsize': hdrsize, 'maxattr': maxattr,
            'ops': None if ops is None else [{'index': i, 'id': c, 'flags': f} for i, (c, f) in enumerate(ops, 1)],
            'groups': None if groups is None else [{'index': i, 'id': g, 'name': n} for i, (g, n) in enumerate(groups, 1)]}


def table_caps_low():
    # flags 0x0 .. 0xf: every subset of the four capability bits, including the empty one (the word "none")
    return [make_family('mockcaps_lo', 0x20, 2, 0, 7, [(i + 1, i) for i in range(16)], [(0x40, 'mockgrp')])]


def table_caps_uns():
    # flags 0x10 .. 0x1f: the same subsets plus GENL_UNS_ADMIN_PERM, for which the candidate has no word
    return [make_family('mockcaps_uns', 0x21, 2, 0, 7, [(i + 1, 0x10 | i) for i in range(16)])]


def table_caps_unknown():
    flags = [0x20, 0x40, 0x80, 0x100, 0x8000, 0x10000, 0xffffff00, 0x80000000, 0x21, 0x22, 0x24, 0x28, 0xfffffff0, 0xffffffff]
    return [make_family('mockcaps_unk', 0x22, 2, 0, 7, [(i + 1, f) for i, f in enumerate(flags)])]


def table_multipart():
    # 24 families with 0, 1, 2, 5, 40, 0, 3 and 120 operations in turn, 0..3 groups; no operation has flags 0 (no "none")
    shapes = [0, 1, 2, 5, 40, 0, 3, 120]
    families = []
    for i in range(24):
        count = shapes[i % 8]
        ops = [(1 + 2 * j, (1 + (i + j) % 15) | (0x10 if (i + j) % 5 == 0 else 0)) for j in range(count)] or None
        groups = [(0x100 + 4 * i + k, 'grp%02d_%d' % (i, k)) for k in range(i % 4)] or None
        families.append(make_family('mockfam%02d' % i, 0x30 + i, 1 + i % 3, (i % 4) * 4, (i * 3) % 17, ops, groups))
    return families


def table_large():
    return [make_family('mocklarge%d' % i, 0x60 + i, 2, 0, 11, [(1 + j, 1 + (i + j) % 15) for j in range(250)],
                        [(0x200 + 2 * i, 'lg%d_a' % i), (0x201 + 2 * i, 'lg%d_b' % i)]) for i in range(8)]


def table_mixed():
    return [make_family('m_nothing', 0x40, 1, 0, 0),
            make_family('m_ops_only', 0x41, 2, 0, 5, [(1, 0xe), (2, 0xc), (255, 0x6)]),
            make_family('m_groups_only', 0x42, 3, 8, 9, None, [(0x300, 'one'), (0x301, 'two_two')]),
            make_family('m_both', 0x43, 0xffffffff, 0xffffffff, 0xffffffff, [(0, 0x1f)], [(0xffffffff, 'g')]),
            make_family('abcdefghijklmno', 0x3ff, 1, 0, 1, [(1, 0x1)]),
            make_family('m_mixed_flags', 0x44, 2, 4, 3, [(7, 0x0), (8, 0x1), (9, 0x20), (10, 0xa)], [(0x400, 'mg')])]


def table_foreign_base():
    return [make_family('fa_one', 0x50, 1, 0, 2, [(1, 0xe)], [(0x500, 'fa_grp')]),
            make_family('fb_two', 0x51, 2, 0, 3, [(1, 0x6), (2, 0xc)]),
            make_family('fc_three', 0x52, 3, 4, 4, None, [(0x510, 'fc_grp')])]


def table_lookup():
    return table_caps_low() + table_caps_uns()


TABLES = {'caps-low': table_caps_low, 'caps-uns': table_caps_uns, 'caps-unknown': table_caps_unknown, 'multipart': table_multipart,
          'large': table_large, 'mixed': table_mixed, 'foreign-base': table_foreign_base, 'lookup': table_lookup}
STRAY = make_family('foreign_fam', 0x7f, 1, 0, 0, [(1, 0xe)], [(0x500, 'foreign_grp')])
SENTINEL = make_family('after_done', 0x7e, 1, 0, 0)


def encode_family(family, seq, pid, flags):
    """One CTRL_CMD_NEWFAMILY message laid out like the guest kernel's ctrl_fill_info (verified against its bytes)."""
    attrs = (B.attribute(B.CTRL_ATTR_FAMILY_NAME, family['name'].encode() + b'\0')
             + B.attribute(B.CTRL_ATTR_FAMILY_ID, B.U16.pack(family['id']))
             + B.attribute(B.CTRL_ATTR_VERSION, B.U32.pack(family['version']))
             + B.attribute(B.CTRL_ATTR_HDRSIZE, B.U32.pack(family['hdrsize']))
             + B.attribute(B.CTRL_ATTR_MAXATTR, B.U32.pack(family['maxattr'])))
    if family['ops'] is not None:
        attrs += B.attribute(B.CTRL_ATTR_OPS, b''.join(
            B.attribute(op['index'], B.attribute(B.CTRL_ATTR_OP_ID, B.U32.pack(op['id']))
                        + B.attribute(B.CTRL_ATTR_OP_FLAGS, B.U32.pack(op['flags']))) for op in family['ops']))
    if family['groups'] is not None:
        attrs += B.attribute(B.CTRL_ATTR_MCAST_GROUPS, b''.join(
            B.attribute(group['index'], B.attribute(B.CTRL_ATTR_MCAST_GRP_ID, B.U32.pack(group['id']))
                        + B.attribute(B.CTRL_ATTR_MCAST_GRP_NAME, group['name'].encode() + b'\0')) for group in family['groups']))
    return B.message(B.GENL_ID_CTRL, flags, seq, pid, B.GENL.pack(B.CTRL_CMD_NEWFAMILY, 2, 0) + attrs)


class Controller:
    """A kernel-like NETLINK_GENERIC controller over a synthetic table, answering with a planned sequence of datagrams."""

    def __init__(self, table, plan):
        self.table, self.plan = table, plan

    def error(self, request, seq, portid, code):
        # like netlink_ack for an error: the whole original request is echoed after the error code
        return B.message(B.NLMSG_ERROR, 0, seq, portid, B.S32.pack(-code) + request)

    def __call__(self, request, portid):
        if len(request) < B.NLMSG.size + B.GENL.size:
            raise B.ProtocolError('request shorter than the netlink and generic headers')
        length, mtype, flags, seq, _pid = B.NLMSG.unpack_from(request)
        if length != len(request):
            raise B.ProtocolError('nlmsg_len %d differs from the %d bytes sent' % (length, len(request)))
        if mtype != B.GENL_ID_CTRL:
            return [self.error(request, seq, portid, errno.ENOENT)]
        if B.GENL.unpack_from(request, B.NLMSG.size)[0] != B.CTRL_CMD_GETFAMILY:
            return [self.error(request, seq, portid, errno.EOPNOTSUPP)]
        attrs = B.unique(B.parse_attributes(request[B.NLMSG.size + B.GENL.size:]))
        if flags & B.NLM_F_DUMP == B.NLM_F_DUMP:
            return self.dump(seq, portid)
        if B.CTRL_ATTR_FAMILY_ID in attrs:
            number = B.as_u16(attrs[B.CTRL_ATTR_FAMILY_ID], 'family id')
            found = [f for f in self.table if f['id'] == number]
        elif B.CTRL_ATTR_FAMILY_NAME in attrs:
            name = B.as_string(attrs[B.CTRL_ATTR_FAMILY_NAME], 'family name')
            found = [f for f in self.table if f['name'] == name]
        else:
            return [self.error(request, seq, portid, errno.EINVAL)]
        if not found:
            return [self.error(request, seq, portid, errno.ENOENT)]
        return [encode_family(found[0], seq, portid, 0)]

    def dump(self, seq, portid):
        plan = self.plan
        records = [encode_family(f, seq, portid, B.NLM_F_MULTI) for f in self.table]
        groups, index = [], 0
        for count in plan['chunks']:
            groups.append(records[index:index + count])
            index += count
        if index != len(records):
            raise RuntimeError('internal: the chunk sizes cover %d of %d records' % (index, len(records)))
        done = B.message(B.NLMSG_DONE, B.NLM_F_MULTI, seq, portid, B.S32.pack(0))
        if plan['done'] == 'separate':
            groups.append([done])
        else:
            groups[-1].append(done)
        for mode, position in plan['foreign']:
            stray = encode_family(STRAY, seq + 1, portid, B.NLM_F_MULTI)
            if mode == 'own':
                groups.insert(position, [stray])
            else:
                groups[position].insert(1, stray)
        if len(groups) != plan['datagrams']:
            raise RuntimeError('internal: %d datagrams built, the plan says %d' % (len(groups), plan['datagrams']))
        if plan['sentinel']:
            groups.append([encode_family(SENTINEL, seq, portid, B.NLM_F_MULTI)])
        datagrams = [b''.join(group) for group in groups]
        if max(len(d) for d in datagrams) > MAX_DATAGRAM:
            raise RuntimeError('internal: a datagram exceeds %d bytes' % MAX_DATAGRAM)
        return datagrams


# ---------------------------------------------------------------------------
# The seccomp user-notification supervisor.
# ---------------------------------------------------------------------------

def install_filter(lib):
    ctx = lib.seccomp_init(ALLOW)
    if not ctx:
        raise OSError('seccomp_init failed')
    for name, conds in RULES:
        number = lib.seccomp_syscall_resolve_name(name.encode())
        if number < 0:
            raise OSError('unknown syscall ' + name)
        array = (ArgCmp * len(conds))()
        for slot, (index, value) in enumerate(conds):
            array[slot] = ArgCmp(index, CMP_MASKED_EQ, 0xffffffff, value)
        if lib.seccomp_rule_add_array(ctx, ctypes.c_uint32(NOTIFY), number, len(conds), array) != 0:
            raise OSError('cannot add the rule for ' + name)
    if lib.seccomp_load(ctx) != 0:
        raise OSError('seccomp_load failed')
    listener = lib.seccomp_notify_fd(ctx)
    if listener < 0:
        raise OSError('no notification descriptor')
    return listener


def read_memory(pid, address, length):
    if not 0 <= length <= 1 << 20:
        raise ValueError('implausible length %d' % length)
    if length == 0:
        return b''
    fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY)
    try:
        data = os.pread(fd, length, address)
    finally:
        os.close(fd)
    if len(data) != length:
        raise OSError(errno.EIO, 'short read of the supervised program memory')
    return data


class Supervisor:
    """Runs one program under the filter; its NETLINK_GENERIC socket becomes a mock controller served by `controller`."""

    def __init__(self, controller):
        self.controller = controller
        self.numbers = {name: LIB.seccomp_syscall_resolve_name(name.encode()) for name, _conds in RULES}
        self.events, self.errors, self.requests, self.destinations = [], [], [], []
        self.sockets = self.binds = self.sendmsgs = self.recvmsgs = 0
        self.outbox = collections.deque()
        self.delivered = self.total = self.leftover = 0
        self.stdout = self.stderr = b''
        self.exit = None
        self.timed_out = False
        self.peer = self.end = None

    # -- child side -------------------------------------------------------
    def exec_child(self, argv, env, null, out_w, err_w, pass_child):
        try:
            os.setsid()
            os.dup2(null, 0)
            os.dup2(out_w, 1)
            os.dup2(err_w, 2)
            listener = install_filter(LIB)
            os.set_inheritable(listener, False)
            socket.send_fds(pass_child, [b'L'], [listener])
            os.execve(argv[0], argv, env)
        except BaseException as exc:  # never return into the parent's code
            try:
                os.write(2, ('genl-mock-observer child: %s\n' % exc).encode())
            finally:
                os._exit(126)
        os._exit(126)

    # -- parent side ------------------------------------------------------
    def run(self, argv, env):
        end, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pass_parent, pass_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        null = os.open(os.devnull, os.O_RDONLY)
        out_r, out_w = os.pipe()
        err_r, err_w = os.pipe()
        self.end, self.peer = end, peer
        pid = os.fork()
        if pid == 0:
            self.exec_child(argv, env, null, out_w, err_w, pass_child)
        for fd in (null, out_w, err_w):
            os.close(fd)
        pass_child.close()
        chunks = {out_r: [], err_r: []}
        live = set(chunks)
        listener, status = None, None
        try:
            if not select.select([pass_parent], [], [], 10)[0]:
                reason = b''
                if select.select([err_r], [], [], 0)[0]:
                    reason = os.read(err_r, 4096)
                raise B.ControlFailure('the supervised program did not install the seccomp filter: %r' % reason)
            _data, fds, _flags, _address = socket.recv_fds(pass_parent, 16, 1)
            if not fds:
                raise B.ControlFailure('no notification descriptor was passed')
            listener = fds[0]
            deadline = time.monotonic() + VECTOR_SECONDS
            while True:
                if status is None:
                    done, wait = os.waitpid(pid, os.WNOHANG)
                    if done:
                        status = wait
                if status is not None and not live:
                    break
                if time.monotonic() > deadline:
                    self.timed_out = True
                    break
                readers = sorted(live) + ([listener] if status is None else [])
                writers = [peer] if self.outbox and status is None else []
                ready, writable, _ = select.select(readers, writers, [], 0.05)
                for fd in ready:
                    if fd == listener:
                        self.service(listener)
                    else:
                        data = os.read(fd, 65536)
                        if data:
                            chunks[fd].append(data)
                        else:
                            os.close(fd)
                            live.discard(fd)
                if writable:
                    self.pump()
        finally:
            if status is None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                status = os.waitpid(pid, 0)[1]
            for fd in live:
                os.close(fd)
            if listener is not None:
                os.close(listener)
            pass_parent.close()
            self.leftover = self.drain()
            end.close()
            peer.close()
        self.exit = os.waitstatus_to_exitcode(status)
        self.stdout, self.stderr = b''.join(chunks[out_r]), b''.join(chunks[err_r])

    def drain(self):
        """Datagrams that were sent to the candidate's end but never read by it."""
        count = 0
        while True:
            try:
                data = self.end.recv(65536, socket.MSG_DONTWAIT)
            except OSError:  # BlockingIOError: nothing is queued
                return count
            if not data:
                return count
            count += 1

    def pump(self):
        while self.outbox:
            try:
                self.peer.send(self.outbox[0], socket.MSG_DONTWAIT)
            except BlockingIOError:
                return
            except OSError:  # the candidate closed its end
                self.outbox.clear()
                return
            self.outbox.popleft()
            self.delivered += 1

    def respond(self, listener, ident, value=0, error=0, flags=0):
        try:
            fcntl.ioctl(listener, NOTIF_SEND, struct.pack('<QqiI', ident, value, -error, flags))
        except OSError as exc:
            if exc.errno != errno.ENOENT:  # the caller died meanwhile
                raise

    def service(self, listener):
        request = bytearray(80)
        try:
            fcntl.ioctl(listener, NOTIF_RECV, request, True)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.EINTR):
                return
            raise
        ident, pid, _flags, number, _arch, _ip = struct.unpack_from('<QIIiIQ', request)
        args = struct.unpack_from('<6Q', request, 32)
        if number == self.numbers['socket']:
            self.on_socket(listener, ident, pid, args)
        elif number == self.numbers['bind']:
            self.binds += 1
            self.events.append({'syscall': 'bind', 'pid': pid, 'fd': args[0] & 0xffffffff, 'reply': 0})
            self.respond(listener, ident)
        elif number == self.numbers['sendmsg']:
            self.on_sendmsg(listener, ident, pid, args)
        elif number == self.numbers['recvmsg']:
            self.recvmsgs += 1
            self.respond(listener, ident, flags=FLAG_CONTINUE)
        else:
            self.errors.append('unexpected notification for syscall %d' % number)
            self.respond(listener, ident, flags=FLAG_CONTINUE)

    def on_socket(self, listener, ident, pid, args):
        self.sockets += 1
        try:
            buf = bytearray(struct.pack('<QIIII', ident, ADDFD_SETFD | ADDFD_SEND, self.end.fileno(), K, os.O_CLOEXEC))
            got = fcntl.ioctl(listener, NOTIF_ADDFD, buf, True)
        except OSError as exc:
            self.errors.append('addfd failed: %s' % exc)
            self.respond(listener, ident, error=errno.EPERM)
            return
        self.events.append({'syscall': 'socket', 'pid': pid, 'args': [a & 0xffffffff for a in args[:3]], 'action': 'addfd', 'fd': got})
        if got != K:
            self.errors.append('addfd returned descriptor %r, wanted %d' % (got, K))

    def read_request(self, listener, ident, pid, header_address):
        header = read_memory(pid, header_address, 56)
        name_pointer, name_length, iov_pointer, iov_count, _control, _control_length, _msg_flags = struct.unpack('<QI4xQQQQi4x', header)
        if not 1 <= iov_count <= 8:
            raise ValueError('implausible iovec count %d' % iov_count)
        pairs = struct.unpack('<%dQ' % (2 * iov_count), read_memory(pid, iov_pointer, 16 * iov_count))
        payload = b''.join(read_memory(pid, pairs[i], pairs[i + 1]) for i in range(0, len(pairs), 2))
        destination = read_memory(pid, name_pointer, name_length) if name_pointer and name_length else b''
        fcntl.ioctl(listener, NOTIF_ID_VALID, struct.pack('<Q', ident))  # the caller is still blocked in this very call
        return payload, destination

    def on_sendmsg(self, listener, ident, pid, args):
        self.sendmsgs += 1
        try:
            request, destination = self.read_request(listener, ident, pid, args[1])
        except (OSError, ValueError, struct.error) as exc:
            self.errors.append('cannot read the request: %s' % exc)
            self.respond(listener, ident, error=errno.EFAULT)
            return
        self.requests.append(request)
        self.destinations.append(destination)
        try:
            datagrams = self.controller(request, pid)
        except B.ProtocolError as exc:
            self.errors.append('the mock controller refused the request: %s' % exc)
            self.respond(listener, ident, error=errno.EINVAL)
            return
        self.total += len(datagrams)
        self.outbox.extend(datagrams)
        self.pump()
        self.events.append({'syscall': 'sendmsg', 'pid': pid, 'request_base64': base64.b64encode(request).decode(),
                            'destination_hex': destination.hex(), 'datagram_bytes': [len(d) for d in datagrams],
                            'datagram_sha256': [hashlib.sha256(d).hexdigest() for d in datagrams], 'reply': len(request)})
        self.respond(listener, ident, value=len(request))

    @property
    def consumed(self):
        return self.delivered - self.leftover

    @property
    def unconsumed(self):
        return self.total - self.consumed


def supervised(argv, controller):
    supervisor = Supervisor(controller)
    supervisor.run(argv, dict(os.environ))
    return supervisor


# ---------------------------------------------------------------------------
# Request decoding and the per-vector keys.
# ---------------------------------------------------------------------------

def decode_request(payload, destination):
    length, mtype, flags, seq, pid = B.NLMSG.unpack_from(payload)
    cmd, version, reserved = B.GENL.unpack_from(payload, B.NLMSG.size)
    attrs = [(kind, bytes(body)) for kind, _bits, body in B.parse_attributes(payload[B.NLMSG.size + B.GENL.size:length])]
    return {'sent': len(payload), 'len': length, 'type': mtype, 'flags': flags, 'seq': seq, 'pid': pid, 'cmd': cmd,
            'version': version, 'reserved': reserved, 'attrs': attrs,
            'dest': struct.unpack('<HHII', destination[:12]) if len(destination) >= 12 else None}


def request_matches(supervisor, flags, attrs):
    if len(supervisor.requests) != 1:
        return False
    try:
        d = decode_request(supervisor.requests[0], supervisor.destinations[0])
    except (B.ProtocolError, struct.error):
        return False
    return (d['len'] == d['sent'] and d['type'] == B.GENL_ID_CTRL and d['flags'] == flags and d['cmd'] == B.CTRL_CMD_GETFAMILY
            and d['version'] == 1 and d['reserved'] == 0 and d['attrs'] == attrs and d['seq'] != 0 and d['pid'] == 0
            and d['dest'] == (AF_NETLINK, 0, 0, 0))


def lookup_target(table, args):
    kind, value = args[2], args[3]
    if kind == 'name':
        return [f for f in table if f['name'] == value][0], [(B.CTRL_ATTR_FAMILY_NAME, value.encode() + b'\0')]
    number = int(value, 0)
    return [f for f in table if f['id'] == number][0], [(B.CTRL_ATTR_FAMILY_ID, B.U16.pack(number))]


def mock_values(line, supervisor, table):
    ran = B.Ran(line['args'], supervisor.exit, supervisor.stdout, supervisor.stderr, supervisor.timed_out)
    kind = line['kind']
    if kind == 'mock-get':
        family, attrs = lookup_target(table, line['args'])
        families, flags = [family], B.NLM_F_REQUEST
        values, parsed = B.listing_values(ran, families)
        values['request-name'] = yes(line['args'][2] == 'name' and request_matches(supervisor, flags, attrs))
        values['request-id'] = yes(line['args'][2] == 'id' and request_matches(supervisor, flags, attrs))
        values['one-record'] = yes(len(parsed['families']) == 1 and not parsed['junk'])
        values['request-dump'] = 'no'
    else:
        families = table
        values, parsed = B.listing_values(ran, families)
        values['request-dump'] = yes(request_matches(supervisor, DUMP_FLAGS, []))
        values['request-name'] = values['request-id'] = 'no'
        values['one-record'] = 'no'
    values['injected'] = yes(not supervisor.errors and supervisor.sockets == 1 and supervisor.binds == 1 and supervisor.sendmsgs == 1
                             and supervisor.recvmsgs >= 1)
    values['recv-calls'] = str(supervisor.recvmsgs)
    values['consumed'] = str(supervisor.consumed)
    values['unconsumed'] = str(supervisor.unconsumed)
    # the flag text of every operation: exact words and the word "none" for exactly the operations without a known bit
    shown = parsed['families']
    words_ok = none_ok = len(shown) == len(families)
    expected_none = seen_none = 0
    for p, f in zip(shown, families):
        wants = f['ops'] or []
        if len(p['ops']) != len(wants):
            words_ok = none_ok = False
            continue
        for op, want in zip(p['ops'], wants):
            is_none = not want['flags'] & 0xf
            words_ok = words_ok and op['words'] == B.words(want['flags']).strip()
            none_ok = none_ok and is_none == (op['words'] == 'none')
            expected_none += is_none
            seen_none += op['words'] == 'none'
    values['words-exact'] = yes(words_ok)
    values['none-words'] = yes(none_ok and expected_none == seen_none and expected_none > 0)
    values['foreign-ignored'] = yes(b'foreign_fam' not in supervisor.stdout and b'foreign_grp' not in supervisor.stdout)
    return values


def observe(row):
    with Path('mock-observations.jsonl').open('a') as stream:
        stream.write(json.dumps(row, sort_keys=True) + '\n')


def save_events(label, supervisor):
    Path('mock-events-%s.json' % label).write_text(json.dumps({
        'events': supervisor.events, 'errors': supervisor.errors, 'sockets': supervisor.sockets, 'binds': supervisor.binds,
        'sendmsgs': supervisor.sendmsgs, 'recvmsgs': supervisor.recvmsgs, 'datagrams_planned': supervisor.total,
        'datagrams_delivered': supervisor.delivered, 'datagrams_left_unread': supervisor.leftover, 'exit': supervisor.exit,
        'timed_out': supervisor.timed_out}, indent=1) + '\n')


# ---------------------------------------------------------------------------
# Probe children: a Python program making the candidate's syscalls.
# ---------------------------------------------------------------------------

def probe_open():
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    fd = sock.fileno()
    sock.bind((0, 0))
    return sock, fd


def probe_exchange(sock, seq, flags, attrs, dump):
    request = B.controller_request(B.CTRL_CMD_GETFAMILY, flags, seq, attrs)
    sent = sock.sendmsg([request], [], 0, (0, 0))
    conversation = B.Conversation(seq, os.getpid(), dump)
    datagrams = []
    while not conversation.complete:
        if not select.select([sock], [], [], 5.0)[0]:
            break
        data, _ancillary, _flags, _address = sock.recvmsg(B.RECV_SIZE)
        datagrams.append(data)
        conversation.feed(data)
    return request, sent, conversation, datagrams


def probe_child(mode, arguments):
    if mode == 'dump':
        sock, fd = probe_open()
        request, sent, conversation, datagrams = probe_exchange(sock, PROBE_SEQ, DUMP_FLAGS, b'', True)
        print(json.dumps({'pid': os.getpid(), 'fd': fd, 'sent': sent, 'request': request.hex(), 'complete': conversation.complete,
                          'datagram_sha256': [hashlib.sha256(d).hexdigest() for d in datagrams], 'datagram_bytes': [len(d) for d in datagrams],
                          'foreign': len(conversation.foreign), 'multi': conversation.multi,
                          'families': [B.parse_family(m['payload']) for m in conversation.messages],
                          'payloads': [m['payload'].hex() for m in conversation.messages]}), flush=True)
    elif mode == 'narrow':
        route = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        route.bind((0, 0))
        name = route.getsockname()
        plain = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print(json.dumps({'route_fd': route.fileno(), 'route_name_is_pair': isinstance(name, tuple) and len(name) == 2,
                          'unix_fd': plain.fileno()}), flush=True)
    elif mode == 'lookups':
        known_name, known_id = arguments[0], int(arguments[1])
        sock, fd = probe_open()
        results = []
        for label, flags, attrs in (('no-attribute', B.NLM_F_REQUEST, b''),
                                    ('unknown-name', B.NLM_F_REQUEST, B.name_attribute('bashos_nofam')),
                                    ('known-name', B.NLM_F_REQUEST, B.name_attribute(known_name)),
                                    ('known-id', B.NLM_F_REQUEST, B.id_attribute(known_id))):
            _request, _sent, conversation, _datagrams = probe_exchange(sock, PROBE_SEQ + len(results) + 1, flags, attrs, False)
            results.append({'label': label, 'complete': conversation.complete, 'error': conversation.error,
                            'families': [B.parse_family(m['payload']) for m in conversation.messages]})
        print(json.dumps({'fd': fd, 'results': results}), flush=True)
    else:
        raise SystemExit('unknown probe mode ' + mode)


def run_probe(controller, mode, arguments=()):
    supervisor = supervised([PYTHON, str(SELF), 'probe-child', mode, *arguments], controller)
    if supervisor.timed_out or supervisor.exit != 0 or supervisor.errors:
        raise B.ControlFailure('probe %s failed: exit=%r timed_out=%r errors=%r calls=%d/%d/%d/%d (socket/bind/sendmsg/recvmsg) '
                               'last events=%r stderr=%r' % (mode, supervisor.exit, supervisor.timed_out, supervisor.errors,
                                                             supervisor.sockets, supervisor.binds, supervisor.sendmsgs,
                                                             supervisor.recvmsgs, supervisor.events[-4:], supervisor.stderr[-400:]))
    return supervisor, json.loads(supervisor.stdout.decode().strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# Controls. Each returns (bool, detail); setup treats a False as invalid evidence, the control case prints it.
# ---------------------------------------------------------------------------

CANONICAL = {'chunks': None, 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 2}
SPREAD = {'chunks': [3, 1, 5, 1, 2, 4, 1, 3, 2, 1, 1], 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 12}


def control_known_answers():
    try:
        B.known_answer_tests()
    except B.ControlFailure as exc:
        return False, str(exc)
    return True, 'frozen oracle known-answer tests'


def control_roundtrip():
    """Every synthetic table, encoded by this helper, decodes with the frozen parser to exactly the table."""
    bad = []
    for name, build in sorted(TABLES.items()):
        table = build()
        plan = dict(CANONICAL, chunks=[len(table)])
        request = B.controller_request(B.CTRL_CMD_GETFAMILY, DUMP_FLAGS, 0x1234)
        conversation = B.Conversation(0x1234, 77, True)
        try:
            for datagram in Controller(table, plan)(request, 77):
                conversation.feed(datagram)
            decoded = [B.parse_family(m['payload']) for m in conversation.messages]
        except (B.ProtocolError, RuntimeError) as exc:
            bad.append('%s: %s' % (name, exc))
            continue
        if not conversation.complete or decoded != table:
            bad.append('%s: decoded table differs' % name)
    return not bad, bad or 'every synthetic table encodes and decodes unchanged'


def control_probe_dump():
    controller = Controller(table_multipart(), SPREAD)
    supervisor, result = run_probe(controller, 'dump')
    request = bytes.fromhex(result['request'])
    planned = controller(request, result['pid'])
    checks = {'injected at the fixed descriptor': result['fd'] == K, 'sendmsg returned the request length': result['sent'] == len(request) == 20,
              'bind answered': supervisor.binds == 1, 'one socket, one sendmsg': supervisor.sockets == 1 and supervisor.sendmsgs == 1,
              'request decoded from memory equals the request sent': supervisor.requests == [request],
              'datagram boundaries and bytes preserved': result['datagram_sha256'] == [hashlib.sha256(d).hexdigest() for d in planned],
              'conversation complete with every record multipart': result['complete'] and result['multi'] and result['foreign'] == 0,
              'decoded families equal the table': result['families'] == table_multipart()}
    return all(checks.values()), checks


def control_probe_narrow():
    supervisor, result = run_probe(Controller([], SPREAD), 'narrow')
    checks = {'another netlink protocol is not injected': result['route_fd'] != K and result['route_name_is_pair'],
              'no notification for it': supervisor.sockets == 0 and supervisor.binds == 0 and supervisor.sendmsgs == 0}
    return all(checks.values()), checks


def real_kernel_dump():
    nl = B.Netlink('mock-kernel-transcript.jsonl')
    try:
        conversation = nl.dump('mock-kernel-dump')
        return conversation, B.families_of(conversation, 'mock-kernel-dump')
    finally:
        nl.close()


def real_plan(count):
    return dict(CANONICAL, chunks=[4] * (count // 4) + ([count % 4] if count % 4 else []),
                datagrams=count // 4 + (1 if count % 4 else 0) + 1)


def control_kernel_end_to_end():
    """The real guest table, served through the mock, reaches a client unchanged (semantic) and byte-identical per record."""
    conversation, families = real_kernel_dump()
    controller = Controller(families, real_plan(len(families)))
    supervisor, result = run_probe(controller, 'dump')
    request = bytes.fromhex(result['request'])
    mine = [encode_family(f, PROBE_SEQ, result['pid'], B.NLM_F_MULTI)[B.NLMSG.size:] for f in families]
    real = [m['payload'] for m in conversation.messages]
    checks = {'families through the mock equal the kernel dump': result['families'] == families and result['complete'],
              'request decoded from memory equals the request sent': supervisor.requests == [request]}
    bytes_equal = mine == real
    return all(checks.values()), checks, bytes_equal, [i for i, (a, b) in enumerate(zip(mine, real)) if a != b]


def control_kernel_like_errors():
    nl = B.Netlink('mock-kernel-lookup-transcript.jsonl')
    try:
        plain = nl.start('lookup-no-attribute', B.CTRL_CMD_GETFAMILY, B.NLM_F_REQUEST)
        nl.wait('lookup-no-attribute', [plain])
        unknown = nl.get_family('lookup-unknown-name', name='bashos_nofam')
        _conversation, families = real_kernel_dump()
    finally:
        nl.close()
    known = families[-1]
    supervisor, result = run_probe(Controller(families, real_plan(len(families))), 'lookups', [known['name'], str(known['id'])])
    by_label = {r['label']: r for r in result['results']}
    checks = {'plain GETFAMILY is refused with the kernel errno': by_label['no-attribute']['error'] == plain.error != 0,
              'unknown name is refused with the kernel errno': by_label['unknown-name']['error'] == unknown.error == errno.ENOENT,
              'known name and id return the family': by_label['known-name']['families'] == [known] == by_label['known-id']['families'],
              'four requests, four answers': supervisor.sendmsgs == 4 and supervisor.sockets == 1}
    return all(checks.values()), checks


def control_no_strays():
    try:
        done, _status = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        return True, 'no child process remains'
    return False, 'a child process is still present (pid %d)' % done


CONTROL_KEYS = {'base-known-answers': 'known answers', 'encoder-roundtrip': 'roundtrip', 'injection': 'probe dump',
                'boundaries': 'probe dump', 'decode-request': 'probe dump', 'narrow': 'probe narrow',
                'kernel-end-to-end': 'end to end', 'kernel-records': 'end to end', 'kernel-like-errors': 'errors', 'no-strays': 'strays'}


def run_controls():
    """All controls, none aborting another; returns {summary key: bool} and a detail report."""
    report, values = {}, {}

    def attempt(name, action):
        try:
            report[name] = action()
        except Exception as exc:  # a control that cannot run is a failed control, reported with its reason
            report[name] = (False, '%s: %s' % (type(exc).__name__, exc))

    attempt('known answers', control_known_answers)
    attempt('roundtrip', control_roundtrip)
    attempt('probe dump', control_probe_dump)
    attempt('probe narrow', control_probe_narrow)
    attempt('end to end', control_kernel_end_to_end)
    attempt('errors', control_kernel_like_errors)
    attempt('strays', control_no_strays)
    dump = report['probe dump']
    checks = dump[1] if isinstance(dump[1], dict) else {}
    values['base-known-answers'] = report['known answers'][0]
    values['encoder-roundtrip'] = report['roundtrip'][0]
    values['injection'] = bool(checks) and checks['injected at the fixed descriptor'] and checks['sendmsg returned the request length'] \
        and checks['bind answered'] and checks['one socket, one sendmsg']
    values['boundaries'] = bool(checks) and checks['datagram boundaries and bytes preserved'] \
        and checks['conversation complete with every record multipart']
    values['decode-request'] = bool(checks) and checks['request decoded from memory equals the request sent'] \
        and checks['decoded families equal the table']
    values['narrow'] = report['probe narrow'][0]
    e2e = report['end to end']
    values['kernel-end-to-end'] = e2e[0]
    values['kernel-records'] = len(e2e) > 2 and e2e[2] is True
    values['kernel-like-errors'] = report['errors'][0]
    values['no-strays'] = report['strays'][0]
    return values, report


# ---------------------------------------------------------------------------
# Scenarios: one entry per case; every line is one candidate invocation (or the control run).
# ---------------------------------------------------------------------------

# "needs": mock = injection controls, kernel = end-to-end control against the real guest table. The suite generator reads this
# literal with ast.literal_eval, so the pinned stdout and the printed lines cannot drift.
SCENARIOS = {
    'caps-matrix': {
        'needs': ['mock', 'kernel'],
        'lines': [
            {'label': 'flags-0x00-0x0f', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'caps-low', 'chunks': [1], 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 2},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes commands=yes caps-hex=yes word-admin=yes word-doit=yes '
                      'word-dumpit=yes word-haspol=yes words-exact=yes none-words=yes')},
            {'label': 'flags-0x10-0x1f', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'caps-uns', 'chunks': [1], 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 2},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes commands=yes caps-hex=yes word-admin=yes word-doit=yes '
                      'word-dumpit=yes word-haspol=yes words-exact=yes none-words=yes')},
            {'label': 'flags-unknown-bits', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'caps-unknown', 'chunks': [1], 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 2},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes commands=yes caps-hex=yes word-admin=yes word-doit=yes '
                      'word-dumpit=yes word-haspol=yes words-exact=yes none-words=yes')},
        ]},
    'multipart': {
        'needs': ['mock', 'kernel'],
        'lines': [
            {'label': 'done-separate', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'multipart', 'chunks': [3, 1, 5, 1, 2, 4, 1, 3, 2, 1, 1], 'done': 'separate', 'foreign': [],
                      'sentinel': True, 'datagrams': 12},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes families-complete=yes records=yes groups=yes commands=yes '
                      'caps-hex=yes recv-calls=12 consumed=12 unconsumed=1')},
            {'label': 'done-with-last-record', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'multipart', 'chunks': [4, 2, 6, 1, 5, 3, 2, 1], 'done': 'with-last', 'foreign': [],
                      'sentinel': True, 'datagrams': 8},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes families-complete=yes records=yes groups=yes commands=yes '
                      'caps-hex=yes recv-calls=8 consumed=8 unconsumed=1')},
            {'label': 'one-record-per-datagram', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'multipart', 'chunks': [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                      'done': 'separate', 'foreign': [], 'sentinel': True, 'datagrams': 25},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes families-complete=yes records=yes groups=yes commands=yes '
                      'caps-hex=yes recv-calls=25 consumed=25 unconsumed=1')},
            {'label': 'large-datagrams', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'large', 'chunks': [4, 4], 'done': 'separate', 'foreign': [], 'sentinel': True, 'datagrams': 3},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes families-complete=yes records=yes groups=yes commands=yes '
                      'caps-hex=yes recv-calls=3 consumed=3 unconsumed=1')},
        ]},
    'request-dump': {
        'needs': ['mock', 'kernel'],
        'lines': [
            {'label': 'list-request', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'caps-low', 'chunks': [1], 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 2},
             'keys': 'status=0 stderr=empty injected=yes request-dump=yes families-complete=yes'},
        ]},
    'lookup-requests': {
        'needs': ['mock', 'kernel'],
        'lines': [
            {'label': 'get-name', 'kind': 'mock-get', 'args': ['ctrl', 'get', 'name', 'mockcaps_lo'],
             'plan': {'table': 'lookup'},
             'keys': 'status=0 stderr=empty injected=yes request-name=yes exact=yes semantic=yes one-record=yes'},
            {'label': 'get-id-hex', 'kind': 'mock-get', 'args': ['ctrl', 'get', 'id', '0x21'],
             'plan': {'table': 'lookup'},
             'keys': 'status=0 stderr=empty injected=yes request-id=yes exact=yes semantic=yes one-record=yes'},
            {'label': 'get-id-decimal', 'kind': 'mock-get', 'args': ['ctrl', 'get', 'id', '32'],
             'plan': {'table': 'lookup'},
             'keys': 'status=0 stderr=empty injected=yes request-id=yes exact=yes semantic=yes one-record=yes'},
        ]},
    'exact': {
        'needs': ['mock', 'kernel'],
        'lines': [
            {'label': 'exact-mixed', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'mixed', 'chunks': [2, 3, 1], 'done': 'separate', 'foreign': [], 'sentinel': False, 'datagrams': 4},
             'keys': 'status=0 stderr=empty injected=yes request-dump=yes exact=yes semantic=yes'},
        ]},
    'foreign-sequence': {
        'needs': ['mock', 'kernel'],
        'lines': [
            {'label': 'foreign-own-and-inline', 'kind': 'mock-list', 'args': ['ctrl', 'list'],
             'plan': {'table': 'foreign-base', 'chunks': [2, 1], 'done': 'separate', 'foreign': [['own', 0], ['inline', 1]],
                      'sentinel': True, 'datagrams': 4},
             'keys': ('status=0 stderr=empty injected=yes request-dump=yes exact=yes foreign-ignored=yes recv-calls=4 consumed=4 '
                      'unconsumed=1')},
        ]},
    'control': {
        'needs': [],
        'lines': [
            {'label': 'mock-controls', 'kind': 'control',
             'keys': ('base-known-answers=yes encoder-roundtrip=yes injection=yes boundaries=yes decode-request=yes narrow=yes '
                      'kernel-end-to-end=yes kernel-records=yes kernel-like-errors=yes no-strays=yes')},
        ]},
}


def observe_scenario(shell, scenario):
    spec = SCENARIOS[scenario]
    printed = []
    for line in spec['lines']:
        label = line['label']
        if line['kind'] == 'control':
            controls, report = run_controls()
            values = {key: yes(controls[key]) for key in CONTROL_KEYS}
            observe({'scenario': scenario, 'label': label, 'values': values,
                     'report': {name: [bool(item[0]), item[1] if isinstance(item[1], (str, list, dict)) else str(item[1]),
                                       list(item[2:]) if len(item) > 2 else []] for name, item in report.items()}})
        else:
            plan = line['plan']
            table = TABLES[plan['table']]()
            controller = Controller(table, plan)
            argv = [shell, '--noprofile', '--norc', '-c', 'genl "$@"', 'genl-case'] + list(line['args'])
            supervisor = supervised(argv, controller)
            save_events(label, supervisor)
            values = mock_values(line, supervisor, table)
            expected = B.render_all(table if line['kind'] == 'mock-list' else [lookup_target(table, line['args'])[0]])
            observe({'scenario': scenario, 'label': label, 'argv': line['args'], 'status': supervisor.exit, 'timed_out': supervisor.timed_out,
                     'stdout_base64': base64.b64encode(supervisor.stdout).decode(), 'stderr_base64': base64.b64encode(supervisor.stderr).decode(),
                     'expected_stdout_base64': base64.b64encode(expected).decode(), 'values': values,
                     'errors': supervisor.errors, 'datagrams': {'planned': supervisor.total, 'delivered': supervisor.delivered,
                                                                'unread': supervisor.leftover, 'recv_calls': supervisor.recvmsgs}})
        keys = [item.partition('=')[0] for item in line['keys'].split()]
        missing = [key for key in keys if key not in values]
        if missing:
            raise RuntimeError('internal: no value computed for %s of %s' % (missing, label))
        printed.append(label + ' ' + ' '.join('%s=%s' % (key, values[key]) for key in keys))
    for text in printed:
        print(text, flush=True)


def setup(scenario):
    needs = set(SCENARIOS[scenario]['needs'])
    report = {'scenario': scenario, 'controls': []}
    if 'mock' in needs:
        for name, action in (('frozen known answers', control_known_answers), ('encoder round trip', control_roundtrip),
                             ('probe dump', control_probe_dump), ('probe narrow', control_probe_narrow)):
            try:
                ok, detail = action()
            except Exception as exc:  # an unexpected failure of a control is invalid evidence as well
                raise B.ControlFailure('%s raised %s: %s' % (name, type(exc).__name__, exc))
            if not ok:
                raise B.ControlFailure('%s failed: %s' % (name, detail))
            report['controls'].append(name)
    if 'kernel' in needs:
        try:
            ok, detail, bytes_equal, differing = control_kernel_end_to_end()
        except Exception as exc:
            raise B.ControlFailure('kernel end-to-end raised %s: %s' % (type(exc).__name__, exc))
        if not ok:
            raise B.ControlFailure('kernel end-to-end failed: %s' % detail)
        report['controls'].append('kernel end to end')
        report['kernel_records_byte_identical'] = bytes_equal
        report['kernel_records_differing'] = differing
    print(json.dumps(report, sort_keys=True), flush=True)


def main(argv):
    global B, LIB
    if len(argv) >= 2 and argv[0] == 'probe-child':
        require_guest()
        B = load_base()
        probe_child(argv[1], argv[2:])
        return 0
    if len(argv) != 2 or argv[1] not in SCENARIOS:
        sys.stderr.write('usage: genl-mock-observer.py setup|SHELL %s\n' % '|'.join(sorted(SCENARIOS)))
        return 2
    require_guest()
    B = load_base()
    LIB = load_seccomp()
    try:
        if argv[0] == 'setup':
            setup(argv[1])
        else:
            observe_scenario(argv[0], argv[1])
    except B.ControlFailure as exc:
        print('CONTROL-INVALID %s %s: %s' % ('setup' if argv[0] == 'setup' else 'observe', argv[1], exc), flush=True)
        return 97
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
