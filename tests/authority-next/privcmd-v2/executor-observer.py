#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent disposable-guest syscall observation; never an authority issuer.

The production executor translation unit is entered by a separately pinned test
bootstrap. Only one selected fault is substituted. Every other accepted call is
a real kernel call. Containment is recorded as a failure, never as proof of an
executor abort. No candidate result or missing target marker supplies the verdict.
"""
import array
import ctypes as C
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import time

ADDRESS = b'\0bashos-privcmd-v2-qualification-observer'
CALLS = {116: 'setgroups', 119: 'setresgid', 117: 'setresuid', 126: 'capset',
         118: 'getresuid', 120: 'getresgid', 122: 'setfsuid', 123: 'setfsgid',
         59: 'execve', 322: 'execveat', 60: 'exit', 231: 'exit_group',
         105: 'setuid', 106: 'setgid', 113: 'setreuid', 114: 'setregid'}
ORDER = ['setgroups', 'setresgid', 'setresuid', 'capset', 'getresuid',
         'getresgid', 'setfsuid', 'setfsgid']
FAULTS = ('none', 'setgroups', 'setresgid', 'setresuid', 'capset', 'getresuid',
          'getresgid', 'mismatch-getresuid', 'mismatch-getresgid')
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
LIBC = C.CDLL(None, use_errno=True)


class Iovec(C.Structure):
    _fields_ = [('base', C.c_void_p), ('length', C.c_size_t)]


for function in (LIBC.process_vm_readv, LIBC.process_vm_writev):
    function.argtypes = [C.c_int, C.POINTER(Iovec), C.c_ulong,
                         C.POINTER(Iovec), C.c_ulong, C.c_ulong]
    function.restype = C.c_ssize_t


def require(value, reason):
    if not value: raise RuntimeError(reason)


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(pid):
    root = Path('/proc', str(pid))
    fields = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines() if ':' in line)
    result = {k: [int(x) for x in fields[k].split()] for k in ('Uid', 'Gid', 'Groups')}
    result['Groups'].sort()
    result.update({k: int(fields[k], 16) for k in CAPS})
    result.update(pid=pid, ppid=int(fields['PPid']), threads=int(fields['Threads']),
                  nnp=int(fields['NoNewPrivs']), start=int((root / 'stat').read_text().rsplit(')', 1)[1].split()[19]))
    require(result['threads'] == 1, 'observer requires single-thread native actors')
    return result


def memory(pid, address, size, data=None):
    require(address and 0 < size <= 65536, 'invalid remote memory request')
    local = C.create_string_buffer(size)
    if data is not None:
        require(len(data) == size, 'remote write size differs')
        C.memmove(local, data, size)
    lv, rv = Iovec(C.cast(local, C.c_void_p), size), Iovec(address, size)
    function = LIBC.process_vm_readv if data is None else LIBC.process_vm_writev
    require(function(pid, C.byref(lv), 1, C.byref(rv), 1, 0) == size,
            'live remote memory operation failed: errno %s' % C.get_errno())
    return local.raw


def cstring(pid, address, limit=4096):
    # Byte reads avoid reading beyond a mapped page for short strings. All
    # pointers belong to the blocked, single-thread child and are bounded.
    out = bytearray()
    for i in range(limit):
        byte = memory(pid, address + i, 1)
        if byte == b'\0': return bytes(out)
        out.extend(byte)
    raise RuntimeError('unterminated remote string')


def strings(pid, address):
    out, size = [], 0
    for i in range(257):
        pointer = struct.unpack('<Q', memory(pid, address + 8 * i, 8))[0]
        if not pointer: return out
        require(i < 256, 'remote argv/env count exceeded')
        value = cstring(pid, pointer); size += len(value) + 1
        require(size <= 65536, 'remote argv/env size exceeded')
        out.append(value)
    raise RuntimeError('unterminated remote vector')


def same_ids(left, right):
    return all(left[k] == right[k] for k in ('Uid', 'Gid', 'Groups'))


def target_ids(value, config):
    return value['Uid'] == [config['uid']] * 4 and value['Gid'] == [config['gid']] * 4 and \
        value['Groups'] == sorted(config['groups']) and value['nnp'] == 1 and all(value[k] == 0 for k in CAPS)


def verdict(config, rows):
    """Classify raw observations without trusting the executor's response."""
    problems = []
    check = lambda ok, why: problems.append(why) if not ok else None
    selected = [r for r in rows if r.get('reply_origin') == 'selected-fault']
    setup = [r for r in rows if r.get('phase') == 'child-setup' and r.get('syscall') in ORDER]
    attempts = [r for r in rows if r.get('phase') == 'target-exec-attempt']
    child_exit = [r for r in rows if r.get('phase') == 'child-exit']
    monitor_exit = [r for r in rows if r.get('phase') == 'monitor-exit']
    opened = [r for r in rows if r.get('phase') == 'monitor-connected']
    check(len(opened) == len(monitor_exit) == 1, 'missing unique live monitor identity/exit')
    if len(opened) == len(monitor_exit) == 1:
        check(same_ids(opened[0]['identity'], monitor_exit[0]['identity']), 'monitor IDs changed')
        check(monitor_exit[0]['status'] == 0, 'monitor did not report completed protocol')
    check(len(child_exit) == 1, 'missing unique live child exit')
    check(not any(r.get('reply_origin') == 'containment-guard' for r in rows), 'containment intervened')
    check(not any(r.get('argument_mismatch') for r in rows), 'credential or exec arguments differ')
    fault = config['fault']
    if fault == 'none':
        check(not selected, 'unexpected fault injection')
        check([r['syscall'] for r in setup] == ORDER, 'successful credential sequence differs')
        check(len(attempts) == 1 and attempts[0].get('reply') == 'continue', 'target exec not observed exactly once')
        if attempts: check(target_ids(attempts[0]['identity'], config), 'target attempted with wrong live IDs/caps')
        if child_exit:
            check(child_exit[0]['status'] == 7, 'actual target did not exit 7')
            check(target_ids(child_exit[0]['identity'], config), 'live target exit IDs/caps differ')
            check(child_exit[0].get('executable_sha256') == config['target_sha256'], 'exit is not the actual target image')
    else:
        underlying = fault.removeprefix('mismatch-')
        expected = ORDER[:ORDER.index(underlying) + 1]
        if fault == 'mismatch-getresuid': expected = ORDER[:6]
        check([r['syscall'] for r in setup] == expected, 'executor did not stop after exact fault prefix')
        check(len(selected) == 1 and selected[0]['syscall'] == underlying, 'exactly one selected-fault origin required')
        check(not attempts, 'target exec attempted after selected fault')
        if child_exit:
            check(child_exit[0]['status'] == 126, 'setup failure did not terminate with 126')
            if selected:
                check(same_ids(child_exit[0]['identity'], selected[0]['identity']),
                      'live exit IDs differ from the selected fault point')
    for row in setup:
        if row not in selected:
            check(row.get('reply') == 'continue' and row.get('real_kernel_call') is True,
                  'unselected credential call was replaced')
    return {'status': 'FAIL' if problems else 'PASS', 'problems': problems,
            'fault': fault, 'selected_fault_count': len(selected), 'target_exec_attempts': len(attempts),
            'guard_denials': sum(r.get('reply_origin') == 'containment-guard' for r in rows),
            'child_exit_live_identity': child_exit[0]['identity'] if len(child_exit) == 1 else None,
            'literal_failed_syscall_ids_unchanged': bool(len(child_exit) == len(selected) == 1 and
                same_ids(child_exit[0]['identity'], selected[0]['identity'])),
            'scope': 'real kernel credential calls under a test-only observer bootstrap; no authentication shortcut'}


class Observer:
    def __init__(self, config, output):
        require(config['fault'] in FAULTS, 'unknown fault')
        self.config, self.output, self.rows = config, Path(output), []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.server.bind(ADDRESS); self.server.listen(1); self.server.settimeout(15)
        self.listener = self.monitor_fd = self.child_fd = None
        self.monitor = self.child = self.monitor_start = self.child_start = None
        self.injected = self.executed = False
        self.bootstrap_peer = None

    def log(self, row):
        require(len(self.rows) < 256, 'bounded observation count exceeded')
        self.rows.append(row)
        with self.output.with_suffix('.jsonl').open('a') as f: f.write(json.dumps(row, sort_keys=True) + '\n')

    def credentials(self, name, pid, args):
        uid, gid, groups = self.config['uid'], self.config['gid'], sorted(self.config['groups'])
        if name == 'setgroups':
            require(args[0] <= 128, 'group count exceeds input bound')
            observed = list(struct.unpack('<%dI' % args[0], memory(pid, args[1], args[0] * 4))) if args[0] else []
            return sorted(observed) == groups, {'groups': observed}
        if name in ('setresgid', 'setresuid'):
            values = [int(x & 0xffffffff) for x in args[:3]]
            return values == ([gid] if name == 'setresgid' else [uid]) * 3, {'ids': values}
        if name == 'capset':
            header = struct.unpack('<II', memory(pid, args[0], 8))
            bits = list(struct.unpack('<6I', memory(pid, args[1], 24)))
            return header == (0x20080522, 0) and bits == [0] * 6, {'header': list(header), 'caps': bits}
        if name in ('setfsuid', 'setfsgid'): return (args[0] & 0xffffffff) == 0xffffffff, {'query': args[0] & 0xffffffff}
        return name in ('getresuid', 'getresgid'), {}

    def notification(self, request):
        ident, pid, flags, number, arch, ip, *args = struct.unpack('<QIIiI7Q', request)
        require(flags == 0 and arch == 0xc000003e and number in CALLS, 'unexpected notification ABI')
        fcntl.ioctl(self.listener, 0x40082102, struct.pack('<Q', ident))
        name, live = CALLS[number], identity(pid)
        require(pid == self.monitor or live['ppid'] == self.monitor, 'notification is not the owned direct actor')
        if pid == self.monitor:
            require(live['start'] == self.monitor_start, 'monitor identity changed')
        elif self.child is None:
            self.child, self.child_start, self.child_fd = pid, live['start'], os.pidfd_open(pid)
        else: require(pid == self.child and live['start'] == self.child_start, 'extra/reused child identity')
        row = {'notification_id': ident, 'syscall': name, 'identity': live, 'args': args,
               'phase': 'monitor' if pid == self.monitor else 'target' if self.executed else 'child-setup',
               'reply': 'continue', 'reply_origin': 'real-kernel', 'real_kernel_call': True}
        error, value, response_flags = 0, 0, 1
        guard = False
        if name in ('exit', 'exit_group'):
            row.update(phase='monitor-exit' if pid == self.monitor else 'child-exit', status=args[0] & 255)
            row['executable_sha256'] = sha('/proc/%d/exe' % pid)
        elif pid == self.monitor:
            guard = True
        elif name in ('execve', 'execveat'):
            row['phase'] = 'target-exec-attempt'
            valid = name == 'execveat' and args[4] == 0x1000 and cstring(pid, args[1], 2) == b''
            if valid:
                path = Path('/proc', str(pid), 'fd', str(args[0]))
                st = path.stat(); expected = self.config['target_identity']
                valid = [st.st_dev, st.st_ino] == expected and sha(path) == self.config['target_sha256']
                argv, env = strings(pid, args[2]), strings(pid, args[3])
                row.update(argv_hex=[v.hex() for v in argv], env_sha256=hashlib.sha256(b'\0'.join(env) + b'\0').hexdigest())
                valid = valid and argv == [os.fsencode(self.config['target']), b'exit-7']
            row['argument_mismatch'] = not valid
            guard = self.injected or self.executed or not valid or not target_ids(live, self.config)
            if not guard: self.executed = True
        elif self.executed:
            valid, details = self.credentials(name, pid, args); row.update(details)
            # The fixed harmless target reads back IDs. It may not change them.
            guard = name not in ('getresuid', 'getresgid', 'setfsuid', 'setfsgid') or not valid
        else:
            valid, details = self.credentials(name, pid, args); row.update(details)
            row['argument_mismatch'] = not valid
            special = self.config.get('negative') == 'saved-root-id' and name == 'setresuid' and \
                details.get('ids') == [self.config['uid'], self.config['uid'], 0]
            guard = (not valid and not special) or (self.injected and not (
                self.config['fault'] == 'mismatch-getresuid' and name == 'getresgid'))
            chosen = not self.injected and name == self.config['fault'].removeprefix('mismatch-')
            if chosen and not guard:
                self.injected = True; response_flags = 0
                row.update(reply_origin='selected-fault', real_kernel_call=False)
                if self.config['fault'].startswith('mismatch-'):
                    target = self.config['uid'] if name == 'getresuid' else self.config['gid']
                    for address, word in zip(args[:3], (target, target, 0)):
                        memory(pid, address, 4, struct.pack('<I', word))
                    row.update(reply='synthetic-readback', injected_readback=[target, target, 0])
                else:
                    error = -errno.EPERM; row.update(reply='error', injected_errno=errno.EPERM)
            elif special and not guard:
                row['negative_control_real_saved_root_call'] = True
        if guard:
            error, response_flags = -errno.EPERM, 0
            row.update(reply='error', reply_origin='containment-guard', real_kernel_call=False,
                       denied_errno=errno.EPERM)
        # Validate again after live /proc and bounded memory reads. No call is
        # continued using a stale/reused seccomp notification identifier.
        fcntl.ioctl(self.listener, 0x40082102, struct.pack('<Q', ident))
        self.log(row)
        fcntl.ioctl(self.listener, 0xc0182101, struct.pack('<QqiI', ident, value, error, response_flags))
        return row['phase'] == 'monitor-exit'

    def run(self):
        result = {'status': 'ERROR', 'reason': 'observer did not finish'}
        connection = None
        def expired(_sig, _frame): raise RuntimeError('observer deadline exceeded')
        signal.signal(signal.SIGALRM, expired); signal.signal(signal.SIGTERM, expired); signal.alarm(40)
        try:
            connection, _ = self.server.accept()
            raw_peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, gid = struct.unpack('3i', raw_peer)
            self.bootstrap_peer = {
                'raw_so_peercred_hex': raw_peer.hex(), 'pid': pid, 'uid': uid, 'gid': gid,
                'observer_pid': os.getpid(),
                'observer_pid_namespace': os.readlink('/proc/self/ns/pid'),
                'observer_network_namespace': os.readlink('/proc/self/ns/net'),
                'visible_init_pid_namespace': os.readlink('/proc/1/ns/pid'),
                'failed_predicates': [name for name, passed in
                    (('root_uid', uid == 0), ('root_gid', gid == 0), ('visible_positive_pid', pid > 0)) if not passed]}
            self.log({'phase': 'bootstrap-peer-preflight', **self.bootstrap_peer})
            require(uid == gid == 0 and pid > 0, 'untrusted observer bootstrap peer')
            self.monitor, self.monitor_fd = pid, os.pidfd_open(pid)
            live = identity(pid); self.monitor_start = live['start']
            require(live['Uid'] == live['Gid'] == [0] * 4 and sha('/proc/%d/exe' % pid) == self.config['executor_sha256'],
                    'bootstrap identity/image differs')
            net = os.readlink('/proc/%d/ns/net' % pid)
            require(net == self.config['network_namespace'] == os.readlink('/proc/self/ns/net'),
                    'bootstrap did not enter the evaluator network namespace')
            # Admission is sent only after all original independent identity
            # checks succeed. The bootstrap has not installed seccomp yet.
            connection.sendall(b'\2')
            payload, ancillary, flags, _ = connection.recvmsg(8, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            require(payload == b'BAEXOBS\2' and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
                    len(ancillary) == 1, 'bootstrap handshake differs')
            level, kind, data = ancillary[0]
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS and len(data) == 4, 'listener descriptor differs')
            self.listener = array.array('i', data)[0]
            self.log({'phase': 'monitor-connected', 'identity': live, 'executable_sha256': self.config['executor_sha256'],
                      'network_namespace': net})
            connection.sendall(b'\1'); connection.close(); connection = None
            ended = False
            while not ended:
                ready = select.select([self.listener, self.monitor_fd], [], [], .2)[0]
                require(self.monitor_fd not in ready, 'monitor disappeared without a live exit notification')
                if self.listener not in ready: continue
                request = bytearray(80)
                try: fcntl.ioctl(self.listener, 0xc0502100, request, True)
                except OSError as e:
                    if e.errno in (errno.EINTR, errno.ENOENT): continue
                    raise
                ended = self.notification(request)
            require(select.select([self.monitor_fd], [], [], 5)[0], 'monitor did not exit after notification')
            result = verdict(self.config, self.rows)
            result['completed'] = True
        except Exception as error:
            result = {'status': 'ERROR', 'reason': type(error).__name__ + ': ' + str(error), 'completed': False}
        finally:
            signal.alarm(0)
            # Only pidfds opened for the identified monitor/direct child can be
            # signalled. A timeout is an observer ERROR, never a candidate PASS.
            for fd in (self.child_fd, self.monitor_fd):
                if fd is not None:
                    try:
                        if not select.select([fd], [], [], 0)[0]: signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError: pass
                    os.close(fd)
            if self.listener is not None: os.close(self.listener)
            if connection is not None: connection.close()
            self.server.close()
            result.update(config=self.config, observations=len(self.rows),
                          bootstrap_peer=self.bootstrap_peer,
                          syscall_observations=sum('syscall' in row for row in self.rows),
                          trace_sha256=sha(self.output.with_suffix('.jsonl')) if self.rows else None)
            self.output.write_text(json.dumps(result, indent=2) + '\n')
        return result
