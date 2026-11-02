#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-root SU client fixture: modeled token replies, real credential syscalls.

Only the authority descriptor and token ioctls are modeled. Credential calls
continue to Linux except for one explicitly selected errno/readback fault.
This does not establish the production authority's policy or token semantics.
Notification points do not capture syscall return values. Post-call identity
records read the kernel's live credentials, never retired stack buffers.
"""
import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import stat
import struct
import sys
import time
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
DEVICE = '/dev/bashos-auth'
MINT = 0xc078ba08
CONSUME = 0x4078ba09
ADD_FD = 0x40182103
TOKEN = bytes(range(32, 64))
CREDS = ('setgroups', 'setresgid', 'setresuid', 'getresuid', 'getresgid')
OTHER_CREDS = ('setuid', 'setgid', 'setreuid', 'setregid', 'setfsuid', 'setfsgid')


class Incomplete(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Incomplete(message)


def guard():
    require(__debug__ and platform.machine() == 'x86_64', 'unsupported interpreter or architecture')
    require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'guest root required')
    require(Path.cwd() == CASE and os.environ.get('HOME') == str(HOME), 'private scratch required')
    token = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU', 'QEMU guest required')
    require(Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'guest attestation differs')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'matching guest evaluator required')
    require(not os.path.lexists(DEVICE), 'real authority device must not be present')


def identity(pid):
    data = Path(f'/proc/{pid}/stat').read_bytes()
    fields = data.rsplit(b')', 1)[1].split()
    status = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        name, _, value = line.partition(':')
        if name in ('Uid', 'Gid', 'Groups'):
            status[name] = [int(x) for x in value.split()]
        elif name in ('CapEff', 'NoNewPrivs'):
            status[name] = value.strip()
    return {'pid': pid, 'ppid': int(fields[1]), 'pgrp': int(fields[2]),
            'session': int(fields[3]), 'birth': int(fields[19]), 'state': fields[0].decode(),
            **status}


def memory(pid, address, size, data=None):
    require(address > 0 and 0 <= size <= 65536, 'memory observation exceeds bounds')
    fd = os.open(f'/proc/{pid}/mem', (os.O_RDONLY if data is None else os.O_RDWR) | os.O_CLOEXEC)
    try:
        if data is None:
            value = os.pread(fd, size, address)
            require(len(value) == size, 'short tracee memory read')
            return value
        require(len(data) == size and os.pwrite(fd, data, address) == size, 'short tracee memory write')
    finally:
        os.close(fd)


def string(pid, address):
    result = bytearray()
    while len(result) < 4096:
        at = address + len(result)
        chunk = memory(pid, at, min(256, 4096 - len(result), 4096 - at % 4096))
        end = chunk.find(b'\0')
        if end >= 0:
            return os.fsdecode(bytes(result) + chunk[:end])
        result.extend(chunk)
    raise Incomplete('unterminated tracee string')


def vector(pid, address):
    result = []
    for index in range(128):
        pointer, = struct.unpack('<Q', memory(pid, address + index * 8, 8))
        if not pointer:
            return result
        result.append(string(pid, pointer))
    raise Incomplete('tracee vector exceeds bounds')


def main():
    guard()
    require(len(sys.argv) >= 4, 'configuration and program required')
    config_path = Path(sys.argv[1]).resolve()
    require(config_path.is_relative_to(CASE), 'configuration outside fixture')
    cfg = json.loads(config_path.read_text())
    trace = Path(cfg['trace']).resolve()
    require(trace.is_relative_to(HOME), 'trace outside private HOME')
    require(cfg['uid'] in (3101, 3102) and cfg['gid'] in (3201, 3202), 'unapproved fixture identity')
    require(set(cfg['groups']) <= {3201, 3202, 4101, 4102}, 'unapproved fixture groups')
    program = sys.argv[2:]
    require(program[0] in ('/opt/bashos-parity/candidate', '/usr/bin/python3'), 'unapproved program')
    if program[0] == '/usr/bin/python3':
        require(Path(program[-1]).resolve().is_relative_to(CASE), 'native control outside fixture')
    spec = importlib.util.spec_from_file_location('su_native_listener',
            '/opt/bashos-parity/harness/helpers/auth-client-listener.py')
    seq = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seq)
    seq.guest_guard = guard
    seq.BOOTSTRAP_LOG = Path(str(trace) + '.bootstrap')

    def supervise(lib, listener, child, *_unused):
        status = None
        deadline = time.monotonic() + 25
        devices, processes, observations = {}, {}, set()
        authorization_pid = None
        stage = 0
        injected = False
        target_executed = False
        events = 0
        with trace.open('w') as log:
            def emit(event):
                nonlocal events
                events += 1
                require(events <= 512, 'observation count exceeded')
                event.update(sequence=events, monotonic_ns=time.monotonic_ns())
                log.write(json.dumps(event, sort_keys=True) + '\n')
                log.flush()

            def owned(pid):
                current = identity(pid)
                if pid in processes:
                    require(processes[pid]['birth'] == current['birth'], 'tracee identity changed')
                else:
                    cursor = current
                    for _ in range(8):
                        if cursor['pid'] == child:
                            break
                        cursor = identity(cursor['ppid'])
                    else:
                        raise Incomplete('notification is not from the owned program tree')
                    processes[pid] = current
                return current

            def response(ident, kind='continue', value=0):
                fcntl.ioctl(listener, seq.NOTIF_SEND,
                            struct.pack('<QqiI', ident, value if kind == 'value' else 0,
                                        -value if kind == 'errno' else 0,
                                        seq.FLAG_CONTINUE if kind == 'continue' else 0))

            try:
                while status is None:
                    require(time.monotonic() < deadline, 'supervision deadline exceeded')
                    done, wait = os.waitpid(child, os.WNOHANG)
                    if done:
                        status = wait
                        break
                    if not select.select([listener], [], [], .05)[0]:
                        continue
                    request = bytearray(80)
                    try:
                        fcntl.ioctl(listener, seq.NOTIF_RECV, request, True)
                    except OSError as exc:
                        if exc.errno in (errno.EINTR, errno.ENOENT):
                            continue
                        raise
                    ident, pid, _, nr, arch, _ = struct.unpack_from('<QIIiIQ', request)
                    require(arch == 0xc000003e, 'unexpected syscall ABI')
                    # A canceled notification cannot support memory or identity evidence.
                    fcntl.ioctl(listener, 0x40082102, struct.pack('<Q', ident))
                    args = struct.unpack_from('<6Q', request, 32)
                    raw = lib.seccomp_syscall_resolve_num_arch(0, nr)
                    name = ctypes.cast(raw, ctypes.c_char_p).value.decode() if raw else str(nr)
                    current = owned(pid)
                    event = None
                    kind, value = 'continue', 0
                    if name in ('open', 'openat'):
                        index = 0 if name == 'open' else 1
                        path = string(pid, args[index])
                        if path == DEVICE:
                            require(authorization_pid is None, 'unexpected second authority opener')
                            require(current['Uid'] == [0] * 4, 'authority client is not guest root')
                            flags = args[index + 1] & 0xffffffff
                            fd = os.memfd_create('su-fixture-authority', os.MFD_CLOEXEC)
                            try:
                                info = os.fstat(fd)
                                add = bytearray(struct.pack('<QIIII', ident, 0, fd, 0,
                                                           os.O_CLOEXEC if flags & os.O_CLOEXEC else 0))
                                newfd = fcntl.ioctl(listener, ADD_FD, add, True)
                            finally:
                                os.close(fd)
                            devices[(info.st_dev, info.st_ino)] = {'minted': False, 'consumed': False}
                            authorization_pid = pid
                            kind, value = 'value', newfd
                            event = {'path': path, 'flags': flags, 'fd': newfd,
                                     'modeled_authority': True, 'device': [info.st_dev, info.st_ino]}
                    elif name == 'ioctl':
                        try:
                            info = os.stat(f'/proc/{pid}/fd/{args[0]}')
                            device = devices.get((info.st_dev, info.st_ino))
                        except OSError:
                            device = None
                        if device is not None:
                            require(pid == authorization_pid, 'authority descriptor crossed tracee identity')
                            operation = args[1] & 0xffffffff
                            if operation in (MINT, CONSUME):
                                payload = memory(pid, args[2], 120)
                                uid, gid, purpose, expiry, token, user, flags, reserved = struct.unpack('<IIII32s64sII', payload)
                                expected_user = cfg['user'].encode().ljust(64, b'\0')
                                valid = ((uid, gid, purpose, user, flags, reserved) ==
                                         (cfg['uid'], cfg['gid'], 2, expected_user, 0, 0))
                                kind, value = 'value', 0
                                if operation == MINT:
                                    valid = valid and expiry == 5 and token == bytes(32) and not device['minted']
                                    if valid:
                                        output = bytearray(payload)
                                        output[16:48] = TOKEN
                                        memory(pid, args[2], 120, bytes(output))
                                        device['minted'] = True
                                else:
                                    valid = valid and expiry == 0 and token == TOKEN and device['minted'] and not device['consumed']
                                    if valid:
                                        device['consumed'] = True
                                if not valid:
                                    kind, value = 'errno', errno.EPERM
                                event = {'request': hex(operation), 'input_hex': payload.hex(),
                                         'valid': valid, 'modeled_authority': True,
                                         'state': dict(device)}
                            else:
                                kind, value = 'errno', errno.ENOTTY
                                event = {'request': hex(operation), 'modeled_authority': True}
                    elif name in CREDS and pid == authorization_pid and not target_executed:
                        consumed = any(d['consumed'] for d in devices.values())
                        if consumed:
                            for label in sorted(observations):
                                emit({'syscall': 'kernel-identity-after-' + label, 'notifying': current,
                                      'real_kernel_credential_observation': True})
                            observations.clear()
                            event = {'args': list(args[:3]), 'stage': stage, 'real_kernel_call': True}
                            expected_name = CREDS[stage] if stage < len(CREDS) else None
                            if name == 'setgroups':
                                groups = list(struct.unpack('<' + 'I' * args[0], memory(pid, args[1], args[0] * 4))) if args[0] <= 16 else []
                                event['groups'] = groups
                                valid = sorted(groups) == sorted(cfg['groups'])
                            elif name in ('setresuid', 'setresgid'):
                                wanted = cfg['uid'] if name == 'setresuid' else cfg['gid']
                                valid = list(args[:3]) == [wanted] * 3
                            else:
                                valid = True
                            if expected_name != name or not valid:
                                kind, value = 'errno', errno.EPERM
                                event['invalid_order_or_arguments'] = True
                                event.update(real_kernel_call=False, reply_origin='containment-guard')
                            elif cfg.get('fault') == name and not injected:
                                kind, value = 'errno', errno.EPERM
                                injected = True
                                event['injected_errno'] = errno.EPERM
                                event['real_kernel_call'] = False
                                event['reply_origin'] = 'selected-fault'
                            elif cfg.get('fault') == 'mismatch-' + name and not injected:
                                require(name in ('getresuid', 'getresgid'), 'unsupported readback fault')
                                wanted = cfg['uid'] if name == 'getresuid' else cfg['gid']
                                for pointer, number in zip(args[:3], (wanted, wanted, 0)):
                                    memory(pid, pointer, 4, struct.pack('<I', number))
                                kind, value = 'value', 0
                                injected = True
                                event.update(injected_readback=[wanted, wanted, 0], real_kernel_call=False)
                                event['reply_origin'] = 'selected-fault'
                                stage += 1
                            else:
                                if name in ('getresuid', 'getresgid'):
                                    observations.add(name)
                                stage += 1
                    elif name in OTHER_CREDS and pid == authorization_pid:
                        kind, value = 'errno', errno.EPERM
                        event = {'args': list(args[:3]), 'invalid_order_or_arguments': True,
                                 'real_kernel_call': False, 'reply_origin': 'containment-guard'}
                    elif name in ('exit', 'exit_group') and pid == authorization_pid:
                        event = {'phase': 'actor-exit', 'status': args[0] & 255,
                                 'real_kernel_call': True}
                    elif name == 'execve':
                        path = string(pid, args[0])
                        if pid == child and not processes[pid].get('bootstrap_exec'):
                            require(path == program[0], 'bootstrap executable differs')
                            processes[pid]['bootstrap_exec'] = True
                            event = {'path': path, 'phase': 'bootstrap'}
                        elif pid == authorization_pid:
                            for label in sorted(observations):
                                emit({'syscall': 'kernel-identity-after-' + label, 'notifying': current,
                                      'real_kernel_credential_observation': True})
                            observations.clear()
                            argv, environ = vector(pid, args[1]), vector(pid, args[2])
                            allowed = path == cfg['shell'] and stage == len(CREDS) and not injected
                            event = {'path': path, 'argv': argv, 'env': environ,
                                     'cwd': os.readlink(f'/proc/{pid}/cwd'),
                                     'phase': 'target-exec', 'credential_stage': stage}
                            if not allowed:
                                kind, value = 'errno', errno.EPERM
                                event['unapproved_target'] = True
                                event.update(real_kernel_call=False, reply_origin='containment-guard')
                            else:
                                target_executed = True
                        else:
                            kind, value = 'errno', errno.EPERM
                            event = {'path': path, 'phase': 'unapproved-exec', 'real_kernel_call': False,
                                     'reply_origin': 'containment-guard'}
                    if event is not None:
                        event.update(syscall=name, notifying=current,
                                     reply=kind if kind == 'continue' else f'{kind}:{value}')
                        emit(event)
                    fcntl.ioctl(listener, 0x40082102, struct.pack('<Q', ident))
                    response(ident, kind, value)
            finally:
                if status is None:
                    for target, original in sorted(processes.items(), reverse=True):
                        try:
                            now = identity(target)
                            if now['birth'] == original['birth']:
                                fd = os.pidfd_open(target)
                                try:
                                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                                finally:
                                    os.close(fd)
                        except (FileNotFoundError, ProcessLookupError):
                            pass
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    status = os.waitpid(child, 0)[1]
                emit({'syscall': 'supervisor-end', 'raw_wait_status': status,
                      'credential_stage': stage, 'injected': injected,
                      'target_executed': target_executed, 'authorization_pid': authorization_pid})
        return status

    seq.supervise = supervise
    rules = []
    for name in ('open', 'openat', 'ioctl', 'execve', 'exit', 'exit_group', *CREDS, *OTHER_CREDS):
        rules += ['--notify', name]
    sys.argv = [str(Path(seq.__file__)), *rules, '--', *program]
    seq.main()


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException as error:
        print('su native observer incomplete: ' + repr(error), file=sys.stderr)
        raise SystemExit(125)
