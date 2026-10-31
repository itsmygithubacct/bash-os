#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only private-PID-namespace process-annotation race observer."""
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

HELPERS = '/opt/bashos-parity/harness/helpers'
sys.path.insert(0, HELPERS)
import ns_guest_identity_r1

HOME = Path('/tmp/parity-home')
SELF = HELPERS + '/ss-race-additive.py'
SHELL = '/opt/bashos-parity/candidate'
REFERENCE = '/opt/bash-5.3.15/bin/bash'
LIMIT = 65536
EVENT_LIMIT = 128
JOURNAL_LIMIT = 880000
JOURNAL_RESERVE = 4096
REPORT_LIMIT = 950000
TYPE_BEGIN = b'ss-race-type-begin\n'
TYPE_END = b'ss-race-type-end\n'
ARCH = 0xc000003e
TRACEME, PEEK, SYSCALL, GETREGS, SETREGS = 0, 2, 24, 12, 13
SETOPTIONS, GETINFO, GETEVENTMSG = 0x4200, 0x420e, 0x4201
OPTIONS = 1 | 2 | 4 | 8 | 16 | 0x100000
lib = ctypes.CDLL(None, use_errno=True)
lib.ptrace.restype = ctypes.c_long


class Incomplete(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Incomplete(message)


def call(op, pid=0, addr=0, data=0):
    ctypes.set_errno(0)
    v = lib.ptrace(op, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    error = ctypes.get_errno()
    if v == -1 and error: raise OSError(error, os.strerror(error))
    return v


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx',
                 'rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss',
                 'fs_base','gs_base','ds','es','fs','gs')]


def syscall_info(pid):
    buf = ctypes.create_string_buffer(128)
    n = call(GETINFO, pid, 128, ctypes.addressof(buf))
    raw = buf.raw
    require(n >= 24 and struct.unpack_from('=I', raw, 4)[0] == ARCH, 'unsupported syscall ABI')
    if raw[0] == 1 and n >= 80: return 'entry', struct.unpack_from('=7Q', raw, 24)
    if raw[0] == 2 and n >= 33: return 'exit', struct.unpack_from('=q', raw, 24)[0]
    raise Incomplete('unsupported syscall stop')


def peek(pid, addr, size):
    require(0 <= size <= LIMIT, 'trace read bound')
    skip = addr & 7
    base = addr - skip
    out = bytearray()
    while len(out) < size + skip:
        out.extend((call(PEEK, pid, base + len(out)) & ((1 << 64) - 1)).to_bytes(8, 'little'))
    return bytes(out[skip:skip + size])


def path_at(pid, addr):
    require(addr != 0, 'null path')
    data = bytearray()
    for pos in range(0, 512, 8):
        data.extend(peek(pid, addr + pos, 8))
        if b'\0' in data:
            return bytes(data).split(b'\0', 1)[0].decode('utf-8', 'strict')
    raise Incomplete('path length bound')


def raw(data):
    return {'base64': base64.b64encode(data).decode('ascii'), 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def process_identity(pid):
    row = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'state': row[0], 'ppid': int(row[1]), 'pgrp': int(row[2]),
            'session': int(row[3]), 'start_ticks': int(row[19])}


def close_except(keep):
    for item in os.listdir('/proc/self/fd'):
        fd = int(item)
        if fd >= 3 and fd not in keep:
            try: os.close(fd)
            except OSError: pass


def read_line(fd, seconds=4):
    deadline = time.monotonic() + seconds
    data = bytearray()
    while time.monotonic() < deadline and len(data) < 8192:
        ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
        if not ready: break
        part = os.read(fd, 1)
        if not part: break
        data.extend(part)
        if part == b'\n': return bytes(data)
    raise Incomplete('owner control deadline or line bound')


def owner():
    command_r, command_w = os.pipe()
    answer_r, answer_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(command_w); os.close(answer_r)
            close_except({command_r, answer_w})
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('127.0.0.1', 0)); sock.listen(4)
            data = {'pid': os.getpid(), 'fd': sock.fileno(), 'inode': os.fstat(sock.fileno()).st_ino,
                    'port': sock.getsockname()[1]}
            os.write(answer_w, (json.dumps(data, sort_keys=True) + '\n').encode())
            while True:
                cmd = os.read(command_r, 1)
                if cmd == b'C':
                    sock.close()
                    os.write(answer_w, b'closed\n')
                elif cmd == b'Q' or not cmd:
                    break
                else:
                    os._exit(125)
            sock.close()
            os.write(answer_w, b'bye\n')
            os._exit(0)
        except BaseException:
            os._exit(126)
    os.close(command_r); os.close(answer_w)
    try:
        data = json.loads(read_line(answer_r))
        require(data['pid'] == pid, 'owner PID mismatch')
        data['identity'] = process_identity(pid)
        require(data['identity']['ppid'] == os.getpid(), 'socket owner is not our child')
        data['comm'] = (Path('/proc') / str(pid) / 'comm').read_text().strip()
        path = '/proc/%d/fd/%d' % (pid, data['fd'])
        data['link_before'] = os.readlink(path)
        require(data['link_before'] == 'socket:[%d]' % data['inode'], 'owner socket identity')
        return {'pid': pid, 'command': command_w, 'answer': answer_r, 'facts': data, 'closed': False}
    except BaseException:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            got, _ = os.waitpid(pid, os.WNOHANG)
            if got: break
            time.sleep(.005)
        os.close(command_w); os.close(answer_r)
        raise


def close_owner_socket(item):
    before = process_identity(item['pid'])
    require(before['start_ticks'] == item['facts']['identity']['start_ticks'], 'owner identity changed')
    start = time.monotonic_ns()
    os.write(item['command'], b'C')
    ack = read_line(item['answer'])
    end = time.monotonic_ns()
    require(ack == b'closed\n', 'owner close acknowledgement')
    link = '/proc/%d/fd/%d' % (item['pid'], item['facts']['fd'])
    try:
        os.readlink(link)
    except FileNotFoundError:
        absent = True
    else:
        absent = False
    require(absent, 'descriptor still exists after close')
    item['closed'] = True
    return {'before': before, 'command_ns': start, 'ack_ns': end, 'ack': raw(ack),
            'link_absent': absent, 'identity_after': process_identity(item['pid'])}


def finish_owner(item):
    result = {'pid': item['pid'], 'forced': False}
    try:
        os.write(item['command'], b'Q')
        result['ack'] = raw(read_line(item['answer']))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            got, status = os.waitpid(item['pid'], os.WNOHANG)
            if got:
                result['wait_status'] = status
                break
            time.sleep(.005)
        else:
            raise Incomplete('owner reap deadline')
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        try: os.kill(item['pid'], signal.SIGKILL); result['forced'] = True
        except ProcessLookupError: pass
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try: got, status = os.waitpid(item['pid'], os.WNOHANG)
            except ChildProcessError: break
            if got:
                result['wait_status'] = status
                break
            time.sleep(.005)
        else:
            result['reap_incomplete'] = True
    finally:
        os.close(item['command']); os.close(item['answer'])
    result['clean'] = (not result['forced'] and not result.get('error') and
                       result.get('ack') == raw(b'bye\n') and os.WIFEXITED(result.get('wait_status', -1)) and
                       os.WEXITSTATUS(result['wait_status']) == 0)
    return result


def dirents(data):
    names = []
    offset = 0
    while offset < len(data):
        require(len(data) - offset >= 19, 'short linux_dirent64')
        length = struct.unpack_from('=H', data, offset + 16)[0]
        require(length >= 20 and offset + length <= len(data), 'invalid linux_dirent64')
        name = data[offset + 19:offset + length].split(b'\0', 1)[0]
        names.append(name.decode('ascii', 'strict'))
        offset += length
    return names


def snapshot(fd):
    data = bytearray()
    result = {'data': raw(b''), 'overflow': False, 'eof': False, 'stable': False, 'complete': False}
    try:
        before = os.fstat(fd)
        result['size'] = before.st_size
        while len(data) <= LIMIT:
            part = os.pread(fd, min(16384, LIMIT + 1 - len(data)), len(data))
            if not part:
                result['eof'] = True
                break
            data.extend(part)
        after = os.fstat(fd)
        result['overflow'] = len(data) > LIMIT
        result['stable'] = ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        result['complete'] = (stat.S_ISREG(before.st_mode) and result['eof'] and not result['overflow'] and
                              result['stable'] and len(data) == before.st_size)
    except OSError as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    result['data'] = raw(bytes(data[:LIMIT]))
    return result


def trace(program, mode, first, second, seconds=7):
    target_dir = '/proc/%d/fd' % first['pid']
    target_link = target_dir + '/%d' % first['facts']['fd']
    safe_dir = '/proc/%d/fd' % second['pid']
    safe_link = safe_dir + '/%d' % second['facts']['fd']
    result = {'argv': program, 'mode': mode, 'target_dir': target_dir, 'target_link': target_link,
              'safe_dir': safe_dir, 'safe_link': safe_link, 'events': [], 'complete': False,
              'descendant_attempted': False, 'forced_cleanup': False}
    out, err = tempfile.TemporaryFile(dir=HOME), tempfile.TemporaryFile(dir=HOME)
    gate_r, gate_w = os.pipe()
    pid = None
    reaped = False
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.close(gate_w)
                os.dup2(os.open('/dev/null', os.O_RDONLY), 0)
                os.dup2(out.fileno(), 1); os.dup2(err.fileno(), 2)
                close_except({gate_r})
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT + 1, LIMIT + 1))
                if os.read(gate_r, 1) != b'1': os._exit(126)
                os.close(gate_r)
                call(TRACEME)
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execve(program[0], program, {'HOME': str(HOME), 'PATH': '/empty', 'LC_ALL': 'C',
                                               'LANG': 'C', 'BASH_ENV': '', 'ENV': ''})
            except BaseException:
                os._exit(126)
        os.close(gate_r); gate_r = -1
        os.write(gate_w, b'1'); os.close(gate_w); gate_w = -1
        result['pid'] = pid
        deadline = time.monotonic() + seconds
        ready = exec_seen = enumerated = False
        pending = None
        while time.monotonic() < deadline:
            got, status = os.waitpid(pid, os.WNOHANG | 0x40000000)
            if not got:
                time.sleep(.001)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                reaped = True
                result['wait_status'] = status
                result['finished_ns'] = time.monotonic_ns()
                break
            require(os.WIFSTOPPED(status), 'invalid trace status')
            sig, event = os.WSTOPSIG(status), status >> 16
            if not ready:
                require(sig == signal.SIGSTOP, 'initial ptrace stop missing')
                result['initial_identity'] = process_identity(pid)
                require(result['initial_identity']['ppid'] == os.getpid(), 'tracee not owned')
                call(SETOPTIONS, pid, 0, OPTIONS)
                ready = True
                call(SYSCALL, pid)
                continue
            if event in (1, 2, 3):
                msg = ctypes.c_ulonglong()
                call(GETEVENTMSG, pid, 0, ctypes.addressof(msg))
                result['descendant_attempted'] = True
                result['descendant_pid'] = msg.value
                try:
                    descendant_fd = os.pidfd_open(msg.value)
                    try: signal.pidfd_send_signal(descendant_fd, signal.SIGKILL)
                    finally: os.close(descendant_fd)
                except (AttributeError, OSError) as exc:
                    result['cleanup_error'] = 'descendant signal: ' + str(exc)
                raise Incomplete('unexpected ptrace child event')
            if event == 4:
                require(not exec_seen, 'extra exec')
                info = process_identity(pid)
                actual = os.stat('/proc/%d/exe' % pid)
                wanted = os.stat(program[0])
                require(info['ppid'] == os.getpid() and info['start_ticks'] == result['initial_identity']['start_ticks'] and
                        (actual.st_dev, actual.st_ino) == (wanted.st_dev, wanted.st_ino), 'exec identity changed')
                result['exec_identity'] = dict(info, exe_dev=actual.st_dev, exe_ino=actual.st_ino)
                exec_seen = True
                call(SYSCALL, pid)
                continue
            if sig != signal.SIGTRAP | 0x80:
                call(SYSCALL, pid, 0, 0 if sig == signal.SIGTRAP else sig)
                continue
            op, value = syscall_info(pid)
            if op == 'entry':
                nr, *args = value
                pending = {'nr': nr, 'args': args, 'entry_ns': time.monotonic_ns()}
                if nr in (56, 57, 58, 109, 112, 435):
                    result['descendant_attempted'] = True
                    raise Incomplete('process creation is outside the controlled trace')
                if nr in (2, 257, 89, 267):
                    path_index = 0 if nr in (2, 89) else 1
                    p = path_at(pid, args[path_index])
                    if p in (target_dir, target_link, safe_dir, safe_link):
                        pending['path'] = p
                        if mode == 'denied' and p == target_dir and nr in (2, 257):
                            regs = Registers()
                            call(GETREGS, pid, 0, ctypes.addressof(regs))
                            require(regs.orig_rax == nr, 'unexpected open syscall register')
                            regs.orig_rax = (1 << 64) - 1
                            call(SETREGS, pid, 0, ctypes.addressof(regs))
                            pending['denied'] = True
                            pending['denial_set_ns'] = time.monotonic_ns()
                        if mode == 'race' and p == target_link and nr in (89, 267):
                            require(enumerated, 'readlink before witnessed enumeration')
                            require(not first['closed'], 'target descriptor already closed')
                            pending['close'] = close_owner_socket(first)
                if nr == 217:
                    try:
                        p = os.readlink('/proc/%d/fd/%d' % (pid, args[0]))
                    except OSError:
                        p = ''
                    if p in (target_dir, safe_dir): pending['directory'] = p
            else:
                if pending is None:
                    call(SYSCALL, pid)
                    continue
                nr, args = pending['nr'], pending['args']
                stamp = time.monotonic_ns()
                if pending.get('denied'):
                    regs = Registers()
                    call(GETREGS, pid, 0, ctypes.addressof(regs))
                    pending['kernel_result'] = value
                    require(value == -errno.ENOSYS, 'suppressed open did not return ENOSYS')
                    regs.rax = (-errno.EACCES) & ((1 << 64) - 1)
                    call(SETREGS, pid, 0, ctypes.addressof(regs))
                    verify = Registers()
                    call(GETREGS, pid, 0, ctypes.addressof(verify))
                    require(verify.rax == regs.rax, 'denial result did not stick')
                    value = -errno.EACCES
                    pending['injected_result'] = value
                if nr == 217 and pending.get('directory') and value > 0:
                    require(value <= LIMIT and value <= args[2], 'dirent bound')
                    contents = peek(pid, args[1], value)
                    names = dirents(contents)
                    pending['dirent_bytes'] = raw(contents)
                    pending['names'] = names
                    if pending['directory'] == target_dir and str(first['facts']['fd']) in names:
                        enumerated = True
                        pending['target_enumerated'] = True
                if pending.get('path') and nr in (89, 267) and value >= 0:
                    buffer_index, size_index = (1, 2) if nr == 89 else (2, 3)
                    require(value <= min(args[size_index], LIMIT), 'readlink result bound')
                    pending['link_bytes'] = raw(peek(pid, args[buffer_index], value))
                if pending.get('path') or pending.get('directory'):
                    pending['result'] = value
                    pending['exit_ns'] = stamp
                    pending['task'] = result.get('exec_identity')
                    result['events'].append(pending)
                    require(len(result['events']) <= EVENT_LIMIT, 'event count bound')
                pending = None
            call(SYSCALL, pid)
        require(reaped, 'trace deadline')
        result['complete'] = True
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if pid is not None and not reaped:
            result['forced_cleanup'] = True
            try:
                fd = os.pidfd_open(pid)
                try: signal.pidfd_send_signal(fd, signal.SIGKILL)
                finally: os.close(fd)
            except (OSError, AttributeError) as exc:
                result['cleanup_error'] = type(exc).__name__ + ': ' + str(exc)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try: got, status = os.waitpid(pid, os.WNOHANG | 0x40000000)
                except ChildProcessError: break
                if got and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    result['wait_status'] = status; reaped = True; break
                if got and os.WIFSTOPPED(status):
                    try: call(SYSCALL, pid, 0, signal.SIGKILL)
                    except OSError: pass
                time.sleep(.005)
            if not reaped: result['cleanup_error'] = 'tracee reap deadline'
        result['reaped'] = reaped
        if gate_r >= 0: os.close(gate_r)
        if gate_w >= 0: os.close(gate_w)
        result['stdout'] = snapshot(out.fileno())
        result['stderr'] = snapshot(err.fileno())
        out.close(); err.close()
    return result


def natural_status(result):
    status = result.get('wait_status')
    if (result.get('complete') and result.get('reaped') and result.get('exec_identity') and
        not result.get('error') and not result.get('forced_cleanup') and
        not result.get('cleanup_error') and not result.get('descendant_attempted') and
        isinstance(status, int) and os.WIFEXITED(status) and
        result.get('stdout', {}).get('complete') and result.get('stderr', {}).get('complete')):
        return os.WEXITSTATUS(status)
    return None


def normal_status(result):
    return natural_status(result) == 0


def type_script(name, body, setup=''):
    # The type check and target builtin execute in the same shell task. No
    # command substitution, pipeline, external utility or background job.
    return (setup + "builtin printf 'ss-race-type-begin\\n' >&2 || exit 98\n"
            + 'builtin type -t ' + name + ' >&2 || exit 99\n'
            + "builtin printf 'ss-race-type-end\\n' >&2 || exit 98\n" + body)


def type_observation(tr):
    if not tr.get('stderr', {}).get('complete'):
        return {'state': 'incomplete'}
    stderr = b64(tr, 'stderr')
    required = TYPE_BEGIN + b'builtin\n' + TYPE_END
    if stderr.startswith(required):
        return {'state': 'builtin', 'prefix_bytes': len(required)}
    if stderr.startswith(TYPE_BEGIN) and TYPE_END not in stderr:
        return {'state': 'unavailable-or-error'}
    return {'state': 'ambiguous'}


def run_one(label, trace_mode, command_kind, checkpoint):
    first = second = None
    report = {'label': label, 'mode': trace_mode, 'kind': command_kind, 'complete': False}
    try:
        first = owner(); second = owner()
        report['target_owner'] = first['facts']
        report['unaffected_owner'] = second['facts']
        first_dir = '/proc/%d/fd' % first['pid']
        first_link = first_dir + '/%d' % first['facts']['fd']
        second_link = '/proc/%d/fd/%d' % (second['pid'], second['facts']['fd'])
        if command_kind == 'candidate':
            command = [SHELL, '--noprofile', '--norc', '-c', type_script('ss', 'builtin ss -tnlp\n')]
        elif command_kind in ('type-positive', 'type-missing', 'type-disabled'):
            name = {'type-positive': 'printf', 'type-missing': '__ss_race_missing_builtin__',
                    'type-disabled': 'true'}[command_kind]
            setup = 'builtin enable -n true || exit 98\n' if command_kind == 'type-disabled' else ''
            command = [REFERENCE, '--noprofile', '--norc', '-c',
                       type_script(name, "builtin printf 'ss-race-type-control\\n'\n", setup)]
        elif command_kind == 'native-ss':
            command = ['/usr/bin/ss', '-tnlp']
        else:
            probe = ("import os,sys\n"
                     "d,p,q,n=sys.argv[1:5]\n"
                     "names=os.listdir(d) if sys.argv[5]=='race' else []\n"
                     "if sys.argv[5]=='race': print('enumerated='+str(n in names))\n"
                     "try:\n"
                     " if sys.argv[5]=='race': os.readlink(p)\n"
                     " else: f=os.open(d,os.O_RDONLY|os.O_DIRECTORY); os.close(f)\n"
                     " print('target=ok')\n"
                     "except OSError as e: print('target='+str(e.errno))\n"
                     "f=os.open(os.path.dirname(q),os.O_RDONLY|os.O_DIRECTORY); os.close(f)\n"
                     "print('safe-open=ok')\n"
                     "print('safe='+os.readlink(q))\n")
            command = ['/usr/bin/python3', '-c', probe, first_dir, first_link, second_link,
                       str(first['facts']['fd']), 'race' if trace_mode == 'race' else 'open']
        observation = trace(command, trace_mode, first, second,
                            seconds=3 if command_kind.startswith('type-') else 7)
        report['trace'] = observation
        # Retain the reached trace while its owners and captured facts still
        # exist.  It is provisional until the matching teardown is recorded.
        report['trace_checkpoint'] = checkpoint(report)
        if command_kind == 'candidate' or command_kind.startswith('type-'):
            report['type_observation'] = type_observation(observation)
        # A completed, nonzero candidate is retained for independent product
        # assessment; tracer and containment failures are infrastructure data.
        require(observation.get('reaped') and not observation.get('cleanup_error'), 'trace cleanup uncertain')
        try:
            report['safe_link_after'] = os.readlink(second_link)
            report['safe_identity_after'] = process_identity(second['pid'])
        except OSError as exc:
            report['safe_after_error'] = type(exc).__name__ + ': ' + str(exc)
        report['complete'] = bool(observation.get('complete'))
    except BaseException as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        report['teardown'] = []
        for item in (second, first):
            if item is None:
                continue
            try:
                report['teardown'].append(finish_owner(item))
            except BaseException as exc:
                report['teardown'].append({'pid': item['pid'], 'clean': False,
                                           'error': type(exc).__name__ + ': ' + str(exc)})
        if not all(x.get('clean') for x in report['teardown']):
            report['cleanup_incomplete'] = True
    return report


def b64(result, name):
    return base64.b64decode(result[name]['data']['base64'], validate=True)


def native_control_ok(report, mode):
    tr = report.get('trace', {})
    if not report.get('complete') or report.get('cleanup_incomplete') or not normal_status(tr): return False
    output = b64(tr, 'stdout')
    suffix = ('safe-open=ok\nsafe=socket:[%d]\n' % report['unaffected_owner']['inode']).encode()
    if not output.endswith(suffix) or b64(tr, 'stderr'): return False
    events = tr['events']
    if mode == 'baseline': return output == b'target=ok\n' + suffix
    if mode == 'denied':
        return (output == b'target=13\n' + suffix and
                any(e.get('path') == tr['target_dir'] and e.get('injected_result') == -errno.EACCES for e in events))
    if mode == 'race':
        return (output == b'enumerated=True\ntarget=2\n' + suffix and
                any(e.get('directory') == tr['target_dir'] and e.get('target_enumerated') for e in events) and
                any(e.get('path') == tr['target_link'] and e.get('result') == -errno.ENOENT and
                    e.get('close', {}).get('link_absent') for e in events))
    return False


def type_control_ok(report, kind):
    tr = report.get('trace', {})
    if not report.get('complete') or report.get('cleanup_incomplete'):
        return False
    status = natural_status(tr)
    if status is None:
        return False
    stdout, stderr = b64(tr, 'stdout'), b64(tr, 'stderr')
    if kind == 'type-positive':
        return (status == 0 and stdout == b'ss-race-type-control\n' and
                stderr == TYPE_BEGIN + b'builtin\n' + TYPE_END and
                report['type_observation']['state'] == 'builtin')
    return (kind in ('type-missing', 'type-disabled') and status == 99 and not stdout and
            stderr.startswith(TYPE_BEGIN) and TYPE_END not in stderr and
            report['type_observation']['state'] == 'unavailable-or-error')


OWNER_TUPLE = re.compile(r'\("([^"\\\r\n]*)",pid=([0-9]+),fd=([0-9]+)\)')


def owner_tuples(line):
    fields = list(re.finditer(r'(?:^|\s)users:\((.*)\)(?=\s|$)', line))
    if len(fields) != 1: return None
    value = fields[0].group(1)
    offset = 0
    rows = []
    while offset < len(value):
        match = OWNER_TUPLE.match(value, offset)
        if match is None: return None
        rows.append((match.group(1), int(match.group(2)), int(match.group(3))))
        offset = match.end()
        if offset < len(value):
            if value[offset] != ',': return None
            offset += 1
    return rows or None


def parser_controls():
    samples = [
        ('single', 'x users:(("python3",pid=42,fd=4))', [('python3', 42, 4)]),
        ('multiple', 'x users:(("python3",pid=42,fd=4),("other",pid=8,fd=9))',
         [('python3', 42, 4), ('other', 8, 9)]),
        ('split-identity', 'x users:(("python3",pid=7,fd=8),("other",pid=42,fd=4))',
         [('python3', 7, 8), ('other', 42, 4)]),
        ('fake-prefix', 'x fakeusers:(("python3",pid=42,fd=4))', None),
        ('malformed', 'x users:(("python3",pid=42,fd=4)garbage)', None)]
    return [{'name': name, 'input': line, 'expected': expected, 'actual': owner_tuples(line)}
            for name, line, expected in samples]


def native_listing_ok(report):
    trace_result = report.get('trace', {})
    if not report.get('complete') or report.get('cleanup_incomplete') or not normal_status(trace_result):
        return False
    try:
        if b64(trace_result, 'stderr'):
            return False
        lines = b64(trace_result, 'stdout').decode('utf-8', 'strict').splitlines()
        for fact in (report['target_owner'], report['unaffected_owner']):
            endpoint = '127.0.0.1:' + str(fact['port'])
            expected = (fact['comm'], fact['pid'], fact['fd'])
            matches = [line for line in lines if endpoint in line.split() and
                       expected in (owner_tuples(line) or [])]
            if len(matches) != 1:
                return False
        return True
    except (ValueError, KeyError, UnicodeError):
        return False


def ns_id(name):
    st = os.stat('/proc/self/ns/' + name)
    return [st.st_dev, st.st_ino]


def journal_write(fd, value, reserve=JOURNAL_RESERVE):
    """Append and sync one complete record; a partial tail never replaces a prefix."""
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    evidence = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    if os.fstat(fd).st_size + len(data) > JOURNAL_LIMIT - reserve:
        return False, evidence
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if count <= 0: raise Incomplete('journal short write')
        offset += count
    os.fsync(fd)
    return True, evidence


def private_inner(mode):
    ns_guest_identity_r1.verify()
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0 and
            os.getpid() == 1, 'not the private namespace init')
    def mapping(name):
        with open('/proc/self/' + name, 'rb') as stream:
            data = stream.read(513)
        require(0 < len(data) <= 512 and data.decode('ascii').split() == ['0', '2000', '1'],
                'unexpected user mapping: ' + name)
        return data
    uid_map, gid_map = mapping('uid_map'), mapping('gid_map')
    outer_identity = json.loads(os.environ['SS_OUTER_IDENTITY'])
    require(isinstance(outer_identity, dict) and
            all(outer_identity.get(key) == 2000 for key in ('uid', 'euid', 'gid', 'egid')) and
            outer_identity.get('cwd') == '/tmp/parity-case' and outer_identity.get('home') == str(HOME) and
            outer_identity.get('guard') == 'ns_guest_identity_r1.verify-returned', 'outer identity mismatch')
    namespace = {kind: ns_id(kind) for kind in ('pid', 'mnt', 'net')}
    outer_namespace = {}
    for kind in namespace:
        before = [int(x) for x in os.environ['SS_OUTER_' + kind.upper()].split(':')]
        require(len(before) == 2 and namespace[kind] != before, 'namespace not private: ' + kind)
        outer_namespace[kind] = before
    proc_self = os.readlink('/proc/self')
    require(proc_self == '1', 'proc is not mounted for private PID namespace')
    numeric = sorted(int(x) for x in os.listdir('/proc') if x.isdigit())
    require(numeric == [1], 'unexpected processes in private PID namespace')
    with open('/proc/net/dev', 'rb') as stream:
        netdev = stream.read(LIMIT + 1)
    require(len(netdev) <= LIMIT, 'network device table bound')
    interfaces = [line.split(b':', 1)[0].strip().decode('ascii')
                  for line in netdev.splitlines()[2:] if b':' in line]
    require(interfaces == ['lo'], 'not isolated loopback-only network namespace')
    identity = {'guard': 'ns_guest_identity_r1.verify-returned', 'uid': os.getuid(), 'euid': os.geteuid(),
                'gid': os.getgid(), 'egid': os.getegid(), 'pid': os.getpid(), 'proc_self': proc_self,
                'cwd': str(Path.cwd()), 'home': os.environ.get('HOME'),
                'uid_map_raw': raw(uid_map), 'gid_map_raw': raw(gid_map)}
    report = {'schema': 'ss-race-additive-v3', 'mode': mode, 'namespace': namespace,
              'outer_namespace': outer_namespace, 'identity': identity, 'outer_identity': outer_identity,
              'uid_map': '0 2000 1', 'gid_map': '0 2000 1', 'pid_before': numeric,
              'network_devices': raw(netdev), 'runs': [], 'complete': False,
              'coverage_claim': False, 'started_ns': time.monotonic_ns()}
    report['parser_controls'] = parser_controls()
    runs = [('native-type-positive', 'baseline', 'type-positive'),
            ('native-type-missing', 'baseline', 'type-missing'),
            ('native-type-disabled', 'baseline', 'type-disabled'),
            ('native-open-positive', 'baseline', 'probe'),
            ('native-fault-control', mode, 'probe'),
            ('native-listing-positive', 'baseline', 'native-ss'),
            ('candidate-listing-positive', 'baseline', 'candidate'),
            ('candidate-fault', mode, 'candidate')]
    journal_path = HOME / ('ss-race-additive-' + mode + '.jsonl')
    fd = os.open(journal_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    report['journal'] = {'file': journal_path.name, 'limit': JOURNAL_LIMIT, 'stages': []}
    try:
        written, header = journal_write(fd, {'kind': 'header', 'schema': 'ss-race-journal-v2',
                                             'mode': mode, 'namespace': namespace,
                                             'outer_namespace': outer_namespace, 'identity': identity,
                                             'outer_identity': outer_identity,
                                             'uid_map': report['uid_map'], 'gid_map': report['gid_map'],
                                             'pid_before': numeric, 'network_devices': report['network_devices'],
                                             'started_ns': report['started_ns'],
                                             'parser_controls': report['parser_controls']})
        require(written, 'journal header limit')
        report['journal']['header'] = header
        journal_broken = False
        try:
            require(all(row['actual'] == row['expected'] for row in report['parser_controls']),
                    'owner parser control failed')
            for index, (label, selected, kind) in enumerate(runs):
                checkpoint_state = {'attempted': False, 'io_error': False, 'overflow': None}
                def checkpoint(snapshot):
                    checkpoint_state['attempted'] = True
                    entry = {'kind': 'run-trace', 'mode': mode, 'index': index, 'label': label,
                             'provisional': True, 'data': snapshot}
                    try:
                        written, info = journal_write(fd, entry)
                    except BaseException:
                        checkpoint_state['io_error'] = True
                        raise
                    if not written:
                        checkpoint_state['overflow'] = info
                        raise Incomplete('trace checkpoint journal budget exceeded')
                    return info
                item = run_one(label, selected, kind, checkpoint)
                report['runs'].append(item)
                if 'trace_checkpoint' not in item:
                    report['error'] = label + ': trace checkpoint unavailable'
                    if checkpoint_state['overflow'] is not None:
                        marker = {'kind': 'overflow', 'phase': 'trace', 'mode': mode,
                                  'index': index, 'label': label, **checkpoint_state['overflow']}
                        ok, info = journal_write(fd, marker, reserve=2048)
                        require(ok, 'journal overflow marker limit')
                        report['journal']['overflow'] = info
                    elif checkpoint_state['io_error']:
                        # A partial record may already exist.  Preserve earlier
                        # complete lines and do not append a misleading footer.
                        journal_broken = True
                    else:
                        entry = {'kind': 'run-unreached', 'mode': mode, 'index': index,
                                 'label': label, 'data': item}
                        ok, info = journal_write(fd, entry, reserve=2048)
                        require(ok, 'journal unreached record limit')
                        report['journal']['stages'].append({'label': label, 'unreached': info})
                    break
                problem = None
                try:
                    if item.get('cleanup_incomplete') or item.get('trace', {}).get('cleanup_error'):
                        problem = label + ': cleanup uncertain; no dependent operations'
                    elif kind.startswith('type-'):
                        item['type_control_valid'] = type_control_ok(item, kind)
                        if not item['type_control_valid']: problem = label + ': type control unavailable'
                    elif kind == 'probe':
                        item['native_control_valid'] = native_control_ok(item, selected)
                        if not item['native_control_valid']: problem = label + ': native control unavailable'
                    elif kind == 'native-ss':
                        item['native_listing_valid'] = native_listing_ok(item)
                        if not item['native_listing_valid']: problem = label + ': native listing unavailable'
                    elif kind == 'candidate':
                        if natural_status(item.get('trace', {})) is None:
                            problem = label + ': candidate trace or capture incomplete'
                        elif item.get('type_observation', {}).get('state') != 'builtin':
                            problem = label + ': candidate builtin availability unqualified'
                except Exception as exc:
                    item['assessment_error'] = type(exc).__name__ + ': ' + str(exc)
                    problem = label + ': control assessment incomplete'
                # The separate final record binds teardown and evaluation to
                # the earlier provisional trace without duplicating its bytes.
                pre_fields = {'label', 'mode', 'kind', 'target_owner', 'unaffected_owner', 'trace'}
                delta = {key: value for key, value in item.items() if key not in pre_fields}
                entry = {'kind': 'run-end', 'mode': mode, 'index': index, 'label': label,
                         'trace_checkpoint': item['trace_checkpoint'], 'finished_ns': time.monotonic_ns(),
                         'delta': delta, 'problem': problem}
                written, info = journal_write(fd, entry, reserve=2048)
                if not written:
                    report['error'] = label + ': journal finalization budget exceeded'
                    marker = {'kind': 'overflow', 'phase': 'final', 'mode': mode,
                              'index': index, 'label': label, **info}
                    ok, overflow = journal_write(fd, marker, reserve=1024)
                    require(ok, 'journal overflow marker limit')
                    report['journal']['overflow'] = overflow
                    break
                report['journal']['stages'].append({'label': label, 'trace': item['trace_checkpoint'],
                                                    'final': info})
                if problem:
                    report['error'] = problem
                    break
        except Exception as exc:
            report['error'] = type(exc).__name__ + ': ' + str(exc)
            # An I/O exception can leave a partial tail; do not append to it.
            journal_broken = True
        report['finished_ns'] = time.monotonic_ns()
        report['complete'] = len(report['runs']) == len(runs) and not report.get('error')
        if not journal_broken:
            try:
                written, footer = journal_write(fd, {'kind': 'end', 'mode': mode, 'complete': report['complete'],
                                                    'run_count': len(report['runs']), 'error': report.get('error')}, reserve=0)
                require(written, 'journal footer limit')
                report['journal']['footer'] = footer
            except Exception as exc:
                report['complete'] = False
                report['error'] = 'journal footer: ' + type(exc).__name__ + ': ' + str(exc)
        report['journal']['bytes'] = os.fstat(fd).st_size
    finally:
        os.close(fd)
    path = HOME / ('ss-race-additive-' + mode + '.json')
    data = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(data) <= REPORT_LIMIT, 'report byte budget; retained journal remains authoritative for earlier stages')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    return 0 if report['complete'] else 125


def outer_limit():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # The namespace reporter and append-only journal have larger budgets than
    # traced children, which explicitly lower their own file limit in trace().
    resource.setrlimit(resource.RLIMIT_FSIZE, (REPORT_LIMIT + 1, REPORT_LIMIT + 1))


def private_outer(mode):
    ns_guest_identity_r1.verify()
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 2000, 'outer uid/gid')
    require(os.uname().machine == 'x86_64', 'unsupported architecture')
    path = HOME / ('ss-race-additive-' + mode + '.json')
    journal_path = HOME / ('ss-race-additive-' + mode + '.jsonl')
    require(not path.exists() and not path.is_symlink() and
            not journal_path.exists() and not journal_path.is_symlink(), 'existing diagnostic path')
    env = {'HOME': str(HOME), 'PATH': '/empty', 'LC_ALL': 'C', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    outer_identity = {'guard': 'ns_guest_identity_r1.verify-returned', 'uid': os.getuid(), 'euid': os.geteuid(),
                      'gid': os.getgid(), 'egid': os.getegid(), 'cwd': str(Path.cwd()), 'home': os.environ.get('HOME')}
    env['SS_OUTER_IDENTITY'] = json.dumps(outer_identity, sort_keys=True, separators=(',', ':'))
    outer_namespace = {}
    for kind in ('pid', 'mnt', 'net'):
        outer_namespace[kind] = ns_id(kind)
        env['SS_OUTER_' + kind.upper()] = ':'.join(str(x) for x in outer_namespace[kind])
    command = ['/usr/bin/unshare', '--user', '--map-root-user', '--pid', '--fork', '--mount-proc', '--net',
               '/usr/bin/python3', '-B', SELF, 'inner', mode, SHELL]
    result = {'command': command, 'outer_identity': outer_identity, 'outer_namespace': outer_namespace,
              'started_ns': time.monotonic_ns(), 'timed_out': False, 'forced': False}
    out, err = tempfile.TemporaryFile(dir=HOME), tempfile.TemporaryFile(dir=HOME)
    proc = None
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                env=env, start_new_session=True, preexec_fn=outer_limit)
        result['supervisor_pid'] = proc.pid
        deadline = time.monotonic() + 49
        observed = None
        while time.monotonic() < deadline:
            observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is not None: break
            time.sleep(.01)
        if observed is None:
            result['timed_out'] = True
        else:
            result['waitid'] = {'pid': observed.si_pid, 'code': observed.si_code, 'status': observed.si_status}
        # A complete inner report can only be published after its owned tasks
        # have been reaped. Otherwise keep the direct supervisor unreaped as
        # the private group anchor while stopping every remaining member.
        complete = False
        if observed is not None and path.is_file():
            with path.open('rb') as source:
                data = source.read(REPORT_LIMIT + 1)
            if len(data) <= REPORT_LIMIT:
                try: complete = bool(json.loads(data).get('complete'))
                except (ValueError, TypeError): pass
        result['inner_complete_before_reap'] = complete
        if not complete:
            result['forced'] = True
            try: os.killpg(proc.pid, signal.SIGKILL); result['group_kill'] = 'sent'
            except ProcessLookupError: result['group_kill'] = 'no-group'
        try:
            result['status'] = proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            result['cleanup_error'] = 'namespace supervisor reap deadline'
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        if proc is not None and proc.returncode is None:
            try:
                # A fresh waitid establishes that the direct child is still
                # ours and unreaped before using its numeric group identity.
                os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except (ChildProcessError, OSError, ValueError) as check_error:
                result['cleanup_error'] = 'supervisor identity uncertain: ' + str(check_error)
            else:
                try: os.killpg(proc.pid, signal.SIGKILL); result['forced'] = True
                except ProcessLookupError: pass
                try: result['status'] = proc.wait(timeout=3)
                except subprocess.TimeoutExpired: result['cleanup_error'] = 'namespace supervisor reap deadline'
    finally:
        result['stdout'] = snapshot(out.fileno()); result['stderr'] = snapshot(err.fileno())
        result['finished_ns'] = time.monotonic_ns()
        out.close(); err.close()
    report = HOME / ('ss-race-additive-' + mode + '-outer.json')
    fd = os.open(report, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    require(result.get('status') == 0 and not result.get('timed_out') and not result.get('forced') and
            not result.get('cleanup_error') and result.get('inner_complete_before_reap'), 'private namespace observation incomplete')
    print('ss-race-additive-' + mode + '-observed')


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == 'inner' and sys.argv[2] in ('denied', 'race') and sys.argv[3] == SHELL:
            raise SystemExit(private_inner(sys.argv[2]))
        if len(sys.argv) == 3 and sys.argv[1] in ('denied', 'race') and sys.argv[2] == SHELL:
            private_outer(sys.argv[1])
        else:
            raise Incomplete('invalid invocation')
    except (Exception, KeyboardInterrupt) as exc:
        print('ss-race-additive-incomplete: ' + repr(exc), file=sys.stderr)
        sys.exit(125)
