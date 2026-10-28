#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disposable-VM-only, parent-owned clock syscall observer with an EPERM guard.

Pinned x86-64 guest ABI. The tracee cannot fork, alter clocks, or escape the
observer: a seccomp ERRNO filter blocks all observed clock and process-creation
calls, while ptrace records syscall entry even when another filter denies it.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import sys
import uuid

PTRACE_TRACEME = 0
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GET_SYSCALL_INFO = 0x420e
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_TRACEEXEC = 0x10
PTRACE_O_EXITKILL = 0x00100000
PTRACE_EVENT_EXEC = 4
ALLOW = 0x7fff0000
ERRNO_EPERM = 0x00050000 | errno.EPERM
CLOCK_CALLS = ('clock_settime', 'clock_adjtime', 'adjtimex', 'settimeofday')
FORK_CALLS = ('fork', 'vfork', 'clone', 'clone3')
MAX_RECORDS = 128


def require_guest():
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        if str(uuid.UUID(marker)) != marker.lower(): raise ValueError('non-canonical VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU': raise ValueError('not a QEMU guest')
        if os.getuid() != 2000 or os.geteuid() != 2000: raise ValueError('unexpected guest uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('unexpected guest scratch directory')
    except (OSError, ValueError) as exc:
        raise SystemExit('disposable-VM guard refused helper: ' + str(exc))


class SyscallEntry(ctypes.Structure):
    _fields_ = [('number', ctypes.c_uint64), ('args', ctypes.c_uint64 * 6)]


class SyscallExit(ctypes.Structure):
    _fields_ = [('result', ctypes.c_int64), ('is_error', ctypes.c_uint8)]


class SyscallData(ctypes.Union):
    _fields_ = [('entry', SyscallEntry), ('exit', SyscallExit)]


class SyscallInfo(ctypes.Structure):
    _fields_ = [('op', ctypes.c_uint8), ('pad', ctypes.c_uint8 * 3),
                ('arch', ctypes.c_uint32), ('instruction_pointer', ctypes.c_uint64),
                ('stack_pointer', ctypes.c_uint64), ('data', SyscallData)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', required=True)
    parser.add_argument('program', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    program = args.program[1:] if args.program and args.program[0] == '--' else args.program
    if not program or not os.path.isabs(program[0]): raise ValueError('absolute target program required')
    log = Path(args.log)
    if not log.is_absolute() or log.parent != Path('/tmp/parity-home'):
        raise ValueError('trace log must be in the private HOME')
    if os.uname().machine != 'x86_64': raise ValueError('unsupported ptrace register ABI')
    libc = ctypes.CDLL(None, use_errno=True); libc.ptrace.restype = ctypes.c_long
    libsec = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    libsec.seccomp_init.argtypes = [ctypes.c_uint32]; libsec.seccomp_init.restype = ctypes.c_void_p
    libsec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]; libsec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    libsec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    libsec.seccomp_load.argtypes = [ctypes.c_void_p]; libsec.seccomp_release.argtypes = [ctypes.c_void_p]
    numbers = {name: libsec.seccomp_syscall_resolve_name(name.encode()) for name in CLOCK_CALLS + FORK_CALLS}
    if any(number < 0 for number in numbers.values()): raise RuntimeError('required syscall name unavailable')
    by_number = {number: name for name, number in numbers.items()}
    def ptrace(op, pid, addr=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(ctypes.c_ulong(op), ctypes.c_ulong(pid), ctypes.c_void_p(addr), ctypes.c_void_p(data))
        err = ctypes.get_errno()
        if result == -1 and err: raise OSError(err, os.strerror(err))
        return result
    def process_status(pid):
        selected = {}
        for line in Path('/proc/%d/status' % pid).read_text().splitlines():
            if line.startswith(('NoNewPrivs:', 'Seccomp:', 'Seccomp_filters:')):
                key, value = line.split(':', 1); selected[key] = int(value.strip())
        return selected
    records = []
    report = {'syscall_numbers': numbers, 'records': records, 'program': program,
              'observer': 'ptrace-entry-and-exit; libseccomp EPERM guard', 'exec_seen': False}
    child = os.fork()
    if child == 0:
        try:
            ptrace(PTRACE_TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            ctx = libsec.seccomp_init(ALLOW)
            if not ctx: raise RuntimeError('seccomp_init failed')
            for name, number in numbers.items():
                if libsec.seccomp_rule_add(ctx, ERRNO_EPERM, number, 0) != 0:
                    raise RuntimeError('cannot deny ' + name)
            if libsec.seccomp_load(ctx) != 0: raise RuntimeError('seccomp_load failed')
            libsec.seccomp_release(ctx)
            os.execv(program[0], program)
        except BaseException as exc:
            os.write(2, ('trace child: ' + str(exc) + '\n').encode())
            os._exit(126)
    exitcode = None
    try:
        _, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError('child did not enter trace stop')
        report['before_filter'] = process_status(child)
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)
        pending = None; deliver = 0
        while True:
            ptrace(PTRACE_SYSCALL, child, 0, deliver); deliver = 0
            _, status = os.waitpid(child, 0)
            if os.WIFEXITED(status): exitcode = os.WEXITSTATUS(status); break
            if os.WIFSIGNALED(status): exitcode = 128 + os.WTERMSIG(status); break
            if not os.WIFSTOPPED(status): continue
            sig = os.WSTOPSIG(status); event = status >> 16
            if sig == signal.SIGTRAP and event == PTRACE_EVENT_EXEC:
                report['exec_seen'] = True; report['after_filter'] = process_status(child)
                continue
            if sig != (signal.SIGTRAP | 0x80):
                deliver = 0 if sig == signal.SIGTRAP else sig
                continue
            info = SyscallInfo()
            size = ptrace(PTRACE_GET_SYSCALL_INFO, child, ctypes.sizeof(info), ctypes.addressof(info))
            if size < 24 or info.arch != 0xc000003e:
                raise RuntimeError('syscall observation ABI unavailable or not x86-64')
            if info.op == 1:
                pending = None
                name = by_number.get(info.data.entry.number)
                if report['exec_seen'] and name:
                    if len(records) >= MAX_RECORDS: raise RuntimeError('trace exceeds record limit')
                    pending = {'syscall': name, 'number': int(info.data.entry.number),
                               'args': [int(arg) for arg in info.data.entry.args]}
                    records.append(pending)
            elif info.op == 2:
                if pending is not None:
                    pending['return'] = int(info.data.exit.result)
                    pending['is_error'] = bool(info.data.exit.is_error)
                pending = None
            else:
                raise RuntimeError('unexpected syscall stop type')
        report['exit_status'] = exitcode
        before, after = report.get('before_filter', {}), report.get('after_filter', {})
        if not report['exec_seen'] or after.get('NoNewPrivs') != 1 or after.get('Seccomp') != 2:
            raise RuntimeError('guarded target exec was not established')
        if 'Seccomp_filters' in before and 'Seccomp_filters' in after and after['Seccomp_filters'] <= before['Seccomp_filters']:
            raise RuntimeError('seccomp filter count did not increase')
        if any(row['syscall'] in FORK_CALLS for row in records):
            raise RuntimeError('guard blocked a descendant process attempt')
        if any('return' not in row for row in records): raise RuntimeError('truncated syscall observation')
        if any(row['return'] != -errno.EPERM for row in records):
            raise RuntimeError('clock guard did not deny a recorded mutation call')
        return exitcode
    except BaseException as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
        print('ptrace observer: ' + report['error'], file=sys.stderr)
        return 125
    finally:
        if exitcode is None:
            try:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            except (ChildProcessError, ProcessLookupError): pass
        log.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    require_guest()
    sys.exit(main())
