#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-guest-only ownership and PTRACE_O_EXITKILL controls.

Every signalled PID is a direct, unreaped child of this process, additionally
pinned by a pidfd. The guest controller independently checks VM identity.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import sys
import time
import uuid


def require_guest():
    try:
        marker = Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker)) != marker.lower(): raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip() != 'QEMU': raise ValueError('not QEMU')
        if os.getuid() != 2000 or os.geteuid() != 2000: raise ValueError('wrong uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home': raise ValueError('wrong scratch directory')
        if os.uname().machine != 'x86_64': raise ValueError('requires pinned x86-64 guest')
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: ' + str(exc))


require_guest()
HOME = Path('/tmp/parity-home')
PTRACE_ATTACH = 16
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_EXITKILL = 0x00100000
WAIT_WALL = 0x40000000
PR_SET_PTRACER = 0x59616d61
PR_SET_PTRACER_ANY = (1 << 64) - 1
LIB = ctypes.CDLL(None, use_errno=True)
LIB.ptrace.restype = ctypes.c_long
LIB.prctl.restype = ctypes.c_int


def ptrace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = LIB.ptrace(ctypes.c_ulong(request), ctypes.c_ulong(pid), ctypes.c_void_p(address), ctypes.c_void_p(data))
    error = ctypes.get_errno()
    if result == -1 and error: raise OSError(error, os.strerror(error))
    return result


def wait_event(pid, deadline):
    while time.monotonic() < deadline:
        try:
            got, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED | WAIT_WALL)
        except InterruptedError:
            continue
        if got == pid:
            return status
        time.sleep(0.0002)
    raise TimeoutError('waitpid timed out for owned child %d' % pid)


def status_record(status):
    result = {'raw': status}
    if os.WIFEXITED(status): result.update(kind='exit', code=os.WEXITSTATUS(status))
    elif os.WIFSIGNALED(status): result.update(kind='signal', signal=os.WTERMSIG(status))
    elif os.WIFSTOPPED(status): result.update(kind='stop', signal=os.WSTOPSIG(status))
    else: result['kind'] = 'other'
    return result


class OwnedChild:
    """A forked direct child; never signal a process selected by name or group."""
    def __init__(self, pid):
        if pid <= 0: raise ValueError('invalid direct child PID')
        self.pid = pid
        self.pidfd = None
        self.reaped = False
        self.status = None
        self.wait_count = 0
        self.events = [{'phase': 'registered', 'pid': pid}]
        try:
            self.pidfd = os.pidfd_open(pid, 0)
        except BaseException:
            # The PID remains ours and cannot be recycled while unreaped.
            self._fallback_kill_and_reap()
            raise
        self.events.append({'phase': 'pidfd-open', 'fd': self.pidfd})

    def _fallback_kill_and_reap(self):
        try:
            got, status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED | WAIT_WALL)
            if got == self.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                self.reaped, self.status = True, status
                return
            os.kill(self.pid, signal.SIGKILL)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                got, status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED | WAIT_WALL)
                if got == self.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    self.reaped, self.status = True, status
                    return
                time.sleep(0.001)
            raise TimeoutError('fallback owned-child reap timed out')
        except ProcessLookupError:
            got, status = os.waitpid(self.pid, 0)
            self.reaped, self.status = got == self.pid, status

    def wait(self, deadline):
        if self.reaped: raise RuntimeError('owned child already reaped')
        status = wait_event(self.pid, deadline)
        record = status_record(status)
        self.wait_count += 1
        if self.wait_count <= 128:
            self.events.append({'phase': 'wait', **record})
        elif self.wait_count == 129:
            self.events.append({'phase': 'wait-records-truncated', 'limit': 128})
        if record['kind'] in ('exit', 'signal'):
            self.reaped, self.status = True, status
        return status

    def cleanup(self):
        failure = None
        try:
            if not self.reaped:
                # Kill only this pinned, direct child. SIGKILL also releases a
                # child stopped in ptrace; EXITKILL is the tracer-death backup.
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGKILL, None, 0)
                    self.events.append({'phase': 'signal', 'signal': signal.SIGKILL, 'method': 'pidfd'})
                except ProcessLookupError:
                    self.events.append({'phase': 'signal', 'result': 'already exited'})
                deadline = time.monotonic() + 4
                while not self.reaped:
                    self.wait(deadline)
            if not self.reaped: raise RuntimeError('owned child was not reaped')
        except BaseException as exc:
            failure = repr(exc)
            self.events.append({'phase': 'cleanup-error', 'error': failure})
        finally:
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.events.append({'phase': 'pidfd-close', 'fd': self.pidfd})
                self.pidfd = None
        record = {'pid': self.pid, 'reaped': self.reaped,
                  'status': status_record(self.status) if self.status is not None else None,
                  'events': list(self.events), 'wait_count': self.wait_count, 'error': failure}
        if failure: raise RuntimeError('exact owned-child cleanup failed: ' + repr(record))
        return record


def read_line(fd, deadline):
    result = bytearray()
    while len(result) < 2048:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]: raise TimeoutError('control pipe timed out')
        part = os.read(fd, 1)
        if not part: raise RuntimeError('control pipe closed early')
        result += part
        if part == b'\n': return bytes(result)
    raise RuntimeError('control pipe exceeded bound')


def _controlled_tracee(ready_fd):
    ctypes.set_errno(0)
    rc = LIB.prctl(ctypes.c_int(PR_SET_PTRACER), ctypes.c_ulong(PR_SET_PTRACER_ANY),
                   ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    if rc != 0:
        os.write(ready_fd, ('ERROR:%d\n' % ctypes.get_errno()).encode())
        os._exit(121)
    os.write(ready_fd, b'READY\n')
    os.close(ready_fd)
    while True:
        signal.pause()


def _controlled_tracer(tracee_pid, output_fd, enable):
    try:
        ptrace(PTRACE_ATTACH, tracee_pid)
        status = wait_event(tracee_pid, time.monotonic() + 5)
        if not os.WIFSTOPPED(status): raise RuntimeError('control tracee did not stop')
        options = PTRACE_O_TRACESYSGOOD | (PTRACE_O_EXITKILL if enable else 0)
        ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, options)
        payload = {'phase': 'options-set', 'pid': tracee_pid, 'options': options,
                   'attach_wait': status_record(status)}
        os.write(output_fd, (json.dumps(payload, sort_keys=True) + '\n').encode())
        os.close(output_fd)
        # Deliberately exit with the attached tracee stopped. The parent owns
        # both processes and observes whether the kernel kills the tracee.
        os._exit(0)
    except BaseException as exc:
        try: os.write(output_fd, (json.dumps({'phase': 'error', 'error': repr(exc)}) + '\n').encode())
        except OSError: pass
        os._exit(122)


def exitkill_trial(enable):
    fds = []
    children = []
    report = {'enabled': enable, 'events': []}
    before_cleanup = None
    try:
        ready_r, ready_w = os.pipe(); fds.extend((ready_r, ready_w))
        pid = os.fork()
        if pid == 0:
            os.close(ready_r)
            _controlled_tracee(ready_w)
            os._exit(123)
        tracee = OwnedChild(pid); children.append(tracee)
        os.close(ready_w); fds.remove(ready_w)
        ready = read_line(ready_r, time.monotonic() + 5)
        report['events'].append({'phase': 'tracee-ready', 'pid': pid, 'bytes_hex': ready.hex()})
        if ready != b'READY\n': raise RuntimeError('controlled tracee did not become ready')
        os.close(ready_r); fds.remove(ready_r)
        info_r, info_w = os.pipe(); fds.extend((info_r, info_w))
        tracer_pid = os.fork()
        if tracer_pid == 0:
            os.close(info_r)
            _controlled_tracer(pid, info_w, enable)
            os._exit(124)
        tracer = OwnedChild(tracer_pid); children.append(tracer)
        os.close(info_w); fds.remove(info_w)
        info = json.loads(read_line(info_r, time.monotonic() + 5))
        report['events'].append(info)
        if info.get('phase') != 'options-set': raise RuntimeError('controlled tracer could not set options')
        status = tracer.wait(time.monotonic() + 5)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0: raise RuntimeError('controlled tracer failed')
        report['events'].append({'phase': 'tracer-exit', 'pid': tracer_pid, **status_record(status)})
        if enable:
            deadline = time.monotonic() + 5
            while not tracee.reaped:
                status = tracee.wait(deadline)
                if not tracee.reaped:
                    report['events'].append({'phase': 'tracee-intermediate', **status_record(status)})
            report['events'].append({'phase': 'tracee-after-tracer-exit', **status_record(status)})
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                raise RuntimeError('EXITKILL did not kill the tracee')
        else:
            # A readable pidfd denotes an exited child. Absence of readiness
            # is a bounded negative control before exact-child cleanup.
            alive = not select.select([tracee.pidfd], [], [], 0.2)[0]
            report['events'].append({'phase': 'tracee-after-tracer-exit', 'alive': alive})
            if not alive: raise RuntimeError('negative control tracee exited unexpectedly')
    except BaseException as exc:
        before_cleanup = {'type': type(exc).__name__, 'message': str(exc)}
        report['before_cleanup_failure'] = before_cleanup
    finally:
        cleanups = []
        for child in reversed(children):
            try: cleanups.append(child.cleanup())
            except BaseException as exc: cleanups.append({'pid': child.pid, 'reaped': child.reaped, 'error': repr(exc), 'events': child.events})
        for fd in fds:
            try: os.close(fd)
            except OSError: pass
        report['cleanup'] = cleanups
    if before_cleanup or not all(x.get('reaped') and not x.get('error') for x in report['cleanup']):
        raise RuntimeError('exitkill control failed: ' + json.dumps(report, sort_keys=True))
    return report


def selftest():
    observations = []
    try:
        observations.append(exitkill_trial(False))
        observations.append(exitkill_trial(True))
        result = {'checks': {'negative_alive': observations[0]['events'][-1].get('alive') is True,
                             'exitkill_signal': observations[1]['events'][-1].get('signal') == signal.SIGKILL,
                             'all_direct_children_reaped': all(x['reaped'] for o in observations for x in o['cleanup'])},
                  'trials': observations}
        (HOME / 'trace-supervisor-control.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        if not all(result['checks'].values()): raise AssertionError('EXITKILL checks failed')
    except BaseException as exc:
        (HOME / 'trace-supervisor-control.json').write_text(json.dumps({'trials': observations, 'failure': repr(exc)}, indent=2, sort_keys=True) + '\n')
        raise
    print('supervisor EXITKILL controls ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']: selftest()
    else: raise SystemExit('invalid invocation')
