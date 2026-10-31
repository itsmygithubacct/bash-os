#!/usr/bin/python3
"""Guest-only owned-child lifecycle primitives; callers must guard first.

No numeric process-group probe or signal is used.  An unreaped direct child is
observed with waitid(WNOWAIT); signals target pidfds for verified children.
The retained child list is not a complete descendant-containment witness.
"""
import base64
import ctypes
import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import time
import runpy

CAP = 65536
CHILD_CAP = 64
GUARD = '/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py'
GUARD_SHA = 'a74d97058d313388948010d1033f50dde7151c2d204d221ed3aeb4da3e9e1762'
_owner_pid = None


def children():
    path = Path('/proc/self/task') / str(os.getpid()) / 'children'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    raw = bytearray()
    try:
        while len(raw) <= 4096:
            part = os.read(fd, 4097 - len(raw))
            if not part: break
            raw.extend(part)
    finally: os.close(fd)
    if len(raw) > 4096: raise ValueError('children list byte limit')
    values = [int(x) for x in raw.split()]
    if len(values) > CHILD_CAP: raise ValueError('children list count limit')
    return values


def prepare():
    global _owner_pid
    if hashlib.sha256(Path(GUARD).read_bytes()).hexdigest() != GUARD_SHA:
        raise ValueError('guest guard digest')
    runpy.run_path(GUARD)['verify']()
    if os.getuid() != 2000 or os.geteuid() != 2000: raise ValueError('guest uid')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal') or not hasattr(os, 'waitid'):
        raise RuntimeError('pidfd and waitid required')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'subreaper setup')
    if children(): raise RuntimeError('observer already has children')
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    _owner_pid = os.getpid()


def before_spawn():
    if _owner_pid != os.getpid(): raise RuntimeError('observer is not guarded')
    if children(): raise RuntimeError('observer has outstanding children')


def spawn(argv, excluded_children=(), **kwargs):
    """Arm parent-death before exec; exclusions must remain unreaped children."""
    if _owner_pid != os.getpid(): raise RuntimeError('observer is not guarded')
    if sorted(children()) != sorted(excluded_children): raise RuntimeError('unexpected children before spawn')
    for pid in excluded_children:
        observed_exit(pid)  # waitid proves a direct, unreaped child without consuming it.
    parent = os.getpid(); extra = kwargs.pop('preexec_fn', None)
    libc = ctypes.CDLL(None, use_errno=True)
    def arm():
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(125)
        value = ctypes.c_int(0)
        if libc.prctl(2, ctypes.byref(value), 0, 0, 0) != 0 or value.value != signal.SIGKILL:
            os._exit(125)
        if extra is not None: extra()
    return subprocess.Popen(argv, preexec_fn=arm, **kwargs)


def proc_stat(pid):
    path = '/proc/%d/stat' % pid
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: raw = os.read(fd, 4097)
    finally: os.close(fd)
    if len(raw) > 4096: raise ValueError('proc stat limit')
    end = raw.rfind(b')')
    if end < 0: raise ValueError('bad proc stat')
    parts = raw[end + 2:].split()
    if len(parts) < 20 or int(raw[:raw.find(b' ')]) != pid: raise ValueError('bad proc identity')
    return {'raw_base64': base64.b64encode(raw).decode(), 'pid': pid,
            'state': parts[0].decode('ascii'), 'ppid': int(parts[1]),
            'pgrp': int(parts[2]), 'session': int(parts[3]), 'starttime': int(parts[19])}


def observed_exit(pid):
    event = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if event is None: return None
    return {'pid': event.si_pid, 'uid': event.si_uid, 'code': event.si_code,
            'status': event.si_status, 'monotonic_ns': time.monotonic_ns()}


def cleanup_direct(pid, proc=None, seconds=3):
    """Fallback: waitid proves direct-child ownership while PID is unreaped."""
    row = {'pid': pid, 'started_ns': time.monotonic_ns(), 'reaped': False,
           'signal': None, 'errors': []}
    try:
        event = observed_exit(pid)
        row['ownership_waitid'] = event if event is not None else 'live-direct-child'
        if event is None:
            # No other thread waits here, SIGCHLD is default and the PID cannot
            # be recycled until our own terminal wait. Never target a group.
            try:
                os.kill(pid, signal.SIGKILL); row['signal'] = 'SIGKILL-direct-unreaped-child'
            except ProcessLookupError:
                row['signal'] = 'already-exited-before-signal'
        deadline = time.monotonic() + seconds
        while event is None and time.monotonic() < deadline:
            select.select([], [], [], .02); event = observed_exit(pid)
        if event is None: raise TimeoutError('fallback exit unobserved')
        row['exit_waitid_wnowait'] = event
        waited, status = os.waitpid(pid, 0)
        row['waitpid'] = {'pid': waited, 'raw_status': status, 'exitcode': os.waitstatus_to_exitcode(status)}
        row['reaped'] = True
        if proc is not None: proc.returncode = row['waitpid']['exitcode']
    except (OSError, ValueError, ChildProcessError, TimeoutError) as exc:
        row['errors'].append(type(exc).__name__ + ': ' + str(exc))
        row['controller_containment_required'] = True
    row['finished_ns'] = time.monotonic_ns()
    return row


def finish(proc, timeout=4, injected_error=False, excluded_children=(), fault=None):
    """Reap leader only after WNOWAIT; use pidfds for adopted child signals."""
    if _owner_pid != os.getpid(): raise RuntimeError('observer is not guarded')
    result = {'pid': proc.pid, 'started_ns': time.monotonic_ns(), 'forced': False,
              'timeout': False, 'signal_scope': 'verified pidfd or waitid-proven unreaped direct child',
              'whole_descendant_containment': 'unwitnessed', 'errors': [], 'adopted': [],
              'excluded_children': list(excluded_children),
              'stdout': '', 'stderr': '', 'eof': {'stdout': proc.stdout is None, 'stderr': proc.stderr is None},
              'truncated': {'stdout': False, 'stderr': False}, 'rc': None}
    data = {'stdout': bytearray(), 'stderr': bytearray()}; streams = {}
    def drain(wait):
        if not streams:
            if wait > 0: select.select([], [], [], wait)
            return
        for fd in select.select(list(streams), [], [], wait)[0]:
            try: chunk = os.read(fd, 4096)
            except BlockingIOError: continue
            name = streams[fd]
            if not chunk:
                result['eof'][name] = True; del streams[fd]; continue
            room = max(0, CAP - len(data[name])); data[name].extend(chunk[:room])
            if len(chunk) > room: result['truncated'][name] = True
    leaderfd = None; leader_reaped = False; leader_owned = False
    try:
        for name in ('stdout', 'stderr'):
            stream = getattr(proc, name)
            if stream is not None:
                os.set_blocking(stream.fileno(), False); streams[stream.fileno()] = name
        result['observer_initial'] = proc_stat(os.getpid())
        if fault == 'leader_pidfd': raise OSError('injected leader pidfd failure')
        leaderfd = os.pidfd_open(proc.pid, 0)
        if fault == 'leader_identity': raise OSError('injected leader identity failure')
        result['leader_initial'] = proc_stat(proc.pid)
        if result['leader_initial']['ppid'] != os.getpid(): raise ValueError('leader is not direct child')
        leader_owned = True
        deadline = time.monotonic() + timeout
        event = None
        while event is None:
            if fault == 'leader_wait':
                fault = None; raise OSError('injected leader wait failure')
            event = observed_exit(proc.pid)
            if event is not None: break
            left = deadline - time.monotonic()
            if left <= 0:
                result['timeout'] = True; result['forced'] = True
                if fault == 'leader_signal':
                    fault = None; raise OSError('injected leader signal failure')
                signal.pidfd_send_signal(leaderfd, signal.SIGKILL)
                result['leader_signal'] = 'SIGKILL-via-pidfd'
                break
            drain(min(left, .05))
        if event is None:
            deadline = time.monotonic() + 3
            while event is None and time.monotonic() < deadline:
                event = observed_exit(proc.pid)
                if event is None: drain(.05)
        if event is None: raise TimeoutError('leader exit unobserved')
        result['leader_waitid_wnowait'] = event
        result['observer_after'] = proc_stat(os.getpid())
        if result['observer_after']['starttime'] != result['observer_initial']['starttime']:
            raise ValueError('observer identity changed')
        # Do not probe or signal any numeric process group before or after reap.
        result['rc'] = proc.wait(timeout=2); leader_reaped = True
        end = time.monotonic() + 3
        while True:
            try:
                if fault == 'enumeration':
                    fault = None; raise OSError('injected descendant enumeration failure')
                ids = [pid for pid in children() if pid not in excluded_children]
            except (OSError, ValueError) as exc:
                result['errors'].append('descendant enumeration: ' + str(exc))
                # Retry once; failure still makes the observation incomplete.
                ids = [pid for pid in children() if pid not in excluded_children]
            if not ids: break
            if len(result['adopted']) + len(ids) > CHILD_CAP or time.monotonic() >= end:
                raise TimeoutError('adopted child limit')
            for pid in ids:
                child = {'pid': pid, 'opened_ns': time.monotonic_ns()}; result['adopted'].append(child)
                handle = None
                try:
                    if fault == 'adopted_pidfd':
                        fault = None; raise OSError('injected adopted pidfd failure')
                    handle = os.pidfd_open(pid, 0)
                    if fault == 'adopted_identity':
                        fault = None; raise OSError('injected adopted identity failure')
                    before = proc_stat(pid); after = proc_stat(pid)
                    child['identity_before'] = before; child['identity_after'] = after
                    if (before['ppid'] != os.getpid() or after['ppid'] != os.getpid() or
                        before['starttime'] != after['starttime'] or
                        Path('/proc/%d' % pid).stat().st_uid != os.geteuid()):
                        raise ValueError('adopted child ownership or identity')
                    if injected_error:
                        child['injected_failure'] = 'adopted-observation-error'
                        result['errors'].append('injected-adopted-observation-failure-control')
                        injected_error = False
                    if after['state'] != 'Z':
                        signal.pidfd_send_signal(handle, signal.SIGKILL)
                        child['signal'] = 'SIGKILL-via-pidfd'; result['forced'] = True
                    event = observed_exit(pid)
                    while event is None and time.monotonic() < end:
                        drain(.05); event = observed_exit(pid)
                    if event is None: raise TimeoutError('adopted child exit unobserved')
                    child['waitid_wnowait'] = event
                    waited, status = os.waitpid(pid, 0)
                    child['waitpid'] = {'pid': waited, 'raw_status': status,
                                        'exitcode': os.waitstatus_to_exitcode(status)}
                except (OSError, ValueError, ChildProcessError, TimeoutError) as exc:
                    child['error'] = type(exc).__name__ + ': ' + str(exc)
                    result['errors'].append('adopted cleanup: ' + child['error'])
                    child['fallback'] = cleanup_direct(pid)
                    if not child['fallback']['reaped']:
                        result['controller_containment_required'] = True
                        raise RuntimeError('adopted child cleanup incomplete')
                    if child['fallback']['signal']: result['forced'] = True
                finally:
                    if handle is not None: os.close(handle)
        result['children_after'] = [pid for pid in children() if pid not in excluded_children]
        if injected_error:
            result['errors'].append('injected-failure-not-reached')
    except (OSError, ValueError, RuntimeError, TimeoutError, ChildProcessError, subprocess.SubprocessError) as exc:
        result['errors'].append(type(exc).__name__ + ': ' + str(exc))
        # A pidfd remains bound to the original leader even if identity reads failed.
        if not leader_reaped and leaderfd is not None and leader_owned:
            try:
                signal.pidfd_send_signal(leaderfd, signal.SIGKILL); result['forced'] = True
                result['leader_signal'] = 'SIGKILL-via-pidfd-after-error'
            except ProcessLookupError: pass
            except OSError as inner: result['errors'].append('leader pidfd signal: ' + str(inner))
            try:
                event = observed_exit(proc.pid)
                end = time.monotonic() + 2
                while event is None and time.monotonic() < end:
                    drain(.05); event = observed_exit(proc.pid)
                if event is not None:
                    result['leader_waitid_wnowait'] = event
                    result['rc'] = proc.wait(timeout=1); leader_reaped = True
            except (OSError, ChildProcessError, TimeoutError, subprocess.SubprocessError) as inner:
                result['errors'].append('leader reap: ' + str(inner))
        if not leader_reaped:
            result['leader_fallback'] = cleanup_direct(proc.pid, proc)
            leader_reaped = result['leader_fallback']['reaped']
            if leader_reaped:
                result['rc'] = proc.returncode
                if result['leader_fallback']['signal']: result['forced'] = True
            else:
                result['controller_containment_required'] = True
        if leader_reaped:
            try:
                end = time.monotonic() + 3
                while True:
                    ids = [pid for pid in children() if pid not in excluded_children]
                    if not ids: break
                    if len(result['adopted']) + len(ids) > CHILD_CAP or time.monotonic() >= end:
                        raise TimeoutError('fallback descendant limit')
                    for pid in ids:
                        row = {'pid': pid, 'fallback': cleanup_direct(pid)}
                        result['adopted'].append(row)
                        if row['fallback']['signal']: result['forced'] = True
                        if not row['fallback']['reaped']: raise RuntimeError('fallback child not reaped')
                result['children_after'] = [pid for pid in children() if pid not in excluded_children]
            except (OSError, ValueError, RuntimeError, TimeoutError) as inner:
                result['errors'].append('fallback descendants: ' + str(inner))
                result['controller_containment_required'] = True
    finally:
        end = time.monotonic() + 2
        while streams and time.monotonic() < end:
            try: drain(min(.05, max(0, end - time.monotonic())))
            except (OSError, ValueError) as exc:
                result['errors'].append('pipe drain: ' + str(exc)); break
        if streams: result['errors'].append('pipe EOF deadline')
        for name in ('stdout', 'stderr'):
            result[name] = base64.b64encode(data[name]).decode()
            stream = getattr(proc, name)
            if stream is not None:
                try: stream.close()
                except OSError as exc: result['errors'].append('pipe close: ' + str(exc))
        if leaderfd is not None:
            try: os.close(leaderfd)
            except OSError as exc: result['errors'].append('pidfd close: ' + str(exc))
        result['leader_ownership_verified'] = leader_owned
        result['leader_reaped'] = leader_reaped; result['finished_ns'] = time.monotonic_ns()
        result['complete'] = (leader_reaped and not result['errors'] and all(result['eof'].values())
                              and not any(result['truncated'].values()) and result.get('children_after') == [])
    return result
