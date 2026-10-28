#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Observe argv bytes only in owned, synchronized children of a parity guest."""
import base64
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid


def require_guest():
    try:
        marker = Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker)) != marker.lower():
            raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip() != 'QEMU':
            raise ValueError('not QEMU')
        if os.getuid() != 2000 or os.geteuid() != 2000:
            raise ValueError('wrong uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('wrong scratch directory')
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: ' + str(exc))


require_guest()
GUARD = r'''[[ $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r v </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r u </etc/bashos-parity-vm || exit 125
[[ $v == QEMU && $u =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
'''
CANDIDATE = GUARD + r'''
printf 'READY\n'
IFS= read -r sync || exit 91
case $1 in
  short) scrub scrub-argv trace-label ;;
  default) scrub scrub-argv ;;
  empty) scrub scrub-argv '' ;;
  long) printf -v label '%05000d' 0; label=${label//0/X}; scrub scrub-argv "$label" ;;
  extra) scrub scrub-argv untouched extra ;;
  *) exit 92 ;;
esac
rc=$?
printf 'RESULT:%s\n' "$rc"
IFS= read -r sync || exit 93
exit "$rc"
'''
SIBLING = GUARD + "printf 'READY\\n'\nIFS= read -r sync || exit 91\nexit 0\n"
REPORT = Path('/tmp/parity-home/argv-observations.jsonl')


def spawn(shell, script, *args):
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise RuntimeError('guest lacks pidfd supervision')
    proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script, 'argv-fixture', *args],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        proc.fixture_pidfd = os.pidfd_open(proc.pid, 0)
    except BaseException:
        # Popen owns this direct, unreaped child. Do not leak it if pidfd setup fails.
        try:
            proc.kill()
            proc.wait(timeout=4)
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed: stream.close()
        raise
    return proc


def line(proc):
    out = bytearray()
    deadline = time.monotonic() + 5
    while len(out) < 512:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
            raise TimeoutError('child marker timed out')
        b = os.read(proc.stdout.fileno(), 1)
        if not b:
            raise RuntimeError('child closed marker pipe')
        out += b
        if b == b'\n':
            return bytes(out)
    raise ValueError('child marker exceeded bound')


def snapshot(proc):
    # proc is a directly-owned child; no other process can be selected.
    root = Path('/proc') / str(proc.pid)
    stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    start, end = int(stat[45]), int(stat[46])
    cmdline = (root / 'cmdline').read_bytes()
    if not (0 < end - start <= 16384) or len(cmdline) != end - start:
        raise RuntimeError('unexpected cmdline span; control cannot qualify fixture')
    return {'pid': proc.pid, 'arg_start': start, 'arg_end': end, 'span': end - start,
            'cmdline_base64': base64.b64encode(cmdline).decode()}


def decode(s):
    return base64.b64decode(s['cmdline_base64'], validate=True)


def same_observation(before, after):
    return before['span'] == after['span'] and decode(before) == decode(after)


def expected(label, span):
    clipped = label[:span - 1]
    return clipped + bytes(span - len(clipped))


def save(record):
    with REPORT.open('a', encoding='utf8') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


def release(proc):
    proc.stdin.write(b'go\n')
    proc.stdin.flush()


def drain(stream, limit=8192):
    if stream is None or stream.closed: return b''
    os.set_blocking(stream.fileno(), False)
    result = bytearray()
    while len(result) < limit:
        try: part = os.read(stream.fileno(), min(4096, limit - len(result)))
        except BlockingIOError: break
        if not part: break
        result.extend(part)
    return bytes(result)


def finish(proc):
    if proc.stdin is not None and not proc.stdin.closed: proc.stdin.close()
    status = proc.wait(timeout=5)
    return status, drain(proc.stderr)


def cleanup_owned(procs, label):
    # Only exact Popen children, protected against PID reuse by pidfds.
    observations = []; stdin_errors = {}
    for proc in procs:
        try:
            if proc.stdin is not None and not proc.stdin.closed: proc.stdin.close()
        except BaseException as exc:
            stdin_errors[proc.pid] = repr(exc)
    for proc in reversed(procs):
        item = {'pid': proc.pid, 'pidfd': proc.fixture_pidfd, 'events': []}
        if proc.pid in stdin_errors: item['stdin_close_error'] = stdin_errors[proc.pid]
        try:
            try:
                proc.wait(timeout=0.3)
                item['events'].append({'phase': 'eof-exit', 'status': proc.returncode})
            except subprocess.TimeoutExpired:
                for sig, delay in ((signal.SIGTERM, 0.4), (signal.SIGKILL, 4)):
                    try:
                        signal.pidfd_send_signal(proc.fixture_pidfd, sig, None, 0)
                        item['events'].append({'phase': 'signal', 'signal': int(sig), 'method': 'pidfd'})
                    except ProcessLookupError:
                        item['events'].append({'phase': 'signal', 'signal': int(sig), 'result': 'already-exited'})
                    try:
                        proc.wait(timeout=delay)
                        break
                    except subprocess.TimeoutExpired:
                        item['events'].append({'phase': 'wait-timeout', 'seconds': delay})
            item['reaped'] = proc.poll() is not None
            item['exit_status'] = proc.returncode
            item['stdout_base64'] = base64.b64encode(drain(proc.stdout)).decode()
            item['stderr_base64'] = base64.b64encode(drain(proc.stderr)).decode()
            if not item['reaped']: item['error'] = 'owned child was not reaped after pidfd SIGKILL'
        except BaseException as exc:
            item['primary_cleanup_error'] = repr(exc)
        finally:
            # Even a bookkeeping, wait or signal exception must not leave an
            # owned child running. pidfd is tied to this Popen child only.
            try:
                if proc.poll() is None:
                    try:
                        signal.pidfd_send_signal(proc.fixture_pidfd, signal.SIGKILL, None, 0)
                        item['events'].append({'phase': 'finally-signal', 'signal': int(signal.SIGKILL), 'method': 'pidfd'})
                    except ProcessLookupError:
                        pass
                    except OSError as exc:
                        item['events'].append({'phase': 'pidfd-error', 'error': repr(exc), 'fallback': 'direct-Popen-child'})
                        proc.kill()
                    proc.wait(timeout=4)
                item['reaped'] = proc.poll() is not None
                item['exit_status'] = proc.returncode
                if not item['reaped']: item['error'] = 'owned child survived bounded cleanup'
            except BaseException as exc:
                item['reaped'] = proc.poll() is not None
                item['exit_status'] = proc.returncode
                item['error'] = repr(exc)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    try: stream.close()
                    except BaseException as exc: item.setdefault('close_errors', []).append(repr(exc))
            try: os.close(proc.fixture_pidfd); item['pidfd_closed'] = True
            except BaseException as exc: item['pidfd_closed'] = False; item.setdefault('close_errors', []).append(repr(exc))
            item.update(stdin_closed=proc.stdin is None or proc.stdin.closed,
                        stdout_closed=proc.stdout is None or proc.stdout.closed,
                        stderr_closed=proc.stderr is None or proc.stderr.closed)
        observations.append(item)
    with (Path('/tmp/parity-home') / 'argv-cleanup-observations.jsonl').open('a', encoding='utf8') as stream:
        stream.write(json.dumps({'label': label, 'children': observations}, sort_keys=True) + '\n')
    if not all(item.get('reaped') and not item.get('error') and not item.get('close_errors') for item in observations):
        raise RuntimeError('owned child cleanup failed: ' + repr(observations))
    return observations


def control():
    procs = []
    try:
        p = spawn('/opt/bash-5.3.15/bin/bash', SIBLING); procs.append(p)
        if line(p) != b'READY\n':
            raise RuntimeError('reference child not ready')
        first = snapshot(p); second = snapshot(p)
        release(p)
        status, err = finish(p)
        sample = expected(b'control', 16)
        checks = {'child_stable': same_observation(first, second), 'child_status_zero': status == 0,
                  'stderr_empty': err == b'', 'sample_expected': sample == b'control' + bytes(9),
                  'reject_bad_padding': sample != b'control' + b'X' + bytes(8),
                  'reject_bad_label': sample != expected(b'wrong', 16)}
        save({'control': checks, 'first': first, 'second': second,
              'status': status, 'stderr_base64': base64.b64encode(err).decode(),
              'sample_base64': base64.b64encode(sample).decode()})
        if not all(checks.values()):
            raise RuntimeError('argv observer control failed')
    except BaseException as exc:
        save({'phase': 'pre-cleanup-normal-control-exception', 'error': repr(exc), 'pids': [p.pid for p in procs]})
        raise
    finally:
        normal_cleanup = cleanup_owned(procs, 'control-normal')
    procs = []
    caught = False
    stubborn = GUARD + "trap '' TERM\nprintf 'READY\\n'\nwhile :; do :; done\n"
    try:
        for script in (SIBLING, stubborn):
            p = spawn('/opt/bash-5.3.15/bin/bash', script); procs.append(p)
            if line(p) != b'READY\n': raise RuntimeError('exception control child not ready')
        raise RuntimeError('deliberate exception control')
    except BaseException as exc:
        save({'phase': 'pre-cleanup-control-exception', 'error': repr(exc), 'pids': [p.pid for p in procs]})
        if not isinstance(exc, RuntimeError) or str(exc) != 'deliberate exception control': raise
        caught = True
    finally:
        exceptional_cleanup = cleanup_owned(procs, 'control-exception')
    by_pid = {x['pid']: x for x in exceptional_cleanup}
    sleepy, stubborn_pid = procs[0].pid, procs[1].pid
    checks = {'exception_reached': caught, 'two_owned_children_reaped': len(exceptional_cleanup) == 2 and all(x['reaped'] for x in exceptional_cleanup),
              'eof_child_status': by_pid[sleepy]['exit_status'] == 91,
              'stubborn_child_sigkill': by_pid[stubborn_pid]['exit_status'] == -signal.SIGKILL,
              'stubborn_term_then_kill': [e['signal'] for e in by_pid[stubborn_pid]['events'] if e['phase']=='signal'] == [signal.SIGTERM, signal.SIGKILL],
              'all_pipes_and_pidfds_closed': all(x['stdin_closed'] and x['stdout_closed'] and x['stderr_closed'] and x['pidfd_closed'] for x in exceptional_cleanup),
              'normal_child_reaped': len(normal_cleanup) == 1 and normal_cleanup[0]['reaped']}
    save({'exception_control': checks, 'normal_cleanup': normal_cleanup, 'exceptional_cleanup': exceptional_cleanup})
    if not all(checks.values()): raise RuntimeError('exception cleanup control failed')
    print('owned child and byte-oracle controls ok')

def exercise(shell, mode):
    procs = []
    try:
        sibling = spawn('/opt/bash-5.3.15/bin/bash', SIBLING); procs.append(sibling)
        target = spawn(shell, CANDIDATE, mode); procs.append(target)
        if line(sibling) != b'READY\n' or line(target) != b'READY\n':
            raise RuntimeError('child readiness failed')
        sibling_before, before = snapshot(sibling), snapshot(target)
        if mode == 'long' and before['span'] >= 5000:
            raise RuntimeError('long label is not longer than original argv span')
        release(target)
        message = line(target)
        if not message.startswith(b'RESULT:') or not message.endswith(b'\n'):
            raise RuntimeError('unexpected result marker')
        operation_status = int(message[7:-1])
        after, sibling_after = snapshot(target), snapshot(sibling)
        release(target)
        release(sibling)
        target_status, target_err = finish(target)
        sibling_status, sibling_err = finish(sibling)
        label = {'short': b'trace-label', 'default': b'[scrub]', 'empty': b'',
                 'long': b'X' * 5000}.get(mode)
        expected_bytes = decode(before) if mode == 'extra' else expected(label, before['span'])
        checks = {'target_status': operation_status == (2 if mode == 'extra' else 0),
                  'final_status': target_status == operation_status,
                  'target_exact_bytes': decode(after) == expected_bytes,
                  'same_span': before['span'] == after['span'],
                  'sibling_unchanged': same_observation(sibling_before, sibling_after),
                  'sibling_status': sibling_status == 0 and sibling_err == b'',
                  'target_stderr': (b'scrub-argv: unexpected arg: extra' in target_err) if mode == 'extra' else target_err == b''}
        save({'mode': mode, 'before': before, 'after': after,
              'sibling_before': sibling_before, 'sibling_after': sibling_after,
              'expected_base64': base64.b64encode(expected_bytes).decode(),
              'marker_base64': base64.b64encode(message).decode(),
              'operation_status': operation_status, 'final_status': target_status,
              'sibling_status': sibling_status, 'checks': checks,
              'target_stderr_base64': base64.b64encode(target_err).decode(),
              'sibling_stderr_base64': base64.b64encode(sibling_err).decode()})
        if not all(checks.values()):
            raise AssertionError('argv mismatch in ' + mode + ': ' + repr(checks))
        print(mode + ': ok')
    except BaseException as exc:
        save({'phase': 'pre-cleanup-exception', 'mode': mode, 'error': repr(exc), 'pids': [p.pid for p in procs]})
        raise
    finally:
        cleanup_owned(procs, 'exercise-' + mode)


if len(sys.argv) == 2 and sys.argv[1] == '--control':
    control()
elif len(sys.argv) == 2 and sys.argv[1] == '/opt/bashos-parity/candidate':
    for scenario in ('short', 'default', 'empty', 'long', 'extra'):
        exercise(sys.argv[1], scenario)
else:
    raise SystemExit('invalid invocation')
