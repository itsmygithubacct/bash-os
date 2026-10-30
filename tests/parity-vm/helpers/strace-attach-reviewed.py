#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only preflight, controlled candidate observation and assessment."""
import base64
import json
import os
from pathlib import Path
import re
import resource
import signal
import struct
import subprocess
import sys
import time
import uuid

HOME = Path('/tmp/parity-home')
LIMIT = 512 * 1024


def guard():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    actual = Path('/sys/class/dmi/id/product_uuid').read_text().strip()
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME) or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
            uuid.UUID(marker) != uuid.UUID(actual) or os.uname().machine != 'x86_64'):
        raise RuntimeError('requires isolated uid-2000 x86_64 parity guest')


def save(name, value):
    temporary = HOME / (name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(HOME / name)


def parse_trace(text, leader, worker, parent, require_worker=True):
    """Only full line-anchored events count; no guessed pairing of fragments."""
    if not text or not text.endswith('\n') or '\0' in text:
        raise ValueError('empty, incomplete or NUL-containing trace')
    found = {'leader_call': False, 'worker_call': False, 'leader_exit': False, 'worker_exit': False}
    positions = {}
    expected = {leader: ('getpid', leader, 'leader_call')}
    if require_worker:
        expected[worker] = ('getppid', parent, 'worker_call')
    for index, line in enumerate(text.splitlines()):
        if (re.search(r'(^|:\s)strace:', line) or re.search(r'\bPTRACE_[A-Z_]+\b', line) or
                re.search(r'\bwaitpid\s*:', line) or '+++ killed by signal' in line or '+++ detached' in line):
            raise ValueError('tracer error: ' + line[:200])
        for tid, (call, value, label) in expected.items():
            prefix = '[pid %d] %s(' % (tid, call)
            if prefix in line:
                if line != '[pid %d] %s() = %d' % (tid, call, value):
                    raise ValueError('incomplete, interleaved or malformed selected syscall: ' + line[:200])
                if found['leader_exit' if tid == leader else 'worker_exit']:
                    raise ValueError('selected syscall after task exit')
                found[label] = True
                positions.setdefault(label, index)
            exit_text = '[pid %d] +++ exited with 0 +++' % tid
            if exit_text in line:
                if line != exit_text:
                    raise ValueError('malformed exit event: ' + line[:200])
                exit_label = 'leader_exit' if tid == leader else 'worker_exit'
                if found[exit_label]:
                    raise ValueError('duplicate exit event')
                found[exit_label] = True
                positions[exit_label] = index
    for who in ('leader', 'worker'):
        if found[who + '_call'] and found[who + '_exit'] and positions[who + '_call'] >= positions[who + '_exit']:
            raise ValueError(who + ' syscall occurs after exit')
    if found['worker_exit'] and found['leader_call'] and positions['worker_exit'] >= positions['leader_call']:
        raise ValueError('leader call precedes worker exit')
    return found


def parser_controls():
    # Whole events from different TIDs may interleave; selected calls are
    # serialized by the shared gates to avoid unattributable partial lines.
    good = ('[pid 101] write(1, 0x0, 0) = 0\n[pid 102] getppid() = 99\n'
            '[pid 101] close(3) = 0\n[pid 102] +++ exited with 0 +++\n'
            '[pid 101] getpid() = 101\n[pid 101] +++ exited with 0 +++\n')
    negative = {
        'truncated': good.replace('[pid 101] getpid() = 101\n', '[pid 101] getpid('),
        'diagnostic': good.replace('[pid 101] getpid() = 101', 'strace: error [pid 101] getpid() = 101'),
        'exit_in_text': good.replace('[pid 101] +++ exited with 0 +++', 'error: [pid 101] +++ exited with 0 +++'),
        'wrong_tid': good.replace('[pid 102] getppid()', '[pid 103] getppid()'),
        'wrong_order': good.replace('[pid 101] getpid() = 101\n[pid 101] +++ exited with 0 +++', '[pid 101] +++ exited with 0 +++\n[pid 101] getpid() = 101'),
        'error': good + 'strace: PTRACE_ATTACH: Operation not permitted\n',
        'worker_order': good.replace('[pid 102] getppid() = 99', '[pid 102] +++ exited with 0 +++').replace('[pid 102] +++ exited with 0 +++\n[pid 101] getpid()', '[pid 102] getppid() = 99\n[pid 101] getpid()'),
        'no_newline': good.rstrip('\n'), 'empty': '',
        'partial_return': good.replace('getpid() = 101', 'getpid() ='),
        'wrong_return': good.replace('getpid() = 101', 'getpid() = 999'),
        'late_duplicate': good + '[pid 101] getpid() = 101\n',
        'truncated_exit': good.replace('+++ exited with 0 +++', '+++ exited with 0'),
    }
    record = {'inputs': {'positive': good, **negative}, 'outcomes': {}, 'complete': False}
    try:
        outcomes = record['outcomes']
        outcomes['positive'] = parse_trace(good, 101, 102, 99)
        if not all(outcomes['positive'].values()):
            raise ValueError('positive parser control failed')
        outcomes['positive_r1'] = parse_trace(good, 101, 102, 99, False)
        if not outcomes['positive_r1']['leader_call'] or not outcomes['positive_r1']['leader_exit']:
            raise ValueError('positive r1 parser control failed')
        for label, value in negative.items():
            try:
                result = parse_trace(value, 101, 102, 99)
                outcomes[label] = result
                if all(result.values()):
                    raise ValueError('parser accepted negative control ' + label)
            except ValueError as exc:
                if str(exc).startswith('parser accepted'):
                    raise
                outcomes[label] = {'rejected': str(exc)}
        record['complete'] = True
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        save('parser-controls.json', record)


def task_status(pid, tid):
    text = Path('/proc/%d/task/%d/status' % (pid, tid)).read_text()
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    return {key: int(fields[key].strip()) for key in ('Tgid', 'Pid', 'PPid', 'TracerPid')}


def shared_init(prefix):
    Path(prefix + '.shared').write_bytes(bytes(16))


def shared_read(prefix):
    return list(struct.unpack('=4i', Path(prefix + '.shared').read_bytes()))


def release(prefix, index):
    fd = os.open(prefix + '.shared', os.O_WRONLY)
    try:
        if os.pwrite(fd, struct.pack('=i', 1), index * 4) != 4:
            raise OSError('short gate write')
    finally:
        os.close(fd)
    if shared_read(prefix)[index] != 1:
        raise ValueError('gate write was not retained')


def wait_ready(prefix, fixture, tracer):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if fixture.poll() is not None:
            raise ValueError('fixture exited before ready: %s' % fixture.returncode)
        if Path(prefix + '.ready').exists():
            raw = Path(prefix + '.ready').read_text()
            if re.fullmatch(r'[0-9]+ [0-9]+\n', raw) and shared_read(prefix)[2:] == [1, 1]:
                leader, worker = map(int, raw.split())
                tids = sorted(int(p.name) for p in Path('/proc/%d/task' % fixture.pid).iterdir() if p.name.isdecimal())
                states = [task_status(fixture.pid, tid) for tid in tids]
                tracer_status = task_status(tracer.pid, tracer.pid)
                if (shared_read(prefix) != [0, 0, 1, 1] or
                        leader != fixture.pid or worker == leader or tids != sorted([leader, worker]) or
                        tracer_status['PPid'] != os.getpid() or
                        any(s['Pid'] != tid or s['Tgid'] != leader or s['PPid'] != os.getpid() or s['TracerPid'] != 0 for tid, s in zip(tids, states))):
                    raise ValueError('fixture identity, parentage or initial tracer state mismatch')
                return {'leader': leader, 'worker': worker, 'tasks': tids, 'task_statuses': states,
                        'tracer_status': tracer_status, 'ready': raw, 'shared_before': shared_read(prefix),
                        'owner_pid': os.getpid(), 'tracer_pid': tracer.pid}
        time.sleep(.01)
    raise ValueError('fixture readiness timeout')


def stop(proc, group=False):
    if proc is not None and proc.poll() is None:
        try:
            if group:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)


def native_control():
    shared_init('native')
    control = fixture = None
    record = {'complete': False, 'stage': 'start'}
    out = err = f_out = f_err = b''
    control_collected = fixture_collected = False
    try:
        control = subprocess.Popen(['./attach-fixture', 'native'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        fixture = subprocess.Popen(['./attach-fixture', 'tracee', str(control.pid), 'native'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        Path('native.pid.tmp').write_text('%d %d\n' % (fixture.pid, os.getpid()))
        Path('native.pid.tmp').replace('native.pid')
        record.update(stage='running', control_pid=control.pid, fixture_pid=fixture.pid)
        out, err = control.communicate(timeout=12)
        control_collected = True
        f_out, f_err = fixture.communicate(timeout=3)
        fixture_collected = True
        record.update(control_status=control.returncode, fixture_status=fixture.returncode)
        if (control.returncode != 0 or fixture.returncode != 0 or out or f_err or
                sorted(f_out.splitlines()) != [b'leader-done', b'worker-done'] or
                not re.search(rb'native ids=\d+,\d+ leader_getpid=[1-9]\d* worker_getppid=[1-9]\d* exits=2', err)):
            raise ValueError('native sibling attach control failed')
        record.update(complete=True, stage='complete')
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        stop(control, True)
        stop(fixture)
        if control is not None:
            if not control_collected:
                out, err = control.communicate()
            record['control_status'] = control.returncode
        if fixture is not None:
            if not fixture_collected:
                f_out, f_err = fixture.communicate()
            record['fixture_status'] = fixture.returncode
        for name, data in [('control_stdout', out), ('control_stderr', err),
                           ('fixture_stdout', f_out), ('fixture_stderr', f_err)]:
            record[name + '_base64'] = base64.b64encode(data).decode()
        save('native-control.json', record)


def candidate_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def observe(record):
    shared_init('candidate')
    tracer = fixture = None
    record.update(stage='candidate-launch', complete=False, error=None)
    save('setup-controls.json', record)
    try:
        with (HOME / 'candidate.out').open('wb') as out, (HOME / 'candidate.err').open('wb') as err, \
             (HOME / 'fixture.out').open('wb') as f_out, (HOME / 'fixture.err').open('wb') as f_err:
            candidate_env = dict(os.environ, PATH='/empty')
            tracer = subprocess.Popen(['/opt/bashos-parity/candidate', '--noprofile', '--norc', '-c',
                                       'IFS= read -r p || exit 97; strace -p "$p"'],
                                      stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True,
                                      env=candidate_env, preexec_fn=candidate_limit)
            fixture = subprocess.Popen(['./attach-fixture', 'tracee', str(tracer.pid), 'candidate'],
                                       stdout=f_out, stderr=f_err)
            record.update(stage='candidate-readiness', tracer_pid=tracer.pid, fixture_pid=fixture.pid)
            save('setup-controls.json', record)
            pre = wait_ready('candidate', fixture, tracer)
            record['preconditions'] = pre
            if tracer.poll() is not None:
                raise ValueError('candidate shell exited before invocation')
            tracer.stdin.write(('%d\n' % fixture.pid).encode())
            tracer.stdin.close()
            record['invoked'] = True
            record['stage'] = 'attach-monitor'
            samples = []
            record['tracer_samples'] = samples
            record['stable_both_attached'] = False
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                states = [task_status(fixture.pid, tid) for tid in pre['tasks']]
                sample = [s['TracerPid'] for s in states]
                if any(value not in (0, tracer.pid) for value in sample):
                    raise ValueError('unexpected tracer on fixture task')
                samples.append(sample)
                if sample == [tracer.pid, tracer.pid]:
                    reverse = [task_status(fixture.pid, tid)['TracerPid'] for tid in reversed(pre['tasks'])]
                    reverse.reverse()
                    if any(value not in (0, tracer.pid) for value in reverse):
                        raise ValueError('unexpected tracer on fixture task')
                    samples.append(reverse)
                    if reverse == [tracer.pid, tracer.pid]:
                        record['stable_both_attached'] = True
                        break
                if tracer.poll() is not None:
                    break
                time.sleep(.01)
            record['tracer_samples'] = samples
            record['stage'] = 'worker-release'
            release('candidate', 0)
            record['worker_release'] = True
            deadline = time.monotonic() + 4
            while Path('/proc/%d/task/%d' % (fixture.pid, pre['worker'])).exists() and time.monotonic() < deadline:
                if fixture.poll() is not None:
                    raise ValueError('fixture exited before worker completion')
                time.sleep(.01)
            if Path('/proc/%d/task/%d' % (fixture.pid, pre['worker'])).exists():
                raise ValueError('worker did not exit after release')
            record['worker_gone_before_leader_release'] = True
            record['stage'] = 'leader-release'
            release('candidate', 1)
            record['leader_release'] = True
            record['stage'] = 'fixture-completion'
            fixture.wait(timeout=5)
            record['fixture_status'] = fixture.returncode
            if fixture.returncode != 0:
                raise ValueError('fixture did not exit naturally with zero status')
            try:
                tracer.wait(timeout=3)
                record['candidate_timeout'] = False
            except subprocess.TimeoutExpired:
                record['candidate_timeout'] = True
                stop(tracer, True)
            record['candidate_status'] = tracer.returncode
        if (HOME / 'fixture.err').read_bytes() or sorted((HOME / 'fixture.out').read_bytes().splitlines()) != [b'leader-done', b'worker-done']:
            raise ValueError('fixture output incomplete or erroneous')
        if any((HOME / name).stat().st_size >= LIMIT for name in ('candidate.out', 'candidate.err')):
            raise ValueError('candidate output hit capture size limit; observation incomplete')
        record.update(stage='complete', complete=True)
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        stop(tracer, True)
        stop(fixture)
        if tracer is not None:
            record['candidate_status'] = tracer.returncode
        if fixture is not None:
            record['fixture_status'] = fixture.returncode
        save('setup-controls.json', record)


def setup():
    record = {'stage': 'parser-controls', 'complete': False, 'invoked': False, 'error': None}
    save('setup-controls.json', record)
    try:
        parser_controls()
        record['stage'] = 'compile'; save('setup-controls.json', record)
        with (HOME / 'gcc.out').open('wb') as out, (HOME / 'gcc.err').open('wb') as err:
            subprocess.run(['/usr/bin/gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-pthread',
                            '-o', 'attach-fixture', '/opt/bashos-parity/harness/helpers/strace-attach-reviewed.c'],
                           stdout=out, stderr=err, check=True, timeout=20)
        record['stage'] = 'native-control'; save('setup-controls.json', record)
        native_control()
        observe(record)
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        save('setup-controls.json', record)
        raise


def verify(requirement):
    checks = {}
    failures = []
    classification = 'candidate_mismatch'
    try:
        record = json.loads((HOME / 'setup-controls.json').read_text())
        native = json.loads((HOME / 'native-control.json').read_text())
        if not record['complete'] or record['error'] or not record['invoked'] or not native['complete']:
            raise ValueError('incomplete infrastructure controls')
        pre = record['preconditions']
        trace_bytes = (HOME / 'candidate.err').read_bytes()
        try:
            trace = trace_bytes.decode('utf-8', 'strict')
            parsed = parse_trace(trace, pre['leader'], pre['worker'], pre['owner_pid'], requirement == 'r2')
        except (ValueError, UnicodeError) as exc:
            failures.append('candidate_trace_rejected: ' + str(exc))
            parsed = {'leader_call': False, 'leader_exit': False, 'worker_call': False, 'worker_exit': False}
        leader_index = pre['tasks'].index(pre['leader'])
        checks = {'leader_call': parsed['leader_call'], 'leader_exit': parsed['leader_exit'],
                  'leader_attached': any(sample[leader_index] == pre['tracer_pid'] for sample in record['tracer_samples']),
                  'candidate_status': record['candidate_status'] == 0 and not record['candidate_timeout'],
                  'candidate_stdout': (HOME / 'candidate.out').read_bytes() == b''}
        if requirement == 'r2':
            checks.update(worker_call=parsed['worker_call'], worker_exit=parsed['worker_exit'],
                          both_attached=record['stable_both_attached'])
        failures.extend(name for name, passed in checks.items() if not passed)
    except (OSError, KeyError, ValueError, UnicodeError) as exc:
        classification = 'infrastructure_error'
        failures.append('assessment_infrastructure_error: ' + str(exc))
    if not failures:
        classification = 'candidate_match'
    save('assertions.json', {'requirement': requirement, 'classification': classification, 'checks': checks, 'failures': failures})
    if failures:
        print('attach assertion failures: ' + ', '.join(failures))
        return 1
    print(requirement + '-ok')
    return 0


def main():
    guard()
    if sys.argv[1:] == ['setup']:
        setup(); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'verify' and sys.argv[2] in ('r1', 'r2'):
        return verify(sys.argv[2])
    raise ValueError('expected setup or verify r1/r2')


if __name__ == '__main__':
    raise SystemExit(main())
