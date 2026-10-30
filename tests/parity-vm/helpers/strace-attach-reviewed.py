#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only setup, per-observation controls and checks for owned attach."""
import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

HOME = Path('/tmp/parity-home')


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


def parse_trace(text, leader, worker):
    # Entry fragments can interleave when two tasks are stopped in syscalls.
    # Match the unique TID/call prefixes, not a fabricated complete line.
    found = {}
    for label, tid, call in [('leader_call', leader, 'getpid'), ('worker_call', worker, 'getppid')]:
        found[label] = bool(re.search(r'\[pid ' + str(tid) + r'\] ' + call + r'\(', text))
    for label, tid in [('leader_exit', leader), ('worker_exit', worker)]:
        found[label] = bool(re.search(r'\[pid ' + str(tid) + r'\] \+\+\+ exited with 0 \+\+\+', text))
    return found


def setup():
    positive = '[pid 101] getpid() = 101\n[pid 102] getppid() = 99\n[pid 102] +++ exited with 0 +++\n[pid 101] +++ exited with 0 +++\n'
    controls = [positive, positive.replace('[pid 102] getppid', '[pid 103] getppid'),
                positive.replace('[pid 101] +++ exited with 0 +++', '[pid 101] +++ killed by signal 9 +++'), '']
    outcomes = [parse_trace(s, 101, 102) for s in controls]
    if not all(outcomes[0].values()) or all(outcomes[1].values()) or all(outcomes[2].values()) or any(outcomes[3].values()):
        raise ValueError('trace parser controls failed')
    save('parser-controls.json', {'inputs': controls, 'outcomes': outcomes})
    with (HOME / 'gcc.out').open('wb') as out, (HOME / 'gcc.err').open('wb') as err:
        subprocess.run(['/usr/bin/gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-pthread',
                        '-o', 'attach-fixture', '/opt/bashos-parity/harness/helpers/strace-attach-reviewed.c'],
                       stdout=out, stderr=err, check=True, timeout=20)
    os.mkfifo('native.gate', 0o600)
    control = subprocess.Popen(['./attach-fixture', 'native'], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    fixture = subprocess.Popen(['./attach-fixture', 'tracee', str(control.pid), 'native'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    Path('native.pid.tmp').write_text(str(fixture.pid) + '\n')
    Path('native.pid.tmp').replace('native.pid')
    record = {'control_pid': control.pid, 'fixture_pid': fixture.pid}
    try:
        out, err = control.communicate(timeout=17)
        fixture_out, fixture_err = fixture.communicate(timeout=3)
        record.update(control_status=control.returncode, fixture_status=fixture.returncode)
    except subprocess.TimeoutExpired:
        if control.poll() is None:
            os.killpg(control.pid, signal.SIGKILL)
        if fixture.poll() is None:
            fixture.kill()
        out, err = control.communicate()
        fixture_out, fixture_err = fixture.communicate()
        record.update(control_status=control.returncode, fixture_status=fixture.returncode, timeout=True)
    for name, data in [('control_stdout', out), ('control_stderr', err),
                       ('fixture_stdout', fixture_out), ('fixture_stderr', fixture_err)]:
        record[name + '_base64'] = base64.b64encode(data).decode()
    save('native-control.json', record)
    if (record.get('timeout') or control.returncode != 0 or fixture.returncode != 0 or out or fixture_err or
            sorted(fixture_out.splitlines()) != [b'leader-done', b'worker-done'] or
            not re.search(rb'native ids=\d+,\d+ leader_getpid=[1-9]\d* worker_getppid=[1-9]\d* exits=2', err)):
        raise ValueError('native sibling ptrace attach control failed')
    os.mkfifo('candidate.gate', 0o600)


def status(pid, tid):
    text = Path('/proc/%d/task/%d/status' % (pid, tid)).read_text()
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    return {key: int(fields[key].strip()) for key in ('Tgid', 'Pid', 'PPid', 'TracerPid')}


def launch(shell):
    with (HOME / 'fixture.out').open('wb') as out, (HOME / 'fixture.err').open('wb') as err:
        proc = subprocess.Popen(['./attach-fixture', 'tracee', str(shell), 'candidate'], stdout=out, stderr=err)
        (HOME / 'fixture.pid.tmp').write_text(str(proc.pid) + '\n')
        (HOME / 'fixture.pid.tmp').replace(HOME / 'fixture.pid')
        deadline = time.monotonic() + 6
        while not (HOME / 'preconditions.json').exists() and time.monotonic() < deadline:
            time.sleep(.01)
        if (HOME / 'preconditions.json').exists():
            pre = json.loads((HOME / 'preconditions.json').read_text())
            if not pre.get('error'):
                monitor(proc.pid, shell)
            else:
                proc.kill()
        else:
            proc.kill()
        try:
            rc = proc.wait(timeout=16)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            (HOME / 'fixture.status').write_text('timeout\n')
            return 1
    (HOME / 'fixture.status').write_text(str(rc) + '\n')
    return 0


def prepare(supervisor, shell):
    info = {'supervisor_pid': supervisor, 'shell_pid': shell, 'error': None}
    try:
        deadline = time.monotonic() + 5
        raw = ''
        while time.monotonic() < deadline:
            if Path('candidate.ready').exists() and (HOME / 'fixture.pid').exists():
                raw = Path('candidate.ready').read_text()
                if re.fullmatch(r'[0-9]+ [0-9]+\n', raw):
                    break
            time.sleep(.01)
        pid = int((HOME / 'fixture.pid').read_text().strip())
        numbers = raw.split()
        if len(numbers) != 2 or not all(x.isdecimal() for x in numbers):
            raise ValueError('malformed readiness record')
        leader, worker = map(int, numbers)
        tasks = sorted(int(p.name) for p in Path('/proc/%d/task' % pid).iterdir() if p.name.isdecimal())
        states = [status(pid, tid) for tid in tasks]
        supervisor_status = status(supervisor, supervisor)
        info.update(fixture_pid=pid, ready=raw, leader=leader, worker=worker, tasks=tasks,
                    statuses=states, supervisor_status=supervisor_status)
        if (leader != pid or worker == pid or tasks != sorted([pid, worker]) or
                supervisor_status['PPid'] != shell or
                any(s['Tgid'] != pid or s['PPid'] != supervisor or s['TracerPid'] != 0 for s in states)):
            raise ValueError('owned live untraced two-thread fixture not established')
    except (OSError, ValueError, KeyError) as exc:
        info['error'] = str(exc)
    save('preconditions.json', info)
    return 1 if info['error'] else 0


def monitor(pid, shell):
    info = json.loads((HOME / 'preconditions.json').read_text())
    seen = []
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        try:
            states = [status(pid, tid) for tid in info['tasks']]
            seen.append([s['TracerPid'] for s in states])
            if all(s['TracerPid'] == shell for s in states):
                break
        except (OSError, KeyError):
            seen.append(['unavailable'])
            break
        time.sleep(.01)
    attached = bool(seen and seen[-1] == [shell, shell])
    result = {'tracer_samples': seen, 'both_attached_before_release': attached, 'release_error': None}
    try:
        fd = os.open('candidate.gate', os.O_WRONLY | os.O_NONBLOCK)
        try:
            if os.write(fd, b'GG') != 2:
                raise OSError('short gate write')
        finally:
            os.close(fd)
    except OSError as exc:
        result['release_error'] = str(exc)
    save('monitor.json', result)
    return 1 if result['release_error'] else 0


def verify(requirement):
    checks = {}
    problems = []
    try:
        deadline = time.monotonic() + 3
        while not (HOME / 'fixture.status').exists() and time.monotonic() < deadline:
            time.sleep(.01)
        pre = json.loads((HOME / 'preconditions.json').read_text())
        mon = json.loads((HOME / 'monitor.json').read_text())
        if pre['error'] or mon['release_error']:
            raise ValueError('fixture precondition or release failed')
        trace_bytes = (HOME / 'candidate.err').read_bytes()
        if len(trace_bytes) > 900000:
            raise ValueError('trace exceeds safe diagnostic capture size')
        trace = trace_bytes.decode('utf-8', 'strict')
        parsed = parse_trace(trace, pre['leader'], pre['worker'])
        leader_index = pre['tasks'].index(pre['leader'])
        checks = {'leader_call': parsed['leader_call'], 'leader_exit': parsed['leader_exit'],
                  'leader_attached': any(len(sample) == 2 and sample[leader_index] == pre['shell_pid']
                                         for sample in mon['tracer_samples'])}
        if requirement == 'r2':
            checks.update(worker_call=parsed['worker_call'], worker_exit=parsed['worker_exit'],
                          both_attached=mon['both_attached_before_release'])
        checks.update(
                      fixture_exit=(HOME / 'fixture.status').read_text().strip() == '0',
                      tracer_exit=(HOME / 'candidate.status').read_text().strip() == '0',
                      fixture_markers=sorted((HOME / 'fixture.out').read_bytes().splitlines()) == [b'leader-done', b'worker-done'],
                      fixture_stderr=(HOME / 'fixture.err').read_bytes() == b'',
                      tracer_stdout=(HOME / 'candidate.out').read_bytes() == b'')
        problems.extend(name for name, ok in checks.items() if not ok)
    except (OSError, KeyError, ValueError, UnicodeError) as exc:
        problems.append('fixture_or_diagnostic_error: ' + str(exc))
    save('assertions.json', {'requirement': requirement, 'checks': checks, 'failures': problems})
    if problems:
        print('attach assertion failures: ' + ', '.join(problems))
        return 1
    print(requirement + '-ok')
    return 0


def main():
    guard()
    if sys.argv[1:] == ['setup']:
        setup(); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'launch':
        return launch(int(sys.argv[2]))
    if len(sys.argv) == 4 and sys.argv[1] in ('prepare', 'monitor'):
        pid, shell = map(int, sys.argv[2:])
        return prepare(pid, shell) if sys.argv[1] == 'prepare' else monitor(pid, shell)
    if len(sys.argv) == 3 and sys.argv[1] == 'verify' and sys.argv[2] in ('r1', 'r2'):
        return verify(sys.argv[2])
    raise ValueError('expected setup, prepare PID SHELL, monitor PID SHELL, or verify')


if __name__ == '__main__':
    raise SystemExit(main())
