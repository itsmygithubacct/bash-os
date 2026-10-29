#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only PTY step observer with raw live modes and graceful failed-step cleanup.

The candidate predicates and step order are supplied as data from the original
fixture. A failed step stays failed; remaining behavioral steps are not run.
The observer then attempts only the configured cleanup keys against its own
PTY child and records whether forced cleanup was necessary.
"""
import base64
import fcntl
import json
import os
import pty
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import traceback
import uuid
from pathlib import Path


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture UID, or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires the disposable QEMU parity guest and fixture scratch') from exc


require_guest()
sys.path.insert(0, '/opt/bashos-parity/harness')
import terminal

LIMIT = 512 * 1024
HOME = Path('/tmp/parity-home')


def execute(shell, script, case, cleanup_keys, step_budget=None):
    height, width = case.get('size', [24, 80])
    master, slave = pty.openpty()
    os.set_blocking(master, False)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))
    # The already-dropped fixture UID owns its newly opened slave. No attempt is
    # made to chown it or regain privileges; the outer guest applied limits.
    info = os.fstat(slave)
    if info.st_uid != 2000:
        os.close(master)
        os.close(slave)
        raise RuntimeError('new PTY slave is not owned by fixture uid')
    os.fchmod(slave, 0o620)
    terminal.initial_modes(slave)
    before = terminal.modes(termios.tcgetattr(slave))
    terminal.set_subreaper()
    started = time.monotonic()
    deadline = started + case.get('timeout', 15)
    session = terminal.Session(master, slave, height, width, deadline, case.get('answer_queries', False))
    events, live_modes, cleanup_events = [], [], []
    proc = None
    failure = None
    infrastructure_error = None
    trace = None
    after = None
    cursor = 0
    forced = False
    stray = []
    finished_steps = 0

    def event(index, action, **detail):
        events.append({'step': index, 'action': action,
                       't_ms': round((time.monotonic()-started)*1000),
                       'offset': len(session.captured), **detail})

    def pump(wait=.03):
        session.pump(wait)
        if len(session.captured) > LIMIT:
            raise RuntimeError('PTY output limit')
        if session.decoder_error:
            raise RuntimeError(session.decoder_error)

    def wait_for(condition, desc):
        nonlocal infrastructure_error
        until = deadline - 3
        if step_budget is not None:
            until = min(until, time.monotonic() + step_budget)
        problem = 'not reached'
        while time.monotonic() < until:
            problem = condition()
            if problem is None:
                return
            if terminal.leader_exited(proc.pid):
                session.drain()
                problem = condition()
                if problem is None:
                    return
                raise RuntimeError('child exited before ' + desc + ': ' + str(problem))
            pump(min(.03, max(0, until-time.monotonic())))
        raise TimeoutError('step deadline for ' + desc + ': ' + str(problem))

    def mode_problem(spec):
        attrs = termios.tcgetattr(slave)
        for name in spec.get('set', []):
            index, mask = terminal.FLAGS[name]
            if attrs[index] & mask != mask:
                return name + ' is clear'
        for name in spec.get('clear', []):
            index, mask = terminal.FLAGS[name]
            if attrs[index] & mask:
                return name + ' is set'
        for name, want in spec.get('cc', {}).items():
            value = attrs[6][terminal.CC[name]]
            value = value if isinstance(value, int) else value[0]
            if value != want:
                return name + ' is ' + str(value)
        live_modes.append({'t_ms': round((time.monotonic()-started)*1000),
                           'offset': len(session.captured), 'requested': spec,
                           'actual': terminal.modes(attrs),
                           'VMIN_index': termios.VMIN, 'VTIME_index': termios.VTIME})
        return None

    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    def cleanup_attempt(data, label):
        if proc is None or terminal.leader_exited(proc.pid):
            return
        cleanup_events.append({'event': label, 't_ms': round((time.monotonic()-started)*1000),
                               'offset': len(session.captured), 'bytes_hex': data.hex()})
        try:
            session.write(data)
            until = min(deadline-.2, time.monotonic()+1)
            while time.monotonic() < until and not terminal.leader_exited(proc.pid):
                pump(.03)
        except (OSError, RuntimeError, TimeoutError) as exc:
            cleanup_events.append({'event': 'cleanup-error', 'error': str(exc)})

    try:
        proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script],
                                stdin=slave, stdout=slave, stderr=slave,
                                preexec_fn=child_setup)
        for index, step in enumerate(case['steps']):
            (action, value), = step.items()
            if action == 'screen':
                wait_for(lambda: terminal.screen_problem(session, value), 'screen step ' + str(index))
                event(index, action, screen=session.rows(),
                      cursor=[session.screen.cursor.y, session.screen.cursor.x])
            elif action == 'cursor_line':
                def cursor_problem():
                    if session.screen is None or session.decoder_error:
                        return session.decoder_error or 'screen decoder unavailable'
                    y = session.screen.cursor.y
                    rows = session.rows()
                    if not 0 <= y < len(rows):
                        return 'cursor is outside the screen'
                    return None if re.search(value, rows[y]) else 'cursor is on ' + repr(rows[y])
                wait_for(cursor_problem, 'cursor line step ' + str(index))
                event(index, action, cursor=[session.screen.cursor.y, session.screen.cursor.x],
                      screen=session.rows())
            elif action == 'termios':
                wait_for(lambda: mode_problem(value), 'termios step ' + str(index))
                event(index, action, live_sample=len(live_modes)-1)
            elif action == 'expect':
                regex = re.compile(value.encode())
                wait_for(lambda: None if regex.search(session.captured, cursor) else 'not seen',
                         'expect step ' + str(index))
                cursor = regex.search(session.captured, cursor).end()
                event(index, action, matched_end=cursor)
            elif action == 'output_lacks':
                session.drain()
                if re.search(value.encode(), session.captured):
                    raise RuntimeError('forbidden output at step ' + str(index))
                event(index, action)
            elif action in ('send', 'send_base64', 'key'):
                data = (value.encode() if action == 'send' else
                        base64.b64decode(value) if action == 'send_base64' else
                        terminal.KEYS[value][session.cursor_application_mode()])
                event(index, action + '-begin', bytes_hex=data.hex())
                session.write(data)
                event(index, action, bytes_hex=data.hex())
            elif action == 'resize':
                h, w = value
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', h, w, 0, 0))
                if session.screen:
                    session.screen.resize(lines=h, columns=w)
                event(index, action, size=value)
            elif action == 'settle_ms':
                end = time.monotonic() + value / 1000
                while time.monotonic() < end:
                    pump(min(.02, max(0, end-time.monotonic())))
                event(index, action)
            elif action == 'quiet_ms':
                last = time.monotonic()
                while time.monotonic() - last < value / 1000:
                    if session.pump(.01):
                        last = time.monotonic()
                event(index, action)
            else:
                raise ValueError('unsupported repair PTY step: ' + action)
            finished_steps += 1
        wait_for(lambda: None if terminal.leader_exited(proc.pid) else 'child still running',
                 'natural exit')
        session.drain()
    except (OSError, RuntimeError, TimeoutError) as exc:
        failure = type(exc).__name__ + ': ' + str(exc)
        if session.decoder_error:
            infrastructure_error = session.decoder_error
    except Exception as exc:
        failure = infrastructure_error = type(exc).__name__ + ': ' + str(exc)
        trace = traceback.format_exc()
    finally:
        if proc is not None and not terminal.leader_exited(proc.pid):
            cleanup_attempt(cleanup_keys, 'graceful-cleanup')
            if not terminal.leader_exited(proc.pid) and cleanup_keys != b'\x03':
                cleanup_attempt(b'\x03', 'interrupt-cleanup')
            if not terminal.leader_exited(proc.pid):
                forced = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            after = terminal.modes(termios.tcgetattr(slave))
        except (OSError, termios.error) as exc:
            cleanup_events.append({'event': 'termios-error', 'error': str(exc)})
        if proc is not None:
            # The unreaped leader keeps the group identity reserved. Kill only
            # owned descendants and record them before reaping that leader.
            for item in terminal.owned_processes(proc.pid):
                if item['pid'] == proc.pid or item['state'] == 'Z':
                    continue
                stray.append(item)
                try:
                    os.kill(item['pid'], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired as exc:
                cleanup_events.append({'event': 'wait-error', 'error': str(exc)})
        os.close(master)
        os.close(slave)
    code = None if proc is None else proc.returncode
    status = None if code is None else code if code >= 0 else 128-code
    report = {'failure': failure, 'infrastructure_error': infrastructure_error, 'traceback': trace,
              'events': events, 'live_termios': live_modes, 'cleanup_events': cleanup_events,
              'child_pid': None if proc is None else proc.pid, 'status': status,
              'signal': -code if code is not None and code < 0 else None,
              'forced_cleanup': forced, 'stray_descendants': stray, 'termios_before': before,
              'termios_after': after, 'completed_steps': finished_steps,
              'total_steps': len(case['steps']), 'decoder_error': session.decoder_error}
    return report, bytes(session.captured[:LIMIT])


def control():
    stub = '''import os,select,termios,time
s=termios.tcgetattr(0); a=list(s); a[6]=list(s[6]); a[3]&=~(termios.ICANON|termios.ECHO); termios.tcsetattr(0,termios.TCSANOW,a)
os.write(1,b"READY\\r\\n")
try:
 while True:
  if select.select([0],[],[],0.1)[0]:
   c=os.read(0,1)
   if c in (b"x",b"q"): break
 os.write(1,b"ACCEPTED\\r\\n")
finally: termios.tcsetattr(0,termios.TCSANOW,s)
'''
    body = '/usr/bin/python3 -c ' + shlex.quote(stub)
    steps = [{'termios': {'clear': ['ICANON', 'ECHO']}}, {'expect': 'READY'},
             {'send': 'x'}, {'expect': 'ACCEPTED'}]
    shell = '/opt/bash-5.3.15/bin/bash'
    good, _ = execute(shell, body, {'steps': steps, 'timeout': 8}, b'q', step_budget=2)
    bad, _ = execute(shell, body, {'steps': steps[:2]+[{'expect': 'NEVER-HAPPENS'}], 'timeout': 8}, b'q', step_budget=.5)
    okay = (good['failure'] is None and good['status'] == 0 and good['live_termios']
            and good['termios_before'] == good['termios_after'] and not good['forced_cleanup']
            and bad['failure'] is not None and bad['completed_steps'] == 2
            and any(x['event'] == 'graceful-cleanup' for x in bad['cleanup_events'])
            and bad['status'] == 0 and not bad['forced_cleanup'])
    (HOME / 'pty-repair-control.json').write_text(json.dumps({'good': good, 'expected_failure': bad}, indent=2)+'\n')
    if not okay:
        raise SystemExit('PTY repair observer control failed')
    print('PTY repair observer control PASS')


def main():
    if sys.argv[1] == 'control':
        control()
        return 0
    if sys.argv[1] != 'run' or len(sys.argv) != 4 or sys.argv[3] not in ('candidate', 'reference'):
        raise SystemExit('usage: control | run SHELL candidate|reference')
    shell, role = sys.argv[2:]
    allowed = {'candidate': '/opt/bashos-parity/candidate', 'reference': '/opt/bash-5.3.15/bin/bash'}
    if shell != allowed[role]:
        raise SystemExit('unexpected parity shell')
    config = json.loads(Path('pty-repair-config.json').read_text())
    report, raw = execute(shell, config[role + '_script'], config,
                          base64.b64decode(config['cleanup_base64']))
    (HOME / 'pty-repair.raw').write_bytes(raw)
    (HOME / 'pty-repair.json').write_text(json.dumps(report, indent=2)+'\n')
    print('observer=PASS' if report['infrastructure_error'] is None else 'observer=FAIL')
    print('steps=PASS' if report['failure'] is None and report['completed_steps'] == report['total_steps'] else 'steps=FAIL')
    print('exit=PASS' if report['status'] == config['expected_status'] else 'exit=FAIL')
    print('restored=PASS' if report['termios_before'] == report['termios_after'] else 'restored=FAIL')
    print('cleanup=PASS' if not report['forced_cleanup'] and not report['stray_descendants'] else 'cleanup=FAIL')
    return 0


if __name__ == '__main__':
    sys.exit(main())
