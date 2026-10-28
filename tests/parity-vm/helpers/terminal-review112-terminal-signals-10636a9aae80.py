#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only owned-session signal and terminal-restoration observer."""
import fcntl
import json
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid
from pathlib import Path

# The root evaluator has verified the exact VM UUID before dropping privileges.
# The readable marker is checked only for UUID format here; sys_vendor is
# unprivileged-readable, unlike the DMI product UUID.
def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() not in (2000,)
                or os.geteuid() != os.getuid()
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture UID, or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires the disposable QEMU parity guest and fixture scratch') from exc


require_guest()
HOME = Path(os.environ['HOME'])
SHOW = b'\x1b[?25h'
LIMIT = 128 * 1024


def mode_fields(attrs):
    return {'iflag': attrs[0], 'oflag': attrs[1], 'cflag': attrs[2],
            'lflag': attrs[3], 'ispeed': attrs[4], 'ospeed': attrs[5],
            'cc': [v if isinstance(v, int) else v[0] for v in attrs[6]],
            'VMIN_index': termios.VMIN, 'VTIME_index': termios.VTIME}


def stub():
    saved = termios.tcgetattr(0)
    active = list(saved)
    active[6] = list(saved[6])
    active[3] &= ~(termios.ICANON | termios.ECHO)
    active[6][termios.VMIN] = 0
    active[6][termios.VTIME] = 0
    stop = [False]
    def handler(signum, frame):
        stop[0] = True
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, handler)
    termios.tcsetattr(0, termios.TCSANOW, active)
    os.write(1, b'STUB-READY\n')
    while not stop[0]:
        time.sleep(.02)
    termios.tcsetattr(0, termios.TCSANOW, saved)
    os.write(1, SHOW)
    return 0



def escape_stub(delay):
    saved = termios.tcgetattr(0)
    active = list(saved)
    active[6] = list(saved[6])
    active[3] &= ~(termios.ICANON | termios.ECHO)
    active[6][termios.VMIN] = 1
    active[6][termios.VTIME] = 0
    termios.tcsetattr(0, termios.TCSANOW, active)
    os.write(1, b'STUB-READY\n')
    os.read(0, 1)
    time.sleep(delay)
    os.write(1, b'ESCAPE\r\n')
    termios.tcsetattr(0, termios.TCSANOW, saved)
    return 0


def observe_escape(command, is_stub):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    raw = bytearray()
    events = []
    start = time.monotonic()
    deadline = start + 8
    child = None
    error = None
    elapsed = None
    result = {'raw-mode': False, 'escape-record': False, 'grace-window': False,
              'child-exited': False, 'termios-restored': False}
    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    def pump():
        if select.select([master], [], [], .01)[0]:
            raw.extend(os.read(master, 4096))
            if len(raw) > LIMIT:
                raise RuntimeError('PTY output limit')
    try:
        child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, preexec_fn=child_setup)
        while time.monotonic() < deadline:
            pump()
            attrs = termios.tcgetattr(slave)
            if not attrs[3] & (termios.ICANON | termios.ECHO) and (not is_stub or b'STUB-READY' in raw):
                break
            if child.poll() is not None:
                raise RuntimeError('reader exited before raw readiness')
        else:
            raise TimeoutError('raw readiness timeout')
        result['raw-mode'] = True
        events.append({'event': 'raw-ready', 'offset': len(raw),
                       't_ms': round((time.monotonic()-start)*1000),
                       'child_pid': child.pid, 'termios': mode_fields(attrs)})
        t0 = time.monotonic()
        os.write(master, b'\x1b')
        events.append({'event': 'escape-sent', 'offset': len(raw),
                       't_ms': round((time.monotonic()-start)*1000),
                       'child_pid': child.pid, 'bytes_hex': '1b'})
        while b'ESCAPE' not in raw and time.monotonic() < deadline:
            pump()
            if child.poll() is not None and b'ESCAPE' not in raw:
                raise RuntimeError('reader exited without ESCAPE')
        if b'ESCAPE' not in raw:
            raise TimeoutError('ESCAPE output timeout')
        elapsed = (time.monotonic() - t0) * 1000
        result['escape-record'] = True
        result['grace-window'] = 30 <= elapsed < 500
        events.append({'event': 'escape-record', 'offset': len(raw), 'elapsed_ms': round(elapsed, 2)})
        while child.poll() is None and time.monotonic() < deadline:
            pump()
        result['child-exited'] = child.poll() is not None
        result['termios-restored'] = termios.tcgetattr(slave) == before
    except (OSError, RuntimeError, TimeoutError) as exc:
        error = str(exc)
    finally:
        after = termios.tcgetattr(slave)
        forced = False
        if child is not None and child.poll() is None:
            forced = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        os.close(master)
        os.close(slave)
    return bytes(raw[:LIMIT]), {'results': result, 'error': error, 'elapsed_ms': elapsed,
                               'events': events, 'status': None if child is None else child.returncode,
                               'child_pid': None if child is None else child.pid, 'forced_cleanup': forced,
                               'before': mode_fields(before), 'after': mode_fields(after)}

def observe(command, signum, name, need_show):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    raw = bytearray()
    events = []
    start = time.monotonic()
    deadline = start + 9
    child = None
    result = {'raw-mode': False, 'signal-delivered': False, 'child-exited': False,
              'termios-restored': False, 'cursor-shown': False}
    error = None
    def event(kind, **fields):
        events.append({'event': kind, 't_ms': round((time.monotonic()-start)*1000),
                       'offset': len(raw), **fields})
    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    def pump():
        if select.select([master], [], [], .025)[0]:
            data = os.read(master, 65536)
            raw.extend(data)
            if len(raw) > LIMIT:
                raise RuntimeError('PTY output limit')
    try:
        child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, preexec_fn=child_setup)
        while time.monotonic() < deadline:
            pump()
            attrs = termios.tcgetattr(slave)
            mode = not attrs[3] & (termios.ICANON | termios.ECHO)
            ready = (b'STUB-READY' in raw if name == 'stub' else
                     b'Score:' in raw if name == 'tetris' else True)
            if mode and ready:
                result['raw-mode'] = True
                event('raw-ready', child_pid=child.pid, termios=mode_fields(attrs))
                break
            if child.poll() is not None:
                raise RuntimeError('child exited before raw readiness')
        if not result['raw-mode']:
            raise TimeoutError('raw readiness timeout')
        # child is an unreaped leader of a session this observer created, so the
        # PID cannot be reused. This only runs inside a disposable parity VM.
        signal_offset = len(raw)
        os.kill(child.pid, signum)
        result['signal-delivered'] = True
        event('signal-sent', child_pid=child.pid, signal=signum)
        while child.poll() is None and time.monotonic() < deadline:
            pump()
        if child.poll() is None:
            raise TimeoutError('child did not exit after signal')
        result['child-exited'] = True
        event('child-exited', child_pid=child.pid, status=child.returncode)
        while select.select([master], [], [], 0)[0]:
            raw.extend(os.read(master, 65536))
        after = termios.tcgetattr(slave)
        result['termios-restored'] = after == before
        result['cursor-shown'] = SHOW in raw[signal_offset:]
    except (OSError, RuntimeError, TimeoutError) as exc:
        error = str(exc)
        after = termios.tcgetattr(slave)
    finally:
        forced = False
        if child is not None and child.poll() is None:
            forced = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        os.close(master)
        os.close(slave)
    report = {'kind': name, 'signal': signum, 'results': result, 'error': error,
              'status': None if child is None else child.returncode,
              'child_pid': None if child is None else child.pid, 'forced_cleanup': forced,
              'before': mode_fields(before), 'after': mode_fields(after), 'events': events}
    return bytes(raw[:LIMIT]), report


def save(prefix, raw, report):
    (HOME / (prefix + '.raw')).write_bytes(raw)
    (HOME / (prefix + '.json')).write_text(json.dumps(report, indent=2) + '\n')


def main():
    mode = sys.argv[1]
    if mode == 'stub':
        return stub()
    if mode == 'escape-stub':
        return escape_stub(float(sys.argv[2]))
    if mode == 'control':
        outcomes = []
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            raw, result = observe([sys.executable, __file__, 'stub'], signum, 'stub', True)
            save('signal-control-' + str(signum), raw, result)
            outcomes.append(not result['error'] and all(result['results'].values()))
        for delay, expected in ((0.05, True), (0.0, False)):
            raw, result = observe_escape([sys.executable, __file__, 'escape-stub', str(delay)], True)
            save('escape-control-' + str(delay), raw, result)
            outcomes.append(not result['error'] and result['results']['escape-record'] and
                            result['results']['grace-window'] == expected and
                            result['results']['termios-restored'])
        if not all(outcomes):
            print('signal observer control failed', file=sys.stderr)
            return 2
        print('signal observer control PASS')
        return 0
    if mode == 'escape':
        shell = sys.argv[2]
        raw, report = observe_escape([shell, '--noprofile', '--norc', '-c',
                                      'termpixel key-read --timeout 7000'], False)
        save('escape-actual', raw, report)
        print('observer-control=PASS')
        for key, value in report['results'].items():
            print(key + '=' + ('PASS' if value else 'FAIL'))
        return 0
    if mode not in ('tetris', 'termpixel'):
        raise SystemExit('unknown mode')
    shell, signal_name = sys.argv[2:]
    signum = getattr(signal, signal_name)
    body = 'bsdgames tetris --seed 12345 -l 1' if mode == 'tetris' else 'termpixel key-read --timeout 10000'
    raw, report = observe([shell, '--noprofile', '--norc', '-c', body], signum, mode, mode == 'tetris')
    save('signal-actual', raw, report)
    print('observer-control=PASS')
    for key in ('raw-mode', 'signal-delivered', 'child-exited', 'termios-restored'):
        print(key + '=' + ('PASS' if report['results'][key] else 'FAIL'))
    if mode == 'tetris':
        print('cursor-shown=' + ('PASS' if report['results']['cursor-shown'] else 'FAIL'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
