#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disposable-VM password observer; checks every decoded terminal byte/frame."""
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
import pyte

try:
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
except (OSError, ValueError):
    raise SystemExit('requires disposable parity VM marker')
if os.getuid() != 2000:
    raise SystemExit('requires parity fixture UID')
HOME = Path(os.environ['HOME'])
SECRET = b'@~%^&}'
LIMIT = 128 * 1024


def stub(kind):
    saved = termios.tcgetattr(0)
    raw = list(saved)
    raw[6] = list(saved[6])
    raw[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
    raw[6][termios.VMIN] = 1
    raw[6][termios.VTIME] = 0
    termios.tcsetattr(0, termios.TCSANOW, raw)
    os.write(1, b'Choose secret\r\n')
    data = bytearray()
    while True:
        ch = os.read(0, 1)
        if ch in (b'\r', b'\n', b''):
            break
        data.extend(ch)
        os.write(1, ch if kind == 'leak' else b'*')
    (HOME / ('stub-result-' + kind)).write_bytes(data)
    termios.tcsetattr(0, termios.TCSANOW, saved)
    return 0


def observe(command, result_path):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    screen = pyte.Screen(80, 24)
    stream = pyte.ByteStream(screen)
    raw = bytearray()
    leaks = []
    events = []
    started = time.monotonic()
    deadline = started + 10
    child = None
    error = None
    result = {'ready': False, 'baseline-clean': False, 'result': False,
              'status': False, 'restored': False, 'no-leak': False}
    def log_event(name):
        events.append({'event': name, 't_ms': round((time.monotonic()-started)*1000), 'offset': len(raw)})
    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    def take(wait=.02):
        if not select.select([master], [], [], wait)[0]:
            return
        block = os.read(master, 4096)
        for b in block:
            raw.append(b)
            if len(raw) > LIMIT:
                raise RuntimeError('PTY output limit')
            stream.feed(bytes([b]))
            if result['ready']:
                for row, line in enumerate(screen.display):
                    hit = next((chr(c) for c in SECRET if chr(c) in line), None)
                    if hit and len(leaks) < 16:
                        leaks.append({'offset': len(raw), 'row': row, 'character': hit})
                        break
    try:
        child = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, preexec_fn=child_setup)
        while time.monotonic() < deadline:
            take()
            attrs = termios.tcgetattr(slave)
            if (not attrs[3] & (termios.ICANON | termios.ECHO) and
                    any('Choose secret' in line for line in screen.display)):
                break
            if child.poll() is not None:
                raise RuntimeError('child exited before password input readiness')
        else:
            raise TimeoutError('password input readiness timeout')
        result['baseline-clean'] = not any(chr(c) in line for c in SECRET for line in screen.display)
        if not result['baseline-clean']:
            raise RuntimeError('fixture secret characters already present on the initial screen')
        result['ready'] = True
        log_event('input-ready')
        for ch in SECRET:
            os.write(master, bytes([ch]))
            end = time.monotonic() + .10
            while time.monotonic() < end:
                take(min(.02, max(0, end-time.monotonic())))
        log_event('secret-sent')
        os.write(master, b'\r')
        while child.poll() is None and time.monotonic() < deadline:
            take()
        if child.poll() is None:
            raise TimeoutError('password widget did not finish')
        while select.select([master], [], [], 0)[0]:
            take(0)
        result['status'] = child.returncode == 0
        contents = result_path.read_bytes() if result_path.exists() else b''
        result['result'] = contents in (SECRET, SECRET + b'\n')
        result['restored'] = termios.tcgetattr(slave) == before
        result['no-leak'] = not leaks
        log_event('finished')
    except (OSError, RuntimeError, TimeoutError) as exc:
        error = str(exc)
    finally:
        after = termios.tcgetattr(slave)
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        os.close(master)
        os.close(slave)
    return bytes(raw[:LIMIT]), {'results': result, 'error': error, 'leaks': leaks,
                                'events': events, 'status': None if child is None else child.returncode,
                                'before': repr(before), 'after': repr(after)}


def save(prefix, raw, report):
    (HOME / (prefix + '.raw')).write_bytes(raw)
    (HOME / (prefix + '.json')).write_text(json.dumps(report, indent=2) + '\n')


def main():
    mode = sys.argv[1]
    if mode == 'stub':
        return stub(sys.argv[2])
    if mode == 'control':
        for kind in ('mask', 'leak'):
            raw, report = observe([sys.executable, __file__, 'stub', kind], HOME / ('stub-result-' + kind))
            save('password-control-' + kind, raw, report)
            good = (not report['error'] and all(report['results'][x] for x in
                    ('ready', 'baseline-clean', 'result', 'status', 'restored')) and
                    report['results']['no-leak'] == (kind == 'mask'))
            if not good:
                print('password observer control failed for ' + kind, file=sys.stderr)
                return 2
        print('password observer control PASS')
        return 0
    if mode != 'run':
        raise SystemExit('unknown mode')
    shell = sys.argv[2]
    body = 'whiptail --output-fd 3 --passwordbox "Choose secret" 9 40 3>"$HOME/password-result"'
    raw, report = observe([shell, '--noprofile', '--norc', '-c', body], HOME / 'password-result')
    save('password-actual', raw, report)
    print('observer-control=PASS')
    for key in ('ready', 'baseline-clean', 'result', 'status', 'restored', 'no-leak'):
        print(key + '=' + ('PASS' if report['results'][key] else 'FAIL'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
