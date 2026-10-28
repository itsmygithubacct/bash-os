#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only geometry-based tetris PTY observer; never runs headless mode."""
import fcntl
import json
import os
import re
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

import pyte
HOME = Path(os.environ['HOME'])
LIMIT = 128 * 1024
ROW = re.compile(r'^\|(?:\[\]| \.){10}\|$')


def board(screen):
    rows = [screen.display[y].rstrip() for y in range(1, 21)]
    if len(rows) != 20 or not all(ROW.fullmatch(row) for row in rows):
        return None
    return {(x, y) for y, row in enumerate(rows) for x in range(10)
            if row[1+2*x:3+2*x] == '[]'}


def normalized(points):
    minx = min(x for x, y in points)
    miny = min(y for x, y in points)
    return {(x-minx, y-miny) for x, y in points}


def shifted_horizontal(before, after, amount):
    # Ignore gravity's vertical translation but require exactly one horizontal
    # cell shift and the same relative vertical shape.
    if len(before) != 4 or len(after) != 4:
        return False
    by, ay = min(y for x, y in before), min(y for x, y in after)
    return {(x+amount, y-by) for x, y in before} == {(x, y-ay) for x, y in after}


def rotate_ccw(points):
    return normalized({(y, -x) for x, y in points})


def control():
    shape = {(3, 2), (4, 2), (5, 2), (3, 3)}
    lines = []
    for y in range(20):
        lines.append('|' + ''.join('[]' if (x, y) in shape else ' .' for x in range(10)) + '|')
    screen = pyte.Screen(80, 24)
    stream = pyte.ByteStream(screen)
    stream.feed(('Score: 0\r\n' + '\r\n'.join(lines)).encode())
    got = board(screen)
    shifted = {(x-1, y+1) for x, y in shape}
    rotated = {(y+4, -x+8) for x, y in shape}
    if (got != shape or not shifted_horizontal(shape, shifted, -1) or
            shifted_horizontal(shape, shifted, 1) or normalized(rotated) != rotate_ccw(shape) or
            normalized(shape) == rotate_ccw(shape)):
        return 2
    print('tetris geometry observer control PASS')
    return 0


def run(shell, mode):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    before_tio = termios.tcgetattr(slave)
    screen = pyte.Screen(80, 24)
    stream = pyte.ByteStream(screen)
    raw = bytearray()
    events = []
    start = time.monotonic()
    deadline = start + 12
    child = None
    error = None
    result = {'geometry': False, 'four-cells': False, 'transition': False,
              'quit-status': False, 'terminal-restored': False, 'cursor-shown': False}
    details = {}
    def event(name, points=None):
        events.append({'event': name, 't_ms': round((time.monotonic()-start)*1000),
                       'offset': len(raw), 'cells': None if points is None else sorted(points)})
    def send(data):
        written = os.write(master, data)
        events.append({'event': 'input', 't_ms': round((time.monotonic()-start)*1000),
                       'offset': len(raw), 'bytes_hex': data[:written].hex(),
                       'requested_hex': data.hex(), 'written': written})
        if written != len(data):
            raise OSError('short PTY input write')
    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    def pump(wait=.03):
        if select.select([master], [], [], wait)[0]:
            block = os.read(master, 65536)
            raw.extend(block)
            if len(raw) > LIMIT:
                raise RuntimeError('PTY output limit')
            stream.feed(block)
    def until(predicate, name):
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                event(name, value if isinstance(value, set) else None)
                return value
            if child.poll() is not None:
                raise RuntimeError('game exited before ' + name)
            pump()
        raise TimeoutError('waiting for ' + name)
    def next_frame(offset):
        until(lambda: b'q=quit' in raw[offset:] and board(screen) is not None, 'frame')
        return board(screen)
    def wait_for_duration(seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            pump(min(.03, max(0, end-time.monotonic())))
    try:
        child = subprocess.Popen([shell, '--noprofile', '--norc', '-c',
                                  'bsdgames tetris --seed 12345 -l 1'],
                                 stdin=slave, stdout=slave, stderr=slave, preexec_fn=child_setup)
        until(lambda: board(screen) is not None and b'q=quit' in raw, 'well')
        result['geometry'] = True
        initial = until(lambda: (p if (p := board(screen)) is not None and len(p) == 4 else None), 'four-cells')
        result['four-cells'] = True
        if mode == 'rotate':
            spawn = initial
            # Rotation at the spawn row can legitimately place one cell in
            # the invisible overflow row. Wait for an observed gravity-only
            # transition to a safe fully visible height before sending k.
            initial = until(lambda: (p if (p := board(screen)) is not None
                                     and len(p) == 4 and min(y for x, y in p) >= 2
                                     and shifted_horizontal(spawn, p, 0) else None),
                            'visible-gravity-transition')
            details['spawn'] = sorted(spawn)
        if mode in ('left', 'right', 'rotate'):
            offset = len(raw)
            send({'left': b'j', 'right': b'l', 'rotate': b'k'}[mode])
            after = next_frame(offset)
            details['before'] = sorted(initial)
            details['after'] = sorted(after)
            if mode == 'left':
                result['transition'] = shifted_horizontal(initial, after, -1)
            elif mode == 'right':
                result['transition'] = shifted_horizontal(initial, after, 1)
            else:
                result['transition'] = (len(after) == 4 and normalized(initial) != rotate_ccw(initial)
                                        and normalized(after) == rotate_ccw(initial))
        elif mode == 'pause':
            # A no-key gravity control proves this particular session advances.
            wait_for_duration(1.4)
            advancing = board(screen)
            baseline = (advancing is not None and len(advancing) == 4 and
                        min(y for x, y in advancing) > min(y for x, y in initial))
            offset = len(raw)
            send(b'p')
            paused = next_frame(offset)
            wait_for_duration(1.4)
            still = board(screen)
            offset = len(raw)
            send(b'p')
            resumed_start = next_frame(offset)
            wait_for_duration(1.4)
            resumed = board(screen)
            resumed_ok = (resumed is not None and len(resumed) == 4 and len(resumed_start) == 4 and
                          min(y for x, y in resumed) > min(y for x, y in resumed_start))
            details.update(baseline_gravity=baseline, paused=sorted(paused), after_pause=sorted(still or []),
                           resumed=sorted(resumed or []), resumed_gravity=resumed_ok)
            result['transition'] = baseline and paused == still and resumed_ok
        else:
            raise RuntimeError('unknown tetris key mode')
        event('transition', board(screen))
        send(b'q')
        while child.poll() is None and time.monotonic() < deadline:
            pump()
        if child.poll() is None:
            raise TimeoutError('quit timeout')
        while select.select([master], [], [], 0)[0]:
            pump(0)
        result['quit-status'] = child.returncode == 0 and b'Your score:' in raw
        result['terminal-restored'] = termios.tcgetattr(slave) == before_tio
        result['cursor-shown'] = b'\x1b[?25h' in raw
        event('finished')
    except (OSError, RuntimeError, TimeoutError) as exc:
        error = str(exc)
    finally:
        after_tio = termios.tcgetattr(slave)
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        os.close(master)
        os.close(slave)
    report = {'mode': mode, 'results': result, 'details': details, 'error': error, 'events': events,
              'status': None if child is None else child.returncode,
              'before': repr(before_tio), 'after': repr(after_tio)}
    (HOME / 'tetris-geometry.raw').write_bytes(raw[:LIMIT])
    (HOME / 'tetris-geometry.json').write_text(json.dumps(report, indent=2) + '\n')
    print('observer-control=PASS')
    for key, value in result.items():
        print(key + '=' + ('PASS' if value else 'FAIL'))
    return 0


if __name__ == '__main__':
    sys.exit(control() if sys.argv[1] == 'control' else run(sys.argv[2], sys.argv[3]))
