#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only bounded mouse-mode emulator and consumer observer.

A fresh private controlling PTY models DEC 1000, 1015 and 1006. A click is
only generated when 1000 tracking is on, in the highest enabled encoding.
The reference-less setup control exercises the same complete PTY protocol
against an independently scripted shell stub and fixed hand-encoded vectors.
No real input device or host terminal is opened. Guest-only; never run on host.
"""
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

MODE = re.compile(rb'\x1b\[\?([0-9;]+)([hl])')
ROOT = Path(os.environ['HOME'])
LIMIT = 128 * 1024


def modes(data):
    result = set()
    for match in MODE.finditer(data):
        for item in match.group(1).split(b';'):
            number = int(item)
            if number in (1000, 1015, 1006):
                if match.group(2) == b'h':
                    result.add(number)
                else:
                    result.discard(number)
    return result


def click(state):
    if 1000 not in state:
        return None
    if 1006 in state:
        return b'\x1b[<0;4;6M'
    if 1015 in state:
        return b'\x1b[32;4;6M'
    return b'\x1b[M $&'


def control_vectors():
    # Exact xterm-compatible press, button 1, one-based x=4 y=6.
    vectors = [(set(), None), ({1006}, None), ({1000}, b'\x1b[M $&'),
               ({1000, 1015}, b'\x1b[32;4;6M'),
               ({1000, 1006}, b'\x1b[<0;4;6M'),
               ({1000, 1015, 1006}, b'\x1b[<0;4;6M')]
    if not all(click(state) == expected for state, expected in vectors):
        return False
    wire = b'\x1b[?1000h\x1b[?1015h\x1b[?1006h\x1b[?1006l'
    return modes(wire) == {1000, 1015} and modes(wire + b'\x1b[?1015l\x1b[?1000l') == set()


STUB = r'''
mouse() {
 case "$1:$2" in
  enable:x10) printf '\033[?1000h';;
  enable:1015) printf '\033[?1015h';;
  enable:1006) printf '\033[?1006h';;
  disable:x10) printf '\033[?1000l';;
  disable:1015) printf '\033[?1015l';;
  disable:1006) printf '\033[?1006l';;
  decode:1b5b3c303b343b364d) printf 'mouse protocol=1006 kind=press button=button1 x=4 y=6 mods= code=0\n';;
  decode:1b5b33323b343b364d) printf 'mouse protocol=1015 kind=press button=button1 x=4 y=6 mods= code=0\n';;
  decode:1b5b4d202426) printf 'mouse protocol=x10 kind=press button=button1 x=4 y=6 mods= code=0\n';;
  *) printf 'stub rejected: %s %s\n' "$1" "$2" >&2; return 1;;
 esac
}
'''

CONSUMER = r'''
saved=$(/bin/stty -g) || exit 21
/bin/stty -icanon -echo min 1 time 0 || exit 22
read_event() {
 IFS= read -r -N "$1" bytes || exit 23
 hex=$(printf '%s' "$bytes" | /usr/bin/od -An -tx1 | /usr/bin/tr -d ' \n')
 mouse decode "$hex" || exit 24
}
mouse enable x10
mouse enable 1015
mouse enable 1006
printf 'AWAIT-1006\n'
read_event 9
mouse disable 1006
printf 'AWAIT-1015\n'
read_event 9
mouse disable 1015
printf 'AWAIT-X10\n'
read_event 6
mouse disable x10
/bin/stty "$saved" || exit 25
printf 'ALL-DISABLED\n'
'''


def session(shell, mock):
    master, slave = os.openpty()
    termios.tcsetattr(slave, termios.TCSANOW, termios.tcgetattr(slave))
    fcntl = __import__('fcntl')
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    data = bytearray()
    events = []
    results = {}
    error = None
    proc = None
    deadline = time.monotonic() + 12

    def child():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    def wait_marker(marker):
        while marker not in data:
            if len(data) > LIMIT:
                raise RuntimeError('output limit')
            if time.monotonic() >= deadline:
                raise TimeoutError('waiting for ' + marker.decode())
            if proc.poll() is not None:
                raise RuntimeError('consumer exited before ' + marker.decode())
            if select.select([master], [], [], .05)[0]:
                data.extend(os.read(master, 4096))
        return len(data)

    try:
        proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', (STUB if mock else '') + CONSUMER],
                                stdin=slave, stdout=slave, stderr=slave, preexec_fn=child)
        for marker, expected, label in [
                (b'AWAIT-1006', {1000, 1015, 1006}, '1006'),
                (b'AWAIT-1015', {1000, 1015}, '1015'),
                (b'AWAIT-X10', {1000}, 'x10')]:
            offset = wait_marker(marker)
            state = modes(bytes(data))
            report = click(state)
            results['mode-' + label] = state == expected
            events.append({'marker': marker.decode(), 'offset': offset, 'modes': sorted(state),
                           'generated_hex': None if report is None else report.hex()})
            if report is None:
                raise RuntimeError('report disabled at ' + marker.decode())
            os.write(master, report)
        wait_marker(b'ALL-DISABLED')
        final = modes(bytes(data))
        results['mode-disabled'] = not final and click(final) is None
        events.append({'marker': 'ALL-DISABLED', 'offset': len(data), 'modes': sorted(final),
                       'generated_hex': None if click(final) is None else click(final).hex()})
        proc.wait(timeout=max(.1, deadline - time.monotonic()))
        while select.select([master], [], [], 0)[0]:
            data.extend(os.read(master, 4096))
        for label in ('1006', '1015', 'x10'):
            target = ('mouse protocol=' + label + ' kind=press button=button1 x=4 y=6 mods= code=0').encode()
            results['record-' + label] = target in data
        results['consumer-status'] = proc.returncode == 0
        results['termios-restored'] = termios.tcgetattr(slave) == before
    except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        error = str(exc)
    finally:
        after = termios.tcgetattr(slave)
        if proc is not None and proc.poll() is None:
            # This group was created by this fixture and exists only inside its VM.
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)
        os.close(master)
        os.close(slave)
    return bytes(data), {'events': events, 'results': results, 'error': error,
                         'returncode': None if proc is None else proc.returncode,
                         'before': repr(before), 'after': repr(after), 'mock': mock}


def save(prefix, data, report):
    (ROOT / (prefix + '.raw')).write_bytes(data[:LIMIT])
    (ROOT / (prefix + '.json')).write_text(json.dumps(report, indent=2) + '\n')


def main():
    kind, shell = sys.argv[1:]
    if not control_vectors():
        print('vector control failed', file=sys.stderr)
        return 2
    raw, result = session(shell, kind == 'control')
    save('mouse-control' if kind == 'control' else 'mouse-emulator', raw, result)
    keys = ('mode-1006', 'mode-1015', 'mode-x10', 'mode-disabled',
            'record-1006', 'record-1015', 'record-x10', 'consumer-status', 'termios-restored')
    if kind == 'control':
        if result['error'] or not all(result['results'].get(key) for key in keys):
            print('mock PTY control failed: ' + str(result['error']), file=sys.stderr)
            return 2
        print('mouse emulator control PASS')
        return 0
    print('vector-control=PASS')
    for key in keys:
        print(key + '=' + ('PASS' if result['results'].get(key) else 'FAIL'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
