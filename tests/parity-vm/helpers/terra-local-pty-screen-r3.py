#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only screen children and independent argv, geometry and tree observers."""
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import termios
import time

HOME = Path(os.environ.get('HOME', '/nonexistent'))
EXPECTED_ARGV = [b'', b'a b', b'quote"inside', b'*', b'line\nnext',
                 b'$(/usr/bin/touch /tmp/parity-home/argv-side-effect)',
                 b'x; /usr/bin/touch /tmp/parity-home/argv-side-effect']


def marker(name, data):
    path = HOME / name
    tmp = HOME / (name + '.tmp')
    tmp.write_bytes(data)
    os.replace(tmp, path)


def current_size():
    rows, cols, _, _ = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8))
    return ('%d %d\n' % (rows, cols)).encode()


def keep_alive():
    end = time.monotonic() + 25
    while time.monotonic() < end:
        time.sleep(.05)


def argv_child(label, args):
    payload = {'pid': os.getpid(), 'ppid': os.getppid(),
               'argv_hex': [os.fsencode(a).hex() for a in args]}
    marker('argv-' + label + '.json', (json.dumps(payload, sort_keys=True) + '\n').encode())
    keep_alive()


def pane_child(label):
    def record(reason):
        raw = fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8)
        rows, cols, xpixels, ypixels = struct.unpack('HHHH', raw)
        size = ('%d %d\n' % (rows, cols)).encode()
        entry = {'reason': reason, 'monotonic_ns': time.monotonic_ns(), 'pid': os.getpid(),
                 'winsize_hex': raw.hex(), 'rows': rows, 'cols': cols,
                 'xpixels': xpixels, 'ypixels': ypixels}
        with (HOME / ('pane-' + label + '-events.jsonl')).open('a') as stream:
            stream.write(json.dumps(entry, sort_keys=True) + '\n')
            stream.flush()
        marker('pane-' + label + '-size', size)
        if reason == 'initial':
            marker('pane-' + label + '-pid', ('%d\n' % os.getpid()).encode())
            marker('pane-' + label + '-initial', size)

    def winch(_sig, _frame):
        record('SIGWINCH')
    signal.signal(signal.SIGWINCH, winch)
    record('initial')
    keep_alive()


def tree_child():
    child = os.fork()
    if child == 0:
        marker('screen-grandchild', ('%d\n' % os.getpid()).encode())
        keep_alive()
        os._exit(0)
    marker('screen-child', ('%d\n' % os.getpid()).encode())
    keep_alive()


def verify_argv(label):
    data = json.loads((HOME / ('argv-' + label + '.json')).read_text())
    if data['argv_hex'] != [a.hex() for a in EXPECTED_ARGV]:
        raise ValueError('literal argv mismatch for ' + label)
    if (HOME / 'argv-side-effect').exists():
        raise ValueError('shell-looking argument produced a side effect')


def verify_size(label, rows, cols):
    target = ('%s %s\n' % (rows, cols)).encode()
    path = HOME / ('pane-' + label + '-size')
    end = time.monotonic() + 4
    while time.monotonic() < end:
        if path.is_file() and path.read_bytes() == target:
            return
        time.sleep(.03)
    actual = path.read_bytes() if path.exists() else b'<missing>'
    raise ValueError('pane size %s: expected %r got %r' % (label, target, actual))


def verify_layout(stage, path):
    expected = {
        'split': {'0': (0, 0, 24, 40), '1': (0, 41, 12, 39), '2': (13, 41, 11, 39)},
        'resized': {'0': (0, 0, 24, 43), '1': (0, 41, 10, 39), '2': (13, 41, 11, 39)},
        'swapped': {'0': (13, 41, 11, 39), '1': (0, 41, 10, 39), '2': (0, 0, 24, 43)},
        'window': {'0': (0, 0, 24, 80)},
    }[stage]
    actual = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r'(\d+) (\d+) (\d+) (\d+) (\d+)(?: \*)?', line)
        if not match or match[1] in actual:
            raise ValueError('malformed or repeated pane-list row: ' + line)
        actual[match[1]] = tuple(map(int, match.groups()[1:]))
    if actual != expected:
        raise ValueError('geometry: expected %r got %r' % (expected, actual))
    if stage == 'split':
        # The expected 1-cell horizontal/vertical separators account for the
        # otherwise unoccupied cells; pane rectangles must not overlap.
        occupied = set()
        for r, c, height, width in actual.values():
            cells = {(y, x) for y in range(r, r + height) for x in range(c, c + width)}
            if occupied & cells:
                raise ValueError('pane rectangles overlap')
            occupied |= cells
        gaps = {(r, 40) for r in range(24)} | {(12, c) for c in range(41, 80)}
        if occupied | gaps != {(r, c) for r in range(24) for c in range(80)} or occupied & gaps:
            raise ValueError('pane rectangles and 1-cell separators do not partition the window')


def sample_stage(stage):
    expected = {
        'initial': {'p0': (24, 80)},
        'window': {'p0': (24, 80), 'w1': (24, 80)},
        'horizontal': {'p0': (24, 40), 'p1': (24, 39), 'w1': (24, 80)},
        'split': {'p0': (24, 40), 'p1': (12, 39), 'p2': (11, 39), 'w1': (24, 80)},
        'resized': {'p0': (24, 43), 'p1': (10, 39), 'p2': (11, 39), 'w1': (24, 80)},
        'swapped': {'p0': (11, 39), 'p1': (10, 39), 'p2': (24, 43), 'w1': (24, 80)},
    }[stage]
    result = {'stage': stage, 'monotonic_ns': time.monotonic_ns(), 'panes': {}}
    good = True
    for label, wanted in expected.items():
        rec = {'expected_rows': wanted[0], 'expected_cols': wanted[1]}
        try:
            pid = int((HOME / ('pane-' + label + '-pid')).read_text().strip())
            if pid <= 1:
                raise ValueError('invalid fixture child pid')
            proc = Path('/proc') / str(pid)
            text = (proc / 'stat').read_text().strip()
            fields = text[text.rindex(')') + 2:].split()
            if proc.stat().st_uid != os.getuid():
                raise ValueError('pane child not owned by fixture uid')
            target = os.readlink(proc / 'fd/0')
            if re.fullmatch(r'/dev/pts/[0-9]+', target) is None:
                raise ValueError('pane stdin is not a private PTY slave')
            fd = os.open(proc / 'fd/0', os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)
            try:
                identity = os.fstat(fd)
                raw = fcntl.ioctl(fd, termios.TIOCGWINSZ, b'\0' * 8)
            finally:
                os.close(fd)
            rows, cols, xpixels, ypixels = struct.unpack('HHHH', raw)
            rec.update(pid=pid, proc_stat=text, starttime=int(fields[19]), tty_name=target,
                       device=identity.st_dev, inode=identity.st_ino, rdev=identity.st_rdev,
                       winsize_hex=raw.hex(), rows=rows, cols=cols,
                       xpixels=xpixels, ypixels=ypixels)
            if (rows, cols) != wanted:
                good = False
        except (OSError, ValueError, IndexError) as exc:
            rec['error'] = '%s: %s' % (type(exc).__name__, exc)
            good = False
        result['panes'][label] = rec
    with (HOME / 'screen-size-samples.jsonl').open('a') as stream:
        stream.write(json.dumps(result, sort_keys=True) + '\n')
    return good


def collect_sizes():
    result = {}
    for name in ['screen-size-samples.jsonl'] + ['pane-' + label + '-events.jsonl'
                                                 for label in ('p0', 'p1', 'p2', 'w1')]:
        path = HOME / name
        try:
            lines = path.read_text().splitlines()
            if len(lines) > 256:
                raise ValueError('too many size events')
            result[name] = [json.loads(line) for line in lines]
        except FileNotFoundError:
            result[name] = {'missing': True}
    Path(HOME / 'screen-size-evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


def snapshot(root, dest):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob('*')):
        s = path.lstat()
        record = {'mode': stat.S_IMODE(s.st_mode)}
        if stat.S_ISDIR(s.st_mode):
            record['type'] = 'directory'
        elif stat.S_ISREG(s.st_mode):
            data = path.read_bytes()
            if len(data) > 65536:
                raise ValueError('oversize metadata file')
            record.update(type='file', base64=base64.b64encode(data).decode())
        elif stat.S_ISSOCK(s.st_mode):
            record['type'] = 'socket'
        elif stat.S_ISLNK(s.st_mode):
            record.update(type='symlink', target=os.readlink(path))
        else:
            raise ValueError('unexpected metadata object')
        result[str(path.relative_to(root))] = record
        if len(result) > 512:
            raise ValueError('too many metadata objects')
    Path(dest).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


def gone_or_zombie(pid):
    path = Path('/proc/%d/stat' % pid)
    end = time.monotonic() + 3
    while time.monotonic() < end:
        try:
            text = path.read_text()
            state = text[text.rindex(')') + 2:].split()[0]
        except FileNotFoundError:
            return
        if state == 'Z':
            return
        time.sleep(.03)
    raise ValueError('fixture process still live: %d' % pid)


def require_guest():
    # The root guest evaluator verifies the exact UUID; this unprivileged
    # guard checks the readable marker, QEMU vendor, uid and case scratch.
    import uuid
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture uid or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires disposable QEMU uid2000 fixture scratch') from exc


if __name__ == '__main__':
    require_guest()
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == 'argv':
        argv_child(args[1], args[2:])
    elif len(args) == 2 and args[0] == 'pane':
        pane_child(args[1])
    elif args == ['tree']:
        tree_child()
    elif len(args) == 2 and args[0] == 'check-argv':
        verify_argv(args[1])
    elif len(args) == 4 and args[0] == 'check-size':
        verify_size(*args[1:])
    elif len(args) == 3 and args[0] == 'check-layout':
        verify_layout(args[1], args[2])
    elif len(args) == 2 and args[0] == 'sample-stage':
        raise SystemExit(0 if sample_stage(args[1]) else 1)
    elif args == ['collect-sizes']:
        collect_sizes()
    elif len(args) == 3 and args[0] == 'snapshot':
        snapshot(args[1], args[2])
    elif len(args) == 2 and args[0] == 'gone':
        gone_or_zombie(int(args[1]))
    else:
        raise SystemExit('invalid fixture arguments')
