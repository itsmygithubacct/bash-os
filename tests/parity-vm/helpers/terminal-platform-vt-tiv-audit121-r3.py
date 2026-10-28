#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only bounded VT corpus, owned PTY clients, and truecolor PNG sizing.

No project helper imports. Entry guard precedes every behavioral operation,
including pyte import and native controls. Host checks may compile this file.
"""
import base64
import copy
import ctypes
import errno
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
import uuid
import zlib

SELF = '/opt/bashos-parity/harness/helpers/terminal-platform-vt-tiv-audit121-r3.py'
HOME = Path('/tmp/parity-home')
PYTHON = '/usr/bin/python3'


def guard():
    # Require the root-owned VM marker and the already identity-checked guest
    # evaluator as PID 1 in its private PID namespace before any behavior.
    # Setup uses assert statements, so optimized Python must never remove them.
    if sys.flags.optimize:
        raise RuntimeError('optimized Python would disable fixture controls')
    marker = Path('/etc/bashos-parity-vm')
    meta = marker.lstat()
    if meta.st_uid != 0 or meta.st_mode & 0o022 or (meta.st_mode & 0o170000) != 0o100000:
        raise RuntimeError('untrusted VM marker')
    token = marker.read_text().strip()
    uuid.UUID(token)
    init_args = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    if (Path('/proc/1').stat().st_uid != 0 or len(init_args) < 4
            or init_args[:3] != [b'/usr/bin/python3', b'/opt/bashos-parity/harness/guest.py', b'--vm-token']
            or init_args[3] != token.encode('ascii')):
        raise RuntimeError('expected the identity-checked isolated guest evaluator as PID 1')
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or os.getuid() != 2000 or os.geteuid() != 2000
            or Path.cwd() != Path('/tmp/parity-case') or Path.home() != HOME
            or os.uname().machine != 'x86_64'):
        raise RuntimeError('terminal-platform refuses outside QEMU uid2000 case scratch')
    lib = ctypes.CDLL(None, use_errno=True)
    if lib.prctl(36, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')


def b64(raw):
    return base64.b64encode(raw).decode()


def decode(text):
    return base64.b64decode(text, validate=True)


def save(name, data):
    path = HOME / name
    tmp = path.with_name(path.name + '.writing')
    tmp.write_text(json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)


def result(data):
    Path('result.json').write_text(json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + '\n')


def modes(value):
    return value[:6] + [[v if isinstance(v, int) else b64(v) for v in value[6]]]


def reap_owned():
    for pid in map(int, Path('/proc/self/task/%d/children' % os.getpid()).read_text().split()):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, name, actual, expected=True):
        self.rows.append(dict(label=name, passed=actual == expected, actual=actual, expected=expected,
                              ns=time.monotonic_ns()))

    def end(self):
        save('assertions.json', self.rows)
        print('all-explicit-assertions=' + ('FAIL' if any(not r['passed'] for r in self.rows) else 'PASS'))
        return int(any(not r['passed'] for r in self.rows))


def screen(width, height):
    import pyte                 # only after guard in guest
    class Screen(pyte.Screen):
        def __init__(self):
            super().__init__(width, height)
            self.replies = []
        def write_process_input(self, text):
            self.replies.append(text.encode())
    model = Screen()
    return model, pyte.ByteStream(model)


COLORS = {'black': '000000', 'red': 'cd0000', 'green': '00cd00', 'brown': 'cdcd00',
          'blue': '0000ee', 'magenta': 'cd00cd', 'cyan': '00cdcd', 'white': 'e5e5e5',
          'brightblack': '7f7f7f', 'brightred': 'ff0000', 'brightgreen': '00ff00',
          'brightbrown': 'ffff00', 'brightblue': '5c5cff', 'brightmagenta': 'ff00ff',
          'brightcyan': '00ffff', 'brightwhite': 'ffffff'}


def color(name, default):
    if name == 'default':
        name = default
    return COLORS.get(name, name.lower())


def cells(model):
    rows = []
    for y in range(model.lines):
        row = []
        for x in range(model.columns):
            c = model.buffer[y][x]
            row.append(dict(text=c.data, fg=color(c.fg, 'white'), bg=color(c.bg, 'black'),
                **{name: bool(getattr(c, name)) for name in ('bold', 'italics', 'underscore', 'strikethrough', 'reverse')}))
        rows.append(row)
    return rows


def model_result(model):
    return dict(size=[model.lines, model.columns], cursor=[model.cursor.y + 1, model.cursor.x + 1],
                cells=cells(model), responses_base64=b64(b''.join(model.replies)))


def rendered_cells(raw, width, height):
    lines = raw.split(b'\n')
    if len(lines) != height + 1 or lines[-1]:
        raise ValueError('vt render row framing differs from declared contract')
    answer = []
    for line in lines[:-1]:
        model, stream = screen(width + 1, 1)
        stream.feed(line)
        answer.append(cells(model)[0][:width])
    return answer


class Shell:
    """A remembered owned shell, command acknowledgements and bounded pipes."""
    def __init__(self, executable, fds=()):
        self.events, self.raw, self.err = [], bytearray(), bytearray()
        self.process = subprocess.Popen([executable, '--noprofile', '--norc'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=fds, env=dict(os.environ, LC_ALL='C.UTF-8'))
        self.sequence = 0
        self.deadline = time.monotonic() + 30

    def command(self, command):
        self.sequence += 1
        token = ('TP_ACK_%d:' % self.sequence).encode()
        wire = (command + '\nbuiltin printf "TP_ACK_%d:%%s\\n" "$?"\n' % self.sequence).encode()
        self.events.append(dict(direction='send', ns=time.monotonic_ns(), base64=b64(wire)))
        self.process.stdin.write(wire)
        self.process.stdin.flush()
        begin = len(self.raw)
        end = min(self.deadline, time.monotonic() + 4)
        while time.monotonic() < end:
            for fd in select.select([self.process.stdout, self.process.stderr], [], [], .02)[0]:
                raw = os.read(fd.fileno(), 65536)
                if raw:
                    target = self.raw if fd == self.process.stdout else self.err
                    target.extend(raw)
                    self.events.append(dict(direction='stdout' if fd == self.process.stdout else 'stderr',
                        ns=time.monotonic_ns(), base64=b64(raw)))
            tail = bytes(self.raw[begin:])
            if token in tail and b'\n' in tail.split(token, 1)[1]:
                return int(tail.split(token, 1)[1].split(b'\n', 1)[0])
            if len(self.raw) + len(self.err) > 1000000:
                raise RuntimeError('shell output bound')
            if self.process.poll() is not None:
                break
        raise RuntimeError('owned shell command did not acknowledge: ' + command)

    def close(self):
        natural = self.process.poll()
        if natural is None:
            self.process.stdin.close()
            try:
                natural = self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        for fd, target, direction in [(self.process.stdout, self.raw, 'stdout'), (self.process.stderr, self.err, 'stderr')]:
            while select.select([fd], [], [], 0)[0]:
                raw = os.read(fd.fileno(), 65536)
                if not raw:
                    break
                target.extend(raw)
                self.events.append(dict(direction=direction, ns=time.monotonic_ns(), base64=b64(raw)))
        save('shell.json', dict(pid=self.process.pid, natural_status=natural,
            status_after_cleanup=self.process.returncode, events=self.events))
        (HOME / 'shell.stdout.raw').write_bytes(self.raw)
        (HOME / 'shell.stderr.raw').write_bytes(self.err)
        return natural


def vt_run(side, executable):
    spec = json.loads(Path('scenario.json').read_text())
    model, stream = screen(spec['width'], spec['height'])
    chunks = [decode(x) for x in spec['chunks_base64']]
    expected = []
    for raw in chunks:
        stream.feed(raw)
        expected.append(model_result(model))
        model.replies.clear()
    save('oracle.json', expected)
    checks = Checks()
    statuses = []
    shell_status = 0
    if side == 'reference':
        actual = expected
    else:
        shell = Shell(executable)
        actual = []
        try:
            statuses.append(shell.command('vt new -h tp_model -W %d -H %d' % (spec['width'], spec['height'])))
            for i, raw in enumerate(chunks):
                path = HOME / ('chunk%d.bin' % i)
                path.write_bytes(raw)
                statuses.append(shell.command('exec 7<%s; vt feed-fd "$tp_model" 7 -N %d; tp_status=$?; exec 7<&-; (exit "$tp_status")' % (shlex.quote(str(path)), len(raw))))
                for verb, options, filename in [('render', '-A', 'render.raw'), ('cursor', '', 'cursor.txt'),
                        ('size', '', 'size.txt'), ('response', '', 'responses.raw')]:
                    statuses.append(shell.command('vt %s "$tp_model" %s >"$HOME/%s"' % (verb, options, filename)))
                actual.append(dict(cells=rendered_cells((HOME / 'render.raw').read_bytes(), spec['width'], spec['height']),
                    cursor=list(map(int, (HOME / 'cursor.txt').read_text().split())),
                    size=list(map(int, (HOME / 'size.txt').read_text().split())),
                    responses_base64=b64((HOME / 'responses.raw').read_bytes()),
                    render_base64=b64((HOME / 'render.raw').read_bytes())))
                # Retain each intermediate raw render, including states later
                # erases or insert/delete operations would otherwise obscure.
                save('vt-stages.json', actual)
            statuses.append(shell.command('vt free "$tp_model"'))
        finally:
            shell_status = shell.close()
    normalized = [{k: value for k, value in stage.items() if k != 'render_base64'} for stage in actual]
    result(normalized)
    checks.add('owned-shell-natural-exit', shell_status, 0)
    checks.add('all-model-operations', statuses, [0] * len(statuses))
    for i, (observed, wanted) in enumerate(zip(normalized, expected)):
        checks.add('rendered-grid-and-each-cell-attributes/phase%d' % i, observed['cells'], wanted['cells'])
        checks.add('model-geometry/phase%d' % i, observed['size'], wanted['size'])
        checks.add('model-cursor/phase%d' % i, observed['cursor'], wanted['cursor'])
        checks.add('exact-independent-DA-DSR-replies/phase%d' % i, observed['responses_base64'], wanted['responses_base64'])
    checks.add('all-checkpoints-reached', len(normalized), len(expected))
    return checks.end()


class Child:
    def __init__(self, argv, size, prefix='terminal'):
        self.master, self.slave = os.openpty()
        self.initial = copy.deepcopy(termios.tcgetattr(self.slave))
        self.argv, self.prefix, self.events = argv, prefix, []
        self.size(size)
        self.pid = os.fork()
        if not self.pid:
            try:
                os.close(self.master)
                os.setsid()
                fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
                os.tcsetpgrp(self.slave, os.getpgrp())
                for fd in (0, 1, 2):
                    os.dup2(self.slave, fd)
                if self.slave > 2:
                    os.close(self.slave)
                os.execve(argv[0], argv, dict(os.environ, LC_ALL='C.UTF-8'))
            except BaseException:
                os._exit(126)
        self.status = None

    def size(self, value):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', *value))
        self.events.append(dict(action='geometry', ns=time.monotonic_ns(), geometry=list(value),
            actual_hex=fcntl.ioctl(self.slave, termios.TIOCGWINSZ, b'\0' * 8).hex()))

    def poll(self):
        if self.status is None:
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.status = os.waitstatus_to_exitcode(status)
        return self.status

    def write(self, raw):
        end = time.monotonic() + 2
        waiting = False
        sample = {}
        while time.monotonic() < end and not waiting:
            try:
                text = Path('/proc/%d/syscall' % self.pid).read_text().strip()
                sample = dict(action='owned-stdin-readiness', ns=time.monotonic_ns(), pid=self.pid, syscall=text)
                values = [] if text == 'running' else [int(x, 0) for x in text.split()]
                if values and values[0] == 0 and values[1] == 0:
                    waiting = True
                elif values and values[0] in (23, 270) and values[1] == 1 and values[2] and values[3] == values[4] == 0:
                    with open('/proc/%d/mem' % self.pid, 'rb', buffering=0) as memory:
                        mask = os.pread(memory.fileno(), 8, values[2])
                    sample['read_fdset_hex'] = mask.hex()
                    waiting = int.from_bytes(mask, 'little') == 1
            except (OSError, ValueError) as exc:
                sample['error'] = str(exc)
            if not waiting:
                select.select([], [], [], .005)
        sample['stdin_wait'] = waiting
        self.events.append(sample)
        if not waiting:
            raise RuntimeError('remembered child not waiting for input')
        self.events.append(dict(direction='send', ns=time.monotonic_ns(), base64=b64(raw)))
        at = 0
        while at < len(raw):
            at += os.write(self.master, raw[at:])

    def receive(self, amount=None, timeout=4):
        raw = bytearray()
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if select.select([self.master], [], [], .02)[0]:
                try:
                    data = os.read(self.master, 65536 if amount is None else amount - len(raw))
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    data = b''
                if data:
                    raw.extend(data)
                    self.events.append(dict(direction='read', ns=time.monotonic_ns(), base64=b64(data)))
                elif amount is None and self.poll() is not None:
                    self.events.append(dict(action='owned-master-EOF', ns=time.monotonic_ns()))
                    return bytes(raw)
            if amount is not None and len(raw) >= amount or amount is None and self.poll() is not None:
                # Drain exit output after observing natural waitpid completion.
                if amount is not None or not select.select([self.master], [], [], 0)[0]:
                    return bytes(raw)
            if len(raw) > 1000000:
                raise RuntimeError('terminal output bound')
        raise RuntimeError('owned terminal receive deadline')

    def close(self):
        natural = self.poll()
        before = termios.tcgetattr(self.slave)
        if natural is None:
            os.kill(self.pid, signal.SIGKILL)
            self.status = os.waitstatus_to_exitcode(os.waitpid(self.pid, 0)[1])
        termios.tcsetattr(self.slave, termios.TCSANOW, self.initial)
        save(self.prefix + '.json', dict(argv=self.argv, pid=self.pid, natural_status=natural,
            status_after_cleanup=self.status, termios_initial=modes(self.initial),
            termios_before_cleanup=modes(before), restored_before_cleanup=before == self.initial,
            events=self.events))
        os.close(self.master)
        os.close(self.slave)
        return natural, before == self.initial


def png(path):
    raw = Path(path).read_bytes()
    if raw[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('PNG signature')
    at, data = 8, bytearray()
    width = height = None
    while at < len(raw):
        length = struct.unpack('>I', raw[at:at + 4])[0]
        kind, body = raw[at + 4:at + 8], raw[at + 8:at + 8 + length]
        crc = struct.unpack('>I', raw[at + 8 + length:at + 12 + length])[0]
        if zlib.crc32(kind + body) & 0xffffffff != crc:
            raise ValueError('PNG CRC')
        if kind == b'IHDR':
            width, height, depth, typ, comp, filt, interlace = struct.unpack('>IIBBBBB', body)
            if (depth, typ, comp, filt, interlace) != (8, 2, 0, 0, 0) or width * height > 10000:
                raise ValueError('PNG outside fixture RGB8 profile')
        if kind == b'IDAT':
            data.extend(body)
        at += 12 + length
    decoded = zlib.decompress(data)
    if len(decoded) != (width * 3 + 1) * height:
        raise ValueError('PNG data length')
    rows = []
    for y in range(height):
        line = decoded[y * (width * 3 + 1):(y + 1) * (width * 3 + 1)]
        if line[0] != 0:
            raise ValueError('fixture PNG uses only independently reviewable filter0')
        rows.append([list(line[1 + x * 3:4 + x * 3]) for x in range(width)])
    return rows


def image_expected(pixels, width, rows):
    """Declared RGB half-block area-average profile; dimensions are fixed data."""
    sh, sw = len(pixels), len(pixels[0])
    values = []
    for y in range(rows * 2):
        y0, y1 = y * sh // (rows * 2), max(y * sh // (rows * 2) + 1, (y + 1) * sh // (rows * 2))
        line = []
        for x in range(width):
            x0, x1 = x * sw // width, max(x * sw // width + 1, (x + 1) * sw // width)
            region = [pixels[sy][sx] for sy in range(y0, min(sh, y1)) for sx in range(x0, min(sw, x1))]
            line.append([sum(p[c] for p in region) // len(region) for c in range(3)])
        values.append(line)
    out = bytearray()
    for y in range(rows):
        for x in range(width):
            out.extend(('\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dm▀' % tuple(values[y * 2][x] + values[y * 2 + 1][x])).encode())
        out.extend(b'\x1b[0m\n')
    return bytes(out)


def tiv_run(side, executable):
    spec = json.loads(Path('scenario.json').read_text())
    pixels = png('image.png')
    expected = image_expected(pixels, spec['expected_width'], spec['expected_rows'])
    (HOME / 'expected.raw').write_bytes(expected)
    checks = Checks()
    initial = None
    if side == 'reference':
        raw, status, restored = expected, 0, True
    elif spec['tty']:
        argv = [executable, '--noprofile', '--norc', '-c', 'tiv ' + ' '.join(spec['options'] + ['image.png'])]
        child = Child(argv, spec['size'])
        try:
            raw = child.receive(timeout=6)
            (HOME / 'terminal.raw').write_bytes(raw)
        finally:
            status, restored = child.close()
        raw = raw.replace(b'\r\n', b'\n')   # explicit owned-PTY ONLCR profile only
    else:
        proc = subprocess.run([executable, '--noprofile', '--norc', '-c', 'tiv image.png'], capture_output=True, timeout=6)
        raw, status, restored = proc.stdout, proc.returncode, True
        (HOME / 'terminal.raw').write_bytes(raw)
        (HOME / 'shell.stderr.raw').write_bytes(proc.stderr)
        save('terminal.json', dict(argv=proc.args, status=status, stdout_is_tty=False))
        checks.add('non-tty-stderr-empty', b64(proc.stderr), '')
    checks.add('image-command-natural-status', status, 0)
    checks.add('terminal-restored-before-cleanup', restored)
    checks.add('exact-truecolor-cells-and-row-column-count', b64(raw), b64(expected))
    (HOME / 'actual.raw').write_bytes(raw)
    result(dict(expected_geometry=[spec['expected_rows'], spec['expected_width']], actual_base64=b64(raw)))
    return checks.end()


def await_state(label, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        path = HOME / 'client.json'
        if path.exists():
            data = json.loads(path.read_text())
            if data['state'] == label:
                return data
        select.select([], [], [], .01)
    raise RuntimeError('client did not reach ' + label)


def client_action(kind):
    initial = termios.tcgetattr(0)
    raw = copy.deepcopy(initial)
    raw[0] &= ~(termios.ICRNL | termios.IXON)
    raw[1] &= ~termios.OPOST
    raw[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
    raw[6][termios.VMIN], raw[6][termios.VTIME] = 1, 0
    termios.tcsetattr(0, termios.TCSANOW, raw)
    data = dict(state='begin', pid=os.getpid(), tty=os.ttyname(0), initial=modes(initial), raw=modes(raw), writes=[], reads=[], winch=[])
    signal.signal(signal.SIGWINCH, lambda *_: data['winch'].append(time.monotonic_ns()))
    def emit(value):
        count = os.write(1, value)
        data['writes'].append(dict(ns=time.monotonic_ns(), base64=b64(value), written=count))
    def read(n, timeout=8):
        value = bytearray()
        end = time.monotonic() + timeout
        while len(value) < n and time.monotonic() < end:
            if select.select([0], [], [], .1)[0]:
                value.extend(os.read(0, n - len(value)))
        data['reads'].append(dict(ns=time.monotonic_ns(), base64=b64(value)))
        return bytes(value)
    try:
        if kind == 'resize':
            data['state'] = 'ready'
            save('client.json', data)
            read(1)
            geometry = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0' * 8))
            stty = subprocess.run(['/usr/bin/stty', 'size'], capture_output=True, timeout=2)
            data.update(geometry=list(geometry), stty_base64=b64(stty.stdout), stty_status=stty.returncode)
            emit(b'\x1b[2J\x1b[HRESIZED')
        else:
            first = b'\x1b[2J\x1b[HCLIENT' if kind == 'echo' else b'\x1b[2J\x1b[H\x1b[3;5H\x1b[6n' if kind == 'dsr' else b'\x1b[2J\x1b[H\x1b[c'
            emit(first)
            data['state'] = 'ready'
            save('client.json', data)
            if kind == 'echo':
                received = read(3)
                emit(b'\x1b[2;1HECHO:' + received)
            else:
                received = bytearray()
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    char = read(1, .2)
                    if not char:
                        continue
                    received.extend(char)
                    if char in (b'R', b'c') or len(received) > 64:
                        break
                data['response_base64'] = b64(received)
                emit(b'\x1b[4;1H' + (b'REPLY-RECEIVED' if received else b'NO-REPLY'))
        data['state'] = 'completed'
        save('client.json', data)
        read(1)                  # coordinator's explicit cleanup acknowledgement
        return 0
    finally:
        termios.tcsetattr(0, termios.TCSANOW, initial)
        data.update(state='exited', final=modes(termios.tcgetattr(0)))
        save('client.json', data)


def client_run(side, executable):
    spec = json.loads(Path('scenario.json').read_text())
    kind, width, height = spec['client'], 20, 6
    checks = Checks()
    child = Child([PYTHON, SELF, 'client', kind], [height, width, 200, 120], 'terminal')
    shell = None
    statuses, stages, rawlog = [], [], bytearray()
    oracle, stream = screen(width, height)
    actual = None
    try:
        initial_client = await_state('ready')
        if side == 'candidate':
            shell = Shell(executable, (child.master,))
            statuses.append(shell.command('vt new -h tp_model -W 20 -H 6'))
        def feed(written):
            nonlocal actual
            if not written:
                return
            rawlog.extend(written)
            stream.feed(written)
            if side == 'candidate':
                # This FD is the actual inherited master of the remembered child.
                statuses.append(shell.command('tp_got=0; while (( tp_got < %d )); do vt feed-fd "$tp_model" %d -N "$((%d-tp_got))" || break; ((BVT_LAST_BYTES>0)) || break; ((tp_got+=BVT_LAST_BYTES)); done; ((tp_got==%d))' % (len(written), child.master, len(written), len(written))))
            else:
                received = child.receive(len(written))
                checks.add('actual-master-bytes/' + str(len(stages)), b64(received), b64(written))
        first = b''.join(decode(r['base64']) for r in initial_client['writes'])
        feed(first)
        if kind == 'resize':
            if side == 'candidate':
                statuses.append(shell.command('pty resize %d -W 31 -H 9; vt resize "$tp_model" -W 31 -H 9' % child.master))
            else:
                child.size([9, 31, 200, 120])
            oracle.resize(lines=9, columns=31)
            child.write(b'g')
        elif kind == 'echo':
            child.write(b'xyz')
        else:
            expected_reply = b''.join(oracle.replies)
            if side == 'candidate':
                statuses.append(shell.command('vt response "$tp_model" >"$HOME/responses.raw"'))
                reply = (HOME / 'responses.raw').read_bytes()
            else:
                reply = expected_reply
            checks.add('exact-forwarded-model-reply', b64(reply), b64(expected_reply))
            child.write(reply)
        completed = await_state('completed', 7)
        later = b''.join(decode(r['base64']) for r in completed['writes'][len(initial_client['writes']):])
        feed(later)
        if kind == 'resize':
            checks.add('client-received-SIGWINCH', bool(completed['winch']))
            checks.add('independent-client-TIOCGWINSZ', completed['geometry'][:2], [9, 31])
            checks.add('independent-stty-size', decode(completed['stty_base64']).decode(), '9 31\n')
            checks.add('independent-stty-status', completed['stty_status'], 0)
            child.events.append(dict(action='geometry-after-candidate-resize', ns=time.monotonic_ns(),
                actual_hex=fcntl.ioctl(child.slave, termios.TIOCGWINSZ, b'\0' * 8).hex()))
        elif kind == 'echo':
            checks.add('client-received-exact-forwarded-input', completed['reads'][0]['base64'], b64(b'xyz'))
        else:
            checks.add('client-received-exact-model-response', completed['response_base64'], b64(b''.join(oracle.replies)))
        expected = model_result(oracle)
        expected['responses_base64'] = ''   # model response queue was explicitly drained
        if side == 'candidate':
            for verb, options, filename in [('render', '-A', 'render.raw'), ('cursor', '', 'cursor.txt'), ('size', '', 'size.txt')]:
                statuses.append(shell.command('vt %s "$tp_model" %s >"$HOME/%s"' % (verb, options, filename)))
            h, w = (9, 31) if kind == 'resize' else (height, width)
            actual = dict(cells=rendered_cells((HOME / 'render.raw').read_bytes(), w, h),
                cursor=list(map(int, (HOME / 'cursor.txt').read_text().split())),
                size=list(map(int, (HOME / 'size.txt').read_text().split())), responses_base64='')
            statuses.append(shell.command('vt free "$tp_model"'))
        else:
            actual = expected
        save('oracle.json', expected)
        result(actual)
        checks.add('pty-master-feed-and-client-model', actual, expected)
        checks.add('all-client-model-commands', statuses, [0] * len(statuses))
        checks.add('all-client-output-write-counts', [r['written'] for r in completed['writes']], [len(decode(r['base64'])) for r in completed['writes']])
        child.write(b'q')
        await_state('exited')
        end = time.monotonic() + 2
        while child.poll() is None and time.monotonic() < end:
            select.select([], [], [], .01)
    finally:
        (HOME / 'client-writes.raw').write_bytes(rawlog)
        if shell:
            shell.close()
        status, restored = child.close()
    checks.add('client-natural-exit', status, 0)
    checks.add('client-termios-restored-before-cleanup', restored)
    return checks.end()


def setup():
    # Independent model controls are literal terminal expectations, not output
    # of the candidate or merely a second call of the same corpus function.
    if importlib.metadata.version('pyte') != '0.8.0':
        raise RuntimeError('requires sealed independent python3-pyte0.8.0')
    model, stream = screen(12, 4)
    stream.feed(b'\x1b[2J\x1b[Habc\x1b[2;2H\x1b[31;7mZ\x1b[0m\x1b[6n\x1b[c')
    assert model.display[0] == 'abc         '
    assert model.buffer[1][1].data == 'Z' and model.buffer[1][1].fg == 'red' and model.buffer[1][1].reverse
    assert b''.join(model.replies) == b'\x1b[2;3R\x1b[?6c'
    save('setup.json', dict(pyte_version='0.8.0', literal_control=model_result(model),
        protocol_profile='VT102 primaryDA; xterm16 default white/black; UTF8 plus DEC SCS corpus',
        no_gpu_or_physical_terminal_claim=True))
    if Path('image.png').exists():
        manifest = json.loads(Path('pixels.json').read_text())
        assert png('image.png') == manifest['pixels']
        save('image-control.json', dict(pixels=manifest['pixels'], sha256=hashlib.sha256(Path('image.png').read_bytes()).hexdigest()))
    # Native geometry, raw PTY data and termios control run as a guest-owned
    # child, independently of every candidate builtin.
    child = Child([PYTHON, SELF, 'client', 'echo'], [6, 20, 200, 120], 'setup-terminal')
    try:
        ready = await_state('ready')
        first = b''.join(decode(r['base64']) for r in ready['writes'])
        assert child.receive(len(first)) == b'\x1b[2J\x1b[HCLIENT'
        child.write(b'xyz')
        done = await_state('completed')
        last = decode(done['writes'][-1]['base64'])
        assert child.receive(len(last)) == b'\x1b[2;1HECHO:xyz'
        assert decode(done['reads'][0]['base64']) == b'xyz'
        child.write(b'q')
        await_state('exited')
        end = time.monotonic() + 2
        while child.poll() is None and time.monotonic() < end:
            select.select([], [], [], .01)
    finally:
        status, restored = child.close()
    assert status == 0 and restored
    (HOME / 'setup-client.json').write_bytes((HOME / 'client.json').read_bytes())
    (HOME / 'client.json').unlink()
    print('independent-model-image-native-PTY-controls=PASS')
    return 0


def main():
    guard()
    action, *args = sys.argv[1:]
    try:
        if action == 'setup':
            return setup()
        if action == 'client':
            return client_action(*args)
        side, executable = args
        return {'vt': vt_run, 'tiv': tiv_run, 'vt-client': client_run}[action](side, executable)
    finally:
        reap_owned()


if __name__ == '__main__':
    sys.exit(main())
