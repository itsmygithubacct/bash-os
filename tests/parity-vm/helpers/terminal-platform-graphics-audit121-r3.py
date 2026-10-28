#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only bounded graphics-protocol consumer and software-canvas fixture.

The supported Kitty subset and Kilix frame1 extensions are explicit. Consumed
pixels/modes/cursor are observations of this model, never GPU/shader evidence.
No project helper imports. Host use is restricted to source/data/syntax work.
"""
import base64
import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
import uuid
import zlib

SELF = '/opt/bashos-parity/harness/helpers/terminal-platform-graphics-audit121-r3.py'
HOME = Path('/tmp/parity-home')
ESC = b'\x1b'
ST = ESC + b'\\'


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
            or os.getuid() != 2000 or os.geteuid() != 2000 or Path.home() != HOME
            or Path.cwd() != Path('/tmp/parity-case') or os.uname().machine != 'x86_64'):
        raise RuntimeError('terminal-platform graphics refuses outside disposable guest uid2000 scratch')
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'subreaper')


def b64(raw):
    return base64.b64encode(raw).decode()


def un64(text):
    raw = text.encode() if isinstance(text, str) else text
    return base64.b64decode(raw + b'=' * (-len(raw) % 4), validate=True)


def save(name, data):
    (HOME / name).write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')


def mode(value):
    return value[:6] + [[x if isinstance(x, int) else b64(x) for x in value[6]]]


def rgba(pixels):
    return bytes(component for row in pixels for pixel in row for component in list(pixel) + [255])


def reference_key(buffer):
    keys = {b'\x1b[A': b'UP', b'\x1b[B': b'DOWN', b'\x1b[C': b'RIGHT', b'\x1b[D': b'LEFT',
        b'\x1b[H': b'HOME', b'\x1b[F': b'END', b'\x1b[2~': b'INSERT', b'\x1b[3~': b'DELETE',
        b'\x1b[5~': b'PAGEUP', b'\x1b[6~': b'PAGEDOWN'}
    for wire, event in keys.items():
        if buffer.startswith(wire):
            return event, len(wire)
    mouse = re.match(rb'\x1b\[<([0-9]+);([0-9]+);([0-9]+)([Mm])', buffer)
    if mouse:
        button, x, y, release = mouse.groups()
        return b'MOUSE:' + (b'down' if release == b'M' else b'up') + b':' + b':'.join((button, x, y)), mouse.end()
    if not buffer:
        return b'', 0
    first = buffer[0]
    fixed = {27:b'ESC',13:b'ENTER',10:b'ENTER',9:b'TAB',8:b'BACKSPACE',127:b'BACKSPACE'}
    if first in fixed:
        return fixed[first], 1
    if first < 32:
        return ('CTRL-' + chr(first + 64)).encode(), 1
    # Python's independent strict Unicode decoder identifies a whole first
    # codepoint. A malformed leading sequence falls back to its first byte.
    for length in range(1, min(4, len(buffer)) + 1):
        try:
            if len(buffer[:length].decode('utf8')) == 1:
                return buffer[:length], length
        except UnicodeError:
            pass
    return buffer[:1], 1


def reference(spec):
    manifest = json.loads(Path('pixels.json').read_text()) if Path('pixels.json').exists() else None
    if spec['kind'] == 'kitty':
        rows, cols = spec['placement_cells']
        cursor = list(spec['initial_cursor'])
        if not spec.get('static_cursor'):
            cursor = [cursor[0] + rows, cursor[1] + cols]
        return dict(image_rgba_base64=b64(rgba(manifest['pixels'])), placement_cells=[rows, cols],
            cursor=cursor, responses_sent=0)
    pixels = [[[0,0,0] for _ in range(spec['width'])] for _ in range(spec['height'])]
    frames = []
    for operation in spec.get('operations', []):
        effect = operation['effect']
        if effect == 'load':
            pixels = copy.deepcopy(manifest['pixels'])
        elif effect == 'clear':
            pixels = [[list(operation['color']) for _ in row] for row in pixels]
        elif effect == 'rectangle':
            x, y, w, h = operation['rectangle']
            for row in range(y, y + h):
                for col in range(x, x + w):
                    pixels[row][col] = list(operation['color'])
        elif effect == 'scroll':
            x, y, w, h = operation['rectangle']
            dx, dy = operation['delta']
            old = copy.deepcopy(pixels)
            for row in range(y, y + h):
                for col in range(x, x + w):
                    pixels[row][col] = (old[row-dy][col-dx] if x <= col-dx < x+w and y <= row-dy < y+h else list(operation['color']))
        elif effect == 'present':
            frames.append(b64(rgba(pixels)))
        else:
            raise ValueError('unreviewed software operation')
    pending, events = (b'X' if spec.get('resize') else b''), []
    for i, item in enumerate(spec.get('inputs', [])):
        if 'send_base64' in item:
            pending += un64(item['send_base64'])
        if spec.get('resize') and i == 0:
            rows, cols, xp, yp = spec['resize']
            event, consumed = ('RESIZE:%d:%d:%d:%d' % (cols, rows, xp, yp)).encode(), 0
        else:
            event, consumed = reference_key(pending)
        pending = pending[consumed:]
        code = 0 if consumed or spec.get('resize') and i == 0 else 1
        if item.get('readonly'):
            event, code = b'STALE', 1
        events.append(dict(status=code, event_base64=b64(event)))
    return dict(frames=frames, inputs=events)


def validate_image_data(spec):
    if not Path('pixels.json').exists():
        return
    manifest = json.loads(Path('pixels.json').read_text())
    pixels = manifest['pixels']
    h, w = len(pixels), len(pixels[0])
    raw_pixels = bytes(c for row in pixels for p in row for c in p)
    if Path('image.ppm').exists():
        assert Path('image.ppm').read_bytes() == ('P6\n%d %d\n255\n' % (w,h)).encode() + raw_pixels
    if Path('image.png').exists():
        data = Path('image.png').read_bytes()
        assert data[:8] == b'\x89PNG\r\n\x1a\n'
        at, compressed = 8, bytearray()
        while at < len(data):
            length = struct.unpack('>I', data[at:at+4])[0]
            kind, body = data[at+4:at+8], data[at+8:at+8+length]
            assert zlib.crc32(kind+body) & 0xffffffff == struct.unpack('>I', data[at+8+length:at+12+length])[0]
            if kind == b'IHDR':
                assert body == struct.pack('>IIBBBBB',w,h,8,2,0,0,0)
            if kind == b'IDAT':
                compressed.extend(body)
            at += length + 12
        assert zlib.decompress(compressed) == b''.join(b'\0' + bytes(c for p in row for c in p) for row in pixels)
    save('image-control.json', dict(width=w,height=h,pixels=pixels,rgba_base64=b64(rgba(pixels))))


class Checks:
    def __init__(self):
        self.rows = []
    def add(self, label, actual, expected=True):
        self.rows.append(dict(label=label, actual=actual, expected=expected,
            passed=actual == expected, ns=time.monotonic_ns()))
    def end(self):
        save('assertions.json', self.rows)
        bad = any(not x['passed'] for x in self.rows)
        print('all-explicit-assertions=' + ('FAIL' if bad else 'PASS'))
        return int(bad)


class Consumer:
    """Strict finite Kitty RGB/RGBA subset, plus declared Kilix frame1 ops."""
    def __init__(self, geometry, transmit, options=None):
        self.geometry = geometry
        self.transmit = transmit
        self.options = options or {}
        self.owner = None
        self.buffer = bytearray()
        self.images, self.events, self.errors, self.replies, self.shm = {}, [], [], [], []
        self.current = None
        self.pending = None
        self.cursor = [0, 0]
        self.modes = {'1049': False, '25': True, '1000': False, '1006': False, '2026': False}
        self.sync_frames = []
        self.mode_events = []
        self.placements = []
        self.queries = []
        self.wrappers = 0

    def reply(self, image, text, quiet=0):
        raw = ESC + b'_Gi=' + str(image).encode() + b';' + text.encode() + ST
        self.replies.append(dict(ns=time.monotonic_ns(), image=image, text=text,
            suppressed=quiet == 2 or quiet == 1 and text == 'OK', base64=b64(raw)))
        if not self.replies[-1]['suppressed']:
            self.transmit(raw)

    def error(self, message):
        self.errors.append(dict(ns=time.monotonic_ns(), message=str(message)))

    def shared(self, name, length, query):
        text = name.decode('ascii')
        allowed = bool(self.owner and re.fullmatch('/bashos-gpu-%d-[0-9a-f]{16}-[0-9]+' % self.owner, text))
        allowed |= text in self.options.get('control_names', [])
        if not allowed:
            raise ValueError('unowned or malformed shared-memory name')
        path = Path('/dev/shm') / text[1:]
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != length or length > 4 * 1024 * 1024):
                raise ValueError('shared-memory inode/size/owner/mode mismatch')
            raw = os.read(fd, length + 1)
            if len(raw) != length:
                raise ValueError('short shared-memory object')
            row = dict(name=text, path=str(path), ns=time.monotonic_ns(), size=info.st_size,
                mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, nlink=info.st_nlink,
                query=query, raw_base64=b64(raw), existed_before_ack=path.exists())
        finally:
            os.close(fd)
        hold = self.options.get('hold_queries' if query else 'hold_frames', False)
        if not hold:
            path.unlink()
        row.update(peer_unlinked=not hold, exists_after_peer_action=path.exists())
        self.shm.append(row)
        return raw

    def place(self, image, control):
        if image not in self.images:
            raise ValueError('placement of an undefined image')
        obj = self.images[image]
        rows, cols, xp, yp = self.geometry
        cw, ch = xp // cols, yp // rows
        c = int(control.get('c', math.ceil(obj['width'] / cw)))
        r = int(control.get('r', math.ceil(obj['height'] / ch)))
        if not 0 < c <= cols or not 0 < r <= rows:
            raise ValueError('placement outside bounded geometry')
        before = list(self.cursor)
        # Explicit fixture placements are exactly1:1 in pixels, so interpolation
        # and letterboxing choices cannot seed a false pixel-rendering claim.
        exact = c * cw == obj['width'] and r * ch == obj['height']
        row = dict(image=image, cursor_before=before, columns=c, rows=r,
            cell_pixels=[cw, ch], source_pixels=[obj['width'], obj['height']],
            source_rgba_base64=b64(obj['rgba']),
            rendered_pixels_base64=b64(obj['rgba']) if exact else None, exact_one_to_one=exact,
            static_cursor=int(control.get('C', '0')) == 1)
        if not row['static_cursor']:
            self.cursor = [self.cursor[0] + r, self.cursor[1] + c]
        row['cursor_after'] = list(self.cursor)
        self.placements.append(row)
        self.current = image

    def packet(self, body):
        entry = dict(ns=time.monotonic_ns(), wire_body_base64=b64(body))
        self.events.append(entry)
        try:
            header, encoded = body.split(b';', 1)
            pairs = [x.split('=', 1) for x in header.decode('ascii').split(',') if x]
            if any(len(x) != 2 or len(x[0]) != 1 for x in pairs) or len({x[0] for x in pairs}) != len(pairs):
                raise ValueError('control grammar or duplicate key')
            control = dict(pairs)
            entry['control'] = control
            if len(encoded) > 4096 or not re.fullmatch(rb'[A-Za-z0-9+/=]*', encoded):
                raise ValueError('base64 chunk grammar or4096-byte bound')
            if control.get('m') == '1' and len(encoded) % 4:
                raise ValueError('nonfinal chunk is not a multiple of4')
            payload = un64(encoded)
            entry['decoded_payload_base64'] = b64(payload)
            if self.pending:
                first, data = self.pending
                allowed = {'m', 'q', 'a'} if first.get('a') == 'f' else {'m', 'q'}
                if set(control) - allowed or control.get('a', first.get('a')) != first.get('a'):
                    raise ValueError('invalid/interleaved continuation')
                data.extend(payload)
                if control.get('m') == '1':
                    entry['partial_not_displayed'] = True
                    return
                if control.get('m') != '0':
                    raise ValueError('continuation lacks final m=0')
                control, payload = first, bytes(data)
                self.pending = None
            elif control.get('m') == '1':
                self.pending = (control, bytearray(payload))
                entry['partial_not_displayed'] = True
                return
            action = control.get('a', 't')
            image = int(control.get('i', '0'))
            quiet = int(control.get('q', '0'))
            if quiet not in (0, 1, 2):
                raise ValueError('invalid quiet policy')
            if action in ('q', 't', 'T', 'f'):
                width, height = int(control['s']), int(control['v'])
                fmt, transport = int(control.get('f', '32')), control.get('t', 'd')
                if fmt not in (24, 32) or not 0 < width * height <= 262144:
                    raise ValueError('outside RGB24/RGBA32 finite profile')
                length = width * height * (fmt // 8)
                if transport == 's':
                    payload = self.shared(payload, length, action == 'q')
                elif transport != 'd':
                    raise ValueError('outside declared direct/shared-memory profile')
                if len(payload) != length:
                    raise ValueError('decoded pixel length differs from geometry')
                rgba = (payload if fmt == 32 else b''.join(payload[i:i + 3] + b'\xff' for i in range(0, len(payload), 3)))
                entry.update(action=action, image=image, rgba_base64=b64(rgba), pixel_size=[width, height], transport=transport)
                if action == 'q':
                    self.queries.append(dict(image=image, transport=transport, rgba_base64=b64(rgba)))
                    rejected = self.options.get('reject') in ('all', transport)
                    if self.options.get('wrong_id'):
                        self.reply(image + 100000, 'ENOENT:unrelated-probe')
                    self.reply(image, 'ENOTSUP:fixture-rejection' if rejected else 'OK', quiet)
                    return
                if action == 'f':
                    if not self.options.get('kilix_frames') or image not in self.images or control.get('r') != '1' or control.get('X') != '1':
                        raise ValueError('outside declared frame1 direct-replacement extension')
                    x, y = int(control.get('x', '0')), int(control.get('y', '0'))
                    obj = self.images[image]
                    if min(x, y) < 0 or x + width > obj['width'] or y + height > obj['height']:
                        raise ValueError('damage rectangle outside image')
                    entry['image_before_base64'] = b64(obj['rgba'])
                    dest = bytearray(obj['rgba'])
                    for row in range(height):
                        begin = ((y + row) * obj['width'] + x) * 4
                        dest[begin:begin + width * 4] = rgba[row * width * 4:(row + 1) * width * 4]
                    obj['rgba'] = bytes(dest)
                    entry['image_after_base64'] = b64(obj['rgba'])
                else:
                    self.images[image] = dict(width=width, height=height, rgba=rgba)
                if action == 'T':
                    self.place(image, control)
                self.reply(image, 'OK', quiet)
            elif action == 'p':
                self.place(image, control)
                self.reply(image, 'OK', quiet)
            elif action == 'd':
                if control.get('d') != 'I':
                    raise ValueError('outside image-ID delete profile')
                self.images.pop(image, None)
                if self.current == image:
                    self.current = None
                self.reply(image, 'OK', quiet)
            elif action == 'c':
                if not self.options.get('kilix_frames') or image not in self.images or control.get('N') != '2' or control.get('r') != '1' or control.get('c') != '1':
                    raise ValueError('outside declared frame1 composition extension')
                obj = self.images[image]
                x, y, sx, sy, w, h = [int(control[k]) for k in ('x', 'y', 'X', 'Y', 'w', 'h')]
                if min(x, y, sx, sy, w, h) < 0 or max(x + w, sx + w) > obj['width'] or max(y + h, sy + h) > obj['height']:
                    raise ValueError('composition outside image')
                old, dest = obj['rgba'], bytearray(obj['rgba'])
                entry['image_before_base64'] = b64(old)
                for row in range(h):
                    src = ((sy + row) * obj['width'] + sx) * 4
                    begin = ((y + row) * obj['width'] + x) * 4
                    dest[begin:begin + w * 4] = old[src:src + w * 4]
                obj['rgba'] = bytes(dest)
                entry['image_after_base64'] = b64(obj['rgba'])
                self.reply(image, 'OK', quiet)
            else:
                raise ValueError('unsupported graphics action: ' + action)
            entry['accepted'] = True
        except (ValueError, KeyError, OSError, UnicodeError) as exc:
            entry['error'] = str(exc)
            self.error(exc)

    def feed(self, raw):
        self.buffer.extend(raw)
        if len(self.buffer) > 2 * 1024 * 1024:
            raise RuntimeError('protocol input bound')
        while self.buffer:
            data = bytes(self.buffer)
            if data.startswith(ESC + b'_G'):
                at = data.find(ST, 3)
                if at < 0:
                    return
                self.packet(data[3:at])
                del self.buffer[:at + 2]
            elif data.startswith(ESC + b'Ptmux;'):
                at, inner = 7, bytearray()
                while at < len(data):
                    if data[at:at + 2] == ESC + ESC:
                        inner.append(27)
                        at += 2
                    elif data[at:at + 2] == ST:
                        self.wrappers += 1
                        remainder = data[at + 2:]
                        self.buffer = bytearray(inner + remainder)
                        break
                    elif data[at] == 27 and at + 1 >= len(data):
                        return
                    else:
                        inner.append(data[at])
                        at += 1
                else:
                    return
            elif data.startswith(ESC + b'['):
                found = re.match(rb'\x1b\[([0-?]*)([ -/]*)([@-~])', data)
                if not found:
                    return
                params, _, verb = found.groups()
                text = params.decode()
                if verb in (b'h', b'l') and text.startswith('?'):
                    for key in text[1:].split(';'):
                        if key not in self.modes:
                            self.error('unmodeled terminal mode ' + key)
                        else:
                            if key == '2026' and self.modes[key] == (verb == b'h'):
                                self.error('unbalanced synchronized-update boundary')
                            self.modes[key] = verb == b'h'
                            self.mode_events.append(dict(key=key, enabled=verb == b'h', ns=time.monotonic_ns()))
                    if text == '?2026' and verb == b'l' and self.current in self.images:
                        self.sync_frames.append(b64(self.images[self.current]['rgba']))
                elif verb in (b'H', b'f'):
                    values = [int(x or 1) for x in text.split(';')]
                    self.cursor = [(values[0] if values else 1) - 1, (values[1] if len(values) > 1 else 1) - 1]
                else:
                    self.error('outside bounded CSI profile')
                del self.buffer[:found.end()]
            elif data[0] == 27:
                if len(data) < 7 and any(prefix.startswith(data) for prefix in (ESC + b'_G', ESC + b'Ptmux;', ESC + b'[')):
                    return
                self.error('unknown escape framing')
                del self.buffer[0]
            else:
                self.events.append(dict(ns=time.monotonic_ns(), plain_byte=data[0]))
                self.error('unexpected plain output outside declared graphics framing')
                del self.buffer[0]


class Peer:
    def __init__(self, geometry, options):
        self.master, self.slave = os.openpty()
        self.original = copy.deepcopy(termios.tcgetattr(self.slave))
        profile = copy.deepcopy(self.original)
        profile[3] &= ~termios.ECHO
        termios.tcsetattr(self.slave, termios.TCSANOW, profile)
        self.initial = copy.deepcopy(termios.tcgetattr(self.slave))
        self.name = os.ttyname(self.slave)
        self.raw, self.events, self.samples = bytearray(), [], []
        self.set_size(geometry)
        self.model = Consumer(geometry, self.send, options)
        os.set_blocking(self.master, False)

    def set_size(self, value):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', *value))
        self.events.append(dict(action='geometry', ns=time.monotonic_ns(), geometry=list(value),
            actual_hex=fcntl.ioctl(self.slave, termios.TIOCGWINSZ, b'\0' * 8).hex()))

    def send(self, raw):
        self.events.append(dict(direction='send', ns=time.monotonic_ns(), base64=b64(raw),
            termios=mode(termios.tcgetattr(self.slave))))
        if raw:
            count = os.write(self.master, raw)
            if count != len(raw):
                raise RuntimeError('peer input short write')

    def pump(self):
        while select.select([self.master], [], [], 0)[0]:
            try:
                raw = os.read(self.master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    return
                raise
            if not raw:
                return
            self.raw.extend(raw)
            if len(self.raw) > 4 * 1024 * 1024:
                raise RuntimeError('PTY output bound')
            self.events.append(dict(direction='read', ns=time.monotonic_ns(), base64=b64(raw)))
            self.model.feed(raw)

    def stdin_wait(self, pid):
        """Only the remembered Bash PID, and only its FD for our slave."""
        try:
            raw = Path('/proc/%d/syscall' % pid).read_text().strip()
            values = [] if raw == 'running' else [int(x, 0) for x in raw.split()]
            sample = dict(pid=pid, ns=time.monotonic_ns(), syscall=raw, termios=mode(termios.tcgetattr(self.slave)))
            wait = False
            if values and values[0] in (7, 271) and 0 < values[2] <= 8:
                with open('/proc/%d/mem' % pid, 'rb', buffering=0) as memory:
                    array = os.pread(memory.fileno(), values[2] * 8, values[1])
                sample['pollfds_hex'] = array.hex()
                for fd, flags, _ in struct.iter_unpack('ihh', array):
                    if fd >= 0 and flags & select.POLLIN and os.readlink('/proc/%d/fd/%d' % (pid, fd)) == self.name:
                        wait = True
            sample['owned_tty_input_wait'] = wait
            if wait:
                self.samples.append(sample)
            return wait
        except (OSError, ValueError):
            return False

    def close(self):
        self.pump()
        before = termios.tcgetattr(self.slave)
        observed = dict(tty=self.name, initial=mode(self.initial), before_cleanup=mode(before),
            restored_before_cleanup=before == self.initial, original_before_profile=mode(self.original),
            events=self.events, readiness=self.samples, final_modes=self.model.modes)
        save('terminal.json', observed)
        (HOME / 'terminal.raw').write_bytes(self.raw)
        save('protocol.json', dict(events=self.model.events, errors=self.model.errors, replies=self.model.replies,
            queries=self.model.queries, shared_memory=self.model.shm, placements=self.model.placements,
            terminal_mode_events=self.model.mode_events,
            synchronized_frames=self.model.sync_frames, remaining_bytes_base64=b64(self.model.buffer),
            pending_chunk=self.model.pending is not None, tmux_wrappers=self.model.wrappers))
        termios.tcsetattr(self.slave, termios.TCSANOW, self.original)
        for row in self.model.shm:
            path = Path(row['path'])
            row['exists_before_observer_cleanup'] = path.exists()
            if path.exists():
                path.unlink()   # only exact previously validated owned names
        save('shared-memory.json', self.model.shm)
        os.close(self.master)
        os.close(self.slave)
        return before == self.initial


class Loop:
    def __init__(self, executable, peer, compose=False):
        self.peer, self.events, self.raw, self.err, self.number = peer, [], bytearray(), bytearray(), 0
        env = dict(os.environ, LC_ALL='C.UTF-8')
        for name in ('TMUX', 'SSH_CONNECTION', 'SSH_TTY', 'BASHOS_GPU_DEVICE', 'KITTY_KILIX_RENDERING'):
            env.pop(name, None)
        if compose:
            env['KITTY_KILIX_RENDERING'] = '1'
        self.proc = subprocess.Popen([executable, '--noprofile', '--norc'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        peer.model.owner = self.proc.pid

    def command(self, text, input_bytes=None, require_wait=False):
        self.number += 1
        token = ('GRAPHICS_ACK_%d:' % self.number).encode()
        raw = (text + '\nbuiltin printf "GRAPHICS_ACK_%d:%%s\\n" "$?"\n' % self.number).encode()
        begin, now = len(self.raw), time.monotonic_ns()
        self.events.append(dict(direction='send', ns=now, base64=b64(raw)))
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()
        deadline, sent, waited = time.monotonic() + 5, False, False
        while time.monotonic() < deadline:
            self.peer.pump()
            if require_wait and not waited and self.peer.stdin_wait(self.proc.pid):
                waited = True
                if input_bytes is not None:
                    self.peer.send(input_bytes)
                    sent = True
            for fd in select.select([self.proc.stdout, self.proc.stderr], [], [], .002)[0]:
                data = os.read(fd.fileno(), 65536)
                if data:
                    (self.raw if fd == self.proc.stdout else self.err).extend(data)
                    self.events.append(dict(direction='stdout' if fd == self.proc.stdout else 'stderr',
                        ns=time.monotonic_ns(), base64=b64(data)))
            tail = bytes(self.raw[begin:])
            if token in tail and b'\n' in tail.split(token, 1)[1]:
                for fd, target, direction in ((self.proc.stdout, self.raw, 'stdout'), (self.proc.stderr, self.err, 'stderr')):
                    while select.select([fd], [], [], 0)[0]:
                        data = os.read(fd.fileno(), 65536)
                        if not data:
                            break
                        target.extend(data)
                        self.events.append(dict(direction=direction, ns=time.monotonic_ns(), base64=b64(data)))
                self.peer.pump()
                row = dict(command=text, ns=now, finished_ns=time.monotonic_ns(),
                    status=int(tail.split(token, 1)[1].split(b'\n')[0]),
                    input_sent=sent, actual_input_wait=waited,
                    termios_after=mode(termios.tcgetattr(self.peer.slave)), terminal_modes=dict(self.peer.model.modes))
                return row
            if len(self.raw) + len(self.err) > 1000000 or self.proc.poll() is not None:
                break
        raise RuntimeError('remembered shell command deadline: ' + text)

    def close(self):
        natural = self.proc.poll()
        if natural is None:
            self.proc.stdin.close()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and self.proc.poll() is None:
                self.peer.pump()
                select.select([], [], [], .002)
            natural = self.proc.poll()
            if natural is None:
                self.proc.kill()
                self.proc.wait()
        for fd, target, direction in ((self.proc.stdout, self.raw, 'stdout'), (self.proc.stderr, self.err, 'stderr')):
            while select.select([fd], [], [], 0)[0]:
                data = os.read(fd.fileno(), 65536)
                if not data:
                    break
                target.extend(data)
                self.events.append(dict(direction=direction, ns=time.monotonic_ns(), base64=b64(data)))
        save('shell.json', dict(pid=self.proc.pid, natural_status=natural,
            status_after_cleanup=self.proc.returncode, events=self.events))
        (HOME / 'shell.stdout.raw').write_bytes(self.raw)
        (HOME / 'shell.stderr.raw').write_bytes(self.err)
        return natural


def native():
    initial = termios.tcgetattr(0)
    raw = copy.deepcopy(initial)
    raw[0] &= ~(termios.ICRNL | termios.IXON)
    raw[3] &= ~(termios.ICANON | termios.ECHO)
    raw[6][termios.VMIN], raw[6][termios.VTIME] = 1, 0
    termios.tcsetattr(0, termios.TCSANOW, raw)
    query = ESC + b'_Ga=q,t=d,f=32,s=1,v=1,i=111;AAAA/w==' + ST
    expected = ESC + b'_Gi=111;OK' + ST
    try:
        written = os.write(1, query)
        received = bytearray()
        end = time.monotonic() + 3
        while ST not in received and time.monotonic() < end:
            if select.select([0], [], [], .01)[0]:
                received.extend(os.read(0, 256))
        save('native.json', dict(query_base64=b64(query), written=written,
            received_base64=b64(received), expected_base64=b64(expected), raw_modes=mode(raw)))
        return int(bytes(received) != expected)
    finally:
        termios.tcsetattr(0, termios.TCSANOW, initial)


def setup():
    # Independent Python math/Unicode plus fixed original-contract literals
    # check the authored expectation data before either behavioral side.
    spec = json.loads(Path('scenario.json').read_text())
    validate_image_data(spec)
    assert reference(spec) == spec['expected_result']
    save('reference-control.json', reference(spec))
    # Literal positive/negative protocol controls precede every behavioral side.
    replies = []
    consumer = Consumer([10, 20, 40, 40], replies.append, {})
    consumer.cursor = [1, 2]
    consumer.feed(ESC + b'_Ga=T,f=24,t=d,s=2,v=1,c=1,r=1,C=1,q=2,m=1;/wAA' + ST)
    assert not consumer.images and not consumer.placements
    consumer.feed(ESC + b'_Gm=0,q=2;AP8A' + ST)
    assert consumer.images[0]['rgba'] == b'\xff\0\0\xff\0\xff\0\xff'
    assert consumer.cursor == [1, 2] and not replies and not consumer.errors
    consumer.feed(ESC + b'_Ga=p,i=0,c=1,r=1,q=2;' + ST)
    assert consumer.cursor == [2, 3]
    before = len(consumer.errors)
    consumer.feed(ESC + b'_Ga=T,f=24,t=d,s=2,v=1,q=2;/wAA' + ST)
    assert len(consumer.errors) == before + 1 and not replies
    save('model-control.json', dict(images={str(k): b64(v['rgba']) for k, v in consumer.images.items()},
        placements=consumer.placements, replies=consumer.replies, expected_negative_errors=consumer.errors))
    name = '/terminal-platform-control-%d-%s' % (os.getpid(), uuid.uuid4().hex)
    path = Path('/dev/shm') / name[1:]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b'\x01\x02\x03\xff')
    finally:
        os.close(fd)
    shm = Consumer([10, 20, 40, 40], replies.append, {'control_names': [name]})
    try:
        shm.feed(ESC + b'_Ga=q,t=s,f=32,s=1,v=1,i=222;' + base64.b64encode(name.encode()) + ST)
        assert not shm.errors and not path.exists() and shm.shm[0]['raw_base64'] == b64(b'\x01\x02\x03\xff')
        save('shm-control.json', dict(observations=shm.shm, replies=shm.replies))
    finally:
        if path.exists():
            path.unlink()
    peer = Peer([10, 20, 40, 40], {})
    proc = subprocess.Popen(['/usr/bin/python3', SELF, 'native'], stdin=peer.slave, stdout=peer.slave,
        stderr=peer.slave, start_new_session=True)
    try:
        deadline = time.monotonic() + 4
        while proc.poll() is None and time.monotonic() < deadline:
            peer.pump()
            select.select([], [], [], .002)
        assert proc.poll() == 0
        peer.pump()
        assert not peer.model.errors and len(peer.model.queries) == 1
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        restored = peer.close()
    assert restored
    # Preserve setup evidence before the behavioral peer reuses these names.
    for name in ('terminal.json', 'terminal.raw', 'protocol.json', 'shared-memory.json'):
        (HOME / ('setup-' + name)).write_bytes((HOME / name).read_bytes())
    print('independent-protocol-pixel-shm-PTY-controls=PASS')
    return 0


def expected_result(spec):
    return reference(spec)


def run(side, executable):
    spec = json.loads(Path('scenario.json').read_text())
    expected = expected_result(spec)
    save('oracle.json', expected)
    checks, phases = Checks(), []
    if side == 'reference':
        Path('result.json').write_text(json.dumps(expected, sort_keys=True, indent=2) + '\n')
        if 'saved_rgba_base64' in spec:
            Path('canvas.rgba').write_bytes(un64(spec['saved_rgba_base64']))
        checks.add('independent-declared-contract-result', expected, spec['expected_result'])
        return checks.end()
    peer = Peer(spec['geometry'], spec.get('peer', {}))
    loop = Loop(executable, peer, spec.get('compose', False))
    inputs, frames = [], []
    try:
        if spec['kind'] == 'kitty':
            command = ('exec 8>%s; builtin printf "\\033[%d;%dH" >&8; kitty %s image.png >&8; tp_kitty=$?; exec 8>&-; (exit "$tp_kitty")' % (
                shlex.quote(peer.name), spec['initial_cursor'][0] + 1, spec['initial_cursor'][1] + 1, ' '.join(spec['options'])))
            row = loop.command(command)
            phases.append(row)
            checks.add('kitty-emitter-status', row['status'], 0)
            placements = peer.model.placements
            checks.add('one-complete-placement', len(placements), 1)
            actual = dict(image_rgba_base64=placements[-1]['rendered_pixels_base64'] if placements else '',
                placement_cells=[placements[-1]['rows'], placements[-1]['columns']] if placements else [],
                cursor=peer.model.cursor, responses_sent=sum(not r['suppressed'] for r in peer.model.replies))
            checks.add('placement-pixels-are-exact-one-to-one', bool(placements) and placements[-1]['exact_one_to_one'])
            checks.add('expected-tmux-passthrough-profile', peer.model.wrappers > 0, spec.get('tmux', False))
            checks.add('expected-continuation-packets', sum('partial_not_displayed' in e for e in peer.model.events), spec.get('nonfinal_chunks', 0))
            initial_headers = [e['control'] for e in peer.model.events if e.get('control',{}).get('a') == 'T']
            pixels = json.loads(Path('pixels.json').read_text())['pixels']
            keys = ('a','f','t','s','v','c','r','q','i','p','z')
            checks.add('exact-declared-Kitty-command-profile', [{k:c.get(k) for k in keys} for c in initial_headers],
                [dict(a='T',f='24',t='d',s=str(len(pixels[0])),v=str(len(pixels)),c=str(spec['placement_cells'][1]),
                    r=str(spec['placement_cells'][0]),q='2',i='42',p='7',z='-1')])
            checks.add('exact-static-cursor-control', [c.get('C','0') for c in initial_headers], ['1' if spec.get('static_cursor') else '0'])
        else:
            command = 'gpu start %d %d --tty %s --transport %s%s' % (spec['width'], spec['height'],
                shlex.quote(peer.name), spec['transport'], ' --fullscreen' if spec.get('fullscreen') else '')
            start = loop.command(command)
            phases.append(start)
            checks.add('gpu-start-result', start['status'], spec.get('start_status', 0))
            checks.add('probe-terminal-settings-restored', start['termios_after'], mode(peer.initial))
            checks.add('exact-query-transport-order', [r['transport'] for r in peer.model.queries], spec['query_transports'])
            checks.add('exact-query-pixel-content', [r['rgba_base64'] for r in peer.model.queries], [b64(b'\0\0\0\xff')] * len(spec['query_transports']))
            if spec.get('peer', {}).get('hold_queries') and start['status'] == 0:
                held_queries = [r for r in peer.model.shm if r['query']]
                checks.add('exactly-one-held-shm-query-acknowledged', len(held_queries), 1)
                checks.add('acknowledged-query-unlinked-before-any-later-operation',
                    [Path(r['path']).exists() for r in held_queries], [False])
            if start['status'] == 0:
                if spec.get('fullscreen'):
                    checks.add('fullscreen-enter-modes', {k: start['terminal_modes'][k] for k in ('1049','25','1000','1006')},
                        {'1049':True,'25':False,'1000':True,'1006':True})
                for i, operation in enumerate(spec.get('operations', [])):
                    before = len(peer.model.events)
                    mode_before = len(peer.model.mode_events)
                    row = loop.command(operation['command'])
                    phases.append(row)
                    checks.add('canvas-command-status/%d' % i, row['status'], 0)
                    if operation.get('present'):
                        image = peer.model.images.get(peer.model.current)
                        frame = b64(image['rgba']) if image else ''
                        frames.append(frame)
                        checks.add('present-exact-image-geometry/%d' % i,
                            [image['width'],image['height']] if image else [], [spec['width'],spec['height']])
                        checks.add('present-exact-pixels/%d' % i, frame, operation['rgba_base64'])
                        transfer = [e for e in peer.model.events[before:] if e.get('action') in ('t','T','f')]
                        if 'transfer_actions' in operation:
                            checks.add('only-intended-full-or-damage-transfer/%d' % i, [e['action'] for e in transfer], operation['transfer_actions'])
                        if 'transports' in operation:
                            checks.add('actual-inline-shm-frame-transport/%d' % i, [e['transport'] for e in transfer], operation['transports'])
                        if 'patch_rectangle' in operation:
                            patches = [e for e in transfer if e['action'] == 'f']
                            checks.add('exact-changed-damage-rectangle/%d' % i,
                                [[int(e['control'].get(k, '0')) for k in ('x','y','s','v')] for e in patches], [operation['patch_rectangle']])
                        if 'compose_after_base64' in operation:
                            compositions = [e for e in peer.model.events[before:] if e.get('control',{}).get('a') == 'c']
                            checks.add('one-scroll-composition/%d' % i, len(compositions), 1)
                            checks.add('scroll-composition-before-later-patch/%d' % i,
                                [e.get('image_after_base64') for e in compositions], [operation['compose_after_base64']])
                            checks.add('scroll-copy-source-destination/%d' % i,
                                [[int(e['control'][k]) for k in ('X','Y','x','y','w','h')] for e in compositions], [operation['compose_rectangles']])
                        checks.add('synchronized-present-completed/%d' % i, not peer.model.modes['2026'])
                        checks.add('exact-synchronized-update-boundaries/%d' % i,
                            [[e['key'], e['enabled']] for e in peer.model.mode_events[mode_before:]], [['2026', True], ['2026', False]])
                if spec.get('resize'):
                    peer.set_size(spec['resize'])
                    peer.send(b'X')
                for i, event in enumerate(spec.get('inputs', [])):
                    path = HOME / ('input%d.bin' % i)
                    variable = 'tp_event%d' % i
                    init = ('readonly %s=STALE' if event.get('readonly') else '%s=STALE') % variable
                    phases.append(loop.command(init))
                    if event.get('late_probe'):
                        stale = peer.model.queries[0]['image']
                        payload = ESC + b'_Gi=' + str(stale).encode() + b';ENOTSUP:late' + ST + un64(event['send_base64'])
                    else:
                        payload = un64(event['send_base64']) if 'send_base64' in event else None
                    text = 'gpu input %s %d; tp_input_rc=$?; builtin printf "%%s" "$%s" >%s; (exit "$tp_input_rc")' % (
                        variable, event.get('timeout_ms', 600), variable, shlex.quote(str(path)))
                    row = loop.command(text, payload, event.get('wait', False))
                    observed = path.read_bytes()
                    row['variable_base64'] = b64(observed)
                    phases.append(row)
                    inputs.append(dict(status=row['status'], event_base64=b64(observed)))
                    checks.add('input-return-status/%d' % i, row['status'], event.get('status', 0))
                    checks.add('input-exact-variable-bytes/%d' % i, b64(observed), event['event_base64'])
                    checks.add('input-termios-restored-before-next-operation/%d' % i, row['termios_after'], mode(peer.initial))
                    if event.get('wait'):
                        checks.add('causal-owned-tty-input-wait/%d' % i, row['actual_input_wait'])
                        checks.add('input-raw-mode-before-supplied-bytes/%d' % i,
                            bool(peer.samples) and not (peer.samples[-1]['termios'][3] & (termios.ICANON | termios.ECHO | termios.ISIG)))
                    if 'send_base64' in event:
                        checks.add('actual-input-bytes-sent/%d' % i, row['input_sent'])
                    if event.get('timeout_ms') == 200:
                        elapsed = (row['finished_ns'] - row['ns']) / 1e6
                        checks.add('bounded-real-input-timeout/%d' % i, 150 <= elapsed < 2000)
                if 'saved_rgba_base64' in spec:
                    phases.append(loop.command('gpu save canvas.rgba rgba'))
                    checks.add('exact-saved-canvas-file', b64(Path('canvas.rgba').read_bytes()), spec['saved_rgba_base64'])
                if spec.get('held_objects'):
                    names = [r for r in peer.model.shm if not r['query']]
                    checks.add('owned-objects-remain-before-stop', [Path(r['path']).exists() for r in names], [True] * spec['held_objects'])
                stop = loop.command('gpu stop')
                phases.append(stop)
                checks.add('stop-result', stop['status'], 0)
            else:
                phases.append(dict(unreached='start failed: no canvas edit/present/input claimed', ns=time.monotonic_ns()))
            checks.add('all-known-shm-objects-unlinked-before-observer-cleanup',
                [Path(r['path']).exists() for r in peer.model.shm], [False] * len(peer.model.shm))
            allowed_reply_ids = {q['image'] for q in peer.model.queries}
            if spec.get('peer', {}).get('wrong_id'):
                allowed_reply_ids.update(q['image'] + 100000 for q in peer.model.queries)
            checks.add('quiet-presentation-no-success-or-error-replies-sent',
                [r for r in peer.model.replies if not r['suppressed'] and r['image'] not in allowed_reply_ids], [])
            checks.add('every-nonquery-graphics-command-declares-q2',
                [e['control'].get('q') for e in peer.model.events if 'control' in e and e['control'].get('a') != 'q'],
                ['2'] * sum('control' in e and e['control'].get('a') != 'q' for e in peer.model.events))
            transfer_headers = [e['control'] for e in peer.model.events if e.get('control',{}).get('a') in ('q','t','f') and 's' in e['control']]
            checks.add('every-pixel-probe-and-transfer-is-RGBA32', [c.get('f') for c in transfer_headers], ['32'] * len(transfer_headers))
            checks.add('fullscreen-stop-restores-modes', peer.model.modes,
                {'1049':False,'25':True,'1000':False,'1006':False,'2026':False})
            if spec.get('start_status'):
                checks.add('terminal-rejection-visible', b'fixture-rejection' in loop.err and b'terminal rejected' in loop.err)
            if 'nonfinal_chunks' in spec:
                checks.add('all-expected-m1-continuations-reached', sum('partial_not_displayed' in e for e in peer.model.events), spec['nonfinal_chunks'])
            actual = dict(frames=frames, inputs=inputs)
        checks.add('consumer-accepted-every-emitted-protocol-packet', peer.model.errors, [])
        checks.add('all-chunk-and-escape-framing-complete', not peer.model.buffer and peer.model.pending is None)
        checks.add('exact-independent-result', actual, expected)
        Path('result.json').write_text(json.dumps(actual, sort_keys=True, indent=2) + '\n')
    finally:
        save('phases.json', phases)
        natural = loop.close()
        restored = peer.close()
    checks.add('owned-shell-natural-exit', natural, 0)
    checks.add('all-terminal-settings-restored-before-observer-cleanup', restored)
    return checks.end()


def main():
    guard()
    action, *args = sys.argv[1:]
    try:
        if action == 'setup':
            return setup()
        if action == 'native':
            return native()
        if action == 'run':
            return run(*args)
        raise ValueError(action)
    finally:
        for pid in map(int, Path('/proc/self/task/%d/children' % os.getpid()).read_text().split()):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


if __name__ == '__main__':
    sys.exit(main())
