#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only nano follow-up PTYs, independent controls, and spell fixtures.

No project helper imports. Full input/output and decoded snapshots remain in
HOME. Saved bytes are never normalized. GNU custom-speller filename protocol
is tested strictly before a separately labelled dual-interface semantic probe.
"""
import base64
import copy
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
import unicodedata
import uuid

SELF = '/opt/bashos-parity/harness/helpers/nano-followup-observer.py'
PYTHON = '/usr/bin/python3'
LIB = ctypes.CDLL(None, use_errno=True)


def require_guest():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or os.getuid() != 2000 or os.geteuid() != 2000
            or Path.cwd() != Path('/tmp/parity-case')
            or Path.home() != Path('/tmp/parity-home') or os.uname().machine != 'x86_64'):
        raise RuntimeError('refusing outside disposable QEMU uid2000 case scratch')
    # The root evaluator independently verifies the DMI UUID against marker.
    if LIB.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')


def b64(data):
    return base64.b64encode(data).decode()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def reap_owned():
    # Only this subreaper's direct children, including adopted helper children.
    for pid in map(int, Path('/proc/self/task/%d/children' % os.getpid()).read_text().split()):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)


def modes_json(modes):
    return modes[:6] + [[v if isinstance(v, int) else b64(v) for v in modes[6]]]


def memory(pid, address, size):
    with open('/proc/%d/mem' % pid, 'rb', buffering=0) as handle:
        return os.pread(handle.fileno(), size, address)


class Session:
    def __init__(self, argv, env=None, prefix='session'):
        import pyte                 # guest only; never imported by host checks
        class Screen(pyte.Screen):
            def __init__(self):
                super().__init__(80, 24)
                self.replies = bytearray()
            def write_process_input(self, data):
                self.replies.extend(data.encode())
            def select_graphic_rendition(self, *attrs, private=False):
                if not private:
                    super().select_graphic_rendition(*attrs)
        self.screen = Screen()
        self.stream = pyte.ByteStream(self.screen)
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        self.initial = copy.deepcopy(termios.tcgetattr(self.slave))
        self.argv, self.prefix = argv, prefix
        self.raw, self.events, self.samples, self.snapshots = bytearray(), [], [], []
        self.status, self.body, self.closed = None, 1, False
        self.deadline = time.monotonic() + 35
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(self.master)
                os.setsid()
                fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
                os.tcsetpgrp(self.slave, os.getpgrp())
                for fd in (0, 1, 2):
                    os.dup2(self.slave, fd)
                if self.slave > 2:
                    os.close(self.slave)
                os.execve(argv[0], argv, os.environ.copy() if env is None else env)
            except BaseException as exc:
                os.write(2, ('nano fixture exec: %s\n' % exc).encode())
            os._exit(126)
        os.set_blocking(self.master, False)

    def poll(self):
        if self.status is None:
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.status = os.waitstatus_to_exitcode(status)
        return self.status

    def pump(self, duration=.01):
        if time.monotonic() > self.deadline:
            raise RuntimeError('nano session wall-clock limit')
        if select.select([self.master], [], [], duration)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                data = b''
            if data:
                if len(self.raw) + len(data) > 900000:
                    raise RuntimeError('nano raw output limit')
                self.raw.extend(data)
                self.events.append({'direction': 'read', 'ns': time.monotonic_ns(), 'base64': b64(data)})
                self.stream.feed(data)
                if self.screen.replies:
                    replies = bytes(self.screen.replies)
                    self.screen.replies.clear()
                    self.send(replies, 'terminal-query-reply')

    def wait(self, predicate, seconds=2):
        end = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < end:
            self.pump()
            if predicate():
                # The child can already be waiting on stdin while the PTY
                # still holds the tail of its completed render frame.
                while select.select([self.master], [], [], 0)[0]:
                    self.pump(0)
                if predicate():
                    return True
            if self.poll() is not None:
                self.pump(0)
                return bool(predicate())
        return bool(predicate())

    def ready(self, pid=None):
        pid = self.pid if pid is None else pid
        if pid != self.pid:
            try:
                parent = next(line for line in Path('/proc/%d/status' % pid).read_text().splitlines()
                              if line.startswith('PPid:')).split()[1]
                if int(parent) != self.pid:
                    return False
            except (FileNotFoundError, ProcessLookupError):
                return False
        try:
            raw = Path('/proc/%d/syscall' % pid).read_text().strip()
            values = [] if raw == 'running' else [int(v, 0) for v in raw.split()]
            fact = {'pid': pid, 'syscall': raw}
            result = False
            if len(values) > 2 and values[0] == 0 and values[1] == 0:
                result = True
            elif len(values) > 6 and values[0] in (23, 270) and values[1] == 1 and values[2]:
                mask = memory(pid, values[2], 8)
                fact['read_fdset_hex'] = mask.hex()
                result = int.from_bytes(mask, 'little') == 1 and values[3] == values[4] == 0
            elif len(values) > 3 and values[0] in (7, 271) and 1 <= values[2] <= 8:
                array = memory(pid, values[1], values[2] * 8)
                fact['pollfds_hex'] = array.hex()
                result = (values[0] == 271 or values[3] != 0) and any(
                    fd == 0 and flags & select.POLLIN for fd, flags, _ in struct.iter_unpack('ihh', array))
            fact['stdin_wait'] = bool(result)
            if not self.samples or {k: v for k, v in self.samples[-1].items() if k != 'ns'} != fact:
                self.samples.append(dict(fact, ns=time.monotonic_ns()))
            return bool(result)
        except (FileNotFoundError, ProcessLookupError, OSError, ValueError, struct.error) as exc:
            self.samples.append({'pid': pid, 'ns': time.monotonic_ns(), 'readiness_error': str(exc)})
            return False

    def send(self, data, label):
        if self.poll() is not None:
            self.events.append({'direction': 'unsent', 'label': label, 'base64': b64(data), 'ns': time.monotonic_ns()})
            return False
        self.events.append({'direction': 'send', 'label': label, 'base64': b64(data), 'ns': time.monotonic_ns()})
        os.write(self.master, data)
        return True

    def text(self, row):
        return self.screen.display[row].rstrip()

    def contains(self, text):
        return any(text in line for line in self.screen.display)

    def snapshot(self, label):
        rows = list(self.screen.display)
        reverse = [{'row': y, 'column': x, 'data': char.data} for y, line in self.screen.buffer.items()
                   for x, char in line.items() if char.reverse]
        self.snapshots.append({'label': label, 'ns': time.monotonic_ns(), 'rows': rows,
                               'cursor': [self.screen.cursor.y, self.screen.cursor.x], 'reverse_cells': reverse})

    def step(self, label, data):
        before = len(self.raw)
        sent = self.send(data, label)
        ack = self.wait(lambda: len(self.raw) > before and self.ready()) if sent else False
        self.snapshot(label)
        return sent, ack

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.pump(0)
        except Exception as exc:
            self.events.append({'cleanup_read_error': str(exc), 'ns': time.monotonic_ns()})
        natural = self.poll()
        final_modes = termios.tcgetattr(self.slave)
        if natural is None:
            os.kill(self.pid, signal.SIGKILL)
            self.status = os.waitstatus_to_exitcode(os.waitpid(self.pid, 0)[1])
        try:
            self.pump(0)
        except Exception as exc:
            self.events.append({'cleanup_read_error': str(exc), 'ns': time.monotonic_ns()})
        try:
            termios.tcsetattr(self.slave, termios.TCSANOW, self.initial)
            restored = termios.tcgetattr(self.slave) == self.initial
        finally:
            os.close(self.master)
            os.close(self.slave)
            reap_owned()
        (Path.home() / (self.prefix + '.raw')).write_bytes(self.raw)
        save(Path.home() / (self.prefix + '.json'), {
            'argv': self.argv, 'pid': self.pid, 'natural_status': natural,
            'status_after_cleanup': self.status, 'termios_initial': modes_json(self.initial),
            'termios_before_cleanup': modes_json(final_modes), 'cleanup_restored': restored,
            'restored_before_cleanup': final_modes == self.initial, 'events': self.events,
            'readiness': self.samples, 'snapshots': self.snapshots})


def native_tty():
    initial = termios.tcgetattr(0)
    raw = copy.deepcopy(initial)
    raw[3] &= ~(termios.ICANON | termios.ECHO)
    termios.tcsetattr(0, termios.TCSANOW, raw)
    try:
        os.write(1, '\x1b[2J\x1b[H\x1b[7malpha\x1b[0m beta\r\ne\u0301中\r\nNATIVE READY\r\n'.encode())
        fdset = (ctypes.c_ulong * 16)()
        fdset[0] = 1
        LIB.pselect.argtypes = [ctypes.c_int] + [ctypes.c_void_p] * 5
        if LIB.pselect(1, ctypes.byref(fdset), None, None, None, None) != 1:
            return 1
        return 0 if os.read(0, 1) == b'g' else 1
    finally:
        termios.tcsetattr(0, termios.TCSANOW, initial)


def helper_log(event, **data):
    name = os.environ.get('NANO_FOLLOWUP_LOG', 'spell-helper.jsonl')
    if name not in ('spell-helper.jsonl', 'setup-helper.jsonl'):
        raise ValueError('unsafe helper log')
    row = dict(event=event, ns=time.monotonic_ns(), pid=os.getpid(), **data)
    with (Path.home() / name).open('a') as handle:
        handle.write(json.dumps(row, sort_keys=True) + '\n')


def speller(args):
    mode = os.environ['NANO_FOLLOWUP_MODE']
    protocol = 'filename' if len(args) == 1 else 'wordlist' if not args else 'invalid'
    helper_log('start', mode=mode, protocol=protocol, argv=args, stdin_tty=os.isatty(0))
    path = None
    if protocol == 'filename':
        path = Path(args[0]).resolve()
        info = path.lstat()
        if (path.parent not in (Path.cwd(), Path.home() / 'nano-tmp')
                or not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_nlink != 1):
            raise RuntimeError('unsafe speller input file')
        data = path.read_bytes()
    elif protocol == 'wordlist':
        data = sys.stdin.buffer.read(262145)
    else:
        return 43
    if len(data) > 262144:
        return 44
    helper_log('input', mode=mode, protocol=protocol, input_base64=b64(data))
    dictionary = json.loads(Path('dictionary.json').read_text())
    if dictionary != {'teh': 'the'}:
        return 45
    if mode == 'failure':
        helper_log('exit', code=7)
        return 7
    if mode == 'timeout':
        helper_log('deadline-ready', deadline_seconds=12)
        # A documented fixture-local 12s failure bound for GNU's alternate
        # process; candidate's own 10s timeout should terminate it first.
        select.select([], [], [], 12)
        helper_log('exit', code=124)
        return 124
    if mode == 'strict-replace' and protocol != 'filename':
        helper_log('protocol-refused', code=42)
        return 42
    if protocol == 'wordlist':
        out = b'teh\n' if re.search(rb'\bteh\b', data) else b''
        os.write(1, out)
        helper_log('wordlist', output_base64=b64(out))
        return 0
    if mode == 'control':
        result = re.sub(rb'\bteh\b', b'the', data)
        path.write_bytes(result)
        helper_log('replacement', output_base64=b64(result), control=True)
        return 0
    initial = termios.tcgetattr(0)
    raw = copy.deepcopy(initial)
    raw[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
    raw[6][termios.VMIN], raw[6][termios.VTIME] = 1, 0
    termios.tcsetattr(0, termios.TCSANOW, raw)
    replacement = bytearray(b'teh')
    try:
        os.write(1, b'NF SPELL replacement (ESC cancels): teh')
        helper_log('prompt-ready')
        end = time.monotonic() + 8
        while time.monotonic() < end:
            if not select.select([0], [], [], .1)[0]:
                continue
            char = os.read(0, 1)
            if char == b'\x1b':
                helper_log('cancel', output_base64=b64(data))
                os.write(1, b'\r\nNF CANCELLED\r\n')
                return 0
            if char in (b'\r', b'\n'):
                result = re.sub(rb'\bteh\b', bytes(replacement), data)
                path.write_bytes(result)
                # Ensure GNU observes a changed temporary file even on a
                # guest filesystem whose timestamp clock tick is coarse.
                stamp = max(time.time_ns(), info.st_mtime_ns + 1_000_000)
                os.utime(path, ns=(stamp, stamp))
                helper_log('replacement', output_base64=b64(result), replacement_base64=b64(replacement))
                os.write(1, b'\r\nNF REPLACED\r\n')
                return 0
            if char in (b'\x7f', b'\x08'):
                if replacement:
                    replacement.pop()
                    os.write(1, b'\b \b')
            elif char and char >= b' ':
                replacement.extend(char)
                os.write(1, char)
        helper_log('prompt-bound', code=46)
        return 46
    finally:
        termios.tcsetattr(0, termios.TCSANOW, initial)


def read_helper_log():
    path = Path.home() / 'spell-helper.jsonl'
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def setup():
    Path('helper').chmod(0o755)
    (Path.home() / 'nano-tmp').mkdir(mode=0o700)
    os.utime('note.txt', ns=(1000000000 * 10**9, 1000000000 * 10**9))
    version = subprocess.run(['/usr/bin/nano', '--version'], capture_output=True, timeout=3)
    (Path.home() / 'reference-version.raw').write_bytes(version.stdout + version.stderr)
    if version.returncode or b'version 8.4' not in version.stdout.splitlines()[0]:
        raise RuntimeError('GNU nano8.4 reference control failed')
    native = Session([PYTHON, SELF, 'native-tty'], prefix='setup-tty')
    try:
        if not native.wait(lambda: native.contains('NATIVE READY') and native.ready()):
            raise RuntimeError('native pselect/readiness control failed')
        assert all(native.screen.buffer[0][x].reverse for x in range(5))
        assert not native.screen.buffer[0][5].reverse
        assert native.screen.buffer[1][0].data == 'é' and native.screen.buffer[1][1].data == '中'
        native.send(b'g', 'control-input')
        assert native.wait(lambda: native.poll() is not None) and native.status == 0
        assert termios.tcgetattr(native.slave) == native.initial
    finally:
        native.close()
    controls = {}
    env = dict(os.environ, NANO_FOLLOWUP_MODE='control', NANO_FOLLOWUP_LOG='setup-helper.jsonl')
    seed = b'teh cat teh\n'
    Path('control-note.txt').write_bytes(seed)
    try:
        for protocol, args in [('wordlist', []), ('filename', ['control-note.txt'])]:
            result = subprocess.run([PYTHON, SELF, 'speller'] + args, input=seed,
                                    capture_output=True, timeout=3, env=env)
            assert result.returncode == 0 and not result.stderr
            assert result.stdout == (b'teh\n' if protocol == 'wordlist' else b'')
            controls[protocol] = {'status': result.returncode, 'stdout_base64': b64(result.stdout),
                                  'stderr_base64': b64(result.stderr)}
        assert Path('control-note.txt').read_bytes() == b'the cat the\n'
        controls['corrected_file_base64'] = b64(Path('control-note.txt').read_bytes())
    finally:
        Path('control-note.txt').unlink()
    save(Path.home() / 'setup-helper-controls.json', controls)
    print('independent-terminal-decoder-and-helper-controls=PASS')
    return 0


def run_case(side, shell):
    spec = json.loads(Path('scenario.json').read_text())
    options = spec.get('options', [])
    mode = spec.get('spell_mode', '')
    argv = (['/usr/bin/nano', '--rcfile=/tmp/parity-case/nano.rc'] + options + ['note.txt']
            if side == 'reference' else [shell, '--noprofile', '--norc', '-c',
                'nano ' + ' '.join(options + ['note.txt'])])
    env = dict(os.environ, NANO_FOLLOWUP_MODE=mode, NANO_FOLLOWUP_LOG='spell-helper.jsonl',
               TMPDIR=str(Path.home() / 'nano-tmp'))
    session = Session(argv, env=env)
    phases, checks = [], {'editor-ready': False, 'all-input-operations-sent': True,
                          'causal-input-acknowledgements': True, 'explicit-visible-assertions': True,
                          'expected-saved-bytes': False, 'exit-zero-after-save': False,
                          'termios-restored-before-cleanup': False, 'helper-contract': True}
    def visible(label, okay, detail=None):
        checks['explicit-visible-assertions'] &= bool(okay)
        phases.append({'label': label, 'assertion': bool(okay), 'detail': detail})
    def key(label, data):
        sent, ack = session.step(label, data)
        checks['all-input-operations-sent'] &= sent
        checks['causal-input-acknowledgements'] &= ack
        phases.append({'label': label, 'sent': sent, 'acknowledged': ack})
    def lines(label, expected):
        observed = [session.text(session.body + i) for i in range(len(expected))]
        wanted = [unicodedata.normalize('NFC', line).rstrip() for line in expected]
        visible(label, observed == wanted, {'expected': wanted, 'observed': observed})
    def save_file(label):
        key(label, b'\x13')
        visible(label + '-reported', session.contains('Wrote'))
        session.snapshot(label + '-after-save')
    try:
        checks['editor-ready'] = session.wait(lambda: session.contains('note.txt') and session.ready()
            and not (termios.tcgetattr(session.slave)[3] & termios.ICANON), 4)
        # Both controlled layouts have one title row and no emptyline/gutter
        # option. The cursor may be in a transient status position while a
        # terminal query is answered; body row is a fixed display contract.
        session.body = 1
        session.snapshot('initial')
        kind = spec['kind']
        if kind in ('redo', 'trim', 'repeat'):
            key('justify', b'\x1bj')
            lines('first-justification-visible', spec['justified_lines'])
            if kind == 'redo':
                key('undo', b'\x1bu')
                lines('undo-restores-original-visible', spec['initial_lines'])
                key('redo', b'\x1be')
                lines('redo-reapplies-justification-visible', spec['justified_lines'])
            elif kind == 'repeat':
                save_file('first-save')
                Path('first-save.txt').write_bytes(Path('note.txt').read_bytes())
                key('justify-again', b'\x1bj')
                lines('repeated-justification-visible', spec['justified_lines'])
        elif kind in ('region', 'grapheme', 'highlight'):
            if kind == 'grapheme':
                key('type-utf8', 'e\u0301中Z'.encode())
                lines('typed-utf8-visible', ['e\u0301中Z'])
                key('home', b'\x01')
            key('mark', b'\x1ba')
            if kind == 'grapheme':
                key('right-combining-cluster', b'\x1b[C')
                visible('combining-step-is-one-cell', session.screen.cursor.x == 1)
                key('right-wide-cluster', b'\x1b[C')
                visible('wide-step-is-two-cells', session.screen.cursor.x == 3)
            else:
                key('select-alpha', b'\x1b[C' * 5)
                visible('selected-exact-five-cells', all(
                    session.screen.buffer[session.body][x].reverse for x in range(5))
                    and not session.screen.buffer[session.body][5].reverse)
            session.snapshot('selected-region')
            if kind == 'highlight':
                key('unmark', b'\x1ba')
                visible('unmark-removes-reverse', all(
                    not session.screen.buffer[session.body][x].reverse for x in range(6)))
            else:
                key('cut-marked-region', b'\x0b')
                lines('cut-visible', [spec['after_cut']])
                key('end', b'\x05')
                key('paste-marked-region', b'\x15')
                lines('paste-visible', [spec['after_paste']])
        elif kind == 'completion':
            key('next-line', b'\x0e')
            key('end-fragment', b'\x05')
            first_row = session.screen.cursor.y
            key('first-completion', b'\x1d')
            first = session.text(first_row)
            visible('first-completion-exact-word', first == unicodedata.normalize('NFC', spec['first_word']),
                    {'observed': first, 'expected': spec['first_word']})
            Path('first-completion.txt').write_text(first + '\n')
            key('cycle-completion', b'\x1d')
            second = session.text(first_row)
            visible('second-completion-exact-word', second == unicodedata.normalize('NFC', spec['second_word']),
                    {'observed': second, 'expected': spec['second_word']})
            visible('repeated-key-cycles-distinctly', first != second)
        elif kind == 'spell':
            sent = session.send(b'\x14', 'invoke-configured-speller')
            checks['all-input-operations-sent'] &= sent
            invoked = session.wait(lambda: any(row['event'] == 'input' for row in read_helper_log()), 4)
            visible('configured-helper-invoked', invoked)
            log = read_helper_log()
            protocol = log[0].get('protocol') if log else None
            supplied = next((row.get('input_base64') for row in log if row['event'] == 'input'), None)
            visible('helper-saw-exact-controlled-buffer', supplied == spec['spell_seed_base64'],
                    {'expected_base64': spec['spell_seed_base64'], 'observed_base64': supplied})
            if mode == 'strict-replace':
                checks['helper-contract'] = protocol == 'filename'
            if mode in ('strict-replace', 'dual-replace', 'dual-cancel'):
                target = 'NF SPELL replacement (ESC cancels): teh' if side == 'reference' else 'Edit a replacement: teh'
                def prompt_ready():
                    if not session.contains(target):
                        return False
                    if side == 'candidate':
                        return session.ready()
                    started = read_helper_log()
                    return bool(started) and session.ready(started[0]['pid'])
                prompted = session.wait(prompt_ready, 4)
                visible('actual-correction-prompt', prompted, {'expected': target})
                if prompted:
                    reply = b'\x1b' if mode == 'dual-cancel' else b'\x7f' * 3 + b'the\r'
                    checks['all-input-operations-sent'] &= session.send(reply, 'correction-reply')
                    response = ('Nothing changed' if side == 'reference' else 'Spell check cancelled (0 replaced)') \
                        if mode == 'dual-cancel' else ('the cat the' if side == 'reference' else 'Finished checking spelling (2 replaced)')
                    ended = session.wait(lambda: session.contains(response) and session.ready(), 4)
                    visible('correction-outcome-visible', ended, {'expected': response})
                else:
                    checks['all-input-operations-sent'] = False
                    phases.append({'label': 'correction-reply', 'sent': False,
                                   'gap': 'no correction prompt; no editing bytes sent into the main editor'})
            else:
                expected = "Error invoking './helper'" if side == 'reference' else (
                    'Spell helper timed out: ./helper' if mode == 'timeout' else 'Spell helper failed (exit 7): ./helper')
                seconds = 15 if mode == 'timeout' else 4
                reported = session.wait(lambda: session.contains(expected) and session.ready(), seconds)
                visible('helper-error-exact-visible', reported, {'expected': expected})
                if mode == 'timeout':
                    rows = read_helper_log()
                    ready_row = next((r for r in rows if r['event'] == 'deadline-ready'), None)
                    elapsed = None if ready_row is None else time.monotonic_ns() - ready_row['ns']
                    lower, upper = ((11_000_000_000, 15_000_000_000) if side == 'reference'
                                    else (9_000_000_000, 12_000_000_000))
                    visible('causal-helper-deadline-window', elapsed is not None and lower <= elapsed < upper,
                            {'elapsed_ns': elapsed, 'lower_ns': lower, 'upper_ns': upper,
                             'note': 'GNU helper self-exits124 at12s; candidate editor owns10s timeout. '
                                     'No claim that GNU implements a10s editor timeout.'})
            session.snapshot('spell-outcome')
        else:
            raise ValueError(kind)
        save_file('final-save')
        actual = Path('note.txt').read_bytes()
        Path('saved.txt').write_bytes(actual)
        checks['expected-saved-bytes'] = actual == base64.b64decode(spec['expected_final_base64'])
        sent = session.send(b'\x18', 'exit-after-save')
        checks['all-input-operations-sent'] &= sent
        ended = session.wait(lambda: session.poll() is not None, 3)
        checks['exit-zero-after-save'] = ended and session.status == 0
        checks['termios-restored-before-cleanup'] = ended and termios.tcgetattr(session.slave) == session.initial
    finally:
        session.close()
        save(Path.home() / 'observations.json', {'checks': checks, 'phases': phases,
              'unreached_policy': 'A sent operation is not proof of a later branch. Inspect phases, helper '
                                  'protocol/prompt logs and snapshots. All actual saved bytes remain unchanged.'})
    for label, passed in checks.items():
        print('%s=%s' % (label, 'PASS' if passed else 'FAIL'))
    return 0 if all(checks.values()) else 1


def main():
    require_guest()
    action, *args = sys.argv[1:]
    if action == 'setup':
        return setup()
    if action == 'run':
        return run_case(*args)
    if action == 'native-tty':
        return native_tty()
    if action == 'speller':
        return speller(args)
    raise ValueError(action)


if __name__ == '__main__':
    sys.exit(main())
