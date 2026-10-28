#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only terminal and clock observations for the bounded terminal review.

No candidate result supplies an expectation. PTY children are direct children;
readiness is an observed read(0) or pselect6 waiting on fd 0, not a delay.
Every interaction, syscall sample,
termios snapshot, elapsed interval and unmodified output is retained in HOME.
Only the rendering case puts its raw bytes in the compared workspace as well.
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
import subprocess
import sys
import termios
import time
import uuid


SELF = '/opt/bashos-parity/harness/helpers/terminal-review-observer.py'
SECCOMP = '/opt/bashos-parity/harness/helpers/system-seccomp.py'
PYTHON = '/usr/bin/python3'
READ = 0                       # sealed x86_64 guest; checked by require_guest
PSELECT6 = 270
CLOCK_NANOSLEEP = 230
LIB = ctypes.CDLL(None, use_errno=True)


def require_guest():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or os.geteuid() != 2000 or os.getuid() != 2000
            or Path.cwd() != Path('/tmp/parity-case')
            or Path.home() != Path('/tmp/parity-home')
            or os.uname().machine != 'x86_64'):
        raise RuntimeError('refusing outside the disposable QEMU case as uid 2000')
    # The root evaluator has already verified the marker against the DMI UUID.
    if LIB.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')


def save(name, value):
    (Path.home() / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def b64(data):
    return base64.b64encode(data).decode()


def report(checks):
    for name, passed in checks.items():
        print('%s=%s' % (name, 'PASS' if passed else 'FAIL'))
    return 0 if all(checks.values()) else 1


def syscall_sample(pid):
    # pid is always a direct child or a still-owned descendant, never selected
    # by name or by scanning the system process table.
    try:
        raw = Path('/proc/%d/syscall' % pid).read_text().strip()
        parts = raw.split()
        if parts and parts[0] != 'running':
            return raw, [int(v, 0) for v in parts]
        return raw, []
    except (FileNotFoundError, ProcessLookupError):
        return 'exited', []


def reap_adopted():
    """Only direct children of this subreaper; no process-name selection."""
    children = Path('/proc/self/task/%d/children' % os.getpid())
    for child in map(int, children.read_text().split()):
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(child, 0)


def serial_modes(modes):
    return modes[:6] + [[v if isinstance(v, int) else b64(v) for v in modes[6]]]


class Pty:
    def __init__(self, argv):
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, b'\x18\x00\x50\x00\x00\x00\x00\x00')
        self.initial = copy.deepcopy(termios.tcgetattr(self.slave))
        self.raw = bytearray()
        self.events = []
        self.samples = []
        self.status = None
        self.closed = False
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
                os.execv(argv[0], argv)
            except BaseException as exc:
                os.write(2, ('PTY exec: %s\n' % exc).encode())
            os._exit(126)
        os.set_blocking(self.master, False)

    def poll(self):
        if self.status is None:
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.status = os.waitstatus_to_exitcode(status)
        return self.status

    def pump(self, seconds=0.01):
        if select.select([self.master], [], [], seconds)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                data = b''
            if data:
                if len(self.raw) + len(data) > 1024 * 1024:
                    raise RuntimeError('PTY output bound exceeded')
                self.events.append({'direction': 'read', 'ns': time.monotonic_ns(), 'base64': b64(data)})
                self.raw.extend(data)

    def until(self, predicate, seconds=1.5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.pump()
            if predicate():
                return True
            if self.poll() is not None:
                self.pump(0)
                return bool(predicate())
        return bool(predicate())

    def ready(self):
        last = None
        def reading():
            nonlocal last
            raw, values = syscall_sample(self.pid)
            if raw != last:
                self.samples.append({'ns': time.monotonic_ns(), 'syscall': raw})
                last = raw
            if len(values) > 1 and values[0] == READ and values[1] == 0:
                return True
            # GNU bc/readline waits in pselect6(1, &readfds, NULL, NULL,
            # NULL, ...). Check bit 0 in the direct child's actual fd_set;
            # a generic poll/select syscall is not sufficient readiness.
            if len(values) > 6 and values[0] == PSELECT6 and values[1] == 1 and values[2]:
                try:
                    with open('/proc/%d/mem' % self.pid, 'rb', buffering=0) as mem:
                        mask = os.pread(mem.fileno(), 8, values[2])
                except (OSError, OverflowError) as exc:
                    self.samples[-1]['fdset_error'] = str(exc)
                    return False
                self.samples[-1]['stdin_fdset_hex'] = mask.hex()
                return (len(mask) == 8 and int.from_bytes(mask, 'little') == 1
                        and values[3] == values[4] == values[5] == 0)
            return False
        return self.until(reading, 3)

    def send(self, data):
        if self.poll() is not None:
            return False
        self.events.append({'direction': 'send', 'ns': time.monotonic_ns(), 'base64': b64(data)})
        os.write(self.master, data)
        return True

    def has(self, token, start=0, seconds=1.5):
        return self.until(lambda: token in self.raw[start:], seconds)

    def exit(self, seconds=2):
        return self.until(lambda: self.poll() is not None, seconds)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.pump(0)
        natural = self.poll()
        before_cleanup = termios.tcgetattr(self.slave)
        if natural is None:
            os.kill(self.pid, signal.SIGKILL)
            self.status = os.waitstatus_to_exitcode(os.waitpid(self.pid, 0)[1])
        self.pump(0)
        try:
            termios.tcsetattr(self.slave, termios.TCSANOW, self.initial)
            cleanup_restored = termios.tcgetattr(self.slave) == self.initial
        finally:
            os.close(self.master)
            os.close(self.slave)
        (Path.home() / 'pty.raw').write_bytes(self.raw)
        save('pty.json', {'pid': self.pid, 'events': self.events, 'readiness': self.samples,
                          'natural_status': natural, 'status_after_cleanup': self.status,
                          'initial_modes': serial_modes(self.initial),
                          'before_cleanup_modes': serial_modes(before_cleanup),
                          'terminal_restored_before_cleanup': before_cleanup == self.initial,
                          'cleanup_restored': cleanup_restored})


def pty_case(scenario, side, shell):
    tool = 'ed' if scenario.startswith('ed-') else 'bc'
    command = 'ed note' if tool == 'ed' else 'bc -q'
    argv = ['/usr/bin/' + tool] + (['note'] if tool == 'ed' else ['-q'])
    if side == 'candidate':
        argv = [shell, '--noprofile', '--norc', '-c', command]
    session = Pty(argv)
    checks = {}
    try:
        checks['program-reading-stdin'] = session.ready()
        if tool == 'ed':
            # A command with a visible result establishes that the append has
            # finished. Neither ed's startup byte count nor a delay is a gate.
            start = len(session.raw)
            session.send(b'a\rtwo\r.\r$p\r')
            checks['modified-buffer-ready'] = session.has(b'$p\r\ntwo\r\n', start)
            if scenario == 'ed-force':
                start = len(session.raw)
                checks['Q-sent'] = session.send(b'Q\r')
                ended = session.exit()
                checks['Q-unconditional-exit-zero'] = ended and session.status == 0
                checks['Q-no-warning'] = b'\r\n?\r\n' not in session.raw[start:]
            elif scenario == 'ed-eof':
                start = len(session.raw)
                checks['first-EOF-sent'] = session.send(b'\x04')
                checks['EOF-warns'] = session.has(b'?\r\n', start)
                checks['EOF-retains-editor'] = session.poll() is None and session.ready()
                checks['second-EOF-sent'] = session.send(b'\x04')
                ended = session.exit()
                checks['second-EOF-exit-two'] = ended and session.status == 2
            else:
                start = len(session.raw)
                session.send(b'q\r')
                checks['first-q-warns-and-retains-editor'] = (
                    session.has(b'\r\n?\r\n', start) and session.poll() is None)
                if scenario == 'ed-help':
                    start = len(session.raw)
                    checks['h-sent'] = session.send(b'h\r')
                    checks['h-explains-warning'] = session.has(b'Warning: buffer modified\r\n', start)
                elif scenario == 'ed-rearm':
                    start = len(session.raw)
                    checks['intervening-p-sent'] = session.send(b'p\r')
                    checks['intervening-p-prints-two'] = session.has(b'p\r\ntwo\r\n', start)
                    # GNU ed does not re-arm its warning for p alone (raw
                    # revision94). An actual intervening edit changes it.
                    start = len(session.raw)
                    checks['intervening-edit-sent'] = session.send(b'a\rthree\r.\r$p\r')
                    checks['intervening-edit-prints-three'] = session.has(b'$p\r\nthree\r\n', start)
                    start = len(session.raw)
                    checks['second-q-sent'] = session.send(b'q\r')
                    checks['intervening-command-rearms-warning'] = (
                        session.has(b'\r\n?\r\n', start) and session.poll() is None)
                else:
                    raise ValueError(scenario)
                # Always attempt the cleanup command, even when h/rearm failed.
                session.send(b'Q\r')
                session.exit()
            checks['file-unchanged'] = Path('note').read_bytes() == b'one\n'
        elif scenario == 'bc-quit':
            checks['quit-sent'] = session.send(b'quit\r')
            ended = session.exit(3)
            checks['quit-exit-zero-without-EOF'] = ended and session.status == 0
            checks['quit-restores-termios'] = ended and termios.tcgetattr(session.slave) == session.initial
        elif scenario in ('bc-render', 'bc-history'):
            if scenario == 'bc-render':
                modes = termios.tcgetattr(session.slave)
                checks['readline-noncanonical'] = not (modes[3] & termios.ICANON)
                checks['paste-enabled-before-input'] = b'\x1b[?2004h' in session.raw
                start = len(session.raw)
                checks['editing-keys-sent'] = session.send(b'20+21\x02\x042\r')
                checks['edited-expression-is-42-before-EOF'] = session.has(b'42\r\n', start)
                checks['next-line-reading'] = session.ready()
                checks['paste-disabled-after-line'] = b'\x1b[?2004l' in session.raw[start:]
                checks['paste-reenabled-for-next-line'] = b'\x1b[?2004h' in session.raw[start:]
            else:
                start = len(session.raw)
                checks['first-expression-sent'] = session.send(b'6*7\r')
                checks['first-expression-is-42-before-EOF'] = session.has(b'42\r\n', start)
                checks['ready-before-Up'] = session.ready()
                start = len(session.raw)
                checks['Up-and-enter-sent'] = session.send(b'\x1b[A\r')
                recalled = session.has(b'6*7', start)
                checks['history-renders-prior-expression'] = recalled
                second_result = session.has(b'42\r\n', start)
                # A late result from the original expression after Up cannot
                # establish reevaluation if recall itself was not observed.
                checks['history-reevaluates-42-before-EOF'] = recalled and second_result
            # Editing/history failures do not prevent this attempt. The
            # dedicated bc-quit case independently qualifies quit and termios.
            session.send(b'quit\r')
            session.exit(2)
        else:
            raise ValueError(scenario)
    finally:
        session.close()
        reap_adopted()
        if scenario == 'bc-render':
            Path('render.raw').write_bytes(session.raw)
        save('observations.json', checks)
    return report(checks)


def pty_control_child():
    """Native pselect control; never calls a candidate or reference tool."""
    fdset = (ctypes.c_ulong * 16)()
    fdset[0] = 1
    LIB.pselect.argtypes = [ctypes.c_int] + [ctypes.c_void_p] * 5
    LIB.pselect.restype = ctypes.c_int
    os.write(1, b'CONTROL_READY\n')
    ready = LIB.pselect(1, ctypes.byref(fdset), None, None, None, None)
    line = os.read(0, 128)
    if ready != 1 or line != b'control\n':
        return 1
    os.write(1, b'CONTROL_ACCEPTED\n')
    return 0


def pty_setup():
    """Validate stdin fd_set access before a behavioral PTY session."""
    session = Pty([PYTHON, SELF, 'pty-control-child'])
    checks = {}
    try:
        checks['native-pselect-fd0-readiness'] = session.ready()
        checks['control-input-sent'] = session.send(b'control\r')
        checks['native-pselect-accepted-input'] = session.has(b'CONTROL_ACCEPTED\r\n')
        checks['control-exit-zero'] = session.exit() and session.status == 0
        checks['control-termios-unchanged'] = termios.tcgetattr(session.slave) == session.initial
    finally:
        session.close()
        for name in ['pty.raw', 'pty.json']:
            (Path.home() / name).rename(Path.home() / ('setup-' + name))
        reap_adopted()
    save('setup-pty-observations.json', checks)
    return report(checks)


def producer(mode):
    rows = []
    def record(event, **values):
        rows.append(dict(event=event, ns=time.monotonic_ns(), **values))
        save('producer.json', rows)
    record('start', pid=os.getpid(), mode=mode, isatty=os.isatty(0))
    os.write(1, b'READY\n')
    if not select.select([0], [], [], 10)[0]:
        return 97
    command = os.read(0, 128)
    record('command', base64=b64(command))
    if mode == 'silent':
        return 0 if command == b'finish\n' else 96
    if mode != 'stream' or command != b'go\n':
        return 96
    end = time.monotonic() + 7
    tick = time.monotonic()
    while time.monotonic() < end:
        if select.select([0], [], [], max(0, tick - time.monotonic()))[0]:
            command = os.read(0, 128)
            record('stop', base64=b64(command))
            return 0 if command == b'stop\n' else 96
        os.write(1, b'x')
        record('emit')
        tick = time.monotonic() + .05
    record('hard-limit')
    return 98


def run_bounded(argv, prefix, timeout=15):
    start = time.monotonic_ns()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        out, err = proc.communicate(timeout=3)
    finally:
        reap_adopted()
    (Path.home() / (prefix + '.stdout')).write_bytes(out)
    (Path.home() / (prefix + '.stderr')).write_bytes(err)
    save(prefix + '.json', {'argv': argv, 'status': proc.returncode, 'timed_out': timed_out,
                           'elapsed_ns': time.monotonic_ns() - start})
    return proc.returncode, out, err, timed_out


def key_values(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)


def expect_case(scenario, side, shell):
    (Path.home() / 'expect.raw').write_bytes(b'')
    argv = (['/usr/bin/expect', '-f', scenario + '.exp'] if side == 'reference' else
            [shell, '--noprofile', '--norc', scenario + '.sh'])
    status, out, err, timed_out = run_bounded(argv, 'controller', 19)
    metrics_path = Path.home() / 'metrics'
    metrics = key_values(metrics_path) if metrics_path.is_file() else {}
    checks = {'controller-exit-zero': status == 0 and not timed_out,
              'controller-no-diagnostics': not out and not err,
              'ready-match': metrics.get('ready') == '0'}
    if scenario == 'expect-deadline':
        rows_path = Path.home() / 'producer.json'
        rows = json.loads(rows_path.read_text()) if rows_path.is_file() else []
        emissions = [r['ns'] for r in rows if r['event'] == 'emit']
        checks.update({
            'whole-wait-timeout-status-one': metrics.get('wait') == '1',
            'whole-wait-1.9-to-4-seconds': 1900 <= float(metrics.get('elapsed_ms', '-1')) < 4000,
            'producer-continuous-for-at-least-1.8-seconds': (
                len(emissions) >= 30 and (emissions[-1] - emissions[0]) >= 1_800_000_000
                and max(b - a for a, b in zip(emissions, emissions[1:])) < 500_000_000),
            'producer-stopped-by-command-after-wait': (
                bool(rows) and rows[-1]['event'] == 'stop' and rows[-1]['base64'] == b64(b'stop\n')
                and not any(r['event'] == 'hard-limit' for r in rows)),
            'close-zero': metrics.get('close') == '0'})
    elif scenario == 'expect-status':
        checks.update({'eof-live-timeout-one': metrics.get('eof_live') == '1',
                       'expect-live-timeout-one': metrics.get('expect_live') == '1',
                       'expect-EOF-status-two': metrics.get('wait') == '2',
                       'EOF-before-ten-second-deadline': 0 <= float(metrics.get('elapsed_ms', '-1')) < 3000,
                       'close-zero': metrics.get('close') == '0'})
    elif scenario == 'expect-eof':
        checks.update({'eof-EOF-status-zero': metrics.get('wait') == '0',
                       'EOF-before-ten-second-deadline': 0 <= float(metrics.get('elapsed_ms', '-1')) < 3000,
                       'close-zero': metrics.get('close') == '0'})
    else:
        raise ValueError(scenario)
    save('observations.json', {'metrics': metrics, 'checks': checks})
    return report(checks)


class Timespec(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_nsec', ctypes.c_long)]


def native_clock(mode):
    """Independent libc oracle: its returned error number supplies the text."""
    LIB.clock_nanosleep.argtypes = [ctypes.c_int, ctypes.c_int,
                                    ctypes.POINTER(Timespec), ctypes.c_void_p]
    LIB.clock_nanosleep.restype = ctypes.c_int
    request = Timespec(2, 0)
    if mode in ('USR1', 'INT'):
        number = getattr(signal, 'SIG' + mode)
        def caught(_number, _frame):
            os.write(1, ('handler=%s\n' % mode).encode())
        signal.signal(number, caught)
        signal.siginterrupt(number, True)
    ctypes.set_errno(errno.ENOTTY)  # demonstrably distinct from EINTR/EINVAL
    os.write(1, b'armed\n')
    start = time.monotonic_ns()
    returned = LIB.clock_nanosleep(1, 0, ctypes.byref(request), None)
    elapsed = time.monotonic_ns() - start
    preserved_errno = ctypes.get_errno()
    save('native.json', {'return_number': returned, 'errno_after': preserved_errno,
                         'errno_sentinel': errno.ENOTTY, 'elapsed_ns': elapsed,
                         'requested_ns': 2_000_000_000, 'mode': mode})
    if mode == 'EINVAL':
        # A raw syscall has the kernel errno convention. This proves the same
        # inherited filter really injects EINVAL, independent of libc's wrapper.
        ctypes.set_errno(0)
        raw = LIB.syscall(CLOCK_NANOSLEEP, 1, 0, ctypes.byref(request), 0)
        raw_errno = ctypes.get_errno()
        save('errno-control.json', {'raw_return': raw, 'raw_errno': raw_errno,
                                    'libc_return': returned, 'libc_errno': preserved_errno})
    rc = 0 if returned == 0 else 1
    if returned not in (0, errno.EINTR):
        os.write(2, ('bashclock: clock_nanosleep: %s\n' % os.strerror(returned)).encode())
    os.write(1, ('sleep-status=%d\nshell-continued\n' % rc).encode())
    return 0


def clock_argv(mode, side, shell):
    if side == 'reference':
        argv = [PYTHON, SELF, 'native-clock', mode]
    else:
        argv = [shell, '--noprofile', '--norc', 'clock-' + mode + '.sh']
    if mode == 'EINVAL':
        argv = [PYTHON, SECCOMP, '--errno', 'clock_nanosleep:EINVAL', '--'] + argv
    return argv


def clock_observe(mode, side, shell, prefix):
    argv = clock_argv(mode, side, shell)
    if mode == 'EINVAL':
        status, out, err, timed_out = run_bounded(argv, prefix, 5)
        duration = json.loads((Path.home() / (prefix + '.json')).read_text())['elapsed_ns']
        return {'status': status, 'out': out, 'err': err, 'timed_out': timed_out,
                'elapsed_ns': duration, 'signal_sent': False}
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    samples = []
    first = sent_at = None
    timed_out = False
    end = time.monotonic() + 4
    try:
        last = None
        while proc.poll() is None and time.monotonic() < end:
            raw, values = syscall_sample(proc.pid)
            now = time.monotonic_ns()
            if raw != last:
                samples.append({'ns': now, 'syscall': raw})
                last = raw
            in_sleep = len(values) > 2 and values[:3] == [CLOCK_NANOSLEEP, 1, 0]
            if in_sleep and first is None:
                first = now
            if in_sleep and first is not None and now - first >= 250_000_000:
                # Record the still-blocked syscall at the causal signal point.
                samples.append({'ns': now, 'syscall': raw, 'signal': mode})
                os.kill(proc.pid, getattr(signal, 'SIG' + mode))
                sent_at = now
                break
            time.sleep(.005)
        try:
            out, err = proc.communicate(timeout=2.5)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out, err = proc.communicate(timeout=2)
        completed = time.monotonic_ns()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=2)
        reap_adopted()
    result = {'status': proc.returncode, 'out': out, 'err': err, 'timed_out': timed_out,
              'elapsed_ns': None if first is None else completed - first,
              'signal_sent': sent_at is not None}
    (Path.home() / (prefix + '.stdout')).write_bytes(out)
    (Path.home() / (prefix + '.stderr')).write_bytes(err)
    save(prefix + '.json', {k: v for k, v in result.items() if k not in ('out', 'err')} |
         {'argv': argv, 'samples': samples, 'signal_ns': sent_at})
    return result


def clock_checks(mode, result):
    expected_out = b'armed\n'
    if mode != 'EINVAL':
        expected_out += ('handler=%s\n' % mode).encode()
    expected_out += b'sleep-status=1\nshell-continued\n'
    checks = {'clock-controller-exit-zero': result['status'] == 0 and not result['timed_out'],
              'sleep-returned-failure-one': b'sleep-status=1\n' in result['out'],
              'shell-continued': result['out'].endswith(b'shell-continued\n'),
              'clock-stdout-exact': result['out'] == expected_out}
    if mode == 'EINVAL':
        checks['diagnostic-is-EINVAL-text'] = bool(re.fullmatch(
            rb'(?:[^\n]*: )?bashclock: clock_nanosleep: Invalid argument\n', result['err']))
        checks['error-before-one-second'] = result['elapsed_ns'] < 1_000_000_000
    else:
        checks.update({'signal-after-observed-clock-nanosleep': result['signal_sent'],
                       'handler-once': result['out'].count(('handler=%s\n' % mode).encode()) == 1,
                       'interrupted-in-0.2-to-1.5-seconds': (
                           result['elapsed_ns'] is not None and 200_000_000 <= result['elapsed_ns'] < 1_500_000_000),
                       'EINTR-no-diagnostic': result['err'] == b''})
    return checks


def clock_setup(mode):
    result = clock_observe(mode, 'reference', '/bin/bash', 'setup-control')
    checks = clock_checks(mode, result)
    native = json.loads((Path.home() / 'native.json').read_text())
    expected = errno.EINVAL if mode == 'EINVAL' else errno.EINTR
    checks['libc-returns-error-number-with-unchanged-errno'] = (
        native['return_number'] == expected and native['errno_after'] == errno.ENOTTY)
    if mode == 'EINVAL':
        raw = json.loads((Path.home() / 'errno-control.json').read_text())
        checks['raw-syscall-returns-minus-one-EINVAL'] = raw['raw_return'] == -1 and raw['raw_errno'] == errno.EINVAL
        checks['error-returned-before-requested-sleep'] = native['elapsed_ns'] < 500_000_000
    save('setup-observations.json', checks)
    (Path.home() / 'setup-native.json').write_text((Path.home() / 'native.json').read_text())
    return report(checks)


def clock_case(mode, side, shell):
    result = clock_observe(mode, side, shell, 'clock')
    checks = clock_checks(mode, result)
    save('observations.json', checks)
    return report(checks)


def main():
    require_guest()
    action, *args = sys.argv[1:]
    if action == 'pty':
        return pty_case(*args)
    if action == 'pty-setup':
        return pty_setup()
    if action == 'pty-control-child':
        return pty_control_child()
    if action == 'producer':
        return producer(*args)
    if action == 'expect':
        return expect_case(*args)
    if action == 'native-clock':
        return native_clock(*args)
    if action == 'clock-setup':
        return clock_setup(*args)
    if action == 'clock':
        return clock_case(*args)
    raise ValueError(action)


if __name__ == '__main__':
    sys.exit(main())
