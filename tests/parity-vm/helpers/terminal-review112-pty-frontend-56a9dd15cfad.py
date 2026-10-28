#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only screen frontend observations on one or two private PTYs."""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import tty
import uuid

HOME = Path('/tmp/parity-home')
SELF = '/opt/bashos-parity/harness/helpers/terminal-review112-pty-frontend-56a9dd15cfad.py'
HISTORY = b'old\x00\xff\x1b[6n\nraw\x80'
LIVE = b'NEW\x00\xfe\x1b[31m!\n'
QUERY = b'\x1b[6n'
REPLY = b'\x1b[1;1R'
END = b'FRONTEND-END:0\r\n'


def marker(name, data):
    target = HOME / name
    temp = HOME / (name + '.tmp')
    temp.write_bytes(data)
    os.replace(temp, target)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError('short PTY write')
        view = view[count:]


def child():
    tty.setraw(0)
    marker('frontend-child-input', b'')
    marker('frontend-child-pid', ('%d\n' % os.getpid()).encode())
    write_all(1, HISTORY)
    marker('frontend-child-ready', b'1\n')
    input_data = bytearray()
    emitted = False
    deadline = time.monotonic() + 28
    while time.monotonic() < deadline:
        if not emitted and (HOME / 'frontend-release').is_file():
            write_all(1, LIVE)
            marker('frontend-child-live', b'1\n')
            emitted = True
        ready, _, _ = select.select([0], [], [], .05)
        if ready:
            data = os.read(0, 4096)
            if not data:
                break
            input_data.extend(data)
            marker('frontend-child-input', bytes(input_data))


class Frontend:
    def __init__(self, shell, env, label, observer=False, answer_query=False):
        self.label, self.answer_query = label, answer_query
        self.answer_sent = False
        self.data = bytearray()
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        attrs = termios.tcgetattr(self.slave)
        attrs[1] |= termios.OPOST | termios.ONLCR
        attrs[3] |= termios.ECHO | termios.ICANON | termios.ISIG
        termios.tcsetattr(self.slave, termios.TCSANOW, attrs)
        self.before = copy.deepcopy(termios.tcgetattr(self.slave))
        script = ('screen attach live ' + ('-x' if observer else '-r') +
                  '; rc=$?; printf "FRONTEND-END:%s\\n" "$rc"; exit "$rc"')
        def session():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script],
            stdin=self.slave, stdout=self.slave, stderr=self.slave, env=env, preexec_fn=session)

    def pump(self, delay=.05):
        ready, _, _ = select.select([self.master], [], [], delay)
        if ready:
            try:
                data = os.read(self.master, 8192)
            except OSError:
                data = b''
            self.data.extend(data)
            if len(self.data) > 65536:
                raise RuntimeError('frontend capture limit')
            if self.answer_query and not self.answer_sent and QUERY in self.data:
                write_all(self.master, REPLY)
                self.answer_sent = True

    def send(self, data):
        write_all(self.master, data)

    def raw_mode(self):
        attrs = termios.tcgetattr(self.slave)
        return not (attrs[3] & (termios.ECHO | termios.ICANON))

    def restored(self):
        return termios.tcgetattr(self.slave) == self.before

    def finish(self):
        end = time.monotonic() + 5
        while self.proc.poll() is None and time.monotonic() < end:
            self.pump(.03)
        if self.proc.poll() is None:
            return False
        for _ in range(4):
            self.pump(.03)
        return self.proc.returncode == 0

    def close(self):
        forced = self.proc.poll() is None
        if forced:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        marker('frontend-' + self.label + '.raw', bytes(self.data))
        os.close(self.master)
        os.close(self.slave)
        return not forced


def wait_for(predicate, seconds=5, frontends=()):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for frontend in frontends:
            frontend.pump(.01)
        if predicate():
            return True
        time.sleep(.02)
    return bool(predicate())


def observe(scenario, shell):
    env = dict(os.environ, BASHSCREEN_STATE_DIR=str(HOME / 'screen-state'),
               PYTHONDONTWRITEBYTECODE='1')
    Path(env['BASHSCREEN_STATE_DIR']).mkdir(mode=0o700)
    events = []
    checks = []
    frontends = []
    started = False
    cleanup_ok = False

    def check(name, ok, detail=None):
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})
        print(name + ('=PASS' if ok else '=FAIL'), flush=True)

    def call(label, *words):
        proc = subprocess.run([shell, '--noprofile', '--norc', '-c', 'screen "$@"',
                               'frontend-fixture', *words], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=7)
        events.append({'label': label, 'args': list(words), 'status': proc.returncode,
                       'stdout_base64': base64.b64encode(proc.stdout[:16384]).decode(),
                       'stderr_base64': base64.b64encode(proc.stderr[:16384]).decode()})
        return proc

    def status(controller, observers):
        result = call('relay-status', 'relay-status', 'live')
        out = result.stdout.decode(errors='replace')
        return (result.returncode == 0 and 'running 1\n' in out and
                ('controller %d\n' % controller) in out and
                ('observers %d\n' % observers) in out)

    def input_is(data):
        path = HOME / 'frontend-child-input'
        return path.is_file() and path.read_bytes() == data

    try:
        create = call('create', 'run', '-n', 'live', '-d', '--', '/usr/bin/python3', SELF, 'child')
        started = create.returncode == 0
        if not started or not wait_for(lambda: (HOME / 'frontend-child-ready').is_file()):
            raise RuntimeError('session or owned child did not become ready')
        def have_history():
            result = call('capture-control', 'capture-pane', 'live')
            return result.returncode == 0 and result.stdout == HISTORY
        history_ok = wait_for(have_history)
        check('history-control' if scenario == 'attach' else 'captured-raw-history' if scenario == 'capture' else 'history-ready', history_ok)
        if not history_ok:
            raise RuntimeError('history control unavailable')
        controller = Frontend(shell, env, 'controller', answer_query=scenario == 'capture')
        frontends.append(controller)
        if scenario == 'roles':
            observer = Frontend(shell, env, 'observer', observer=True)
            frontends.append(observer)
        wanted = 1 if scenario == 'roles' else 0
        ready = wait_for(lambda: status(1, wanted) and all(f.raw_mode() for f in frontends),
                         frontends=frontends)
        check('both-frontends-ready' if scenario == 'roles' else 'frontend-ready', ready)
        if not ready:
            raise RuntimeError('frontend attach did not become ready')
        marker('frontend-release', b'1\n')
        live = wait_for(lambda: all(LIVE in f.data for f in frontends), frontends=frontends)
        if scenario == 'attach':
            check('live-binary-bytes', live and bytes(controller.data) == LIVE)
            controller.send(b'\x01\x01')
            check('quoted-prefix-reaches-child', wait_for(lambda: input_is(b'\x01'), frontends=frontends))
            controller.send(b'\x01d')
            detached = controller.finish()
            check('detach-keeps-session-live', detached and wait_for(lambda: status(0, 0), seconds=3))
            check('terminal-restored', controller.restored() and bytes(controller.data) == LIVE + END)
        elif scenario == 'capture':
            check('late-attach-no-query-replay', live and bytes(controller.data) == LIVE and not controller.answer_sent)
            controller.send(b'Z')
            input_ok = wait_for(lambda: input_is(b'Z'), frontends=frontends)
            # Keep pumping long enough to answer any delayed replay of the query.
            end = time.monotonic() + .4
            while time.monotonic() < end:
                controller.pump(.03)
            check('no-query-reply-reaches-child', input_ok and input_is(b'Z') and not controller.answer_sent)
            check('live-input-control', input_ok)
            controller.send(b'\x01d')
            detached = controller.finish()
            check('detach-and-terminal-restored', detached and controller.restored() and bytes(controller.data) == LIVE + END)
        else:
            check('identical-live-bytes', live and all(bytes(f.data) == LIVE for f in frontends))
            observer.send(b'O')
            end = time.monotonic() + .5
            while time.monotonic() < end:
                for f in frontends:
                    f.pump(.02)
            controller.send(b'C')
            input_ok = wait_for(lambda: input_is(b'C'), frontends=frontends)
            check('observer-input-suppressed', input_ok and input_is(b'C'))
            observer.send(b'\x01d')
            observer_done = observer.finish()
            check('observer-disconnect-keeps-pane', observer_done and wait_for(lambda: status(1, 0), seconds=3))
            controller.send(b'\x01d')
            controller_done = controller.finish()
            check('controller-disconnect-keeps-pane', controller_done and wait_for(lambda: status(0, 0), seconds=3))
            check('both-terminals-restored', all(f.restored() and bytes(f.data) == LIVE + END for f in frontends))
    except Exception as exc:
        events.append({'exception': '%s: %s' % (type(exc).__name__, exc)})
        check('fixture-completed', False, str(exc))
    finally:
        frontend_cleanup = all([f.close() for f in frontends])
        if started:
            try:
                stopped = call('cleanup', 'kill', 'live')
                cleanup_ok = stopped.returncode == 0 and not (Path(env['BASHSCREEN_STATE_DIR']) / 'live').exists()
            except Exception as exc:
                events.append({'cleanup_exception': '%s: %s' % (type(exc).__name__, exc)})
        check('cleanup', started and cleanup_ok and frontend_cleanup)
        marker('frontend-events.json', (json.dumps({'scenario': scenario, 'checks': checks,
               'events': events}, indent=2, sort_keys=True) + '\n').encode())
    return 0 if checks and all(item['ok'] for item in checks) else 1


def control():
    master, slave = os.openpty()
    try:
        before = termios.tcgetattr(slave)
        tty.setraw(slave)
        raw = termios.tcgetattr(slave)
        assert not (raw[3] & (termios.ICANON | termios.ECHO))
        termios.tcsetattr(slave, termios.TCSANOW, before)
        assert termios.tcgetattr(slave) == before
        assert QUERY in HISTORY and QUERY not in LIVE and len(REPLY) > 0
    finally:
        os.close(master)
        os.close(slave)


if __name__ == '__main__':
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if os.geteuid() != 2000:
        raise SystemExit('fixture requires the unprivileged disposable VM user')
    args = sys.argv[1:]
    if args == ['child']:
        child()
    elif args == ['control']:
        control()
    elif len(args) == 3 and args[0] == 'observe' and args[1] in ('attach', 'capture', 'roles'):
        raise SystemExit(observe(args[1], args[2]))
    else:
        raise SystemExit('invalid fixture arguments')
