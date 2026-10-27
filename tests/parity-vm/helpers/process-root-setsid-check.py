#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only setsid observations using gated, directly owned processes and PTYs.

The reference shell execs util-linux setsid: its PID and group role therefore
remain those of the invoking shell, as they do for the candidate builtin.
Raw process identifiers are evidence; only semantic relations are compared.
"""
import array
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import termios
import time

SELF = str(Path(__file__).resolve())
PYTHON = '/usr/bin/python3'


def state():
    result = {'pid': os.getpid(), 'pgid': os.getpgrp(), 'sid': os.getsid(0),
              'stdin_tty': os.isatty(0)}
    try:
        fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
        try:
            sessions = []
            for terminal in (0, fd):
                value = array.array('i', [0])
                fcntl.ioctl(terminal, getattr(termios, 'TIOCGSID', 0x5429), value, True)
                sessions.append(value[0])
            result['ctty_matches_stdin'] = sessions == [result['sid']] * 2
            result['ctty_foreground'] = os.tcgetpgrp(fd) == result['pgid']
        finally:
            os.close(fd)
    except OSError as error:
        result['ctty_error'] = error.errno
    return result


def report(fd, value):
    os.write(fd, (json.dumps(value, sort_keys=True) + '\n').encode())


def read_report(fd, limit=5):
    data = b''
    deadline = time.monotonic() + limit
    while b'\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError('owned child readiness deadline')
        chunk = os.read(fd, 4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.split(b'\n', 1)[0])


def child(gate, ready):
    report(ready, state())
    os.close(ready)
    assert os.read(gate, 1) == b'G'
    os.close(gate)
    return 7


def keeper(slave, gate, ready):
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    report(ready, {'pid': os.getpid(), 'sid': os.getsid(0), 'pgid': os.getpgrp()})
    os.close(ready)
    assert os.read(gate, 1) == b'G'
    return 0


def primitive(mode, flag, gate, ready):
    """Trusted setup control using Python kernel calls, never the candidate."""
    do_fork = mode == 'ctty' or flag != 'default' or os.getpgrp() == os.getpid()
    if do_fork:
        pid = os.fork()
        if pid:
            if mode == 'ctty':
                return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            return 0
    try:
        os.setsid()
        if mode == 'ctty':
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError as error:
        os.write(2, ('primitive errno=%d\n' % error.errno).encode())
        return 1
    return child(gate, ready)


def yes(value):
    return 'yes' if value else 'no'


def observe(side, shell, mode, role, flag):
    lib = ctypes.CDLL(None, use_errno=True)
    assert lib.prctl(36, 1, 0, 0, 0) == 0, ctypes.get_errno()  # child subreaper
    descriptors, owner, invoker, owner_gate, child_pid = [], None, None, None, None
    observed = {'side': side, 'mode': mode, 'role': role, 'flag': flag}
    log = Path(os.environ['HOME']) / 'setsid-observed.json'

    def pipe():
        pair = os.pipe()
        descriptors.extend(pair)
        return pair

    def close(fd):
        if fd in descriptors:
            os.close(fd)
            descriptors.remove(fd)

    try:
        stdin = subprocess.DEVNULL
        if mode == 'ctty' and role in ('free', 'owned'):
            master, slave = os.openpty()
            descriptors.extend((master, slave))
            stdin = slave
            observed['pty_name'] = os.ttyname(slave)
            if role == 'owned':
                kr, owner_gate = pipe()
                rr, rw = pipe()
                owner = subprocess.Popen([PYTHON, SELF, '--keeper', str(slave), str(kr), str(rw)],
                                         pass_fds=(slave, kr, rw), stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                close(kr)
                close(rw)
                observed['keeper'] = read_report(rr)
                close(rr)
                assert observed['keeper']['pid'] == owner.pid
                assert os.getsid(owner.pid) == owner.pid
        invoke_r, invoke_w = pipe()
        child_r, child_w = pipe()
        ready_r, ready_w = pipe()
        child_command = [PYTHON, SELF, '--child', str(child_r), str(ready_w)]
        if side == 'control':
            command = ['exec', PYTHON, SELF, '--primitive', mode, flag,
                       str(child_r), str(ready_w)]
        else:
            command = (['setsid'] if side == 'candidate' else ['exec', '/usr/bin/setsid'])
            if mode == 'ctty':
                command += ['-w', flag]
            elif flag != 'default':
                command += [flag]
            command += child_command
        script = 'IFS= read -r token <&%d || exit 91\n%s\n' % (invoke_r, shlex.join(command))
        leader = mode == 'ctty' or role == 'leader'
        invoker = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script],
                                   stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(invoke_r, child_r, ready_w),
                                   preexec_fn=(lambda: os.setpgid(0, 0)) if leader else None)
        observed['invoker'] = {'pid': invoker.pid, 'pgid': os.getpgid(invoker.pid),
                               'sid': os.getsid(invoker.pid)}
        assert (observed['invoker']['pgid'] == invoker.pid) == leader
        for fd in (invoke_r, child_r, ready_w):
            close(fd)
        os.write(invoke_w, b'G\n')
        close(invoke_w)
        got = read_report(ready_r)
        close(ready_r)
        observed['child'] = got
        if got:
            child_pid = got['pid']
            # The child cannot exit until this supervisor opens its gate.
            deadline = time.monotonic() + 0.5
            while invoker.poll() is None and time.monotonic() < deadline:
                time.sleep(0.005)
            observed['returned_before_release'] = invoker.poll() is not None
            observed['child_before_release'] = {'pgid': os.getpgid(child_pid),
                                                'sid': os.getsid(child_pid)}
            os.write(child_w, b'G')
        close(child_w)
        out, error = invoker.communicate(timeout=5)
        observed.update(status=invoker.returncode, stdout=out.decode('utf-8', 'backslashreplace'),
                        stderr=error.decode('utf-8', 'backslashreplace'))
        if got:
            if mode == 'ctty' or child_pid == invoker.pid:
                # In -w mode the invocation itself owns and reaps its child;
                # the observed return is its reported wait status.
                child_status = invoker.returncode
            else:
                deadline = time.monotonic() + 5
                while True:
                    pid, status = os.waitpid(child_pid, os.WNOHANG)
                    if pid:
                        child_status = os.waitstatus_to_exitcode(status)
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError('owned orphan reaping deadline')
                    time.sleep(0.005)
            observed['child_status'] = child_status
            assert not Path('/proc/%d' % child_pid).exists(), 'owned child not reaped'
        if owner:
            os.write(owner_gate, b'G')
            close(owner_gate)
            _, owner_error = owner.communicate(timeout=5)
            assert owner.returncode == 0 and not owner_error
        lines = []
        if mode == 'fork':
            lines += ['caller group leader ' + yes(leader),
                      'helper executed ' + yes(got is not None)]
            if got:
                lines += ['new session leader ' + yes(got['pid'] == got['pgid'] == got['sid']),
                          'fork ' + yes(child_pid != invoker.pid),
                          'returned before release ' + yes(observed['returned_before_release']),
                          'child status %d' % observed['child_status']]
        else:
            lines += ['helper executed ' + yes(got is not None)]
            if got:
                lines += ['new session leader ' + yes(got['pid'] == got['pgid'] == got['sid']),
                          'stdin is tty ' + yes(got['stdin_tty']),
                          'ctty matches stdin ' + yes(got.get('ctty_matches_stdin', False)),
                          'ctty foreground ' + yes(got.get('ctty_foreground', False)),
                          'child status %d' % observed['child_status']]
        lines += ['invocation status %d' % observed['status'], 'owned children reaped']
        if side == 'control':
            if mode == 'fork':
                expected_fork = leader or flag != 'default'
                assert got and got['pid'] == got['pgid'] == got['sid']
                assert (child_pid != invoker.pid) == expected_fork
                assert observed['returned_before_release'] == expected_fork
                assert observed['status'] == (0 if expected_fork else 7)
                assert observed['child_status'] == 7 and not error and not out
            elif role == 'free':
                assert got and got['ctty_matches_stdin'] and got['ctty_foreground']
                assert observed['status'] == observed['child_status'] == 7 and not error and not out
            else:
                code = errno.EPERM if role == 'owned' else errno.ENOTTY
                assert got is None and observed['status'] == 1
                assert error == ('primitive errno=%d\n' % code).encode() and not out
            print('setsid mechanism control verified')
        else:
            print('\n'.join(lines))
            sys.stdout.flush()
            os.write(1, out)
            os.write(2, error)
    finally:
        log.write_text(json.dumps(observed, indent=2) + '\n')
        for fd in descriptors:
            os.close(fd)
        for process in (invoker, owner):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        if child_pid and invoker and child_pid != invoker.pid:
            try:
                pending, _ = os.waitpid(child_pid, os.WNOHANG)
                if not pending:
                    os.kill(child_pid, signal.SIGKILL)
                    os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass


def main():
    args = sys.argv[1:]
    if args[0] == '--child':
        return child(*map(int, args[1:]))
    if args[0] == '--keeper':
        return keeper(*map(int, args[1:]))
    if args[0] == '--primitive':
        return primitive(args[1], args[2], int(args[3]), int(args[4]))
    side, shell, mode, role, flag = args
    assert side in ('candidate', 'reference', 'control')
    observe(side, shell, mode, role, flag)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
