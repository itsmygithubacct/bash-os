#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only observations of private PTY/session syscalls; never run on a host.

The reference participant uses Python's OS interfaces; the candidate
participant invokes the Bash pty builtin.  The parent checks /proc and ioctl
state while each participant is stopped at a two-way socket handshake.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import termios


REFERENCE = r'''
import errno, fcntl, os, socket, sys, termios
mode = sys.argv[1]
target = sys.argv[2]
control = socket.socket(fileno=int(os.environ['CONTROL_FD']))
control.sendall(b'PRE\n')
control.recv(1)
sidrc = 0
fd = -1
if mode in ('setsid', 'stdio', 'fdvar'):
    try:
        os.setsid()
    except OSError:
        sidrc = 1
if mode == 'setsid':
    try:
        os.setsid()
        rc = 0
    except OSError as exc:
        rc = int(exc.errno == errno.EPERM)
        rc = 1 if rc else 99
else:
    try:
        fd = os.open(target, os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
        if mode != 'fdvar':
            for n in range(3):
                os.dup2(fd, n)
            if fd > 2:
                os.close(fd)
            fd = -1
        rc = 0
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
            fd = -1
        rc = 1 if exc.errno == errno.EPERM else 99
control.sendall(('DONE %d %d %d\n' % (sidrc, rc, fd)).encode())
control.recv(1)
'''

CANDIDATE = r'''
control=$CONTROL_FD
printf 'PRE\n' >&"$control"
IFS= read -r -n 1 _ <&"$control"
sidrc=0
if [[ $MODE == setsid || $MODE == stdio || $MODE == fdvar ]]; then
  pty setsid || sidrc=$?
fi
fd=-1
if [[ $MODE == setsid ]]; then
  pty setsid 2>/dev/null; rc=$?
elif [[ $MODE == fdvar ]]; then
  pty open-tty "$TARGET" fd; rc=$?
else
  pty open-tty "$TARGET"; rc=$?
fi
printf 'DONE %s %s %s\n' "$sidrc" "$rc" "$fd" >&"$control"
IFS= read -r -n 1 _ <&"$control"
'''


def identity(pid, fd):
    s = os.stat('/proc/%d/fd/%d' % (pid, fd))
    return [s.st_dev, s.st_ino, s.st_rdev]


def stat_fields(pid):
    text = Path('/proc/%d/stat' % pid).read_text()
    return text[text.rindex(')') + 2:].split()


def tty_matches(tty_nr, slave):
    # /proc's tty_nr is the Linux encoded device number; match the exact
    # private slave, even though this observer has no controlling terminal.
    device = tty_nr & 0xffffffff
    actual = os.fstat(slave).st_rdev
    return os.major(device) == os.major(actual) and os.minor(device) == os.minor(actual)


def run(mode, side, shell):
    observations = {'scenario': mode, 'side': side, 'checks': [], 'raw': {}}

    def check(name, condition, detail=None):
        observations['checks'].append({'name': name, 'ok': bool(condition), 'detail': detail})
        print(name + ('=PASS' if condition else '=FAIL'), flush=True)

    master, slave = os.openpty()
    original_master = original_slave = None
    parent, child = socket.socketpair()
    parent.settimeout(4)
    target = os.ttyname(slave)
    env = dict(os.environ, CONTROL_FD=str(child.fileno()), TARGET=target, MODE=mode)
    use_existing_ctty = mode == 'reject-leader'
    if use_existing_ctty:
        original_master, original_slave = os.openpty()

    def attach_existing():
        os.setsid()
        fcntl.ioctl(original_slave, termios.TIOCSCTTY, 0)

    args = ([shell, '--noprofile', '--norc', '-c', CANDIDATE] if side == 'candidate'
            else ['/usr/bin/python3', '-c', REFERENCE, mode, target])
    inherited = [child.fileno()]
    if original_slave is not None:
        inherited.append(original_slave)
    proc = None
    try:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, pass_fds=tuple(inherited),
                                preexec_fn=attach_existing if use_existing_ctty else None)
        child.close()
        control = parent.makefile('rb', buffering=0)
        pre = control.readline(256)
        if pre != b'PRE\n':
            raise RuntimeError('missing PRE handshake: %r' % pre)
        before = [identity(proc.pid, n) for n in range(3)]
        before_sid = os.getsid(proc.pid)
        before_tty = int(stat_fields(proc.pid)[4])
        parent.sendall(b'G')
        line = control.readline(256)
        match = re.fullmatch(rb'DONE ([0-9]+) ([0-9]+) (-?[0-9]+)\n', line)
        if not match:
            raise RuntimeError('missing DONE handshake: %r' % line)
        sidrc, rc, fd = map(int, match.groups())
        after = [identity(proc.pid, n) for n in range(3)]
        after_sid = os.getsid(proc.pid)
        after_pgrp = os.getpgid(proc.pid)
        after_tty = int(stat_fields(proc.pid)[4])
        observations['raw'].update(pid=proc.pid, target=target, before=before, after=after,
                                   before_sid=before_sid, after_sid=after_sid,
                                   pgrp=after_pgrp, before_tty=before_tty, after_tty=after_tty,
                                   sidrc=sidrc, rc=rc, fd=fd)
        if mode == 'setsid':
            check('setsid-new-session', sidrc == 0 and after_sid == proc.pid
                  and after_pgrp == proc.pid and after_tty == 0)
            check('setsid-leader-eperm', rc == 1)
        elif mode in ('stdio', 'fdvar'):
            try:
                # On Linux a PTY master may inspect its slave's foreground
                # group even when the observer is outside that session.
                fg = os.tcgetpgrp(master) if sidrc == 0 and rc == 0 else -1
            except OSError:
                fg = -1
            observations['raw'].update(foreground_group=fg)
            check('acquired-controlling-tty', sidrc == 0 and rc == 0 and after_sid == proc.pid
                  and after_tty != 0 and tty_matches(after_tty, slave) and fg == proc.pid)
            target_identity_error = None
            try:
                target_identity = identity(proc.pid, 0 if mode == 'stdio' else fd) if rc == 0 and (mode == 'stdio' or fd >= 0) else None
            except OSError as exc:
                target_identity = None
                target_identity_error = '%s: %s' % (type(exc).__name__, exc)
            slave_stat = os.fstat(slave)
            expected = [slave_stat.st_dev, slave_stat.st_ino, slave_stat.st_rdev]
            observations['raw'].update(returned_fd_identity=target_identity,
                                       returned_fd_identity_error=target_identity_error,
                                       identity_order=['device', 'inode', 'rdev'],
                                       slave_identity=expected,
                                       slave_tty_name=os.ttyname(slave))
            if mode == 'stdio':
                check('stdio-three-slave-descriptors', after == [expected] * 3)
            else:
                check('fdvar-descriptor-and-stdio', fd >= 3 and target_identity == expected and after == before)
        else:
            check('refusal-nonzero', rc != 0)
            check('refusal-stdio-unchanged', before == after)
            if mode == 'reject-leader':
                check('refusal-precondition-ctty', before_sid == proc.pid and before_tty != 0
                      and tty_matches(before_tty, original_slave))
            else:
                check('refusal-precondition-not-leader', before_sid != proc.pid)
        parent.sendall(b'G')
        out, err = proc.communicate(timeout=4)
        observations['raw']['stdout_hex'] = out[:16384].hex()
        observations['raw']['stderr_hex'] = err[:16384].hex()
        observations['raw']['participant_status'] = proc.returncode
        check('participant-exited', proc.returncode == 0)
    except Exception as exc:
        observations['exception'] = '%s: %s' % (type(exc).__name__, exc)
        check('fixture-completed', False, observations['exception'])
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=4)
        parent.close()
        child.close()
        os.close(master)
        os.close(slave)
        if original_master is not None:
            os.close(original_master)
            os.close(original_slave)
        Path(os.environ['HOME'], 'session-observation.json').write_text(
            json.dumps(observations, indent=2, sort_keys=True) + '\n')
    return 0 if observations['checks'] and all(item['ok'] for item in observations['checks']) else 1


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
    if len(sys.argv) != 4 or sys.argv[1] not in ('setsid', 'stdio', 'fdvar', 'reject-leader', 'reject-nonleader') or sys.argv[2] not in ('reference', 'candidate'):
        raise SystemExit('invalid fixture arguments')
    raise SystemExit(run(*sys.argv[1:]))
