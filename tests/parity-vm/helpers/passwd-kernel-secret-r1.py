#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Root-guest passwd controls against the real secret-slot module.

The secret device admits only init-namespace root, so these cases run passwd
as uid 0 over private PHCLIB_* account files with
BASHPASSWD_REQUIRE_KERNEL_SECRETS=1. The module, its pins, the guest guard,
the load/remove cycle and the kernel-log gate are those of
auth-stage1-fixture.py; nothing is pinned a second time here.

Every candidate invocation runs under the seccomp user-notification listener
and every notified call continues to Linux, so the recorded opens of the
device and the secret-slot ioctls are real kernel calls. Each case first makes
the same kind of request while the module is absent and requires a refusal
that leaves the account file untouched: success with the module loaded is
therefore not the memory-backed path.

Usage (guest only):
  passwd-kernel-secret-r1.py race CANDIDATE none|set|lock|aba
  passwd-kernel-secret-r1.py interrupt CANDIDATE set-new|set-retype|change-current
  passwd-kernel-secret-r1.py trace LABEL CANDIDATE [ARG...]   (internal)
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import termios
import time

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
HELPERS = Path('/opt/bashos-parity/harness/helpers')
CANDIDATE = '/opt/bashos-parity/candidate'
SELF = HELPERS / 'passwd-kernel-secret-r1.py'
# _IOWR/_IOW(0xBA, nr, size) from the published UAPI: NEW_SECRET, WRITE_SECRET,
# SEAL_SECRET, CLEAR_SECRET, EXPORT_SECRET_ONCE.
NEW, WRITE, SEAL, CLEAR, EXPORT = 0xc008ba02, 0x4010ba03, 0x4008ba04, 0x4008ba05, 0xc010ba06
COMPLETE = {NEW, WRITE, SEAL, CLEAR, EXPORT}
BUDGET = 34          # seconds of candidate work; the module is removed inside the case limit
STARTED = time.monotonic()


def stage1():
    spec = importlib.util.spec_from_file_location('stage1_fixture', HELPERS / 'auth-stage1-fixture.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FX = stage1()
require = FX.require


def left(limit):
    return max(.05, min(limit, STARTED + BUDGET - time.monotonic()))


def record(kind, **values):
    with (HOME / 'kernel-secret-observations.jsonl').open('a') as log:
        log.write(json.dumps({'kind': kind, **values}, sort_keys=True) + '\n')


def traced(label, script):
    return ['/usr/bin/python3', str(SELF), 'trace', label, CANDIDATE, '--noprofile', '--norc', '-c', script]


def trace():
    FX.guard()
    require(len(sys.argv) >= 5 and re.fullmatch(r'[a-z][a-z0-9-]{0,31}', sys.argv[2]) and
            sys.argv[3] == CANDIDATE, 'approved trace program required')
    label = sys.argv[2]
    # A terminal interrupt belongs to the candidate. A Python-level handler is
    # reset to the default disposition by execve, unlike SIG_IGN.
    signal.signal(signal.SIGINT, lambda *unused: None)
    spec = importlib.util.spec_from_file_location('secret_listener', HELPERS / 'auth-client-listener.py')
    listener = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(listener)
    listener.guest_guard = FX.guard
    listener.BOOTSTRAP_LOG = HOME / ('kernel-secret-' + label + '.bootstrap')
    sys.argv = [str(HELPERS / 'auth-client-listener.py'),
                '--notify', 'open', '--notify', 'openat', '--notify', 'ioctl',
                '--log', str(HOME / ('kernel-secret-' + label + '.trace')),
                '--log-args', 'open=1', '--log-args', 'openat=2', '--log-args', 'ioctl=0,1',
                '--log-string', 'open=0', '--log-string', 'openat=1', '--', *sys.argv[3:]]
    listener.main()


def observed(label):
    """Device opens and ioctl request numbers one traced candidate really issued."""
    path = HOME / ('kernel-secret-' + label + '.trace')
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    require(rows and all(row.get('reply') == 'continue' for row in rows), 'a real syscall was replaced: ' + label)
    opens = sum(1 for row in rows if FX.DEVICE.as_posix() in (row.get('string0'), row.get('string1')))
    commands = [row['arg1'] for row in rows if row['syscall'] == 'ioctl']
    counts = {name: commands.count(value) for name, value in
              (('new', NEW), ('write', WRITE), ('seal', SEAL), ('clear', CLEAR), ('export', EXPORT))}
    record('trace', label=label, device_opens=opens, secret_ioctls=counts, notified_calls=len(rows))
    return opens, commands, counts


def environment(**accounts):
    env = dict(os.environ, BASHPASSWD_REQUIRE_KERNEL_SECRETS='1', **accounts)
    env.pop('BASHPASSWD_KERNEL_SECRETS', None)
    return env


def refused_without_module(env, user, shadow):
    """With the secret device required but absent, a password update must fail closed."""
    require(not os.path.lexists(FX.DEVICE) and not Path('/sys/module', FX.MODULE).exists(),
            'the absent-device control needs the module unloaded')
    before = shadow.read_bytes()
    result = subprocess.run(traced('absent', 'passwd set-fd ' + user + ' 0'), input=b'absent-device-only\n',
                            env=env, capture_output=True, timeout=left(15))
    opens, _commands, _counts = observed('absent')
    refused = result.returncode != 0 and shadow.read_bytes() == before
    record('absent-device', status=result.returncode, stdout=result.stdout.decode(errors='replace'),
           stderr=result.stderr.decode(errors='replace'), device_open_attempts=opens,
           account_file_unchanged=shadow.read_bytes() == before, refused=refused)
    return refused


def race(mode):
    require(mode in ('none', 'set', 'lock', 'aba'), 'unknown race')
    db, locks = CASE / 'db', CASE / 'locks'
    shadow = db / 'shadow'
    for path in (db, db / 'passwd', db / 'group', shadow):
        os.chown(path, 0, 0)
    require(stat.S_IMODE(shadow.stat().st_mode) == 0o600 and locks.is_dir() and locks.stat().st_uid == 0,
            'private account fixture differs')
    env = environment(PHCLIB_PASSWD=str(db / 'passwd'), PHCLIB_GROUP=str(db / 'group'),
                      PHCLIB_SHADOW=str(shadow), BPW_LOCK_DIR=str(locks),
                      PHCLIB_M='1024', PHCLIB_T='1', PHCLIB_P='1')
    checks = {'absent-device-refused': refused_without_module(env, 'alice', shadow)}
    readers = ['change']
    transcript = bytearray()

    def peer(label, script, data=None, reads_password=False):
        result = subprocess.run(traced(label, script), input=data, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=left(10))
        with (HOME / 'peer.log').open('ab') as log:
            log.write(result.stdout + result.stderr)
        if reads_password:
            readers.append(label)
        return result.returncode

    with FX.loaded():
        master, slave = pty.openpty()
        old_attrs = termios.tcgetattr(slave)

        def session():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        child = subprocess.Popen(traced('change', 'passwd change alice'), stdin=slave, stdout=slave,
                                 stderr=slave, env=env, preexec_fn=session, close_fds=True)

        def until(marker):
            end = time.monotonic() + left(10)
            pending = bytearray()
            while marker not in pending:
                remaining = end - time.monotonic()
                if remaining <= 0 or not select.select([master], [], [], remaining)[0]:
                    return False
                try:
                    data = os.read(master, 4096)
                except OSError:
                    return False
                if not data:
                    return False
                transcript.extend(data)
                pending.extend(data)
            return True

        try:
            checks['prompt-current'] = until(b'Current password: ')
            if checks['prompt-current']:
                os.write(master, b'password\n')
                checks['prompt-new'] = until(b'New password: ')
            if checks.get('prompt-new'):
                original = shadow.read_bytes()
                initial = shadow.stat()
                if mode == 'lock':
                    checks['peer-lock'] = peer('peer-lock', 'passwd lock alice') == 0
                elif mode == 'set':
                    checks['peer-set'] = peer('peer-set', 'passwd set-fd alice 0', b'other-password\n', True) == 0
                elif mode == 'aba':
                    checks['peer-lock'] = peer('peer-lock', 'passwd lock alice') == 0
                    checks['peer-unlock'] = peer('peer-unlock', 'passwd unlock alice') == 0
                    current = shadow.stat()
                    checks['aba-same-bytes'] = shadow.read_bytes() == original
                    checks['aba-new-inode'] = (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino)
                peer_shadow = shadow.read_bytes()
                os.write(master, b'new-password\n')
                checks['prompt-retype'] = until(b'Retype new password: ')
            if checks.get('prompt-retype'):
                os.write(master, b'new-password\n')
                try:
                    status = child.wait(timeout=left(12))
                except subprocess.TimeoutExpired:
                    status = None
                record('change', status=status, mode=mode)
                if mode == 'none':
                    checks['change-accepted'] = status == 0
                    checks['new-password-verifies'] = peer('verify-new', 'passwd verify-fd alice 0',
                                                           b'new-password\n', True) == 0
                else:
                    checks['stale-change-refused'] = status is not None and status != 0
                    checks['peer-state-kept'] = shadow.read_bytes() == peer_shadow
                    if mode == 'lock':
                        checks['peer-locked'] = b'alice:!' in peer_shadow
                    elif mode == 'set':
                        checks['peer-password-verifies'] = peer('verify-other', 'passwd verify-fd alice 0',
                                                                b'other-password\n', True) == 0
                        checks['new-password-rejected'] = peer('verify-new', 'passwd verify-fd alice 0',
                                                               b'new-password\n', True) != 0
                    else:
                        checks['old-password-verifies'] = peer('verify-old', 'passwd verify-fd alice 0',
                                                               b'password\n', True) == 0
                checks['terminal-restored'] = termios.tcgetattr(slave) == old_attrs
        finally:
            (HOME / 'terminal.log').write_bytes(transcript)
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            os.close(master)
            os.close(slave)
        complete = all(checks.get(name) for name in ('prompt-current', 'prompt-new', 'prompt-retype'))
        for label in readers if complete else ():
            opens, commands, _counts = observed(label)
            checks['kernel-secret-' + label] = opens >= 1 and COMPLETE <= set(commands)
    failed = sorted(name for name, good in checks.items() if not good)
    record('race-result', mode=mode, checks=checks, failed=failed)
    if failed:
        print('change-' + mode + ' mismatch: ' + ' '.join(failed))
    else:
        print('change-' + mode + '=expected terminal=restored kernel-secrets=observed absent-device=refused')
    return 0


INTERRUPTS = {
    # command, minimum NEW_SECRET, WRITE_SECRET and SEAL_SECRET calls before the interrupt
    'set-new': ('passwd set w5user', 1, 0, 0),
    'set-retype': ('passwd set w5user', 2, 14, 1),
    'change-current': ('passwd change w5user', 1, 0, 0),
}


def interrupt(which):
    """Run the candidate on the case's own controlling terminal; the PTY driver interrupts it."""
    require(which in INTERRUPTS, 'unknown interrupt point')
    command, news, writes, seals = INTERRUPTS[which]
    signal.signal(signal.SIGINT, lambda *unused: None)
    shadow, locks = CASE / 'shadow', CASE / 'lock'
    locks.mkdir(mode=0o700, exist_ok=True)
    require(shadow.stat().st_uid == 0 and stat.S_IMODE(shadow.stat().st_mode) == 0o600,
            'private account fixture differs')
    env = environment(PHCLIB_SHADOW=str(shadow), PHCLIB_PASSWD=str(CASE / 'passwd'), BPW_LOCK_DIR=str(locks))
    original = shadow.read_bytes()
    refused = refused_without_module(env, 'w5user', shadow)
    status = None
    with FX.loaded():
        child = subprocess.Popen(traced('interrupt', '[[ $(type -t passwd) == builtin ]] || exit 99\n' + command),
                                 env=env)
        try:
            status = child.wait(timeout=left(22))
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        opens, _commands, counts = observed('interrupt')
        slot = (opens >= 1 and counts['new'] >= news and counts['write'] >= writes and counts['seal'] >= seals)
    unchanged = shadow.read_bytes() == original
    record('interrupt-result', point=which, status=status, absent_device_refused=refused,
           kernel_secret_path=slot, account_file_unchanged=unchanged)
    if status is None:
        print('passwd did not end after the interrupt', file=sys.stderr)
        return 1
    if not (refused and slot and unchanged):
        print('kernel-secret interrupt mismatch: absent-device-refused=%s kernel-secret-path=%s '
              'account-file-unchanged=%s' % (refused, slot, unchanged), file=sys.stderr)
        return 1
    return status


def main():
    FX.guard()
    require(len(sys.argv) >= 2, 'action required')
    if sys.argv[1] == 'trace':
        trace()
        return 125
    require(len(sys.argv) == 4 and sys.argv[1] in ('race', 'interrupt') and sys.argv[2] == CANDIDATE,
            'approved candidate and action required')
    return race(sys.argv[3]) if sys.argv[1] == 'race' else interrupt(sys.argv[3])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:
        print('passwd kernel-secret fixture incomplete: ' + repr(exc), file=sys.stderr)
        raise SystemExit(125)
