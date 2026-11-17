#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-guest control: a policy denial launches no kernel helper.

The module starts its verifier and its executor as kernel usermode helpers
from two pinned files. An independent fanotify listener holds FAN_OPEN_EXEC
marks on exactly those two files and on the two command targets, so every
execution of any of them is reported by the kernel's own notification path,
whoever starts it. The same listener, with the same marks, must report the
executor for an allowed request and the verifier for a request that needs
authentication; it must report nothing for a request the policy denies. The
denials are bracketed by positive observations, so an idle or broken listener
cannot pass.
"""
import argparse
import ctypes as C
import errno
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import time

FAN_CLOEXEC, FAN_NONBLOCK, FAN_MARK_ADD = 0x1, 0x2, 0x1
FAN_OPEN_EXEC, FAN_Q_OVERFLOW = 0x1000, 0x4000
AT_FDCWD = -100
EVENT = struct.Struct('<IBBHQii')
HELPERS = ('verifier', 'executor')
DENIED, AUTH_REQUIRED, VERIFY_DENIED, AUTHORIZED, EXEC_START, EXEC_RESULT = 1, 2, 3, 4, 5, 6
REASON_POLICY, REASON_NONINTERACTIVE = 1, 3
SETTLE_SECONDS = 0.3


def require(value, reason):
    if not value: raise RuntimeError(reason)


class ExecWatch:
    """Kernel-reported executions of the marked files, by file identity."""
    def __init__(self, paths):
        self.libc = C.CDLL(None, use_errno=True)
        self.libc.fanotify_mark.argtypes = [C.c_int, C.c_uint, C.c_uint64, C.c_int, C.c_char_p]
        self.fd = self.libc.fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK, os.O_RDONLY | os.O_CLOEXEC)
        require(self.fd >= 0, 'fanotify unavailable: errno %d' % C.get_errno())
        self.identity = {}
        for name, path in paths.items():
            info = os.stat(path, follow_symlinks=False)
            require((info.st_dev, info.st_ino) not in self.identity, 'marked files share an inode')
            self.identity[(info.st_dev, info.st_ino)] = name
            require(self.libc.fanotify_mark(self.fd, FAN_MARK_ADD, FAN_OPEN_EXEC, AT_FDCWD, os.fsencode(path)) == 0,
                    'execution mark failed for %s: errno %d' % (name, C.get_errno()))

    def drain(self):
        time.sleep(SETTLE_SECONDS); rows = []
        while True:
            try: data = os.read(self.fd, 65536)
            except BlockingIOError: break
            offset = 0
            while offset < len(data):
                size, version, _, header, mask, fd, pid = EVENT.unpack_from(data, offset)
                require(version == 3 and header == EVENT.size and size >= header, 'notification framing differs')
                require(not mask & FAN_Q_OVERFLOW and fd >= 0, 'notification queue overflowed')
                try:
                    info = os.fstat(fd)
                    name = self.identity.get((info.st_dev, info.st_ino))
                finally: os.close(fd)
                require(name is not None and mask & FAN_OPEN_EXEC, 'notification for an unmarked file')
                rows.append({'file': name, 'pid': pid, 'mask': mask})
                offset += size
        return rows

    def close(self): os.close(self.fd)


def counts(events): return {name: sum(row['file'] == name for row in events) for name in ('verifier', 'executor', 'allowed-target', 'password-target', 'denied-target')}


def outcomes(rows): return [struct.unpack_from('<I', row, 64)[0] for row in rows]
def reasons(rows): return [struct.unpack_from('<I', row, 248)[0] for row in rows]


def observed(rt, name, action):
    """Run one request between two drains and return what the kernel reported."""
    base = rt.base
    stale = rt.watch.drain(); base.check(not stale, 'execution reported outside any request')
    pending = rt.audit_drain(); base.check(not pending, 'unassigned previous audit records')
    details = action() or {}
    events = rt.watch.drain(); rows = rt.audit_drain()
    (rt.args.output / (name + '-audit.bin')).write_bytes(b''.join(rows))
    details.update(exec_events=events, exec_counts=counts(events), audit_outcomes=outcomes(rows),
                   audit_reasons=reasons(rows), settle_seconds=SETTLE_SECONDS)
    return details


def launched(rt, details, **expected):
    """expected[name] is True (at least one execution) or False (none)."""
    base = rt.base
    for name, wanted in expected.items():
        seen = details['exec_counts'][name.replace('_', '-')]
        base.check((seen > 0) == wanted, '%s executions: %d, expected %s' % (name, seen, 'some' if wanted else 'none'))
    return details


def denial(rt, details, reason=REASON_POLICY, outcome=DENIED):
    base = rt.base
    launched(rt, details, verifier=False, executor=False, allowed_target=False, password_target=False, denied_target=False)
    pairs = list(zip(details['audit_outcomes'], details['audit_reasons']))
    base.check((outcome, reason) in pairs, 'the denial was not recorded by the authority')
    base.check(not {AUTHORIZED, EXEC_START, EXEC_RESULT} & set(details['audit_outcomes']),
               'the authority recorded an authorization or execution for a denied request')
    return details


def controls(rt):
    base = rt.base; q = shlex.quote
    sudo = 'sudo ' + base.SUDO_FLAG; doas = 'doas ' + base.SUDO_FLAG
    allowed, password, refused = q(str(rt.nopass)), q(str(rt.password)), q(str(rt.denied))

    def direct():
        result = subprocess.run([str(rt.nopass), 'exit-0'], cwd=rt.work, env=rt.env, capture_output=True, timeout=20)
        base.check(result.returncode == 0, 'direct target execution failed')
    rt.note('observer-identifies-direct-execution-of-a-marked-file',
            lambda: launched(rt, observed(rt, 'direct', direct), allowed_target=True, verifier=False, executor=False,
                             password_target=False, denied_target=False), 'independent-observer-self-check')

    def allow(name):
        details = observed(rt, name, lambda: rt.bash(name, sudo + '-n -u pcv2target ' + allowed + ' exit-7', 7, 1))
        base.check({EXEC_START, EXEC_RESULT} <= set(details['audit_outcomes']), 'allowed execution was not recorded')
        return launched(rt, details, executor=True, allowed_target=True, verifier=False, denied_target=False)
    rt.note('allowed-request-launches-the-executor', lambda: allow('allowed-before'), 'actual-consumer-positive-observation')

    def verified():
        name = 'auth-required-verified'
        details = observed(rt, name, lambda: rt.bash(
            name, sudo + '-k -u pcv2target ' + password + ' exit-9', 9, 1, base.PASSWORD))
        base.check(AUTH_REQUIRED in details['audit_outcomes'] and AUTHORIZED in details['audit_outcomes'],
                   'authentication requirement and verification were not recorded')
        return launched(rt, details, verifier=True, executor=True, password_target=True, denied_target=False)
    rt.note('auth-required-request-launches-the-verifier', verified, 'actual-consumer-positive-observation')

    def wrong():
        name = 'auth-required-wrong-password'
        details = observed(rt, name, lambda: rt.bash(
            name, sudo + '-k -u pcv2target ' + password, 1, 0, b'wrong-helper-password'))
        base.check(VERIFY_DENIED in details['audit_outcomes'] and
                   not {AUTHORIZED, EXEC_START, EXEC_RESULT} & set(details['audit_outcomes']),
                   'failed verification was not recorded as the only decision')
        return launched(rt, details, verifier=True, executor=False, password_target=False)
    rt.note('failed-verification-launches-the-verifier-and-no-executor', wrong, 'actual-consumer-positive-observation')

    for verb, prefix in (('sudo', sudo), ('doas', doas)):
        name = verb + '-policy-denial-launches-no-helper'
        rt.note(name, lambda n=name, p=prefix: denial(rt, observed(rt, n, lambda: rt.bash(
            n, p + '-n -u pcv2target ' + refused + ' exit-7', 1, 0))), 'actual-consumer-denial')

    def auth_denial():
        name = 'auth-policy-denial-launches-no-helper'
        script = ('auth privcmd-v2-exec' + base.AUTH_FLAG + ' -n %d %d -- %s exit-7; status=$?; [[ $status != 0 && $status != 7 ]]'
                  % (base.TARGET, base.TARGET, refused))
        return denial(rt, observed(rt, name, lambda: rt.bash(name, script, 0, 0)))
    rt.note('auth-policy-denial-launches-no-helper', auth_denial, 'actual-consumer-denial')

    def interactive_denial():
        # A terminal and a correct password are available; the policy denial
        # must be final before any prompt or verification.
        name = 'sudo-interactive-policy-denial-launches-no-helper'
        def run():
            import pty, select
            master, slave = pty.openpty(); data = bytearray()
            def setup():
                os.setsid(); import fcntl, termios; fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                os.setgroups([base.CALLER, base.SHARED]); os.setresgid(*[base.CALLER] * 3); os.setresuid(*[base.CALLER] * 3)
            process = subprocess.Popen([str(rt.args.bash), '--noprofile', '--norc', '-c',
                                        sudo + '-u pcv2target ' + refused + ' exit-7'], cwd=rt.work, env=rt.env,
                                       stdin=slave, stdout=slave, stderr=slave, preexec_fn=setup, close_fds=True)
            try:
                deadline = time.monotonic() + 30
                while process.poll() is None:
                    require(time.monotonic() < deadline and len(data) < 65536, 'denied consumer did not finish')
                    if select.select([master], [], [], .05)[0]:
                        try: data.extend(os.read(master, 4096))
                        except OSError as error:
                            if error.errno != errno.EIO: raise
                while select.select([master], [], [], .05)[0]:
                    try: chunk = os.read(master, 4096)
                    except OSError: break
                    if not chunk: break
                    data.extend(chunk)
            finally:
                if process.poll() is None: process.kill(); process.wait()
                os.close(master); os.close(slave)
                (rt.args.output / (name + '.log')).write_bytes(data)
            base.check(process.returncode == 1, 'denied consumer status %s expected 1' % process.returncode)
            base.check(b'assword' not in data and b'PCV2_TARGET' not in data, 'a denied request prompted or ran its target')
            return {'exit_code': process.returncode, 'terminal_output_hex': bytes(data).hex()}
        return denial(rt, observed(rt, name, run))
    rt.note('sudo-interactive-policy-denial-launches-no-helper', interactive_denial, 'actual-consumer-denial')

    def noninteractive():
        name = 'sudo-noninteractive-auth-required-launches-no-helper'
        return denial(rt, observed(rt, name, lambda: rt.bash(
            name, sudo + '-k -n -u pcv2target ' + password + ' exit-9', 1, 0)),
            reason=REASON_NONINTERACTIVE, outcome=AUTH_REQUIRED)
    rt.note('sudo-noninteractive-auth-required-launches-no-helper', noninteractive, 'actual-consumer-denial')

    def with_fd(function):
        fd = os.open(base.DEVICE, os.O_RDWR | os.O_CLOEXEC)
        try: function(fd)
        finally: os.close(fd)

    def refused_operation(function):
        try: function()
        except OSError as error: return error.errno
        raise AssertionError('operation on a denied request succeeded')

    def device_denial(fd):
        reply = base.prepare(fd, rt.denied, ('exit-7',))
        base.check(reply.decision == 1 and reply.reason == REASON_POLICY, 'device did not report a policy denial')
    rt.note('device-policy-denial-launches-no-helper', lambda: denial(rt, observed(
        rt, 'device-denial', lambda: rt.child('device-denial', lambda: with_fd(device_denial)))), 'actual-device-denial')

    def device_forced(fd):
        reply = base.prepare(fd, rt.denied, ('exit-7',))
        base.check(reply.decision == 1 and reply.reason == REASON_POLICY, 'device did not report a policy denial')
        # Present the correct password and then redeem: neither may reach a helper.
        verify_errno = refused_operation(lambda: base.verify(fd, reply))
        run_errno = refused_operation(lambda: base.redeem(fd, reply))
        print('PCV2_DENIED_FOLLOWUP ' + json.dumps({'verify_errno': verify_errno, 'run_errno': run_errno}), flush=True)
    rt.note('device-verify-and-run-after-denial-launch-no-helper', lambda: denial(rt, observed(
        rt, 'device-forced', lambda: rt.child('device-forced', lambda: with_fd(device_forced)))), 'actual-device-denial')

    rt.note('allowed-request-after-the-denials-launches-the-executor', lambda: allow('allowed-after'),
            'actual-consumer-positive-observation')


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    import hashlib, stat
    def protected(path, pin):
        info = Path(path).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and
                hashlib.sha256(Path(path).read_bytes()).hexdigest() == pin, 'unprotected or mismatched input: ' + str(path))
    protected(args.receipt, args.receipt_sha256)
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-privcmd-v2-build-only', 'receipt kind differs')
    for name, entry in receipt['files'].items():
        require(Path(name).name == name, 'invalid artifact name'); protected(args.receipt.parent / name, entry['sha256'])
        require((args.receipt.parent / name).stat().st_size == entry['bytes'], 'artifact size differs')
    protected(__file__, receipt['files']['guest-denial-no-helper.py']['sha256'])
    spec = importlib.util.spec_from_file_location('privcmd_base', args.receipt.parent / 'guest-privcmd-controls.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.select_endpoint(receipt)
    base.guard(args.expected_uuid, receipt['kernel_release']); protected(args.bash, args.bash_sha256)
    require(args.receipt.is_absolute() and args.bash.is_absolute() and args.output.is_absolute() and
            args.output.resolve().is_relative_to(base.HOME) and not args.output.exists(), 'fresh private absolute output required')
    args.output.mkdir(mode=0o700); rt = base.Runtime(args, receipt); rt.base = base; rt.watch = None
    rt.report.update(scope='kernel-reported helper executions for allowed, authentication-required and denied requests',
                     observer='fanotify FAN_OPEN_EXEC marks on the pinned verifier, executor and command targets',
                     blocking_gaps=[])
    before = rt.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable'); (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        rt.setup()
        rt.denied = rt.root / 'target-not-in-policy'
        rt.install(rt.denied, (rt.artifacts / 'privcmd-target').read_bytes(), 0o755)
        rt.watch = ExecWatch({'verifier': rt.root / 'verifier', 'executor': rt.root / 'executor',
                              'allowed-target': rt.nopass, 'password-target': rt.password, 'denied-target': rt.denied})
        rt.audit_drain()
        controls(rt)
        require(len(rt.cases) == 12 and all(row['status'] == 'PASS' for row in rt.cases), 'denial matrix incomplete')
        rt.report.update(status='PASS', controls_not_run_on_this_endpoint=[])
    except AssertionError as error: rt.report.update(status='FAIL', reason=str(error))
    except Exception as error: rt.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        try:
            if rt.watch is not None: rt.watch.close()
            rt.cleanup(); after = rt.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            require(not any(value in delta.lower() for value in (b'warning:', b'bug:', b'kasan:', b'kcsan:', b'ubsan:',
                b'held lock', b'oops:', b'possible recursive locking', b'inconsistent lock state',
                b'general protection fault', b'info: task ', b'panic:')), 'kernel warning/fault evidence')
            protected(args.bash, args.bash_sha256); protected(args.receipt, args.receipt_sha256)
        except Exception as error: rt.report.update(status='ERROR', cleanup_or_kernel_error=repr(error))
        (args.output / 'commands.json').write_text(json.dumps(rt.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(rt.report, indent=2) + '\n')
    print(json.dumps({'status': rt.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if rt.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: print('denial observer preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
