#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Persistent login state controls; attested disposable guest execution only.

Uses the actual Bash login, native verifier and real authority device. Storage
faults only deny real syscalls. It never supplies positive authority replies.
"""
import argparse
import base64
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import termios
import time
import uuid

sys.dont_write_bytecode = True
HOME = Path('/tmp/parity-home')
LOGIN = 'login login-v2 --qualification-device --no-motd --max-tries '
STATE_FAULTS = ('login-state-file-sync', 'login-state-rename',
                'login-state-directory-sync', 'login-state-clear')


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def check(ok, reason):
    if not ok: raise AssertionError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard(args, receipt):
    require(__debug__ and platform.machine() == 'x86_64' and
            os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'root x86-64 guest required')
    require(Path.cwd() == Path('/tmp/parity-case') and os.environ.get('HOME') == str(HOME), 'guest scratch differs')
    token = str(uuid.UUID(args.expected_uuid))
    require(Path('/etc/bashos-parity-vm').read_text().strip() == token and
            Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'live guest UUID differs')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'owned disposable evaluator required')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU' and
            platform.release() == receipt['kernel_release'], 'guest/kernel differs')


def record(path, count, last=None, until=0):
    last = int(time.time()) if last is None else last
    path.write_text('COUNT=%d\nLAST=%d\nLOCKED_UNTIL=%d\n' % (count, last, until))
    path.chmod(0o600)


def decode(path):
    info = path.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
          stat.S_IMODE(info.st_mode) == 0o600, 'state metadata differs')
    text = path.read_text()
    match = re.fullmatch(r'COUNT=([0-9]+)\nLAST=([0-9]+)\nLOCKED_UNTIL=([0-9]+)\n', text)
    check(match is not None, 'independent state framing differs')
    return dict(zip(('count', 'last', 'until'), map(int, match.groups())))


class Session:
    """One owned PTY/observer, also usable for two concurrent live logins."""
    def __init__(self, runtime, name, script, want, fault=None):
        self.runtime, self.want = runtime, want
        self.directory, config = runtime.config(name, ['--noprofile', '--norc', '-c', script], want, fault=fault)
        value = json.loads(config.read_text()); value['timeout'] = 60
        if fault:
            value['login_state_directory'] = str(runtime.root / 'lock')
            info = (runtime.root / 'lock').stat()
            want.update(state_directory_identity=[info.st_dev, info.st_ino], state_file='fail.42101')
            value['expected'] = want
        config.write_text(json.dumps(value, indent=2) + '\n')
        self.master, self.slave = pty.openpty()
        self.tty = os.ttyname(self.slave)
        env = dict(runtime.environment, V2_TTY=self.tty)
        def setup():
            os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.process = subprocess.Popen(['/usr/bin/python3', '-B', str(runtime.artifacts / 'consumer-observer.py'), str(config)],
            stdin=self.slave, stdout=self.slave, stderr=self.slave, env=env, preexec_fn=setup, close_fds=True)
        self.data, self.cursor, self.secrets, self.events = bytearray(), 0, [], []
        self.deadline = time.monotonic() + 65

    def pump(self):
        require(time.monotonic() < self.deadline, 'login-state terminal deadline exceeded')
        if select.select([self.master], [], [], .02)[0]:
            try: block = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO: raise
                block = b''
            self.data.extend(block)

    def prompt(self, prompt):
        while True:
            at = self.data.find(prompt, self.cursor)
            if at >= 0:
                self.cursor = at + len(prompt)
                now = time.monotonic()
                self.events.append({'prompt': prompt.decode(), 'at_monotonic': now,
                                    'echo': bool(termios.tcgetattr(self.slave)[3] & termios.ECHO)})
                return now
            if self.process.poll() is not None:
                self.pump()
                if self.data.find(prompt, self.cursor) >= 0: continue
                self.runtime.trace_result(self.directory, self.want)
                check(False, 'candidate exited before required prompt: ' + repr(prompt))
            self.pump()

    def send(self, data, secret=False):
        if secret:
            check(not termios.tcgetattr(self.slave)[3] & termios.ECHO, 'password echo enabled')
            self.secrets.append(data)
        block = data + b'\n'
        require(os.write(self.master, block) == len(block), 'short fixture terminal input')
        return time.monotonic()

    def login_name(self, name=b'av2standard'):
        self.prompt(b' login: '); self.send(name)

    def password(self, password):
        self.prompt(b'Password: '); return self.send(password, True)

    def cancel(self, signum):
        values = re.findall(rb'LOGIN_ACTOR=([0-9]+)', self.data)
        require(len(values) == 1, 'one declared cancellation actor required')
        pid = int(values[0]); pidfd = os.pidfd_open(pid)
        try:
            status = dict(line.split(':', 1) for line in Path('/proc/%d/status' % pid).read_text().splitlines())
            require(int(status['PPid']) == self.process.pid and status['Uid'].split() == ['0'] * 4,
                    'signal must target the owned root observer child')
            signal.pidfd_send_signal(pidfd, signum)
        finally: os.close(pidfd)

    def finish(self, status=1):
        while self.process.poll() is None: self.pump()
        while select.select([self.master], [], [], .02)[0]:
            try: block = os.read(self.master, 65536)
            except OSError: break
            if not block: break
            self.data.extend(block)
        verdict = self.runtime.trace_result(self.directory, self.want)
        check(self.process.returncode == status, 'candidate status differs: ' + str(self.process.returncode))
        check(termios.tcgetattr(self.slave)[3] & termios.ECHO, 'terminal echo not restored')
        check(all(value not in self.data for value in self.secrets), 'password printed or echoed')
        check(b'UNSAFE_RETURN' not in self.data, 'unsafe interpreter return')
        result = {'exit_code': status, 'transcript': bytes(self.data), 'tty': self.tty, 'verdict': verdict}
        return result

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL); self.process.wait()
        (self.directory / 'transcript.bin').write_bytes(self.data)
        (self.directory / 'terminal-events.json').write_text(json.dumps(self.events, indent=2) + '\n')
        os.close(self.master); os.close(self.slave)

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def controls(runtime, base):
    lock = runtime.root / 'lock'
    state = lock / 'fail.42101'
    policy = runtime.root / 'login.policy'
    want = base.expected

    def reset():
        runtime.root.chmod(0o755)
        if lock.is_symlink():
            lock.unlink(); (runtime.root / 'saved-lock').rename(lock)
        os.chown(lock, 0, 0); lock.chmod(0o700)
        for path in lock.iterdir():
            if path.is_dir() and not path.is_symlink(): shutil.rmtree(path)
            else: path.unlink()
        policy.write_bytes(b'version 2\n')
        for name in ('utmp', 'wtmp', 'lastlog'): (runtime.trusted / name).write_bytes(b'')

    def snapshot(name):
        rows = []
        for path in sorted(lock.iterdir()):
            info = path.lstat()
            row = {'name': path.name, 'mode': info.st_mode, 'uid': info.st_uid, 'links': info.st_nlink}
            if stat.S_ISREG(info.st_mode) and info.st_size < 1024:
                row['bytes_base64'] = base64.b64encode(path.read_bytes()).decode()
            rows.append(row)
        (runtime.output / (name + '-state.json')).write_text(json.dumps(rows, indent=2) + '\n')

    def note(name, function, kind='actual-consumer'):
        reset()
        def run():
            try: return function()
            finally: snapshot(name)
        runtime.note(name, run, kind)

    def attempt(name, password=b'wrong-password', user=b'av2standard', success=False, fault=None, proof=False):
        expected = want(1 if success else 0, 42101 if success or proof else 0,
                        42102 if success or proof else 0, success or proof, fault)
        with Session(runtime, name, LOGIN + '1', expected, fault) as session:
            session.login_name(user)
            if password is not None: session.password(password)
            result = session.finish(37 if success else 1)
            if success: runtime.target_result(result, 'av2standard', 42101, 42102)
            if password is not None and user == b'av2standard' and not success and not proof:
                events = [json.loads(line) for line in (session.directory / 'trace.jsonl').read_text().splitlines()]
                check(sum(e.get('identity_operation') == 'verify' for e in events) == 1 and
                      not any(e.get('identity_operation') == 'consume' for e in events),
                      'wrong-password case did not reach exactly one real verifier attempt without consumption')
            return result

    def no_auth(result, directory):
        check(b'Password: ' not in result['transcript'], 'locked/corrupt state reached password input')
        events = [json.loads(line) for line in (runtime.output / directory / 'trace.jsonl').read_text().splitlines()]
        check(not any(x.get('identity_operation') for x in events), 'locked/corrupt state reached authority')

    def persisted_threshold():
        policy.write_bytes(b'version 2\nauth required lockout max=2 window=600 duration=900\n')
        for i in range(2):
            result = attempt('threshold-attempt-' + str(i))
            check(b'Login incorrect' in result['transcript'], 'wrong password response differs')
            check(decode(state)['count'] == i + 1, 'failure count not persistent across invocations')
        stored = state.read_bytes(); decoded = decode(state)
        check(decoded['until'] == decoded['last'] + 900, 'lock duration differs')
        result = attempt('threshold-correct-password-blocked', None)
        no_auth(result, 'threshold-correct-password-blocked')
        check(b'Account locked.' in result['transcript'] and state.read_bytes() == stored, 'active lock changed')
    note('login-state-threshold-persists-across-invocations', persisted_threshold)

    def no_module():
        record(state, 5, until=int(time.time()) + 900)
        result = attempt('no-lockout-module', None); no_auth(result, 'no-lockout-module')
    note('login-state-chain-cannot-omit-enforcement', no_module)

    def success_clears():
        record(state, 2); attempt('success-clears', base.PASSWORD, success=True)
        check(not state.exists() and (lock / '.guard.42101').exists(), 'success must clear only failure record')
    note('login-state-success-clears-record-retains-guard', success_clears)

    def expired():
        record(state, 5, int(time.time()) - 20, int(time.time()) - 10)
        attempt('expired-lock', base.PASSWORD, success=True)
        check(not state.exists(), 'expired state was not cleared after success')
    note('login-state-expired-lock-allows-real-auth', expired)

    def window():
        record(state, 4, int(time.time()) - 601)
        attempt('expired-count-window')
        check(decode(state)['count'] == 1 and decode(state)['until'] == 0, 'expired count window not reset')
    note('login-state-failure-window-resets-count', window)

    def existing():
        record(state, 2)
        attempt('existing-record-increment')
        check(decode(state)['count'] == 3 and decode(state)['until'] == 0, 'existing record count was reset/lost')
    note('login-state-existing-record-continues-count', existing)

    def still_locked_after_input():
        with Session(runtime, 'lock-after-password-prompt', LOGIN + '1', want()) as session:
            session.login_name(); session.prompt(b'Password: ')
            guardfd = os.open(lock / '.guard.42101', os.O_RDWR | os.O_CLOEXEC)
            try:
                fcntl.flock(guardfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                record(state, 5, until=int(time.time()) + 900)
            finally: os.close(guardfd)
            session.send(base.PASSWORD, True)
            result = session.finish()
            check(b'Account locked.' in result['transcript'], 'new lock during input was ignored')
        events = [json.loads(x) for x in (runtime.output / 'lock-after-password-prompt/trace.jsonl').read_text().splitlines()]
        check(not any(x.get('identity_operation') for x in events), 'new lock reached authority')
    note('login-state-rechecks-after-input-without-holding-guard', still_locked_after_input)

    def session_denial():
        record(state, 2); before = state.read_bytes()
        policy.write_bytes(b'version 2\nsession required deny all\n')
        attempt('denied-session-keeps-state', base.PASSWORD, proof=True)
        check(state.read_bytes() == before, 'session policy denial cleared failures')
        check(all((runtime.trusted / n).stat().st_size == 0 for n in ('utmp', 'wtmp', 'lastlog')),
              'session policy denial wrote accounting')
    note('login-state-policy-denial-retains-failure-record', session_denial)

    def disabled():
        state.write_bytes(b'explicitly disabled fixture'); state.chmod(0o600)
        policy.write_bytes(b'version 2\nauth required lockout max=0\n')
        attempt('explicit-disabled-state', base.PASSWORD, success=True)
        check(state.read_bytes() == b'explicitly disabled fixture', 'disabled state was migrated or changed')
    note('login-state-explicit-zero-disables-without-migration', disabled)

    def oversized_limit():
        policy.write_bytes(b'version 2\nauth required lockout max=4294967296\n')
        with Session(runtime, 'overflow-policy', LOGIN + '1', want()) as session:
            result = session.finish()
            check(runtime.login_prompt not in result['transcript'], 'oversized limit accepted')
    note('login-state-oversized-policy-limit-rejected', oversized_limit)

    for value in ('0', '11', '2junk', '-1'):
        def bad_tries(value=value):
            with Session(runtime, 'bad-tries-' + value, LOGIN + value, want()) as session:
                result = session.finish(2)
                check(runtime.login_prompt not in result['transcript'], 'invalid max-tries reached login')
        note('login-state-invalid-max-tries-' + value, bad_tries)

    malformed = {
        'missing': b'COUNT=1\nLAST=0\n',
        'duplicate': b'COUNT=1\nCOUNT=0\nLAST=0\nLOCKED_UNTIL=0\n',
        'negative': b'COUNT=-1\nLAST=0\nLOCKED_UNTIL=0\n',
        'overflow': b'COUNT=2147483648\nLAST=0\nLOCKED_UNTIL=0\n',
        'nul': b'COUNT=1\x00\nLAST=0\nLOCKED_UNTIL=0\n',
        'extra-field': b'COUNT=1\nLAST=0\nLOCKED_UNTIL=0\nTRUST=1\n',
        'long': b'X' * 128,
    }
    for name, contents in malformed.items():
        def bad_record(name=name, contents=contents):
            state.write_bytes(contents); state.chmod(0o600)
            result = attempt('bad-record-' + name, None); no_auth(result, 'bad-record-' + name)
            check(state.read_bytes() == contents, 'malformed record was overwritten')
        note('login-state-rejects-record-' + name, bad_record)

    def rollback():
        record(state, 1, int(time.time()) + 3600)
        result = attempt('clock-rollback', None); no_auth(result, 'clock-rollback')
    note('login-state-clock-rollback-fails-closed', rollback)

    for kind in ('symlink', 'fifo', 'hardlink', 'mode', 'owner', 'directory'):
        def unsafe_record(kind=kind):
            if kind == 'symlink':
                record(lock / 'original', 1); state.symlink_to('original')
            elif kind == 'fifo': os.mkfifo(state, 0o600)
            elif kind == 'directory': state.mkdir(mode=0o700)
            else:
                record(state, 1)
                if kind == 'hardlink': os.link(state, lock / 'alias')
                if kind == 'mode': state.chmod(0o644)
                if kind == 'owner': os.chown(state, 42101, 42102)
            result = attempt('unsafe-record-' + kind, None); no_auth(result, 'unsafe-record-' + kind)
        note('login-state-rejects-' + kind, unsafe_record)

    for kind in ('symlink', 'mode', 'owner', 'writable-ancestor'):
        def unsafe_directory(kind=kind):
            if kind == 'symlink':
                lock.rename(runtime.root / 'saved-lock'); lock.symlink_to('saved-lock')
            elif kind == 'mode': lock.chmod(0o755)
            elif kind == 'owner': os.chown(lock, 42101, 42102)
            else: runtime.root.chmod(0o777)
            try:
                result = attempt('unsafe-directory-' + kind, None); no_auth(result, 'unsafe-directory-' + kind)
            finally:
                if kind == 'symlink': lock.unlink(); (runtime.root / 'saved-lock').rename(lock)
                os.chown(lock, 0, 0); lock.chmod(0o700); runtime.root.chmod(0o755)
        note('login-state-rejects-directory-' + kind, unsafe_directory)

    def busy_guard():
        guardfd = os.open(lock / '.guard.42101', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(guardfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = attempt('busy-guard', None); no_auth(result, 'busy-guard')
            check(not state.exists(), 'busy guard changed failure record')
        finally: os.close(guardfd)
    note('login-state-busy-guard-denies-before-authority', busy_guard)

    def concurrent():
        with Session(runtime, 'concurrent-a', LOGIN + '1', want()) as a, \
             Session(runtime, 'concurrent-b', LOGIN + '1', want()) as b:
            a.login_name(); a.prompt(b'Password: '); b.login_name(); b.prompt(b'Password: ')
            a.send(b'wrong-a-password', True); b.send(b'wrong-b-password', True)
            first, second = a.finish(), b.finish()
        completed = sum(b'Login incorrect' in r['transcript'] for r in (first, second))
        check(completed in (1, 2) and decode(state)['count'] == completed, 'lost update or unrecorded completed failure')
        for result in (first, second):
            check(b'Login incorrect' in result['transcript'] or b'persistent failure state unavailable' in result['transcript'],
                  'concurrent failure neither serialized nor denied busy')
        for name, result in (('concurrent-a', first), ('concurrent-b', second)):
            events = [json.loads(line) for line in (runtime.output / name / 'trace.jsonl').read_text().splitlines()]
            check(sum(e.get('identity_operation') == 'verify' for e in events) ==
                  int(b'Login incorrect' in result['transcript']) and
                  not any(e.get('identity_operation') == 'consume' for e in events),
                  'concurrent verification/count evidence differs')
        return {'completed_verifications': completed, 'stored_count': decode(state)['count']}
    note('login-state-concurrent-failures-no-lost-update', concurrent)

    def retries():
        intervals = []
        with Session(runtime, 'three-retry-delays', LOGIN + '3', want()) as session:
            for name, minimum in ((b'av2standard', 1), (b'unknown-v2-login', 5), (b'../invalid', 30)):
                session.login_name(name); started = session.password(b'wrong-retry-password')
                ended = session.prompt(b'Login incorrect')
                interval = ended - started; intervals.append(interval)
                check(interval >= minimum - .05, 'required retry delay was shortened')
            result = session.finish()
            check(result['transcript'].count(b'Login incorrect') == 3 and
                  result['transcript'].count(b' login: ') == 3 and
                  b'Maximum number of tries exceeded.' in result['transcript'], 'retry/max-tries transcript differs')
        check(decode(state)['count'] == 1 and decode(lock / 'fail.unknown-v2-login')['count'] == 1,
              'known/unknown retry state differs')
        check(not any('invalid' in path.name for path in lock.iterdir()), 'invalid username reached state path')
        return {'observed_delay_seconds': intervals, 'required_minimum_seconds': [1, 5, 30]}
    note('login-state-wrong-unknown-invalid-and-1-5-30-retries', retries)

    for label, sig in (('hup', signal.SIGHUP), ('term', signal.SIGTERM), ('int', signal.SIGINT)):
        def cancel(label=label, sig=sig):
            script = ('RESTORED=0; trap \'RESTORED=$((RESTORED+1))\' HUP TERM INT\n'
                      'printf "LOGIN_ACTOR=%s\\n" "$BASHPID"\n' + LOGIN + '3\n'
                      '[[ $? == 1 ]] || exit 98\n'
                      'kill -HUP "$BASHPID"; kill -TERM "$BASHPID"; kill -INT "$BASHPID"\n'
                      '[[ $RESTORED == 3 ]] || exit 99\nprintf "HANDLERS_RESTORED\\n"\n')
            with Session(runtime, 'cancel-delay-' + label, script, want()) as session:
                session.login_name(); session.password(b'wrong-cancel-password')
                while not state.exists():
                    if session.process.poll() is not None:
                        runtime.trace_result(session.directory, session.want)
                        check(False, 'candidate returned without persisting the failure')
                    session.pump()
                started = time.monotonic(); session.cancel(sig); result = session.finish(0)
                elapsed = time.monotonic() - started
                check(elapsed < 3 and result['transcript'].count(b' login: ') == 1 and
                      b'HANDLERS_RESTORED' in result['transcript'], 'cancellation retried or failed to restore handlers')
            check(decode(state)['count'] == 1, 'committed failure lost on cancellation')
            return {'cancel_return_seconds': elapsed}
        note('login-state-cancel-after-persist-' + label, cancel)

    for fault in STATE_FAULTS:
        def io_failure(fault=fault):
            clear = fault == 'login-state-clear'
            if clear: record(state, 1)
            result = attempt('fault-' + fault, base.PASSWORD if clear else b'wrong-io-password', fault=fault, proof=clear)
            check(b'cannot clear persistent failure state' in result['transcript'] if clear else
                  b'cannot persist authentication failure' in result['transcript'], 'storage error was not reported')
            check(not any(path.name.startswith('.state-') for path in lock.iterdir()), 'temporary state file leaked')
            if fault in ('login-state-file-sync', 'login-state-rename'): check(not state.exists(), 'failed transaction installed record')
            else: check(decode(state)['count'] == 1, 'post-rename/failed-unlink state differs')
        note('login-state-fails-closed-' + fault, io_failure)

    def clear_sync_failure():
        record(state, 1)
        result = attempt('clear-directory-sync-fault', base.PASSWORD, proof=True, fault='login-state-directory-sync')
        check(b'cannot clear persistent failure state' in result['transcript'] and not state.exists(),
              'post-unlink sync failure semantics differ')
        check(all((runtime.trusted / n).stat().st_size == 0 for n in ('utmp', 'wtmp', 'lastlog')),
              'post-unlink sync failure reached accounting')
    note('login-state-clear-directory-sync-fails-closed', clear_sync_failure)

    for fault in STATE_FAULTS:
        def negative(fault=fault):
            if fault == 'login-state-clear': record(state, 1)
            expected = want(fault=fault)
            info = lock.stat(); expected.update(state_directory_identity=[info.st_dev, info.st_ino], state_file='fail.42101')
            directory, config = runtime.config('negative-' + fault,
                [runtime.args.expected_uuid, fault, str(runtime.target), 'bad-control'], expected,
                program=runtime.artifacts / 'login-state-negative', fault=fault)
            value = json.loads(config.read_text()); value['login_state_directory'] = str(lock)
            config.write_text(json.dumps(value, indent=2) + '\n')
            result = runtime.command(['/usr/bin/python3', '-B', runtime.artifacts / 'consumer-observer.py', config], timeout=45)
            (directory / 'stdout.bin').write_bytes(result.stdout); (directory / 'stderr.bin').write_bytes(result.stderr)
            verdict = runtime.trace_result(directory, expected, rejection=True)
            check(result.returncode == 1 and verdict['selected_faults'] == 1 and
                  verdict['target_exec_attempts'] == 1 and verdict['guard_denials'] == 1,
                  'deliberate bad storage actor did not exercise the full negative oracle')
            return verdict
        note('login-state-observer-rejects-continuation-' + fault, negative, 'independent-negative-observer-control')


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(sha(args.receipt) == args.receipt_sha256, 'receipt pin differs')
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-consumer-v2-build-only' and
            receipt.get('login_state_overlay', {}).get('name') == 'login-state-ssh-merge-r1',
            'wrong merged login-state receipt')
    guard(args, receipt)
    artifacts = args.receipt.resolve().parent
    require(args.output.is_absolute() and args.output.resolve().is_relative_to(HOME) and not args.output.exists(),
            'fresh private output required')
    for name, pin in receipt['files'].items():
        path = artifacts / name
        require(Path(name).name == name and path.is_file() and not path.is_symlink() and
                sha(path) == pin['sha256'] and path.stat().st_size == pin['bytes'], 'artifact pin differs')
        info = path.stat(); require(info.st_uid == 0 and not info.st_mode & 0o022, 'artifact not protected')
    require(sha(Path(__file__)) == receipt['files']['guest-login-state.py']['sha256'], 'driver source pin differs')
    spec = importlib.util.spec_from_file_location('identity_consumers', artifacts / 'guest-consumers.py')
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    base.protected(args.bash, args.bash_sha256)
    require(args.bash.is_absolute(), 'absolute candidate required')
    args.output.mkdir(mode=0o700)
    runtime = base.Runtime(args, receipt)
    runtime.report.update(suite='login-state-ssh-merge-r1', original_topic_credit=0)
    before = runtime.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        runtime.prepare(); controls(runtime, base)
        require(len(runtime.cases) == 47 and all(row['status'] == 'PASS' for row in runtime.cases), 'control inventory incomplete')
        runtime.report.update(status='PASS', control_counts={'actual_consumer': 43, 'negative_observer': 4})
    except AssertionError as error: runtime.report.update(status='FAIL', reason=str(error))
    except Exception as error: runtime.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        # Preserve a reached case failure if a later teardown/kernel gate also
        # errors, as in the pinned SSH baseline. Every gate remains mandatory.
        runtime.report['behavior_status'] = runtime.report['status']
        runtime.report['secondary_failures'] = []
        try:
            runtime.cleanup()
            runtime.report['cleanup_status'] = 'PASS'
        except Exception as error:
            runtime.report['cleanup_status'] = 'ERROR'
            runtime.report['secondary_failures'].append({'phase': 'cleanup', 'reason': repr(error)})
        try:
            after = runtime.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            bad = (b'WARNING:', b'BUG:', b'KASAN:', b'KCSAN:', b'UBSAN:', b'held lock', b'Oops:',
                   b'possible recursive locking', b'inconsistent lock state', b'general protection fault', b'INFO: task ')
            require(not any(term.lower() in delta.lower() for term in bad), 'kernel diagnostic failure')
            runtime.report['kernel_status'] = 'PASS'
        except Exception as error:
            runtime.report['kernel_status'] = 'ERROR'
            runtime.report['secondary_failures'].append({'phase': 'kernel', 'reason': repr(error)})
        if runtime.report['secondary_failures'] and runtime.report['behavior_status'] == 'PASS':
            runtime.report['status'] = 'ERROR'
        runtime.report['qualification_eligible'] = (runtime.report['status'] == 'PASS' and
                                                   not runtime.report['secondary_failures'])
        (args.output / 'commands.json').write_text(json.dumps(runtime.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(runtime.report, indent=2) + '\n')
    print(json.dumps({'status': runtime.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if runtime.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        print('Login-state preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
