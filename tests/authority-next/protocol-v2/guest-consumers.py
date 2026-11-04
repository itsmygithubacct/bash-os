#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Actual Bash identity consumers, ONLY in the attested disposable guest.

Private mount-namespace account/accounting fixtures; real sealed-secret device,
pinned native verifier and kernel proofs. No authority ioctl result emulation.
Original policy/sudo/sudoedit/timestamp obligations remain separate gates.
"""
import argparse
import base64
import ctypes
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
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import termios
import time
import uuid

sys.dont_write_bytecode = True
HOME, CASE = Path('/tmp/parity-home'), Path('/tmp/parity-case')
DEVICE = '/dev/bashos-auth-v2-test'
PASSWORD, SALT = b'v2-consumer-disposable-password', b'consumer-v2-salt'
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
LIBC.unshare.argtypes = [ctypes.c_int]
VERIFY, VERIFY_LEGACY, CONSUME, RESET = 0x4060bc01, 0x4060bc02, 0x4080bc03, 0xbc04
NEW, WRITE, SEAL, CLEAR = 0xc008ba02, 0x4010ba03, 0x4008ba04, 0x4008ba05
ACCOUNTS = [('av2standard', 42101, 42102, 1), ('av2legacy', 42103, 42104, 2),
            ('av2root', 0, 0, 1), ('av2other', 42105, 42106, 1)]


def require(ok, message):
    if not ok: raise RuntimeError(message)


def check(ok, message):
    if not ok: raise AssertionError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_python(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def guard(token, kernel):
    require(__debug__ and platform.machine() == 'x86_64', 'debug x86-64 required')
    require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'guest root required')
    require(Path.cwd() == CASE and os.environ.get('HOME') == str(HOME), 'private parity scratch required')
    token = str(uuid.UUID(token))
    require(Path('/etc/bashos-parity-vm').read_text().strip() == token and
            Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'live UUID differs')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'matching disposable evaluator required')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU' and
            platform.release() == kernel, 'guest/kernel differs')


def protected(path, expected):
    path = Path(path); info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unprotected input: ' + str(path))
    require(sha(path) == expected, 'input pin differs: ' + str(path))


def expect_errno(function, values):
    try: function()
    except OSError as error:
        check(error.errno in values, 'unexpected errno %s, expected %s' % (error.errno, sorted(values)))
        return
    raise AssertionError('negative operation unexpectedly succeeded')


class Runtime:
    def __init__(self, args, receipt):
        self.args, self.receipt = args, receipt
        self.artifacts, self.output = args.receipt.resolve().parent, args.output
        self.root = Path('/run') / ('bashos-consumer-v2-' + str(uuid.UUID(args.expected_uuid)))
        self.trusted = Path('/var/lib') / ('bashos-consumer-v2-' + str(uuid.UUID(args.expected_uuid)))
        # /run may be mounted noexec. Keep the public executable separate from
        # both runtime state and the private root-only verifier/account data.
        self.executables = Path('/var/lib') / ('bashos-consumer-v2-exec-' + str(uuid.UUID(args.expected_uuid)))
        self.target = self.executables / 'consumer-target'
        self.observer = load_python('consumer_observer', self.artifacts / 'consumer-observer.py')
        self.commands, self.cases, self.mounts, self.created, self.modules = [], [], [], [], []
        self.owned_directories = []
        self.report = {'schema': 1, 'status': 'ERROR', 'guest_uuid': args.expected_uuid,
                       'kernel': platform.release(), 'bash_sha256': args.bash_sha256,
                       'receipt_sha256': args.receipt_sha256, 'cases': self.cases,
                       'production_features_enabled': False, 'kernel_erasure_qualified': False,
                       'all_nine_topics_qualified': False}
        self.environment = {'PATH': '/usr/bin:/bin', 'HOME': str(HOME), 'LANG': 'C', 'LC_ALL': 'C',
                            'TERM': 'xterm', 'BASHAUTH_LOGIN_POLICY': str(self.root / 'login.policy'),
                            'BPW_LOCK_DIR': str(self.root / 'lock'), 'UNSAFE_FIXTURE_ENV': 'must-be-removed'}

    def command(self, argv, timeout=15):
        result = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=self.environment, timeout=timeout)
        self.commands.append({'argv': [str(x) for x in argv], 'exit_code': result.returncode,
                              'stdout_base64': base64.b64encode(result.stdout).decode(),
                              'stderr_base64': base64.b64encode(result.stderr).decode()})
        return result

    def note(self, name, function, kind='actual-consumer'):
        require(name not in [row['id'] for row in self.cases], 'duplicate case ID')
        row = {'id': name, 'kind': kind, 'status': 'RUNNING'}; self.cases.append(row)
        try:
            result = function()
            if result is not None: row['details'] = result
            row['status'] = 'PASS'
        except AssertionError as error:
            row.update(status='FAIL', reason=str(error)); raise
        except Exception as error:
            row.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error)); raise

    def install(self, path, data, mode=0o600):
        with path.open('xb') as handle: handle.write(data)
        path.chmod(mode)

    def bind(self, source, destination, readonly=False):
        destination = Path(destination).resolve()
        if not destination.exists():
            self.install(destination, b'', 0o600); self.created.append(destination)
        require(destination.is_file() and destination.stat().st_uid == 0, 'unexpected bind target')
        require(LIBC.mount(os.fsencode(source), os.fsencode(destination), None, 4096, None) == 0,
                'private bind failed: ' + str(destination))
        self.mounts.append(destination)
        if readonly:
            require(LIBC.mount(None, os.fsencode(destination), None, 4096 | 32 | 1, None) == 0,
                    'read-only account bind failed')

    def independent(self, password, salt, memory=1024, passes=1):
        library = ctypes.CDLL(str(self.artifacts / 'libargon2.so.1'))
        function = library.argon2id_hash_raw
        function.argtypes = [ctypes.c_uint32] * 3 + [ctypes.c_void_p, ctypes.c_size_t] * 3
        function.restype = ctypes.c_int
        pw, sl, output = ctypes.create_string_buffer(password), ctypes.create_string_buffer(salt), ctypes.create_string_buffer(32)
        require(function(passes, memory, 1, pw, len(password), sl, len(salt), output, 32) == 0,
                'independent Argon2 failed')
        return output.raw

    def prepare(self):
        for module, device in [('bashos_auth_v2_test', DEVICE), ('bashos_auth_stage1', '/dev/bashos-auth')]:
            require(not Path('/sys/module', module).exists() and not os.path.lexists(device),
                    'preexisting authority must not be replaced')
        require(not any(os.path.lexists(path) for path in (self.root, self.trusted, self.executables)),
                'fresh guest fixture paths required')
        self.root.mkdir(mode=0o755); self.owned_directories.append(self.root)
        self.trusted.mkdir(mode=0o700); self.owned_directories.append(self.trusted)
        self.executables.mkdir(mode=0o755); self.owned_directories.append(self.executables)
        (self.root / 'lock').mkdir(mode=0o700)
        self.install(self.target, (self.artifacts / 'consumer-target').read_bytes(), 0o755)
        mount_flags = os.statvfs(self.target).f_flag
        require(not mount_flags & os.ST_NOEXEC, 'native target fixture is on a noexec mount')
        parents = []
        for parent in self.target.parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and
                    info.st_mode & 0o111 == 0o111, 'native target ancestor is unprotected or not traversable')
            parents.append({'path': str(parent), 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode)})
        require(sha(self.target) == self.receipt['files']['consumer-target']['sha256'], 'installed target pin differs')
        self.report['native_target_prerequisites'] = {
            'path': str(self.target), 'sha256': sha(self.target), 'mount_flags': mount_flags, 'parents': parents}
        (self.output / 'target-mountinfo.txt').write_bytes(Path('/proc/self/mountinfo').read_bytes())
        self.install(self.root / 'login.policy', b'version 2\nsession required lastlog\n', 0o600)
        check(self.independent(b'password', b'somesalt', 65536, 2).hex() ==
              '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7', 'independent known vector differs')
        derived = self.independent(PASSWORD, SALT)
        encode = lambda b: base64.b64encode(b).rstrip(b'=').decode()
        prefix = '$argon2id$v=19$m=1024,t=1,p=1$'
        self.standard = prefix + encode(SALT) + '$' + encode(derived)
        self.legacy = prefix + SALT.hex() + '$' + derived.hex()
        passwd, group, shadow = [Path('/etc', name).read_bytes() for name in ('passwd', 'group', 'shadow')]
        records = []
        for user, uid, gid, encoding in ACCOUNTS:
            require(not any(line.split(b':')[0] == user.encode() for line in passwd.splitlines()), 'fixture account exists')
            home = self.root / user; home.mkdir(mode=0o700); os.chown(home, uid, gid)
            phc = self.standard if encoding == 1 else self.legacy
            passwd += ('%s:x:%d:%d:Authority fixture:%s:%s\n' % (user, uid, gid, home, self.target)).encode()
            shadow += ('%s:%s:20000:0:99999:7:::\n' % (user, phc)).encode()
            if gid:
                require(not any(line.split(b':')[2:3] == [str(gid).encode()] for line in group.splitlines()), 'fixture gid exists')
                group += ('%s:x:%d:\n' % (user, gid)).encode()
            records.append(struct.pack('<IIII64s512s', uid, gid, encoding, 1, user.encode(), phc.encode()))
        snapshot = struct.pack('<IIIIQQ', 0x32564142, 2, 32 + 592 * len(records), len(records), 2, 0) + b''.join(records)
        self.install(self.trusted / 'accounts', snapshot)
        self.install(self.trusted / 'verifier', (self.artifacts / 'verifier-v2').read_bytes(), 0o700)
        require(LIBC.unshare(0x00020000) == 0, 'private mount namespace unavailable')
        require(LIBC.mount(None, b'/', None, 1 << 18 | 16384, None) == 0, 'cannot make mounts private')
        for name, data in [('passwd', passwd), ('group', group), ('shadow', shadow)]:
            path = self.trusted / name; self.install(path, data, 0o600 if name == 'shadow' else 0o644)
            self.bind(path, '/etc/' + name, True)
        for name, destination in [('utmp', '/var/run/utmp'), ('wtmp', '/var/log/wtmp'), ('lastlog', '/var/log/lastlog')]:
            path = self.trusted / name; self.install(path, b''); self.bind(path, destination)
        for name in ('bashos_auth_stage1', 'bashos_auth_v2_test'):
            require(not Path('/sys/module', name).exists(), 'unexpected concurrent module load')
            command = ['/usr/sbin/insmod', str(self.artifacts / (name + '.ko'))]
            if name.endswith('v2_test'):
                command += ['test_only=1', 'verifier_path=' + str(self.trusted / 'verifier'),
                            'verifier_sha256=' + sha(self.trusted / 'verifier'),
                            'accounts_path=' + str(self.trusted / 'accounts'),
                            'accounts_sha256=' + sha(self.trusted / 'accounts')]
            result = self.command(command)
            if result.returncode == 0 and Path('/sys/module', name).exists(): self.modules.append(name)
            require(result.returncode == 0 and name in self.modules, 'real module load failed')
        for device in (DEVICE, '/dev/bashos-auth'):
            for _ in range(100):
                if os.path.lexists(device): break
                time.sleep(.01)
            info = Path(device).lstat()
            require(stat.S_ISCHR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                    'authority device differs')
        result = self.command([self.args.bash, '--noprofile', '--norc', '-c', 'printf "%s\\n" "$BASH_VERSION"'])
        require(result.returncode == 0 and result.stdout.decode().strip().startswith('5.3.20('), 'Bash 5.3.20 required')
        self.report.update(bash_version=result.stdout.decode().strip(), account_snapshot_sha256=sha(self.trusted / 'accounts'),
                           verifier_sha256=sha(self.trusted / 'verifier'), phc_standard=self.standard, phc_legacy=self.legacy)
        hostname = Path('/etc/hostname').read_bytes()
        require(re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\n?', hostname) is not None,
                'bounded canonical guest hostname required for the prompt oracle')
        self.login_prompt = hostname.rstrip(b'\n') + b' login: '
        self.report['login_prompt_hex'] = self.login_prompt.hex()
        self.report['hostname_file_sha256'] = hashlib.sha256(hostname).hexdigest()

    def config(self, name, arguments, expected, program=None, fault=None):
        directory = self.output / name; directory.mkdir()
        program = Path(program or self.args.bash)
        config = {'schema': 1, 'uuid': self.args.expected_uuid, 'kernel': platform.release(),
                  'timeout': 40, 'trace': str(directory / 'trace.jsonl'), 'arguments': arguments,
                  'expected': expected, 'fault': fault}
        for key, path in [('listener', self.artifacts / 'auth-client-listener.py'),
                          ('libseccomp', self.artifacts / 'libseccomp.so.2'),
                          ('program', program), ('target', self.target)]:
            config[key], config[key + '_sha256'] = str(path), sha(path)
        config_path = directory / 'observer-config.json'
        self.install(config_path, (json.dumps(config, indent=2) + '\n').encode())
        return directory, config_path

    def trace_result(self, directory, expected, rejection=False):
        events = [json.loads(line) for line in (directory / 'trace.jsonl').read_text().splitlines()]
        verdict = self.observer.evaluate(events, expected)
        (directory / 'verdict.json').write_text(json.dumps(verdict, indent=2) + '\n')
        require(verdict['observation_complete'], 'observer setup/transport incomplete: ' + str(verdict))
        check(verdict['accepted'] != rejection, 'independent trace verdict differs: ' + str(verdict))
        return verdict

    def terminal(self, command, directory, inputs, timeout=45, extra_env=None):
        master, slave = pty.openpty(); tty = os.ttyname(slave)
        env = dict(self.environment, V2_TTY=tty, **(extra_env or {}))
        def child_setup():
            os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                   env=env, preexec_fn=child_setup, close_fds=True)
        data, sent, echo = bytearray(), 0, []
        cursor, deadline, signal_at = 0, time.monotonic() + timeout, None
        try:
            while True:
                require(time.monotonic() < deadline, 'terminal consumer timeout')
                ready, _, _ = select.select([master], [], [], .05)
                if ready:
                    try: block = os.read(master, 65536)
                    except OSError as failure:
                        if failure.errno == errno.EIO: block = b''
                        else: raise
                    if block: data.extend(block)
                if sent < len(inputs):
                    prompt, answer, secret = inputs[sent]
                    offset = data.lower().find(prompt.lower(), cursor)
                    if offset >= 0:
                        is_echo = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
                        echo.append({'prompt': prompt.decode(), 'secret': secret, 'echo': is_echo})
                        if secret: check(not is_echo, 'password terminal echo enabled')
                        if isinstance(answer, dict):
                            matches = re.findall(rb'LOGIN_ACTOR=([0-9]+)', data)
                            require(len(matches) == 1, 'one declared login actor required')
                            actor = int(matches[0]); actor_fd = os.pidfd_open(actor)
                            try:
                                status = dict(line.split(':', 1) for line in Path('/proc/%d/status' % actor).read_text().splitlines())
                                require(int(status['PPid']) == process.pid and
                                        list(map(int, status['Uid'].split())) == [0] * 4,
                                        'signal target must be the owned root observer child')
                                signal.pidfd_send_signal(actor_fd, answer['signal'])
                                signal_at = time.monotonic()
                            finally:
                                os.close(actor_fd)
                        else:
                            os.write(master, answer + b'\n')
                        cursor = len(data); sent += 1
                if process.poll() is not None:
                    # Drain queued output while the slave remains open here.
                    while select.select([master], [], [], .05)[0]:
                        try: block = os.read(master, 65536)
                        except OSError: break
                        if not block: break
                        data.extend(block)
                    break
            restored = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
            for _, answer, secret in inputs:
                if secret and isinstance(answer, bytes): check(answer not in data, 'password was echoed or printed')
            return {'exit_code': process.returncode, 'transcript': bytes(data), 'tty': tty,
                    'echo': echo, 'echo_restored': restored, 'input_complete': sent == len(inputs),
                    'signal_return_seconds': time.monotonic() - signal_at if signal_at is not None else None}
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
            (directory / 'transcript.bin').write_bytes(data)
            os.close(master); os.close(slave)

    def bash_case(self, name, script, expected, inputs=(), fault=None, wanted_status=0):
        arguments = ['--noprofile', '--norc', '-c', script]
        directory, config = self.config(name, arguments, expected, fault=fault)
        result = self.terminal(['/usr/bin/python3', '-B', str(self.artifacts / 'consumer-observer.py'), str(config)],
                               directory, inputs)
        verdict = self.trace_result(directory, expected)
        check(result['input_complete'], 'required prompt was not reached')
        check(result['exit_code'] == wanted_status, 'Bash consumer status differs: %s' % result['exit_code'])
        check(b'UNSAFE_RETURN' not in result['transcript'], 'credential failure returned to interpreter')
        check(result['echo_restored'], 'terminal echo was not restored')
        result['verdict'] = verdict
        return result

    def target_result(self, result, user, uid, gid, command=False):
        lines = [line.partition(b'AUTHORITY_TARGET_V2 ')[2] for line in result['transcript'].splitlines()
                 if b'AUTHORITY_TARGET_V2 ' in line]
        check(len(lines) == 1, 'one completed native target record required')
        target = json.loads(lines[0])
        check(target['uid'] == [uid] * 3 and target['gid'] == [gid] * 3 and target['groups'] == [gid],
              'actual target credentials/groups differ')
        decode = lambda text: bytes.fromhex(text).decode()
        argv = list(map(decode, target['argv_hex']))
        env = dict(decode(x).split('=', 1) for x in target['env_hex'])
        check(decode(target['cwd_hex']) == str(self.root / user), 'target cwd differs')
        check(env.get('USER') == user and env.get('LOGNAME') == user and env.get('HOME') == str(self.root / user)
              and env.get('SHELL') == str(self.target) and env.get('PATH') == '/bin:/bash-os:/usr/bin',
              'target safe environment differs')
        check('UNSAFE_FIXTURE_ENV' not in env and 'BASHAUTH_LOGIN_POLICY' not in env, 'caller environment leaked')
        if command:
            check(argv[1:] == ['-c', 'consumer-fixture', 'arg with space', 'quote"arg'], 'target argv differs')
        else:
            check(argv[1:] == ['--login'], 'interactive target argv differs')
        return target

    def cleanup(self):
        errors = []
        for module in reversed(self.modules):
            result = self.command(['/usr/sbin/rmmod', module])
            if result.returncode or Path('/sys/module', module).exists(): errors.append('module cleanup: ' + module)
        for path in reversed(self.mounts):
            if LIBC.umount2(os.fsencode(path), 0): errors.append('mount cleanup: ' + str(path))
        if not errors:
            for path in self.created: path.unlink()
            for path in reversed(self.owned_directories):
                if path.exists(): shutil.rmtree(path)
        require(not errors, '; '.join(errors))


def expected(exec_count=0, uid=0, gid=0, proof=False, fault=None):
    return {'exec_count': exec_count, 'uid': uid, 'gid': gid, 'require_proof': proof, 'fault': fault}


def auth_prefix(user='av2standard', legacy=False):
    verb = 'verify-login-v2-legacy-hex' if legacy else 'verify-login-v2'
    return ('auth open-v2-qualification FD || exit 91\n'
            'auth read-secret "$FD" -p "V2 password: " H || exit 92\n'
            'auth %s "$FD" "$H" %s || exit 93\n'
            'auth clear "$FD" "$H" || exit 94\n'
            '[[ $FD =~ ^[0-9]+$ && -z ${TOKEN+x} ]] || exit 95\n' % (verb, user))


def native_identity_controls(runtime):
    def identity(user='av2standard', uid=42101, gid=42102, encoding=1, purpose=1):
        return struct.pack('<IIII64s', purpose, uid, gid, encoding, user.encode())
    def attempt(fd, who, password=PASSWORD, legacy=False):
        handle = bytearray(8); fcntl.ioctl(fd, NEW, handle, True)
        index, _ = struct.unpack('<II', handle)
        data = ctypes.create_string_buffer(password)
        try:
            fcntl.ioctl(fd, WRITE, struct.pack('<IIQ', index, len(password), ctypes.addressof(data)))
            fcntl.ioctl(fd, SEAL, handle)
            fcntl.ioctl(fd, VERIFY_LEGACY if legacy else VERIFY, struct.pack('<IIII', 96, 2, index, 0) + who)
        finally: fcntl.ioctl(fd, CLEAR, handle)
    def consume(fd, value, who, reserved=0):
        fcntl.ioctl(fd, CONSUME, struct.pack('<IIII', 128, 2, reserved, 0) + who + value)
    def stream(fd):
        value = os.read(fd, 32); check(len(value) == 32 and os.read(fd, 1) == b'', 'proof stream differs'); return value
    def with_fd(function):
        fd = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC)
        try: function(fd)
        finally: os.close(fd)
    def positive(fd):
        who = identity(); attempt(fd, who); value = stream(fd); consume(fd, value, who)
        expect_errno(lambda: consume(fd, value, who), {errno.ENOENT})
    runtime.note('identity-public-positive-and-replay', lambda: with_fd(positive), 'actual-device')
    for field, who in [('uid', identity(uid=42105)), ('gid', identity(gid=42106)), ('purpose', identity(purpose=2)),
                       ('encoding', identity(encoding=2)), ('user', identity(user='av2other'))]:
        def changed(fd, who=who):
            original = identity(); attempt(fd, original); value = stream(fd)
            expect_errno(lambda: consume(fd, value, who), {errno.EACCES})
            expect_errno(lambda: consume(fd, value, original), {errno.ENOENT})
        runtime.note('identity-wrong-' + field + '-terminal', lambda fn=changed: with_fd(fn), 'actual-device')
    def replaced(fd):
        who = identity(); attempt(fd, who); value = stream(fd)
        expect_errno(lambda: attempt(fd, who, b'wrong-password'), {errno.EACCES})
        expect_errno(lambda: consume(fd, value, who), {errno.ENOENT})
    runtime.note('identity-failed-replacement-revokes-prior-proof', lambda: with_fd(replaced), 'actual-device')
    def bad_envelope(fd):
        who = identity(); attempt(fd, who); value = stream(fd)
        expect_errno(lambda: consume(fd, value, who, 1), {errno.EINVAL})
        expect_errno(lambda: consume(fd, value, who), {errno.ENOENT})
    runtime.note('identity-malformed-consume-spends-known-proof', lambda: with_fd(bad_envelope), 'actual-device')
    def copy_fault(fd):
        who = identity(); attempt(fd, who); value = stream(fd)
        expect_errno(lambda: fcntl.ioctl(fd, CONSUME, 0), {errno.EFAULT})
        expect_errno(lambda: consume(fd, value, who), {errno.ENOENT})
    runtime.note('identity-owned-consume-copy-fault-revokes', lambda: with_fd(copy_fault), 'actual-device')
    def foreign_fault(fd):
        who = identity(); attempt(fd, who); value = stream(fd)
        pid = os.fork()
        if not pid:
            try: expect_errno(lambda: fcntl.ioctl(fd, CONSUME, 0), {errno.EFAULT})
            except BaseException: os._exit(97)
            os._exit(0)
        waited, status = os.waitpid(pid, 0)
        check(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, 'foreign copy-fault child failed')
        consume(fd, value, who)
    runtime.note('identity-foreign-copy-fault-cannot-revoke', lambda: with_fd(foreign_fault), 'actual-device')
    def oracle(fd):
        who = identity(); attempt(fd, who); value = stream(fd)
        digest = hashlib.sha256(b'bashos-identity-v2' + struct.pack('<5I', 1, 42101, 42102, 1, 11) + b'av2standard').digest()
        # The independent private qualification decoder accepts only a matching
        # trusted claim. It does not compute the new identity digest for us.
        fcntl.ioctl(fd, 0x4090bb03, struct.pack('<IIII64s32s32s', 144, 2, 1, 0, b'av2standard', value, digest))
    runtime.note('identity-request-digest-independent-oracle', lambda: with_fd(oracle), 'actual-device')


def consumer_controls(runtime):
    prompt = [(b'V2 password: ', PASSWORD, True)]
    def production_unavailable():
        runtime.bash_case('production-v2-unavailable', 'auth open-v2 FD; [[ $? != 0 && -z ${FD+x} ]]', expected())
    runtime.note('production-v2-endpoint-stays-unavailable', production_unavailable)
    for mode, fault in [('continue-after-fault', 'setresuid'), ('ignore-saved-ids', None)]:
        def negative(mode=mode, fault=fault):
            want = expected(0 if fault else 1, 42101, 42102, fault=fault)
            directory, config = runtime.config('negative-' + mode,
                ['--observer-control', mode, '42101', '42102', str(runtime.target)], want,
                program=runtime.target, fault=fault)
            result = runtime.command(['/usr/bin/python3', '-B', runtime.artifacts / 'consumer-observer.py', config], timeout=45)
            (directory / 'stdout.bin').write_bytes(result.stdout); (directory / 'stderr.bin').write_bytes(result.stderr)
            verdict = runtime.trace_result(directory, want, rejection=True)
            check(verdict['target_exec_attempts'] == 1 and verdict['guard_denials'] == 1,
                  'negative actor did not exercise the exec oracle')
            if fault: check(verdict['selected_faults'] == 1, 'negative fault not selected exactly once')
            return verdict
        runtime.note('observer-rejects-' + mode, negative, 'independent-negative-observer-control')
    def orphan_negative():
        want = expected()
        directory, config = runtime.config('negative-orphan-connection',
            ['--observer-control', 'orphan-connection', '0', '0', str(runtime.target)], want,
            program=runtime.target)
        result = runtime.command(['/usr/bin/python3', '-B', runtime.artifacts / 'consumer-observer.py', config], timeout=45)
        (directory / 'stdout.bin').write_bytes(result.stdout); (directory / 'stderr.bin').write_bytes(result.stderr)
        verdict = runtime.trace_result(directory, want, rejection=True)
        events = [json.loads(line) for line in (directory / 'trace.jsonl').read_text().splitlines()]
        reaped = [row for row in events if row.get('phase') == 'orphan-reaped']
        check(result.returncode == 0 and verdict['orphaned_descendants'] == 1 and
              verdict['target_exec_attempts'] == verdict['guard_denials'] == verdict['selected_faults'] == 0 and
              len(reaped) == 1 and os.WIFSIGNALED(reaped[0]['raw_wait_status']) and
              os.WTERMSIG(reaped[0]['raw_wait_status']) == signal.SIGKILL and
              'launcher exited before an owned descendant' in verdict['reasons'],
              'negative actor did not exercise the orphan-lifetime oracle')
        return verdict
    runtime.note('observer-rejects-orphan-connection', orphan_negative, 'independent-negative-observer-control')
    for verb, phc in [('hash-secret-v2', runtime.standard), ('hash-secret-legacy-hex', runtime.legacy),
                      ('hash-secret', runtime.legacy)]:
        def producer(verb=verb, phc=phc):
            script = ('auth open FD || exit 91\nauth read-secret "$FD" -p "V2 password: " H || exit 92\n'
                      'auth %s "$FD" "$H" %s 1 1024 1 32 RESULT || exit 93\n'
                      'printf "PHC=%%s\\n" "$RESULT"\n' % (verb, SALT.hex()))
            result = runtime.bash_case('producer-' + verb, script, expected(), prompt)
            check(('PHC=' + phc).encode() in result['transcript'], 'independent standard/legacy PHC differs')
        runtime.note('actual-' + verb + '-independent-phc', producer)
    for user, uid, gid, legacy in [('av2standard', 42101, 42102, False), ('av2legacy', 42103, 42104, True)]:
        def successful(user=user, uid=uid, gid=gid, legacy=legacy):
            command = ('login become %s --auth-v2-fd "$FD" %s --no-login -c consumer-fixture -- '
                       "'arg with space' 'quote\"arg'\nprintf 'UNSAFE_RETURN\\n'\n" %
                       (user, '--auth-v2-legacy-hex' if legacy else ''))
            result = runtime.bash_case('auth-login-' + user, auth_prefix(user, legacy) + command,
                                       expected(1, uid, gid, True), prompt, wanted_status=37)
            visible = [line.strip() for line in result['transcript'].splitlines() if line.strip()]
            check(len(visible) == 2 and visible[0] == b'V2 password:' and
                  visible[1].startswith(b'AUTHORITY_TARGET_V2 '),
                  'fd-only auth path emitted unexpected bytes')
            return runtime.target_result(result, user, uid, gid, True)
        runtime.note('auth-proof-to-login-' + user, successful)
    def wrong_password():
        script = ('export BASHLOGIN_REQUIRE_KERNEL_TOKEN=0\n'
                  'auth open-v2-qualification FD || exit 91\nauth read-secret "$FD" -p "V2 password: " H || exit 92\n'
                  'auth verify-login-v2 "$FD" "$H" av2standard; vr=$?\n'
                  'login become av2standard --auth-v2-fd "$FD" -c forbidden; cr=$?\n'
                  '[[ $vr != 0 && $cr != 0 ]] || exit 97\n')
        runtime.bash_case('auth-wrong-password', script, expected(), [(b'V2 password: ', b'wrong-password', True)])
    runtime.note('wrong-password-cannot-enter-login', wrong_password)
    def wrong_target():
        script = auth_prefix() + 'login become av2other --auth-v2-fd "$FD" -c forbidden; [[ $? != 0 ]] || exit 97\n'
        runtime.bash_case('auth-wrong-login-target', script, expected(), prompt)
    runtime.note('verified-proof-rejects-different-login-target', wrong_target)
    def fork_transfer():
        script = auth_prefix() + ('( login become av2standard --auth-v2-fd "$FD" -c forbidden ); [[ $? != 0 ]] || exit 97\n'
                  'login become av2standard --auth-v2-fd "$FD" --no-login -c consumer-fixture -- '
                  "'arg with space' 'quote\"arg'\nprintf 'UNSAFE_RETURN\\n'\n")
        result = runtime.bash_case('auth-no-implicit-fork', script, expected(1, 42101, 42102, True), prompt, wanted_status=37)
        runtime.target_result(result, 'av2standard', 42101, 42102, True)
    runtime.note('fork-cannot-consume-parent-login-proof', fork_transfer)
    for fault in ('setgroups', 'setresgid', 'setresuid'):
        def credential_fault(fault=fault):
            script = auth_prefix() + 'login become av2standard --auth-v2-fd "$FD" -c forbidden\nprintf "UNSAFE_RETURN\\n"\n'
            runtime.bash_case('login-fault-' + fault, script, expected(0, 42101, 42102, True, fault), prompt,
                              fault=fault, wanted_status=126)
        runtime.note('real-proof-login-fails-closed-' + fault, credential_fault)
    def interactive():
        for name in ('utmp', 'wtmp', 'lastlog'): (runtime.trusted / name).write_bytes(b'')
        result = runtime.bash_case('login-interactive',
            'login login-v2 --qualification-device --max-tries 1 --policy-chain --no-motd -t "$V2_TTY"',
            expected(1, 42101, 42102, True), [(b' login: ', b'av2standard', False), (b'Password: ', PASSWORD, True)],
            wanted_status=37)
        target = runtime.target_result(result, 'av2standard', 42101, 42102)
        tty = result['tty'].removeprefix('/dev/')
        decoded = runtime.command([runtime.target, '--accounting', '42101', 'av2standard', tty])
        check(decoded.returncode == 0, 'independent accounting reader failed')
        account = json.loads(decoded.stdout.split(b'AUTHORITY_ACCOUNTING_V2 ', 1)[1])
        check(account['utmp'] == 1 and account['wtmp'] == 1 and account['lastlog'] == 1 and account['pid'] == target['pid'],
              'session accounting differs from executed actor')
        for name in ('utmp', 'wtmp', 'lastlog'):
            shutil.copyfile(runtime.trusted / name, runtime.output / 'login-interactive' / (name + '.bin'))
        return {'target': target, 'accounting': account}
    runtime.note('interactive-real-proof-accounting-and-exec', interactive)
    for name in ('av2standard', 'no-such-v2-user', '../invalid'):
        def interactive_denied(name=name):
            result = runtime.bash_case('interactive-denied-' + re.sub('[^a-zA-Z0-9]', '_', name),
                'login login-v2 --qualification-device --max-tries 1 --no-motd', expected(),
                [(b' login: ', name.encode(), False), (b'Password: ', b'wrong-password', True)], wanted_status=1)
            check(b'Login incorrect' in result['transcript'], 'login failure transcript differs')
        runtime.note('interactive-denied-' + re.sub('[^a-zA-Z0-9]', '_', name), interactive_denied)


def login_session_controls(runtime):
    policy = runtime.root / 'login.policy'
    saved_policy = policy.read_bytes()
    login = 'login login-v2 --qualification-device --max-tries 1 --no-motd'
    prompts = [(b' login: ', b'av2standard', False), (b'Password: ', PASSWORD, True)]

    def clear_accounting():
        for name in ('utmp', 'wtmp', 'lastlog'): (runtime.trusted / name).write_bytes(b'')

    def empty_accounting():
        check(all((runtime.trusted / name).stat().st_size == 0 for name in ('utmp', 'wtmp', 'lastlog')),
              'denied session wrote accounting')

    def record_check(result, user='av2standard', uid=42101, gid=42102):
        target = runtime.target_result(result, user, uid, gid)
        tty = result['tty'].removeprefix('/dev/')
        decoded = runtime.command([runtime.target, '--accounting', str(uid), user, tty])
        require(decoded.returncode == 0, 'independent accounting decoder failed')
        account = json.loads(decoded.stdout.split(b'AUTHORITY_ACCOUNTING_V2 ', 1)[1])
        check(account['utmp'] == account['wtmp'] == account['lastlog'] == 1 and account['pid'] == target['pid'],
              'mandatory session accounting does not match actual actor/terminal')
        return {'target': target, 'accounting': account}

    def default_session():
        policy.write_bytes(b'version 2\n'); clear_accounting()
        result = runtime.bash_case('login-default-session', login, expected(1, 42101, 42102, True),
                                   prompts, wanted_status=37)
        check(result['transcript'].count(runtime.login_prompt) == 1,
              'successful session did not exercise the exact hostname prompt oracle')
        return record_check(result)

    def terminal_mismatch():
        clear_accounting()
        result = runtime.bash_case('login-wrong-terminal', login + ' -t /dev/null', expected(), wanted_status=1)
        # Bash's builtin_error prefix contains " login: ". Match the complete
        # hostname prompt instead of confusing that diagnostic with input.
        check(runtime.login_prompt not in result['transcript'] and b'Password: ' not in result['transcript'],
              'terminal mismatch reached prompts')
        events = [json.loads(line) for line in
                  (runtime.output / 'login-wrong-terminal' / 'trace.jsonl').read_text().splitlines()]
        check(not any(event.get('identity_operation') or
                      event.get('syscall') in ('setgroups', 'setresgid', 'setresuid', 'setuid', 'setgid', 'setreuid', 'setregid') or
                      (event.get('syscall') == 'ioctl' and event['args'][1] in (0x5402, 0x5403, 0x5404))
                      for event in events), 'terminal mismatch reached auth, credentials or terminal mutation')
        exits = [event for event in events if event.get('syscall') in ('exit', 'exit_group')]
        check(len(exits) == 1 and exits[0]['args'][0] == 1 and
              exits[0]['notifying']['uid'] == [0] * 4 and exits[0]['notifying']['gid'] == [0] * 4,
              'terminal mismatch exit status/IDs differ')
        empty_accounting()

    def redirected_stdio():
        clear_accounting()
        runtime.bash_case('login-redirected-stdio', login + ' >/dev/null', expected(), wanted_status=1)
        empty_accounting()

    restored = ('RESTORED=0\ntrap \'RESTORED=$((RESTORED+1))\' HUP TERM INT\n'
                'printf "LOGIN_ACTOR=%s\\n" "$BASHPID"\n')
    after_return = ('\nrc=$?; [[ $rc == 1 ]] || exit 98\n'
                    'kill -HUP "$BASHPID"; kill -TERM "$BASHPID"; kill -INT "$BASHPID"\n'
                    '[[ $RESTORED == 3 ]] || exit 99\nprintf "LOGIN_HANDLERS_RESTORED\\n"\n')

    def restored_on_denial():
        policy.write_bytes(b'version 2\n'); clear_accounting()
        result = runtime.bash_case('login-denial-restores-handlers', restored + login + after_return,
            expected(), [(b' login: ', b'av2standard', False), (b'Password: ', b'wrong-password', True)])
        check(b'LOGIN_HANDLERS_RESTORED' in result['transcript'], 'original handlers not effective')
        empty_accounting()

    def suppressed_echo_failure():
        policy.write_bytes(b'version 2\n'); clear_accounting()
        result = runtime.bash_case('login-failed-echo-suppression', restored + login + after_return,
            expected(fault='tty-hide'), [(b' login: ', b'av2standard', False)], fault='tty-hide')
        check(b'Password: ' not in result['transcript'] and b'LOGIN_HANDLERS_RESTORED' in result['transcript'],
              'failed echo suppression reached secret prompt or failed cleanup')
        empty_accounting()

    def denied_session():
        clear_accounting()
        policy.write_bytes(b'version 2\nsession required lastlog\nsession required deny all\n')
        runtime.bash_case('login-denied-session-accounting', login + ' --policy-chain',
                         expected(0, 42101, 42102, True), prompts, wanted_status=1)
        empty_accounting()

    def denied_auth():
        clear_accounting()
        policy.write_bytes(b'version 2\nauth optional lastlog\n')
        runtime.bash_case('login-denied-auth-accounting', login + ' --policy-chain', expected(),
            [(b' login: ', b'av2standard', False), (b'Password: ', b'wrong-password', True)], wanted_status=1)
        empty_accounting()

    try:
        for name, data, phase in [
            ('chain-overflow', b'version 2\n' + b'session optional lastlog\n' * 64 + b'session required deny all\n', 'session'),
            ('field-overflow', b'version 2\naccount required securetty ' + b'off ' * 29 + b'invalid\n', 'account')]:
            def policy_bound(name=name, data=data, phase=phase):
                policy.write_bytes(data)
                runtime.bash_case('login-policy-' + name,
                    'login policy-eval ' + phase + '; [[ $? != 0 ]] || exit 98', expected())
            runtime.note('login-policy-rejects-' + name, policy_bound)
        runtime.note('login-default-real-terminal-and-all-accounting', default_session)
        runtime.note('login-explicit-terminal-mismatch-denied', terminal_mismatch)
        runtime.note('login-redirected-stdio-denied', redirected_stdio)
        runtime.note('login-denial-restores-original-signal-handlers', restored_on_denial)
        for name, sig in [('hup', signal.SIGHUP), ('term', signal.SIGTERM), ('int', signal.SIGINT)]:
            def cancellation(name=name, sig=sig):
                clear_accounting(); policy.write_bytes(b'version 2\n')
                result = runtime.bash_case('login-password-cancel-' + name, restored + login + after_return,
                    expected(), [(b' login: ', b'av2standard', False), (b'Password: ', {'signal': sig}, True)])
                check(b'LOGIN_HANDLERS_RESTORED' in result['transcript'] and
                      result['signal_return_seconds'] is not None and result['signal_return_seconds'] < 3,
                      'password cancellation did not promptly return and restore handlers')
                empty_accounting()
            runtime.note('login-password-cancel-' + name, cancellation)
        runtime.note('login-echo-suppression-fault-refuses-password', suppressed_echo_failure)
        runtime.note('login-session-policy-denial-before-accounting', denied_session)
        runtime.note('login-auth-policy-cannot-record-before-password', denied_auth)
        for name in ('utmp', 'wtmp'):
            def corrupt_accounting(name=name):
                clear_accounting(); policy.write_bytes(b'version 2\n')
                path = runtime.trusted / name; path.write_bytes(b'partial-record')
                runtime.bash_case('login-corrupt-' + name, login, expected(0, 42101, 42102, True),
                                  prompts, wanted_status=1)
                check(path.read_bytes() == b'partial-record', 'malformed accounting file was modified')
            runtime.note('login-rejects-truncated-' + name, corrupt_accounting)
        def linked_lastlog():
            clear_accounting(); policy.write_bytes(b'version 2\n')
            link = runtime.trusted / 'lastlog-alias'; os.link(runtime.trusted / 'lastlog', link)
            try:
                runtime.bash_case('login-linked-lastlog', login, expected(0, 42101, 42102, True),
                                  prompts, wanted_status=1)
                check(not link.read_bytes(), 'multiply linked accounting file was modified')
            finally:
                link.unlink()
        runtime.note('login-accounting-file-alias-refuses-exec', linked_lastlog)
        for label, directive, valid in (
            ('relative-pts', 'tty=pts/3', True),
            ('duplicate', 'tty=pts/3,pts/3', True),
            ('32-entries', 'tty=' + ','.join('pts/%d' % n for n in range(32)), True),
            ('33-entries', 'tty=' + ','.join('pts/%d' % n for n in range(33)), False),
            ('empty-entry', 'tty=tty1,,pts/3', False),
            ('trailing-comma', 'tty=tty1,', False),
            ('absolute', 'tty=/dev/pts/3', False),
            ('traversal', 'tty=pts/../3', False),
            ('dot-component', 'tty=pts/./3', False),
            ('empty-component', 'tty=pts//3', False),
            ('wildcard', 'tty=pts/*', False),
            ('long-terminal', 'tty=' + 'x' * 64, False),
            ('long-file', 'file=/' + 'x' * 255, False),
        ):
            def securetty_parser(label=label, directive=directive, valid=valid):
                policy.write_text('version 2\naccount required securetty ' + directive + '\n')
                runtime.bash_case('login-securetty-parser-' + label,
                    'login policy-eval auth; rc=$?; [[ $rc == %d ]]' % (0 if valid else 1), expected())
            runtime.note('login-securetty-parser-' + label, securetty_parser)
        empty = runtime.root / 'empty-securetty'; runtime.install(empty, b'')
        for allow in (False, True):
            def securetty(allow=allow):
                clear_accounting()
                tty = '"${V2_TTY#/dev/}"' if allow else 'forbidden-terminal'
                script = ('printf "version 2\\naccount required securetty file=%s tty=%%s\\n" %s '
                          '>"$BASHAUTH_LOGIN_POLICY"\n' % (empty, tty)) + login
                case_name = 'login-root-securetty-' + str(int(allow))
                try:
                    result = runtime.bash_case(case_name, script,
                        expected(int(allow), 0, 0, True),
                        [(b' login: ', b'av2root', False), (b'Password: ', PASSWORD, True)],
                        wanted_status=37 if allow else 1)
                finally:
                    if (runtime.output / case_name).exists():
                        (runtime.output / case_name / 'policy-input.txt').write_bytes(policy.read_bytes())
                wanted_policy = ('version 2\naccount required securetty file=%s tty=%s\n' %
                                 (empty, result['tty'].removeprefix('/dev/') if allow else 'forbidden-terminal')).encode()
                actual_policy = policy.read_bytes()
                require(actual_policy == wanted_policy, 'securetty fixture policy bytes differ')
                if allow: return record_check(result, 'av2root', 0, 0)
                empty_accounting()
            runtime.note('login-root-securetty-' + ('allows-actual-terminal' if allow else 'denies-other-terminal'), securetty)
    finally:
        policy.write_bytes(saved_policy)


def ssh_controls(runtime):
    for name, pin in runtime.receipt['guest_tools'].items(): protected(pin['path'], pin['sha256'])
    ssh = runtime.receipt['guest_tools']['ssh']['path']
    keygen = runtime.receipt['guest_tools']['ssh-keygen']['path']
    version = runtime.command([ssh, '-V'])
    runtime.report['independent_openssh'] = {'version': version.stderr.decode(errors='replace'),
                                           'pins': runtime.receipt['guest_tools']}
    hostkey = runtime.trusted / 'ssh-hostkey'
    require(runtime.command([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', hostkey]).returncode == 0,
            'independent host-key generation failed')
    clientkey = runtime.trusted / 'ssh-clientkey'
    require(runtime.command([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', clientkey]).returncode == 0,
            'independent client-key generation failed')
    authorized = runtime.root / 'av2root/.ssh'
    authorized.mkdir(mode=0o700)
    runtime.install(authorized / 'authorized_keys', clientkey.with_suffix('.pub').read_bytes())
    scenarios = [('standard', 'av2standard', 42101, 42102, 'yes', False, PASSWORD, True),
                 ('wrong-password', 'av2standard', 42101, 42102, 'yes', False, b'wrong-password', False),
                 ('root-yes', 'av2root', 0, 0, 'yes', False, PASSWORD, True),
                 ('root-no', 'av2root', 0, 0, 'no', False, PASSWORD, False),
                 ('root-prohibit-password', 'av2root', 0, 0, 'prohibit-password', False, PASSWORD, False),
                 ('root-match-no', 'av2root', 0, 0, 'yes', False, PASSWORD, False),
                 ('root-key-prohibit-password', 'av2root', 0, 0, 'prohibit-password', False, None, True),
                 ('root-key-no', 'av2root', 0, 0, 'no', False, None, False),
                 ('legacy', 'av2legacy', 42103, 42104, 'yes', True, PASSWORD, True),
                 ('legacy-wrong-route', 'av2legacy', 42103, 42104, 'yes', False, PASSWORD, False)]
    for label, user, uid, gid, root_policy, legacy, password, allow in scenarios:
        def scenario(label=label, user=user, uid=uid, gid=gid, root_policy=root_policy,
                     legacy=legacy, password=password, allow=allow):
            listener = socket.socket(); listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]; listener.close()
            policy = runtime.root / ('sshd-' + label + '.conf')
            key_mode = password is None
            configuration = 'PasswordAuthentication %s\nPermitRootLogin %s\nLoginGraceTime 12\nMaxAuthTries 1\n' % (
                'no' if key_mode else 'yes', root_policy)
            if label == 'root-match-no': configuration += 'Match User av2root\n    PermitRootLogin no\n'
            runtime.install(policy, configuration.encode())
            options = ['sshd', 'run', '--encrypted', '--authority-v2-legacy-hex' if legacy else '--authority-v2',
                       '--authority-v2-qualification', '--once', '-a', '127.0.0.1', '-p', str(port), '-k', str(hostkey),
                       '-F', str(policy), '--auth-method', 'publickey' if key_mode else 'password', '-u', user]
            want = expected(int(allow), uid, gid, allow and not key_mode)
            want['delegated'] = not key_mode
            directory, config = runtime.config('ssh-' + label,
                ['--noprofile', '--norc', '-c', shlex.join(options)], want)
            output = (directory / 'server-output.bin').open('wb')
            server = subprocess.Popen(['/usr/bin/python3', '-B', str(runtime.artifacts / 'consumer-observer.py'), str(config)],
                                      stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                      env=runtime.environment, start_new_session=True)
            try:
                deadline = time.monotonic() + 8
                while True:
                    require(server.poll() is None and time.monotonic() < deadline, 'SSH listener did not start')
                    rows = Path('/proc/net/tcp').read_text().splitlines()[1:]
                    if any(row.split()[1].split(':')[1] == '%04X' % port and row.split()[3] == '0A' for row in rows): break
                    time.sleep(.02)
                argv = [ssh, '-vv', '-E', str(directory / 'client-debug.txt'),
                        '-F', '/dev/null', '-p', str(port), '-o', 'StrictHostKeyChecking=no',
                        '-o', 'UserKnownHostsFile=/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null',
                        '-o', 'NumberOfPasswordPrompts=1', '-o', 'ConnectTimeout=5', '-o', 'RequestTTY=no',
                        '-o', 'PreferredAuthentications=' + ('publickey' if key_mode else 'password'),
                        '-o', 'PubkeyAuthentication=' + ('yes' if key_mode else 'no')]
                if key_mode: argv += ['-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no', '-i', str(clientkey)]
                argv += [user + '@127.0.0.1', 'consumer-ssh-fixture']
                (directory / 'client-argv.json').write_text(json.dumps(argv, indent=2) + '\n')
                client = runtime.terminal(argv, directory, [] if key_mode else [(b'password: ', password, True)], timeout=25)
                server_status = server.wait(timeout=10)
                exchange = {'server_status': server_status, 'client_status': client['exit_code'],
                            'client_input_complete': client['input_complete'], 'client_echo': client['echo'],
                            'transcript_sha256': sha(directory / 'transcript.bin')}
                (directory / 'exchange.json').write_text(json.dumps(exchange, indent=2) + '\n')
                verdict = runtime.trace_result(directory, want)
                check(client['input_complete'], 'independent SSH client did not send the required credential')
                check(server_status == (0 if allow else 1), 'SSH one-connection child status differs')
                check(client['exit_code'] == (37 if allow else 255), 'independent SSH client status differs')
                if label in ('wrong-password', 'legacy-wrong-route'):
                    events = [json.loads(line) for line in (directory / 'trace.jsonl').read_text().splitlines()]
                    operations = [row for row in events if row.get('identity_operation')]
                    check(len(operations) == 1 and operations[0]['identity_operation'] == 'verify' and
                          operations[0]['actual_authority_fd'] and
                          operations[0]['identity_request'] == [4, uid, gid, 1, user],
                          'negative SSH password case did not reach its exact verification request')
                completed = [line for line in client['transcript'].splitlines() if b'AUTHORITY_TARGET_V2 ' in line]
                check(len(completed) == int(allow), 'SSH actual target count differs')
                if allow:
                    value = json.loads(completed[0].split(b'AUTHORITY_TARGET_V2 ', 1)[1])
                    check(value['uid'] == [uid] * 3 and value['gid'] == [gid] * 3 and value['groups'] == [gid],
                          'SSH target IDs/groups differ')
                output.flush()
                text = (directory / 'server-output.bin').read_bytes()
                accepted = b'accepted publickey for ' if key_mode else b'accepted password for '
                check((accepted in text) == allow, 'SSH authentication acknowledgement differs')
                return dict(exchange, verdict=verdict)
            finally:
                if server.poll() is None: os.killpg(server.pid, signal.SIGKILL); server.wait()
                output.close()
        runtime.note('actual-ssh-' + label, scenario)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', type=Path, required=True); parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--bash', type=Path, required=True); parser.add_argument('--bash-sha256', required=True)
    parser.add_argument('--expected-uuid', required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    protected(args.receipt, args.receipt_sha256)
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-consumer-v2-build-only', 'unknown receipt')
    guard(args.expected_uuid, receipt['kernel_release'])
    protected(args.bash, args.bash_sha256)
    artifacts = args.receipt.resolve().parent
    require(args.bash.is_absolute() and args.output.is_absolute() and args.output.resolve().is_relative_to(HOME)
            and not args.output.exists(), 'absolute candidate and fresh private output required')
    for name, pin in receipt['files'].items():
        require(Path(name).name == name, 'invalid artifact name')
        protected(artifacts / name, pin['sha256'])
        require((artifacts / name).stat().st_size == pin['bytes'], 'artifact size differs')
    require(sha(Path(__file__)) == receipt['files']['guest-consumers.py']['sha256'], 'observer source differs')
    args.output.mkdir(mode=0o700)
    runtime = Runtime(args, receipt)
    before = runtime.command(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        runtime.prepare()
        native_identity_controls(runtime)
        consumer_controls(runtime)
        login_session_controls(runtime)
        ssh_controls(runtime)
        require(len(runtime.cases) == 70 and all(row['status'] == 'PASS' for row in runtime.cases),
                'consumer control set incomplete')
        runtime.report['control_counts'] = {'actual_device': 11, 'actual_consumer': 56, 'negative_observer': 3}
        runtime.report['versioned_identity_consumers_executed'] = True
        runtime.report['literal_legacy_abi_qualification'] = False
        runtime.report['status'] = 'PASS'
    except AssertionError as error:
        runtime.report.update(status='FAIL', reason=str(error))
    except Exception as error:
        runtime.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        # A later teardown or kernel-log error must not replace the reached
        # behavioral FAIL. Each gate remains mandatory and separately visible.
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
            forbidden = (b'WARNING:', b'BUG:', b'KASAN:', b'KCSAN:', b'UBSAN:', b'held lock', b'Oops:',
                         b'possible recursive locking', b'inconsistent lock state', b'general protection fault', b'INFO: task ')
            require(not any(term.lower() in delta.lower() for term in forbidden), 'kernel warning/fault evidence')
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
        print('Consumer v2 preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
