#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""First real-device PRIVCMD v2 controls, ONLY in an attested disposable guest.

Includes actual auth/doas/sudo commands. This bounded packet does not qualify
safeedit, interactive replacement, or the independent executor-fault observer.
No model or device-only success awards an original consumer obligation.
"""
import argparse
import base64
import ctypes as C
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import select
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
import traceback
import uuid

sys.dont_write_bytecode = True
CASE, HOME = Path('/tmp/parity-case'), Path('/tmp/parity-home')
DEVICE, MODULE = '/dev/bashos-privcmd-v2-test', 'bashos_privcmd_v2_test'
PASSWORD, SALT = b'privcmd-v2-fixture-password', b'privcmd-v2-salt'
CALLER, TARGET, LEGACY, SHARED = 43201, 43202, 43203, 43204
LIBC = C.CDLL(None, use_errno=True)
LIBC.mount.argtypes = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_ulong, C.c_void_p]
LIBC.umount2.argtypes = [C.c_char_p, C.c_int]
U32, U64 = C.c_uint32, C.c_uint64


class Request(C.Structure):
    _fields_ = [(n, U32) for n in ('size mode flags non_interactive caller_uid caller_gid target_uid target_gid '
                                  'argc envc argv_bytes env_bytes').split()] + [
        ('argv_user_ptr', U64), ('env_user_ptr', U64), ('auth_token', C.c_ubyte * 32),
        ('request_digest', C.c_ubyte * 32), ('caller_user', C.c_char * 64), ('target_user', C.c_char * 64),
        ('cwd', C.c_char * 256)] + [(n, U32) for n in 'decision env_policy timestamp_timeout policy_generation policy_status reserved0'.split()] + [
        ('audit_id', U64), ('exec_token', C.c_ubyte * 32), ('policy_digest', C.c_ubyte * 32),
        ('normalized_policy_digest', C.c_ubyte * 32), ('reason', C.c_char * 128),
        ('handle_id', U64), ('handle_expires_sec', U64), ('reserved', U64 * 6)]


class Prepare(C.Structure):
    _fields_ = [('size', U32), ('version', U32), ('reserved', U32 * 2), ('request', Request)] + [
        (n, U32) for n in 'decision reason encoding cache_hit'.split()] + [
        (n, U64) for n in 'request_id deadline_ns audit_sequence'.split()]


def ioc(direction, number, size=0): return direction << 30 | size << 16 | 0xbd << 8 | number
PREPARE, VERIFY, VERIFY_LEGACY, RUN = ioc(3, 1, 888), ioc(3, 2, 72), ioc(3, 3, 72), ioc(3, 4, 80)
RESET, CANCEL = ioc(3, 5, 24), ioc(0, 6)
PEEK, ACK, AUDIT_VERIFY, AUDIT_INFO = ioc(2, 16, 800), ioc(1, 17, 16), ioc(1, 18, 800), ioc(2, 19, 40)
NEW, WRITE, SEAL = 0xc008ba02, 0x4010ba03, 0x4008ba04


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def check(ok, reason):
    if not ok: raise AssertionError(reason)


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path, pin):
    st = Path(path).lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022 and sha(path) == pin,
            'unprotected or mismatched input: ' + str(path))


def guard(token, release):
    require(__debug__ and platform.machine() == 'x86_64', 'debug x86-64 guest required')
    require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'guest root required')
    require(Path.cwd() == CASE and os.environ.get('HOME') == str(HOME), 'private parity scratch required')
    token = str(uuid.UUID(token))
    require(Path('/etc/bashos-parity-vm').read_text().strip() == token and
            Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'guest UUID differs')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'attested disposable evaluator required')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU' and
            platform.release() == release, 'guest/kernel differs')
    require(not Path('/sys/module', MODULE).exists() and not os.path.lexists(DEVICE), 'preexisting authority')
    require(C.sizeof(Request) == 832 and C.sizeof(Prepare) == 888, 'independent wire layout differs')


def rejects(function, values):
    try: function()
    except OSError as error:
        check(error.errno in values, 'errno %s, expected %s' % (error.errno, sorted(values)))
        return
    raise AssertionError('negative operation succeeded')


def ioctl_struct(fd, op, value):
    data = bytearray(bytes(value)); fcntl.ioctl(fd, op, data, True)
    return type(value).from_buffer_copy(data)


def prepare(fd, command, arguments=(), user='pcv2caller', uid=CALLER, env=(), mode=1, noninteractive=0):
    values = [str(command), *arguments] if mode == 1 else []
    argv_blob = b''.join(os.fsencode(x) + b'\0' for x in values)
    env_blob = b''.join(os.fsencode(x) + b'\0' for x in env)
    argv, environment = C.create_string_buffer(argv_blob), C.create_string_buffer(env_blob)
    p = Prepare(); p.size = C.sizeof(p); p.version = 2
    r = p.request; r.size = C.sizeof(r); r.mode = mode; r.non_interactive = noninteractive
    r.caller_uid = uid; r.caller_gid = uid; r.target_uid = TARGET; r.target_gid = TARGET
    r.argc = len(values); r.envc = len(env); r.argv_bytes = len(argv_blob); r.env_bytes = len(env_blob)
    r.argv_user_ptr = C.addressof(argv) if argv_blob else 0
    r.env_user_ptr = C.addressof(environment) if env_blob else 0
    r.caller_user = user.encode(); r.target_user = b'pcv2target'; r.cwd = os.fsencode(os.getcwd())
    # The established C wire framing hashes exactly 16 domain bytes: the
    # trailing ASCII '1' in its source literal is outside that length.
    # Spell those bytes explicitly; do not derive the oracle from candidate code.
    frame = b'bashos-privcmd-v' + struct.pack('<11I', r.mode, r.flags, r.non_interactive,
        r.caller_uid, r.caller_gid, r.target_uid, r.target_gid, r.argc, r.envc, r.argv_bytes, r.env_bytes)
    for value in (r.caller_user, r.target_user, r.cwd): frame += struct.pack('<I', len(value)) + value
    digest = hashlib.sha256(frame + argv_blob + env_blob).digest()
    r.request_digest[:] = digest
    out = ioctl_struct(fd, PREPARE, p)
    check(bytes(out.request.request_digest) == digest, 'kernel request digest differs from independent oracle')
    return out


def verify(fd, prepared, password=PASSWORD, legacy=False):
    handle = bytearray(8); fcntl.ioctl(fd, NEW, handle, True); ident, flags = struct.unpack('<II', handle)
    check(ident and not flags, 'secret handle malformed')
    raw = C.create_string_buffer(password)
    fcntl.ioctl(fd, WRITE, struct.pack('<IIQ', ident, len(password), C.addressof(raw)))
    fcntl.ioctl(fd, SEAL, struct.pack('<II', ident, 0))
    request = bytearray(struct.pack('<IIIIQ32sQQ', 72, 2, ident, 0, prepared.request_id,
                                   bytes(prepared.request.request_digest), 0, 0))
    fcntl.ioctl(fd, VERIFY_LEGACY if legacy else VERIFY, request, True)
    deadline, audit = struct.unpack_from('<QQ', request, 56)
    check(deadline and audit, 'verified grant response malformed')


def redeem(fd, prepared):
    data = bytearray(struct.pack('<IIIIQ32sIIIIQ', 80, 2, 0, 0, prepared.request_id,
                                bytes(prepared.request.request_digest), 0, 0, 0, 0, 0))
    fcntl.ioctl(fd, RUN, data, True)
    return struct.unpack_from('<IIIIQ', data, 56)


def reset(fd, all_sessions=False):
    data = bytearray(struct.pack('<IIIIQ', 24, 2, int(all_sessions), 0, 0))
    fcntl.ioctl(fd, RESET, data, True)
    check(struct.unpack_from('<Q', data, 16)[0] != 0, 'reset missing audit receipt')


class Runtime:
    def __init__(self, args, receipt):
        self.args, self.receipt, self.artifacts = args, receipt, args.receipt.parent
        self.root = Path('/var/lib') / ('bashos-privcmd-v2-' + str(uuid.UUID(args.expected_uuid)))
        self.work = self.root / 'work'; self.nopass = self.root / 'target-nopass'; self.password = self.root / 'target-password'
        self.cases, self.commands, self.mounts = [], [], []
        self.created = self.loaded = False
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(HOME), 'LANG': 'C', 'LC_ALL': 'C',
                    'TERM': 'xterm', 'KEEP_ME': 'inherited-kept', 'UNSAFE_FIXTURE': 'must-disappear'}
        self.report = {'schema': 1, 'status': 'ERROR', 'cases': self.cases, 'guest_uuid': args.expected_uuid,
            'kernel': receipt['kernel_release'], 'bash_sha256': args.bash_sha256,
            'receipt_sha256': args.receipt_sha256, 'all_nine_topics_qualified': False,
            'production_features_enabled': False, 'literal_legacy_abi_qualified': False,
            'blocking_gaps': ['independent executor fault observer and deliberate bad-executor controls',
                              'safeedit all-target preflight and fresh authenticated copyback',
                              'interactive replacement/session requirements', 'complete consumer obligation matrix']}

    def command(self, argv):
        r = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, env=self.env)
        self.commands.append({'argv': [str(x) for x in argv], 'exit_code': r.returncode,
            'stdout_base64': base64.b64encode(r.stdout).decode(), 'stderr_base64': base64.b64encode(r.stderr).decode()})
        return r

    def install(self, path, data, mode=0o600):
        with path.open('xb') as f: f.write(data)
        path.chmod(mode)

    def setup(self):
        require(not self.root.exists(), 'fresh guest fixture directory required')
        self.root.mkdir(mode=0o755); self.created = True
        require(LIBC.unshare(0x00020000) == 0 and LIBC.mount(None, b'/', None, (1 << 18) | 16384, None) == 0,
                'private mount namespace required')
        require(LIBC.mount(b'tmpfs', os.fsencode(self.root), b'tmpfs', 2 | 4,
                           C.c_char_p(b'size=32m,mode=0755')) == 0, 'private local executable filesystem required')
        self.mounts.append(self.root)
        self.work.mkdir(mode=0o755); os.chown(self.work, CALLER, CALLER)
        for path in (self.nopass, self.password): self.install(path, (self.artifacts / 'privcmd-target').read_bytes(), 0o755)
        # A root-owned executable-mode FIFO in a trusted directory must be
        # rejected before its open operation can wait for a writer.
        os.mkfifo(self.root / 'executable-fifo', 0o755)
        (self.root / 'executable-fifo').chmod(0o755)
        library = C.CDLL(str(self.artifacts / 'libargon2.so.1')); derive = library.argon2id_hash_raw
        derive.argtypes = [C.c_uint32] * 3 + [C.c_void_p, C.c_size_t] * 3; derive.restype = C.c_int
        def digest(password, salt, memory, passes):
            pw, sl, result = C.create_string_buffer(password), C.create_string_buffer(salt), C.create_string_buffer(32)
            require(derive(passes, memory, 1, pw, len(password), sl, len(salt), result, 32) == 0, 'independent Argon2 failed')
            return result.raw
        check(digest(b'password', b'somesalt', 65536, 2).hex() ==
              '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7', 'independent Argon2 known vector')
        derived = digest(PASSWORD, SALT, 1024, 1)
        encode = lambda b: base64.b64encode(b).rstrip(b'=').decode()
        standard = '$argon2id$v=19$m=1024,t=1,p=1$' + encode(SALT) + '$' + encode(derived)
        legacy = '$argon2id$v=19$m=1024,t=1,p=1$' + SALT.hex() + '$' + derived.hex()
        records, profiles = [], []
        passwd, group = Path('/etc/passwd').read_bytes(), Path('/etc/group').read_bytes()
        users = [('pcv2caller', CALLER, 1), ('pcv2target', TARGET, 1), ('pcv2legacy', LEGACY, 2), ('root', 0, 1)]
        for name, uid, encoding in users:
            home = self.root / (name + '-home'); home.mkdir(mode=0o700); os.chown(home, uid, uid)
            if uid:
                require(not any(line.split(b':')[0] == name.encode() or line.split(b':')[2:3] == [str(uid).encode()]
                                for line in passwd.splitlines()), 'fixture user exists')
                line = '%s:x:%d:%d:Fixture:%s:%s\n' % (name, uid, uid, home, self.nopass)
                passwd += line.encode(); group += ('%s:x:%d:\n' % (name, uid)).encode()
            profiles.append('%s:x:%d:%d:Fixture:%s:%s\n' % (name, uid, uid, home, self.nopass))
            records.append(struct.pack('<IIII64s512s', uid, uid, encoding, 1, name.encode(),
                                       (standard if encoding == 1 else legacy).encode()))
        self.install(self.root / 'accounts', struct.pack('<IIIIQQ', 0x32564142, 2, 32 + 592 * len(records), len(records), 3, 0) + b''.join(records))
        self.install(self.root / 'profiles', ''.join(profiles).encode())
        group_snapshot = 'root:x:0:\npcv2caller:x:%d:\npcv2target:x:%d:\npcv2legacy:x:%d:\npcv2shared:x:%d:pcv2caller,pcv2target\n' % (CALLER, TARGET, LEGACY, SHARED)
        self.install(self.root / 'groups', group_snapshot.encode())
        group += ('pcv2shared:x:%d:pcv2caller,pcv2target\n' % SHARED).encode()
        # The project subset requires passwords by default; it has no PASSWD: tag.
        # Keep both password rules untagged and NOPASSWD explicit only for its target.
        policy = ('Defaults timestamp_timeout=0\nDefaults env_keep=KEEP_ME\nDefaults:pcv2caller timestamp_timeout=1\n'
                  'pcv2caller ALL = (pcv2target) NOPASSWD: %s\n'
                  'pcv2caller ALL = (pcv2target) %s\n'
                  'pcv2legacy ALL = (pcv2target) %s\n') % (self.nopass, self.password, self.password)
        self.install(self.root / 'policy', policy.encode())
        for name in ('verifier', 'executor'):
            self.install(self.root / name, (self.artifacts / (name + '-v2')).read_bytes(), 0o700)
        for name, data in [('passwd', passwd), ('group', group)]:
            source = self.root / ('view-' + name); self.install(source, data, 0o644)
            target = Path('/etc') / name
            require(LIBC.mount(os.fsencode(source), os.fsencode(target), None, 4096, None) == 0, 'account view bind')
            self.mounts.append(target)
            require(LIBC.mount(None, os.fsencode(target), None, 4096 | 32 | 1, None) == 0, 'readonly account view')
        argv = ['/usr/sbin/insmod', self.artifacts / (MODULE + '.ko'), 'test_only=1']
        for name in ('accounts', 'groups', 'profiles', 'policy', 'verifier', 'executor'):
            argv += [name + '_path=' + str(self.root / name), name + '_sha256=' + sha(self.root / name)]
        r = self.command(argv); self.loaded = r.returncode == 0 and Path('/sys/module', MODULE).exists()
        require(self.loaded, 'real PRIVCMD module load failed')
        for _ in range(100):
            if os.path.lexists(DEVICE): break
            time.sleep(.01)
        st = Path(DEVICE).lstat()
        require(stat.S_ISCHR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o666, 'restricted protocol node mode differs')
        r = self.command([self.args.bash, '--noprofile', '--norc', '-c', 'printf "%s\\n" "$BASH_VERSION"'])
        require(r.returncode == 0 and r.stdout.startswith(b'5.3.20('), 'fresh Bash 5.3.20 required')
        self.report.update(bash_version=r.stdout.decode().strip(), snapshot_pins={n: sha(self.root / n) for n in ('accounts', 'groups', 'profiles', 'policy', 'verifier', 'executor')})

    def note(self, name, function, kind):
        require(name not in [r['id'] for r in self.cases], 'duplicate case')
        row = {'id': name, 'kind': kind, 'status': 'RUNNING'}; self.cases.append(row)
        try: row['details'] = function(); row['status'] = 'PASS'
        except AssertionError: row['status'] = 'FAIL'; raise
        except Exception: row['status'] = 'ERROR'; raise

    def target_rows(self, data, expected):
        rows = [json.loads(line.split(b'PCV2_TARGET ', 1)[1]) for line in data.splitlines() if line.startswith(b'PCV2_TARGET ')]
        check(len(rows) == expected, 'observed target report count differs')
        for row in rows:
            check(row['uid'] == [TARGET] * 4 and row['gid'] == [TARGET] * 4, 'live real/effective/saved/fs IDs differ')
            check(sorted(row['groups']) == [TARGET, SHARED] and row['caps'] == [0] * 6 and row['nnp'] == 1, 'target groups/capability state differs')
            check(bytes.fromhex(row['cwd_hex']) == os.fsencode(self.work), 'captured cwd differs')
            env = dict(bytes.fromhex(x).split(b'=', 1) for x in row['env_hex'])
            check(env[b'USER'] == b'pcv2target' and env[b'LOGNAME'] == b'pcv2target' and
                  env[b'HOME'] == os.fsencode(self.root / 'pcv2target-home'), 'trusted profile environment differs')
            check(b'UNSAFE_FIXTURE' not in env and not any(x.startswith((b'LD_', b'BASH_FUNC_')) for x in env), 'unsafe environment survived')
        return rows

    def child(self, name, function, target_count=0, uid=CALLER):
        rd, wr = os.pipe(); pid = os.fork()
        if not pid:
            os.close(rd); os.dup2(wr, 1); os.dup2(wr, 2); os.close(wr)
            try:
                os.chdir(self.work); os.setgroups([uid, SHARED] if uid == CALLER else [uid])
                os.setresgid(uid, uid, uid); os.setresuid(uid, uid, uid)
                function(); os.write(1, b'PCV2_API_OK\n'); os._exit(0)
            except BaseException:
                traceback.print_exc(); sys.stderr.flush(); os._exit(97)
        os.close(wr); data = bytearray(); deadline = time.monotonic() + 45
        try:
            while True:
                require(time.monotonic() < deadline and len(data) < 1048576, 'owned API actor timeout/output bound')
                if not select.select([rd], [], [], .05)[0]: continue
                chunk = os.read(rd, 65536)
                if not chunk: break
                data.extend(chunk)
            waited, status = os.waitpid(pid, 0)
        except BaseException:
            # Still an unreaped direct child; its numeric ID cannot be reused.
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise
        finally:
            os.close(rd)
            (self.args.output / (name + '.log')).write_bytes(data)
        (self.args.output / (name + '.log')).write_bytes(data)
        check(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and data.endswith(b'PCV2_API_OK\n'), 'owned API actor failed')
        return {'targets': self.target_rows(data, target_count), 'log_sha256': sha(self.args.output / (name + '.log'))}

    def bash(self, name, script, expected_status, target_count, password=None, uid=CALLER):
        master = slave = None; data = bytearray(); sent = released = False; actor = None
        if password is not None: master, slave = pty.openpty()
        def setup():
            if slave is not None: os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            os.setgroups([uid, SHARED] if uid == CALLER else [uid]); os.setresgid(uid, uid, uid); os.setresuid(uid, uid, uid)
        # Hold the actual invoking Bash after its builtin returns so an
        # independent root observer can read live real/effective/saved/fs IDs.
        wrapped = ('{\n' + script + '\n}\npcv2_status=$?\n'
                   'builtin printf "\\nPCV2_AFTER %s\\n" "$pcv2_status"\n'
                   'builtin read -r pcv2_release || exit 96\nexit "$pcv2_status"\n')
        p = subprocess.Popen([str(self.args.bash), '--noprofile', '--norc', '-c', wrapped], cwd=self.work, env=self.env,
            stdin=slave if slave is not None else subprocess.PIPE, stdout=slave if slave is not None else subprocess.PIPE,
            stderr=slave if slave is not None else subprocess.STDOUT, preexec_fn=setup, close_fds=True)
        try:
            reader = master if master is not None else p.stdout.fileno()
            writer = master if master is not None else p.stdin.fileno()
            deadline = time.monotonic() + 45
            while p.poll() is None:
                require(time.monotonic() < deadline and len(data) < 1048576, 'consumer timeout/output bound')
                if select.select([reader], [], [], .05)[0]:
                    try: chunk = os.read(reader, 65536)
                    except OSError as e:
                        if e.errno != errno.EIO: raise
                        chunk = b''
                    data.extend(chunk)
                if password is not None and not sent and b'Password: ' in data:
                    check(not termios.tcgetattr(slave)[3] & termios.ECHO, 'password echo enabled')
                    os.write(writer, password + b'\n'); sent = True
                if not released and b'PCV2_AFTER ' in data:
                    status = dict(line.split(':', 1) for line in Path('/proc', str(p.pid), 'status').read_text().splitlines() if ':' in line)
                    actor = {key: [int(x) for x in status[key].split()] for key in ('Uid', 'Gid', 'Groups')}
                    check(actor['Uid'] == [uid] * 4 and actor['Gid'] == [uid] * 4 and
                          sorted(actor['Groups']) == ([uid, SHARED] if uid == CALLER else [uid]),
                          'invoking Bash retained altered credentials after return')
                    os.write(writer, b'release\n'); released = True
            while select.select([reader], [], [], .05)[0]:
                chunk = os.read(reader, 65536)
                if not chunk: break
                data.extend(chunk)
            check(released and actor is not None, 'live invoking actor observation missing')
            if password is not None:
                check(sent and password not in data and termios.tcgetattr(slave)[3] & termios.ECHO, 'password handling/terminal restoration differs')
            (self.args.output / (name + '.log')).write_bytes(data)
            check(p.returncode == expected_status, 'consumer status %s expected %s' % (p.returncode, expected_status))
            return {'exit_code': p.returncode, 'invoking_actor_after': actor, 'targets': self.target_rows(data, target_count), 'log_sha256': sha(self.args.output / (name + '.log'))}
        finally:
            if p.poll() is None: p.kill(); p.wait()
            (self.args.output / (name + '.log')).write_bytes(data)
            if master is not None: os.close(master); os.close(slave)
            else: p.stdin.close(); p.stdout.close()

    def audit_drain(self):
        fd = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC); rows = []
        try:
            while True:
                data = bytearray(800)
                try: fcntl.ioctl(fd, PEEK, data, True)
                except OSError as e:
                    if e.errno == errno.EAGAIN: break
                    raise
                fcntl.ioctl(fd, AUDIT_VERIFY, data)
                size, version, epoch, sequence = struct.unpack_from('<IIQQ', data)
                check(size == 800 and version == 2 and epoch and sequence, 'audit framing')
                rows.append(bytes(data)); fcntl.ioctl(fd, ACK, struct.pack('<QQ', epoch, sequence))
        finally: os.close(fd)
        return rows

    def cleanup(self):
        if self.loaded:
            r = self.command(['/usr/sbin/rmmod', MODULE]); require(r.returncode == 0, 'module cleanup failed')
            self.loaded = False
        for path in reversed(self.mounts): require(LIBC.umount2(os.fsencode(path), 0) == 0, 'account view cleanup')
        if self.created: shutil.rmtree(self.root)


def device_cases(rt):
    def with_fd(function):
        fd = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC)
        try: function(fd)
        finally: os.close(fd)
    rt.note('executable-fifo-rejected-before-open',
            lambda: rt.child('executable-fifo-rejected-before-open', lambda: with_fd(
                lambda fd: rejects(lambda: prepare(fd, rt.root / 'executable-fifo'), {errno.EPERM}))),
            'actual-device')
    def positive(fd):
        p = prepare(fd, rt.nopass, ('exit-7', 'separate arg'))
        check(p.decision == 3 and not p.cache_hit, 'NOPASSWD policy did not authorize')
        kind, status, step, error, audit = redeem(fd, p)
        check((kind, status, step, error) == (1, 7, 0, 0) and audit, 'native result differs')
        rejects(lambda: redeem(fd, p), {errno.EKEYREJECTED})
    def fork_binding(fd):
        p = prepare(fd, rt.nopass, ('exit-0',)); pid = os.fork()
        if not pid:
            try: rejects(lambda: redeem(fd, p), {errno.EPERM}); os._exit(0)
            except BaseException: os._exit(97)
        waited, status = os.waitpid(pid, 0)
        check(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, 'inherited-fd control')
        check(redeem(fd, p)[:4] == (1, 0, 0, 0), 'foreign rejection revoked parent')
    def expire(fd):
        p = prepare(fd, rt.nopass); time.sleep(5.1)
        rejects(lambda: redeem(fd, p), {errno.EKEYEXPIRED})
    def reset_pending(fd):
        p = prepare(fd, rt.nopass); second = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC)
        try: reset(second)
        finally: os.close(second)
        rejects(lambda: redeem(fd, p), {errno.EKEYREVOKED})
    def password_cache(fd):
        reset(fd); p = prepare(fd, rt.password, ('exit-0',))
        check(p.decision == 2 and not p.cache_hit, 'fresh password request did not require verifier')
        verify(fd, p); check(redeem(fd, p)[:4] == (1, 0, 0, 0), 'verified command result')
        p = prepare(fd, rt.password, ('exit-9',)); check(p.decision == 3 and p.cache_hit == 1, 'real verified cache miss')
        check(redeem(fd, p)[:4] == (1, 9, 0, 0), 'cached command result')
        reset(fd); p = prepare(fd, rt.password)
        check(p.decision == 2 and not p.cache_hit, 'reset failed to invalidate cache')
        rejects(lambda: verify(fd, p, b'wrong'), {errno.EACCES})
        rejects(lambda: redeem(fd, p), {errno.EKEYREJECTED})
    def default_zero(fd):
        p = prepare(fd, rt.password, user='pcv2legacy', uid=LEGACY)
        check(p.decision == 2 and p.encoding == 2, 'explicit legacy record not selected')
        rejects(lambda: verify(fd, p), {errno.EACCES})
        p = prepare(fd, rt.password, user='pcv2legacy', uid=LEGACY); verify(fd, p, legacy=True)
        check(redeem(fd, p)[:4] == (1, 0, 0, 0), 'legacy native verification result')
        p = prepare(fd, rt.password, user='pcv2legacy', uid=LEGACY)
        check(p.decision == 2 and not p.cache_hit, 'default timeout zero incorrectly cached')
    def copy_fault(fd):
        p = prepare(fd, rt.nopass)
        C.set_errno(0); rc = LIBC.ioctl(fd, RUN, C.c_void_p(1))
        check(rc == -1 and C.get_errno() == errno.EFAULT, 'known-owner request copy fault')
        rejects(lambda: redeem(fd, p), {errno.EKEYREJECTED})
    def env_order(fd):
        rejects(lambda: prepare(fd, rt.nopass, env=('BASHOS_INLINE_KEEP_ME=x', 'BASHOS_CALLER_KEEP_ME=y')),
                {errno.EACCES, errno.EINVAL})
    for name, fn, count, uid in [
        ('device-nonroot-native-exec-and-replay', positive, 1, CALLER),
        ('device-fork-rejected-parent-still-owns', fork_binding, 1, CALLER),
        ('device-boottime-expiry', expire, 0, CALLER),
        ('device-reset-invalidates-pending', reset_pending, 0, CALLER),
        ('device-real-password-cache-reset-wrong-password', password_cache, 2, CALLER),
        ('device-explicit-legacy-default-zero', default_zero, 1, LEGACY),
        ('device-copy-fault-consumes', copy_fault, 0, CALLER),
        ('device-environment-reorder-denied', env_order, 0, CALLER)]:
        rt.note(name, lambda n=name, f=fn, c=count, u=uid: rt.child(n, lambda: with_fd(f), c, u), 'actual-device')
        rt.audit_drain()


def consumer_cases(rt):
    q = shlex.quote; common = '--authority-v2-qualification -u pcv2target '
    def authz():
        name = 'auth-policy-request-independent-digest'
        result = rt.bash(name, 'auth privcmd-v2-authz --qualification -n %d %d -- %s' %
                         (TARGET, TARGET, q(str(rt.nopass))), 0, 0)
        argv = os.fsencode(rt.nopass) + b'\0'
        frame = b'bashos-privcmd-v' + struct.pack('<11I', 1, 0, 1, CALLER, CALLER, TARGET, TARGET, 1, 0, len(argv), 0)
        for value in (b'pcv2caller', b'pcv2target', os.fsencode(rt.work)):
            frame += struct.pack('<I', len(value)) + value
        digest = hashlib.sha256(frame + argv).hexdigest()
        output = (rt.args.output / (name + '.log')).read_bytes()
        check(b'decision=3 ' in output and ('request_sha256=' + digest).encode() in output,
              'actual auth policy result/digest differs from independent oracle')
        result['independent_request_sha256'] = digest
        return result
    rt.note('auth-policy-request-independent-digest', authz, 'actual-consumer')
    for verb in ('doas', 'sudo'):
        name = verb + '-nonroot-nopasswd-status'
        rt.note(name, lambda n=name, v=verb: rt.bash(n, v + ' ' + common + q(str(rt.nopass)) + ' exit-7', 7, 1), 'actual-consumer')
    rt.note('auth-native-status', lambda: rt.bash('auth-native-status', 'auth privcmd-v2-exec --qualification -n %d %d -- %s exit-9' %
            (TARGET, TARGET, q(str(rt.nopass))), 9, 1), 'actual-consumer')
    rt.note('sudo-real-signal-status', lambda: rt.bash('sudo-real-signal-status', 'sudo ' + common + q(str(rt.nopass)) + ' signal-term', 143, 1), 'actual-consumer')
    rt.note('sudo-noninteractive-auth-required', lambda: rt.bash('sudo-noninteractive-auth-required',
        'sudo --authority-v2-qualification -k -n -u pcv2target ' + q(str(rt.password)), 1, 0), 'actual-consumer')
    rt.note('sudo-root-policy-denied', lambda: rt.bash('sudo-root-policy-denied', 'sudo ' + common + q(str(rt.nopass)), 1, 0, uid=0), 'actual-consumer')
    rt.note('sudo-wrong-password', lambda: rt.bash('sudo-wrong-password',
        'sudo --authority-v2-qualification -k -u pcv2target ' + q(str(rt.password)), 1, 0, password=b'wrong'), 'actual-consumer')
    script = ('sudo --authority-v2-qualification -k -u pcv2target %s exit-7; a=$?; '
              'sudo --authority-v2-qualification -n -u pcv2target %s exit-9; b=$?; '
              'sudo --authority-v2-qualification -K || exit 93; '
              'sudo --authority-v2-qualification -n -u pcv2target %s; c=$?; '
              '[[ $a == 7 && $b == 9 && $c == 1 ]]') % ((q(str(rt.password)),) * 3)
    rt.note('sudo-real-password-cache-and-K', lambda: rt.bash('sudo-real-password-cache-and-K', script, 0, 2, PASSWORD), 'actual-consumer')
    rows = rt.audit_drain()
    (rt.args.output / 'consumer-audit.bin').write_bytes(b''.join(rows))
    check(any(struct.unpack_from('<I', row, 64)[0] == 6 for row in rows), 'no real execution-result audit')


def audit_cases(rt):
    # Root UID is denied by policy, producing a genuine deny record for decoder
    # and integrity controls; no userspace event insertion interface exists.
    result = rt.bash('audit-seed-root-deny', 'sudo --authority-v2-qualification -n -u pcv2target ' + shlex.quote(str(rt.nopass)), 1, 0, uid=0)
    fd = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC)
    try:
        data = bytearray(800); fcntl.ioctl(fd, PEEK, data, True)
        epoch, sequence = struct.unpack_from('<QQ', data, 8)
        fcntl.ioctl(fd, AUDIT_VERIFY, data)
        bad = bytearray(data); bad[120] ^= 1
        rejects(lambda: fcntl.ioctl(fd, AUDIT_VERIFY, bad), {errno.EKEYREJECTED})
        rejects(lambda: fcntl.ioctl(fd, ACK, struct.pack('<QQ', epoch, sequence + 1)), {errno.ESTALE})
        def observer_failure():
            r = rt.command([rt.args.bash, '--noprofile', '--norc', '-c', 'auth audit-v2-drain --qualification 1 >/dev/full'])
            check(r.returncode != 0, 'failed decoder output accepted')
            still = bytearray(800); fcntl.ioctl(fd, PEEK, still, True); check(still == data, 'output failure removed audit record')
        observer_failure()
        r = rt.command([rt.args.bash, '--noprofile', '--norc', '-c', 'auth audit-v2-drain --qualification 1'])
        check(r.returncode == 0, 'actual Bash decoder failed'); row = json.loads(r.stdout)
        check(row['epoch'] == epoch and row['sequence'] == sequence and row['outcome'] == 'denied' and row['hmac_verified'] is True,
              'decoded record disagrees with independent framing')
        (rt.args.output / 'decoded-audit.json').write_text(json.dumps(row, indent=2) + '\n')
        return result
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    for name in ('receipt', 'bash', 'output'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('receipt-sha256', 'bash-sha256', 'expected-uuid'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args(); protected(args.receipt, args.receipt_sha256)
    receipt = json.loads(args.receipt.read_text())
    require(receipt['kind'] == 'authority-privcmd-v2-build-only' and receipt['schema'] == 1, 'build receipt kind differs')
    guard(args.expected_uuid, receipt['kernel_release']); protected(args.bash, args.bash_sha256)
    require(args.receipt.is_absolute() and args.bash.is_absolute() and args.output.is_absolute() and
            args.output.resolve().is_relative_to(HOME) and not args.output.exists(), 'fresh private absolute output required')
    for name, pin in receipt['files'].items():
        require(Path(name).name == name, 'invalid artifact name'); protected(args.receipt.parent / name, pin['sha256'])
        require((args.receipt.parent / name).stat().st_size == pin['bytes'], 'artifact size differs')
    require(sha(__file__) == receipt['files']['guest-privcmd-controls.py']['sha256'], 'guest control source differs')
    args.output.mkdir(mode=0o700); rt = Runtime(args, receipt)
    before = rt.command(['/usr/bin/dmesg', '--raw']); require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    try:
        model = rt.command([rt.artifacts / 'policy-model-controls'])
        check(model.returncode == 0, 'policy model controls failed in guest')
        model_result = json.loads(model.stdout)
        check(model_result['failures'] == 0 and model_result['assertions'] > 0 and model_result['authority_runtime'] is False,
              'model control output invalid')
        rt.report['model_observation'] = model_result
        rt.setup(); device_cases(rt); consumer_cases(rt)
        rt.note('actual-bash-audit-integrity-output-and-ack', lambda: audit_cases(rt), 'actual-consumer')
        require(len(rt.cases) == 19 and all(row['status'] == 'PASS' for row in rt.cases), 'control matrix incomplete')
        rt.report.update(status='PASS', scope='first PRIVCMD v2 controls only; blocking gaps remain')
    except AssertionError as error: rt.report.update(status='FAIL', reason=str(error))
    except Exception as error: rt.report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        try:
            rt.cleanup(); after = rt.command(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout); (args.output / 'dmesg-delta.txt').write_bytes(delta)
            forbidden = (b'warning:', b'bug:', b'kasan:', b'kcsan:', b'ubsan:', b'held lock', b'oops:',
                         b'possible recursive locking', b'inconsistent lock state', b'general protection fault', b'info: task ')
            require(not any(word in delta.lower() for word in forbidden), 'kernel warning/fault evidence')
        except Exception as error: rt.report.update(status='ERROR', cleanup_or_kernel_error=repr(error))
        (args.output / 'commands.json').write_text(json.dumps(rt.commands, indent=2) + '\n')
        (args.output / 'report.json').write_text(json.dumps(rt.report, indent=2) + '\n')
    print(json.dumps({'status': rt.report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if rt.report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error: print('PRIVCMD v2 preflight ERROR: ' + repr(error), file=sys.stderr); sys.exit(125)
