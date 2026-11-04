#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Rental-guest integration with the experimental real secret-slot module.

Runtime artifacts arrive through vm.py's explicit --references input directory.
Their fixed digests identify the exact guest module/device control, not a mock.
All notified calls continue to Linux. Kernel erasure needs separate KUnit proof.
"""
import base64
from contextlib import contextmanager
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
import resource
import select
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
HELPERS = Path('/opt/bashos-parity/harness/helpers')
ARTIFACTS = Path('/opt/bashos-parity/reference-data')
DEVICE = Path('/dev/bashos-auth')
MODULE = 'bashos_auth_stage1'
PINS = {'auth-stage1.ko': 'bc95712ef12cbbd045186078bc17b7232e70c4f8297ef14c226d3766f3183c72',
        'auth-stage1-device-test': 'a389e8a225fc5c1d91601e3f1f00c88b190efa2ec983d939c4d76c7d8bf89fa7',
        'libargon2.so.1': '94b5c0be9d7f09f1b4550ff15422d2ac8a6392c3471c88b93ee0370698388097'}
SECRET = b'fixture-secret-only'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def guard():
    require(__debug__ and platform.machine() == 'x86_64', 'x86-64 debug interpreter required')
    require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'guest root required')
    require(Path.cwd() == CASE and os.environ.get('HOME') == str(HOME), 'private scratch required')
    token = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    require(Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'guest identity differs')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU', 'QEMU guest required')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'matching isolated evaluator required')
    require(platform.release() == '6.12.113+deb13-cloud-amd64', 'module requires its exact guest kernel')


def record(kind, **values):
    with (HOME / 'stage1-observations.jsonl').open('a') as log:
        log.write(json.dumps({'kind': kind, **values}, sort_keys=True) + '\n')


def artifact(name):
    path = ARTIFACTS / name
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'runtime artifact is not protected regular data')
    require(info.st_size <= 2 * 1024**2 and hashlib.sha256(path.read_bytes()).hexdigest() == PINS[name],
            'runtime artifact digest differs: ' + name)
    return path


@contextmanager
def loaded():
    guard()
    require(not os.path.lexists(DEVICE) and not Path('/sys/module', MODULE).exists(),
            'preexisting authority must not be replaced')
    module = artifact('auth-stage1.ko')
    loaded_here = False
    try:
        result = subprocess.run(['/usr/sbin/insmod', str(module)], capture_output=True, timeout=5)
        record('insmod', status=result.returncode, stderr=result.stderr.decode(errors='replace'),
               module_sha256=PINS['auth-stage1.ko'])
        require(result.returncode == 0, 'stage-1 module did not load')
        loaded_here = True
        for _ in range(100):
            if DEVICE.exists():
                break
            time.sleep(.01)
        info = DEVICE.stat()
        require(stat.S_ISCHR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                'authority device type/permissions differ')
        record('real-device', rdev=info.st_rdev, mode=stat.S_IMODE(info.st_mode), kernel=platform.release())
        yield
    finally:
        if loaded_here:
            result = subprocess.run(['/usr/sbin/rmmod', MODULE], capture_output=True, timeout=5)
            record('rmmod', status=result.returncode, stderr=result.stderr.decode(errors='replace'))
            require(result.returncode == 0 and not Path('/sys/module', MODULE).exists()
                    and not os.path.lexists(DEVICE), 'stage-1 module or device remains')


def derive(password, salt, passes, memory, lanes, size=32):
    # Independent Debian libargon2 accepts binary salts, including embedded NUL.
    # The release candidate uses its separately built project implementation.
    require(1 <= passes <= 10 and 1024 <= memory <= 262144 and 1 <= lanes <= 8
            and 8 <= len(salt) <= 64 and 16 <= size <= 128, 'unbounded KDF request')
    lib = ctypes.CDLL(str(artifact('libargon2.so.1')))
    fn = lib.argon2id_hash_raw
    fn.argtypes = [ctypes.c_uint32] * 3 + [ctypes.c_void_p, ctypes.c_size_t] * 3
    fn.restype = ctypes.c_int
    p, s, out = ctypes.create_string_buffer(password), ctypes.create_string_buffer(salt), ctypes.create_string_buffer(size)
    rc = fn(passes, memory, lanes, p, len(password), s, len(salt), out, size)
    require(rc == 0, 'independent Argon2 library failed')
    record('independent-kdf', password_base64=base64.b64encode(password).decode(), salt_hex=salt.hex(),
           passes=passes, memory=memory, lanes=lanes, digest_hex=out.raw.hex())
    return out.raw


def setup():
    with loaded():
        source = artifact('auth-stage1-device-test')
        test = CASE / 'stage1-device-test'
        test.write_bytes(source.read_bytes())
        test.chmod(0o755)
        limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        try:
            # The 128-context quota control needs 256 process descriptors.
            # This is local to the root fixture and restored after the control.
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            result = subprocess.run([str(test), '--disposable-guest'], capture_output=True, timeout=30)
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, limits)
        (HOME / 'stage1-device.stdout').write_bytes(result.stdout)
        (HOME / 'stage1-device.stderr').write_bytes(result.stderr)
        require(result.returncode == 0 and not result.stderr and
                re.fullmatch(rb'PASS: [0-9]+ real-device checks; kernel erasure still requires KUnit evidence\n', result.stdout),
                'independent real-device control failed')
        require(derive(b'password', b'somesalt', 2, 65536, 1).hex() ==
                '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
                'independent KDF known vector differs')


def trace():
    guard()
    require(DEVICE.exists() and Path('/sys/module', MODULE).exists(), 'real module required')
    require(len(sys.argv) >= 4 and sys.argv[2] in ('auth', 'set', 'verify') and
            sys.argv[3] == '/opt/bashos-parity/candidate', 'approved trace program required')
    mode = sys.argv[2]
    spec = importlib.util.spec_from_file_location('stage1_listener', HELPERS / 'auth-client-listener.py')
    seq = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seq)
    seq.guest_guard = guard
    seq.BOOTSTRAP_LOG = HOME / ('stage1-' + mode + '.bootstrap')
    sys.argv = [str(HELPERS / 'auth-client-listener.py'),
                '--notify', 'open', '--notify', 'openat', '--notify', 'ioctl',
                '--log', str(HOME / ('stage1-' + mode + '.trace')),
                '--log-args', 'open=1', '--log-args', 'openat=2', '--log-args', 'ioctl=0,1',
                '--log-string', 'open=0', '--log-string', 'openat=1', '--', *sys.argv[3:]]
    seq.main()


def protocol(mode, minimum_opens):
    rows = [json.loads(x) for x in (HOME / ('stage1-' + mode + '.trace')).read_text().splitlines()]
    opens = [x for x in rows if x.get('string0') == str(DEVICE) or x.get('string1') == str(DEVICE)]
    commands = [x['arg1'] for x in rows if x['syscall'] == 'ioctl']
    require(all(x.get('reply') == 'continue' for x in rows), 'a real syscall was replaced')
    required = {0xc008ba02, 0x4010ba03, 0x4008ba04, 0x4008ba05}
    required |= {0xc010ba06} if mode != 'auth' else {0xc010ba07, 0x8080ba0a}
    return len(opens) >= minimum_opens and required <= set(commands)


def command(binary, mode, script, env):
    return ['/usr/bin/python3', str(HELPERS / 'auth-stage1-standard-phc-r2.py'), 'trace', mode,
            binary, '--noprofile', '--norc', '-c', script], env


AUTH_SCRIPT = '''auth open af || exit 1
auth read-secret "$af" -p 'one> ' a || exit 2
auth read-secret "$af" -p 'two> ' b || exit 3
auth read-secret "$af" -p 'three> ' c || exit 4
auth same-secret "$af" "$a" "$b"; printf 'equal=%s\\n' "$?"
auth same-secret "$af" "$a" "$c"; printf 'different=%s\\n' "$?"
auth clear "$af" "$a"; printf 'clear=%s\\n' "$?"
auth same-secret "$af" "$a" "$b" 2>/dev/null; printf 'cleared=%s\\n' "$?"
auth stats "$af"
exec {af}>&-
auth open fresh || exit 5
auth stats "$fresh"
auth same-secret "$fresh" "$b" "$c" 2>/dev/null; printf 'old-on-fresh=%s\\n' "$?"
exec {fresh}>&-
'''


def auth(binary):
    argv, env = command(binary, 'auth', AUTH_SCRIPT, dict(os.environ))
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    def session():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    child = subprocess.Popen(argv, env=env, stdin=slave, stdout=slave, stderr=slave,
                             preexec_fn=session, close_fds=True)
    output = bytearray()
    prompts = (b'one> ', b'two> ', b'three> ')
    sent, echo_disabled = 0, []
    deadline = time.monotonic() + 20
    try:
        while child.poll() is None:
            require(time.monotonic() < deadline, 'owned PTY deadline exceeded')
            if select.select([master], [], [], .05)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                output.extend(chunk)
                require(len(output) <= 65536, 'PTY output limit exceeded')
            if sent < 3 and prompts[sent] in output:
                echo_disabled.append(not bool(termios.tcgetattr(slave)[3] & termios.ECHO))
                os.write(master, (SECRET if sent < 2 else b'other-fixture-only') + b'\n')
                sent += 1
        child.wait(timeout=3)
        while select.select([master], [], [], .02)[0]:
            try:
                output.extend(os.read(master, 4096))
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break
        restored = termios.tcgetattr(slave) == before
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=3)
        os.close(master)
        os.close(slave)
    (HOME / 'stage1-auth.pty').write_bytes(output)
    expected = (b'equal=0\r\ndifferent=1\r\nclear=0\r\ncleared=1\r\n'
                b'created_secrets=3 cleared_secrets=1 refused_exports=0 minted_tokens=0 consumed_tokens=0 expired_tokens=0\r\n'
                b'created_secrets=0 cleared_secrets=0 refused_exports=0 minted_tokens=0 consumed_tokens=0 expired_tokens=0\r\n'
                b'old-on-fresh=1\r\n')
    good = (child.returncode == 0 and sent == 3 and all(echo_disabled) and restored and
            SECRET not in output and b'other-fixture-only' not in output and bytes(output).endswith(expected)
            and protocol('auth', 2))
    record('auth-result', status=child.returncode, echo_disabled=echo_disabled, restored=restored,
           secret_absent=SECRET not in output, matched=good)
    print('auth-stage1 real-device=yes compare=yes clear=yes fresh-fd=yes pty=yes' if good else 'auth-stage1 mismatch')


def password(binary, mode):
    db = CASE / 'accounts'
    db.mkdir(mode=0o700)
    passwd = 'fixture:x:3101:3201:Fixture:/tmp/parity-case:/bin/false\n'
    group = 'fixture:x:3201:\n'
    digest = derive(SECRET, b'somesalt', 1, 1024, 1)
    phc = '$argon2id$v=19$m=1024,t=1,p=1$' + b'somesalt'.hex() + '$' + digest.hex()
    for name, value in (('passwd', passwd), ('group', group), ('shadow', 'fixture:' + phc + ':19000:0:99999:7:::\n')):
        (db / name).write_text(value)
        (db / name).chmod(0o600 if name == 'shadow' else 0o644)
    goodfile, badfile = CASE / 'good', CASE / 'wrong'
    goodfile.write_bytes(SECRET + b'\n')
    badfile.write_bytes(b'wrong-fixture-only\n')
    env = dict(os.environ, PHCLIB_PASSWD=str(db / 'passwd'), PHCLIB_GROUP=str(db / 'group'),
               PHCLIB_SHADOW=str(db / 'shadow'), BPW_LOCK_DIR=str(CASE / 'lock'),
               PHCLIB_M='1024', PHCLIB_T='1', PHCLIB_P='1', BASHPASSWD_REQUIRE_KERNEL_SECRETS='1')
    env.pop('BASHPASSWD_KERNEL_SECRETS', None)
    if mode == 'set':
        script = 'passwd set-fd fixture 3 3</tmp/parity-case/good; printf "set=%s\\n" "$?"\n'
    else:
        script = ('passwd verify-fd fixture 3 3</tmp/parity-case/good; printf "good=%s\\n" "$?"\n'
                  'passwd verify-fd fixture 3 3</tmp/parity-case/wrong; printf "wrong=%s\\n" "$?"\n'
                  'passwd verify-fd fixture 3 3</tmp/parity-case/good; printf "again=%s\\n" "$?"\n')
    argv, env = command(binary, mode, script, env)
    result = subprocess.run(argv, env=env, capture_output=True, timeout=20)
    (HOME / ('stage1-' + mode + '.stdout')).write_bytes(result.stdout)
    (HOME / ('stage1-' + mode + '.stderr')).write_bytes(result.stderr)
    expected = b'set=0\n' if mode == 'set' else b'good=0\nwrong=1\nagain=0\n'
    independent = True
    if mode == 'set':
        stored = (db / 'shadow').read_text().split(':')[1]
        try:
            fields = stored.split('$')
            parameters = dict(x.split('=') for x in fields[3].split(','))
            salt = base64.b64decode(fields[4] + '=' * (-len(fields[4]) % 4), validate=True)
            hashed = base64.b64decode(fields[5] + '=' * (-len(fields[5]) % 4), validate=True)
            canonical = (base64.b64encode(salt).rstrip(b'=').decode('ascii') == fields[4] and
                         base64.b64encode(hashed).rstrip(b'=').decode('ascii') == fields[5])
            independent = (fields[:3] == ['', 'argon2id', 'v=19'] and parameters == {'m': '1024', 't': '1', 'p': '1'}
                           and canonical and len(salt) == 16 and len(hashed) == 32 and derive(SECRET, salt, 1, 1024, 1) == hashed)
        except (ValueError, IndexError):
            independent = False
        record('stored-shadow', text=(db / 'shadow').read_text(), independent_standard_phc_kdf=independent)
    good = (result.returncode == 0 and result.stdout == expected and not result.stderr and independent
            and protocol(mode, 1 if mode == 'set' else 3) and (db / 'passwd').read_text() == passwd
            and (db / 'group').read_text() == group and stat.S_IMODE((db / 'shadow').stat().st_mode) == 0o600)
    record('passwd-result', mode=mode, matched=good, status=result.returncode, independent=independent)
    print(f'passwd-stage1 {mode} real-device=yes statuses=yes private-accounts=yes independent-kdf=yes' if good
          else f'passwd-stage1 {mode} mismatch')


def main():
    guard()
    require(len(sys.argv) >= 2, 'fixture action required')
    if sys.argv[1] == 'trace':
        trace()
    elif sys.argv[1] == 'setup':
        require(len(sys.argv) == 2, 'unexpected setup argument')
        setup()
    else:
        require(len(sys.argv) == 3 and sys.argv[1] == '/opt/bashos-parity/candidate'
                and sys.argv[2] in ('auth', 'set', 'verify'), 'approved candidate/mode required')
        with loaded():
            auth(sys.argv[1]) if sys.argv[2] == 'auth' else password(sys.argv[1], sys.argv[2])


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:
        print('auth stage-1 fixture incomplete: ' + repr(exc), file=sys.stderr)
        raise SystemExit(125)
