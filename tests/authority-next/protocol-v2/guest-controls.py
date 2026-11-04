#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Real protocol-v2 controls, ONLY in the attested disposable parity guest.

Does not execute Bash, change real accounts, enable production features, or award
the original topic obligations. The test module is a separate endpoint. Its
native verifier actually computes Argon2 against an independently made snapshot.
No verifier-result injection ioctl or KUnit seed participates in positive tests.
"""
import array
import argparse
import base64
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

MAGIC, VERSION = 0x32564142, 2
DEVICE, MODULE = '/dev/bashos-auth-v2-test', 'bashos_auth_v2_test'
CASE, HOME = Path('/tmp/parity-case'), Path('/tmp/parity-home')
PASSWORD = b'protocol-v2-disposable-password\x00binary-tail'
SALT = b'protocol\x00v2-salt'
DIGEST = hashlib.sha256(b'independent protocol-v2 request fixture 1').digest()
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
LIBC.read.restype = ctypes.c_ssize_t
LIBC.unshare.argtypes = [ctypes.c_int]
LIBC.unshare.restype = ctypes.c_int


def ioc(direction, number, size=0, magic=0xbb):
    return (direction << 30) | (size << 16) | (magic << 8) | number


GET_VERSION = ioc(2, 0, 16)
VERIFY, VERIFY_LEGACY, CONSUME = ioc(1, 1, 144), ioc(1, 2, 144), ioc(1, 3, 144)
RESET, DELEGATE = ioc(0, 4), ioc(1, 5, 16)
NEW, WRITE, SEAL = ioc(3, 2, 8, 0xba), ioc(1, 3, 16, 0xba), ioc(1, 4, 8, 0xba)
CASES, COMMANDS = [], []


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def check(ok, why):
    if not ok:
        raise AssertionError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def guard(expected_uuid, kernel):
    require(__debug__ and platform.machine() == 'x86_64', 'debug x86-64 guest required')
    require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'guest root required')
    require(Path.cwd() == CASE and os.environ.get('HOME') == str(HOME), 'private parity scratch required')
    token = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    require(token == str(uuid.UUID(expected_uuid)), 'explicit coordinator guest UUID differs')
    require(Path('/run/bashos-parity-vm-identity').read_text().strip() == token, 'live guest identity differs')
    require(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU', 'QEMU guest required')
    command = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    require(b'/opt/bashos-parity/harness/guest.py' in command and token.encode() in command,
            'matching isolated evaluator required')
    require(platform.release() == kernel, 'exact build receipt kernel required')
    require(not Path('/sys/module', MODULE).exists() and not os.path.lexists(DEVICE),
            'preexisting test authority must not be replaced')


def run(command, timeout=10):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    COMMANDS.append({'argv': command, 'exit_code': result.returncode,
                     'stdout_base64': base64.b64encode(result.stdout).decode(),
                     'stderr_base64': base64.b64encode(result.stderr).decode()})
    return result


def note(name, function):
    require(name not in [x['id'] for x in CASES], 'duplicate control ID')
    item = {'id': name, 'status': 'RUNNING'}
    CASES.append(item)
    try:
        function()
        item['status'] = 'PASS'
    except Exception:
        item['status'] = 'FAIL'
        raise


def fails(function, expected):
    try:
        function()
    except OSError as error:
        check(error.errno in expected, 'unexpected errno: %s; expected %s' % (error.errno, sorted(expected)))
        return
    raise AssertionError('operation unexpectedly succeeded')


@contextmanager
def context():
    fd = os.open(DEVICE, os.O_RDWR | os.O_CLOEXEC)
    try:
        yield fd
    finally:
        os.close(fd)


def secret(fd, password=PASSWORD):
    request = bytearray(struct.pack('<II', 0, 0))
    fcntl.ioctl(fd, NEW, request, True)
    handle, flags = struct.unpack('<II', request)
    check(handle != 0 and flags == 0, 'secret handle response differs')
    data = ctypes.create_string_buffer(password)
    fcntl.ioctl(fd, WRITE, struct.pack('<IIQ', handle, len(password), ctypes.addressof(data)))
    fcntl.ioctl(fd, SEAL, struct.pack('<II', handle, 0))
    return handle


def verify(fd, user='alice', password=PASSWORD, purpose=1, legacy=False, request_digest=DIGEST, handle=None):
    if handle is None:
        handle = secret(fd, password)
    request = struct.pack('<IIII64s32s32s', 144, VERSION, handle, purpose,
                          user.encode(), request_digest, bytes(32))
    fcntl.ioctl(fd, VERIFY_LEGACY if legacy else VERIFY, request)


def reference(fd):
    head, tail = os.read(fd, 7), os.read(fd, 25)
    check(len(head) == 7 and len(tail) == 25 and os.read(fd, 1) == b'', 'reference stream framing differs')
    value = head + tail
    check(any(value), 'zero reference')
    return value


def consume(fd, value, user='alice', purpose=1, request_digest=DIGEST):
    request = struct.pack('<IIII64s32s32s', 144, VERSION, purpose, 0, user.encode(), value, request_digest)
    fcntl.ioctl(fd, CONSUME, request)


def grant(fd, **kwargs):
    verify(fd, **kwargs)
    return reference(fd)


def child_control(function):
    pid = os.fork()
    if pid == 0:
        try:
            function()
        except BaseException:
            os._exit(97)
        os._exit(0)
    waited, status = os.waitpid(pid, 0)
    check(waited == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
          'owned control child failed or signaled: %s' % status)


def positive(user='alice', purpose=1, legacy=False):
    with context() as fd:
        value = grant(fd, user=user, purpose=purpose, legacy=legacy)
        consume(fd, value, user=user, purpose=purpose)
        fails(lambda: consume(fd, value, user=user, purpose=purpose), {errno.ENOENT})
        check(os.read(fd, 32) == b'', 'consumed grant remains readable')


def rejected_verification(**kwargs):
    with context() as fd:
        fails(lambda: verify(fd, **kwargs), {errno.EACCES, errno.EIO, errno.EINVAL, errno.EKEYREJECTED})
        check(os.read(fd, 32) == b'', 'failed verification queued a reference')


def changed_claim(**kwargs):
    with context() as fd:
        value = grant(fd)
        fails(lambda: consume(fd, value, **kwargs), {errno.EACCES})
        fails(lambda: consume(fd, value), {errno.ENOENT})


def actor_drift(mutate):
    def body():
        with context() as fd:
            verify(fd)
            mutate(fd)
            fails(lambda: os.read(fd, 32), {errno.EPERM})
    child_control(body)


def namespace_drift(fd, flags=0x00020000):
    if LIBC.unshare(flags):
        raise OSError(ctypes.get_errno(), 'guest namespace control unavailable')


def exec_drift():
    def body():
        with context() as fd:
            verify(fd)
            os.set_inheritable(fd, True)
            code = ('import os,errno\ntry: os.read(%d,32)\n'
                    'except OSError as e: os._exit(0 if e.errno==errno.EPERM else 98)\n'
                    'os._exit(99)\n') % fd
            os.execv(sys.executable, [sys.executable, '-c', code])
    child_control(body)


def fork_denied():
    with context() as fd:
        value = grant(fd)
        child_control(lambda: fails(lambda: consume(fd, value), {errno.EPERM}))
        consume(fd, value)


def thread_denied():
    with context() as fd:
        value = grant(fd)
        result = []
        def body():
            try:
                consume(fd, value)
                result.append(0)
            except OSError as error:
                result.append(error.errno)
        thread = threading.Thread(target=body)
        thread.start()
        thread.join(5)
        check(not thread.is_alive() and result == [errno.EPERM], 'thread transfer accepted')
        consume(fd, value)


def scm_denied():
    with context() as fd:
        value = grant(fd)
        parent, child = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            parent.close()
            os.close(fd)
            try:
                data, controls, flags, _ = child.recvmsg(1, socket.CMSG_SPACE(4))
                if data != b'f' or flags or len(controls) != 1: os._exit(94)
                level, kind, packed = controls[0]
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS: os._exit(93)
                transferred = array.array('i')
                transferred.frombytes(packed)
                if len(transferred) != 1: os._exit(92)
                fails(lambda: consume(transferred[0], value), {errno.EPERM})
                os.close(transferred[0])
            except BaseException:
                os._exit(95)
            os._exit(0)
        child.close()
        try:
            parent.sendmsg([b'f'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
            waited, status = os.waitpid(pid, 0)
            check(waited == pid and status == 0, 'SCM_RIGHTS control child failed')
            consume(fd, value)
        finally:
            parent.close()


def ssh_delegation(kind='positive'):
    with context() as fd:
        purpose = 1 if kind == 'wrong-purpose' else 4
        verify(fd, purpose=purpose)
        if kind == 'already-read':
            value = reference(fd)
        go_read, go_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(go_write)
            try:
                message = os.read(go_read, 1)
                if message == b'Y':
                    if kind == 'child-cred':
                        os.setgroups(os.getgroups() + [47112])
                        fails(lambda: os.read(fd, 32), {errno.EPERM})
                    else:
                        value = reference(fd)
                        consume(fd, value, purpose=4)
                        fails(lambda: consume(fd, value, purpose=4), {errno.ENOENT})
                elif message != b'N':
                    os._exit(91)
            except BaseException:
                os._exit(96)
            os._exit(0)
        os.close(go_read)
        try:
            request = struct.pack('<IIII', 16, VERSION, pid, 0)
            if kind in ('wrong-purpose', 'already-read', 'active-pid'):
                fails(lambda: fcntl.ioctl(fd, DELEGATE, request), {errno.EPERM})
                os.write(go_write, b'N')
                if kind != 'already-read': value = reference(fd)
                consume(fd, value, purpose=purpose)
            else:
                fcntl.ioctl(fd, DELEGATE, request)
                fails(lambda: os.read(fd, 32), {errno.EPERM})
                fails(lambda: fcntl.ioctl(fd, DELEGATE, request), {errno.EPERM})
                os.write(go_write, b'Y')
        finally:
            os.close(go_write)
            waited, status = os.waitpid(pid, 0)
            check(waited == pid and status == 0, 'delegation control child failed: %s' % status)


def ssh_cross_active_pid_namespace():
    def body():
        namespace_drift(-1, 0x20000000)  # CLONE_NEWPID affects future children
        # Keep PID 1 alive before opening the authority context: Linux exposes
        # pid_for_children through proc only once the new namespace is live.
        ready_read, ready_write = os.pipe()
        keep_read, keep_write = os.pipe()
        keeper = os.fork()
        if keeper == 0:
            os.close(ready_read); os.close(keep_write)
            os.write(ready_write, b'R'); os.close(ready_write)
            os.read(keep_read, 1)
            os._exit(0)
        os.close(ready_write); os.close(keep_read)
        try:
            check(os.read(ready_read, 1) == b'R', 'PID namespace keeper did not start')
            ssh_delegation('active-pid')
        finally:
            os.close(ready_read); os.close(keep_write)
            waited, status = os.waitpid(keeper, 0)
            check(waited == keeper and status == 0, 'PID namespace keeper cleanup failed')
    child_control(body)


def reference_controls(trusted):
    def version():
        with context() as fd:
            response = bytearray(16)
            fcntl.ioctl(fd, GET_VERSION, response, True)
            check(struct.unpack('<IIQ', response) == (16, 2, 0), 'production feature advertisement')
    note('separate-version-production-features-zero', version)
    note('native-standard-login-one-redemption', positive)
    note('native-standard-su-one-redemption', lambda: positive(purpose=2))
    note('native-standard-ssh-one-redemption', lambda: positive(purpose=4))
    note('native-explicit-legacy-one-redemption', lambda: positive(user='legacy', legacy=True))
    note('native-uid-zero-account-needs-password', lambda: positive(user='v2-root'))
    for name, arguments in [
        ('wrong-password', {'password': b'wrong'}), ('binary-password-tail', {'password': PASSWORD.split(b'\0')[0]}),
        ('wrong-password-root-target', {'user': 'v2-root', 'password': b'wrong'}),
        ('unknown-account', {'user': 'missing'}), ('disabled-account', {'user': 'disabled'}),
        ('legacy-on-standard-route', {'user': 'legacy'}), ('standard-on-legacy-route', {'legacy': True}),
        ('unsupported-purpose-three', {'purpose': 3}), ('unsupported-purpose-zero', {'purpose': 0}),
        ('standard-record-not-autodetected-as-hex', {'user': 'wrong-tag'}),
    ]:
        note(name, lambda arguments=arguments: rejected_verification(**arguments))
    for name, arguments in [('different-target', {'user': 'v2-root'}), ('unknown-target', {'user': 'missing'}),
                            ('different-purpose', {'purpose': 2}), ('invalid-purpose', {'purpose': 0}),
                            ('different-request', {'request_digest': bytes(32)})]:
        note('known-reference-revokes-' + name, lambda arguments=arguments: changed_claim(**arguments))
    def random_value():
        with context() as fd:
            value = grant(fd)
            wrong = bytearray(value); wrong[-1] ^= 1
            fails(lambda: consume(fd, bytes(wrong)), {errno.ENOENT})
            consume(fd, value)
    note('random-reference-does-not-spend-another-grant', random_value)
    def other_context():
        with context() as fd, context() as other:
            value = grant(fd)
            fails(lambda: consume(other, value), {errno.ENOENT})
            consume(fd, value)
    note('another-open-context-cannot-redeem', other_context)
    def dup_same():
        with context() as fd:
            value = grant(fd)
            other = os.dup(fd)
            try: consume(other, value)
            finally: os.close(other)
    note('same-task-dup-shares-one-open-context', dup_same)
    def active():
        with context() as fd:
            value = grant(fd)
            fails(lambda: verify(fd), {errno.EBUSY})
            consume(fd, value)
    note('second-verification-cannot-overwrite-live-grant', active)
    def expiry():
        with context() as fd:
            value = grant(fd)
            time.sleep(5.15)
            fails(lambda: consume(fd, value), {errno.EKEYEXPIRED})
            fails(lambda: consume(fd, value), {errno.ENOENT})
    note('real-boottime-expiry-and-removal', expiry)
    def copy_fault():
        with context() as fd:
            verify(fd)
            ctypes.set_errno(0)
            check(LIBC.read(fd, ctypes.c_void_p(1), 32) == -1 and ctypes.get_errno() == errno.EFAULT,
                  'invalid copy address did not fault')
            check(os.read(fd, 32) == b'', 'copy fault left a usable reference')
    note('read-copy-fault-revokes', copy_fault)
    def reset():
        with context() as fd:
            value = grant(fd)
            fcntl.ioctl(fd, RESET)
            fails(lambda: consume(fd, value), {errno.ENOENT})
    note('explicit-reset-revokes', reset)
    def last_close():
        with context() as fd: value = grant(fd)
        with context() as fd:
            check(os.read(fd, 32) == b'', 'fresh context inherited last-closed grant')
            fails(lambda: consume(fd, value), {errno.ENOENT})
    note('last-close-cannot-reopen-reference', last_close)
    def old_routes():
        with context() as fd:
            for command, size in [(ioc(3, 8, 120, 0xba), 120), (ioc(1, 9, 120, 0xba), 120),
                                  (ioc(3, 6, 16, 0xba), 16)]:
                fails(lambda command=command, size=size: fcntl.ioctl(fd, command, bytes(size)), {errno.ENOTTY})
            check(os.read(fd, 32) == b'', 'raw legacy route created a grant')
    note('legacy-mint-consume-export-unavailable-even-for-root', old_routes)
    note('implicit-fork-denied', fork_denied)
    note('implicit-thread-denied', thread_denied)
    note('implicit-scm-rights-denied', scm_denied)
    note('exec-replacement-denied', exec_drift)
    note('supplementary-group-credential-drift-denied', lambda: actor_drift(lambda fd: os.setgroups(os.getgroups() + [47111])))
    note('session-drift-denied', lambda: actor_drift(lambda fd: os.setsid()))
    note('cwd-drift-denied', lambda: actor_drift(lambda fd: os.chdir(trusted)))
    note('mount-namespace-drift-denied', lambda: actor_drift(namespace_drift))
    # These mutate the calling task's real namespace tuple after issuance.
    # PID/time unshare changes the namespace for future children first, so
    # checking only the active PID/time identity would miss these controls.
    for name, flags in [('uts', 0x04000000), ('ipc', 0x08000000),
                        ('net', 0x40000000), ('cgroup', 0x02000000),
                        ('pid-for-children', 0x20000000), ('time-for-children', 0x00000080)]:
        note(name + '-namespace-drift-denied',
             lambda flags=flags: actor_drift(lambda fd: namespace_drift(fd, flags)))
    for kind in ('positive', 'wrong-purpose', 'already-read', 'child-cred'):
        note('explicit-ssh-child-' + kind, lambda kind=kind: ssh_delegation(kind))
    note('ssh-delegation-cross-active-pid-namespace-denied', ssh_cross_active_pid_namespace)
    def foreign_delegate():
        with context() as fd:
            verify(fd, purpose=4)
            fails(lambda: fcntl.ioctl(fd, DELEGATE, struct.pack('<IIII', 16, VERSION, os.getppid(), 0)), {errno.EPERM})
            consume(fd, reference(fd), purpose=4)
    note('ssh-delegation-unrelated-task-denied', foreign_delegate)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sha(args.receipt) == args.receipt_sha256, 'build receipt pin differs')
    receipt = json.loads(args.receipt.read_text())
    require(receipt['schema'] == 1 and receipt['kind'] == 'authority-protocol-v2-build-only', 'unknown build receipt')
    guard(args.expected_uuid, receipt['kernel_release'])
    require(args.output.is_absolute() and args.output.resolve().is_relative_to(HOME) and not args.output.exists(),
            'fresh report directory under private parity HOME required')
    artifacts = args.receipt.resolve().parent
    expected_files = {'bashos_auth_v2_test.ko', 'verifier-v2', 'guest-controls.py', 'libargon2.so.1'}
    expected_files.update('fault-verifier-' + str(n) for n in range(1, 16))
    require(set(receipt['files']) == expected_files, 'unexpected/missing build artifacts')
    for name, pin in receipt['files'].items():
        path = artifacts / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'unprotected runtime artifact: ' + name)
        require(info.st_size == pin['bytes'] and sha(path) == pin['sha256'], 'artifact pin differs: ' + name)
    require(sha(Path(__file__)) == receipt['files']['guest-controls.py']['sha256'], 'observer source differs')
    args.output.mkdir()
    trusted = Path('/var/lib') / ('bashos-auth-v2-test-' + str(uuid.UUID(args.expected_uuid)))
    require(not trusted.exists(), 'fresh trusted fixture directory required')
    trusted.mkdir(mode=0o700)
    report = {'schema': 1, 'status': 'ERROR', 'guest_uuid': str(uuid.UUID(args.expected_uuid)),
              'kernel': platform.release(), 'build_receipt_sha256': args.receipt_sha256,
              'source_manifest_sha256': receipt['source_manifest_sha256'], 'cases': CASES,
              'production_features_enabled': False, 'original_topic_credit': 0,
              'kernel_erasure_qualified': False, 'full_bash_consumer_coverage': False}
    before = run(['/usr/bin/dmesg', '--raw'])
    require(before.returncode == 0, 'kernel log unavailable')
    (args.output / 'dmesg-before.txt').write_bytes(before.stdout)
    loaded_here = False
    helper = trusted / 'verifier'
    accounts = trusted / 'accounts'

    def install(path, data, mode=0o600):
        path.write_bytes(data)
        path.chmod(mode)

    def load(helper_path=helper, account_path=accounts, helper_pin=None, account_pin=None, success=True):
        nonlocal loaded_here
        require(not loaded_here and not Path('/sys/module', MODULE).exists(), 'test module already loaded')
        result = run(['/usr/sbin/insmod', str(artifacts / 'bashos_auth_v2_test.ko'), 'test_only=1',
                      'verifier_path=' + str(helper_path), 'verifier_sha256=' + (helper_pin or sha(helper_path)),
                      'accounts_path=' + str(account_path), 'accounts_sha256=' + (account_pin or sha(account_path))])
        loaded_here = Path('/sys/module', MODULE).exists()
        if not success:
            check(result.returncode != 0 and not loaded_here and not os.path.lexists(DEVICE),
                  'invalid trusted input was accepted')
            return
        check(result.returncode == 0 and loaded_here, 'real module did not load')
        for _ in range(100):
            if os.path.lexists(DEVICE): break
            time.sleep(.01)
        info = Path(DEVICE).stat()
        check(stat.S_ISCHR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
              'test device identity/permissions differ')

    def unload():
        nonlocal loaded_here
        if loaded_here:
            result = run(['/usr/sbin/rmmod', MODULE])
            require(result.returncode == 0 and not Path('/sys/module', MODULE).exists() and not os.path.lexists(DEVICE),
                    'test module cleanup failed')
            loaded_here = False

    def independent(password, salt, memory=1024, passes=1):
        lib = ctypes.CDLL(str(artifacts / 'libargon2.so.1'))
        fn = lib.argon2id_hash_raw
        fn.argtypes = [ctypes.c_uint32] * 3 + [ctypes.c_void_p, ctypes.c_size_t] * 3
        fn.restype = ctypes.c_int
        pw, sl, out = ctypes.create_string_buffer(password), ctypes.create_string_buffer(salt), ctypes.create_string_buffer(32)
        require(fn(passes, memory, 1, pw, len(password), sl, len(salt), out, 32) == 0, 'independent Argon2 failed')
        return out.raw

    try:
        check(independent(b'password', b'somesalt', 65536, 2).hex() ==
              '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7', 'independent known vector differs')
        CASES.append({'id': 'independent-libargon2-known-vector', 'status': 'PASS'})
        derived = independent(PASSWORD, SALT)
        b64 = lambda x: base64.b64encode(x).rstrip(b'=').decode()
        prefix = '$argon2id$v=19$m=1024,t=1,p=1$'
        standard, legacy = prefix + b64(SALT) + '$' + b64(derived), prefix + SALT.hex() + '$' + derived.hex()
        records = [struct.pack('<IIII64s512s', uid, gid, encoding, enabled, user.encode(), phc.encode())
                   for user, uid, gid, encoding, enabled, phc in [
                       ('alice', 42001, 42002, 1, 1, standard), ('legacy', 42003, 42004, 2, 1, legacy),
                       ('v2-root', 0, 0, 1, 1, standard), ('disabled', 42005, 42006, 1, 0, standard),
                       ('wrong-tag', 42007, 42008, 1, 1, legacy)]]
        snapshot = struct.pack('<IIIIQQ', MAGIC, VERSION, 32 + 592 * len(records), len(records), 1, 0) + b''.join(records)
        install(accounts, snapshot)
        install(helper, (artifacts / 'verifier-v2').read_bytes(), 0o700)
        report['trusted_fixture'] = {'accounts_sha256': sha(accounts), 'verifier_sha256': sha(helper),
                                     'account_generation': 1, 'records': len(records),
                                     'salt_hex': SALT.hex(), 'derived_hash_hex': derived.hex(),
                                     'independent_libargon2_sha256': receipt['files']['libargon2.so.1']['sha256']}
        load()
        reference_controls(trusted)
        def write_denied():
            fails(lambda: os.open(helper, os.O_WRONLY), {errno.ETXTBSY})
            fails(lambda: os.open(accounts, os.O_WRONLY), {errno.ETXTBSY})
        note('held-trusted-inodes-deny-writes', write_denied)
        def path_swap():
            saved_helper, saved_accounts = trusted / 'helper-held', trusted / 'accounts-held'
            helper.rename(saved_helper); accounts.rename(saved_accounts)
            try:
                install(helper, (artifacts / 'fault-verifier-1').read_bytes(), 0o700)
                install(accounts, b'not the pinned account snapshot')
                positive()
            finally:
                helper.unlink(); accounts.unlink()
                saved_helper.rename(helper); saved_accounts.rename(accounts)
        note('pathname-replacement-cannot-substitute-pinned-inode-or-snapshot', path_swap)
        unload()
        for mode in range(1, 16):
            install(helper, (artifacts / ('fault-verifier-' + str(mode))).read_bytes(), 0o700)
            load()
            def invalid_reply(mode=mode):
                with context() as fd:
                    expected = {errno.ETIMEDOUT} if mode == 2 else (
                        {errno.EACCES} if mode == 11 else {errno.EIO} if mode == 12 else {errno.EKEYREJECTED})
                    fails(lambda: verify(fd), expected)
                    check(os.read(fd, 32) == b'', 'invalid native reply queued a grant')
            note('pinned-fault-verifier-' + str(mode) + '-rejected', invalid_reply)
            unload()
        install(helper, (artifacts / 'verifier-v2').read_bytes(), 0o700)
        note('wrong-verifier-pin-rejected', lambda: load(helper_pin='01' * 32, success=False))
        note('wrong-accounts-pin-rejected', lambda: load(account_pin='01' * 32, success=False))
        link = trusted / 'helper-link'
        link.symlink_to(helper)
        note('symlink-verifier-rejected', lambda: load(helper_path=link, success=False))
        link.unlink()
        link.symlink_to(trusted, target_is_directory=True)
        note('symlink-parent-rejected', lambda: load(helper_path=link / helper.name, success=False))
        link.unlink()
        os.link(helper, link)
        note('hardlinked-verifier-rejected', lambda: load(success=False))
        link.unlink()
        helper.chmod(0o722)
        note('writable-verifier-rejected', lambda: load(success=False))
        helper.chmod(0o700)
        trusted.chmod(0o722)
        note('writable-parent-rejected', lambda: load(success=False))
        trusted.chmod(0o700)
        writer = os.open(helper, os.O_WRONLY)
        try: note('already-open-writer-rejected', lambda: load(success=False))
        finally: os.close(writer)
        install(helper, b'#!/bin/sh\nexit 0\n', 0o700)
        note('script-helper-rejected', lambda: load(success=False))
        # Construct a signed-but-invalid ELF dependency flag from the actual
        # native image. This checks the loader, without invoking /bin/true or a
        # separately unpinned dynamic executable.
        elf = bytearray((artifacts / 'verifier-v2').read_bytes())
        phoff, = struct.unpack_from('<Q', elf, 32)
        struct.pack_into('<I', elf, phoff, 3)  # PT_INTERP
        install(helper, elf, 0o700)
        note('elf-interpreter-header-rejected', lambda: load(success=False))
        install(helper, (artifacts / 'verifier-v2').read_bytes(), 0o700)
        mutations = [('magic', 0, '<I', 0), ('version', 4, '<I', 1), ('size', 8, '<I', 32),
                     ('count-zero', 12, '<I', 0), ('count-limit', 12, '<I', 33),
                     ('generation-zero', 16, '<Q', 0), ('reserved', 24, '<Q', 1),
                     ('invalid-uid', 32, '<I', 0xffffffff), ('unknown-encoding', 40, '<I', 3),
                     ('unknown-flags', 44, '<I', 2), ('noncanonical-name-tail', 60, '<B', 1)]
        for name, offset, form, value in mutations:
            data = bytearray(snapshot); struct.pack_into(form, data, offset, value)
            install(accounts, data)
            note('snapshot-' + name + '-rejected', lambda: load(success=False))
        data = bytearray(snapshot); data[32 + 592:32 + 2 * 592] = data[32:32 + 592]
        install(accounts, data)
        note('snapshot-duplicate-account-rejected', lambda: load(success=False))
        install(accounts, snapshot)
        load()
        note('native-positive-after-all-fault-controls', positive)
        unload()
        report['status'] = 'PASS'
    except AssertionError as error:
        report.update(status='FAIL', reason=str(error))
    except Exception as error:
        report.update(status='ERROR', reason=type(error).__name__ + ': ' + str(error))
    finally:
        try:
            unload()
            after = run(['/usr/bin/dmesg', '--raw'])
            require(after.returncode == 0 and after.stdout.startswith(before.stdout), 'kernel log lost/wrapped')
            delta = after.stdout[len(before.stdout):]
            (args.output / 'dmesg-after.txt').write_bytes(after.stdout)
            (args.output / 'dmesg-delta.txt').write_bytes(delta)
            forbidden = (b'WARNING:', b'BUG:', b'KASAN:', b'KCSAN:', b'UBSAN:', b'held lock',
                         b'possible recursive locking', b'inconsistent lock state', b'general protection fault',
                         b'INFO: task ', b'Oops:')
            require(not any(word in delta for word in forbidden), 'kernel diagnostics gate failed')
            report['kernel_diagnostics_clean'] = True
        except Exception as error:
            report.update(status='ERROR', cleanup_or_kernel_error=str(error))
        report['case_count'] = len(CASES)
        report['commands'] = COMMANDS
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        # Only our newly created, UUID-named trusted directory is removed.
        # Cleanup never removes preexisting production modules/accounts/files.
        if not loaded_here:
            shutil.rmtree(trusted)
    print(json.dumps({'status': report['status'], 'controls': len(CASES),
                      'report': str(args.output / 'report.json'), 'original_topic_credit': 0}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('Protocol v2 guard/prerequisite ERROR: ' + str(error), file=sys.stderr)
        sys.exit(125)
