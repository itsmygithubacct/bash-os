#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Guest-only fixture proposal; do not import or execute this file on the host.
import base64
import ctypes
import fcntl
import hashlib
import json
import os
import platform
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
MARKER = Path('/etc/bashos-parity-vm')
ATTEST = Path('/run/bashos-parity-vm-identity')
NS_ATTEST = Path('/run/bashos-syslog-namespace-208.json')
PID1 = Path('/proc/1')
CANDIDATE = Path('/opt/bashos-parity/candidate')

class Incomplete(Exception):
    pass

class Mismatch(Exception):
    pass

# These four functions are source-copied from the pinned 208 proposal.
def bounded_pseudo(path, limit):
    # procfs/sysfs often report st_size 0; bound actual bytes instead.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks, length = [], 0
        while length <= limit:
            chunk = os.read(fd, min(16384, limit + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
    finally:
        os.close(fd)
    if length > limit:
        raise Incomplete('pseudo-file cap: ' + str(path))
    return b''.join(chunks)


def protected_identity(path):
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise Incomplete('guest identity parent is not root-controlled')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1 or info.st_size != 37):
            raise Incomplete('guest identity file is not root-owned, immutable and single-link')
        raw = os.read(fd, 38)
    finally:
        os.close(fd)
    if len(raw) != 37 or raw[-1:] != b'\n':
        raise Incomplete('malformed guest identity bytes')
    token = raw[:-1].decode('ascii')
    if str(uuid.UUID(token)) != token:
        raise Incomplete('noncanonical guest identity')
    return token


def protected_namespace(token):
    """Compare our namespace links to the root-created bounded attestation."""
    parent = NS_ATTEST.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise Incomplete('namespace attestation parent is not root-controlled')
    fd = os.open(NS_ATTEST, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1
                or not 1 <= before.st_size <= 4096):
            raise Incomplete('namespace attestation file is not protected or bounded')
        parts, total = [], 0
        while total <= 4096:
            part = os.read(fd, 4097 - total)
            if not part:
                break
            parts.append(part)
            total += len(part)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    raw = b''.join(parts)
    if (total != before.st_size or total > 4096 or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise Incomplete('namespace attestation changed while reading')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Incomplete('duplicate namespace attestation field')
            result[key] = value
        return result
    try:
        proof = json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise Incomplete('invalid namespace attestation JSON') from error
    if (not isinstance(proof, dict) or set(proof) != {'schema', 'token', 'namespaces', 'outer_namespaces'}
            or proof['schema'] != 'bashos-syslog-namespace-attestation-v1' or proof['token'] != token):
        raise Incomplete('namespace attestation identity mismatch')
    inner, outer = proof['namespaces'], proof['outer_namespaces']
    if not isinstance(inner, dict) or not isinstance(outer, dict) or set(inner) != {'pid','net','mnt'} or set(outer) != set(inner):
        raise Incomplete('namespace attestation fields are invalid')
    for name in ('pid', 'net', 'mnt'):
        if (not isinstance(inner[name], str) or not re.fullmatch(name + r':\[[0-9]+\]', inner[name])
                or not isinstance(outer[name], str) or not re.fullmatch(name + r':\[[0-9]+\]', outer[name])
                or inner[name] == outer[name] or os.readlink('/proc/self/ns/' + name) != inner[name]):
            raise Incomplete('helper namespace differs from protected root attestation: ' + name)
    return proof


def scratch_capture_file(path, limit):
    """Read only a fixed self-proc file, retaining a bounded prefix on error."""
    data = bytearray()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            while len(data) <= limit:
                block = os.read(fd, min(16384, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
        finally:
            os.close(fd)
        return {'raw':bytes(data[:limit]), 'truncated':len(data) > limit, 'error':None}
    except (OSError, ValueError) as error:
        return {'raw':bytes(data[:limit]), 'truncated':len(data) > limit,
                'error':(type(error).__name__ + ': ' + str(error))[:320]}

def scratch_observe_fd(fd):
    info = os.fstat(fd)
    return {'directory':stat.S_ISDIR(info.st_mode), 'device':info.st_dev, 'inode':info.st_ino,
            'major':os.major(info.st_dev), 'minor':os.minor(info.st_dev),
            'uid':info.st_uid, 'gid':info.st_gid, 'mode':stat.S_IMODE(info.st_mode),
            'fdinfo':scratch_capture_file(Path('/proc/self/fdinfo') / str(fd), 4096)}

def scratch_observe():
    """Observe only /tmp, its expected directories and our own proc files."""
    observed = {'objects':{}, 'errors':[], 'cwd':None, 'home':os.environ.get('HOME')}
    try:
        observed['cwd'] = os.getcwd()
    except (OSError, ValueError) as error:
        observed['errors'].append(('cwd: '+type(error).__name__+': '+str(error))[:320])
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    tmp_fd = None
    try:
        tmp_fd = os.open('/tmp', flags)
        observed['objects']['tmp'] = scratch_observe_fd(tmp_fd)
        try:
            vfs = os.fstatvfs(tmp_fd)
            observed['tmp_capacity'] = {'block_size':vfs.f_frsize, 'blocks':vfs.f_blocks,
                                        'bytes':vfs.f_frsize * vfs.f_blocks}
        except (OSError, ValueError) as error:
            observed['errors'].append(('tmp statvfs: '+type(error).__name__+': '+str(error))[:320])
        for label, name in (('case','parity-case'), ('home','parity-home')):
            try:
                fd = os.open(name, flags, dir_fd=tmp_fd)
                try:
                    observed['objects'][label] = scratch_observe_fd(fd)
                finally:
                    os.close(fd)
            except (OSError, ValueError) as error:
                observed['errors'].append((label+': '+type(error).__name__+': '+str(error))[:320])
        try:
            fd = os.open('.', flags)
            try:
                observed['objects']['cwd'] = scratch_observe_fd(fd)
            finally:
                os.close(fd)
        except (OSError, ValueError) as error:
            observed['errors'].append(('cwd fd: '+type(error).__name__+': '+str(error))[:320])
        observed['mountinfo'] = scratch_capture_file('/proc/self/mountinfo', 131072)
    except (OSError, ValueError) as error:
        observed['errors'].append(('tmp: '+type(error).__name__+': '+str(error))[:320])
        observed['mountinfo'] = scratch_capture_file('/proc/self/mountinfo', 131072)
    finally:
        if tmp_fd is not None:
            os.close(tmp_fd)
    return observed

def scratch_mount_id(entry):
    fdinfo = entry.get('fdinfo', {})
    if fdinfo.get('error') or fdinfo.get('truncated') or not isinstance(fdinfo.get('raw'), bytes):
        raise Incomplete('scratch fdinfo is unavailable or capped')
    matches = [line.split(b':', 1)[1].strip() for line in fdinfo['raw'].splitlines()
               if line.startswith(b'mnt_id:')]
    if len(matches) != 1 or not matches[0].isdigit() or int(matches[0]) <= 0:
        raise Incomplete('scratch fdinfo lacks a unique mount ID')
    return int(matches[0])

def validate_scratch(observed):
    """Bind the active /tmp fd and owned scratch directories to one mount ID."""
    objects = observed.get('objects', {})
    if observed.get('errors') or set(objects) != {'tmp','case','home','cwd'}:
        raise Incomplete('scratch objects or fd observations are unavailable')
    tmp = objects['tmp']
    if (not tmp['directory'] or tmp['uid'] != 0 or tmp['gid'] != 0 or tmp['mode'] != 0o1777
            or observed.get('tmp_capacity', {}).get('bytes') != 128 * 1024**2):
        raise Incomplete('active scratch mount root or capacity differs from the fixed workspace')
    mount_id = scratch_mount_id(tmp)
    for label in ('case','home','cwd'):
        item = objects[label]
        if (not item['directory'] or item['device'] != tmp['device'] or scratch_mount_id(item) != mount_id
                or item['uid'] != 2000 or item['gid'] != 2000 or item['mode'] & 0o022):
            raise Incomplete('scratch directory is not owned on the active tmp mount: ' + label)
    if (observed.get('cwd') != str(CASE) or observed.get('home') != str(HOME)
            or (objects['cwd']['device'],objects['cwd']['inode']) != (objects['case']['device'],objects['case']['inode'])):
        raise Incomplete('scratch cwd or HOME differs from the pinned workspace')
    mountinfo = observed.get('mountinfo', {})
    if mountinfo.get('error') or mountinfo.get('truncated') or not isinstance(mountinfo.get('raw'), bytes):
        raise Incomplete('scratch mountinfo is unavailable or capped')
    candidates = [line for line in mountinfo['raw'].splitlines()
                  if line.split(None, 1)[:1] == [str(mount_id).encode('ascii')]]
    if len(candidates) != 1:
        raise Incomplete('scratch mount ID does not have exactly one mountinfo record')
    left, separator, right = candidates[0].partition(b' - ')
    before, after = left.split(), right.split()
    if (not separator or len(before) < 6 or len(after) < 3 or before[3] != b'/' or before[4] != b'/tmp'
            or before[2] != (str(tmp['major']) + ':' + str(tmp['minor'])).encode('ascii')
            or not {b'rw',b'nodev',b'nosuid'}.issubset(set(before[5].split(b',')))
            or after[0] != b'tmpfs' or after[1] != b'parity-scratch'):
        raise Incomplete('active scratch mount identity, source or options differ from the fixed workspace')

def scratch_emit_refusal(error, observed):
    """Emit bounded raw mount observations through the existing captured stderr."""
    report = {'schema':'bashos-scratch-guard224-v1', 'state':'refused',
              'error':(type(error).__name__+': '+str(error))[:320],
              'cwd':str(observed.get('cwd'))[:512], 'home':str(observed.get('home'))[:512],
              'errors':observed.get('errors',[])[:12], 'tmp_capacity':observed.get('tmp_capacity'),
              'objects':{}}
    for name, item in observed.get('objects', {}).items():
        entry = {key:item[key] for key in ('directory','device','inode','major','minor','uid','gid','mode')}
        info = item['fdinfo']; raw = info.get('raw',b'')
        entry['fdinfo'] = {'prefix_base64':base64.b64encode(raw[:512]).decode('ascii'),
                           'captured_bytes':len(raw), 'prefix_truncated':len(raw)>512,
                           'source_truncated':info.get('truncated'), 'error':info.get('error')}
        report['objects'][name] = entry
    mountinfo = observed.get('mountinfo', {})
    raw = mountinfo.get('raw',b'')
    rows = [line for line in raw.splitlines() if len(line.split()) > 4 and line.split()[4] == b'/tmp']
    report['mountinfo'] = {'prefix_base64':base64.b64encode(raw[:4096]).decode('ascii'),
        'captured_bytes':len(raw), 'prefix_truncated':len(raw)>4096,
        'source_truncated':mountinfo.get('truncated'), 'error':mountinfo.get('error'),
        'tmp_rows_base64':[base64.b64encode(line[:768]).decode('ascii') for line in rows[:8]],
        'tmp_row_count':len(rows), 'tmp_rows_truncated':len(rows)>8 or any(len(line)>768 for line in rows[:8])}
    try:
        mount_id = scratch_mount_id(observed.get('objects',{}).get('tmp',{}))
        active = [line for line in raw.splitlines() if line.split(None,1)[:1] == [str(mount_id).encode('ascii')]]
        report['mountinfo']['fd_mnt_id'] = mount_id
        report['mountinfo']['id_rows_base64'] = [base64.b64encode(line[:768]).decode('ascii') for line in active[:2]]
        report['mountinfo']['id_row_count'] = len(active)
        report['mountinfo']['id_rows_truncated'] = len(active)>2 or any(len(line)>768 for line in active[:2])
    except (Incomplete, OSError, ValueError, TypeError) as failure:
        report['mountinfo']['fd_mnt_id_error'] = (type(failure).__name__+': '+str(failure))[:320]
    encoded = json.dumps(report, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    if len(encoded.encode('ascii')) >= 24 * 1024:
        report['mountinfo']['prefix_base64'] = ''
        report['mountinfo']['tmp_rows_base64'] = report['mountinfo']['tmp_rows_base64'][:2]
        report['report_capped'] = True
        encoded = json.dumps(report, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    if len(encoded.encode('ascii')) >= 24 * 1024:
        encoded = json.dumps({'schema':'bashos-scratch-guard224-v1','state':'refused',
                              'error':report['error'],'report_capped':True}, sort_keys=True, separators=(',', ':'))
    print('SCRATCH224-GUARD-V1 ' + encoded, file=sys.stderr, flush=True)

def guard():
    """Keep the protected guest checks and report any guard refusal."""
    observation = None
    scratch_allowed = False
    try:
        if not __debug__ or platform.machine() != 'x86_64':
            raise Incomplete('expected unoptimized x86-64 guest execution')
        if os.getresuid() != (2000, 2000, 2000) or os.getresgid() != (2000, 2000, 2000) or os.getgroups() != []:
            raise Incomplete('expected real/effective/saved uid/gid 2000 without supplementary groups')
        token = protected_identity(MARKER)
        if protected_identity(ATTEST) != token:
            raise Incomplete('root-created attestation differs from guest marker')
        argv = bounded_pseudo(PID1 / 'cmdline', 8192).split(b'\0')
        if (argv.count(b'/opt/bashos-parity/harness/guest.py') != 1 or argv.count(b'--vm-token') != 1
                or argv.index(b'--vm-token') + 1 >= len(argv)
                or argv[argv.index(b'--vm-token') + 1] != token.encode('ascii')):
            raise Incomplete('PID 1 is not this guest evaluator')
        status = bounded_pseudo(PID1 / 'status', 16384).decode('ascii')
        uid = next((line.split()[1:5] for line in status.splitlines() if line.startswith('Uid:')), None)
        if uid != ['0', '0', '0', '0']:
            raise Incomplete('evaluation PID 1 is not guest root')
        if bounded_pseudo(Path('/sys/class/dmi/id/sys_vendor'), 256).strip() != b'QEMU':
            raise Incomplete('QEMU vendor not observed')
        proof = protected_namespace(token)
        if sorted(path.name for path in Path('/sys/class/net').iterdir()) != ['lo']:
            raise Incomplete('guest network is not loopback-only')
        scratch_allowed = True
        observation = scratch_observe()
        validate_scratch(observation)
        return {'token':token,'namespace_attestation':proof,
                'scratch_mount_id':scratch_mount_id(observation['objects']['tmp'])}
    except Exception as error:
        try:
            if scratch_allowed:
                if observation is None:
                    observation = scratch_observe()
                scratch_emit_refusal(error, observation)
            else:
                # Before guest identity, PID-1, namespace and loopback proof,
                # even a diagnostic must not inspect the scratch environment.
                early = {'schema':'bashos-scratch-guard224-v1', 'state':'refused',
                         'error':(type(error).__name__+': '+str(error))[:320],
                         'scratch_observation':'not-attempted'}
                print('SCRATCH224-GUARD-V1 '+json.dumps(early, sort_keys=True, separators=(',', ':')),
                      file=sys.stderr, flush=True)
        except Exception as reporting_error:
            try:
                fallback = {'schema':'bashos-scratch-guard224-v1', 'state':'refused',
                            'error':(type(error).__name__+': '+str(error))[:320],
                            'observation_error':(type(reporting_error).__name__+': '+str(reporting_error))[:320]}
                print('SCRATCH224-GUARD-V1 '+json.dumps(fallback, sort_keys=True, separators=(',', ':')),
                      file=sys.stderr, flush=True)
            except OSError:
                pass
        raise


# This fixture creates only direct children and a private same-UID peer. All
# time and byte caps are guest-side; the VM controller still owns whole-unit
# and VM teardown and must reject unproven cleanup.
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_CONT = 7
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GET_SYSCALL_INFO = 0x420e
PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_EXITKILL = 0x100000
AUDIT_ARCH_X86_64 = 0xc000003e
SYS_POLL = 7
MAX_LOG = 65536
MAX_CHILD_STDERR = 4096
MAX_TIME = 8.0
libc = None
STREAMS = []


def ptrace(request, pid, address=0, value=0):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(value))
    error = ctypes.get_errno()
    if result == -1 and error:
        raise Incomplete('ptrace request %d failed: errno %d' % (request, error))
    return result


def fd_write(fd, data):
    while data:
        n = os.write(fd, data)
        if n <= 0:
            raise Incomplete('short control write')
        data = data[n:]


def record(name, data):
    if not re.fullmatch(r'broker245-[a-z0-9-]+\.(?:bin|json|txt)', name) or len(data) > MAX_LOG:
        raise Incomplete('invalid or excessive evidence record')
    fd = os.open(HOME / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fd_write(fd, data)
    finally:
        os.close(fd)


def jrecord(name, value):
    record(name, (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def proc_identity(pid, expected):
    raw = bounded_pseudo(Path('/proc/%d/stat' % pid), 8192).decode('ascii')
    parts = raw[raw.rfind(')') + 2:].split()
    if len(parts) < 20 or int(parts[1]) != os.getpid() or int(parts[2]) != pid or int(parts[3]) != pid:
        raise Incomplete('child is not the direct session leader')
    status = bounded_pseudo(Path('/proc/%d/status' % pid), 16384).decode('ascii')
    uid = next((x.split()[1:5] for x in status.splitlines() if x.startswith('Uid:')), None)
    if uid != ['2000'] * 4:
        raise Incomplete('owned child UID mismatch')
    actual, target = os.stat('/proc/%d/exe' % pid), os.stat(expected)
    if (actual.st_dev, actual.st_ino) != (target.st_dev, target.st_ino):
        raise Incomplete('owned child executable mismatch')
    return {'pid': pid, 'ppid': int(parts[1]), 'pgrp': int(parts[2]),
            'session': int(parts[3]), 'starttime': int(parts[19]),
            'exe_dev': actual.st_dev, 'exe_ino': actual.st_ino}


class Lines:
    def __init__(self, fd):
        self.fd, self.buf = fd, b''
        os.set_blocking(fd, False)

    def line(self, timeout=MAX_TIME):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise Incomplete('bounded child control read timed out')
            chunk = os.read(self.fd, 4097 - len(self.buf))
            if not chunk or len(self.buf) + len(chunk) > 4096:
                raise Incomplete('child control EOF or cap')
            self.buf += chunk
        line, self.buf = self.buf.split(b'\n', 1)
        return line.decode('ascii')


class Owned:
    def __init__(self, argv, pass_fds=(), traced=False):
        self.pidfd = None
        self.proc = None
        self.reaped = False
        self.exit_status = None
        self.forced_cleanup = False
        self.identity = None
        self.stderr_file = tempfile.TemporaryFile(dir=HOME)
        def before_exec():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if traced:
                ptrace(PTRACE_TRACEME, 0)
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.stderr_file, close_fds=True, pass_fds=pass_fds, start_new_session=True,
                env={'LC_ALL':'C', 'LANG':'C', 'HOME':str(HOME), 'PATH':'/empty',
                     'BASH_ENV':'', 'ENV':'', 'HISTFILE':'/dev/null'}, preexec_fn=before_exec)
            try:
                self.pidfd = os.pidfd_open(self.proc.pid, 0)
            except Exception:
                # The child is still an unreaped direct child. Release only its
                # initial gate, without any numeric-PID signal. A traced exec
                # stop must first be resumed; a controller checks the unit too.
                if traced:
                    st = self.wait_event()
                    if os.WIFSTOPPED(st):
                        ptrace(PTRACE_CONT, self.proc.pid)
                self.proc.stdin.close()
                self.wait_event()
                raise
            self.lines = Lines(self.proc.stdout.fileno())
            if traced:
                st = self.wait_event()
                if not os.WIFSTOPPED(st) or os.WSTOPSIG(st) != signal.SIGTRAP:
                    raise Incomplete('missing traced exec stop')
                ptrace(PTRACE_SETOPTIONS, self.proc.pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)
            self.identity = proc_identity(self.proc.pid, argv[0])
        except BaseException:
            self.cleanup()
            raise

    def wait_event(self, timeout=MAX_TIME):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            pid, status = os.waitpid(self.proc.pid, os.WNOHANG | os.WUNTRACED)
            if pid:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    self.reaped = True
                    self.exit_status = status
                    self.proc.returncode = os.waitstatus_to_exitcode(status)
                return status
            time.sleep(0.001)
        raise Incomplete('owned-child wait exceeded deadline')

    def wait_exit(self):
        status = self.wait_event()
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise Incomplete('owned child did not exit cleanly')
        return status

    def send(self, data=b'GO\n'):
        fd_write(self.proc.stdin.fileno(), data)

    def cleanup(self):
        problem = None
        if self.proc is not None and not self.reaped:
            try:
                # pidfd refers to the exact child even if a numeric PID is reused.
                if self.pidfd is None:
                    raise Incomplete('missing owned pidfd')
                self.forced_cleanup = True
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                st = self.wait_event()
                while os.WIFSTOPPED(st):
                    st = self.wait_event()
                if not self.reaped:
                    raise Incomplete('child not reaped')
            except Exception as exc:
                problem = 'cleanup: ' + str(exc)
        if self.pidfd is not None:
            os.close(self.pidfd)
        if self.proc is not None:
            for f in (self.proc.stdin, self.proc.stdout):
                if f is not None:
                    f.close()
        self.stderr_file.seek(0)
        stderr = self.stderr_file.read(MAX_CHILD_STDERR + 1)
        self.stderr_file.close()
        if len(stderr) > MAX_CHILD_STDERR:
            problem = 'child stderr exceeded cap'
        else:
            STREAMS.append({'pid': self.proc.pid if self.proc is not None else None,
                            'stderr_hex': stderr.hex(), 'reaped':self.reaped,
                            'raw_wait_status':self.exit_status, 'forced_cleanup':self.forced_cleanup})
        if problem:
            raise Incomplete(problem)


class Peer:
    def __init__(self, partial):
        self.root = Path(tempfile.mkdtemp(prefix='p245-', dir=HOME))
        self.session = self.root / 'one'
        self.path = self.session / 'control.sock'
        self.server = None
        self.finished = False
        try:
            self.session.mkdir(mode=0o700)
            self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self.server.bind(str(self.path))
            os.chmod(self.path, 0o600)
            self.server.listen(1)
            self.server.settimeout(MAX_TIME)
        except BaseException:
            if self.server is not None:
                self.server.close()
            if self.path.exists():
                self.path.unlink()
            if self.session.exists():
                self.session.rmdir()
            self.root.rmdir()
            raise
        self.partial = partial
        self.log = {'error':None, 'request_hex':'', 'peer_pid':None, 'peer_uid':None, 'peer_gid':None,
                    'frames':[], 'eof':False}
        self.thread = None
        self.expected_pid = None
        self.payload = b''.join((i ^ 0x9e3779b97f4a7c15).to_bytes(8, 'big') for i in range(2048))

    @staticmethod
    def packet(kind, payload=b''):
        return struct.pack('=IIIIQ', 0x42505431, kind, len(payload), 0, 0) + payload

    def run(self):
        conn = None
        try:
            conn, _ = self.server.accept()
            conn.settimeout(MAX_TIME)
            pid, uid, gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            self.log['peer_pid'], self.log['peer_uid'], self.log['peer_gid'] = pid, uid, gid
            if (pid, uid, gid) != (self.expected_pid, 2000, 2000):
                raise Incomplete('mock peer credentials do not match owned child')
            data = conn.recv(20000)
            self.log['request_hex'] = data.hex()
            if data != self.packet(6):
                raise Incomplete('mock attach request differs from control request')
            status = struct.pack('=iiiiiIIII4xQQ', os.getpid(), os.getpid(), 1, 0, -1,
                                 24, 80, 1, 0, 0, 0)
            frames = [self.packet(38, status), self.packet(65, status)]
            if self.partial:
                frames.append(self.packet(64, self.payload))
            for frame in frames:
                sent = conn.send(frame)
                if sent != len(frame):
                    raise Incomplete('short seqpacket send')
                self.log['frames'].append({'type':struct.unpack_from('=I', frame, 4)[0],
                                           'size':len(frame), 'sha256':sha(frame),
                                           'frame_hex':frame.hex() if len(frame)<1024 else None,
                                           'send_completed_ns':time.monotonic_ns()})
                if self.partial and len(self.log['frames']) == 3:
                    record('broker245-peer-frame.bin', frame)
            while True:
                data = conn.recv(1024)
                if not data:
                    self.log['eof'] = True
                    break
                raise Incomplete('unexpected data from candidate on peer socket')
        except Exception as exc:
            self.log['error'] = type(exc).__name__ + ': ' + str(exc)
        finally:
            if conn is not None:
                conn.close()
            self.server.close()

    def start(self, pid):
        self.expected_pid = pid
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def finish(self):
        if self.finished:
            if self.log['error'] or not self.log['eof']:
                raise Incomplete('mock peer did not complete: ' + str(self.log['error']))
            return self.log
        if self.thread is None:
            self.server.close()
        else:
            self.thread.join(MAX_TIME + 1)
            if self.thread.is_alive():
                raise Incomplete('mock peer thread did not stop')
        if self.path.exists():
            self.path.unlink()
        self.session.rmdir()
        self.root.rmdir()
        self.finished = True
        if self.log['error'] or not self.log['eof']:
            raise Incomplete('mock peer did not complete: ' + str(self.log['error']))
        return self.log


BASH_BASE = r'''set -u
IFS= read -r gate || exit 71
[[ $gate == GO ]] || exit 72
ptybroker attach "$1" one control h || exit 73
'''
BASH_PARTIAL = BASH_BASE + r'''
ptybroker receive "$h" "$2" ev 1000 || exit 74
[[ $ev == attached\ * ]] || exit 75
printf 'ATTACHED\n'
IFS= read -r gate || exit 79
[[ $gate == GO ]] || exit 80
for i in 1 2 3 4; do
    ev=unset
    ptybroker receive "$h" "$2" ev 300; rc=$?
    printf 'PART %s %s %s\n' "$i" "$rc" "$ev"
    IFS= read -r gate || exit 76
    [[ $gate == STOP ]] && break
    [[ $gate == GO ]] || exit 77
done
ptybroker detach "$h" || exit 78
'''
BASH_TIMING = BASH_BASE + r'''
ptybroker receive "$h" "$2" ev 1000 || exit 74
[[ $ev == attached\ * ]] || exit 75
ptybroker fd "$h" sock || exit 76
printf 'READY %s %s\n' "$BASHPID" "$sock"
kill -STOP "$BASHPID" || exit 77
ev=unset
printf 'BEGIN\n'
if [[ $3 == default ]]; then ptybroker receive "$h" "$2" ev; rc=$?
else ptybroker receive "$h" "$2" ev 250; rc=$?; fi
printf 'RESULT %s %s\n' "$rc" "$ev"
ptybroker detach "$h" || exit 78
'''
BASH_BOUNDS = BASH_BASE + r'''
printf 'ATTACHED\n'
IFS= read -r gate || exit 79
[[ $gate == GO ]] || exit 80
ev=unset
ptybroker receive "$h" "$2" ev 60000; a=$?
printf 'MAX %s %s\n' "$a" "$ev"
ptybroker receive "$h" "$2" ev 60001; b=$?
printf 'OVER %s\n' "$b"
ptybroker detach "$h" || exit 78
'''


def shell_args(script, root, outfd, mode=''):
    return [str(CANDIDATE), '--noprofile', '--norc', '-c', script, 'broker245',
            str(root), str(outfd), mode]


def exact_read(fd, length):
    data = bytearray()
    end = time.monotonic() + MAX_TIME
    while len(data) < length:
        left = end - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise Incomplete('drain did not reach exact bounded length')
        chunk = os.read(fd, length - len(data))
        if not chunk:
            raise Incomplete('early output EOF')
        data.extend(chunk)
    return bytes(data)


def available_partial(fd, limit):
    """Capture bytes already written when the owned receive has returned."""
    data = bytearray()
    while len(data) < limit:
        try:
            chunk = os.read(fd, limit - len(data))
        except BlockingIOError:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def case_partial(token):
    peer, child, readfd, writefd = None, None, None, None
    log, observed = {}, []
    try:
        peer = Peer(True)
        expected = peer.payload
        blocks = [expected[i:i+4096] for i in range(0, len(expected), 4096)]
        if (len(expected) != 16384 or len(set(blocks)) != 4 or
                len({expected[i:i+8] for i in range(0, len(expected), 8)}) != 2048):
            raise Incomplete('bad independent input vector')
        controls = {'exact':expected, 'swapped':blocks[1]+blocks[0]+blocks[2]+blocks[3],
                    'duplicate_first':blocks[0]+blocks[0]+blocks[2]+blocks[3],
                    'drop_and_duplicate':blocks[0]+blocks[2]+blocks[3]+blocks[3]}
        if any(value == expected for name, value in controls.items() if name != 'exact'):
            raise Incomplete('fault control was not distinguished')
        record('broker245-expected.bin', expected)
        jrecord('broker245-controls.json', {'sha256':{n:sha(v) for n,v in controls.items()},
                 'block_sha256':[sha(x) for x in blocks],
                 'mutations':{'swapped':[1,0,2,3], 'duplicate_first':[0,0,2,3],
                              'drop_and_duplicate':[0,2,3,3]},
                 'compared_as_bytes':True})
        readfd, writefd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        actual = fcntl.fcntl(writefd, fcntl.F_SETPIPE_SZ, 4096)
        if actual != 4096 or fcntl.fcntl(writefd, fcntl.F_GETPIPE_SZ) != 4096:
            raise Incomplete('cannot establish pipe capacity')
        child = Owned(shell_args(BASH_PARTIAL, peer.root, writefd), (writefd,))
        os.close(writefd); writefd = None
        peer.start(child.proc.pid)
        child.send()
        if child.lines.line() != 'ATTACHED':
            raise Incomplete('attached-event prerequisite not established')
        end = time.monotonic() + MAX_TIME
        while len(peer.log['frames']) < 3 and not peer.log['error'] and time.monotonic() < end:
            time.sleep(0.001)
        if len(peer.log['frames']) != 3 or peer.log['error']:
            raise Incomplete('full output frame not sent before partial receive')
        queued_before_go_ns = time.monotonic_ns()
        child.send()
        lines = []
        want = ['PART 1 124 unset', 'PART 2 124 unset', 'PART 3 124 unset',
                'PART 4 0 output size=16384 offset=0']
        mismatch = False
        for index in range(1, 5):
            line = child.lines.line()
            lines.append(line)
            block = available_partial(readfd, 4096)
            record('broker245-drain-%d.bin' % index, block)
            observed.append(block)
            mismatch = line != want[index - 1] or block != blocks[index - 1][:len(block)]
            if mismatch:
                child.send(b'STOP\n')
                break
            if len(block) != 4096:
                raise Incomplete('short prefix without an attributable mismatch')
            child.send()
        child.wait_exit()
        peerlog = peer.finish(); peer = None
        extra = os.read(readfd, 1)
        log = {'token':token, 'identity':child.identity, 'peer':peerlog,
               'pipe_capacity':actual, 'lines':lines, 'queued_before_go_ns':queued_before_go_ns,
               'observed_block_sha256':[sha(x) for x in observed],
               'expected_sha256':sha(expected), 'observed_sha256':sha(b''.join(observed))}
        log['extra_hex'] = extra.hex()
        log['mismatch'] = []
        if extra or mismatch or (len(lines) == 4 and (lines != want or b''.join(observed) != expected)):
            log['mismatch'].append('partial status, event metadata or raw bytes differ')
        return log
    finally:
        if child is not None:
            child.cleanup()
        if writefd is not None:
            os.close(writefd)
        if readfd is not None:
            os.close(readfd)
        if peer is not None:
            peer.finish()

# Python's select.poll is an independent, fixed-argument native poll control.
# If this interpreter uses a different syscall or ptrace is unavailable, the
# control cannot establish the premise and the result is INCOMPLETE.
CONTROL = r'''import os, select, signal, sys
os.read(0, 3)
fd, timeout = int(sys.argv[1]), int(sys.argv[2])
print('READY %d %d' % (os.getpid(), fd), flush=True)
os.kill(os.getpid(), signal.SIGSTOP)
p = select.poll()
p.register(fd, select.POLLIN)
print('BEGIN', flush=True)
events = p.poll(timeout)
print('RESULT %d' % len(events), flush=True)
'''


def syscall_info(pid):
    buf = ctypes.create_string_buffer(128)
    size = ptrace(PTRACE_GET_SYSCALL_INFO, pid, 128, ctypes.addressof(buf))
    raw = buf.raw
    if size < 24 or struct.unpack_from('=I', raw, 4)[0] != AUDIT_ARCH_X86_64:
        raise Incomplete('missing x86-64 ptrace syscall information')
    op = raw[0]
    if op == 1 and size >= 80:
        return op, struct.unpack_from('=7Q', raw, 24), raw[:min(size,128)].hex()
    if op == 2 and size >= 33:
        return op, struct.unpack_from('=q', raw, 24)[0], raw[:min(size,128)].hex()
    return op, None, raw[:min(size,128)].hex()


def traced_bytes(pid, address, length):
    if not 1 <= length <= 256:
        raise Incomplete('traced result write is not bounded')
    words = []
    for offset in range(0, length, 8):
        word = ptrace(PTRACE_PEEKDATA, pid, address + offset) & ((1 << 64) - 1)
        words.append(struct.pack('=Q', word))
    return b''.join(words)[:length]


def poll_entry(child, fd):
    pid = child.proc.pid
    ptrace(PTRACE_SYSCALL, pid)
    marker_entry = False
    marker_raw = None
    marker_word = None
    marker_exit_raw = None
    begin_resume = None
    for _ in range(5000):
        status = child.wait_event()
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP | 0x80:
            raise Incomplete('unexpected event while looking for poll entry')
        op, args, info_hex = syscall_info(pid)
        if op == 1 and args is not None and args[0] == 1 and args[1] == 1 and args[3] == 6:
            word = ptrace(PTRACE_PEEKDATA, pid, args[2]) & ((1 << 64) - 1)
            marker_entry = struct.pack('=Q', word)[:6] == b'BEGIN\n'
            if marker_entry:
                marker_raw, marker_word = info_hex, struct.pack('=Q', word).hex()
        elif op == 2 and marker_entry:
            marker_entry = False
            if args != 6 or child.lines.line() != 'BEGIN' or begin_resume is not None:
                raise Incomplete('begin marker was not a complete owned write')
            # The target call follows this marker; this timestamp precedes
            # resumption, so the marker-to-result interval is an upper bound.
            marker_exit_raw = info_hex
            begin_resume = time.monotonic_ns()
        elif (op == 1 and args is not None and begin_resume is not None and
              args[0] == 1 and args[1] == 1 and 1 <= args[3] <= 256):
            output = traced_bytes(pid, args[2], args[3])
            if output.startswith(b'RESULT ') and output.endswith(b'\n') and output.count(b'\n') == 1:
                return {'kind':'result_without_poll', 'fd':fd, 'begin_resume_ns':begin_resume,
                        'marker_entry_info_hex':marker_raw, 'marker_exit_info_hex':marker_exit_raw,
                        'marker_word_hex':marker_word, 'result_entry_info_hex':info_hex,
                        'result_write_hex':output.hex(), 'result_entry_ns':time.monotonic_ns()}
        elif op == 1 and args is not None and args[0] == SYS_POLL:
            if begin_resume is None:
                raise Incomplete('poll preceded the owned begin marker')
            nr, address, nfds, milliseconds = args[:4]
            data = ptrace(PTRACE_PEEKDATA, pid, address) & ((1 << 64) - 1)
            target, events, revents = struct.unpack('=iHH', struct.pack('=Q', data))
            if nfds != 1 or target != fd or events != select.POLLIN or revents != 0:
                raise Incomplete('poll is not on the expected readable owned descriptor')
            return {'address':address, 'fd':target, 'nfds':nfds,
                    'events':events, 'milliseconds':milliseconds,
                    'begin_resume_ns':begin_resume, 'entry_observed_ns':time.monotonic_ns(),
                    'syscall_info_hex':info_hex, 'pollfd_word_hex':struct.pack('=Q',data).hex(),
                    'marker_entry_info_hex':marker_raw, 'marker_exit_info_hex':marker_exit_raw,
                    'marker_word_hex':marker_word}
        ptrace(PTRACE_SYSCALL, pid)
    raise Incomplete('syscall stop count cap')


def poll_sample(child, entry):
    pid = child.proc.pid
    before = time.monotonic_ns()
    stat1 = bounded_pseudo(Path('/proc/%d/stat' % pid), 8192).decode('ascii')
    fields1 = stat1[stat1.rfind(')') + 2:].split()
    syscall_raw = bounded_pseudo(Path('/proc/%d/syscall' % pid), 8192).decode('ascii')
    raw = syscall_raw.split()
    stat2 = bounded_pseudo(Path('/proc/%d/stat' % pid), 8192).decode('ascii')
    fields2 = stat2[stat2.rfind(')') + 2:].split()
    after = time.monotonic_ns()
    if (len(fields1) < 20 or len(fields2) < 20 or fields1[0] != 'S' or fields2[0] != 'S'
            or int(fields1[19]) != child.identity['starttime']
            or int(fields2[19]) != child.identity['starttime'] or len(raw) < 4):
        return None
    try:
        values = [int(value, 0) for value in raw[:4]]
    except ValueError:
        return None
    if values != [SYS_POLL, entry['address'], entry['nfds'], entry['milliseconds']]:
        return None
    return {'before_ns':before, 'after_ns':after, 'stat_before':stat1,
            'syscall_raw':syscall_raw, 'stat_after':stat2}


def trace_wait(child, fd):
    entry = poll_entry(child, fd)
    if entry.get('kind') == 'result_without_poll':
        ptrace(PTRACE_SYSCALL, child.proc.pid)
        status = child.wait_event()
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP | 0x80:
            raise Incomplete('unpolled result write did not reach its exit stop')
        op, written, info_hex = syscall_info(child.proc.pid)
        expected = bytes.fromhex(entry['result_write_hex'])
        if op != 2 or written != len(expected):
            raise Incomplete('unpolled result write was not completed')
        line = child.lines.line()
        result_observed = time.monotonic_ns()
        if (line + '\n').encode('ascii') != expected:
            raise Incomplete('unpolled result bytes differ from traced write')
        ptrace(PTRACE_CONT, child.proc.pid)
        child.wait_exit()
        return {'kind':'result_without_poll', 'entry':entry, 'result_exit_info_hex':info_hex,
                'result_line':line, 'result_observed_ns':result_observed,
                'begin_to_result_upper_ns':result_observed-entry['begin_resume_ns'],
                'identity':child.identity}
    resume_before = time.monotonic_ns()
    ptrace(PTRACE_SYSCALL, child.proc.pid)
    first, last, samples = None, None, 0
    end = time.monotonic() + MAX_TIME
    while time.monotonic() < end:
        pid, status = os.waitpid(child.proc.pid, os.WNOHANG | os.WUNTRACED)
        if pid:
            exit_observed = time.monotonic_ns()
            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP | 0x80:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    child.reaped = True
                    child.proc.returncode = os.waitstatus_to_exitcode(status)
                raise Incomplete('poll did not reach a syscall-exit stop')
            op, result, exit_info_hex = syscall_info(pid)
            if op != 2 or result != 0:
                raise Incomplete('poll did not return zero at its traced exit')
            break
        sample = poll_sample(child, entry)
        if sample:
            if first is None:
                first = sample
            last = sample
            samples += 1
        time.sleep(0.001)
    else:
        raise Incomplete('poll wait witness exceeded deadline')
    ptrace(PTRACE_CONT, child.proc.pid)
    line = child.lines.line()
    result_observed = time.monotonic_ns()
    child.wait_exit()
    lower = max(0, last['before_ns'] - first['after_ns']) if first and last else 0
    return {'entry':entry, 'resume_before_ns':resume_before, 'exit_observed_ns':exit_observed,
            'first_blocked_sample':first, 'last_blocked_sample':last, 'sample_count':samples,
            'blocked_lower_ns':lower, 'observed_upper_ns':exit_observed-resume_before,
            'poll_return':result, 'poll_exit_info_hex':exit_info_hex,
            'result_line':line, 'result_observed_ns':result_observed,
            'begin_to_result_upper_ns':result_observed-entry['begin_resume_ns'],
            'identity':child.identity}


def start_traced(child):
    child.send()
    ptrace(PTRACE_CONT, child.proc.pid)
    status = child.wait_event()
    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
        raise Incomplete('missing owned phase stop')
    words = child.lines.line().split()
    if len(words) != 3 or words[0] != 'READY' or int(words[1]) != child.proc.pid:
        raise Incomplete('phase marker does not bind the owned child')
    return int(words[2])


def trace_control(milliseconds):
    readfd, writefd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    child = None
    try:
        child = Owned(['/usr/bin/python3', '-I', '-c', CONTROL, str(readfd), str(milliseconds)],
                      (readfd,), traced=True)
        target = start_traced(child)
        if target != readfd:
            raise Incomplete('fixed poll control descriptor mismatch')
        result = trace_wait(child, target)
        if result['entry']['milliseconds'] != milliseconds or result['result_line'] != 'RESULT 0':
            raise Incomplete('fixed poll control does not match its source')
        return result
    finally:
        if child is not None:
            child.cleanup()
        os.close(readfd)
        os.close(writefd)


def verify_peer_fd(child, fd, path):
    # x86-64 pidfd_getfd duplicates only the candidate-reported descriptor;
    # no process-table or unrelated descriptor scan is performed.
    ctypes.set_errno(0)
    copied = libc.syscall(438, child.pidfd, fd, 0)
    if copied < 0:
        raise Incomplete('pidfd_getfd for exact peer descriptor failed: errno %d' % ctypes.get_errno())
    sock = socket.socket(fileno=copied)
    try:
        kind = sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        cred = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        endpoint = sock.getpeername()
        info = os.fstat(copied)
        if kind != socket.SOCK_SEQPACKET or cred != (os.getpid(), 2000, 2000) or endpoint != str(path):
            raise Incomplete('owned poll descriptor is not connected to the private peer')
        return {'fd':fd, 'socket_type':kind, 'peer_pid':cred[0], 'peer_uid':cred[1],
                'peer_gid':cred[2], 'path':endpoint, 'device':info.st_dev, 'inode':info.st_ino}
    finally:
        sock.close()


def trace_candidate(mode):
    peer, child, outfd = None, None, None
    try:
        peer = Peer(False)
        outfd = os.open('/dev/null', os.O_WRONLY | os.O_CLOEXEC)
        child = Owned(shell_args(BASH_TIMING, peer.root, outfd, mode), (outfd,), traced=True)
        peer.start(child.proc.pid)
        target = start_traced(child)
        binding = verify_peer_fd(child, target, peer.path)
        result = trace_wait(child, target)
        result['descriptor_binding'] = binding
        result['peer'] = peer.finish(); peer = None
        return result
    finally:
        if child is not None:
            child.cleanup()
        if outfd is not None:
            os.close(outfd)
        if peer is not None:
            peer.finish()


def timeout_bounds():
    peer, child, outfd = None, None, None
    try:
        peer = Peer(False)
        outfd = os.open('/dev/null', os.O_WRONLY | os.O_CLOEXEC)
        child = Owned(shell_args(BASH_BOUNDS, peer.root, outfd), (outfd,))
        peer.start(child.proc.pid)
        child.send()
        if child.lines.line() != 'ATTACHED':
            raise Incomplete('missing queued-event phase')
        end = time.monotonic() + MAX_TIME
        while len(peer.log['frames']) < 2 and time.monotonic() < end:
            time.sleep(0.001)
        if len(peer.log['frames']) != 2 or peer.log['error']:
            raise Incomplete('attached event was not proven queued')
        queued_before_go_ns=time.monotonic_ns()
        child.send()
        maximum, over = child.lines.line(), child.lines.line()
        child.wait_exit()
        result = {'maximum':maximum, 'over':over, 'identity':child.identity,
                  'queued_before_go_ns':queued_before_go_ns,
                  'peer':peer.finish()}
        peer = None
        return result
    finally:
        if child is not None:
            child.cleanup()
        if outfd is not None:
            os.close(outfd)
        if peer is not None:
            peer.finish()


def case_timeout(token):
    positive = trace_control(100)
    negative = trace_control(10)
    if positive['blocked_lower_ns'] < 75_000_000:
        raise Incomplete('100 ms independent poll control lacks a 75 ms blocked interval')
    if negative['begin_to_result_upper_ns'] >= 75_000_000:
        raise Incomplete('early-return poll control cannot be distinguished under this scheduling')
    result = {'token':token, 'control_100':positive, 'control_10':negative, 'mismatch':[]}
    for label, mode, nominal, minimum in (('default','default',100,75_000_000),
                                           ('explicit_250','explicit',250,200_000_000)):
        sample = trace_candidate(mode)
        result[label] = sample
        if sample['result_line'].split()[:2] != ['RESULT', '124']:
            result['mismatch'].append(label + ' status')
        elif sample['begin_to_result_upper_ns'] < minimum:
            # Everything from the pre-call marker through result observation,
            # including tracer and scheduler delay, fits inside this bound.
            result['mismatch'].append(label + ' returned before its minimum wait')
        elif sample.get('kind') == 'result_without_poll':
            raise Incomplete(label + ' no-poll wait interval is not established')
        elif not nominal-20 <= sample['entry']['milliseconds'] <= nominal or sample['blocked_lower_ns'] < minimum:
            raise Incomplete(label + ' wait interval or timeout argument is not established')
        if result['mismatch']:
            # A reached, fully attributed mismatch is not erased by unrelated
            # later probes; the report explicitly records their absence.
            result['unreached'] = (['explicit_250', 'bounds'] if label == 'default' else ['bounds'])
            return result
    bounds = timeout_bounds()
    result['bounds'] = bounds
    if not bounds['maximum'].startswith('MAX 0 attached ') or bounds['over'] != 'OVER 2':
        result['mismatch'].append('60000 acceptance or 60001 rejection')
    result['unreached'] = []
    return result


def main():
    global libc
    guard_record = guard()
    token = guard_record['token']
    if len(sys.argv) != 3 or sys.argv[1] not in ('setup', 'case') or sys.argv[2] not in ('timeout', 'partial'):
        raise Incomplete('invalid fixture invocation')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise Incomplete('pidfd support unavailable')
    if not CANDIDATE.is_file():
        raise Incomplete('candidate binary missing')
    if sys.argv[1] == 'setup':
        jrecord('broker245-setup.json', {'schema':'bashos-broker256-setup-v1',
                'scenario':sys.argv[2], 'guard':guard_record})
        print('broker245 setup=ok')
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.syscall.restype = ctypes.c_long
    name = sys.argv[2]
    result = case_timeout(token) if name == 'timeout' else case_partial(token)
    mismatch = bool(result.get('mismatch'))
    result['guard'] = guard_record
    result['child_stderr'] = STREAMS
    result['classification'] = 'FAIL' if mismatch else 'PASS'
    result['schema'] = 'bashos-broker256-evidence-v1'
    jrecord('broker245-report.json', result)
    print('broker245 %s=%s' % (name, result['classification']))
    return 1 if mismatch else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('broker245 incomplete: %s: %s' % (type(error).__name__, str(error)), file=sys.stderr)
        raise SystemExit(125)
