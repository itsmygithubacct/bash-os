#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only FIFO observations; never import or probe this helper on the host."""
import base64
import ctypes
import json
import os
from pathlib import Path
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
import time
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
MARKER = Path('/etc/bashos-parity-vm')
ATTEST = Path('/run/bashos-parity-vm-identity')
NS_ATTEST = Path('/run/bashos-syslog-namespace-208.json')
PID1 = Path('/proc/1')
CANDIDATE = Path('/opt/bashos-parity/candidate')
SELF = Path('/opt/bashos-parity/harness/helpers/system-client-syslog-fifo-231.py')
NS = 1_000_000_000
START = (b'fifo169-start-a', b'fifo169-start-b', b'fifo169-start-c')
WARM = b'fifo169-warm'
HUP = (b'fifo169-hup-a', b'fifo169-hup-b', b'fifo169-hup-c')
PERIODIC = (b'fifo169-periodic-a', b'fifo169-periodic-b', b'fifo169-periodic-c')
FINISH = b'fifo169-finish'
MAX_QUEUE = 8192
MAX_STREAM = 32768
MAX_PACKETS = 24
MAX_REPORT = 196608
OVERALL_SECONDS = 32
SO_TIMESTAMPNS_NEW = 64  # Linux x86-64 UAPI; payload is two signed 64-bit fields.
CLOCK_BRACKET_NS = 1_000_000
CLOCK_DRIFT_NS = 2_000_000
CLOCK_PAD_NS = 2_000_000
MAX_CLOCK_SAMPLES = 1024


class Incomplete(Exception):
    """A control, attribution, timing or capture condition was not established."""


class CandidateMismatch(Exception):
    """A possible product mismatch requiring attribution after capture closes."""

    def __init__(self, message, kind, **witness):
        super().__init__(message)
        self.witness = {'kind': kind, **witness}


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


class ClockBridge:
    """Bound realtime-to-monotonic offset; reject observed clock steps or coarse samples."""
    def __init__(self):
        self.samples = []
        self.sample()

    def sample(self):
        before = time.monotonic_ns()
        realtime = time.time_ns()
        after = time.monotonic_ns()
        if after - before > CLOCK_BRACKET_NS or len(self.samples) >= MAX_CLOCK_SAMPLES:
            raise Incomplete('clock sample is too slow or clock sample cap was reached')
        self.samples.append({'mono_before_ns':before,'realtime_ns':realtime,'mono_after_ns':after,
                             'offset_low_ns':realtime-after,'offset_high_ns':realtime-before})
        if max(x['offset_high_ns'] for x in self.samples) - min(x['offset_low_ns'] for x in self.samples) > CLOCK_DRIFT_NS:
            raise Incomplete('realtime/monotonic offset changed during observation')

    def interval(self, kernel_realtime_ns):
        if type(kernel_realtime_ns) is not int:
            raise Incomplete('missing kernel receive timestamp')
        low = kernel_realtime_ns - max(x['offset_high_ns'] for x in self.samples) - CLOCK_PAD_NS
        high = kernel_realtime_ns - min(x['offset_low_ns'] for x in self.samples) + CLOCK_PAD_NS
        if low > high:
            raise Incomplete('invalid kernel receive time interval')
        return low, high


class RealtimeFence:
    """Guest-only kernel cancellation witness; no system-clock writes."""
    def __init__(self):
        self.fd = None
        self.checks = []
        self.report = {'schema':'bashos-realtime-fence231-v1', 'checks':self.checks,
                       'clockid':0, 'settime_flags':3}
        libc = ctypes.CDLL(None, use_errno=True)
        libc.timerfd_create.restype = ctypes.c_int
        libc.timerfd_settime.restype = ctypes.c_int
        self.fd = libc.timerfd_create(time.CLOCK_REALTIME, os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            self.fd = None
            raise Incomplete('realtime timerfd creation failed: %d' % ctypes.get_errno())
        try:
            before = time.monotonic_ns()
            expires = time.time_ns() // NS + 120
            spec = (ctypes.c_long * 4)(0, 0, expires, 0)
            if libc.timerfd_settime(self.fd, 3, ctypes.byref(spec), None) != 0:
                raise Incomplete('realtime timerfd cancellation guard unavailable: %d' % ctypes.get_errno())
            after = time.monotonic_ns()
            raw = bounded_pseudo(Path('/proc/self/fdinfo') / str(self.fd), 4096)
            info = raw.decode('ascii').splitlines()
            clocks = [x.split(':',1)[1].strip() for x in info if x.startswith('clockid:')]
            flags = [x.split(':',1)[1].strip() for x in info if x.startswith('settime flags:')]
            if clocks != ['0'] or len(flags) != 1 or int(flags[0],8) != 3:
                raise Incomplete('realtime timerfd flags or clock could not be attested')
            self.report.update(armed_before_ns=before, armed_after_ns=after,
                               expiry_realtime_sec=expires, fdinfo_hex=raw.hex())
            self.check('armed')
        except BaseException:
            self.close()
            raise

    def check(self, label):
        if self.fd is None or len(self.checks) >= 16:
            raise Incomplete('realtime fence unavailable or check cap reached')
        before = time.monotonic_ns()
        try:
            data = os.read(self.fd, 8)
        except BlockingIOError:
            self.checks.append({'label':label,'before_ns':before,'after_ns':time.monotonic_ns(),
                                'result':'EAGAIN'})
            return
        except OSError as error:
            raise Incomplete('realtime fence reported clock change or read error: %d' % error.errno) from error
        raise Incomplete('realtime fence unexpectedly expired or returned data: ' + data.hex())

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def expired_timer_control():
    """An actually expired timer must be readable, never accepted as a quiet fence."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.timerfd_create.restype = ctypes.c_int
    libc.timerfd_settime.restype = ctypes.c_int
    fd = libc.timerfd_create(time.CLOCK_REALTIME, os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise Incomplete('expired timer control unavailable')
    try:
        expiry = max(1, time.time_ns() // NS - 1)
        spec = (ctypes.c_long * 4)(0, 0, expiry, 0)
        if libc.timerfd_settime(fd, 3, ctypes.byref(spec), None) != 0:
            raise Incomplete('expired timer control could not arm')
        if not select.select([fd], [], [], 1)[0]:
            raise Incomplete('expired timer control was not readable')
        data = os.read(fd, 8)
        if len(data) != 8 or struct.unpack('=Q', data)[0] < 1:
            raise Incomplete('expired timer control returned no expiration')
        return {'result':'expired-readable', 'count':struct.unpack('=Q', data)[0]}
    finally:
        os.close(fd)


def realtime_after_marker(marker, stamp, fence_quiet):
    return (fence_quiet is True and type(marker) is int and type(stamp) is int
            and 0 < marker < stamp)


def finish_order_ok(finish, sample, packet, low, high, fence_quiet):
    """Strict post-send realtime witness and conservative monotonic deadline."""
    values = (finish.get('started_ns'), finish.get('returned_ns'), finish.get('deadline_ns'),
              sample.get('mono_before_ns'), sample.get('mono_after_ns'), sample.get('realtime_ns'),
              packet.get('time_ns'), packet.get('kernel_realtime_ns'), low, high)
    if not all(type(value) is int for value in values):
        return False
    started, returned, deadline, before, after, marker, observed, stamp, low, high = values
    return (0 <= started <= returned <= before <= after <= min(observed, deadline)
            and after - before <= CLOCK_BRACKET_NS and low <= high < deadline
            and realtime_after_marker(marker, stamp, fence_quiet))


def kernel_receive(sock):
    data, ancillary, flags, peer = sock.recvmsg(4096, socket.CMSG_SPACE(16))
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or peer[0] != '127.0.0.1':
        raise Incomplete('UDP or ancillary data truncated, or source is non-loopback')
    records = [value for level, kind, value in ancillary
               if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS_NEW]
    if len(records) != 1 or len(records[0]) != 16:
        raise Incomplete('missing or malformed kernel nanosecond receive timestamp')
    sec, nsec = struct.unpack('=qq', records[0])
    if sec <= 0 or not 0 <= nsec < NS:
        raise Incomplete('invalid kernel receive timestamp')
    return data, peer, sec*NS+nsec


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
        protected_namespace(token)
        if sorted(path.name for path in Path('/sys/class/net').iterdir()) != ['lo']:
            raise Incomplete('guest network is not loopback-only')
        scratch_allowed = True
        observation = scratch_observe()
        validate_scratch(observation)
        return token
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


def encoded_records(records):
    if len(records) < 3 or len(set(records)) != len(records):
        raise Incomplete('control records must be distinct')
    raw = b''.join(item.hex().encode('ascii') + b'\n' for item in records)
    if len(raw) >= MAX_QUEUE:
        raise Incomplete('queue input cap')
    return raw


def read_queue(path):
    """Distinguish confirmed absence from every permission/type/size error."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {'state': 'absent', 'time_ns': time.monotonic_ns()}
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 2000 or before.st_nlink != 1
                or before.st_size >= MAX_QUEUE):
            raise Incomplete('queue identity or size invalid')
        data = os.read(fd, MAX_QUEUE)
        after = os.fstat(fd)
        if (len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise Incomplete('queue changed while being recorded')
        return {'state': 'file', 'dev': before.st_dev, 'ino': before.st_ino, 'size': before.st_size,
                'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
                'raw_hex': data.hex(), 'time_ns': time.monotonic_ns()}
    finally:
        os.close(fd)


def queue_empty(snapshot):
    return snapshot['state'] == 'absent' or (snapshot['state'] == 'file' and snapshot['size'] == 0)


def queue_write(path, raw, label):
    if len(raw) >= MAX_QUEUE or not queue_empty(read_queue(path)):
        raise Incomplete('queue was not empty or input was too large: ' + label)
    temp = path.parent / ('queue-stage-' + label)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise Incomplete('short queue write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    start = time.monotonic_ns()
    os.replace(temp, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    saved = read_queue(path)
    if saved.get('state') != 'file' or saved.get('raw_hex') != raw.hex():
        raise Incomplete('queue changed before its snapshot: ' + label)
    saved.update(label=label, replace_started_ns=start)
    return saved


def save_report(name, value):
    if not re.fullmatch(r'fifo169-(setup|result)\.json', name):
        raise Incomplete('invalid diagnostic name')
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    capped = len(raw) >= MAX_REPORT
    if capped:
        value['classification'] = 'INCOMPLETE'
        raw = b'{"classification":"INCOMPLETE","error":"report cap reached"}\n'
    fd = os.open(HOME / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise Incomplete('short report write')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    return not capped


def proc_identity(pid):
    if type(pid) is not int or pid <= 1:
        raise Incomplete('invalid owned PID')
    root = Path('/proc') / str(pid)
    raw = bounded_pseudo(root / 'stat', 8192)
    right = raw.rfind(b')')
    if right < 0 or raw.split(b' ', 1)[0] != str(pid).encode('ascii'):
        raise Incomplete('malformed process stat')
    fields = raw[right + 2:].split()
    status = bounded_pseudo(root / 'status', 16384).decode('ascii')
    uids = next((list(map(int, x.split()[1:5])) for x in status.splitlines() if x.startswith('Uid:')), None)
    gids = next((list(map(int, x.split()[1:5])) for x in status.splitlines() if x.startswith('Gid:')), None)
    if len(fields) < 20 or fields[0] == b'Z' or uids != [2000]*4 or gids != [2000]*4:
        raise Incomplete('process is not live guest uid/gid 2000')
    return {'pid': pid, 'state': fields[0].decode('ascii'), 'ppid': int(fields[1]), 'pgrp': int(fields[2]), 'session': int(fields[3]),
            'starttime': int(fields[19]), 'uid': uids, 'gid': gids, 'stat_hex': raw.hex(),
            'time_ns': time.monotonic_ns()}


def same_birth(first, second):
    return all(first[k] == second[k] for k in ('pid', 'ppid', 'pgrp', 'session', 'starttime', 'uid', 'gid'))


def require_direct_child(proc, initial=None):
    identity = proc_identity(proc.pid)
    if (identity['ppid'] != os.getpid() or identity['pgrp'] != proc.pid or identity['session'] != proc.pid
            or (initial is not None and not same_birth(initial, identity))):
        raise Incomplete('owned direct child identity changed')
    return identity


def fifo_compare(expected, actual):
    """Pure byte comparison; actual packets are independently received UDP bytes."""
    return len(actual) == len(expected) and tuple(actual) == tuple(expected)


def signal_window_ok(snapshot_ns, signal_ns, arrival_ns, boundary_ns):
    return snapshot_ns < signal_ns <= arrival_ns < boundary_ns


def continuation_window_ok(snapshot_ns, signal_ns, continued_ns, arrival_ns, boundary_ns):
    return snapshot_ns < signal_ns <= continued_ns <= arrival_ns < boundary_ns


def retry_window_ok(snapshot_ns, arrival_ns, boundary_ns, end_ns):
    return snapshot_ns < boundary_ns <= arrival_ns < end_ns

CONTROL_CHILD = r'''import ctypes,os,signal,sys
parent=int(sys.argv[1])
if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:
    os._exit(125)

def hup(_sig,_frame):
    os.write(1,b'HUP\n');os._exit(0)
def alarm(_sig,_frame):
    os._exit(124)
signal.signal(signal.SIGHUP,hup)
signal.signal(signal.SIGALRM,alarm)
signal.alarm(5)
os.write(1,b'READY\n')
while True: signal.pause()
'''


def setup(variant, token):
    """Positive and negative controls, with no candidate/reference behavior."""
    if variant not in ('hup', 'periodic'):
        raise Incomplete('invalid setup variant')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise Incomplete('pidfd API unavailable')
    info = CANDIDATE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or not info.st_mode & stat.S_IXUSR):
        raise Incomplete('candidate is not a regular unprivileged executable')
    clock = time.get_clock_info('monotonic')
    if not clock.monotonic or clock.resolution > 0.001:
        raise Incomplete('monotonic timer is not sufficiently fine')
    folder = CASE / ('fifo169-control-' + variant)
    folder.mkdir(mode=0o700)
    queue = folder / 'queue'
    input_bytes = encoded_records(START)
    snapshot = queue_write(queue, input_bytes, 'control')
    if bytes.fromhex(snapshot['raw_hex']) != input_bytes:
        raise Incomplete('queue control bytes differ')
    left = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    right = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bridge = ClockBridge()
    udp, sends = [], []
    fence = None
    realtime_control = None
    try:
        realtime_info = time.get_clock_info('time')
        if realtime_info.resolution > 0.001:
            raise Incomplete('realtime clock resolution is too coarse')
        fence = RealtimeFence()
        expired = expired_timer_control()
        left.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS_NEW, 1)
        left.bind(('127.0.0.1', 0))
        right.bind(('127.0.0.1', 0))
        left.setblocking(False)
        for value in START:
            before = time.monotonic_ns()
            real_before = time.time_ns()
            if right.sendto(value, left.getsockname()) != len(value):
                raise Incomplete('control UDP send short')
            real_after = time.time_ns()
            sends.append({'before_ns':before,'after_ns':time.monotonic_ns(),
                          'realtime_before_ns':real_before,'realtime_after_ns':real_after})
        deadline = time.monotonic() + 3
        while len(udp) < len(START) and time.monotonic() < deadline:
            ready, _, _ = select.select([left], [], [], min(.05, max(0, deadline-time.monotonic())))
            if ready:
                data, peer, kernel_ns = kernel_receive(left)
                observed = time.monotonic_ns()
                bridge.sample()
                udp.append({'hex':data.hex(),'time_ns':observed,'kernel_realtime_ns':kernel_ns,'peer':list(peer)})
        if not fifo_compare(START, [bytes.fromhex(x['hex']) for x in udp]):
            raise Incomplete('control UDP bytes/order mismatch')
        bridge.sample()
        for packet, sent in zip(udp, sends):
            lower, upper = bridge.interval(packet['kernel_realtime_ns'])
            if upper < sent['before_ns'] or lower > packet['time_ns']:
                raise Incomplete('kernel timestamp does not match controlled send/receive')
            packet.update(kernel_monotonic_lower_ns=lower,kernel_monotonic_upper_ns=upper)
            if not (sent['realtime_before_ns'] <= packet['kernel_realtime_ns']
                    <= sent['realtime_after_ns']):
                raise Incomplete('control UDP kernel timestamp outside realtime send bracket')
        if fence is not None:
            fence.check('setup-final')
            realtime_control = {'fence':fence.report,'expired':expired,
                                'resolution':realtime_info.resolution}
    finally:
        left.close()
        right.close()
        if fence is not None:
            fence.close()
    negatives = {
        'reverse_rejected': not fifo_compare(START, START[::-1]),
        'missing_rejected': not fifo_compare(START, START[:-1]),
        'duplicate_rejected': not fifo_compare(START, (START[0], START[0], START[2])),
        'changed_rejected': not fifo_compare(START, (START[0], START[1], b'wrong')),
        'pre_signal_rejected': not signal_window_ok(10, 20, 19, 100),
        'late_signal_rejected': not signal_window_ok(10, 20, 100, 100),
        'continuation_window_accepted': continuation_window_ok(10, 20, 30, 31, 100),
        'pre_continuation_rejected': not continuation_window_ok(10, 20, 30, 29, 100),
        'continuation_boundary_rejected': not continuation_window_ok(10, 20, 30, 100, 100),
        'early_retry_rejected': not retry_window_ok(10, 19, 20, 100),
        'late_retry_rejected': not retry_window_ok(10, 100, 20, 100),
    }
    negatives.update(realtime_order_accepted=realtime_after_marker(100, 101, True),
                     realtime_earlier_rejected=not realtime_after_marker(100, 99, True),
                     realtime_equal_rejected=not realtime_after_marker(100, 100, True),
                     realtime_unquiet_rejected=not realtime_after_marker(100, 101, False),
                     expired_timer_rejected=expired['result'] == 'expired-readable' and expired['count'] > 0)
    test_send = {'started_ns':10, 'returned_ns':20, 'deadline_ns':80}
    test_sample = {'mono_before_ns':30, 'mono_after_ns':31, 'realtime_ns':100}
    test_packet = {'time_ns':50, 'kernel_realtime_ns':101}
    negatives.update(
        finish_after_send_accepted=finish_order_ok(test_send, test_sample, test_packet, 5, 60, True),
        finish_pre_send_sample_rejected=not finish_order_ok(test_send, {**test_sample,'mono_before_ns':19}, test_packet, 5, 60, True),
        finish_early_realtime_rejected=not finish_order_ok(test_send, test_sample, {**test_packet,'kernel_realtime_ns':99}, 5, 60, True),
        finish_equal_realtime_rejected=not finish_order_ok(test_send, test_sample, {**test_packet,'kernel_realtime_ns':100}, 5, 60, True),
        finish_unquiet_rejected=not finish_order_ok(test_send, test_sample, test_packet, 5, 60, False),
        finish_deadline_rejected=not finish_order_ok(test_send, test_sample, test_packet, 5, 80, True),
        finish_marker_deadline_rejected=not finish_order_ok(test_send, {**test_sample,'mono_before_ns':81,'mono_after_ns':81}, {**test_packet,'time_ns':90}, 5, 60, True),
        finish_observation_order_rejected=not finish_order_ok(test_send, test_sample, {**test_packet,'time_ns':30}, 5, 60, True))
    if not all(negatives.values()):
        raise Incomplete('predicate negative control failed')
    proc = subprocess.Popen(['/usr/bin/python3', '-I', '-c', CONTROL_CHILD, str(os.getpid())], cwd=str(CASE),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True, bufsize=0)
    pidfd = None
    control = {'pid': proc.pid}
    try:
        first = require_direct_child(proc)
        pidfd = os.pidfd_open(proc.pid, 0)
        again = require_direct_child(proc, first)
        signal.pidfd_send_signal(pidfd, 0)
        ready, _, _ = select.select([proc.stdout], [], [], 3)
        if not ready or os.read(proc.stdout.fileno(), 16) != b'READY\n':
            raise Incomplete('pidfd control child not ready')
        before = require_direct_child(proc, first)
        signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
        end = time.monotonic() + 2
        stopped = None
        while time.monotonic() < end:
            stopped = require_direct_child(proc, first)
            if stopped['state'] in ('T', 't'):
                break
            time.sleep(.01)
        if not stopped or stopped['state'] not in ('T', 't'):
            raise Incomplete('pidfd control child did not stop')
        signal_at = time.monotonic_ns()
        signal.pidfd_send_signal(pidfd, signal.SIGHUP)
        if select.select([proc.stdout], [], [], .05)[0]:
            raise Incomplete('stopped control child ran before continuation')
        continued = time.monotonic_ns()
        signal.pidfd_send_signal(pidfd, signal.SIGCONT)
        out, err = proc.communicate(timeout=3)
        if proc.returncode != 0 or out != b'HUP\n' or err:
            raise Incomplete('pidfd HUP control did not complete')
        try:
            signal.pidfd_send_signal(pidfd, 0)
        except ProcessLookupError:
            dead = 'ESRCH'
        else:
            raise Incomplete('reaped pidfd negative control failed')
        control.update(first=first, recheck=again, before_signal=before, stopped=stopped,
                       signal_ns=signal_at, continued_ns=continued, stdout_hex=out.hex(),
                       exit_status=proc.returncode, after_reap=dead)
    finally:
        if proc.poll() is None and pidfd is not None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise Incomplete('control child cleanup incomplete')
        if proc.poll() is None and pidfd is None:
            # The child's own alarm is bounded; never signal an unpinned PID.
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                raise Incomplete('control child cleanup without pidfd unconfirmed')
        if pidfd is not None:
            os.close(pidfd)
        for stream in (proc.stdout, proc.stderr):
            if stream and not stream.closed:
                stream.close()
    report = {'classification':'CONTROL_PASS','variant':variant,'token':token,
              'queue':snapshot,'udp':udp,'udp_sends':sends,'clock_samples':bridge.samples,
              'pidfd':control,'negative_controls':negatives,
              'clock_resolution':clock.resolution,'candidate_inode':info.st_ino,'candidate_dev':info.st_dev}
    report['realtime_control'] = realtime_control
    if not save_report('fifo169-setup.json', report):
        raise Incomplete('setup evidence cap reached')
    print('fifo169 setup=ok', flush=True)


SHELL = r'''set -u
IFS= read -r __marker < /etc/bashos-parity-vm || exit 125
IFS= read -r __attest < /run/bashos-parity-vm-identity || exit 125
[[ $UID == 2000 && $EUID == 2000 && $__marker == "$FIFO169_TOKEN" && $__attest == "$FIFO169_TOKEN" ]] || exit 125
printf 'fifo169-ready=%s\n' "$BASHPID"
bashsyslogd run -s "$FIFO169_SOCKET" -o "$FIFO169_OUTPUT" --syslog "$FIFO169_SYSLOG" --auth "$FIFO169_AUTH" --kern "$FIFO169_KERN" --queue "$FIFO169_QUEUE" --forward "$FIFO169_FORWARD" --once
__rc=$?
printf 'fifo169-status=%d\n' "$__rc"
exit "$__rc"
'''


def child_exec(parent_pid, parent_start, gate_fd, token, values):
    """Direct child only: retain parent-death kill and finite launch handshake."""
    if os.getppid() != parent_pid or proc_identity(parent_pid)['starttime'] != parent_start:
        raise Incomplete('launch parent changed before child gate')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        raise Incomplete('could not install parent-death signal')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    ready, _, _ = select.select([gate_fd], [], [], 8)
    if not ready or os.read(gate_fd, 3) != b'go\n':
        raise Incomplete('parent launch gate closed or timed out')
    os.close(gate_fd)
    if os.getppid() != parent_pid:
        raise Incomplete('parent died before candidate exec')
    env = {'PATH':'/usr/bin:/bin','HOME':str(HOME),'LC_ALL':'C','LANG':'C','FIFO169_TOKEN':token,
           'FIFO169_SOCKET':values['socket'],'FIFO169_QUEUE':values['queue'],'FIFO169_OUTPUT':values['output'],
           'FIFO169_SYSLOG':values['syslog'],'FIFO169_AUTH':values['auth'],'FIFO169_KERN':values['kern'],
           'FIFO169_FORWARD':values['forward']}
    os.execve(str(CANDIDATE), [str(CANDIDATE),'--noprofile','--norc','-c',SHELL,'fifo169'], env)


def align_start(deadline_ns):
    while time.monotonic_ns() < deadline_ns:
        now = time.monotonic_ns()
        if now % NS < 120_000_000:
            return now
        time.sleep(.01)
    raise Incomplete('could not establish an early monotonic-second window')


class Observer:
    def __init__(self, variant, token, report):
        self.variant, self.token, self.report = variant, token, report
        self.proc = self.pidfd = self.gate_write = None
        self.launch_attempted = False
        self.identity = None
        self.exec_verified = False
        self.sockets = None
        self.stdout, self.stderr, self.packets = bytearray(), bytearray(), []
        self.streams = {}
        self.folder = CASE / ('fifo169-' + variant)
        self.folder.mkdir(mode=0o700)
        self.queue = self.folder / 'queue'
        self.unix = self.folder / 'input.sock'
        self.clock = ClockBridge()
        self.report['clock_samples'] = self.clock.samples
        self.fence = None
        self.rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.fence = RealtimeFence()
            self.report['realtime_fence'] = self.fence.report
            self.rx.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS_NEW, 1)
            self.rx.bind(('127.0.0.1', 0))
            self.rx.setblocking(False)
            self.report['receiver'] = {'address':list(self.rx.getsockname()), 'created_ns':time.monotonic_ns()}
            self.report['queue_startup'] = queue_write(self.queue, encoded_records(START), 'startup')
        except BaseException:
            self.rx.close()
            if self.fence is not None:
                self.fence.close()
            raise

    def launch(self, anchor):
        parent = proc_identity(os.getpid())
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        self.gate_write = write_fd
        values = {'socket':str(self.unix),'queue':str(self.queue),'output':str(self.folder/'messages'),
                  'syslog':str(self.folder/'syslog'),'auth':str(self.folder/'auth'),'kern':str(self.folder/'kern'),
                  'forward':'127.0.0.1:' + str(self.rx.getsockname()[1])}
        argv = ['/usr/bin/python3','-I',str(SELF),'child',str(os.getpid()),str(parent['starttime']),
                str(read_fd),self.token,json.dumps(values,sort_keys=True,separators=(',',':'))]
        self.report['launch'] = {'argv':argv,'anchor_ns':anchor,'parent':parent}
        try:
            self.launch_attempted = True
            self.proc = subprocess.Popen(argv, cwd=str(CASE), stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         close_fds=True, pass_fds=(read_fd,), start_new_session=True, bufsize=0)
        finally:
            os.close(read_fd)
        for stream, label in ((self.proc.stdout,'stdout'),(self.proc.stderr,'stderr')):
            os.set_blocking(stream.fileno(), False)
            self.streams[stream.fileno()] = (stream,label)
        self.identity = require_direct_child(self.proc)
        self.pidfd = os.pidfd_open(self.proc.pid, 0)
        self.report['launch']['child_before_release'] = require_direct_child(self.proc, self.identity)
        signal.pidfd_send_signal(self.pidfd, 0)
        if os.write(self.gate_write, b'go\n') != 3:
            raise Incomplete('short child gate release')
        os.close(self.gate_write)
        self.gate_write = None
        self.report['launch']['gate_released_ns'] = time.monotonic_ns()

    def pump(self, interval=.05):
        self.clock.sample()
        fds = [self.rx.fileno()] + list(self.streams)
        ready, _, _ = select.select(fds, [], [], max(0, min(interval, .05)))
        for fd in ready:
            if fd == self.rx.fileno():
                data, peer, kernel_ns = kernel_receive(self.rx)
                observed = time.monotonic_ns()
                self.clock.sample()
                if len(self.packets) >= MAX_PACKETS:
                    raise Incomplete('UDP packet capture cap reached')
                self.packets.append({'hex':data.hex(),'time_ns':observed,
                                     'kernel_realtime_ns':kernel_ns,'peer':list(peer)})
            else:
                stream, label = self.streams[fd]
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not data:
                    del self.streams[fd]
                    stream.close()
                    continue
                target = self.stdout if label == 'stdout' else self.stderr
                if len(target) + len(data) >= MAX_STREAM:
                    raise Incomplete(label + ' capture cap reached')
                target.extend(data)

    def process_alive(self):
        if self.proc.poll() is not None:
            if not self.exec_verified:
                raise Incomplete('launch child exited before candidate executable attribution')
            if self.proc.returncode < 0:
                raise Incomplete('candidate termination by signal is not attributed to product behavior')
            raise CandidateMismatch('candidate exited before its observation completed: ' + str(self.proc.returncode),
                                    'exit', returncode=self.proc.returncode)

    def wait_packets(self, start, expected, deadline_ns, label):
        while True:
            self.pump(0)
            captured = self.packets[start:]
            prefix = [bytes.fromhex(v['hex']) for v in captured]
            if prefix != list(expected[:len(prefix)]):
                raise CandidateMismatch(label + ' UDP order or bytes differ', 'packet',
                                        phase=label, first_index=start, past_index=len(self.packets),
                                        expected_hex=[x.hex() for x in expected])
            if len(captured) >= len(expected):
                return captured
            self.process_alive()
            if time.monotonic_ns() >= deadline_ns:
                raise Incomplete(label + ' did not complete inside the attributable time window')
            self.pump(min(.05, max(0, (deadline_ns-time.monotonic_ns())/NS)))

    def wait_empty(self, deadline_ns, label):
        while time.monotonic_ns() < deadline_ns:
            try:
                snapshot = read_queue(self.queue)
            except Incomplete:
                self.pump(.01)
                continue
            if queue_empty(snapshot):
                self.report['queue_after_' + label] = snapshot
                return snapshot
            self.process_alive()
            self.pump(.01)
        raise Incomplete(label + ' queue did not become observably empty')

    def require_no_extra(self, expected_count, label, early_boundary_ns=None):
        self.pump(0)
        if len(self.packets) != expected_count:
            if len(self.packets) < expected_count:
                raise Incomplete(label + ' lacks the preceding captured datagrams')
            if early_boundary_ns is not None:
                raise Incomplete(label + ' replay occurred before its trigger was attributable')
            raise CandidateMismatch(label + ' produced an unexpected UDP datagram', 'packet',
                                    phase=label, first_index=expected_count, past_index=len(self.packets),
                                    expected_hex=[])

    def socket_identity(self):
        try:
            st = self.unix.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != 2000:
            raise Incomplete('daemon input is not the owned guest socket')
        return {'dev':st.st_dev,'ino':st.st_ino,'mode':stat.S_IMODE(st.st_mode),
                'uid':st.st_uid,'time_ns':time.monotonic_ns()}

    def wait_ready(self, deadline_ns):
        while time.monotonic_ns() < deadline_ns:
            self.pump(.01)
            found = self.socket_identity()
            if found is not None:
                self.sockets = found
                self.report['socket_ready'] = found
                return
            self.process_alive()
        raise Incomplete('candidate socket readiness did not complete in the timing window')

    def verify_exec(self):
        current = require_direct_child(self.proc, self.identity)
        target = CANDIDATE.stat()
        setup_candidate = self.report['setup_candidate']
        if (target.st_dev, target.st_ino) != (setup_candidate['device'], setup_candidate['inode']):
            raise Incomplete('candidate inode changed after setup')
        try:
            executable = (Path('/proc') / str(self.proc.pid) / 'exe').stat()
        except OSError as exc:
            raise Incomplete('candidate executable identity unavailable: ' + type(exc).__name__)
        if (target.st_dev, target.st_ino) != (executable.st_dev, executable.st_ino):
            raise Incomplete('owned process has not execed the expected candidate')
        self.exec_verified = True
        self.report['candidate_exec'] = {'identity':current,'device':executable.st_dev,'inode':executable.st_ino}

    def hold_for_hup(self, boundary_ns, checkpoint='held_before_queue'):
        self.verify_exec()
        before = require_direct_child(self.proc, self.identity)
        sent = time.monotonic_ns()
        if sent >= boundary_ns - 150_000_000:
            raise Incomplete('insufficient time to hold owned child before HUP')
        signal.pidfd_send_signal(self.pidfd, signal.SIGSTOP)
        stopped = None
        while time.monotonic_ns() < boundary_ns - 120_000_000:
            self.pump(.01)
            stopped = require_direct_child(self.proc, self.identity)
            if stopped['state'] in ('T','t'):
                self.report[checkpoint] = {'pidfd_signal':int(signal.SIGSTOP),
                    'signal_ns':sent,'before':before,'stopped':stopped,'time_ns':time.monotonic_ns()}
                return
        raise Incomplete('owned child did not become observably stopped before the boundary')

    def continue_without_hup(self, snapshot, boundary_ns):
        """Control for a resume alone waking the candidate before the periodic tick."""
        held = require_direct_child(self.proc, self.identity)
        if held['state'] not in ('T','t'):
            raise Incomplete('owned child was not held for the no-HUP control')
        started = time.monotonic_ns()
        if started >= boundary_ns - 250_000_000:
            raise Incomplete('insufficient time for the no-HUP continuation control')
        signal.pidfd_send_signal(self.pidfd, signal.SIGCONT)
        resumed = time.monotonic_ns()
        end = resumed + 60_000_000
        continued_identity = None
        while time.monotonic_ns() < end:
            self.pump(.01)
            if len(self.packets) != 4:
                # A delayed observer must not confuse a periodic tick with an
                # early replay caused by resume; use the kernel receive time.
                if len(self.packets) > 4 and all(
                    self.clock.interval(x['kernel_realtime_ns'])[1] < boundary_ns
                    for x in self.packets[4:]
                ):
                    raise Incomplete('queue replayed after continuation without HUP; HUP attribution unavailable')
                raise Incomplete('no-HUP continuation observation overlaps the retry boundary')
            if time.monotonic_ns() >= boundary_ns - 180_000_000:
                raise Incomplete('no-HUP continuation control ran out of retry-window time')
            current = require_direct_child(self.proc, self.identity)
            if current['state'] not in ('T','t'):
                continued_identity = current
        if continued_identity is None:
            raise Incomplete('no-HUP control never observed the child leave its stopped state')
        self.hold_for_hup(boundary_ns, 'held_after_continue_control')
        current = read_queue(self.queue)
        if (current.get('state') != 'file' or current.get('raw_hex') != snapshot['raw_hex']
                or (current.get('dev'),current.get('ino')) != (snapshot['dev'],snapshot['ino'])):
            raise Incomplete('queue changed during no-HUP continuation control')
        self.require_no_extra(4, 'after the no-HUP continuation control', boundary_ns)
        self.report['continue_without_hup'] = {'signal':int(signal.SIGCONT),
            'started_ns':started,'resumed_ns':resumed,'observation_end_ns':time.monotonic_ns(),
            'continued_identity':continued_identity,'queue_recheck':current,'datagrams_during_control':0}

    def hup(self, snapshot, boundary_ns):
        before = require_direct_child(self.proc, self.identity)
        if before['state'] not in ('T','t'):
            raise Incomplete('owned child is no longer held at the HUP checkpoint')
        current_queue = read_queue(self.queue)
        if (current_queue.get('state') != 'file' or current_queue.get('raw_hex') != snapshot['raw_hex']
                or (current_queue.get('dev'),current_queue.get('ino')) != (snapshot['dev'],snapshot['ino'])):
            raise Incomplete('queued records changed while the owned child was held')
        self.require_no_extra(4, 'immediately before HUP', boundary_ns)
        signal.pidfd_send_signal(self.pidfd, 0)
        sent = time.monotonic_ns()
        if not snapshot['time_ns'] < sent < boundary_ns:
            raise Incomplete('HUP could not be attributed within the current second')
        signal.pidfd_send_signal(self.pidfd, signal.SIGHUP)
        returned = time.monotonic_ns()
        if returned >= boundary_ns - 30_000_000:
            raise Incomplete('insufficient time after HUP and before the periodic boundary')
        # Keep the daemon stopped long enough to distinguish kernel receive
        # timestamps after HUP from the conservative clock-bridge uncertainty.
        while time.monotonic_ns() < returned + 10_000_000:
            self.pump(.005)
            if len(self.packets) != 4:
                raise Incomplete('unexpected packet while the HUP target was held')
            if time.monotonic_ns() >= boundary_ns:
                raise Incomplete('HUP hold crossed the periodic boundary')
        before_cont = require_direct_child(self.proc, self.identity)
        if before_cont['state'] not in ('T','t'):
            raise Incomplete('HUP target did not remain stopped before continuation')
        self.fence.check('before-continuation')
        continue_started = time.monotonic_ns()
        marker_realtime = time.time_ns()
        marker_after = time.monotonic_ns()
        signal.pidfd_send_signal(self.pidfd, signal.SIGCONT)
        continued = time.monotonic_ns()
        if continued >= boundary_ns:
            raise Incomplete('continuation crossed the periodic boundary')
        self.report['hup_signal'] = {'pid':self.proc.pid,'signal':int(signal.SIGHUP),
             'identity_while_stopped':before,'identity_before_continuation':before_cont,
             'queue_recheck':current_queue,
             'signal_started_ns':sent,'signal_returned_ns':returned,
             'continue_started_ns':continue_started,'continue_marker_realtime_ns':marker_realtime,
             'continue_marker_after_ns':marker_after,'continued_ns':continued,
             'delivery':'pidfd_send_signal; queued while stopped, then continued by pidfd'}
        return returned

    def finish(self):
        now = self.socket_identity()
        if not now or not self.sockets or (now['dev'],now['ino']) != (self.sockets['dev'],self.sockets['ino']):
            raise Incomplete('owned daemon socket identity changed before finish')
        before = len(self.packets)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            started = time.monotonic_ns()
            if sender.sendto(FINISH, str(self.unix)) != len(FINISH):
                raise Incomplete('short finish datagram')
            returned = time.monotonic_ns()
        finish_deadline = time.monotonic_ns()+4*NS
        self.report['finish_send'] = {'started_ns':started,'returned_ns':returned,'deadline_ns':finish_deadline}
        # Record a bracketed realtime marker only after the send has returned.
        # Packets earlier than/equal to it remain INCOMPLETE, not product FAIL.
        self.clock.sample()
        self.report['finish_send']['post_send_sample_index'] = len(self.clock.samples) - 1
        received = self.wait_packets(before, (FINISH,), finish_deadline, 'finish')
        self.report['finish_packet'] = received[0]
        deadline = time.monotonic_ns() + 4*NS
        while self.proc.poll() is None and time.monotonic_ns() < deadline:
            self.pump(.05)
        if self.proc.poll() is None:
            raise Incomplete('candidate did not exit after finish')
        while self.streams and time.monotonic_ns() < deadline:
            self.pump(.05)
        if self.streams:
            raise Incomplete('candidate output pipes did not close')
        expected = (f'fifo169-ready={self.proc.pid}\nfifo169-status=0\n').encode()
        if self.proc.returncode != 0 or bytes(self.stdout) != expected or self.stderr:
            if self.proc.returncode < 0:
                raise Incomplete('candidate termination by signal is not attributed to product behavior')
            raise CandidateMismatch('candidate daemon exit/status/output differs', 'output',
                                    returncode=self.proc.returncode)

    def close(self):
        no_handle = self.launch_attempted and self.proc is None
        cleanup = {'actions':[],'exited':self.proc is None and not no_handle,
                   'launch_without_handle':no_handle,'errors':[]}
        if no_handle:
            cleanup['errors'].append('launch was attempted but child handle was not established')
        try:
            if self.gate_write is not None:
                os.close(self.gate_write)
                self.gate_write = None
            if self.proc is not None and self.proc.poll() is None and self.pidfd is not None:
                for sig in (signal.SIGCONT, signal.SIGTERM, signal.SIGKILL):
                    if self.proc.poll() is not None:
                        break
                    try:
                        signal.pidfd_send_signal(self.pidfd, sig)
                        cleanup['actions'].append({'signal':int(sig),'time_ns':time.monotonic_ns()})
                    except ProcessLookupError:
                        break
                    if sig == signal.SIGCONT:
                        continue
                    until = time.monotonic_ns() + 2*NS
                    while self.proc.poll() is None and time.monotonic_ns() < until:
                        try:
                            self.pump(.05)
                        except (Incomplete, OSError) as exc:
                            cleanup['errors'].append(type(exc).__name__ + ': ' + str(exc))
                            time.sleep(.01)
            if self.proc is not None and self.proc.poll() is None and self.pidfd is None:
                # Closing the gate forces the child to exit; never guess or signal its PID.
                try:
                    self.proc.wait(timeout=9)
                except subprocess.TimeoutExpired:
                    pass
            if self.proc is not None:
                cleanup['exited'] = self.proc.poll() is not None
                cleanup['returncode'] = self.proc.returncode
                drain_until = time.monotonic_ns() + NS
                while self.streams and time.monotonic_ns() < drain_until:
                    try:
                        self.pump(.05)
                    except (Incomplete, OSError) as exc:
                        cleanup['errors'].append(type(exc).__name__ + ': ' + str(exc))
                        break
                if self.streams:
                    cleanup['errors'].append('output streams not fully drained')
        finally:
            if self.fence is not None:
                try:
                    self.fence.check('cleanup')
                except (Incomplete, OSError) as exc:
                    cleanup['errors'].append('realtime fence: ' + str(exc))
                finally:
                    self.fence.close()
            self.report['cleanup'] = cleanup
            self.report['stdout_hex'] = bytes(self.stdout).hex()
            self.report['stderr_hex'] = bytes(self.stderr).hex()
            self.report['udp_packets'] = self.packets
            for stream, _ in list(self.streams.values()):
                stream.close()
            self.streams.clear()
            if self.pidfd is not None:
                os.close(self.pidfd)
            self.rx.close()
        if not cleanup['exited'] or cleanup['errors']:
            raise Incomplete('owned process cleanup or capture not confirmed')



def read_setup(variant, token):
    path = HOME / 'fifo169-setup.json'
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 2000 or st.st_nlink != 1 or st.st_size >= MAX_REPORT:
            raise Incomplete('setup record is unsafe or too large')
        raw = os.read(fd, MAX_REPORT)
        if len(raw) != st.st_size:
            raise Incomplete('setup record changed while reading')
    finally:
        os.close(fd)
    result = json.loads(raw)
    negatives = result.get('negative_controls', {})
    required = {'reverse_rejected','missing_rejected','duplicate_rejected','changed_rejected',
                'pre_signal_rejected','late_signal_rejected','continuation_window_accepted',
                'pre_continuation_rejected','continuation_boundary_rejected',
                'early_retry_rejected','late_retry_rejected'}
    required |= {'realtime_order_accepted','realtime_earlier_rejected',
                 'realtime_equal_rejected','realtime_unquiet_rejected','expired_timer_rejected',
                 'finish_after_send_accepted','finish_pre_send_sample_rejected',
                 'finish_early_realtime_rejected','finish_equal_realtime_rejected',
                 'finish_unquiet_rejected','finish_deadline_rejected','finish_marker_deadline_rejected',
                 'finish_observation_order_rejected'}
    control = result.get('realtime_control', {})
    if (control.get('expired', {}).get('result') != 'expired-readable'
            or type(control.get('expired', {}).get('count')) is not int
            or control['expired']['count'] < 1
            or [x.get('label') for x in control.get('fence', {}).get('checks', [])] != ['armed','setup-final']
            or any(x.get('result') != 'EAGAIN' for x in control['fence']['checks'])):
        raise Incomplete('realtime ordering setup controls missing')
    candidate = CANDIDATE.lstat()
    if (result.get('classification') != 'CONTROL_PASS' or result.get('variant') != variant
            or result.get('token') != token or set(negatives) != required
            or any(negatives[name] is not True for name in required)
            or result.get('pidfd', {}).get('after_reap') != 'ESRCH'
            or result.get('queue', {}).get('raw_hex') != encoded_records(START).hex()
            or not fifo_compare(START, [bytes.fromhex(v['hex']) for v in result.get('udp', [])])
            or len(result.get('udp_sends', [])) != 3 or not result.get('clock_samples')
            or any(type(v.get('kernel_realtime_ns')) is not int for v in result.get('udp', []))
            or (result.get('candidate_dev'),result.get('candidate_inode')) != (candidate.st_dev,candidate.st_ino)):
        raise Incomplete('required setup controls are absent or invalid')
    return result


def packet_intervals(observer):
    """Recompute every recorded receive interval after the last clock sample."""
    observer.clock.sample()
    intervals = []
    for packet in observer.packets:
        lower, upper = observer.clock.interval(packet['kernel_realtime_ns'])
        if lower > packet['time_ns']:
            raise Incomplete('kernel timestamp is later than the receiver observation')
        packet['kernel_monotonic_lower_ns'] = lower
        packet['kernel_monotonic_upper_ns'] = upper
        intervals.append((lower, upper))
    return intervals


def finalize_kernel_timing(observer, report, variant, first_boundary, second_boundary):
    """Recompute conservative packet intervals with every recorded clock sample."""
    intervals = packet_intervals(observer)
    if len(intervals) < 8:
        raise Incomplete('missing kernel packet timestamps')
    startup = report['queue_startup']['time_ns']
    if any(low < startup or high >= first_boundary for low,high in intervals[:3]):
        raise Incomplete('startup time overlaps the first retry boundary')
    if not (first_boundary <= intervals[3][0] <= intervals[3][1] < first_boundary + 700_000_000):
        raise Incomplete('warm retry kernel time is ambiguous')
    if variant == 'hup':
        sent = report['hup_signal']['signal_returned_ns']
        hup = report['hup_signal']
        continued_start, marker, marker_after = hup['continue_started_ns'], hup['continue_marker_realtime_ns'], hup['continue_marker_after_ns']
        if not sent <= continued_start <= marker_after <= hup['continued_ns']:
            raise Incomplete('HUP continuation timing is inconsistent')
        if any(not signal_window_ok(report['queue_before_trigger']['time_ns'], sent, low, second_boundary)
               or not signal_window_ok(report['queue_before_trigger']['time_ns'], sent, high, second_boundary)
               or not realtime_after_marker(marker, pkt['kernel_realtime_ns'], True)
               for (low,high),pkt in zip(intervals[4:7],observer.packets[4:7])):
            raise Incomplete('HUP kernel time overlaps signal, realtime marker or periodic boundary')
    else:
        if any(low < second_boundary or high >= second_boundary+700_000_000 for low,high in intervals[4:7]):
            raise Incomplete('periodic kernel time overlaps a retry boundary')
        warm_low, warm_high = intervals[3]
        deltas = [(low-warm_high, high-warm_low) for low, high in intervals[4:7]]
        if any(low < 750_000_000 or high > 1_250_000_000 for low, high in deltas):
            raise Incomplete('observed periodic interval is not attributable to a one-second retry')
        report['periodic_elapsed_ns'] = [{'lower_ns':low,'upper_ns':high} for low,high in deltas]
    finish = report['finish_send']
    index = finish.get('post_send_sample_index')
    if (type(index) is not int or not 0 <= index < len(observer.clock.samples)
            or observer.fence is None or not finish_order_ok(finish, observer.clock.samples[index],
                    observer.packets[7], *intervals[7], True)):
        raise Incomplete('finish packet lacks a strict post-send realtime marker or misses its deadline')
    report['clock_assumptions'] = {'max_observed_offset_span_ns':CLOCK_DRIFT_NS,
        'interval_padding_ns':CLOCK_PAD_NS,
        'limit':'HUP and finish ordering use the same realtime clock with an armed cancellation fence; sender exclusivity and clock integrity require independent review.'}


def validate_mismatch(observer, report, variant):
    """Attribute a provisional mismatch before allowing the diagnostic FAIL.

    A private receiver and an interval do not by themselves prove which process
    sent UDP. The primary must independently establish sender exclusivity for
    packet-based PASS or FAIL when reviewing the complete VM evidence.
    """
    witness = report['mismatch_witness']
    if not observer.exec_verified or 'candidate_exec' not in report:
        raise Incomplete('candidate executable was not attributed')
    intervals = packet_intervals(observer)
    kind = witness['kind']
    if kind == 'exit':
        if type(witness['returncode']) is not int or witness['returncode'] < 0:
            raise Incomplete('candidate exit was not attributable')
        report['mismatch_attribution'] = {'kind':kind, 'candidate_exec_verified':True}
        return
    if kind == 'output':
        if type(witness['returncode']) is not int or witness['returncode'] < 0:
            raise Incomplete('candidate exit was not attributable')
        timing = report['timing']
        finalize_kernel_timing(observer, report, variant, timing['first_boundary_ns'], timing['second_boundary_ns'])
        report['mismatch_attribution'] = {'kind':kind, 'complete_packet_timing':True,
            'sender_exclusivity':'requires independent VM evidence'}
        return
    if kind != 'packet':
        raise Incomplete('unknown provisional mismatch kind')
    stages = {'startup':'startup', 'warm retry':'warm', 'after warm retry':'warm',
              'SIGHUP replay':'trigger', 'periodic replay':'trigger', 'after trigger':'trigger',
              'quiet post-trigger observation':'trigger', 'finish':'finish', 'after finish':'finish'}
    phase = witness['phase']
    if phase not in stages:
        raise Incomplete('extra packet has no uniquely attributable stage')
    stage = stages[phase]
    first, past = witness['first_index'], witness['past_index']
    if not (type(first) is int and type(past) is int and 0 <= first < past <= len(intervals)):
        raise Incomplete('invalid mismatch packet range')
    floor = {'startup':0, 'warm':3, 'trigger':4, 'finish':7}[stage]
    if first < floor:
        raise Incomplete('mismatch packet range precedes its claimed stage')
    data = [x['hex'] for x in observer.packets]
    first_boundary = report['timing']['first_boundary_ns']
    startup = report['queue_startup']['time_ns']
    startup_end = min(3, past) if stage == 'startup' else 3
    if len(intervals) < startup_end or any(low < startup or high >= first_boundary
                                           for low,high in intervals[:startup_end]):
        raise Incomplete('startup packet time is not attributable')
    if stage == 'startup':
        if data[:min(first, 3)] != [x.hex() for x in START[:min(first, 3)]]:
            raise Incomplete('earlier startup prefix was not established')
        if any(low < startup or high >= first_boundary for low,high in intervals[:past]):
            raise Incomplete('startup mismatch time is not attributable')
    else:
        if data[:3] != [x.hex() for x in START] or len(intervals) < 3:
            raise Incomplete('earlier startup evidence was not established')
        warm = report['queue_before_warm']
        if warm['time_ns'] >= first_boundary:
            raise Incomplete('warm snapshot crossed its boundary')
        warm_end = past if stage == 'warm' else 4
        if len(intervals) < warm_end or any(low < first_boundary or high >= first_boundary+700_000_000
                                           for low,high in intervals[3:warm_end]):
            raise Incomplete('warm mismatch time is not attributable')
        if stage == 'warm' and first > 3 and data[3] != WARM.hex():
            raise Incomplete('earlier warm packet was not established')
        if stage in ('trigger','finish'):
            if data[3] != WARM.hex():
                raise Incomplete('earlier warm evidence was not established')
            second = report['timing']['second_boundary_ns']
            queued = report['queue_before_trigger']
            expected = HUP if variant == 'hup' else PERIODIC
            if queued['raw_hex'] != encoded_records(expected).hex() or queued['time_ns'] >= second:
                raise Incomplete('trigger queue evidence is invalid')
            trigger_end = past if stage == 'trigger' else 7
            if len(intervals) < trigger_end:
                raise Incomplete('trigger packet capture is incomplete')
            if stage == 'trigger' and data[4:min(first, 7)] != [x.hex() for x in expected[:max(0, min(first, 7)-4)]]:
                raise Incomplete('earlier trigger prefix was not established')
            if variant == 'hup':
                sent = report['hup_signal']['signal_returned_ns']
                continued_start = report['hup_signal']['continue_started_ns']
                if ('continue_without_hup' not in report or not queued['time_ns'] < sent <= continued_start
                        or continued_start > report['hup_signal']['continued_ns']):
                    raise Incomplete('HUP control or continuation timing is invalid')
                hup = report['hup_signal']
                marker = hup['continue_marker_realtime_ns']
                if not continued_start <= hup['continue_marker_after_ns'] <= hup['continued_ns']:
                    raise Incomplete('HUP mismatch marker timing is inconsistent')
                if any(not signal_window_ok(queued['time_ns'], sent, low, second)
                       or not signal_window_ok(queued['time_ns'], sent, high, second)
                       or not realtime_after_marker(marker, pkt['kernel_realtime_ns'], True)
                       for (low,high),pkt in zip(intervals[4:trigger_end],observer.packets[4:trigger_end])):
                    raise Incomplete('HUP mismatch time is not attributable')
            else:
                warm_low, warm_high = intervals[3]
                if any(low < second or high >= second+700_000_000
                       or low-warm_high < 750_000_000 or high-warm_low > 1_250_000_000
                       for low,high in intervals[4:trigger_end]):
                    raise Incomplete('periodic mismatch time is not attributable')
            if stage == 'finish':
                if data[4:7] != [x.hex() for x in expected]:
                    raise Incomplete('earlier trigger evidence was not established')
                sent = report['finish_send']
                if first > 7 and data[7] != FINISH.hex():
                    raise Incomplete('earlier finish packet was not established')
                index = sent.get('post_send_sample_index')
                if (type(index) is not int or not 0 <= index < len(observer.clock.samples)
                        or observer.fence is None
                        or any(not finish_order_ok(sent, observer.clock.samples[index], pkt, low, high, True)
                               for (low,high),pkt in zip(intervals[7:past], observer.packets[7:past]))):
                    raise Incomplete('finish mismatch time is not attributable')
    report['mismatch_attribution'] = {'kind':kind, 'phase':phase, 'first_index':first, 'past_index':past,
        'clock_intervals_recomputed_after_cleanup':True,
        'sender_exclusivity':'requires independent VM evidence'}


def scenario(variant, token):
    if variant not in ('hup', 'periodic'):
        raise Incomplete('invalid candidate variant')
    report = {'schema':'bashos-syslog-fifo169-v1','variant':variant,'token':token,
              'classification':'INCOMPLETE','errors':[], 'started_ns':time.monotonic_ns(),
              'setup_controls':'fifo169-setup.json', 'input_records':{
                  'startup_hex':[v.hex() for v in START],
                  'warm_hex':WARM.hex(),
                  'trigger_hex':[v.hex() for v in (HUP if variant == 'hup' else PERIODIC)]}}
    observer = None
    def expired(_signum, _frame):
        raise Incomplete('overall candidate observation deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, OVERALL_SECONDS - 5)
    try:
        setup = read_setup(variant, token)
        report['setup_candidate'] = {'device':setup['candidate_dev'], 'inode':setup['candidate_inode']}
        observer = Observer(variant, token, report)
        anchor = align_start(time.monotonic_ns() + 2*NS)
        first_boundary = (anchor//NS + 1)*NS
        report['timing'] = {'anchor_ns':anchor,'first_boundary_ns':first_boundary}
        observer.launch(anchor)
        observer.wait_ready(first_boundary)
        observer.verify_exec()
        initial = observer.wait_packets(0, START, first_boundary, 'startup')
        if any(observer.clock.interval(x['kernel_realtime_ns'])[1] >= first_boundary for x in initial):
            raise Incomplete('kernel startup timestamp overlaps the monotonic-second boundary')
        observer.wait_empty(first_boundary, 'startup')
        observer.require_no_extra(3, 'startup')
        report['startup_packets'] = initial
        if time.monotonic_ns() >= first_boundary - 200_000_000:
            raise Incomplete('insufficient time to seed the periodic calibration')
        warm_bytes = WARM.hex().encode('ascii') + b'\n'
        warm_snapshot = queue_write(observer.queue, warm_bytes, 'warm')
        report['queue_before_warm'] = warm_snapshot
        if warm_snapshot['time_ns'] >= first_boundary:
            raise Incomplete('warm queue snapshot crossed the first boundary')
        observer.require_no_extra(3, 'before warm retry', first_boundary)
        warm = observer.wait_packets(3, (WARM,), first_boundary + 700_000_000, 'warm retry')
        warm_low, warm_high = observer.clock.interval(warm[0]['kernel_realtime_ns'])
        if warm_high < first_boundary:
            raise Incomplete('warm queued record replayed before the attributable retry boundary')
        if warm_low < first_boundary or warm_high >= first_boundary + 700_000_000:
            raise Incomplete('kernel warm-retry time overlaps an attribution boundary')
        report['warm_packet'] = warm[0]
        observer.wait_empty(first_boundary + 700_000_000, 'warm')
        observer.require_no_extra(4, 'after warm retry')
        second_boundary = first_boundary + NS
        report['timing']['second_boundary_ns'] = second_boundary
        if time.monotonic_ns() >= second_boundary - 200_000_000:
            raise Incomplete('insufficient time to seed the three-record trigger')
        expected = HUP if variant == 'hup' else PERIODIC
        if variant == 'hup':
            observer.hold_for_hup(second_boundary)
            observer.require_no_extra(4, 'while held before queue')
        queue_before = queue_write(observer.queue, encoded_records(expected), variant)
        report['queue_before_trigger'] = queue_before
        if not first_boundary <= queue_before['time_ns'] < second_boundary - 100_000_000:
            raise Incomplete('trigger queue snapshot is outside its attributable window')
        observer.require_no_extra(4, 'before trigger', second_boundary)
        if variant == 'hup':
            observer.continue_without_hup(queue_before, second_boundary)
            signal_returned = observer.hup(queue_before, second_boundary)
            burst = observer.wait_packets(4, expected, second_boundary, 'SIGHUP replay')
            observer.fence.check('after-hup-packets')
            marker = report['hup_signal']['continue_marker_realtime_ns']
            if not all(all(signal_window_ok(queue_before['time_ns'], signal_returned, bound, second_boundary)
                           for bound in observer.clock.interval(x['kernel_realtime_ns']))
                       and realtime_after_marker(marker, x['kernel_realtime_ns'], True) for x in burst):
                raise Incomplete('kernel HUP replay time overlaps signal, realtime marker or periodic boundary')
            observer.wait_empty(second_boundary, 'trigger')
        else:
            burst = observer.wait_packets(4, expected, second_boundary + 700_000_000, 'periodic replay')
            intervals = [observer.clock.interval(x['kernel_realtime_ns']) for x in burst]
            if any(high < second_boundary for _low, high in intervals):
                raise Incomplete('queued records arrived before the attributable retry boundary')
            if not all(retry_window_ok(queue_before['time_ns'], low, second_boundary, second_boundary+700_000_000)
                       and retry_window_ok(queue_before['time_ns'], high, second_boundary, second_boundary+700_000_000)
                       for low, high in intervals):
                raise Incomplete('kernel periodic replay time overlaps an attribution boundary')
            observer.wait_empty(second_boundary + 700_000_000, 'trigger')
        report['trigger_packets'] = burst
        observer.require_no_extra(7, 'after trigger')
        until = time.monotonic_ns() + 150_000_000
        while time.monotonic_ns() < until:
            observer.pump(.03)
        observer.require_no_extra(7, 'quiet post-trigger observation')
        observer.finish()
        observer.require_no_extra(8, 'after finish')
        finalize_kernel_timing(observer, report, variant, first_boundary, second_boundary)
        report['classification'] = 'PASS'
    except CandidateMismatch as exc:
        report['classification'] = 'PENDING_FAIL'
        report['mismatch_witness'] = exc.witness
        report['errors'].append(str(exc))
    except (Incomplete, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        report['classification'] = 'INCOMPLETE'
        report['errors'].append(type(exc).__name__ + ': ' + str(exc))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if observer is not None:
            try:
                observer.close()
                if report['classification'] == 'PASS':
                    finalize_kernel_timing(observer, report, variant, first_boundary, second_boundary)
                elif report['classification'] == 'PENDING_FAIL':
                    validate_mismatch(observer, report, variant)
                    report['classification'] = 'FAIL'
            except (Incomplete, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
                report['classification'] = 'INCOMPLETE'
                report['errors'].append('cleanup, mismatch attribution or final timing: ' + type(exc).__name__ + ': ' + str(exc))
        report['finished_ns'] = time.monotonic_ns()
        if report['finished_ns'] - report['started_ns'] > OVERALL_SECONDS*NS:
            report['classification'] = 'INCOMPLETE'
            report['errors'].append('overall observation budget exceeded')
        save_report('fifo169-result.json', report)
    print('fifo169 ' + variant + '=' + report['classification'].lower(), flush=True)


def main():
    token = guard()
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == 'setup':
        setup(args[1], token)
    elif len(args) == 3 and args[0] == 'case':
        if args[2] != str(CANDIDATE):
            raise Incomplete('case was not invoked by the exact candidate path')
        scenario(args[1], token)
    elif len(args) == 6 and args[0] == 'child':
        if args[4] != token:
            raise Incomplete('child token differs from protected guest token')
        child_exec(int(args[1]), int(args[2]), int(args[3]), token, json.loads(args[5]))
    else:
        raise Incomplete('invalid fixture invocation')


if __name__ == '__main__':
    try:
        main()
    except (Incomplete, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        # A setup failure exits nonzero, so the guest classifies the case ERROR.
        print('fifo169 infrastructure: ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr, flush=True)
        raise SystemExit(125)
