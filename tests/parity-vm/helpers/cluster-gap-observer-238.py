#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only, nonroot cluster gap fixture. Never run or import on a host."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import select
import shlex
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
REFERENCE_BASH = Path('/opt/bash-5.3.15/bin/bash')

class Incomplete(Exception):
    """Control, capture, setup or teardown did not establish valid evidence."""

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
    report = {'schema':'bashos-scratch-guard226-v1', 'state':'refused',
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
        encoded = json.dumps({'schema':'bashos-scratch-guard226-v1','state':'refused',
                              'error':report['error'],'report_capped':True}, sort_keys=True, separators=(',', ':'))
    print('SCRATCH226-GUARD-V1 ' + encoded, file=sys.stderr, flush=True)


def guard():
    """208 protected proof and 223 active mount; never inspect scratch before the gate."""
    admitted = False
    observation = None
    try:
        if not __debug__ or platform.machine() != 'x86_64':
            raise Incomplete('expected unoptimized x86-64 guest execution')
        if os.getresuid() != (2000, 2000, 2000) or os.getresgid() != (2000, 2000, 2000) or os.getgroups() != []:
            raise Incomplete('expected uid/gid 2000 without supplementary groups')
        token = protected_identity(MARKER)
        if protected_identity(ATTEST) != token:
            raise Incomplete('root-created identity differs from marker')
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
        admitted = True
        observation = scratch_observe()
        validate_scratch(observation)
        return {'token':token, 'namespace_attestation':proof,
                'scratch_mount_id':scratch_mount_id(observation['objects']['tmp'])}
    except Exception as error:
        try:
            if admitted:
                if observation is None:
                    observation = scratch_observe()
                scratch_emit_refusal(error, observation)
            else:
                # No /tmp, cwd, fdinfo or mountinfo access before the protected gate.
                print('CLUSTER238-GUARD-V1 '+json.dumps({'state':'pre-gate-refused',
                    'error':(type(error).__name__+': '+str(error))[:320],
                    'scratch_observation':'not-attempted'}, sort_keys=True),
                    file=sys.stderr, flush=True)
        except Exception:
            try:
                print('CLUSTER238-GUARD-V1 {"state":"guard-reporting-failed"}', file=sys.stderr, flush=True)
            except OSError:
                pass
        raise


def b64(data):
    return base64.b64encode(data).decode('ascii')


def write_exclusive(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise Incomplete('short file write: '+str(path))
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def save_report(name, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))+'\n').encode('ascii')
    if len(raw) > 512*1024:
        raise Incomplete('result report exceeds cap')
    target = HOME / name
    temporary = HOME / ('.'+name+'.tmp')
    write_exclusive(temporary, raw)
    os.replace(temporary, target)


class Recorder:
    """No silent loss, truncation or compression: cap/write failure invalidates the run."""
    def __init__(self, path, budget=4*1024*1024):
        self.path, self.budget, self.count, self.length = path, budget, 0, 0
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.closed = False

    def emit(self, kind, **fields):
        if self.closed:
            raise Incomplete('write after event close')
        entry = {'seq':self.count+1, 'kind':kind, 'monotonic_ns':time.monotonic_ns(), **fields}
        data = (json.dumps(entry, sort_keys=True, ensure_ascii=True, separators=(',', ':'))+'\n').encode('ascii')
        if self.length + len(data) > self.budget:
            raise Incomplete('event log retention cap would be exceeded')
        view = memoryview(data)
        while view:
            count = os.write(self.fd, view)
            if count <= 0:
                raise Incomplete('event log short write')
            view = view[count:]
        self.length += len(data)
        self.count += 1

    def close(self):
        if not self.closed:
            self.emit('recorder-close', event_count=self.count+1, byte_count_before_close=self.length)
            os.fsync(self.fd)
            os.close(self.fd)
            self.closed = True


def proc_birth(pid):
    """Read one known PID; callers validate parent and birth before opening its pidfd."""
    try:
        raw = bounded_pseudo(Path('/proc') / str(pid) / 'stat', 8192)
    except FileNotFoundError:
        return None
    try:
        fields = raw[raw.rindex(b')')+2:].split()
        return {'pid':pid, 'state':fields[0].decode('ascii'), 'ppid':int(fields[1]),
                'pgrp':int(fields[2]), 'session':int(fields[3]), 'starttime':int(fields[19])}
    except (ValueError, IndexError, UnicodeError) as exc:
        raise Incomplete('invalid process stat for known PID') from exc


def pin_owned(pid, parent):
    before = proc_birth(pid)
    if before is None or before['ppid'] != parent or before['state'] in ('Z','X','x'):
        raise Incomplete('known process is not a live child of the recorded parent')
    fd = os.pidfd_open(pid, 0)
    try:
        after = proc_birth(pid)
        if (after is None or after['ppid'] != parent or after['starttime'] != before['starttime']
                or after['state'] in ('Z','X','x')):
            raise Incomplete('known process identity changed during pidfd_open')
    except Exception:
        os.close(fd)
        raise
    return fd, before


def wait_until(test, timeout=3.0):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        value = test()
        if value:
            return value
        select.select([], [], [], 0.01)
    return None


def pidfd_signal(fd, sig):
    # The descriptor, never the numeric PID, is the signal target.
    signal.pidfd_send_signal(fd, sig)


class Shell:
    """Owned persistent shell with bounded, separate stdout/stderr command markers."""
    def __init__(self, executable, state_dir, event, label):
        self.label, self.event, self.sequence = label, event, 0
        env = dict(os.environ, BASHCLUSTER_STATE_DIR=str(state_dir), BASHCLUSTER_TIMEOUT_MS='2000')
        self.p = subprocess.Popen([str(executable), '--noprofile', '--norc'], cwd=CASE, env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  close_fds=True, start_new_session=True)
        try:
            self.fd, self.birth = pin_owned(self.p.pid, os.getpid())
        except Exception:
            # No numeric signal if pinning fails: EOF then bounded wait; the tracked unit owns any remainder.
            try:
                self.p.stdin.close()
                self.p.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):
                pass
            raise
        self.buffers = {'out':bytearray(), 'err':bytearray()}
        self.fds = {'out':self.p.stdout.fileno(), 'err':self.p.stderr.fileno()}
        for fd in self.fds.values():
            os.set_blocking(fd, False)
        self.stopped = False
        self.event.emit('shell-start', label=label, pid=self.p.pid, birth=self.birth)

    def call(self, script, timeout=8.0):
        self.sequence += 1
        marker = ('C238_%d_%d' % (self.p.pid, self.sequence)).encode('ascii')
        text = (script+"\n__c238_status=$?\nprintf '\\n@@%s %s@@\\n' "+marker.decode()+
                ' "$__c238_status"\nprintf \'\\n@@%s@@\\n\' '+marker.decode()+' >&2\n').encode()
        started = time.monotonic_ns()
        self.event.emit('command-start', label=self.label, script=script, marker=marker.decode())
        try:
            self.p.stdin.write(text); self.p.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            self.event.emit('command-transport-error', label=self.label, error=type(exc).__name__+': '+str(exc))
            raise Incomplete('owned shell command transport failed') from exc
        out_head = b'\n@@'+marker+b' '
        out_end = b'@@\n'
        err_tail = b'\n@@'+marker+b'@@\n'
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            out, err = self.buffers['out'], self.buffers['err']
            at = out.find(out_head); end = out.find(out_end, at+len(out_head)) if at >= 0 else -1
            e = err.find(err_tail)
            if at >= 0 and end >= 0 and e >= 0:
                try:
                    rc = int(bytes(out[at+len(out_head):end]))
                except ValueError as exc:
                    raise Incomplete('invalid shell status marker') from exc
                stdout, stderr = bytes(out[:at]), bytes(err[:e])
                del out[:end+len(out_end)]; del err[:e+len(err_tail)]
                result = {'rc':rc, 'stdout_base64':b64(stdout), 'stderr_base64':b64(stderr),
                          'started_ns':started, 'finished_ns':time.monotonic_ns()}
                self.event.emit('command-finish', label=self.label, **result)
                return result
            readable, _, _ = select.select(list(self.fds.values()), [], [], min(0.1,max(0,deadline-time.monotonic())))
            for fd in readable:
                name = next(k for k,v in self.fds.items() if v == fd)
                block = os.read(fd, 65536)
                if not block:
                    raise Incomplete('owned shell closed a capture pipe before its status marker')
                self.buffers[name].extend(block)
                if len(self.buffers[name]) > 256*1024:
                    raise Incomplete('owned shell output exceeded capture bound')
        self.event.emit('command-timeout', label=self.label, timeout_seconds=timeout,
                        stdout_base64=b64(self.buffers['out']), stderr_base64=b64(self.buffers['err']))
        raise Incomplete('owned shell command timed out')

    def cluster(self, *args):
        return self.call('builtin cluster '+' '.join(shlex.quote(str(x)) for x in args))

    def pause(self):
        pidfd_signal(self.fd, signal.SIGSTOP)
        def stopped():
            item = proc_birth(self.p.pid)
            return item if item and item['state'] in ('T','t') else None
        current = wait_until(stopped)
        if not current or current['starttime'] != self.birth['starttime']:
            raise Incomplete('owned shell did not enter stopped state')
        self.stopped = True
        self.event.emit('shell-stopped', label=self.label, birth=current)

    def finish(self):
        if self.stopped:
            pidfd_signal(self.fd, signal.SIGCONT)
            self.stopped = False
        try:
            self.p.stdin.write(b'exit\n'); self.p.stdin.flush(); self.p.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            status = self.p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pidfd_signal(self.fd, signal.SIGKILL)
            status = self.p.wait(timeout=3)
        self.event.emit('shell-exit', label=self.label, status=status)
        for stream in (self.p.stdin,self.p.stdout,self.p.stderr):
            try: stream.close()
            except (OSError,ValueError): pass
        os.close(self.fd)


MAGIC = b'BCLSTR2\0'
JOIN, PING, PONG = 1, 4, 7
SIZE, MAC_AT = 1212, 1180
SCRATCH_FILES = ('.members.tmp','.state.tmp','.cluster_id.tmp')


def mac(key, body):
    return hashlib.blake2b(body, key=key, digest_size=32).digest()


def packet(key, kind, port, cluster, node, nonce, magic=MAGIC):
    if len(cluster)!=32 or len(node)!=32 or len(nonce)!=16 or not 1<=port<=65535:
        raise Incomplete('invalid independent packet input')
    body = magic+bytes([kind,0])+struct.pack('!H',port)+nonce+cluster+node+bytes(32*34)
    if len(body)!=MAC_AT:
        raise Incomplete('independent packet geometry mismatch')
    return body+mac(key,body)


def decode(data):
    if len(data)!=SIZE:
        return None
    return {'magic':data[:8], 'kind':data[8], 'count':data[9], 'port':struct.unpack('!H',data[10:12])[0],
            'nonce':data[12:28], 'cluster':data[28:60], 'node':data[60:92], 'rows':data[92:1180], 'mac':data[1180:]}


def authenticated(data, key):
    return len(data)==SIZE and hmac.compare_digest(mac(key,data[:MAC_AT]),data[MAC_AT:])


def digest_label(label, length):
    return hashlib.sha256(('cluster238-'+label).encode()).hexdigest()[:length].encode('ascii')


def pidfd_control(rec):
    child = subprocess.Popen(['/usr/bin/python3','-I','-c','import sys; sys.stdin.buffer.read()'],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             close_fds=True, start_new_session=True)
    fd = None
    try:
        fd, birth = pin_owned(child.pid, os.getpid())
        pidfd_signal(fd, signal.SIGSTOP)
        def stopped():
            z=proc_birth(child.pid)
            return z if z and z['starttime']==birth['starttime'] and z['state'] in ('T','t') else None
        frozen=wait_until(stopped)
        if not frozen:
            raise Incomplete('pidfd control stop not observed')
        pidfd_signal(fd, signal.SIGKILL)
        def dead():
            z=proc_birth(child.pid)
            return z if z and z['starttime']==birth['starttime'] and z['ppid']==os.getpid() and z['state']=='Z' else None
        zombie=wait_until(dead)
        if not zombie or not select.select([fd],[],[],0)[0]:
            raise Incomplete('pidfd control did not retain a dead child as zombie')
        rc=child.wait(timeout=3)
        rec.emit('pidfd-control', birth=birth, stopped=frozen, zombie=zombie, waited_status=rc)
        return {'birth_checked':True,'stop_observed':True,'zombie_observed_before_wait':True,'waited_status':rc}
    finally:
        if fd is not None:
            try:
                if child.returncode is None:
                    try: pidfd_signal(fd, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=3)
            finally:
                os.close(fd)
        if child.stdin:
            child.stdin.close()
        if fd is None:
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired as exc:
                raise Incomplete('unpinned control child needs tracked-unit cleanup') from exc


def loopback_control(rec):
    receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        receiver.bind(('127.0.0.1',0)); sender.bind(('127.0.0.1',0))
        destination=receiver.getsockname()
        checked=[]; counter_before=udp_namespace_counter(); network_before=loopback_network_counter()
        for size in (0,1,1212,65507):
            content=bytes([size%251])*size
            n=sender.sendto(content,destination)
            if n!=size or not select.select([receiver],[],[],2)[0]:
                raise Incomplete('loopback control send/receive failed')
            data,peer=receiver.recvfrom(65536)
            if data!=content or peer[0]!='127.0.0.1':
                raise Incomplete('loopback control data or source differs')
            rec.emit('loopback-control',size=size,send_return=n,source=list(peer),packet_base64=b64(data))
            checked.append(size)
        counter_after=udp_namespace_counter(); network_after=loopback_network_counter()
        calibrated=(counter_before.get('available') and counter_after.get('available')
                    and counter_after['in_datagrams']-counter_before['in_datagrams']==len(checked)
                    and counter_after['out_datagrams']-counter_before['out_datagrams']==len(checked)
                    and counter_after['in_errors']==counter_before['in_errors']
                    and counter_after['rcvbuf_errors']==counter_before['rcvbuf_errors'])
        network_calibrated=(network_before.get('available') and network_after.get('available')
                            and network_after['tx_packets']-network_before['tx_packets']==len(checked)
                            and all(network_after[name]==network_before[name] for name in
                                    ('rx_errors','rx_drops','tx_errors','tx_drops')))
        rec.emit('udp-counter-control',before=counter_before,after=counter_after,calibrated=bool(calibrated),
                 network_before=network_before,network_after=network_after,network_calibrated=bool(network_calibrated))
        return {'exact_delivered_sizes':checked,'namespace_counter_calibrated':bool(calibrated),
                'namespace_counter_before':counter_before,'namespace_counter_after':counter_after,
                'network_counter_calibrated':bool(network_calibrated),
                'network_counter_before':network_before,'network_counter_after':network_after}
    finally:
        sender.close(); receiver.close()


def codec_control(rec):
    if hashlib.blake2b(b'abc',digest_size=32).hexdigest()!='bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319':
        raise Incomplete('independent BLAKE2b known answer mismatch')
    if hashlib.blake2b(b'',key=bytes(range(64)),digest_size=64).hexdigest() != (
       '10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568'):
        raise Incomplete('keyed BLAKE2b known answer mismatch')
    key=bytes(range(32)); other=bytes(reversed(range(32)))
    cluster=b'a'*32; node=b'b'*32; nonce=bytes(range(16))
    valid=packet(key,PING,1234,cluster,node,nonce); q=decode(valid)
    if not (q and len(valid)==1212 and q['magic']==MAGIC and q['kind']==PING and q['count']==0
            and q['port']==1234 and q['cluster']==cluster and q['node']==node and q['nonce']==nonce
            and q['rows']==bytes(1088) and authenticated(valid,key) and not authenticated(valid,other)
            and decode(valid[:-1]) is None and decode(valid+b'x') is None):
        raise Incomplete('independent protocol encoder/decoder controls failed')
    wrong=packet(other,JOIN,1234,cluster,node,nonce)
    if not authenticated(wrong,other) or authenticated(wrong,key):
        raise Incomplete('alternate/group key control failed')
    rec.emit('codec-control',packet_size=len(valid),body_size=MAC_AT,known_answers=True,
             group_accepts_correct=True,group_rejects_alternate=True,alternate_accepts=True)
    return {'known_answers':True,'roundtrip':True,'alternate_key':True}


def recorder_control(rec):
    # The complete 65507-byte sample must survive encoding and file retention.
    sample=bytes(range(256))*255+bytes(range(227))
    rec.emit('recorder-full-byte-control', bytes=len(sample), data_base64=b64(sample))
    return {'sample_bytes':len(sample),'no_prefix_truncation':True}


def shell_control(rec):
    node=Shell(REFERENCE_BASH,CASE,rec,'setup-shell')
    try:
        first=node.call("printf 'alpha'; printf 'beta' >&2; (exit 7)")
        second=node.call("printf 'two\\n'")
        if (first['rc'],base64.b64decode(first['stdout_base64']),base64.b64decode(first['stderr_base64'])) != (7,b'alpha',b'beta'):
            raise Incomplete('reference shell first marker/status control failed')
        if (second['rc'],base64.b64decode(second['stdout_base64']),base64.b64decode(second['stderr_base64'])) != (0,b'two\n',b''):
            raise Incomplete('reference shell second marker/status control failed')
        return {'two_commands':True,'independent_status_and_channels':True}
    finally:
        node.finish()


def setup(scenario, proof):
    if scenario not in ('stale','packets','negative'):
        raise Incomplete('unknown setup scenario')
    rec=Recorder(HOME/'cluster238-setup-events.jsonl')
    details={}
    try:
        rec.emit('setup-begin',scenario=scenario,guard=proof)
        details['pidfd']=pidfd_control(rec)
        details['shell']=shell_control(rec)
        details['recorder']=recorder_control(rec)
        if scenario in ('packets','negative'):
            details['codec']=codec_control(rec)
            details['loopback']=loopback_control(rec)
        rec.emit('setup-complete',scenario=scenario)
    finally:
        rec.close()
    raw=(HOME/'cluster238-setup-events.jsonl').read_bytes()
    records=[json.loads(line) for line in raw.splitlines()]
    expected=list(range(1,len(records)+1))
    retained=next(x for x in records if x['kind']=='recorder-full-byte-control')
    if ([x['seq'] for x in records]!=expected or records[-1]['kind']!='recorder-close'
            or records[-1]['event_count']!=len(records)
            or base64.b64decode(retained['data_base64'],validate=True)!=bytes(range(256))*255+bytes(range(227))):
        raise Incomplete('independent recorder retention selfcheck failed')
    result={'schema':'cluster238-setup-v1','scenario':scenario,'guard':proof,'controls':details,
            'event_count':len(records),'result':'PASS'}
    save_report('cluster238-setup.json',result)
    print('cluster238 setup='+scenario+' pass',flush=True)


def read_regular(path, limit=8192):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=2000 or info.st_size>limit:
            raise Incomplete('unexpected state file identity or size: '+str(path))
        data=b''
        while len(data)<=limit:
            part=os.read(fd, min(4096,limit+1-len(data)))
            if not part: break
            data+=part
        if len(data)>limit or len(data)!=info.st_size:
            raise Incomplete('state file changed or exceeded cap: '+str(path))
        return data
    finally:
        os.close(fd)


def number_file(path):
    data=read_regular(path,128)
    if not re.fullmatch(rb'[0-9]+\n?',data):
        return None
    value=int(data)
    return value if 1<=value<=2**31-1 else None


def entry_absent(path):
    try:
        os.lstat(path)
        return False
    except FileNotFoundError:
        return True


def listener_identity(directory, owner):
    """The recorded live listener and port, bound to this known shell."""
    pid=number_file(directory/'listener_pid'); port=number_file(directory/'port')
    current=proc_birth(pid) if pid else None
    if not (pid and port and port<=65535 and current and current['ppid']==owner
            and current['state'] not in ('Z','X','x')):
        return None
    return {'pid':pid,'port':port,'process':current}


def state_identity(directory, owner):
    """Packet fixtures additionally require the documented independent wire IDs."""
    result=listener_identity(directory,owner)
    cluster=read_regular(directory/'cluster_id',128); node=read_regular(directory/'node_id',128)
    if not result or not re.fullmatch(rb'[0-9a-f]{32}',cluster) or not re.fullmatch(rb'[0-9a-f]{32}',node):
        return None
    return {**result,'cluster':cluster,'node':node}


def new_key(path):
    key=bytes(range(32))
    write_exclusive(path,key.hex().encode('ascii'))
    return key


def stale_case(rec):
    directory=CASE/'stale-owned'; os.mkdir(directory,0o700)
    write_exclusive(directory/'unrelated.txt',b'fixture-preserve\n')
    keypath=CASE/'stale-fixed.key';new_key(keypath)
    shells=[]; oldfd=None; newfd=None
    reached=['initial-init']; checks={}; observations={}
    try:
        first=Shell(CANDIDATE,directory,rec,'original-owner');shells.append(first)
        initial=first.cluster('init','-p','0','-k',keypath)
        observations['initial_init']=initial
        if initial['rc']!=0:
            rec.emit('precondition-unreached',operation='initial-init',candidate_rc=initial['rc'])
            return {'classification':'INCOMPLETE','reached':reached,'checks':checks,
                    'reason':'initial candidate init did not provide a listener; stale init was not reached',
                    'candidate_observations':observations}
        old=listener_identity(directory,first.p.pid)
        if old is None:
            raise Incomplete('initial init did not produce an owned listener identity')
        oldfd,birth=pin_owned(old['pid'],first.p.pid)
        pidfile=read_regular(directory/'listener_pid',128)
        if pidfile not in (str(old['pid']).encode(),str(old['pid']).encode()+b'\n'):
            raise Incomplete('listener PID file differs from the owned listener')
        rec.emit('initial-listener',pid=old['pid'],birth=birth,pid_file_base64=b64(pidfile))
        first.pause()
        pidfd_signal(oldfd,signal.SIGKILL)
        def dead_original():
            item=proc_birth(old['pid'])
            return item if (item and item['ppid']==first.p.pid and item['starttime']==birth['starttime']
                            and item['state']=='Z') else None
        dead=wait_until(dead_original)
        if not dead or not select.select([oldfd],[],[],0)[0]:
            raise Incomplete('original listener did not remain a dead owned zombie')
        if read_regular(directory/'listener_pid',128)!=pidfile:
            raise Incomplete('dead listener PID was replaced before the next init')
        for name in SCRATCH_FILES:
            write_exclusive(directory/name,b'partial-'+name.encode('ascii'))
        # A held zombie cannot be numerically reused. Do not substitute a live sentinel.
        second=Shell(CANDIDATE,directory,rec,'recovery-owner');shells.append(second)
        dead=dead_original()
        actual=read_regular(directory/'listener_pid',128)
        if not dead or actual!=pidfile or not select.select([oldfd],[],[],0)[0]:
            raise Incomplete('dead listener identity or its on-disk PID was lost before recovery init')
        try: unrelated_before=b64(read_regular(directory/'unrelated.txt'))
        except (OSError,Incomplete): unrelated_before=None
        rec.emit('dead-pid-before-next-init',birth=dead,pid_file_base64=b64(actual),
                 held_by_stopped_parent=True,
                 scratch_files={name:b64(read_regular(directory/name,512)) for name in SCRATCH_FILES},
                 unrelated_base64=unrelated_before)
        reached.append('next-init-with-dead-pid')
        again=second.cluster('init','-p','0','-k',keypath)
        observations['next_init']=again
        checks['init_status_zero']=again['rc']==0
        scratch_remaining=[name for name in SCRATCH_FILES if not entry_absent(directory/name)]
        checks['scratch_removed']=not scratch_remaining
        try:
            checks['unrelated_preserved']=read_regular(directory/'unrelated.txt')==b'fixture-preserve\n'
        except (OSError,Incomplete):
            checks['unrelated_preserved']=False
        try:
            new=listener_identity(directory,second.p.pid)
        except FileNotFoundError:
            new=None
        checks['new_live_owned_listener']=new is not None and new['pid']!=old['pid']
        checks['new_state_initialized']=False
        try:
            new_state=read_regular(directory/'state',128)
            checks['new_state_initialized']=new_state.strip()==b'initialized'
        except FileNotFoundError:
            new_state=None
        try: new_pid_bytes=read_regular(directory/'listener_pid',128)
        except FileNotFoundError: new_pid_bytes=None
        # The literal r5 requires successful recovery and cleanup of known leftover temporaries.
        # Preservation of unrelated files is saved separately and belongs to the distinct r6.
        core=('init_status_zero','scratch_removed','new_live_owned_listener','new_state_initialized')
        verdict='PASS' if all(checks[x] for x in core) else 'FAIL'
        rec.emit('stale-result',checks=checks,classification=verdict,
                 old_listener=old['pid'],new_listener=new,
                 new_pid_file_base64=b64(new_pid_bytes) if new_pid_bytes is not None else None,
                 new_state_base64=b64(new_state) if new_state is not None else None,
                 scratch_remaining=scratch_remaining)
        if new:
            newfd,_newbirth=pin_owned(new['pid'],second.p.pid)
            # Supplementary cleanup only; do not use this result to judge r5.
            observations['cleanup_leave']=second.cluster('leave')
        return {'classification':verdict,'reached':reached,'checks':checks,
                'candidate_observations':observations,
                'scope':'dead recorded listener PID and known scratch files at the subsequent init; no live-sentinel substitution'}
    finally:
        problems=[]
        for shell in reversed(shells):
            try: shell.finish()
            except Exception as error: problems.append(type(error).__name__+': '+str(error))
        if newfd is not None:
            try:
                if not select.select([newfd],[],[],0)[0]:
                    pidfd_signal(newfd,signal.SIGKILL)
                    if not select.select([newfd],[],[],3)[0]:
                        problems.append('new listener remained live after exact pidfd cleanup')
                os.close(newfd)
            except OSError as error: problems.append(type(error).__name__+': '+str(error))
        if oldfd is not None:
            try: os.close(oldfd)
            except OSError as error: problems.append(type(error).__name__+': '+str(error))
        if problems:
            rec.emit('teardown-error',errors=problems)
            raise Incomplete('owned shell cleanup uncertain')


def udp_row(port, address='127.0.0.1'):
    raw=bounded_pseudo('/proc/self/net/udp',262144).decode('ascii')
    found=[]
    for line in raw.splitlines()[1:]:
        f=line.split()
        if len(f)<13:
            raise Incomplete('malformed /proc UDP row')
        ip, sep, p=f[1].partition(':')
        if not sep:
            raise Incomplete('malformed /proc UDP address')
        ip=socket.inet_ntoa(bytes.fromhex(ip)[::-1])
        if ip==address and int(p,16)==port:
            q=f[4].split(':')
            if len(q)!=2: raise Incomplete('malformed /proc UDP queues')
            found.append({'ip':ip,'port':port,'tx':int(q[0],16),'rx':int(q[1],16),
                          'uid':int(f[7]),'inode':int(f[9]),'drops':int(f[12])})
    if len(found)>1:
        raise Incomplete('ambiguous owned listener UDP row')
    return found[0] if found else None


def socket_inodes(pid):
    directory=Path('/proc')/str(pid)/'fd'
    result=[]
    try:
        names=os.listdir(directory)
        for name in names:
            try: target=os.readlink(directory/name)
            except FileNotFoundError: continue
            match=re.fullmatch(r'socket:\[([0-9]+)\]',target)
            if match: result.append(int(match.group(1)))
    except OSError as error:
        raise Incomplete('cannot inspect recorded listener socket descriptors') from error
    return sorted(result)


def udp_namespace_counter():
    """Supplementary namespace-wide receive counter; it is not a PID-specific trace."""
    try:
        lines=bounded_pseudo('/proc/self/net/snmp',65536).decode('ascii').splitlines()
        matches=[line.split() for line in lines if line.startswith('Udp:')]
        if len(matches)!=2 or len(matches[0])!=len(matches[1]):
            return {'available':False,'reason':'missing UDP counter rows'}
        names,values=matches
        row=dict(zip(names[1:],values[1:]))
        return {'available':True,'in_datagrams':int(row['InDatagrams']),
                'in_errors':int(row['InErrors']),'rcvbuf_errors':int(row['RcvbufErrors']),
                'out_datagrams':int(row['OutDatagrams'])}
    except (OSError, ValueError, KeyError, UnicodeError, Incomplete) as error:
        return {'available':False,'reason':(type(error).__name__+': '+str(error))[:240]}


def loopback_network_counter():
    """Namespace loopback packet/loss counters cover IP traffic beyond UDP, not syscall identity."""
    try:
        lines=bounded_pseudo('/proc/self/net/dev',65536).decode('ascii').splitlines()[2:]
        rows=[]
        for line in lines:
            name,sep,values=line.partition(':')
            if not sep:
                raise Incomplete('malformed network device counter')
            fields=values.split()
            if len(fields)!=16:
                raise Incomplete('unexpected network device counter geometry')
            rows.append((name.strip(),[int(x) for x in fields]))
        if len(rows)!=1 or rows[0][0]!='lo':
            return {'available':False,'reason':'network counter view is not loopback-only'}
        values=rows[0][1]
        return {'available':True,'rx_errors':values[2],'rx_drops':values[3],
                'tx_packets':values[9],'tx_errors':values[10],'tx_drops':values[11]}
    except (OSError,ValueError,UnicodeError,Incomplete) as error:
        return {'available':False,'reason':(type(error).__name__+': '+str(error))[:240]}


def send_packet(rec, sock, label, destination, content):
    if not re.fullmatch(r'[a-z0-9-]{1,64}',label):
        raise Incomplete('invalid internally generated packet label')
    if (not isinstance(destination,tuple) or len(destination)!=2 or destination[0]!='127.0.0.1'
            or type(destination[1]) is not int or not 1<=destination[1]<=65535):
        raise Incomplete('packet destination is not the owned numeric loopback endpoint')
    folder=CASE/'packets'
    if not os.path.lexists(folder): os.mkdir(folder,0o700)
    folder_info=folder.lstat()
    if not stat.S_ISDIR(folder_info.st_mode) or folder_info.st_uid!=2000 or stat.S_IMODE(folder_info.st_mode)!=0o700:
        raise Incomplete('packet retention directory identity changed')
    path=folder/(label+'.bin')
    write_exclusive(path,content)
    src=sock.getsockname()
    rec.emit('send-attempt',label=label,source=list(src),destination=list(destination),
             size=len(content),packet_base64=b64(content),retained_file=str(path.relative_to(CASE)))
    try:
        count=sock.sendto(content,destination)
    except OSError as error:
        rec.emit('send-error',label=label,error=type(error).__name__+': '+str(error))
        raise Incomplete('owned datagram send failed') from error
    rec.emit('send-complete',label=label,returned=count,expected=len(content))
    if count!=len(content):
        raise Incomplete('owned datagram send was short')


def get_datagram(rec,sock,label,timeout):
    readable,_,_=select.select([sock],[],[],timeout)
    if not readable:
        return None
    data,ancillary,flags,source=sock.recvmsg(65536,0)
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise Incomplete('probe datagram capture was truncated')
    rec.emit('probe-recv',label=label,source=list(source),destination=list(sock.getsockname()),
             size=len(data),packet_base64=b64(data),flags=flags)
    return data,source


def ping(rec,sock,key,info,label):
    nonce=hashlib.sha256(('cluster238-ping-'+label).encode('ascii')).digest()[:16]
    request=packet(key,PING,sock.getsockname()[1],info['cluster'],digest_label('ping-'+label,32),nonce)
    send_packet(rec,sock,'barrier-'+label,('127.0.0.1',info['port']),request)
    end=time.monotonic()+3.0; other=0
    while time.monotonic()<end:
        item=get_datagram(rec,sock,'barrier-'+label,min(0.1,max(0,end-time.monotonic())))
        if item is None:
            continue
        data,source=item;q=decode(data)
        if (q and source==('127.0.0.1',info['port']) and q['magic']==MAGIC and q['kind']==PONG
                and q['count']==0 and q['port']==info['port'] and q['nonce']==nonce
                and q['cluster']==info['cluster'] and q['node']==info['node']
                and q['rows']==bytes(1088) and authenticated(data,key)):
            rec.emit('barrier-answer',label=label,matched=True,other_datagrams=other)
            return True
        other+=1
        if other>128: raise Incomplete('probe received too many datagrams')
    rec.emit('barrier-answer',label=label,matched=False,other_datagrams=other)
    return False


def packet_vectors(key,other,info,probe_port):
    nonce=hashlib.sha256(b'cluster238-wrong-key-nonce').digest()[:16]
    node=digest_label('wrong-key-joiner',32)
    wrong=packet(other,JOIN,probe_port,info['cluster'],node,nonce)
    parsed=decode(wrong)
    if not (parsed and parsed['magic']==MAGIC and parsed['kind']==JOIN and parsed['count']==0
            and parsed['port']==probe_port and parsed['cluster']==info['cluster']
            and parsed['node']==node and parsed['nonce']==nonce
            and authenticated(wrong,other) and not authenticated(wrong,key)):
        raise Incomplete('wrong-key vector does not have the intended independently checked shape')
    normal=packet(key,PING,probe_port,info['cluster'],digest_label('size-node',32),nonce)
    bad_magic=packet(key,PING,probe_port,info['cluster'],digest_label('format-node',32),nonce,magic=b'BCLSTR1\0')
    if not authenticated(bad_magic,key) or decode(bad_magic)['magic']==MAGIC:
        raise Incomplete('malformed magic control failed')
    return [('wrong-key',wrong),('malformed-magic',bad_magic),('truncated-0',b''),('truncated-1',b'\x00'),
            ('truncated-8',MAGIC),('truncated-600',normal[:600]),('truncated-1180',normal[:1180]),
            ('truncated-1211',normal[:-1]),('oversized-1213',normal+b'X'),
            ('oversized-1312',normal+bytes(100)),('oversized-2424',normal*2),
            ('oversized-4096',bytes(4096)),('oversized-65507',bytes(65507))]


def packets_case(rec):
    directory=CASE/'packet-owned'; os.mkdir(directory,0o700)
    keypath=CASE/'packet-fixed.key'; key=new_key(keypath); other=bytes(reversed(range(32)))
    shells=[];listener_fd=None;probe=None
    reached=['initial-init']; checks={}; observations={}; results=[]
    try:
        node=Shell(CANDIDATE,directory,rec,'packet-owner');shells.append(node)
        start=node.cluster('init','-p','0','-k',keypath);observations['initial_init']=start
        if start['rc']!=0:
            return {'classification':'INCOMPLETE','reached':reached,'checks':checks,
                    'reason':'initial candidate init failed; no rejection vector was reached',
                    'candidate_observations':observations}
        info=state_identity(directory,node.p.pid)
        if info is None:
            raise Incomplete('initial init did not provide an owned listener identity')
        listener_fd,birth=pin_owned(info['pid'],node.p.pid)
        row=udp_row(info['port']); inodes=socket_inodes(info['pid'])
        if not row or row['uid']!=2000 or row['inode'] not in inodes:
            raise Incomplete('owned listener UDP socket/port identity not established')
        rec.emit('listener-socket',birth=birth,udp=row,listener_socket_inodes=inodes)
        rec.emit('listener-wire-identity',pid=info['pid'],port=info['port'],
                 cluster_base64=b64(info['cluster']),node_base64=b64(info['node']))
        before=read_regular(directory/'members',8192)
        expected=info['node']+b' 127.0.0.1:'+str(info['port']).encode()+b'\n'
        if before!=expected:
            raise Incomplete('initial private roster is not independently parseable as the seed')
        probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.bind(('127.0.0.1',0))
        probe_port=probe.getsockname()[1]
        probe_initial=udp_row(probe_port)
        probe_link=os.readlink('/proc/self/fd/'+str(probe.fileno()))
        if (not probe_initial or probe_initial['uid']!=2000 or
                probe_link!='socket:[%d]'%probe_initial['inode']):
            raise Incomplete('owned probe UDP socket identity not established')
        rec.emit('probe-socket-created',udp=probe_initial,fd_link=probe_link)
        if not ping(rec,probe,key,info,'initial'):
            rec.emit('precondition-unreached',operation='initial-authenticated-ping')
            return {'classification':'INCOMPLETE','reached':reached,'checks':checks,
                    'reason':'initial independent authenticated ping failed; rejection vectors were not reached',
                    'candidate_observations':observations}
        vectors=packet_vectors(key,other,info,probe.getsockname()[1])
        rec.emit('vector-controls',wrong_key_valid_under_alternate=True,wrong_key_invalid_under_group=True,
                 wrong_key_shape='JOIN, count 0, candidate cluster, owned source port',
                 malformed_group_mac_valid=True,vector_sizes={name:len(data) for name,data in vectors})
        for label,data in vectors:
            current=proc_birth(info['pid'])
            if (not current or current['starttime']!=birth['starttime'] or current['ppid']!=node.p.pid
                    or current['state'] in ('Z','X','x')):
                raise Incomplete('owned listener disappeared before remaining vectors')
            before=read_regular(directory/'members',8192)
            previous=udp_row(info['port'])
            if not previous or previous['inode']!=row['inode'] or previous['rx']!=0:
                raise Incomplete('owned listener socket changed or had pending data before vector')
            probe_before=udp_row(probe_port)
            probe_before_link=os.readlink('/proc/self/fd/'+str(probe.fileno()))
            if (not probe_before or probe_before['uid']!=2000
                    or probe_before['inode']!=probe_initial['inode'] or probe_before_link!=probe_link):
                raise Incomplete('owned probe socket changed before vector')
            counters_before=udp_namespace_counter()
            send_packet(rec,probe,label,('127.0.0.1',info['port']),data)
            reached.append(label)
            # Counters and queue samples strengthen ordinary delivery evidence but do not identify a PID.
            if counters_before.get('available'):
                wait_until(lambda: (udp_namespace_counter().get('in_datagrams',-1) > counters_before['in_datagrams']),timeout=0.25)
            wait_until(lambda: (udp_row(info['port']) or {}).get('rx')==0,timeout=0.5)
            middle=udp_row(info['port']);counters_after=udp_namespace_counter()
            if not middle or middle['inode']!=row['inode']:
                raise Incomplete('owned socket disappeared after stimulus')
            if middle['drops']!=previous['drops']:
                raise Incomplete('listener drop count changed during stimulus')
            rec.emit('stimulus-socket-observation',label=label,before=previous,after=middle,
                     udp_namespace_before=counters_before,udp_namespace_after=counters_after,
                     process_specific_receive_proved=False)
            ok=ping(rec,probe,key,info,label)
            after_barrier=udp_row(info['port'])
            probe_after=udp_row(probe_port)
            probe_after_link=os.readlink('/proc/self/fd/'+str(probe.fileno()))
            rec.emit('probe-socket-observation',label=label,before=probe_before,after=probe_after,
                     fd_link_before=probe_before_link,fd_link_after=probe_after_link)
            if (not probe_after or probe_after['uid']!=2000
                    or probe_after['inode']!=probe_initial['inode'] or probe_after_link!=probe_link
                    or probe_after['drops']!=probe_before['drops'] or (not ok and probe_after['rx']!=0)):
                raise Incomplete('probe socket loss, identity or pending failed-barrier data')
            if (not after_barrier or after_barrier['inode']!=row['inode']
                    or after_barrier['drops']!=previous['drops'] or (not ok and after_barrier['rx']!=0)):
                rec.emit('barrier-socket-incomplete',label=label,after=after_barrier)
                raise Incomplete('socket identity or drop count changed across the barrier')
            try:
                after=read_regular(directory/'members',8192); after_missing=False
            except FileNotFoundError:
                after=None; after_missing=True
            except OSError as error:
                rec.emit('roster-read-error',label=label,error=type(error).__name__+': '+str(error))
                raise Incomplete('could not retain the post-stimulus roster') from error
            result={'label':label,'size':len(data),'before_base64':b64(before),
                    'after_base64':b64(after) if after is not None else None,'after_missing':after_missing,
                    'roster_unchanged':not after_missing and before==after,'later_ping_ok':ok,
                    'socket_drops_before':previous['drops'],'socket_drops_after':after_barrier['drops'],
                    'socket_after_barrier':after_barrier,'probe_before':probe_before,'probe_after':probe_after}
            results.append(result)
            rec.emit('vector-result',**result)
            if not ok or after_missing:
                # A reached later-ping failure is preserved; subsequent vectors were not exercised.
                break
        checks['all_vectors_reached']=len(results)==len(vectors)
        checks['rosters_unchanged']=all(x['roster_unchanged'] for x in results)
        checks['later_ping_ok']=all(x['later_ping_ok'] for x in results)
        verdict='PASS' if all(checks.values()) else 'FAIL'
        rec.emit('packet-result',checks=checks,classification=verdict)
        observations['cleanup_leave']=node.cluster('leave')
        return {'classification':verdict,'reached':reached,'checks':checks,'vectors':results,
                'candidate_observations':observations,
                'receipt_scope':'completed loopback send, owned socket/queue/drop samples and subsequent authenticated barrier; namespace counters are supplementary, not PID-specific receive traces'}
    finally:
        problems=[]
        if probe is not None:
            try: probe.close()
            except OSError as error: problems.append(type(error).__name__+': '+str(error))
        for shell in reversed(shells):
            try: shell.finish()
            except Exception as error: problems.append(type(error).__name__+': '+str(error))
        if listener_fd is not None:
            try:
                if not select.select([listener_fd],[],[],0)[0]:
                    pidfd_signal(listener_fd,signal.SIGKILL)
                    if not select.select([listener_fd],[],[],3)[0]:
                        problems.append('packet listener remained live after exact pidfd cleanup')
                os.close(listener_fd)
            except OSError as error: problems.append(type(error).__name__+': '+str(error))
        if problems:
            rec.emit('teardown-error',errors=problems)
            raise Incomplete('owned packet fixture cleanup uncertain')


def negative_case(rec):
    """Bounded decoys and a namespace counter for two unresolved no-send clauses."""
    directory=CASE/'negative-owned';os.mkdir(directory,0o700)
    decoys=[];decoy_identities=[];sender=None;shells=[];reached=[];observations={};results=[]
    try:
        for label in ('self','peer'):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0',0));decoys.append(sock)
            port=sock.getsockname()[1]
            row=udp_row(port,'0.0.0.0')
            link=os.readlink('/proc/self/fd/'+str(sock.fileno()))
            if not row or row['uid']!=2000 or link!='socket:[%d]'%row['inode']:
                raise Incomplete('wildcard decoy socket identity is not observable')
            decoy_identities.append({'inode':row['inode'],'fd_link':link})
            rec.emit('decoy-created',label=label,udp=row,fd_link=link)
        sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sender.bind(('127.0.0.1',0))
        for index,sock in enumerate(decoys):
            for address in ('127.0.0.1','127.0.0.2'):
                data=('decoy-control-%d-%s'%(index,address)).encode()
                target=(address,sock.getsockname()[1]);count=sender.sendto(data,target)
                rec.emit('decoy-control-send',index=index,address=address,port=target[1],
                         packet_base64=b64(data),returned=count)
                item=get_datagram(rec,sock,'decoy-control',2.0)
                if count!=len(data) or item is None or item[0]!=data or item[1]!=sender.getsockname():
                    raise Incomplete('wildcard decoy positive delivery control failed')
        sender.close();sender=None
        key=bytes(range(32));cluster=digest_label('negative-cluster',32)
        own=digest_label('negative-own',32);peer=digest_label('negative-peer',32)
        unknown=digest_label('negative-unknown',32)
        if len({own,peer,unknown})!=3:
            raise Incomplete('negative node IDs are not distinct')
        ownport,peerport=(s.getsockname()[1] for s in decoys)
        contents={'cluster_id':cluster,'node_id':own,'port':('%d\n'%ownport).encode(),
                  'private_key':key.hex().encode('ascii'),
                  'members':own+b' 127.0.0.1:'+str(ownport).encode()+b'\n'+
                            peer+b' 127.0.0.1:'+str(peerport).encode()+b'\n'}
        for name,data in contents.items(): write_exclusive(directory/name,data)
        rec.emit('offline-state',members_base64=b64(contents['members']),
                 cluster_base64=b64(cluster),node_base64=b64(own))
        node=Shell(CANDIDATE,directory,rec,'negative-owner');shells.append(node)
        for label,target in (('unknown-node',unknown.decode()),
                             ('malformed-target','127.0.0.2:%d'%peerport)):
            before=[udp_row(s.getsockname()[1],'0.0.0.0') for s in decoys]
            before_links=[os.readlink('/proc/self/fd/'+str(s.fileno())) for s in decoys]
            if any(row is None or row['uid']!=2000 or row['inode']!=identity['inode'] or row['rx']!=0
                   or link!=identity['fd_link'] for row,identity,link in zip(before,decoy_identities,before_links)):
                raise Incomplete('decoy identity or pending receive queue before call')
            counter_before=udp_namespace_counter();network_before=loopback_network_counter()
            rec.emit('negative-observation-begin',label=label,decoy_before=before,fd_links=before_links,
                     namespace_counter_before=counter_before,network_counter_before=network_before)
            call=node.cluster('ping',target);reached.append(label)
            received=[];started=time.monotonic_ns();deadline=time.monotonic()+0.30
            while time.monotonic()<deadline:
                readable,_,_=select.select(decoys,[],[],min(0.05,max(0,deadline-time.monotonic())))
                for sock in readable:
                    item=get_datagram(rec,sock,label,0)
                    if item is not None:
                        received.append({'port':sock.getsockname()[1], 'source':list(item[1]),
                                         'packet_base64':b64(item[0])})
                        if len(received)>128: raise Incomplete('negative decoy capture cap exceeded')
            after=[udp_row(s.getsockname()[1],'0.0.0.0') for s in decoys]
            after_links=[os.readlink('/proc/self/fd/'+str(s.fileno())) for s in decoys]
            if any(row is None or row['uid']!=2000 or row['inode']!=old['inode']
                   or row['drops']!=old['drops'] or row['rx']!=0
                   or link!=identity['fd_link'] for row,old,identity,link in zip(after,before,decoy_identities,after_links)):
                raise Incomplete('decoy identity, drop count or pending receive queue changed')
            counter_after=udp_namespace_counter();network_after=loopback_network_counter()
            finished=time.monotonic_ns()
            rec.emit('negative-observation-end',label=label,decoy_after=after,fd_links=after_links,
                     namespace_counter_after=counter_after,network_counter_after=network_after)
            available=counter_before.get('available') and counter_after.get('available')
            delta=(counter_after['out_datagrams']-counter_before['out_datagrams']) if available else None
            if delta is not None and delta<0: raise Incomplete('namespace UDP counter moved backward')
            loss_unchanged=(counter_after['in_errors']==counter_before['in_errors']
                            and counter_after['rcvbuf_errors']==counter_before['rcvbuf_errors']) if available else None
            network_available=network_before.get('available') and network_after.get('available')
            network_unchanged=(all(network_after[name]==network_before[name] for name in
                                   ('tx_packets','rx_errors','rx_drops','tx_errors','tx_drops'))
                               if network_available else None)
            item={'label':label,'target':target,'call':call,'decoy_received':received,
                  'decoy_before':before,'decoy_after':after,'started_ns':started,
                  'finished_ns':finished,'namespace_counter_before':counter_before,
                  'namespace_counter_after':counter_after,'namespace_out_delta':delta,
                  'namespace_loss_unchanged':loss_unchanged,
                  'network_counter_before':network_before,'network_counter_after':network_after,
                  'network_counter_unchanged':network_unchanged}
            results.append(item);rec.emit('negative-observation',**item)
        # Only a directly observed status mismatch or a packet received by our decoys is a product FAIL.
        # A changed/unavailable namespace counter without a decoy packet is un-attributed, hence incomplete.
        status_ok=all((x['call']['rc']!=0 if x['label']=='unknown-node' else x['call']['rc']==1)
                      for x in results)
        decoy_quiet=all(not x['decoy_received'] for x in results)
        setup_record=json.loads(read_regular(HOME/'cluster238-setup.json',512*1024))
        counters_quiet=(setup_record['controls']['loopback'].get('namespace_counter_calibrated') is True
                        and setup_record['controls']['loopback'].get('network_counter_calibrated') is True
                        and all(x['namespace_out_delta']==0 and x['namespace_loss_unchanged'] is True
                                and x['network_counter_unchanged'] is True for x in results))
        verdict='FAIL' if not status_ok or not decoy_quiet else ('PASS' if counters_quiet else 'INCOMPLETE')
        checks={'failure_status':status_ok,'decoys_quiet':decoy_quiet,'namespace_counter_unchanged':counters_quiet}
        rec.emit('negative-result',checks=checks,classification=verdict)
        return {'classification':verdict,'reached':reached,'checks':checks,'vectors':results,
                'candidate_observations':observations,
                'scope':'two owned wildcard decoys plus bounded network-namespace UDP counter; no PID-specific syscall trace'}
    finally:
        problems=[]
        if sender is not None:
            try: sender.close()
            except OSError as error: problems.append(str(error))
        for shell in reversed(shells):
            try: shell.finish()
            except Exception as error: problems.append(type(error).__name__+': '+str(error))
        for sock in decoys:
            try: sock.close()
            except OSError as error: problems.append(str(error))
        if problems:
            rec.emit('teardown-error',errors=problems)
            raise Incomplete('negative observation cleanup uncertain')


def case(scenario, proof):
    if scenario not in ('stale','packets','negative'):
        raise Incomplete('unknown case scenario')
    setup_path=HOME/'cluster238-setup.json'
    setup_record=json.loads(read_regular(setup_path,512*1024))
    required={'pidfd','shell','recorder'} | ({'codec','loopback'} if scenario in ('packets','negative') else set())
    if (setup_record.get('schema')!='cluster238-setup-v1' or setup_record.get('result')!='PASS'
            or setup_record.get('scenario')!=scenario or setup_record.get('guard')!=proof
            or not required.issubset(set(setup_record.get('controls',{})))):
        raise Incomplete('setup record or protected guard binding is missing')
    rec=Recorder(CASE/'cluster238-events.jsonl')
    result={'classification':'INCOMPLETE','reached':[],'checks':{},'reason':'behavior did not finish'}
    event_error=None
    try:
        rec.emit('case-begin',scenario=scenario,guard=proof,setup_controls=sorted(required))
        result={'stale':stale_case,'packets':packets_case,'negative':negative_case}[scenario](rec)
    except Exception as error:
        result={'classification':'INCOMPLETE','reached':[],'checks':{},
                'reason':(type(error).__name__+': '+str(error))[:640],
                'note':'inspect retained command and vector events for reached observations'}
    finally:
        try:
            rec.emit('case-outcome',scenario=scenario,classification=result['classification'],
                     reached=result.get('reached',[]),checks=result.get('checks',{}))
            rec.close()
        except Exception as error:
            event_error=(type(error).__name__+': '+str(error))[:640]
            result['classification']='INCOMPLETE';result['reason']='event retention failed: '+event_error
            try:
                if not rec.closed: os.close(rec.fd)
            except OSError:
                pass
    result.update(schema='cluster238-result-v1',scenario=scenario,guard=proof,event_count=rec.count,
                  event_bytes=rec.length,event_error=event_error,setup_passed=True)
    save_report('cluster238-result.json',result)
    print('cluster238 '+scenario+'='+result['classification'].lower(),flush=True)
    return {'PASS':0,'FAIL':1,'INCOMPLETE':125}[result['classification']]


def main():
    proof=guard()
    argv=sys.argv[1:]
    if len(argv)==2 and argv[0]=='setup':
        setup(argv[1],proof)
        return 0
    if len(argv)==3 and argv[0]=='case':
        if argv[2]!=str(CANDIDATE):
            raise Incomplete('case was not invoked for the exact candidate executable')
        return case(argv[1],proof)
    raise Incomplete('invalid fixture invocation')


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (Incomplete,OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        print('cluster238 infrastructure: '+type(error).__name__+': '+str(error),file=sys.stderr,flush=True)
        raise SystemExit(125)
