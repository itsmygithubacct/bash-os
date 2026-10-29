#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only clock254 gate; copied 224 identity/scratch logic."""
import base64
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
MARKER = Path('/etc/bashos-parity-vm')
ATTEST = Path('/run/bashos-parity-vm-identity')
NS_ATTEST = Path('/run/bashos-syslog-namespace-208.json')
PID1 = Path('/proc/1')

class Incomplete(Exception):
    """A control, attribution, timing or capture condition was not established."""

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


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('clock254 guard takes no arguments')
    guard()
