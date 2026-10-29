#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only gate for terminal 213 fixtures; never a host discovery probe."""
import json
import os
import re
from pathlib import Path
import signal
import stat
import sys
import uuid

MARKER = Path('/etc/bashos-parity-vm')
ATTESTATION = Path('/run/bashos-parity-vm-identity')
NS_ATTEST = Path('/run/bashos-syslog-namespace-208.json')
CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')


def _read_bounded(path, limit):
    with open(path, 'rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('identity pseudo-file exceeds its bound')
    return data


def _read_protected(path):
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise ValueError('unprotected identity directory')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444
                or info.st_size != 37):
            raise ValueError('unprotected identity file')
        raw = os.read(fd, 38)
    finally:
        os.close(fd)
    if len(raw) != 37 or raw[-1:] != b'\n':
        raise ValueError('invalid identity bytes')
    value = raw[:-1].decode('ascii')
    if str(uuid.UUID(value)) != value:
        raise ValueError('noncanonical identity UUID')
    return value


class Incomplete(ValueError):
    pass


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


def _fd_mount_id(fd):
    """Read the mount identity of a directory we already opened ourselves."""
    raw = _read_bounded('/proc/self/fdinfo/%d' % fd, 4096).decode('ascii')
    rows = [line.split(':', 1)[1].strip() for line in raw.splitlines() if line.startswith('mnt_id:')]
    if len(rows) != 1 or not rows[0].isdigit() or int(rows[0]) <= 0:
        raise ValueError('open directory mount ID is unavailable or malformed')
    return int(rows[0])


def _check_scratch_mount():
    """Bind the active /tmp and owned scratch paths by fdinfo mount ID.

    Earlier /tmp mounts may remain below the fresh parity-scratch mount. Only
    the entry matching this open directory's mount ID describes the active one.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    tmpfd = os.open('/tmp', flags)
    try:
        tmpinfo = os.fstat(tmpfd)
        mount_id = _fd_mount_id(tmpfd)
        if (not stat.S_ISDIR(tmpinfo.st_mode) or tmpinfo.st_uid != 0 or tmpinfo.st_gid != 0
                or stat.S_IMODE(tmpinfo.st_mode) != 0o1777):
            raise ValueError('active scratch mount root metadata differs')
        text = _read_bounded('/proc/self/mountinfo', 131072).decode('utf-8')
        matches = []
        for line in text.splitlines():
            if ' - ' not in line:
                raise ValueError('malformed mountinfo row')
            left, right = line.split(' - ', 1)
            fields, fs = left.split(), right.split()
            if len(fields) < 6 or len(fs) < 3 or not fields[0].isdigit():
                raise ValueError('malformed mountinfo fields')
            if int(fields[0]) == mount_id:
                matches.append((fields, fs))
        if len(matches) != 1:
            raise ValueError('active scratch mount ID not uniquely present')
        fields, fs = matches[0]
        if (fields[3] != '/' or fields[4] != '/tmp' or fs[0] != 'tmpfs' or fs[1] != 'parity-scratch'
                or not {'nodev', 'nosuid'} <= set(fields[5].split(','))):
            raise ValueError('active scratch mount is not the expected private tmpfs')
        for path in (CASE, HOME):
            fd = os.open(path, flags)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 2000 or info.st_gid != 2000
                        or stat.S_IMODE(info.st_mode) & 0o022 or _fd_mount_id(fd) != mount_id):
                    raise ValueError('fixture scratch path ownership or active mount differs')
            finally:
                os.close(fd)
    finally:
        os.close(tmpfd)


def require_guest():
    """Check the 163 root attestation and 176 root evaluator before any fixture work."""
    try:
        if os.getresuid() != (2000, 2000, 2000) or os.getresgid() != (2000, 2000, 2000) or os.getgroups():
            raise ValueError('fixture credentials differ')
        marker = _read_protected(MARKER)
        if _read_protected(ATTESTATION) != marker:
            raise ValueError('root DMI attestation differs')
        data = _read_bounded('/proc/1/cmdline', 8192)
        argv = data.split(b'\0')
        if (argv.count(b'/opt/bashos-parity/harness/guest.py') != 1
                or argv.count(b'--vm-token') != 1
                or argv.index(b'--vm-token') + 1 >= len(argv)
                or argv[argv.index(b'--vm-token') + 1] != marker.encode('ascii')):
            raise ValueError('PID 1 is not the matching evaluator')
        status = _read_bounded('/proc/1/status', 16384).decode('ascii')
        uid_lines = [x.split() for x in status.splitlines() if x.startswith('Uid:')]
        if uid_lines != [['Uid:', '0', '0', '0', '0']]:
            raise ValueError('PID 1 is not root')
        protected_namespace(marker)
        if _read_bounded('/sys/class/dmi/id/sys_vendor', 256).strip() != b'QEMU':
            raise ValueError('QEMU vendor missing')
        if Path.cwd() != CASE or os.environ.get('HOME') != str(HOME):
            raise ValueError('fixture scratch differs')
        _check_scratch_mount()
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise ValueError('pidfd ownership primitives unavailable')
        return marker
    except (OSError, ValueError, UnicodeError, IndexError) as exc:
        raise SystemExit('terminal213 fixture guard refused: ' + str(exc)) from exc


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('terminal213 guard takes no arguments')
    require_guest()
