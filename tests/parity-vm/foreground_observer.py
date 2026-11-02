# SPDX-License-Identifier: MIT
"""Passive observations of a fixture-owned foreground job and its PTY owner."""
import os
import re
import select
import stat
import time


class ObservationError(RuntimeError):
    pass


def process_birth(pid):
    with open('/proc/%d/stat' % pid, 'rb') as stream:
        data = stream.read(8193)
    if len(data) > 8192 or b')' not in data:
        raise ObservationError('invalid leader stat')
    fields = data.rsplit(b')', 1)[1].split()
    return (int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))


def foreground_owned_witness(master, leader, leader_birth):
    """Retain a live group leader and its ancestry to this owned PTY leader."""
    group = os.tcgetpgrp(master)
    if group <= 0 or group == leader:
        raise ObservationError('foreground group is not an owned job')
    started = time.monotonic_ns()
    def snap(pid):
        with open('/proc/%d/stat' % pid, 'rb') as stream:
            data = stream.read(8193)
        if len(data) > 8192 or b')' not in data:
            raise ObservationError('invalid foreground member stat')
        f = data.rsplit(b')', 1)[1].split()
        return {'pid': pid, 'ppid': int(f[1]), 'pgrp': int(f[2]),
                'session': int(f[3]), 'starttime': int(f[19]),
                'state': f[0].decode('ascii'), 'uid': os.stat('/proc/%d' % pid).st_uid}
    fd = os.pidfd_open(group, 0)
    try:
        chain = []
        current = group
        for _ in range(16):
            row = snap(current)
            if row['state'] == 'Z' or row['uid'] != 2000 or row['session'] != leader:
                raise ObservationError('foreground ancestor not live, owned or in session')
            chain.append(row)
            if current == leader:
                break
            current = row['ppid']
        else:
            raise ObservationError('foreground ancestry did not reach leader')
        if (chain[0]['pid'] != group or chain[0]['pgrp'] != group or
                tuple(chain[-1][k] for k in ('ppid','pgrp','session','starttime')) != tuple(leader_birth) or
                any(any(now[k] != row[k] for k in ('pid','ppid','pgrp','session','starttime','uid')) for row in chain for now in (snap(row['pid']),)) or
                select.select([fd], [], [], 0)[0] or os.tcgetpgrp(master) != group):
            raise ObservationError('foreground identity changed during observation')
        return {'group': group, 'chain': chain, 'leader_birth': list(leader_birth),
                'sample_started_ns': started, 'sample_finished_ns': time.monotonic_ns()}
    finally:
        os.close(fd)


def passive_foreground_request(leader, leader_birth):
    """Bind the fixture's requested PID to its already pinned PTY owner."""
    path = '/tmp/parity-home/foreground-request.raw'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 2000 or before.st_nlink != 1
                or before.st_mode & 0o022 or not 1 <= before.st_size <= 32):
            raise ObservationError('unsafe foreground request record')
        data = os.read(fd, 33); after = os.fstat(fd)
        if (len(data) != before.st_size or
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) !=
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or
                re.fullmatch(rb'[1-9][0-9]*\n', data) is None or
                process_birth(leader) != tuple(leader_birth)):
            raise ObservationError('foreground request/leader identity changed')
        return int(data), {'dev':before.st_dev,'ino':before.st_ino,'uid':before.st_uid,
                           'mode':stat.S_IMODE(before.st_mode),'raw_hex':data.hex()}
    finally:
        os.close(fd)


def release_passive_foreground_gate():
    """One byte only to the fixture-owned FIFO after a recorded sample."""
    path = '/tmp/parity-home/foreground-proof-gate'
    before = os.lstat(path)
    if (not stat.S_ISFIFO(before.st_mode) or before.st_uid != 2000 or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600):
        raise ObservationError('unsafe foreground gate')
    fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        after = os.fstat(fd)
        if (not stat.S_ISFIFO(after.st_mode) or
                (before.st_dev,before.st_ino,before.st_uid,before.st_mode,before.st_nlink) !=
                (after.st_dev,after.st_ino,after.st_uid,after.st_mode,after.st_nlink)):
            raise ObservationError('foreground gate changed')
        if os.write(fd,b'G') != 1:
            raise ObservationError('foreground gate write incomplete')
        return {'dev':after.st_dev,'ino':after.st_ino,'uid':after.st_uid,
                'mode':stat.S_IMODE(after.st_mode),'bytes':1,'monotonic_ns':time.monotonic_ns()}
    finally:
        os.close(fd)
