#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Runtime plumbing; coordinator guest execution only, never a host data test."""
import array
import ctypes as C
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import time
import executor_observer_contract_r2 as c

LIBC=C.CDLL(None,use_errno=True)
LIBC.mount.argtypes=[C.c_char_p,C.c_char_p,C.c_char_p,C.c_ulong,C.c_char_p]
LIBC.mount.restype=C.c_int
LIBC.renameat2.argtypes=[C.c_int,C.c_char_p,C.c_int,C.c_char_p,C.c_uint]
LIBC.renameat2.restype=C.c_int
NS_GET_USERNS,NS_GET_PARENT,NS_GET_NSTYPE=0xb701,0xb702,0xb703


def sha(raw): return hashlib.sha256(raw).hexdigest()


def raw(path, limit=8192, protected=False):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        c.require(stat.S_ISREG(st.st_mode),'regular input required')
        if protected:c.require(st.st_uid==st.st_gid==0 and not st.st_mode&0o022 and st.st_nlink==1,'unprotected input')
        parts=[];size=0
        while True:
            piece=os.read(fd,min(65536,limit+1-size))
            if not piece:break
            parts.append(piece);size+=len(piece);c.require(size<=limit,'input exceeds bound')
        return b''.join(parts)
    finally:os.close(fd)


def protected(path,pin,limit=2*1024*1024):
    data=raw(path,limit,True);c.require(sha(data)==pin,'protected input digest differs: '+str(path));return data


def digest(path):
    # Used only for fixed trusted executable paths and pidfd-pinned /proc/PID/exe.
    with open(path,'rb') as f:
        c.require(stat.S_ISREG(os.fstat(f.fileno()).st_mode),'ordinary executable required')
        return hashlib.file_digest(f,'sha256').hexdigest()


def write(path,data):
    encoded=(json.dumps(data,sort_keys=True)+'\n').encode()
    c.require(len(encoded)<=1024*1024,'receipt exceeds bound')
    path=Path(path)
    pending=path.with_name('.'+path.name+'.pending-'+os.urandom(16).hex())
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    try:
        try:
            while encoded:
                n=os.write(fd,encoded);c.require(n>0,'short receipt write');encoded=encoded[n:]
        finally:os.close(fd)
        # Existence is the readiness signal. Publish complete, closed bytes with
        # RENAME_NOREPLACE; retain both no-overwrite and st_nlink==1 admission.
        if LIBC.renameat2(-100,os.fsencode(pending),-100,os.fsencode(path),1):
            raise OSError(C.get_errno(),'atomic receipt publication')
    finally:pending.unlink(missing_ok=True)


def fs_type(fd):
    buf=C.create_string_buffer(256)
    if LIBC.fstatfs(fd,C.byref(buf)):raise OSError(C.get_errno(),'fstatfs')
    return C.c_long.from_buffer(buf).value


def nsfd(path,kind):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
    try:c.require(fs_type(fd)==c.NSFS and fcntl.ioctl(fd,NS_GET_NSTYPE)==kind,'wrong nsfs namespace type')
    except BaseException:os.close(fd);raise
    return fd


def ns_identity(fd,name):
    st=os.fstat(fd);return {'dev':st.st_dev,'ino':st.st_ino,'link':name+':['+str(st.st_ino)+']'}


def namespace(pid,name):
    fd=nsfd('/proc/'+str(pid)+'/ns/'+name,{'pid':c.PID,'mnt':c.MNT,'net':c.NET,'user':c.USER}[name])
    try:return ns_identity(fd,name)
    finally:os.close(fd)


def task(pid):
    root='/proc/'+str(pid)
    fields=raw(root+'/stat').decode().rsplit(') ',1)[1].split()
    status=dict(line.split(':',1) for line in raw(root+'/status',16384).decode().splitlines() if ':' in line)
    cg=raw(root+'/cgroup').decode().strip().splitlines();c.require(len(cg)==1 and cg[0].startswith('0::'),'unified cgroup required')
    return {'pid':pid,'ppid':int(fields[1]),'start':int(fields[19]),'state':fields[0],
            'nspid':[int(n) for n in status['NSpid'].split()],
            'uids':[int(n) for n in status['Uid'].split()],'gids':[int(n) for n in status['Gid'].split()],
            'argv':[x.decode() for x in raw(root+'/cmdline').split(b'\0') if x],
            'cgroup':cg[0][3:],'exe_sha256':digest(root+'/exe')}


def live(fd):return not select.select([fd],[],[],0)[0]


def pidfd_reaped(fd):
    # Linux 6.12.113 fs/pidfs.c: invisible live/zombie targets show PID 0;
    # PID -1 is emitted only once pid_has_task(PIDTYPE_PID) is false.
    c.require(os.readlink('/proc/self/fd/'+str(fd))=='anon_inode:[pidfd]','owned pidfd required')
    fields=dict(line.split(':',1) for line in raw('/proc/self/fdinfo/'+str(fd)).decode().splitlines() if ':' in line)
    return c.reaped_fdinfo(fields)


def receive(sock,expected_fds=0):
    rights=[]
    try:
        data,anc,flags,_=sock.recvmsg(c.FRAME_MAX,socket.CMSG_SPACE(16)+socket.CMSG_SPACE(12),socket.MSG_CMSG_CLOEXEC)
        creds=None
        # Collect all installed rights before any validation can raise, so an
        # unexpected earlier control message cannot leak later descriptors.
        for level,kind,body in anc:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                values=array.array('i');values.frombytes(body[:len(body)//4*4]);rights.extend(values)
        for level,kind,body in anc:
            c.require(level==socket.SOL_SOCKET,'foreign ancillary level')
            if kind==socket.SCM_RIGHTS:
                c.require(len(body)%4==0,'malformed rights')
            elif kind==socket.SCM_CREDENTIALS:
                c.require(creds is None and len(body)==12,'duplicate/malformed credentials');creds=list(struct.unpack('3i',body))
            else:raise RuntimeError('unexpected ancillary kind')
        c.require(not flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) and data and
                  (len(rights)<=4 if expected_fds is None else len(rights)==expected_fds),'truncated/closed/wrong-descriptor frame')
        return c.decode(data),rights,creds
    except BaseException:
        for fd in rights:os.close(fd)
        raise


def send(sock,data,fds=()):
    wire=json.dumps(data,sort_keys=True).encode();c.require(len(wire)<=c.FRAME_MAX,'oversized response')
    ancillary=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
    c.require(sock.sendmsg([wire],ancillary)==len(wire),'short control send')


def wait_child(pid,fd,seconds):
    if not select.select([fd],[],[],seconds)[0]:return None
    got,status=os.waitpid(pid,os.WNOHANG);c.require(got==pid,'owned child reaping incomplete');return status


def stop_child(pid,fd):
    forced=False
    if live(fd):
        try:signal.pidfd_send_signal(fd,signal.SIGTERM)
        except ProcessLookupError:pass
    status=wait_child(pid,fd,3)
    if status is None:
        forced=True
        if live(fd):
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        status=wait_child(pid,fd,2)
    return {'wait_status':status,'reaped':status is not None,'forced':forced,
            'meaning':'owned observer cleanup only; never proof that an executor aborted'}


CGROUP_PARENT = '/sys/fs/cgroup/system.slice'


def owned_cgroup_name(expected_path):
    prefix = CGROUP_PARENT + '/bashos-executor-observer-'
    suffix = '.service'
    c.require(type(expected_path) is str and expected_path.startswith(prefix) and expected_path.endswith(suffix),
              'registered cgroup path shape differs')
    token = expected_path[len(prefix):-len(suffix)]
    c.require(expected_path == '/sys/fs/cgroup' + c.cgroup(token), 'registered cgroup path differs')
    return c.unit(token)


def cgroup_parent(child_fd, expected_path, expected_parent):
    """Pin the original system.slice mount via a trusted live child FD.

    The evaluator overmounts /sys with a private sysfs. Relative lookup from
    this descriptor retains the original vfsmount carried by the SCM_RIGHTS FD.
    """
    name = owned_cgroup_name(expected_path)
    c.require(type(expected_parent) is dict and set(expected_parent) == {'dev', 'ino'} and
              all(type(expected_parent[key]) is int and expected_parent[key] > 0 for key in ('dev', 'ino')),
              'registered cgroup parent identity malformed')
    child = os.fstat(child_fd)
    c.require(fs_type(child_fd) == c.CGROUP2 and stat.S_ISDIR(child.st_mode) and
              os.readlink('/proc/self/fd/' + str(child_fd)) == expected_path,
              'trusted live cgroup FD differs')
    parent_fd = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=child_fd)
    try:
        parent = os.fstat(parent_fd)
        c.require(fs_type(parent_fd) == c.CGROUP2 and stat.S_ISDIR(parent.st_mode) and
                  (parent.st_dev, parent.st_ino) == (expected_parent['dev'], expected_parent['ino']) and
                  parent.st_dev == child.st_dev and
                  os.readlink('/proc/self/fd/' + str(parent_fd)) == CGROUP_PARENT and
                  not os.get_inheritable(parent_fd), 'pinned cgroup parent topology differs')
        found = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        c.require(stat.S_ISDIR(found.st_mode) and
                  (found.st_dev, found.st_ino) == (child.st_dev, child.st_ino),
                  'registered child not linked under pinned cgroup parent')
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def cgroup_empty(fd, expected_path, broker_pidfd, expected_identity, parent_fd, expected_parent):
    """Strict bounded observation through the original pinned cgroup mount.

    A private /sys overmount may hide the absolute path while the original
    cgroup remains live. Missing control files are never enough for PASS.
    """
    name = owned_cgroup_name(expected_path)
    c.require(type(expected_identity) in (tuple, list) and len(expected_identity) == 2 and
              all(type(value) is int and value > 0 for value in expected_identity),
              'registered child identity malformed')
    child = os.fstat(fd)
    parent = os.fstat(parent_fd)
    parent_link = os.readlink('/proc/self/fd/' + str(parent_fd))
    c.require(fs_type(fd) == c.CGROUP2 and stat.S_ISDIR(child.st_mode) and
              (child.st_dev, child.st_ino) == tuple(expected_identity) and
              fs_type(parent_fd) == c.CGROUP2 and stat.S_ISDIR(parent.st_mode) and
              (parent.st_dev, parent.st_ino) == (expected_parent['dev'], expected_parent['ino']) and
              parent.st_dev == child.st_dev and parent_link == CGROUP_PARENT and
              not os.get_inheritable(parent_fd), 'pinned cgroup parent/child identity differs')
    c.require(os.readlink('/proc/self/fd/' + str(broker_pidfd)) == 'anon_inode:[pidfd]',
              'owned broker pidfd required for cgroup observation')

    def lookup():
        try:
            value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        c.require(stat.S_ISDIR(value.st_mode) and
                  (value.st_dev, value.st_ino) == tuple(expected_identity),
                  'registered cgroup path rebound or wrong FD: '
                  'relative_dev_ino=' + repr((value.st_dev, value.st_ino)))
        return (value.st_dev, value.st_ino)

    first = lookup()
    first_link = os.readlink('/proc/self/fd/' + str(fd))
    values = {}; missing = []
    for field in ('cgroup.events', 'cgroup.procs'):
        try:
            child_file = os.open(field, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            missing.append(field)
            continue
        try:
            values[field] = os.read(child_file, 8193).decode()
            c.require(len(values[field]) <= 8192, 'cgroup observation bound')
        finally:
            os.close(child_file)
    reaped = pidfd_reaped(broker_pidfd)
    second = lookup()
    second_link = os.readlink('/proc/self/fd/' + str(fd))
    c.require(first_link in (expected_path, expected_path + ' (deleted)') and
              second_link in (expected_path, expected_path + ' (deleted)'),
              'registered cgroup FD/path mismatch: '
              'first=' + repr(first_link) + ' second=' + repr(second_link) +
              ' relative=' + repr((first, second)))
    try:
        absolute = os.stat(expected_path, follow_symlinks=False)
    except FileNotFoundError:
        absolute = None
    observed = {'fd_dev': child.st_dev, 'fd_ino': child.st_ino,
                'fd_nlink_observed': child.st_nlink, 'fd_link': second_link,
                'fd_link_first': first_link,
                'parent_dev': parent.st_dev, 'parent_ino': parent.st_ino,
                'parent_link': parent_link,
                'path_present': second is not None,
                'relative_lookup_first': first,
                'relative_lookup_second': second,
                'absolute_path_present': absolute is not None,
                'absolute_path_dev_ino': None if absolute is None else (absolute.st_dev, absolute.st_ino),
                'observer_mnt_ns': os.readlink('/proc/self/ns/mnt'),
                'broker_reaped': reaped, 'missing_control_files': missing}
    if first != second or first_link != second_link:
        return {**observed, 'empty': False, 'removed': False, 'observation': 'transition'}
    if second is None:
        c.require(second_link == expected_path + ' (deleted)',
                  'missing child under pinned parent still has a linked FD: '
                  'fd_link=' + repr(second_link) + ' observed_nlink=' + str(child.st_nlink))
        removed = True
    else:
        c.require(second_link == expected_path,
                  'registered child exists but pinned FD is deleted: ' + repr(second_link))
        removed = False
    if missing:
        # One absent control file or a still-linked directory is incomplete;
        # bounded caller polling will retain ERROR if it persists.
        complete_removal = removed and len(missing) == 2
        return {**observed, 'empty': complete_removal and reaped,
                'removed': removed, 'observation': 'removed' if complete_removal else 'transition'}
    events = values['cgroup.events'].splitlines()
    c.require(sum(line.startswith('populated ') for line in events) == 1 and
              any(line in ('populated 0', 'populated 1') for line in events),
              'cgroup populated field malformed')
    empty = not removed and 'populated 0' in events and not values['cgroup.procs'].strip() and reaped
    return {**observed, 'empty': empty, 'removed': removed,
            'events': values['cgroup.events'], 'procs': values['cgroup.procs'],
            'observation': 'control-files'}


def guest(reg,broker=False):
    c.require(os.getresuid()==os.getresgid()==(0,0,0),'actual guest root required')
    value=reg['token'];c.token(value)
    for name in ('/etc/bashos-parity-vm','/run/bashos-parity-vm-identity'):
        c.require(raw(name,128,True).decode().strip()==value,'protected VM identity differs')
    c.require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==value and
              Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU','actual QEMU guest identity differs')
    c.require(digest('/proc/self/exe')==reg['python_sha256'],'pinned Python image differs')
    c.require(os.uname().release==reg['kernel_release'],'registered native module kernel release differs')
    if broker:
        c.require(task(os.getpid())['cgroup']==c.cgroup(value),'broker systemd cgroup differs')
        for name in ('pid','mnt','net','user'):
            c.require(namespace('self',name)==reg['initial'][name],'broker not in initial guest namespace: '+name)
        c.require(namespace(1,'pid')==reg['initial']['pid'] and task(1)['argv'][0] in
                  ('/sbin/init','/lib/systemd/systemd','/usr/lib/systemd/systemd'), 'actual initial PID1/procfs required')
