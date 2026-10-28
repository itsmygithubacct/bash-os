#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM client protocol mock for the published bashos-auth UAPI.

This is not the kernel authority. It creates one private memfd stand-in for
an exact /dev/bashos-auth open and mediates only ioctls on those stand-ins.
All modeled slots and tokens are synthetic and scoped to each stand-in. It
logs every relevant raw request, response and state transition under HOME.

PR_SET_DUMPABLE(0) from the client is acknowledged but not applied, solely so
this unprivileged parent can read/write its owned tracee's ioctl buffers. This
deviation is recorded; it cannot establish secrecy or kernel enforcement.
After a successful synthetic SU token consume, the next geteuid syscall in
that exact process is answered with synthetic 0 to reach its root-only client
branch. Real UID/EUID remain 2000; all credential-changing calls are denied.
The pinned system-sequence helper supplies the filter and child lifecycle.
"""
import base64
import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import struct
import sys
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
SEQUENCE=Path('/opt/bashos-parity/harness/helpers/auth-client-listener.py')
ADD_FD=0x40182103
DEVICE='/dev/bashos-auth'
VERSION=0x8020ba01; NEW=0xc008ba02; WRITE=0x4010ba03; SEAL=0x4008ba04
CLEAR=0x4008ba05; EXPORT=0xc010ba06; SAME=0xc010ba07; MINT=0xc078ba08; CONSUME=0x4078ba09; STATS=0x8080ba0a
TOKEN=bytes(range(128,160))


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd().is_relative_to(CASE)
    assert platform.machine()=='x86_64'


def readmem(pid,addr,n):
    if not 0<=n<=65536 or not addr:raise ValueError('memory read out of bounds')
    fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY|os.O_CLOEXEC)
    try:
        data=os.pread(fd,n,addr)
        if len(data)!=n:raise ValueError('short tracee memory read')
        return data
    finally:os.close(fd)


def writemem(pid,addr,data):
    if not addr or len(data)>65536:raise ValueError('memory write out of bounds')
    fd=os.open('/proc/%d/mem'%pid,os.O_RDWR|os.O_CLOEXEC)
    try:
        if os.pwrite(fd,data,addr)!=len(data):raise ValueError('short tracee memory write')
    finally:os.close(fd)


def pathmem(pid,addr):
    # Avoid crossing a page in one read, including for an unaligned NUL.
    fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY|os.O_CLOEXEC)
    try:
        result=bytearray()
        while len(result)<4096:
            pos=addr+len(result); n=min(256,4096-len(result),4096-(pos%4096))
            part=os.pread(fd,n,pos)
            if not part:raise ValueError('unreadable path')
            end=part.find(b'\0')
            if end>=0:return os.fsdecode(bytes(result)+part[:end])
            result.extend(part)
        raise ValueError('overlong path')
    finally:os.close(fd)


def main():
    guard()
    cfgpath=Path(sys.argv[1]).resolve(); assert cfgpath.is_relative_to(CASE)
    cfg=json.loads(cfgpath.read_text()); logpath=Path(cfg['trace']).resolve(); assert logpath.is_relative_to(HOME)
    spec=importlib.util.spec_from_file_location('local_auth_sequence',SEQUENCE)
    seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq)
    seq.BOOTSTRAP_LOG=Path(str(logpath)+'.bootstrap')
    devices={}; credential_ready=set(); count=0; events=0

    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,unused):
        nonlocal count,events
        status=None
        with logpath.open('w') as log:
            def emit(event):
                nonlocal events
                events+=1
                if events>256:raise RuntimeError('auth mock notification limit')
                event['sequence']=events
                log.write(json.dumps(event,sort_keys=True)+'\n');log.flush()
            try:
                while status is None:
                    done,wstatus=os.waitpid(child,os.WNOHANG)
                    if done:status=wstatus;break
                    ready,_,_=select.select([listener],[],[],.05)
                    if not ready:continue
                    req=bytearray(80)
                    try:fcntl.ioctl(listener,seq.NOTIF_RECV,req,True)
                    except OSError as e:
                        if e.errno in (errno.EINTR,errno.ENOENT):continue
                        raise
                    ident,pid,_flags,nr,_arch,_ip=struct.unpack_from('<QIIiIQ',req)
                    args=struct.unpack_from('<6Q',req,32)
                    raw=lib.seccomp_syscall_resolve_num_arch(0,nr)
                    name=ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                    response='continue'; value=0; event=None
                    if name in ('open','openat'):
                        index=0 if name=='open' else 1
                        try:path=pathmem(pid,args[index])
                        except (OSError,ValueError):path=None
                        if path==DEVICE:
                            flags=args[index+1]&0xffffffff
                            standin=os.memfd_create('terra-auth-%d'%(count+1),os.MFD_CLOEXEC)
                            try:
                                st=os.fstat(standin);key=(st.st_dev,st.st_ino)
                                add=bytearray(struct.pack('<QIIII',ident,0,standin,0,
                                                          os.O_CLOEXEC if flags&os.O_CLOEXEC else 0))
                                newfd=fcntl.ioctl(listener,ADD_FD,add,True)
                            finally:os.close(standin)
                            count+=1; devices[key]={'ordinal':count,'slots':{},'next':4097,'counters':[count*100+i for i in range(1,7)]}
                            response='value';value=newfd
                            event={'syscall':name,'pid':pid,'path':path,'flags':flags,'fd':newfd,
                                   'device':list(key),'ordinal':count,'reply':'value:%d'%newfd}
                    elif name=='prctl' and args[0]==4 and args[1]==0:
                        response='value';value=0
                        event={'syscall':'prctl','pid':pid,'args':list(args[:5]),
                               'reply':'value:0','deviation':'PR_SET_DUMPABLE(0) acknowledged, not applied'}
                    elif name=='geteuid' and pid in credential_ready and cfg.get('capture_credentials'):
                        credential_ready.remove(pid)
                        uid_line=next(line for line in Path('/proc/%d/status'%pid).read_text().splitlines() if line.startswith('Uid:'))
                        response='value';value=0
                        event={'syscall':'geteuid','pid':pid,'reply':'value:0','actual_uid_status':uid_line,
                               'deviation':'one synthetic euid 0 after SU consume; real credentials unchanged'}
                    elif name in ('setgroups','setresgid','setresuid','setgid','setuid','setregid','setreuid') and cfg.get('capture_credentials'):
                        response='errno';value=errno.EPERM
                        event={'syscall':name,'pid':pid,'args':list(args),'reply':'errno:%d'%errno.EPERM,
                               'deviation':'credential change prevented by the fixture'}
                    elif name=='ioctl':
                        fd=int(args[0]); request=args[1]&0xffffffff
                        try:st=os.stat('/proc/%d/fd/%d'%(pid,fd)); key=(st.st_dev,st.st_ino)
                        except OSError:key=None
                        if key in devices:
                            dev=devices[key]; size=(request>>16)&0x3fff;ptr=args[2]
                            event={'syscall':'ioctl','pid':pid,'fd':fd,'device':list(key),'ordinal':dev['ordinal'],
                                   'request':'0x%08x'%request,'size':size}
                            supported=(VERSION,STATS,NEW,WRITE,SEAL,CLEAR,EXPORT,SAME,MINT,CONSUME)
                            before=readmem(pid,ptr,size) if request in supported and size else b''
                            event['input_hex']=before.hex();out=bytearray(before)
                            response='value';value=0; err=0;transition=None
                            if request==VERSION:
                                out[:]=struct.pack('<IIQ16s',1,5,15,b'\0'*16)
                            elif request==STATS:
                                out[:]=struct.pack('<16Q',*(dev['counters']+[0]*10))
                            elif request==NEW:
                                ident0,flags=struct.unpack('<II',before)
                                if ident0 or flags:err=errno.EINVAL
                                else:
                                    hid=dev['next'];dev['next']+=1;dev['slots'][hid]={'value':b'','sealed':False,'exported':False}
                                    dev['counters'][0]+=1;out[:]=struct.pack('<II',hid,0);transition={'op':'new','handle':hid}
                            elif request in (WRITE,EXPORT):
                                hid,n,userptr=struct.unpack('<IIQ',before);slot=dev['slots'].get(hid)
                                if slot is None:err=errno.ENOENT
                                elif n>4096:err=errno.EINVAL
                                elif request==WRITE:
                                    if slot['sealed']:err=errno.EPERM
                                    else:
                                        data=readmem(pid,userptr,n) if n else b''
                                        if len(slot['value'])+len(data)>4096:err=errno.E2BIG
                                        else:
                                            slot['value']+=data
                                            transition={'op':'write','handle':hid,'data_base64':base64.b64encode(data).decode(),
                                                        'accumulated_length':len(slot['value'])}
                                elif not slot['sealed'] or slot['exported']:err=errno.EPERM
                                elif len(slot['value'])>n:err=errno.ERANGE
                                else:
                                    data=slot['value'];writemem(pid,userptr,data);out[:]=struct.pack('<IIQ',hid,len(data),userptr)
                                    slot['exported']=True;transition={'op':'export-once','handle':hid,'data_base64':base64.b64encode(data).decode()}
                            elif request in (SEAL,CLEAR):
                                hid,flags=struct.unpack('<II',before);slot=dev['slots'].get(hid)
                                if flags:err=errno.EINVAL
                                elif slot is None:err=errno.ENOENT
                                elif request==SEAL:
                                    slot['sealed']=True;transition={'op':'seal','handle':hid}
                                else:
                                    del dev['slots'][hid];dev['counters'][1]+=1;transition={'op':'clear','handle':hid}
                            elif request==SAME:
                                a,b,_result,flags=struct.unpack('<IIII',before);left=dev['slots'].get(a);right=dev['slots'].get(b)
                                if flags or left is None or right is None or not left['sealed'] or not right['sealed']:err=errno.EINVAL
                                else:
                                    same=int(left['value']==right['value']);out[:]=struct.pack('<IIII',a,b,same,0)
                                    transition={'op':'compare','handles':[a,b],'result':same}
                            elif request in (MINT,CONSUME):
                                uid,gid,purpose,expires=struct.unpack_from('<IIII',before,0)
                                user=before[48:112].split(b'\0',1)[0]
                                if purpose not in (1,2) or not user or any(before[112:120]):err=errno.EINVAL
                                elif request==MINT and any(before[16:48]):err=errno.EINVAL
                                elif request==MINT and cfg.get('mint_error'):err=errno.EACCES
                                elif request==MINT:
                                    out[16:48]=TOKEN;dev['counters'][3]+=1
                                    dev['token']={'uid':uid,'gid':gid,'purpose':purpose,'user':user,'bytes':TOKEN}
                                    transition={'op':'mint-synthetic','uid':uid,'gid':gid,'purpose':purpose,'expires':expires,'user_base64':base64.b64encode(user).decode()}
                                else:
                                    expected=dev.get('token')
                                    event['token_match']=(expected is not None and uid==expected['uid'] and gid==expected['gid'] and
                                                          purpose==expected['purpose'] and user==expected['user'] and before[16:48]==expected['bytes'])
                                    if not event['token_match']:err=errno.EPERM
                                    elif cfg.get('consume_error')=='expired':err=errno.ETIMEDOUT
                                    elif cfg.get('consume_error'):err=errno.EACCES
                                    else:
                                        dev.pop('token');dev['counters'][4]+=1
                                        if purpose==2 and cfg.get('capture_credentials'):credential_ready.add(pid)
                                        transition={'op':'consume-synthetic','uid':uid,'gid':gid,'purpose':purpose,'expires':expires,'user_base64':base64.b64encode(user).decode()}
                            else:err=errno.ENOTTY
                            if err:
                                response='errno';value=err;event['reply']='errno:%d'%err
                            else:
                                if out!=before:writemem(pid,ptr,bytes(out))
                                event['reply']='value:0';event['output_hex']=bytes(out).hex()
                                if transition:event['transition']=transition
                    if event:emit(event)
                    if response=='continue':reply=struct.pack('<QqiI',ident,0,0,seq.FLAG_CONTINUE)
                    elif response=='value':reply=struct.pack('<QqiI',ident,value,0,0)
                    else:reply=struct.pack('<QqiI',ident,0,-value,0)
                    try:fcntl.ioctl(listener,seq.NOTIF_SEND,reply)
                    except OSError as e:
                        if e.errno!=errno.ENOENT:raise
            finally:
                if status is None:
                    os.kill(child,signal.SIGKILL);status=os.waitpid(child,0)[1]
        return status
    seq.supervise=supervise
    rules=['--notify','open','--notify','openat','--notify','ioctl','--notify','prctl:0=4,1=0']
    if cfg.get('capture_credentials'):
        rules+=['--notify','geteuid']
        for name in ('setgroups','setresgid','setresuid','setgid','setuid','setregid','setreuid'):
            rules+=['--notify',name]
    sys.argv=[str(SEQUENCE)]+rules+['--']+sys.argv[2:]
    seq.main()


if __name__=='__main__':main()
