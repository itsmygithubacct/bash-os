#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only policy-info peer with scoped, recorded synthetic root ownership metadata."""
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import stat
import struct
import sys
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
SEQUENCE=Path('/opt/bashos-parity/harness/helpers/auth-client-listener.py')
DEVICE='/dev/bashos-auth';ADD_FD=0x40182103;VERSION=0x8020ba01;POLICY=0xc200ba0c


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd().is_relative_to(CASE) and platform.machine()=='x86_64'


def mem(pid,addr,n,write=None):
    assert addr and 0<=n<=8192
    fd=os.open('/proc/%d/mem'%pid,(os.O_RDWR if write is not None else os.O_RDONLY)|os.O_CLOEXEC)
    try:
        if write is None:
            data=os.pread(fd,n,addr);assert len(data)==n;return data
        assert len(write)==n and os.pwrite(fd,write,addr)==n
    finally:os.close(fd)


def cstring(pid,addr):
    if not addr:return ''
    fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY|os.O_CLOEXEC)
    try:
        out=bytearray()
        while len(out)<4096:
            pos=addr+len(out);part=os.pread(fd,min(256,4096-len(out),4096-pos%4096),pos)
            if not part:raise ValueError('unreadable string')
            end=part.find(b'\0')
            if end>=0:return os.fsdecode(bytes(out)+part[:end])
            out.extend(part)
        raise ValueError('string too long')
    finally:os.close(fd)


def stat_bytes(st,uid):
    vals=[st.st_size,st.st_blksize,st.st_blocks,st.st_atime_ns//10**9,st.st_atime_ns%10**9,
          st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9,0,0,0]
    result=struct.pack('<QQQIIIiQ'+'q'*12,st.st_dev,st.st_ino,st.st_nlink,st.st_mode,uid,st.st_gid,0,st.st_rdev,*vals)
    assert len(result)==144
    return result


def main():
    guard();cfgfile=Path(sys.argv[1]).resolve();assert cfgfile.is_relative_to(CASE)
    cfg=json.loads(cfgfile.read_text());path=Path(cfg['policy']).resolve();assert path.is_relative_to(CASE) and path.is_file()
    st=path.stat();assert st.st_uid==2000 and stat.S_ISREG(st.st_mode) and not st.st_mode&0o022
    raw=path.read_bytes();assert len(raw)<=65536
    trace=Path(cfg['trace']).resolve();assert trace.is_relative_to(HOME)
    spec=importlib.util.spec_from_file_location('policy_sequence',SEQUENCE);seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq)
    seq.BOOTSTRAP_LOG=Path(str(trace)+'.bootstrap')
    devices={};generation=17;infos=0;events=0
    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,unused):
        nonlocal infos,events
        status=None
        with trace.open('w') as log:
            def emit(event):
                nonlocal events
                events+=1
                if events>128:raise RuntimeError('policy event limit')
                event['sequence']=events;log.write(json.dumps(event,sort_keys=True)+'\n');log.flush()
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
                    ident,pid,_flags,nr,_arch,_ip=struct.unpack_from('<QIIiIQ',req);args=struct.unpack_from('<6Q',req,32)
                    n=lib.seccomp_syscall_resolve_num_arch(0,nr);name=ctypes.cast(n,ctypes.c_char_p).value.decode() if n else str(n)
                    response='continue';value=0;event=None
                    if name in ('open','openat'):
                        index=0 if name=='open' else 1
                        try:p=cstring(pid,args[index])
                        except (OSError,ValueError):p=None
                        if p==DEVICE:
                            flags=args[index+1]&0xffffffff;fd=os.memfd_create('terra-policy',os.MFD_CLOEXEC)
                            try:
                                x=os.fstat(fd);key=(x.st_dev,x.st_ino)
                                add=bytearray(struct.pack('<QIIII',ident,0,fd,0,os.O_CLOEXEC if flags&os.O_CLOEXEC else 0))
                                newfd=fcntl.ioctl(listener,ADD_FD,add,True)
                            finally:os.close(fd)
                            devices[key]=True;response='value';value=newfd
                            event={'syscall':name,'pid':pid,'path':p,'fd':newfd,'flags':flags,'reply':'value:%d'%newfd}
                    elif name in ('fstat','newfstatat') and cfg.get('spoof_root'):
                        try:
                            fd=int(args[0]);ptr=args[1] if name=='fstat' else args[2]
                            empty=(name=='fstat' or (args[3]&0x1000 and cstring(pid,args[1])==''))
                            x=os.stat('/proc/%d/fd/%d'%(pid,fd)) if empty else None
                        except (OSError,ValueError):x=None
                        if x and (x.st_dev,x.st_ino)==(st.st_dev,st.st_ino):
                            output=stat_bytes(x,0);mem(pid,ptr,len(output),output);response='value';value=0
                            event={'syscall':name,'pid':pid,'fd':fd,'actual_uid':x.st_uid,'synthetic_uid':0,
                                   'actual_inode':x.st_ino,'output_hex':output.hex(),'reply':'value:0',
                                   'deviation':'private file remains uid 2000; only this fstat result reports uid 0'}
                    elif name=='prctl' and args[0]==4 and args[1]==0:
                        response='value';value=0;event={'syscall':'prctl','pid':pid,'reply':'value:0','deviation':'PR_SET_DUMPABLE(0) acknowledged, not applied'}
                    elif name=='ioctl':
                        fd=int(args[0]);request=args[1]&0xffffffff
                        try:x=os.stat('/proc/%d/fd/%d'%(pid,fd));key=(x.st_dev,x.st_ino)
                        except OSError:key=None
                        if key in devices:
                            size=(request>>16)&0x3fff;ptr=args[2];before=mem(pid,ptr,size) if size and size<=8192 else b''
                            out=bytearray(before);response='value';value=0;err=0;transition=None
                            event={'syscall':'ioctl','pid':pid,'fd':fd,'request':'0x%08x'%request,'input_hex':before.hex()}
                            if request==VERSION:out[:]=struct.pack('<IIQ16s',1,5,15,b'\0'*16)
                            elif request==POLICY:
                                if len(before)!=512 or struct.unpack_from('<I',before)[0]!=512:err=errno.EINVAL
                                else:
                                    infos+=1;out[:]=bytes(512);uid=2000 if cfg.get('unsafe_uid') else 0
                                    mode=st.st_mode|(0o020 if cfg.get('unsafe_mode') else 0)
                                    gen=generation+(1 if cfg.get('change_generation') and infos>1 else 0)
                                    struct.pack_into('<IIIII',out,0,512,0,mode,uid,st.st_gid)
                                    struct.pack_into('<QQqqII',out,24,st.st_ino,st.st_size,st.st_mtime_ns//10**9,st.st_ctime_ns//10**9,gen,0)
                                    digest=hashlib.sha256(raw).digest()
                                    if cfg.get('bad_digest'):digest=bytes([digest[0]^1])+digest[1:]
                                    out[64:96]=digest;out[96:128]=bytes.fromhex('22'*32)
                                    encoded=os.fsencode(path);assert len(encoded)<256;out[128:128+len(encoded)]=encoded
                                    transition={'op':'policy-info','index':infos,'generation':gen,'private_path':str(path),
                                                'actual_uid':st.st_uid,'advertised_uid':uid,'content_sha256':hashlib.sha256(raw).hexdigest()}
                            else:err=errno.ENOTTY
                            if err:response='errno';value=err;event['reply']='errno:%d'%err
                            else:
                                if out!=before:mem(pid,ptr,len(out),bytes(out))
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
                if status is None:os.kill(child,signal.SIGKILL);status=os.waitpid(child,0)[1]
        return status
    seq.supervise=supervise
    sys.argv=[str(SEQUENCE),'--notify','open','--notify','openat','--notify','ioctl','--notify','fstat','--notify','newfstatat',
              '--notify','prctl:0=4,1=0','--']+sys.argv[2:]
    seq.main()


if __name__=='__main__':main()
