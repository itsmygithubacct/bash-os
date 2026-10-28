#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM client protocol mock for the published bashos-auth UAPI.

This is not the kernel authority. It creates one private memfd stand-in for
an exact /dev/bashos-auth open and mediates only ioctls on those stand-ins.
All modeled slots and tokens are synthetic and scoped to each stand-in.
EXEC_VERIFY may return a synthetic success without starting any verifier;
this permits testing client reauthorization but does not prove authentication. It
logs every relevant raw request, response and state transition under HOME.

PR_SET_DUMPABLE(0) from the client is acknowledged but not applied, solely so
this unprivileged parent can read/write its owned tracee's ioctl buffers. This
deviation is recorded; it cannot establish secrecy or kernel enforcement.
The pinned system-sequence helper supplies the filter and child lifecycle.
"""
import base64
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
import struct
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
SEQUENCE=Path('/opt/bashos-parity/harness/helpers/auth-client-listener.py')
ADD_FD=0x40182103
DEVICE='/dev/bashos-auth'
VERSION=0x8020ba01; NEW=0xc008ba02; WRITE=0x4010ba03; SEAL=0x4008ba04
CLEAR=0x4008ba05; EXPORT=0xc010ba06; SAME=0xc010ba07; MINT=0xc078ba08; STATS=0x8080ba0a
TOKEN=bytes(range(128,160))
AUTHZ=0xc340ba0b; HANDOFF=0xc128ba0d; VERIFY=0xc0b0ba0f


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
    devices={}; count=0; events=0; plan_index=0

    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,unused):
        nonlocal count,events,plan_index
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
                    elif name=='ioctl':
                        fd=int(args[0]); request=args[1]&0xffffffff
                        try:st=os.stat('/proc/%d/fd/%d'%(pid,fd)); key=(st.st_dev,st.st_ino)
                        except OSError:key=None
                        if key in devices:
                            dev=devices[key]; size=(request>>16)&0x3fff;ptr=args[2]
                            event={'syscall':'ioctl','pid':pid,'fd':fd,'device':list(key),'ordinal':dev['ordinal'],
                                   'request':'0x%08x'%request,'size':size}
                            supported=(VERSION,STATS,NEW,WRITE,SEAL,CLEAR,EXPORT,SAME,MINT,AUTHZ,HANDOFF,VERIFY)
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
                                        data=readmem(pid,userptr,n) if n else b'';slot['value']=data
                                        transition={'op':'write','handle':hid,'data_base64':base64.b64encode(data).decode()}
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
                            elif request==MINT:
                                uid,gid,purpose,expires=struct.unpack_from('<IIII',before,0)
                                user=before[48:112].split(b'\0',1)[0]
                                if purpose!=1 or not user or any(before[16:48]) or any(before[112:120]):err=errno.EINVAL
                                else:
                                    out[16:48]=TOKEN;dev['counters'][3]+=1
                                    transition={'op':'mint-synthetic','uid':uid,'gid':gid,'purpose':purpose,'expires':expires,'user_base64':base64.b64encode(user).decode()}
                            elif request==AUTHZ:
                                fields=struct.unpack_from('<11I',before,4)
                                mode,flags,noninteractive,caller_uid,caller_gid,target_uid,target_gid,argc,envc,alen,elen=fields
                                aptr,eptr=struct.unpack_from('<QQ',before,48)
                                if alen>32768 or elen>32768:raise ValueError('authority blob bound exceeded')
                                argv=readmem(pid,aptr,alen) if alen else b''
                                env=readmem(pid,eptr,elen) if elen else b''
                                strings=[before[128:192].split(b'\0',1)[0],before[192:256].split(b'\0',1)[0],
                                         before[256:512].split(b'\0',1)[0]]
                                wire=b'bashos-privcmd-v'+struct.pack('<11I',*fields)
                                for s in strings:wire+=struct.pack('<I',len(s))+s
                                calculated=hashlib.sha256(wire+argv+env).digest()
                                argv_list=argv[:-1].split(b'\0') if argv and argv.endswith(b'\0') else []
                                env_list=env[:-1].split(b'\0') if env and env.endswith(b'\0') else []
                                wanted=cfg.get('steps',[])
                                plan=wanted[plan_index] if plan_index<len(wanted) else None
                                valid=(struct.unpack_from('<I',before,0)[0]==832 and before[96:128]==calculated and
                                       len(argv_list)==argc and len(env_list)==envc and plan is not None and
                                       mode==plan['mode'] and flags==plan.get('flags',0) and
                                       noninteractive==plan.get('noninteractive',0) and
                                       caller_uid==os.getuid() and caller_gid==os.getgid() and
                                       target_uid==plan['target_uid'] and target_gid==plan['target_gid'] and
                                       strings[0]==str(os.getuid()).encode() and
                                       strings[1]==plan['target_user'].encode() and strings[2]==os.getcwd().encode() and
                                       argv_list==[x.encode() for x in plan.get('argv',[])] and
                                       all(x.encode() in env_list for x in plan.get('env_contains',[])))
                                event.update(fields=list(fields),strings_base64=[base64.b64encode(x).decode() for x in strings],
                                             argv_base64=base64.b64encode(argv).decode(),env_base64=base64.b64encode(env).decode(),
                                             expected_digest=calculated.hex(),received_digest=before[96:128].hex(),valid=valid)
                                if not valid:err=errno.EPROTO
                                else:
                                    plan_index+=1;decision=plan['decision'];handle=plan.get('handle',0)
                                    struct.pack_into('<6I',out,512,decision,0,30,17,0,0)
                                    struct.pack_into('<Q',out,536,901)
                                    out[576:608]=bytes.fromhex('11'*32);out[608:640]=bytes.fromhex('22'*32)
                                    out[640:768]=b'fixture decision\0'.ljust(128,b'\0')
                                    struct.pack_into('<QQ',out,768,handle,9999 if handle else 0)
                                    if handle:dev['pending']={'handle':handle,'argv':argv,'digest':calculated.hex()}
                                    dev['last_auth']={'decision':decision,'fields':list(fields),'digest':calculated.hex()}
                                    transition={'op':'authz','decision':decision,'mode':mode,'plan_index':plan_index}
                            elif request==VERIFY:
                                q=struct.unpack_from('<12I',before,0);auth=dev.get('last_auth')
                                f=auth['fields'] if auth else []
                                valid=(len(before)==176 and auth is not None and auth['decision']==6 and
                                       q==(176,0,f[0],f[3],f[4],f[5],f[6],17,0,30,0,0) and
                                       before[48:80].hex()==auth['digest'] and before[80:112]==bytes.fromhex('22'*32) and
                                       not any(before[112:176]))
                                event.update(valid=valid,fields=list(q),request_digest=before[48:80].hex(),
                                             normalized_digest=before[80:112].hex(),
                                             deviation='synthetic reply only; no verifier process or credentials')
                                if not valid:err=errno.EPROTO
                                elif cfg.get('verify_error'):err=errno.EACCES
                                else:transition={'op':'verify-synthetic-ack','digest':auth['digest']}
                            elif request==HANDOFF:
                                size,mode,flags,argc=struct.unpack_from('<IIII',before,0)
                                handle=struct.unpack_from('<Q',before,32)[0]
                                aptr=struct.unpack_from('<Q',before,216)[0];alen=struct.unpack_from('<I',before,224)[0]
                                argv=readmem(pid,aptr,alen) if alen else b''
                                pending=dev.get('pending');allowed=cfg.get('allowed_argv',[])
                                valid=(size==296 and mode==1 and flags==0 and pending is not None and
                                       handle==pending['handle'] and argv==pending['argv'] and
                                       argv==b''.join(x.encode()+b'\0' for x in allowed) and
                                       argc==len(allowed) and len(allowed)>=2 and allowed[0]=='/usr/bin/python3' and
                                       Path(allowed[1]).resolve().is_relative_to(CASE))
                                event.update(handle=handle,argv_base64=base64.b64encode(argv).decode(),valid=valid)
                                if not valid:err=errno.EPERM
                                elif cfg.get('handoff_error'):err=errno.EIO
                                else:
                                    childrun=subprocess.run(allowed,cwd=CASE,env=dict(os.environ),stdin=subprocess.DEVNULL,
                                                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                                    if childrun.returncode<0:exitcode=128-childrun.returncode
                                    else:exitcode=childrun.returncode
                                    struct.pack_into('<II',out,228,exitcode,1)
                                    dev.pop('pending',None)
                                    transition={'op':'handoff-owned-child','exit_code':exitcode,
                                                'stdout_base64':base64.b64encode(childrun.stdout[:8192]).decode(),
                                                'stderr_base64':base64.b64encode(childrun.stderr[:8192]).decode()}
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
    sys.argv=[str(SEQUENCE),'--notify','open','--notify','openat','--notify','ioctl',
              '--notify','prctl:0=4,1=0','--']+sys.argv[2:]
    seq.main()


if __name__=='__main__':main()
