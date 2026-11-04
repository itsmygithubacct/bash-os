#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only, bounded ptrace observation; INCOMPLETE is never r8 credit.

Requires the existing protected clock254 guest/namespace guard and a separate
root-created observer attestation. The observer starts only its own exact
candidate child. It records destination attempts and hashes file paths, without
recording payloads, environment, private keys, or arbitrary process memory.
It does not yet establish complete descriptor or credential provenance.
"""
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import time

ROOT=Path('/opt/bashos-parity')
GUARD=ROOT/'harness/helpers/clock254_guard.py'
SELF=ROOT/'harness/helpers/acme-owned-observer-r1.py'
CONTROLS=ROOT/'harness/helpers/acme-observer-controls-r1.py'
CANDIDATE=ROOT/'candidate'
ATTEST=Path('/run/bashos-acme-observer-attestation.json')
GUARD_SHA256='6e40323524fac1bc4a0f4824b54190d0dc34989b02508fc972ae1b9c3c06e262'
TRACEME=0; PEEKDATA=2; SYSCALL=24; SETOPTIONS=0x4200; GETEVENTMSG=0x4201; GET_SYSCALL_INFO=0x420e
OPTIONS=1|2|4|8|16|0x00100000
WALL=0x40000000
AUDIT_ARCH_X86_64=0xc000003e
MAX_EVENTS=4096; MAX_TASKS=128; TIMEOUT=45.0
CALLS={2:'open',41:'socket',42:'connect',43:'accept',44:'sendto',46:'sendmsg',47:'recvmsg',49:'bind',50:'listen',53:'socketpair',56:'clone',57:'fork',58:'vfork',59:'execve',257:'openat',272:'unshare',288:'accept4',299:'recvmmsg',307:'sendmmsg',308:'setns',322:'execveat',425:'io_uring_setup',426:'io_uring_enter',427:'io_uring_register',435:'clone3',437:'openat2',438:'pidfd_getfd'}
SCRIPTS={'network-canary':': > /dev/tcp/127.0.0.1/5999',
         'credential-canary':'read -r x < /tmp/parity-home/acme-observer-canary',
         'cleanup-canary':'( sleep 3 ) & exit 0',
         'candidate':'acme issue --allow-http --http-listen 127.0.0.1:5812 --directory http://127.0.0.1:5810/directory -k 0000000000000000000000000000000000000000000000000000000000000001 --domain fixture.test --out issued'}
class Incomplete(Exception): pass
class Entry(ctypes.Structure): _fields_=[('nr',ctypes.c_uint64),('args',ctypes.c_uint64*6)]
class Exit(ctypes.Structure): _fields_=[('rval',ctypes.c_int64),('is_error',ctypes.c_uint8)]
class Data(ctypes.Union): _fields_=[('entry',Entry),('exit',Exit),('pad',ctypes.c_ubyte*64)]
class Info(ctypes.Structure): _fields_=[('op',ctypes.c_uint8),('pad',ctypes.c_uint8*3),('arch',ctypes.c_uint32),('ip',ctypes.c_uint64),('sp',ctypes.c_uint64),('data',Data)]

def need(value, why):
    if not value: raise Incomplete(why)

def protected(path,limit):
    parent=path.parent.stat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not stat.S_IMODE(parent.st_mode)&0o022,'unprotected parent')
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_gid==0 and a.st_nlink==1 and not stat.S_IMODE(a.st_mode)&0o022 and 0<a.st_size<=limit,'unprotected file')
        data=b''
        while len(data)<a.st_size:
            block=os.read(fd,min(65536,a.st_size-len(data)));need(bool(block),'short protected read');data+=block
        b=os.fstat(fd);need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns),'protected file changed')
        return data,a
    finally: os.close(fd)

def unique(pairs):
    obj={}
    for k,v in pairs:
        need(k not in obj,'duplicate attestation key');obj[k]=v
    return obj

def gate():
    need(sys.flags.isolated==1 and sys.flags.no_site==1,'isolated no-site Python required')
    raw,_=protected(GUARD,128*1024);need(hashlib.sha256(raw).hexdigest()==GUARD_SHA256,'guard pin mismatch')
    ns={'__name__':'clock254_guard','__file__':str(GUARD)};exec(compile(raw,str(GUARD),'exec'),ns);token=ns['guard']()
    raw,att_info=protected(ATTEST,8192);need(stat.S_IMODE(att_info.st_mode)==0o444,'attestation mode is not immutable to guest user');att=json.loads(raw.decode('ascii'),object_pairs_hook=unique)
    need(set(att)=={'schema','token','candidate_sha256','observer_sha256','controls_sha256','cgroup'},'attestation fields')
    need(att['schema']=='bashos-acme-observer-attestation-v1' and att['token']==token,'attestation identity')
    need(Path(__file__)==SELF,'observer not invoked from its protected path')
    own,_=protected(SELF,128*1024);controls,_=protected(CONTROLS,128*1024);binary,identity=protected(CANDIDATE,256*1024*1024)
    need(hashlib.sha256(own).hexdigest()==att['observer_sha256'] and hashlib.sha256(controls).hexdigest()==att['controls_sha256'] and hashlib.sha256(binary).hexdigest()==att['candidate_sha256'],'protected executable pin mismatch')
    cg=Path('/proc/self/cgroup').read_text('ascii').strip();need(cg==att['cgroup'] and cg.startswith('0::/') and cg!='0::/','private cgroup attestation missing')
    children=Path('/proc/self/task/%d/children'%os.getpid()).read_text('ascii').strip();need(not children,'supervisor already has children')
    return token,att,(identity.st_dev,identity.st_ino)

def ptrace(lib,op,pid,addr=0,data=0):
    need(pid>1,'unsafe ptrace PID');ctypes.set_errno(0);v=lib.ptrace(ctypes.c_ulong(op),ctypes.c_ulong(pid),ctypes.c_void_p(addr),ctypes.c_void_p(data));err=ctypes.get_errno()
    if v==-1 and err: raise OSError(err,os.strerror(err))
    return v

def peek(lib,pid,address,n):
    need(address>0 and 0<n<=256,'unsafe bounded memory read');out=bytearray()
    for off in range(0,n,ctypes.sizeof(ctypes.c_long)):
        word=ptrace(lib,PEEKDATA,pid,address+off,0);out.extend(int(word & ((1<<64)-1)).to_bytes(8,'little'))
    return bytes(out[:n])

def cstring(lib,pid,address):
    out=bytearray()
    for off in range(0,256,8):
        block=peek(lib,pid,address+off,8)
        if b'\0' in block: out.extend(block.split(b'\0',1)[0]);return bytes(out)
        out.extend(block)
    raise Incomplete('path exceeds bounded capture')

def sockaddr(lib,pid,address,n):
    need(2<=n<=128,'unsupported sockaddr size');raw=peek(lib,pid,address,n);family=int.from_bytes(raw[:2],'little')
    if family==socket.AF_INET:
        need(n>=16,'short IPv4 sockaddr');return {'family':'inet','host':str(ipaddress.IPv4Address(raw[4:8])),'port':int.from_bytes(raw[2:4],'big')}
    if family==socket.AF_INET6:
        need(n>=28,'short IPv6 sockaddr');return {'family':'inet6','host':str(ipaddress.IPv6Address(raw[8:24])),'port':int.from_bytes(raw[2:4],'big')}
    return {'family':'unsupported','number':family}

def verify_task(pid,att):
    need(pid>1,'unsafe task PID')
    for name in ('pid','net','mnt'):
        need(os.readlink('/proc/%d/ns/%s'%(pid,name))==os.readlink('/proc/self/ns/'+name),'task left attested namespace')
    need(Path('/proc/%d/cgroup'%pid).read_text('ascii').strip()==att['cgroup'],'task left attested cgroup')

def tmp_snapshot():
    result=[]
    for p in sorted(Path('/tmp').glob('bashos-acme-*')):
        need(len(result)<128,'too many ACME temp paths')
        s=p.lstat();result.append({'name':p.name,'dev':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid})
    return result

def observe(mode):
    need(mode in SCRIPTS,'unknown fixed scenario');token,att,identity=gate()
    temp_before=tmp_snapshot()
    lib=ctypes.CDLL(None,use_errno=True);lib.ptrace.restype=ctypes.c_long
    libc=lib;child=os.fork()
    if child==0:
        try:
            # TRACEME permits pid 0 only in this direct child; no other special PID is used.
            need(libc.ptrace(ctypes.c_ulong(TRACEME),ctypes.c_ulong(0),None,None)==0,'TRACEME failed')
            need(os.getpid()>1,'unsafe self PID')
            os.kill(os.getpid(),signal.SIGSTOP)
            fd=os.open('/dev/null',os.O_RDWR|os.O_CLOEXEC)
            for n in (0,1,2): os.dup2(fd,n)
            if fd>2:os.close(fd)
            inherited=os.listdir('/proc/self/fd');need(len(inherited)<=4096,'too many inherited descriptors')
            for text in inherited:
                if not text.isdigit() or int(text)<3:continue
                try:os.close(int(text))
                except OSError as exc:
                    if exc.errno!=errno.EBADF:raise
            os.execve(str(CANDIDATE),[str(CANDIDATE),'--noprofile','--norc','-c',SCRIPTS[mode]],{'PATH':'/usr/bin:/bin','HOME':'/tmp/parity-home','LANG':'C','LC_ALL':'C'})
        except BaseException: os._exit(125)
    need(child>1,'unsafe direct child PID');pidfd=None;done=False;root_reaped=False;root_exit_descendants=[];known={child};tasks={child:{'execs':0}};events=[];pending={};root_status=None;deadline=time.monotonic()+TIMEOUT
    try:
        pidfd=os.pidfd_open(child,0);signal.pidfd_send_signal(pidfd,0)
        while True:
            need(time.monotonic()<deadline,'initial stop timeout')
            p,st=os.waitpid(child,os.WUNTRACED|os.WNOHANG)
            if p:break
            time.sleep(0.001)
        if p==child and (os.WIFEXITED(st) or os.WIFSIGNALED(st)):root_reaped=True
        need(p==child and os.WIFSTOPPED(st) and os.WSTOPSIG(st)==signal.SIGSTOP,'missing initial stop')
        verify_task(child,att)
        ptrace(lib,SETOPTIONS,child,0,OPTIONS);ptrace(lib,SYSCALL,child)
        while known:
            need(time.monotonic()<deadline,'observation timeout')
            p=0;st=0
            for task in tuple(sorted(known)):
                need(task>1,'unsafe wait PID')
                try:p,st=os.waitpid(task,WALL|os.WNOHANG)
                except InterruptedError:continue
                if p:break
            if p==0:time.sleep(0.001);continue
            need(p>1 and p in known,'unexpected or unsafe traced PID')
            if os.WIFEXITED(st) or os.WIFSIGNALED(st):
                if p==child:
                    root_reaped=True
                    root_exit_descendants=sorted(known-{child})
                    root_status={'exit':os.WEXITSTATUS(st)} if os.WIFEXITED(st) else {'signal':os.WTERMSIG(st)}
                known.remove(p);pending.pop(p,None);continue
            need(os.WIFSTOPPED(st),'unexpected wait status');sig=os.WSTOPSIG(st);event=st>>16;deliver=0
            if sig==signal.SIGTRAP and event in (1,2,3):
                val=ctypes.c_ulong();ptrace(lib,GETEVENTMSG,p,0,ctypes.addressof(val));new=int(val.value)
                need(new>1 and new not in known and len(known)<MAX_TASKS,'unsafe or excessive descendant');verify_task(new,att);known.add(new);tasks[new]={'execs':0};events.append({'type':'descendant','parent':p,'pid':new,'event':event})
            elif sig==signal.SIGTRAP and event==4:
                tasks[p]['execs']+=1
                if p==child and tasks[p]['execs']==1:
                    exe=os.stat('/proc/%d/exe'%p);need((exe.st_dev,exe.st_ino)==identity,'candidate executable identity differs')
                else:events.append({'type':'additional-exec','pid':p})
            elif sig==(signal.SIGTRAP|0x80):
                info=Info();size=ptrace(lib,GET_SYSCALL_INFO,p,ctypes.sizeof(info),ctypes.addressof(info));need(size>=24 and info.arch==AUDIT_ARCH_X86_64,'syscall ABI unavailable')
                if info.op==1:
                    e=info.data.entry;name=CALLS.get(int(e.nr));pending.pop(p,None)
                    if name:
                        row={'type':'syscall','pid':p,'name':name};a=[int(x) for x in e.args]
                        if name in ('connect','bind'):row['address']=sockaddr(lib,p,a[1],a[2])
                        elif name=='sendto' and a[4]:row['address']=sockaddr(lib,p,a[4],a[5])
                        elif name in ('open','openat','openat2'):
                            path=cstring(lib,p,a[0] if name=='open' else a[1]);row['path_sha256']=hashlib.sha256(path).hexdigest()
                        elif name=='socket':row.update(domain=a[0],socket_type=a[1],protocol=a[2])
                        elif name in ('sendmsg','recvmsg','recvmmsg','sendmmsg','io_uring_setup','io_uring_enter','io_uring_register','pidfd_getfd','setns','unshare','clone3'):row['coverage']='unsupported'
                        events.append(row);pending[p]=row
                elif info.op==2:
                    row=pending.pop(p,None)
                    if row is not None:row['result']=int(info.data.exit.rval)
                else:raise Incomplete('unknown syscall stop')
            elif sig!=signal.SIGSTOP:deliver=sig
            need(len(events)<=MAX_EVENTS,'observation event cap exceeded');ptrace(lib,SYSCALL,p,0,deliver)
        done=True
        temp_after=tmp_snapshot()
        return {'schema':'bashos-acme-observer-r1','state':'INCOMPLETE','reason':'ptrace evidence does not yet prove fd provenance, complete credential isolation, or trusted external cleanup','vm_token':token,'mode':mode,'candidate_sha256':att['candidate_sha256'],'root_status':root_status,'root_exit_descendants':root_exit_descendants,'tasks':tasks,'events':events,'all_traced_tasks_exited':True,'temp_before':temp_before,'temp_after':temp_after,'qualification_pass':False}
    except BaseException as error:
        return {'schema':'bashos-acme-observer-r1','state':'INCOMPLETE','qualification_pass':False,'vm_token':token,'mode':mode,'candidate_sha256':att['candidate_sha256'],'error':type(error).__name__+': '+str(error),'root_status':root_status,'root_exit_descendants':root_exit_descendants,'tasks':tasks,'events':events,'all_traced_tasks_exited':False,'temp_before':temp_before}
    finally:
        if not done:
            # Only this positive, direct child, still unreaped by us, may be
            # signalled. A child PID cannot be reused while unreaped.
            try:
                if pidfd is not None:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                elif not root_reaped:os.kill(child,signal.SIGKILL)
            except ProcessLookupError:pass
            if not root_reaped:
                reap_deadline=time.monotonic()+2.0
                while time.monotonic()<reap_deadline:
                    try:
                        waited,status=os.waitpid(child,WALL|os.WNOHANG)
                    except (ChildProcessError,ProcessLookupError):break
                    except InterruptedError:continue
                    if waited==child and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):break
                    time.sleep(0.001)
        if pidfd is not None:os.close(pidfd)
        # PTRACE_O_EXITKILL applies to traced descendants when this observer exits;
        # independent coordinator teardown is still required.

def main():
    try:
        need(len(sys.argv)==2,'one fixed scenario required');report=observe(sys.argv[1])
    except BaseException as error:report={'schema':'bashos-acme-observer-r1','state':'INCOMPLETE','qualification_pass':False,'error':type(error).__name__+': '+str(error)}
    print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
    return 125
if __name__=='__main__':sys.exit(main())
