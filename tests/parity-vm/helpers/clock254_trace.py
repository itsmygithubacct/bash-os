#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only exact-callsite clock injection into one owned stock candidate.

No kernel clock, candidate file or process outside the direct traced child is
changed. Unsupported identity, ABI, ptrace, BPF, pointer or cleanup is incomplete.
"""
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import sys
import time

PROFILES = {'dynamic': {'elf_type': 3,
             'map_delta': 0,
             'read_call': 1457541,
             'read_call_hex': 'e8c6e6f6ff85c0783a488b4c2408488b',
             'read_errno': 1457613,
             'read_errno_hex': '8b38e8ecf3f6ff488d3d7af472004889',
             'sha256': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
             'since_call': 1458278,
             'since_call_hex': 'e8e5e3f6ff85c0785f488b542410488b',
             'since_errno': 1458387,
             'since_errno_hex': '41bc010000008b38e8e0f0f6ff488d3d'},
 'static': {'elf_type': 2,
            'map_delta': 4194304,
            'read_call': 4790725,
            'read_call_hex': 'e8268b830085c0783a488b4c2408488b',
            'read_errno': 4790797,
            'read_errno_hex': '8b38e8ac318000488d3d89609a004889',
            'sha256': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
            'since_call': 4791462,
            'since_call_hex': 'e84588830085c0785f488b542410488b',
            'since_errno': 4791571,
            'since_errno_hex': '41bc010000008b38e8a02e8000488d3d'}}
SPECS = {'boundary-large-epoch': {'clock_id': 0,
                          'cmd': 'now',
                          'kind': 'read',
                          'requirement': 'r3',
                          'sample': [4294967296, 999999999],
                          'status': 0,
                          'stderr_contains': '',
                          'stdout': '4294967296.999999999\n',
                          'topic': 'bashclock/clock_domain_reads'},
 'boundary-max-nanos': {'clock_id': 0,
                        'cmd': 'now',
                        'kind': 'read',
                        'requirement': 'r3',
                        'sample': [0, 999999999],
                        'status': 0,
                        'stderr_contains': '',
                        'stdout': '0.999999999\n',
                        'topic': 'bashclock/clock_domain_reads'},
 'boundary-negative-epoch': {'clock_id': 0,
                             'cmd': 'now',
                             'kind': 'read',
                             'requirement': 'r3',
                             'sample': [-1, 0],
                             'status': 0,
                             'stderr_contains': '',
                             'stdout': '-1.000000000\n',
                             'topic': 'bashclock/clock_domain_reads'},
 'boundary-zero': {'clock_id': 0,
                   'cmd': 'now',
                   'kind': 'read',
                   'requirement': 'r3',
                   'sample': [0, 0],
                   'status': 0,
                   'stderr_contains': '',
                   'stdout': '0.000000000\n',
                   'topic': 'bashclock/clock_domain_reads'},
 'domain-boottime': {'clock_id': 7,
                     'cmd': 'boot',
                     'kind': 'read',
                     'requirement': 'r1',
                     'sample': [67890, 333333333],
                     'status': 0,
                     'stderr_contains': '',
                     'stdout': '67890.333333333\n',
                     'topic': 'bashclock/clock_domain_reads'},
 'domain-monotonic': {'clock_id': 1,
                      'cmd': 'mono',
                      'kind': 'read',
                      'requirement': 'r1',
                      'sample': [12345, 222222222],
                      'status': 0,
                      'stderr_contains': '',
                      'stdout': '12345.222222222\n',
                      'topic': 'bashclock/clock_domain_reads'},
 'domain-realtime': {'clock_id': 0,
                     'cmd': 'now',
                     'kind': 'read',
                     'requirement': 'r1',
                     'sample': [1700000001, 111111111],
                     'status': 0,
                     'stderr_contains': '',
                     'stdout': '1700000001.111111111\n',
                     'topic': 'bashclock/clock_domain_reads'},
 'now-clock-error': {'clock_id': 0,
                     'cmd': 'now',
                     'errno': 5,
                     'kind': 'read',
                     'requirement': 'supporting-control',
                     'status': 1,
                     'stderr_contains': 'clock_gettime: Input/output error',
                     'stdout': '',
                     'topic': 'bashclock/clock_domain_reads'},
 'since-borrow': {'clock_id': 1,
                  'cmd': 'since 100.900000000',
                  'kind': 'since',
                  'requirement': 'r2',
                  'sample': [101, 100000001],
                  'status': 0,
                  'stderr_contains': '',
                  'stdout': '0.200000001\n',
                  'topic': 'bashclock/since_arithmetic'},
 'since-clock-error': {'clock_id': 1,
                       'cmd': 'since 100.500000000',
                       'errno': 5,
                       'kind': 'since',
                       'requirement': 'r5',
                       'status': 1,
                       'stderr_contains': 'clock_gettime: Input/output error',
                       'stdout': '',
                       'topic': 'bashclock/since_arithmetic'},
 'since-exact-zero': {'clock_id': 1,
                      'cmd': 'since 100.500000000',
                      'kind': 'since',
                      'requirement': 'r3',
                      'sample': [100, 500000000],
                      'status': 0,
                      'stderr_contains': '',
                      'stdout': '0.000000000\n',
                      'topic': 'bashclock/since_arithmetic'},
 'since-future-fraction': {'clock_id': 1,
                           'cmd': 'since 100.200000000',
                           'kind': 'since',
                           'requirement': 'r3',
                           'sample': [100, 100000000],
                           'status': 0,
                           'stderr_contains': '',
                           'stdout': '-0.100000000\n',
                           'topic': 'bashclock/since_arithmetic'},
 'since-future-integer': {'clock_id': 1,
                          'cmd': 'since 101.500000000',
                          'kind': 'since',
                          'requirement': 'r3',
                          'sample': [100, 500000000],
                          'status': 0,
                          'stderr_contains': '',
                          'stdout': '-1.000000000\n',
                          'topic': 'bashclock/since_arithmetic'}}
GUARD_SHA256 = '6e40323524fac1bc4a0f4824b54190d0dc34989b02508fc972ae1b9c3c06e262'

ROOT=Path('/opt/bashos-parity')
CANDIDATE=ROOT/'candidate'
GUARD=ROOT/'harness/helpers/clock254_guard.py'
HOME=Path('/tmp/parity-home')
CONTROL=HOME/'clock254-control.json'
RESULT=HOME/'clock254-result.json'
MAX_OUTPUT=65536
MAX_REPORT=262144
DEADLINE=12.0
PTRACE_TRACEME=0
PTRACE_PEEKTEXT=1
PTRACE_PEEKDATA=2
PTRACE_POKETEXT=4
PTRACE_POKEDATA=5
PTRACE_CONT=7
PTRACE_GETREGS=12
PTRACE_SETREGS=13
PTRACE_SETOPTIONS=0x4200
PTRACE_O_TRACEEXEC=0x10
PTRACE_O_EXITKILL=0x00100000
PTRACE_EVENT_EXEC=4
LIBC=None


class Incomplete(Exception):
    pass


class TraceIncomplete(Incomplete):
    def __init__(self, detail, evidence):
        super().__init__(detail)
        self.evidence=evidence


def initialize_libc():
    global LIBC
    LIBC=ctypes.CDLL(None,use_errno=True)
    LIBC.ptrace.restype=ctypes.c_long


def require(condition, detail):
    if not condition:
        raise Incomplete(detail)


def stable_read(path, limit, *, root_owned=False):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit,
                'unsafe or oversized protected file')
        if root_owned:
            require(before.st_uid==0 and before.st_gid==0 and not stat.S_IMODE(before.st_mode)&0o022,
                    'protected file is not root controlled')
        chunks=[];left=before.st_size
        while left:
            part=os.read(fd,min(left,1024*1024));require(bool(part),'short protected read')
            chunks.append(part);left-=len(part)
        after=os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_nlink)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_nlink),
                'protected file changed during read')
        return b''.join(chunks),before
    finally:
        os.close(fd)


def guest_gate():
    raw,_=stable_read(GUARD,128*1024,root_owned=True)
    require(hashlib.sha256(raw).hexdigest()==GUARD_SHA256,'guest guard source pin differs')
    module={'__name__':'clock254_guard','__file__':str(GUARD)}
    exec(compile(raw,str(GUARD),'exec'),module)
    return module['guard']()


def write_report(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
    require(len(raw)<MAX_REPORT,'report exceeds bound')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:
            n=os.write(fd,view);require(n>0,'report short write');view=view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def read_control():
    raw,st=stable_read(CONTROL,MAX_REPORT)
    require(st.st_uid==2000 and st.st_gid==2000 and stat.S_IMODE(st.st_mode)==0o600,
            'control record ownership differs')
    value=json.loads(raw)
    require(isinstance(value,dict) and value.get('schema')=='bashos-clock254-control-v1'
            and value.get('classification')=='CONTROL_PASS','required independent ptrace control missing')
    return value,hashlib.sha256(raw).hexdigest()


def candidate_profile():
    data,st=stable_read(CANDIDATE,32*1024*1024,root_owned=True)
    require(st.st_mode & 0o111 and not st.st_mode & (stat.S_ISUID|stat.S_ISGID),
            'candidate executable mode is unsafe')
    digest=hashlib.sha256(data).hexdigest()
    names=[n for n,p in PROFILES.items() if p['sha256']==digest]
    require(len(names)==1,'candidate digest is not a fixed core binary')
    return names[0],PROFILES[names[0]],{'dev':st.st_dev,'ino':st.st_ino,'sha256':digest,'bytes':len(data)}


def ptrace(op,pid,addr=0,value=0):
    ctypes.set_errno(0)
    result=LIBC.ptrace(ctypes.c_ulong(op),ctypes.c_ulong(pid),ctypes.c_void_p(addr),ctypes.c_void_p(value))
    e=ctypes.get_errno()
    if result==-1 and e:
        raise OSError(e,os.strerror(e))
    return int(result)


class Registers(ctypes.Structure):
    _fields_=[(x,ctypes.c_ulonglong) for x in ('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8',
        'rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]


def regs(pid):
    value=Registers();ptrace(PTRACE_GETREGS,pid,0,ctypes.addressof(value));return value


def set_regs(pid,value):
    ptrace(PTRACE_SETREGS,pid,0,ctypes.addressof(value))


def selected_regs(value):
    return {name:int(getattr(value,name)) for name in ('rip','rsp','rdi','rsi','rax')}


def peek_word(pid,address,op=PTRACE_PEEKDATA):
    return (ptrace(op,pid,address,0)&0xffffffffffffffff).to_bytes(8,'little')


def read_mem(pid,address,length,op=PTRACE_PEEKDATA):
    require(type(address) is int and address>0 and 0<=length<=256,'invalid traced read')
    first=address&~7;last=(address+length+7)&~7
    raw=b''.join(peek_word(pid,x,op) for x in range(first,last,8))
    return raw[address-first:address-first+length]


def write_mem(pid,address,data,*,text=False):
    require(isinstance(data,bytes) and 0<len(data)<=32,'invalid traced write')
    first=address&~7;last=(address+len(data)+7)&~7
    current=bytearray(b''.join(peek_word(pid,x,PTRACE_PEEKTEXT if text else PTRACE_PEEKDATA)
                               for x in range(first,last,8)))
    current[address-first:address-first+len(data)]=data
    for i in range(0,len(current),8):
        value=int.from_bytes(current[i:i+8],'little')
        ptrace(PTRACE_POKETEXT if text else PTRACE_POKEDATA,pid,first+i,value)
    require(read_mem(pid,address,len(data),PTRACE_PEEKTEXT if text else PTRACE_PEEKDATA)==data,
            'traced write readback differs')


class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]


class FilterProgram(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]


def install_child_filter():
    # Fixed x86-64 BPF applies only to this future tracee. The first exec is
    # allowed; a second exec is stopped by PTRACE_O_TRACEEXEC before user code.
    deny=(56,57,58,435,227,305,403,405,164,159,272,308,101,311)
    program=[Filter(0x20,0,0,4),Filter(0x15,1,0,0xc000003e),Filter(0x06,0,0,0x80000000),
             Filter(0x20,0,0,0),Filter(0x45,0,1,0x40000000),Filter(0x06,0,0,0x80000000)]
    for number in deny:
        program.extend((Filter(0x15,0,1,number),Filter(0x06,0,0,0x00050000|errno.EPERM)))
    program.append(Filter(0x06,0,0,0x7fff0000))
    array=(Filter*len(program))(*program);descriptor=FilterProgram(len(program),array)
    if LIBC.prctl(38,1,0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'PR_SET_NO_NEW_PRIVS')
    if LIBC.prctl(22,2,ctypes.byref(descriptor),0,0)!=0:
        raise OSError(ctypes.get_errno(),'PR_SET_SECCOMP')


def proc_status(pid):
    with open('/proc/%d/status'%pid,'rb') as f:raw=f.read(32769)
    require(len(raw)<=32768,'tracee status exceeds bound')
    fields={}
    for row in raw.decode('ascii').splitlines():
        if ':' in row:
            key,value=row.split(':',1)
            if key in ('Pid','Tgid','Uid','Gid','PPid','TracerPid','NoNewPrivs','Seccomp','Seccomp_filters'):
                require(key not in fields,'duplicate tracee status field');fields[key]=value.split()
    require(fields.get('Pid')==[str(pid)] and fields.get('Tgid')==[str(pid)]
            and fields.get('Uid')==['2000']*4 and fields.get('Gid')==['2000']*4
            and fields.get('PPid')==[str(os.getpid())] and fields.get('TracerPid')==[str(os.getpid())],
            'tracee credentials or direct ownership differ')
    return fields,raw.hex()


def proc_birth(pid):
    with open('/proc/%d/stat'%pid,'rb') as f:raw=f.read(8193)
    require(len(raw)<=8192 and raw.split(b' ',1)[0]==str(pid).encode() and b') ' in raw,
            'tracee birth record is unavailable')
    tail=raw.rsplit(b') ',1)[1].split()
    require(len(tail)>19 and int(tail[1])==os.getpid(),'tracee parent or birth record differs')
    return {'pid':pid,'ppid':int(tail[1]),'starttime':int(tail[19]),'stat_hex':raw.hex()}


def mappings(pid):
    with open('/proc/%d/maps'%pid,'rb') as f:raw=f.read(32769)
    require(len(raw)<=32768,'tracee map exceeds bound')
    rows=[]
    for line in raw.decode('ascii').splitlines():
        parts=line.split(None,5);require(len(parts)>=5,'malformed tracee map')
        a,b=parts[0].split('-',1);maj,minor=parts[3].split(':',1)
        rows.append({'start':int(a,16),'end':int(b,16),'perms':parts[1],'offset':int(parts[2],16),
                     'dev':os.makedev(int(maj,16),int(minor,16)),'ino':int(parts[4]),
                     'path':parts[5] if len(parts)>5 else ''})
    return rows,raw.hex()


def code_mapping(pid,profile,identity):
    rows,raw=mappings(pid)
    code=[x for x in rows if x['dev']==identity['dev'] and x['ino']==identity['ino']
          and x['perms']=='r-xp']
    require(len(code)==1,'candidate executable mapping is not unique')
    bias=code[0]['start']-code[0]['offset']-profile['map_delta']
    require(bias==0 if profile['elf_type']==2 else bias>0,'candidate load bias differs')
    for name in ('read_call','read_errno','since_call','since_errno'):
        address=bias+profile[name]
        require(code[0]['start']<=address and address+16<=code[0]['end'], 'fixed call site outside candidate mapping')
    return bias,code[0],raw


def writable_mapping(pid,address,size,*,stack=False):
    rows,raw=mappings(pid)
    matches=[x for x in rows if x['perms'].startswith('rw') and x['perms'].endswith('p')
             and x['start']<=address and address+size<=x['end']]
    require(len(matches)==1 and (not stack or matches[0]['path']=='[stack]'),
            'traced output pointer is not in an owned writable mapping')
    return matches[0],raw


def arm(pid,address,expected_hex):
    before=read_mem(pid,address,16,PTRACE_PEEKTEXT)
    require(before.hex()==expected_hex,'fixed call-site bytes differ from pinned binary')
    write_mem(pid,address,b'\xcc',text=True)
    hit=read_mem(pid,address,16,PTRACE_PEEKTEXT)
    require(hit==b'\xcc'+before[1:],'breakpoint write differs')
    return {'address':address,'before_hex':before.hex(),'armed_hex':hit.hex()}


def disarm(pid,record):
    address=record['address'];before=bytes.fromhex(record['before_hex'])
    write_mem(pid,address,before[:1],text=True)
    restored=read_mem(pid,address,16,PTRACE_PEEKTEXT)
    require(restored==before,'breakpoint restoration differs')
    record['restored_hex']=restored.hex()


def wait_event(pid,deadline,streams,output):
    while time.monotonic()<deadline:
        for fd in list(streams):
            try:part=os.read(fd,8192)
            except BlockingIOError:continue
            if not part:
                os.close(fd);streams.pop(fd);continue
            key=streams[fd]
            require(len(output[key])+len(part)<MAX_OUTPUT,'candidate capture cap reached')
            output[key].extend(part)
        got,status=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
        if got==pid:return status
        time.sleep(.002)
    raise Incomplete('owned tracee deadline')


def trace(command,kind,*,sample=None,error_number=None,control=False):
    name,profile,identity=candidate_profile()
    require(kind in ('read','since'),'unknown callsite class')
    out_r,out_w=os.pipe2(os.O_CLOEXEC);err_r,err_w=os.pipe2(os.O_CLOEXEC)
    child=os.fork()
    if child==0:
        try:
            os.close(out_r);os.close(err_r);os.dup2(out_w,1);os.dup2(err_w,2)
            os.close(out_w);os.close(err_w)
            null=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC);os.dup2(null,0);os.close(null)
            ptrace(PTRACE_TRACEME,0);os.kill(os.getpid(),signal.SIGSTOP)
            install_child_filter()
            env={'PATH':'/usr/bin:/bin','HOME':str(HOME),'LC_ALL':'C','LANG':'C'}
            os.execve(str(CANDIDATE),[str(CANDIDATE),'--noprofile','--norc','-c',command],env)
        except BaseException as exc:
            os.write(2,('clock254 child setup: '+type(exc).__name__+': '+str(exc)+'\n').encode())
            os._exit(125)
    os.close(out_w);os.close(err_w)
    os.set_blocking(out_r,False);os.set_blocking(err_r,False)
    streams={out_r:'stdout',err_r:'stderr'};output={'stdout':bytearray(),'stderr':bytearray()}
    deadline=time.monotonic()+DEADLINE;pidfd=None;exited=False;result=None
    doc={'schema':'bashos-clock254-trace-v1','profile':name,'candidate':identity,'kind':kind,'control':control,
         'tracee_pid':child,'parent_pid':os.getpid(),
         'command':command,'events':[],'clock_set_calls_allowed':False,'fork_calls_allowed':False}
    def observed_wait(stage):
        value=wait_event(child,deadline,streams,output)
        doc['events'].append({'stage':stage,'raw_wait_status':value})
        return value
    try:
        pidfd=os.pidfd_open(child,0)
        signal.pidfd_send_signal(pidfd,0)
        doc['pidfd_verified']=True
        st=observed_wait('initial-stop')
        require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==signal.SIGSTOP,'tracee initial stop missing')
        before,before_raw=proc_status(child);birth=proc_birth(child)
        doc['status_before_filter']=before;doc['status_before_raw_hex']=before_raw;doc['birth_before_exec']=birth
        ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL)
        ptrace(PTRACE_CONT,child)
        st=observed_wait('candidate-exec')
        require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==signal.SIGTRAP and st>>16==PTRACE_EVENT_EXEC,
                'candidate exec trace stop missing')
        after,after_raw=proc_status(child);after_birth=proc_birth(child)
        doc['status_after_filter']=after;doc['status_after_raw_hex']=after_raw;doc['birth_after_exec']=after_birth
        require((birth['pid'],birth['ppid'],birth['starttime'])==
                (after_birth['pid'],after_birth['ppid'],after_birth['starttime']), 'tracee birth changed across exec')
        require(after.get('NoNewPrivs')==['1'] and after.get('Seccomp')==['2']
                and len(before.get('Seccomp_filters',[]))==len(after.get('Seccomp_filters',[]))==1
                and int(after['Seccomp_filters'][0])>int(before['Seccomp_filters'][0]),
                'targeted tracee guard filter not established')
        exe=os.stat('/proc/%d/exe'%child)
        require((exe.st_dev,exe.st_ino)==(identity['dev'],identity['ino']),'tracee executable identity differs')
        bias,code,raw_maps=code_mapping(child,profile,identity)
        doc.update(exec_event=True,load_bias=bias,code_mapping=code,code_mapping_raw_hex=raw_maps)
        if control:
            sites={}
            for key in ('read_call','read_errno','since_call','since_errno'):
                site=arm(child,bias+profile[key],profile[key+'_hex']);disarm(child,site);sites[key]=site
            doc['control_sites']=sites
            ptrace(PTRACE_CONT,child)
        else:
            call_key=kind+'_call';error_key=kind+'_errno'
            call=arm(child,bias+profile[call_key],profile[call_key+'_hex']);doc['call_site']=call
            errsite=None
            if error_number is not None:
                errsite=arm(child,bias+profile[error_key],profile[error_key+'_hex']);doc['errno_site']=errsite
            ptrace(PTRACE_CONT,child)
            st=observed_wait('clock-call-trap')
            require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==signal.SIGTRAP and st>>16==0,'candidate callsite was not reached')
            before_regs=regs(child)
            require(before_regs.rip==call['address']+1,'trap was not at the selected candidate call')
            request=int(before_regs.rdi & 0xffffffff)
            doc['request_clock_id']=request;doc['regs_before']=selected_regs(before_regs)
            disarm(child,call)
            if error_number is None:
                pointer=int(before_regs.rsi)
                require(pointer%8==0,'timespec pointer alignment differs')
                mapped,raw_maps=writable_mapping(child,pointer,16,stack=True)
                original=read_mem(child,pointer,16);value=struct.pack('<qq',int(sample[0]),int(sample[1]))
                write_mem(child,pointer,value)
                doc['timespec_write']={'address':pointer,'mapping':mapped,'mapping_raw_hex':raw_maps,'before_hex':original.hex(),
                                       'after_hex':read_mem(child,pointer,16).hex()}
                before_regs.rax=0
            else:
                before_regs.rax=0xffffffffffffffff
            before_regs.rip=call['address']+5
            set_regs(child,before_regs);after_regs=regs(child);doc['regs_after']=selected_regs(after_regs)
            require(after_regs.rip==call['address']+5 and after_regs.rax==(0 if error_number is None else 0xffffffffffffffff),
                    'synthetic return registers do not match')
            ptrace(PTRACE_CONT,child)
            if error_number is not None:
                st=observed_wait('errno-location-trap')
                require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==signal.SIGTRAP and st>>16==0,'errno pointer breakpoint was not reached')
                er=regs(child);require(er.rip==errsite['address']+1,'errno trap differs')
                address=int(er.rax);mapped,raw_maps=writable_mapping(child,address,4)
                original=read_mem(child,address,4);value=struct.pack('<i',int(error_number))
                write_mem(child,address,value)
                doc['errno_write']={'address':address,'mapping':mapped,'mapping_raw_hex':raw_maps,'before_hex':original.hex(),
                                    'after_hex':read_mem(child,address,4).hex(),'errno':int(error_number),
                                    'regs_before':selected_regs(er)}
                disarm(child,errsite);er.rip=errsite['address'];set_regs(child,er)
                doc['errno_write']['regs_after']=selected_regs(regs(child))
                ptrace(PTRACE_CONT,child)
        st=observed_wait('normal-exit')
        require(os.WIFEXITED(st),'tracee did not exit normally or produced an unexpected stop')
        exited=True;result=os.WEXITSTATUS(st)
        while streams and time.monotonic()<deadline:
            for fd in list(streams):
                try:part=os.read(fd,8192)
                except BlockingIOError:continue
                if not part:os.close(fd);streams.pop(fd);continue
                key=streams[fd];require(len(output[key])+len(part)<MAX_OUTPUT,'candidate capture cap reached');output[key].extend(part)
            if streams:time.sleep(.002)
        require(not streams,'candidate output pipes did not close')
        after_name,_,after_identity=candidate_profile()
        require(name==after_name and identity==after_identity,'stock candidate bytes or inode changed')
        doc.update(exit_status=result,stdout_base64=base64.b64encode(output['stdout']).decode(),
                   stderr_base64=base64.b64encode(output['stderr']).decode(),candidate_unchanged=True,
                   cleanup={'direct_child_reaped':True,'identity_bound_pidfd':True,'events':[]})
        return doc
    except (Incomplete,OSError,ValueError,TypeError,KeyError,ChildProcessError) as exc:
        doc['trace_error']=type(exc).__name__+': '+str(exc)
        doc['partial_stdout_base64']=base64.b64encode(output['stdout']).decode()
        doc['partial_stderr_base64']=base64.b64encode(output['stderr']).decode()
        raise TraceIncomplete(doc['trace_error'],doc) from exc
    finally:
        if not exited:
            if pidfd is None:
                raise SystemExit('clock254 direct child has no pidfd; enclosing unit cleanup required')
            try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
            except ProcessLookupError:pass
            end=time.monotonic()+2
            reaped=False
            while time.monotonic()<end:
                try:got,status=os.waitpid(child,os.WNOHANG|os.WUNTRACED)
                except ChildProcessError:
                    reaped=True;break
                if got==child and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    reaped=True;break
                time.sleep(.002)
            doc['incomplete_cleanup']={'pidfd_signal':'SIGKILL','direct_child_reaped':reaped}
            if not reaped:
                raise SystemExit('clock254 tracee cleanup uncertain; enclosing unit cleanup required')
        if pidfd is not None:os.close(pidfd)
        for fd in list(streams):
            try:os.close(fd)
            except OSError:pass


def control():
    token=guest_gate();initialize_libc()
    witness=None
    try:
        witness=trace('exit 0','read',control=True)
        require(witness['exit_status']==0 and witness['stdout_base64']=='' and witness['stderr_base64']=='',
                'non-product ptrace control did not exit cleanly')
    except (Incomplete,OSError,ValueError,TypeError,KeyError) as exc:
        partial=exc.evidence if isinstance(exc,TraceIncomplete) else witness
        write_report(CONTROL,{'schema':'bashos-clock254-control-v1','classification':'INCOMPLETE',
                              'token':token,'trace':partial,'error':type(exc).__name__+': '+str(exc)})
        raise
    write_report(CONTROL,{'schema':'bashos-clock254-control-v1','classification':'CONTROL_PASS',
                          'token':token,'trace':witness})
    print('clock254 control=pass',flush=True)


def case(name):
    token=guest_gate();initialize_libc();require(name in SPECS,'unknown frozen clock case')
    saved,control_sha=read_control();build,_,identity=candidate_profile()
    require(saved['token']==token and saved['trace']['profile']==build and saved['trace']['candidate']==identity,
            'control is not bound to this candidate and guest')
    spec=SPECS[name]
    report={'schema':'bashos-clock254-result-v1','case':name,'token':token,'classification':'INCOMPLETE',
            'control_sha256':control_sha,'expected_clock_id':spec['clock_id']}
    try:
        doc=trace('bashclock '+spec['cmd'],spec['kind'],sample=spec.get('sample'),error_number=spec.get('errno'))
        report['trace']=doc
        stdout=base64.b64decode(doc['stdout_base64'],validate=True)
        stderr=base64.b64decode(doc['stderr_base64'],validate=True)
        matches=(doc['request_clock_id']==spec['clock_id'] and doc['exit_status']==spec['status']
                 and stdout==spec['stdout'].encode()
                 and (spec['stderr_contains'].encode() in stderr if spec['stderr_contains'] else not stderr))
        report['classification']='PASS' if matches else 'FAIL'
    except TraceIncomplete as exc:
        report['trace']=exc.evidence
        report['error']=type(exc).__name__+': '+str(exc)
    except (Incomplete,OSError,ValueError,TypeError,KeyError,ChildProcessError) as exc:
        report['error']=type(exc).__name__+': '+str(exc)
    write_report(RESULT,report)
    print('clock254 case='+report['classification'].lower(),flush=True)


def main():
    if len(sys.argv)==2 and sys.argv[1]=='control':control()
    elif len(sys.argv)==3 and sys.argv[1]=='case':case(sys.argv[2])
    else:raise Incomplete('expected control or frozen case ID')


if __name__=='__main__':
    try:main()
    except (Incomplete,OSError,ValueError,TypeError,KeyError) as exc:
        print('clock254 infrastructure: '+type(exc).__name__+': '+str(exc),file=sys.stderr,flush=True)
        raise SystemExit(125)
