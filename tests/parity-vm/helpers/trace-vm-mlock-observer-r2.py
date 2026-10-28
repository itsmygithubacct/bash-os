#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Trace only owned shell/probe syscall events in a disposable parity guest."""
import ctypes
import errno
import json
import os
import runpy
import time
from pathlib import Path
import signal
import sys
import uuid


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker))!=marker.lower(): raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('wrong uid')
        if Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home': raise ValueError('wrong scratch directory')
        if os.uname().machine!='x86_64': raise ValueError('requires pinned x86-64 guest ABI')
    except (OSError,ValueError,UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: '+str(exc))


require_guest()
HOME=Path('/tmp/parity-home');HELPER='./trace-vm-mlock-observer-r2.py'
SUPERVISOR=runpy.run_path('./trace-vm-supervisor-r2.py')
OwnedChild=SUPERVISOR['OwnedChild']
EXITKILL=SUPERVISOR['PTRACE_O_EXITKILL']
lib=ctypes.CDLL(None,use_errno=True);lib.ptrace.restype=ctypes.c_long
PTRACE_TRACEME=0;PTRACE_PEEKDATA=2;PTRACE_SYSCALL=24;PTRACE_SETOPTIONS=0x4200;PTRACE_GET_SYSCALL_INFO=0x420e
SYS_WRITE=1;SYS_MMAP=9;SYS_MUNMAP=11;SYS_MLOCK=149;SYS_MUNLOCK=150
NAMES={SYS_MMAP:'mmap',SYS_MUNMAP:'munmap',SYS_MLOCK:'mlock',SYS_MUNLOCK:'munlock',SYS_WRITE:'write'}
GUARD=r'''[[ $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r v </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r u </etc/bashos-parity-vm || exit 125
[[ $v == QEMU && $u =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
'''


class Entry(ctypes.Structure):
    _fields_=[('nr',ctypes.c_uint64),('args',ctypes.c_uint64*6)]
class Exit(ctypes.Structure):
    _fields_=[('rval',ctypes.c_int64),('is_error',ctypes.c_uint8)]
class Union(ctypes.Union):
    _fields_=[('entry',Entry),('exit',Exit)]
class Info(ctypes.Structure):
    _fields_=[('op',ctypes.c_uint8),('pad',ctypes.c_uint8*3),('arch',ctypes.c_uint32),
              ('ip',ctypes.c_uint64),('sp',ctypes.c_uint64),('data',Union)]


def ptrace(op,pid,addr=0,data=0):
    ctypes.set_errno(0)
    rc=lib.ptrace(ctypes.c_ulong(op),ctypes.c_ulong(pid),ctypes.c_void_p(addr),ctypes.c_void_p(data))
    err=ctypes.get_errno()
    if rc==-1 and err:raise OSError(err,os.strerror(err))
    return rc


def peek(pid,address,n):
    result=bytearray();word=ctypes.sizeof(ctypes.c_long)
    for offset in range(0,n,word):
        value=ptrace(PTRACE_PEEKDATA,pid,address+offset,0) & ((1<<(word*8))-1)
        result.extend(value.to_bytes(word,'little'))
    return bytes(result[:n])


def probe():
    # Independent direct libc reference, bracketed by two unambiguous writes.
    lib.mmap.restype=ctypes.c_void_p
    lib.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    lib.mlock.argtypes=lib.munlock.argtypes=lib.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    lib.mlock.restype=lib.munlock.restype=lib.munmap.restype=ctypes.c_int
    fd=os.open(str(HOME/'mlock-trace-markers'),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    if fd!=3:os.dup2(fd,3);os.close(fd)
    os.write(3,b'BEGIN\n')
    addr=lib.mmap(None,4096,3,0x22,-1,0)
    ok=addr not in (None,ctypes.c_void_p(-1).value)
    if ok:
        ok=lib.mlock(addr,4096)==0 and lib.munlock(addr,4096)==0 and lib.munmap(addr,4096)==0
    os.write(3,b'END\n');print('0' if ok else '1')
    return 0 if ok else 1


def shell_script(mode,size):
    limit={'small':'','large':'','precheck':'ulimit -S -l 64 || exit 80\n',
           'round':'ulimit -S -l 1023 || exit 80\n'}[mode]
    return GUARD+limit+f'''exec 3>"$HOME/mlock-trace-markers" 4>"$HOME/mlock-trace-operation.out" 5>"$HOME/mlock-trace-operation.err"
printf 'BEGIN\\n' >&3
mlock try-lock {size} >&4 2>&5
rc=$?
printf 'END\\n' >&3
printf '%s\\n' "$rc"
exit 0
'''


class ControlledCleanup(Exception):
    pass


def drain_fd(fd, limit=65536):
    os.set_blocking(fd, False)
    data=bytearray()
    while len(data)<limit:
        try:part=os.read(fd,min(4096,limit-len(data)))
        except BlockingIOError:break
        if not part:break
        data.extend(part)
    return bytes(data)


def append_lifecycle(record):
    with (HOME/'mlock-syscall-lifecycle.jsonl').open('a',encoding='utf8') as stream:
        stream.write(json.dumps(record,sort_keys=True)+'\n')


def observe(argv, fault_after_options=False):
    fds=[];child=None;out_fd=None;err_fd=None;events=[];pending=None;active=False
    seen_begin=False;seen_end=False;failure=None;result=None;options=None
    pre_out=b'';pre_err=b''
    try:
        r_out,w_out=os.pipe();fds.extend((r_out,w_out));out_fd=r_out
        r_err,w_err=os.pipe();fds.extend((r_err,w_err));err_fd=r_err
        pid=os.fork()
        if pid==0:
            try:
                os.close(r_out);os.close(r_err);os.dup2(w_out,1);os.dup2(w_err,2)
                if w_out not in (1,2):os.close(w_out)
                if w_err not in (1,2):os.close(w_err)
                ptrace(PTRACE_TRACEME,0);os.execve(argv[0],argv,dict(os.environ))
            except BaseException as exc:
                os.write(2,('tracee launch failed: '+repr(exc)+'\n').encode());os._exit(125)
        child=OwnedChild(pid)
        os.close(w_out);fds.remove(w_out);os.close(w_err);fds.remove(w_err)
        deadline=time.monotonic()+25
        status=child.wait(deadline)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=signal.SIGTRAP:
            raise RuntimeError('tracee did not stop at exec')
        options=1|EXITKILL
        ptrace(PTRACE_SETOPTIONS,pid,0,options)
        if fault_after_options:raise ControlledCleanup('deliberate exception after ptrace options')
        while True:
            ptrace(PTRACE_SYSCALL,pid);status=child.wait(deadline)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):break
            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=(signal.SIGTRAP|0x80):
                raise RuntimeError('unexpected ptrace stop '+str(status))
            info=Info();ptrace(PTRACE_GET_SYSCALL_INFO,pid,ctypes.sizeof(info),ctypes.addressof(info))
            if info.op==1:
                nr=int(info.data.entry.nr);args=[int(x) for x in info.data.entry.args]
                marker=None;marker_path=None
                if nr==SYS_WRITE and args[0] in (1,3) and args[2] in (4,6):
                    try:marker_path=os.readlink('/proc/%d/fd/%d'%(pid,args[0]))
                    except OSError:marker_path=None
                    if marker_path==str(HOME/'mlock-trace-markers'):
                        marker=peek(pid,args[1],args[2])
                        if marker==b'BEGIN\n':active=True;seen_begin=True
                pending={'nr':nr,'name':NAMES.get(nr,'syscall_'+str(nr)),'args':args}
                if marker is not None:pending.update(write_bytes_hex=marker.hex(),descriptor_path=marker_path)
            elif info.op==2 and pending is not None:
                pending.update(result=int(info.data.exit.rval),is_error=bool(info.data.exit.is_error))
                if active:events.append(pending)
                if pending.get('write_bytes_hex')==b'END\n'.hex():active=False;seen_end=True
                pending=None
            if len(events)>4096:raise RuntimeError('syscall event bound exceeded')
        result={'argv':argv,'pid':pid,'exit_status':os.waitstatus_to_exitcode(status),
                'stdout_hex':drain_fd(out_fd).hex(),'stderr_hex':drain_fd(err_fd).hex(),
                'seen_begin':seen_begin,'seen_end':seen_end,'events':events,'ptrace_options':options}
        return result
    except BaseException as exc:
        failure={'type':type(exc).__name__,'message':str(exc),'argv':argv,
                 'pid':child.pid if child else None,'ptrace_options':options,
                 'events':events,'pending':pending,'seen_begin':seen_begin,'seen_end':seen_end}
        for name,fd in (('stdout',out_fd),('stderr',err_fd)):
            if fd is not None and fd in fds:
                try:
                    data=drain_fd(fd);failure[name+'_before_cleanup_hex']=data.hex()
                    if name=='stdout':pre_out=data
                    else:pre_err=data
                except OSError as read_error:failure[name+'_read_error']=repr(read_error)
        append_lifecycle({'phase':'before-cleanup-failure',**failure})
        raise
    finally:
        lifecycle={'phase':'cleanup','pid':child.pid if child else None,'ptrace_options':options,
                   'controlled_fault':fault_after_options,'failure':failure,'open_fds_before':list(fds)}
        cleanup_error=None
        if child is not None:
            try:lifecycle['child']=child.cleanup()
            except BaseException as exc:
                cleanup_error=exc;lifecycle['child']={'pid':child.pid,'reaped':child.reaped,'events':child.events,'error':repr(exc)}
        for name,fd in (('stdout',out_fd),('stderr',err_fd)):
            if fd is not None and fd in fds:
                try:lifecycle[name+'_after_cleanup_hex']=drain_fd(fd).hex()
                except OSError as exc:lifecycle[name+'_read_error']=repr(exc)
        lifecycle['fd_closes']=[]
        for fd in list(fds):
            try:os.close(fd);lifecycle['fd_closes'].append({'fd':fd,'closed':True})
            except OSError as exc:lifecycle['fd_closes'].append({'fd':fd,'closed':False,'error':repr(exc)})
        lifecycle['all_fds_closed']=all(x['closed'] for x in lifecycle['fd_closes'])
        append_lifecycle(lifecycle)
        if result is not None:result['cleanup']=lifecycle
        if cleanup_error:raise RuntimeError('owned tracee cleanup failed: '+repr(cleanup_error)) from cleanup_error
        if not lifecycle['all_fds_closed']:raise RuntimeError('tracee pipe cleanup failed')


def analyze(obs,mode,size):
    relevant=[e for e in obs['events'] if e['nr'] in (SYS_MMAP,SYS_MLOCK,SYS_MUNLOCK,SYS_MUNMAP)]
    checks={'markers':obs['seen_begin'] and obs['seen_end'],'tracee_exit_zero':obs['exit_status']==0}
    if mode=='precheck':
        checks.update(no_mmap=not any(e['nr']==SYS_MMAP for e in relevant),
                      no_lock_or_unmap=not any(e['nr'] in (SYS_MLOCK,SYS_MUNLOCK,SYS_MUNMAP) for e in relevant))
        return checks
    maps=[(i,e) for i,e in enumerate(relevant) if e['nr']==SYS_MMAP and e['args'][1]==size and (e['args'][3]&0x20)]
    checks['one_target_mapping']=len(maps)==1 and maps[0][1]['result']>0
    if not checks['one_target_mapping']:return checks
    i,mapping=maps[0];address=mapping['result']
    locks=[(j,e) for j,e in enumerate(relevant) if e['nr']==SYS_MLOCK and e['args'][0]==address and e['args'][1]==size]
    unlocks=[(j,e) for j,e in enumerate(relevant) if e['nr']==SYS_MUNLOCK and e['args'][0]==address and e['args'][1]==size]
    unmaps=[(j,e) for j,e in enumerate(relevant) if e['nr']==SYS_MUNMAP and e['args'][0]==address and e['args'][1]==size]
    checks['one_matching_lock']=len(locks)==1
    checks['one_matching_unmap']=len(unmaps)==1 and unmaps[0][1]['result']==0
    if mode=='round':
        checks['lock_failed_enomem']=len(locks)==1 and locks[0][1]['result']==-errno.ENOMEM
        checks['no_munlock_after_failure']=not unlocks
        checks['order']=len(locks)==1 and len(unmaps)==1 and i<locks[0][0]<unmaps[0][0]
    else:
        checks['lock_success']=len(locks)==1 and locks[0][1]['result']==0
        checks['one_successful_unlock']=len(unlocks)==1 and unlocks[0][1]['result']==0
        checks['order']=len(locks)==1 and len(unlocks)==1 and len(unmaps)==1 and i<locks[0][0]<unlocks[0][0]<unmaps[0][0]
    return checks


def save(name,data):
    (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def control():
    obs=observe(['/usr/bin/python3',HELPER,'--probe']);checks=analyze(obs,'control',4096)
    altered=json.loads(json.dumps(obs))
    for event in altered['events']:
        if event['nr']==SYS_MUNMAP and event['args'][1]==4096:
            event['result']=-errno.EINVAL;break
    checks['reject_failed_unmap']=not all(analyze(altered,'control',4096).values())
    caught=False
    try:observe(['/usr/bin/python3',HELPER,'--probe'],fault_after_options=True)
    except ControlledCleanup:caught=True
    lifecycle=[json.loads(x) for x in (HOME/'mlock-syscall-lifecycle.jsonl').read_text().splitlines()]
    item=lifecycle[-1]
    checks['exception_control']=caught and item.get('controlled_fault') is True and item.get('all_fds_closed') is True
    checks['exception_child_reaped']=item.get('child',{}).get('reaped') is True and item.get('child',{}).get('status',{}).get('signal')==signal.SIGKILL
    checks['exitkill_set']=item.get('ptrace_options')==(1|EXITKILL)
    save('mlock-syscall-control.json',{'observation':obs,'exception_lifecycle':item,'checks':checks})
    if not all(checks.values()):raise AssertionError('syscall observer control failed: '+repr(checks))
    print('syscall observer control ok')


def exercise(mode):
    size={'small':1,'large':1048576,'precheck':65537,'round':1047552}[mode]
    script=shell_script(mode,size);obs=observe(['/opt/bashos-parity/candidate','--noprofile','--norc','-c',script])
    checks=analyze(obs,mode,size)
    checks['operation_status']=bytes.fromhex(obs['stdout_hex'])==(b'1\n' if mode in ('precheck','round') else b'0\n')
    output=(HOME/'mlock-trace-operation.out').read_bytes() if (HOME/'mlock-trace-operation.out').exists() else b''
    diagnostic=(HOME/'mlock-trace-operation.err').read_bytes() if (HOME/'mlock-trace-operation.err').exists() else b''
    if mode in ('small','large'):
        checks['operation_output']=output==('try-lock ok size=%d\n'%size).encode() and diagnostic==b''
    elif mode=='precheck':
        checks['operation_output']=output==b'' and b'rlimit: needed=65537 soft=65536 hard=' in diagnostic
    else:
        checks['operation_output']=output==b'' and b'try-lock: mlock(1047552): Cannot allocate memory' in diagnostic
    save('mlock-syscall-observation.json',{'mode':mode,'size':size,'observation':obs,'checks':checks,
         'operation_stdout_hex':output.hex(),'operation_stderr_hex':diagnostic.hex(),
         'markers_hex':(HOME/'mlock-trace-markers').read_bytes().hex() if (HOME/'mlock-trace-markers').exists() else None})
    if not all(checks.values()):raise AssertionError('syscall mismatch: '+repr(checks))
    print(mode+': ok')


if sys.argv[1:]==['--probe']:raise SystemExit(probe())
elif sys.argv[1:]==['--control']:control()
elif len(sys.argv)==2 and sys.argv[1] in ('small','large','precheck','round'):exercise(sys.argv[1])
else:raise SystemExit('invalid invocation')
