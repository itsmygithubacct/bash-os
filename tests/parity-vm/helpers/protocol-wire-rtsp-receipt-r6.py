#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only parent-owned ptrace observer of this fixture's RTSP TCP reads.

Only the just-forked, still-unreaped direct child is traced. Destination ports
are the fixture's loopback listeners. No attach-by-name, global process scan,
network relay, or strace package is used. Linux x86-64 syscall ABI is explicit.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import threading
import time
import uuid

HOME=Path('/tmp/parity-home'); CASE=Path('/tmp/parity-case')
MARKER=Path('/etc/bashos-parity-vm'); PID1=Path('/proc/1')
GETINFO=0x420e; SETOPTIONS=0x4200; SYSCALL=24; PEEKDATA=2
TRACESYSGOOD=1; TRACEEXEC=0x10; EXITKILL=0x00100000
ARCH_X86_64=0xc000003e; MAX_EVENTS=512; MAX_BYTES=131072; LOG_BUDGET=600000; CONTROL_BUDGET=200000


def require_guest():
    try:
        st=MARKER.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022: raise ValueError('marker ownership/mode')
        marker=MARKER.read_text().strip()
        if str(uuid.UUID(marker))!=marker: raise ValueError('noncanonical UUID')
        pid1=PID1.joinpath('cmdline').read_bytes().split(b'\0')
        status=PID1.joinpath('status').read_text().splitlines()
        uidline=next(x for x in status if x.startswith('Uid:')).split()
        if uidline[1:3]!=['0','0']: raise ValueError('PID 1 is not root evaluator')
        if b'/opt/bashos-parity/harness/guest.py' not in pid1: raise ValueError('PID 1 is not guest evaluator')
        ix=pid1.index(b'--vm-token')
        if pid1[ix+1].decode()!=marker: raise ValueError('PID 1 VM token mismatch')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('uid mismatch')
        if Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME): raise ValueError('scratch mismatch')
        for p in (CASE,HOME):
            q=p.lstat()
            if not stat.S_ISDIR(q.st_mode) or q.st_uid!=2000: raise ValueError('scratch ownership')
        if os.uname().machine!='x86_64': raise ValueError('unsupported ABI')
    except (OSError,ValueError,StopIteration,IndexError) as exc:
        raise SystemExit('RTSP receipt observer guest guard: '+str(exc))


class Entry(ctypes.Structure):
    _fields_=[('number',ctypes.c_uint64),('args',ctypes.c_uint64*6)]
class Exit(ctypes.Structure):
    _fields_=[('result',ctypes.c_int64),('is_error',ctypes.c_uint8)]
class Data(ctypes.Union):
    _fields_=[('entry',Entry),('exit',Exit)]
class Info(ctypes.Structure):
    _fields_=[('op',ctypes.c_uint8),('pad',ctypes.c_uint8*3),('arch',ctypes.c_uint32),
              ('ip',ctypes.c_uint64),('sp',ctypes.c_uint64),('data',Data)]


def ptrace(op,pid,addr=0,data=0):
    libc=ctypes.CDLL(None,use_errno=True); libc.ptrace.restype=ctypes.c_long
    ctypes.set_errno(0)
    value=libc.ptrace(ctypes.c_ulong(op),ctypes.c_ulong(pid),ctypes.c_void_p(addr),ctypes.c_void_p(data))
    error=ctypes.get_errno()
    if value==-1 and error: raise OSError(error,os.strerror(error))
    return value


def peek(pid,addr,n):
    if n<0 or n>MAX_BYTES: raise ValueError('memory capture limit')
    base=addr & ~7; skip=addr-base; out=bytearray()
    while len(out)<skip+n:
        value=ptrace(PEEKDATA,pid,base+len(out),0)
        out.extend((value & ((1<<64)-1)).to_bytes(8,'little'))
    return bytes(out[skip:skip+n])


def identity(pid):
    proc=Path('/proc/%d'%pid)
    fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in proc.joinpath('status').read_text().splitlines()
            if line.startswith(('Pid:','PPid:','Uid:','TracerPid:','State:'))}
    fields['starttime_ticks']=int(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19])
    return fields


def wait(pid,deadline):
    while time.monotonic()<deadline:
        got,status=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
        if got: return status
        time.sleep(.001)
    raise TimeoutError('owned tracee timed out')


def run_trace(program,ports,timeout=24,start_control_server=None):
    if not program or not os.path.isabs(program[0]): raise ValueError('absolute program required')
    if not ports or len(ports)>2 or any(not 1<=x<=65535 for x in ports): raise ValueError('invalid listener ports')
    report={'observer':'parent-owned PTRACE_TRACEME, x86-64; selected loopback TCP fds only',
            'program':program,'parent_pid':os.getpid(),'ports':ports,'events':[],
            'connections':[],'complete':False,'terminal':None,'error':None}
    deadline=time.monotonic()+timeout; gate_r,gate_w=os.pipe(); child=os.fork()
    if child==0:
        try:
            os.close(gate_w)
            if os.read(gate_r,1)!=b'1':raise ValueError('parent did not authorize tracing')
            os.close(gate_r)
            ptrace(0,0)
            os.kill(os.getpid(),signal.SIGSTOP)
            # Python ignores SIGPIPE by default; give the exec'd shell a clean baseline.
            signal.signal(signal.SIGPIPE,signal.SIG_DFL)
            os.execv(program[0],program)
        except BaseException as exc:
            os.write(2,('observer tracee bootstrap: '+str(exc)+'\n').encode());os._exit(126)
    os.close(gate_r)
    report['child_pid']=child; terminal=None; active={}; pending=None; copied=0
    try:
        first=identity(child); report['identity_before_traceme']=first
        if first.get('PPid')!=str(os.getpid()) or first.get('Uid','').split()[0]!='2000': raise ValueError('not owned uid-2000 child')
        if start_control_server is not None: start_control_server()
        os.write(gate_w,b'1');os.close(gate_w);gate_w=-1
        report['ownership_verified_before_traceme']=True
        st=wait(child,deadline)
        if not os.WIFSTOPPED(st) or os.WSTOPSIG(st)!=signal.SIGSTOP: raise ValueError('tracee initial stop missing')
        stopped=identity(child); report['identity_at_stop']=stopped
        if stopped.get('PPid')!=str(os.getpid()) or stopped['starttime_ticks']!=first['starttime_ticks'] or stopped.get('TracerPid')!=str(os.getpid()):
            raise ValueError('tracee ownership, birth identity or tracer changed')
        ptrace(SETOPTIONS,child,0,TRACESYSGOOD|TRACEEXEC|EXITKILL)
        deliver=0
        while True:
            ptrace(SYSCALL,child,0,deliver); deliver=0
            st=wait(child,deadline)
            if os.WIFEXITED(st) or os.WIFSIGNALED(st): terminal=st; break
            if not os.WIFSTOPPED(st): raise ValueError('unexpected wait status')
            sig=os.WSTOPSIG(st); event=st>>16
            if sig==signal.SIGTRAP and event==4:
                if active:raise ValueError('exec while observed socket remains open')
                report['exec_seen']=True; pending=None; continue
            if sig!=(signal.SIGTRAP|0x80):
                if sig==signal.SIGTRAP: raise ValueError('unexpected SIGTRAP')
                deliver=sig; continue
            info=Info(); size=ptrace(GETINFO,child,ctypes.sizeof(info),ctypes.addressof(info))
            if size<24 or info.arch!=ARCH_X86_64: raise ValueError('syscall-info ABI unavailable')
            if info.op==1:
                number=int(info.data.entry.number); args=[int(x) for x in info.data.entry.args]
                pending={'number':number,'args':args,'entry_ns':time.monotonic_ns()}
                if number==13 and args[0]==signal.SIGPIPE:  # x86-64 rt_sigaction
                    pending['sigpipe_new_hex']=peek(child,args[1],32).hex() if args[1] else None
                if number==42:  # connect: collect exact sockaddr at entry
                    size_arg=args[2]
                    if 16<=size_arg<=128:
                        addr=peek(child,args[1],16)
                        if struct.unpack_from('=H',addr)[0]==socket.AF_INET:
                            port=struct.unpack_from('!H',addr,2)[0]
                            if addr[4:8]==b'\x7f\0\0\1' and port in ports:
                                pending['peer']={'address':'127.0.0.1','port':port,'sockaddr_hex':addr.hex()}
            elif info.op==2:
                if pending is None: continue
                n=pending['number']; args=pending['args']; fd=args[0]; result=int(info.data.exit.result)
                stamp=time.monotonic_ns()
                if n==13 and fd==signal.SIGPIPE:
                    row={'kind':'sigpipe-action','new_action_hex':pending.get('sigpipe_new_hex'),
                         'old_action_hex':peek(child,args[2],32).hex() if result==0 and args[2] else None,
                         'return':result,'entry_ns':pending['entry_ns'],'exit_ns':stamp}
                    report['events'].append(row)
                elif n in (1,20) and result==-errno.EPIPE:
                    report['events'].append({'kind':'write-epipe','fd':fd,'return':result,
                                             'entry_ns':pending['entry_ns'],'exit_ns':stamp})
                elif n==42 and 'peer' in pending:
                    row={'kind':'connect','fd':fd,'return':result,'entry_ns':pending['entry_ns'],'exit_ns':stamp,**pending['peer']}
                    report['events'].append(row)
                    if result==0:
                        row['connection_id']=len(report['connections'])+1
                        row['socket_link']=os.readlink('/proc/%d/fd/%d'%(child,fd))
                        if not row['socket_link'].startswith('socket:['): raise ValueError('target fd is not socket')
                        conn={'id':row['connection_id'],'port':row['port'],'socket_link':row['socket_link']}
                        report['connections'].append(conn); active[fd]=conn
                elif n in (0,45) and fd in active:  # read/recvfrom
                    row={'kind':'read' if n==0 else 'recvfrom','fd':fd,'connection_id':active[fd]['id'],
                         'requested':args[2],'result':result,'entry_ns':pending['entry_ns'],'exit_ns':stamp}
                    if result>0:
                        if result>args[2] or copied+result>MAX_BYTES: raise ValueError('read capture limit or invalid result')
                        data=peek(child,args[1],result);row['bytes_hex']=data.hex();copied+=len(data)
                    else: row['bytes_hex']='';row['errno']=-result if result<0 else None
                    report['events'].append(row)
                elif n in (19,47,299,295) and fd in active:
                    raise ValueError('unsupported scatter/gather receive on target socket: syscall '+str(n))
                elif n==3 and fd in active and result==0:
                    report['events'].append({'kind':'close','fd':fd,'connection_id':active[fd]['id'],'return':result,'exit_ns':stamp});del active[fd]
                elif n in (33,292) and result>=0:
                    source=active.get(fd)
                    if result!=fd:active.pop(result,None)
                    if source is not None:
                        active[result]=source;report['events'].append({'kind':'dup','old_fd':fd,'new_fd':result,'connection_id':source['id'],'exit_ns':stamp})
                elif n in (32,72) and fd in active and result>=0 and (n!=72 or args[1] in (0,1030)):
                    active[result]=active[fd];report['events'].append({'kind':'dup','old_fd':fd,'new_fd':result,'connection_id':active[fd]['id'],'exit_ns':stamp})
                elif n==436 and active and result==0:
                    raise ValueError('close_range while target socket active; descriptor identity uncertain')
                elif n in (56,57,58,435) and active and result>0:
                    raise ValueError('tracee forked while target socket active; descendants unobserved')
                if len(report['events'])>MAX_EVENTS: raise ValueError('observer event cap exceeded')
                pending=None
            else: raise ValueError('unexpected syscall-info operation')
        report['terminal']={'raw_wait_status':terminal,'returncode':os.waitstatus_to_exitcode(terminal),'time_ns':time.monotonic_ns()}
        report['bytes_captured']=copied
        if not report.get('exec_seen'): raise ValueError('target exec not observed')
        report['complete']=True
    except BaseException as exc:
        report['error']=type(exc).__name__+': '+str(exc)
    finally:
        if gate_w!=-1:os.close(gate_w)
        if terminal is None:
            # An unreaped direct child cannot be replaced by a reused PID.
            try: os.kill(child,signal.SIGKILL)
            except ProcessLookupError: pass
            try:
                _,st=os.waitpid(child,0)
                report['cleanup_wait_status']=st
            except ChildProcessError: pass
    return report


def probe_child(port):
    conn=socket.socket();conn.connect(('127.0.0.1',port))
    try:
        # Deliberately use native read syscalls and small lengths to test boundaries.
        out=b''
        while True:
            b=os.read(conn.fileno(),3)
            if not b: break
            out+=b
        if len(out)>64: raise ValueError('probe exceeded bound')
    finally: conn.close()
    # Native signal-action and EPIPE observer controls in the disposable guest.
    signal.signal(signal.SIGPIPE,signal.SIG_DFL)
    signal.signal(signal.SIGPIPE,signal.SIG_IGN)
    read_fd,write_fd=os.pipe();os.close(read_fd)
    try:
        try: os.write(write_fd,b'signal-control')
        except BrokenPipeError: pass
        else: raise ValueError('native EPIPE control did not fail')
    finally: os.close(write_fd)
    signal.signal(signal.SIGPIPE,signal.SIG_DFL)



def write_bounded(path,obj,budget):
    raw=(json.dumps(obj,indent=2)+'\n').encode()
    if len(raw)>budget:
        path.write_text(json.dumps({'complete':False,'error':'capture budget exceeded','required_bytes':len(raw)})+'\n')
        raise ValueError('capture budget exceeded')
    path.write_bytes(raw)


def control():
    baseline=b'RTSP-observer-control\x00\xff'; results=[]
    for label,payload in (('positive',baseline),('altered',baseline[:-1]+b'X'),('truncated',baseline[:-3])):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
        port=listener.getsockname()[1]; server={'label':label,'payload_hex':payload.hex(),'events':[]}
        def serve():
            try:
                sock,peer=listener.accept();server['events'].append({'kind':'accept','peer':peer,'time_ns':time.monotonic_ns()})
                with sock:
                    off=0
                    while off<len(payload):
                        started=time.monotonic_ns();n=sock.send(payload[off:]);server['events'].append({'kind':'send','offset':off,'accepted':n,'started_ns':started,'ended_ns':time.monotonic_ns()})
                        if n<=0: raise OSError('zero send')
                        off+=n
                    sock.shutdown(socket.SHUT_WR);server['events'].append({'kind':'shutdown-write','time_ns':time.monotonic_ns()})
            except Exception as exc: server['error']=type(exc).__name__+': '+str(exc)
            finally: listener.close()
        thread=threading.Thread(target=serve,daemon=True)
        observation=run_trace(['/usr/bin/python3',str(Path(__file__)), 'probe-child',str(port)],[port],15,start_control_server=thread.start)
        if thread.ident is None: listener.close()
        else: thread.join(6)
        actual=b''.join(bytes.fromhex(e['bytes_hex']) for e in observation['events'] if e['kind'] in ('read','recvfrom'))
        row={'server':server,'observation':observation,'received_hex':actual.hex(),
             'equals_baseline':actual==baseline,'equals_sent':actual==payload}
        results.append(row)
        events=observation['events']
        actions=[(i,int.from_bytes(bytes.fromhex(e['new_action_hex'])[:8],'little'))
                 for i,e in enumerate(events) if e.get('kind')=='sigpipe-action' and e.get('return')==0 and e.get('new_action_hex')]
        epipe=[i for i,e in enumerate(events) if e.get('kind')=='write-epipe' and e.get('return')==-errno.EPIPE]
        signal_control=any(a[1]==0 and b[1]==1 and c[1]==0 and a[0]<b[0]<c[0] and any(b[0]<i<c[0] for i in epipe)
                           for a in actions for b in actions for c in actions)
        row['signal_observer_control']=signal_control
        if thread.is_alive() or server.get('error') or not observation['complete'] or observation['terminal']['returncode']!=0 or actual!=payload or not signal_control:
            write_bounded(HOME/'rtsp-receipt-control.json',results,CONTROL_BUDGET);raise ValueError('native receipt control failed: '+label)
    write_bounded(HOME/'rtsp-receipt-control.json',results,CONTROL_BUDGET)
    if [r['equals_baseline'] for r in results]!=[True,False,False]: raise ValueError('altered/truncated negative control failed')
    if not any(e['kind']=='read' and e['result']==0 for e in results[0]['observation']['events']): raise ValueError('EOF control not recorded')
    print('owned-read-observer-control=ok')


def main():
    if sys.argv[1:]==['control']: control(); return
    if len(sys.argv)==3 and sys.argv[1]=='probe-child': probe_child(int(sys.argv[2])); return
    if len(sys.argv)<7 or sys.argv[1]!='observe' or sys.argv[4]!='--': raise SystemExit('usage: observe LOG PORTS -- PROGRAM ...')
    log=Path(sys.argv[2]); ports=[int(x) for x in sys.argv[3].split(',')]
    if log.parent!=HOME or log.name not in ('rtsp-receipt.json',): raise ValueError('invalid observer output path')
    report=run_trace(sys.argv[5:],ports)
    write_bounded(log,report,LOG_BUDGET)
    if not report['complete']: raise SystemExit(125)
    code=report['terminal']['returncode']
    raise SystemExit(code if code>=0 else 128-code)


if __name__=='__main__':
    require_guest()
    main()
