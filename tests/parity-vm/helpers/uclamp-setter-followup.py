#!/usr/bin/python3
"""Guest-only reset flag, reset-on-fork and seeded policy observations."""
import ctypes,json,os,select,struct,subprocess,sys,time,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case');SEQ='/opt/bashos-parity/harness/helpers/system-sequence.py';TASK='/opt/bashos-parity/harness/helpers/uclamp-owned-task.py';DIRECT='/opt/bashos-parity/harness/helpers/uclamp-direct-reset-control.py'
if os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=C or os.environ.get('HOME')!=str(H):raise SystemExit(125)
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.uname().release!='7.2.11+deb13-amd64':raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
class Attr(ctypes.Structure):
    _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long
def get(pid):
    a=Attr();a.size=ctypes.sizeof(a)
    if lib.syscall(315,pid,ctypes.byref(a),ctypes.sizeof(a),0):raise OSError(ctypes.get_errno(),'sched_getattr')
    return {k:getattr(a,k) for k,_ in Attr._fields_}
def run(argv):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    return {'argv':argv,'status':p.returncode,'stdout':p.stdout.decode('utf8','backslashreplace'),'stderr':p.stderr.decode('utf8','backslashreplace')}
def read_line(stream):
    end=time.monotonic()+10;out=bytearray()
    while len(out)<8192:
        remaining=end-time.monotonic()
        if remaining<=0 or not select.select([stream],[],[],remaining)[0]:raise RuntimeError('owned task read timed out')
        b=os.read(stream.fileno(),1)
        if not b:raise RuntimeError('owned task closed pipe')
        if b==b'\n':return bytes(out)
        out.extend(b)
    raise RuntimeError('owned task line exceeded cap')
def start():
    p=subprocess.Popen(['/usr/bin/python3','-I',TASK,'single'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    try:return p,json.loads(read_line(p.stdout))
    except BaseException:
        p.kill();p.wait(timeout=5);raise
def task_identity(pid):
    text=Path('/proc/%d/stat'%pid).read_text();pos=text.rfind(')')
    if pos<0:raise RuntimeError('invalid proc stat')
    f=text[pos+1:].split()
    if len(f)<20 or f[0] in ('Z','X','x'):raise RuntimeError('owned task dead or proc stat truncated')
    return {'pid':pid,'ppid':int(f[1]),'start_ticks':int(f[19]),'uid':os.stat('/proc/%d'%pid).st_uid}
def bind_owned(p,info):
    if type(info.get('pid')) is not int or info['pid']!=p.pid or info.get('tid')!=p.pid:raise RuntimeError('readiness PID differs from created task')
    a=task_identity(p.pid)
    if a['ppid']!=os.getpid() or a['uid']!=2000:raise RuntimeError('owned task parent or uid differs')
    fd=os.pidfd_open(p.pid,0);poll=select.poll();poll.register(fd,select.POLLIN)
    if poll.poll(0) or p.poll() is not None or task_identity(p.pid)!=a:
        os.close(fd);raise RuntimeError('owned task exited while binding pidfd')
    return {'identity':a,'pidfd':fd,'process':p}
def live(binding):
    poll=select.poll();poll.register(binding['pidfd'],select.POLLIN)
    if poll.poll(0) or binding['process'].poll() is not None or task_identity(binding['identity']['pid'])!=binding['identity']:raise RuntimeError('owned task birth identity or pidfd changed')
    return {'identity':binding['identity'],'pidfd_alive':True}
def seq(cmd,tag):
    log=H/(tag+'.jsonl');r=run(['/usr/bin/python3','-I',SEQ,'--notify','sched_setattr','--log',str(log),'--log-args','sched_setattr=0','--log-mem','sched_setattr=1:56','--',*cmd]);r['trace']=[json.loads(x) for x in log.read_text().splitlines()] if log.exists() else None;return r
def request(r,pid):
    events=r['trace']
    if not isinstance(events,list) or len(events)!=1 or events[0].get('arg0')!=pid:raise ValueError('setter trace does not identify exact target')
    memory=events[0].get('memory1',{});raw=bytes.fromhex(memory.get('hex',''))
    if len(raw)!=56 or memory.get('length')!=56:raise ValueError('setter request bytes unavailable')
    return {'flags':struct.unpack_from('<Q',raw,8)[0],'min':struct.unpack_from('<I',raw,48)[0],'max':struct.unpack_from('<I',raw,52)[0]}
def save(v):(H/'setter-report.json').write_text(json.dumps(v,sort_keys=True)+'\n')
def main():
    mode,shell=sys.argv[1:3];report={'mode':mode,'control_valid':False,'candidate_checks':{},'events':{}};procs=[];bindings={}
    try:
        np,ninfo=start();procs.append(np);cp,cinfo=start();procs.append(cp);n=ninfo['pid'];c=cinfo['pid'];events=report['events'];events.update(native_task=ninfo,candidate_task=cinfo)
        up=None;u=None
        if mode=='fork':
            up,uinfo=start();procs.append(up);u=uinfo['pid'];events['native_util_linux_task']=uinfo
        for proc,info in ((np,ninfo),(cp,cinfo))+(((up,uinfo),) if mode=='fork' else ()):
            bindings[proc.pid]=bind_owned(proc,info)
        events['owned_birth_bindings']={str(pid):live(b) for pid,b in bindings.items()}
        if mode=='policy':
            for pid in (n,c):os.sched_setscheduler(pid,os.SCHED_BATCH,os.sched_param(0));os.setpriority(os.PRIO_PROCESS,pid,5)
            opts=['-m','100','-M','900']
        else:
            for pid in ((n,c,u) if mode=='fork' else (n,c)):
                live(bindings[pid])
                seed=run(['/usr/bin/uclampset','-m','100','-M','800','-p',str(pid)])
                if seed['status']!=0:raise RuntimeError('native seed failed')
                live(bindings[pid])
            opts=['-m','-1','-M','-1'] if mode=='reset' else ['-R','-m','100','-M','800'] if mode=='fork' else None
            if opts is None:raise RuntimeError('unknown setter mode')
        before_n=get(n);before_c=get(c);events.update(before_native=before_n,before_candidate=before_c)
        if mode=='fork' and ((before_c['flags']&1) or (before_c['util_min'],before_c['util_max'])!=(100,800)):raise RuntimeError('candidate target seed or clear reset bit unavailable')
        events['candidate_precondition']={'reset_bit_clear':not bool(before_c['flags']&1),'owned':live(bindings[c])}
        if mode=='fork':
            live(bindings[u]);events['native_util_linux_before']=get(u)
            util=seq(['/usr/bin/uclampset',*opts,'-p',str(u)],'native-util-linux-fork');events['native_util_linux_fork']=util
            if util['status']!=0:raise RuntimeError('native util-linux -R observation failed')
            events['native_util_linux_request']=request(util,u);events['native_util_linux_after']=get(u)
            events['native_util_linux_owned_after']=live(bindings[u])
            up.stdin.write(b'fork\n');up.stdin.flush();events['native_util_linux_child']=json.loads(read_line(up.stdout))
        native_identity=bindings[n]['identity']
        native_command=(['/usr/bin/python3','-I',DIRECT,str(n),str(native_identity['ppid']),str(native_identity['start_ticks'])] if mode=='fork' else ['/usr/bin/uclampset',*opts,'-p',str(n)])
        live(bindings[n]);native=seq(native_command,'native-setter');events['native']=native
        if native['status']!=0:raise RuntimeError('native operation failed')
        nr=request(native,n);after_n=get(n);events.update(native_request=nr,after_native=after_n)
        events['native_owned_after']=live(bindings[n])
        if mode=='reset':
            if nr['flags']&0x60!=0x60 or (nr['min'],nr['max'])!=(0xffffffff,0xffffffff) or (after_n['util_min'],after_n['util_max'])!=(0,1024):raise RuntimeError('native reset request/readback control failed')
        elif mode=='policy':
            if (before_n['policy'],before_n['nice'])!=(os.SCHED_BATCH,5) or (after_n['policy'],after_n['nice'])!=(before_n['policy'],before_n['nice']):raise RuntimeError('native seeded policy control failed')
        else:
            if nr['flags']!=0x71 or not (after_n['flags']&1) or (after_n['util_min'],after_n['util_max'])!=(100,800) or any(after_n[k]!=before_n[k] for k in ('policy','nice','priority','runtime','deadline','period')):raise RuntimeError('direct native reset request or parent readback failed')
            np.stdin.write(b'fork\n');np.stdin.flush();fork_n=json.loads(read_line(np.stdout));events['native_fork']=fork_n
            if (fork_n['child_attr']['util_min'],fork_n['child_attr']['util_max'])!=(0,1024):raise RuntimeError('native reset-on-fork control failed')
        report['control_valid']=True
        if mode=='fork':
            current=get(c)
            if current['flags']&1 or current!=before_c:raise RuntimeError('candidate target state changed before invocation')
            events['candidate_before_invocation']={'attr':current,'owned':live(bindings[c])};save(report)
        cand=seq([shell,'--noprofile','--norc','-c','uclampset "$@"','setter',*opts,'-p',str(c)],'candidate-setter');events['candidate']=cand
        save(report)
        cr=request(cand,c);after_c=get(c);events.update(candidate_request=cr,after_candidate=after_c)
        events['candidate_owned_after']=live(bindings[c]);save(report)
        checks={'status':cand['status']==0,'stderr':cand['stderr']==''}
        if mode=='reset':checks.update(reset_flags=cr['flags']&0x60==0x60,reset_values=(cr['min'],cr['max'])==(0xffffffff,0xffffffff),readback=(after_c['util_min'],after_c['util_max'])==(0,1024))
        elif mode=='policy':checks.update(seeded=(before_c['policy'],before_c['nice'])==(os.SCHED_BATCH,5),unchanged=(before_c['policy'],before_c['nice'])==(after_c['policy'],after_c['nice']))
        else:
            cp.stdin.write(b'fork\n');cp.stdin.flush();fork_c=json.loads(read_line(cp.stdout));events['candidate_fork']=fork_c
            checks.update(reset_on_fork_flag=bool(cr['flags']&1),parent_flag_readback=bool(after_c['flags']&1),child_default=(fork_c['child_attr']['util_min'],fork_c['child_attr']['util_max'])==(0,1024))
        report['candidate_checks']=checks;save(report)
        if not all(checks.values()):raise SystemExit(1)
        print('owned uclamp setter checks ok')
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,AttributeError,subprocess.TimeoutExpired) as e:
        report['incomplete']=type(e).__name__+': '+str(e);save(report);raise SystemExit(125)
    finally:
        for p in procs:
            if p.poll() is None:
                try:p.stdin.write(b'exit\n');p.stdin.flush();p.wait(timeout=5)
                except (BrokenPipeError,subprocess.TimeoutExpired):p.kill();p.wait()
        for binding in bindings.values():os.close(binding['pidfd'])
if __name__=='__main__':main()
