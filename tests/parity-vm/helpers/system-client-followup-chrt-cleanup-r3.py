#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM scheduling observations on remembered owned tasks only."""
import base64
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home');SELF=Path('/opt/bashos-parity/harness/helpers/system-client-followup-chrt-cleanup-r3.py')
RESET=0x40000000


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or
        not Path.cwd().is_relative_to(CASE) or platform.machine()!='x86_64'):
        raise SystemExit(125)


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'chrt-followup-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def safe_path(value):
    p=Path(value).resolve()
    if not p.is_relative_to(CASE):raise ValueError('path outside private case')
    return p


def child_target(marker):
    marker=safe_path(marker);stop=threading.Event();ready=threading.Barrier(3);tids=[]
    def worker():
        tids.append(threading.get_native_id());ready.wait();stop.wait(30)
    threads=[threading.Thread(target=worker) for _ in range(2)]
    for t in threads:t.start()
    ready.wait();marker.write_text(json.dumps({'pid':os.getpid(),'ppid':os.getppid(),'uid':os.getuid(),'tids':[os.getpid()]+sorted(tids)}))
    sys.stdin.buffer.read(1);stop.set()
    for t in threads:t.join(timeout=3)


def child_probe(marker,action,arguments):
    marker=safe_path(marker)
    marker.write_text(json.dumps({'pid':os.getpid(),'uid':os.getuid(),'gid':os.getgid(),
        'policy':os.sched_getscheduler(0),'priority':os.sched_getparam(0).sched_priority,'arguments':arguments},sort_keys=True))
    if action=='signal':os.kill(os.getpid(),signal.SIGTERM);raise RuntimeError('signal failed')
    sys.exit(int(action))


def proc_identity(pid):
    raw=Path('/proc/%d/stat'%pid).read_text();fields=raw[raw.rindex(')')+2:].split()
    lines=Path('/proc/%d/status'%pid).read_text().splitlines()
    uid=next([int(x) for x in line.split()[1:]] for line in lines if line.startswith('Uid:'))
    if fields[0]=='Z' or uid[:2]!=[2000,2000]:raise RuntimeError('unowned target')
    return int(fields[1]),int(fields[19]),tuple(uid)


class Target:
    def __init__(self,label):
        self.marker=CASE/('chrt-followup-'+label+'.target.json');assert not self.marker.exists()
        self.p=subprocess.Popen(['/usr/bin/python3',str(SELF),'target',str(self.marker)],cwd=CASE,env=dict(os.environ),
                                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        end=time.monotonic()+8
        while not self.marker.exists() and self.p.poll() is None and time.monotonic()<end:time.sleep(.02)
        if not self.marker.exists():self.close();raise RuntimeError('owned target not ready')
        self.data=json.loads(self.marker.read_text());self.identity=proc_identity(self.p.pid)
        if (self.data['pid']!=self.p.pid or self.data['ppid']!=os.getpid() or self.data['uid']!=2000 or
            self.identity[0]!=os.getpid()):self.close();raise RuntimeError('invalid target identity')
        self.tids=self.data['tids'];self.check();record('target-ready',label=label,marker_base64=b64(self.marker.read_bytes()),identity=self.identity,tids=self.tids)
    def check(self):
        if self.p.poll() is not None or proc_identity(self.p.pid)!=self.identity:raise RuntimeError('target identity changed')
        observed=sorted(int(x.name) for x in (Path('/proc')/str(self.p.pid)/'task').iterdir())
        if sorted(self.tids)!=observed or len(self.tids)!=3:raise RuntimeError('target threads changed')
    def policies(self):
        self.check();out=[os.sched_getscheduler(tid) for tid in self.tids];self.check()
        record('policy-snapshot',pid=self.p.pid,tids=self.tids,policies=out,identity=self.identity)
        return out
    def close(self):
        forced=False
        if self.p.poll() is None:
            self.p.stdin.close()
            try:self.p.wait(timeout=4)
            except subprocess.TimeoutExpired:
                forced=True
                self.p.kill();self.p.wait(timeout=4)
        record('target-close',pid=self.p.pid,exit_status=self.p.returncode,forced=forced)
        if self.p.stdout:self.p.stdout.close()
        if self.p.stderr:self.p.stderr.close()


def run(argv,env=None,timeout=12):
    p=subprocess.Popen(list(map(str,argv)),cwd=CASE,env=env or dict(os.environ),stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError('owned command timeout')
    return p.returncode,out,err


SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case* ]] || exit 125
policy() { local k colon val; while read -r k colon val; do [[ $k == policy ]] && { printf '%s=%s\n' "$1" "$val"; return; }; done < /proc/self/sched; return 1; }
policy before || exit 121
"$@"; rc=$?
printf 'result=%d\n' "$rc"
policy after || exit 122
'''


def invoke(shell,reference,args,extra_env=None):
    cmd='/usr/bin/chrt' if reference else 'chrt';env=dict(os.environ,PATH=str(CASE)+'/chrt-followup-bin:/usr/bin:/bin',**(extra_env or {}))
    status,out,err=run([shell,'--noprofile','--norc','-c',SCRIPT,'case',cmd,*args],env)
    data={}
    for row in out.decode(errors='replace').splitlines():
        if '=' in row:
            k,v=row.split('=',1);data[k]=v
    record('invocation',reference=reference,args=list(map(str,args)),status=status,stdout_base64=b64(out),stderr_base64=b64(err),parsed=data)
    return {'status':status,'out':out,'err':err,'data':data}


def install_probe():
    directory=CASE/'chrt-followup-bin';directory.mkdir(exist_ok=True);tool=directory/'owned-probe'
    if not tool.exists():shutil.copyfile(SELF,tool);os.chmod(tool,0o700)
    return tool


def command(shell,label,reference,flags,priority,action='7'):
    marker=CASE/('chrt-followup-'+label+'.probe.json');assert not marker.exists()
    args=[*flags,str(priority),'owned-probe','probe',str(marker),action,'with spaces','','-leading']
    result=invoke(shell,reference,args);raw=marker.read_bytes() if marker.exists() else b''
    result['probe']=json.loads(raw) if raw else None
    record('probe',label=label,reference=reference,exists=marker.exists(),raw_base64=b64(raw),parsed=result['probe'])
    return result


def target_call(shell,label,reference,flags):
    target=Target(label)
    try:
        before=target.policies();target.check();r=invoke(shell,reference,[*flags,'0',str(target.p.pid)])
        after=target.policies();r.update(before=before,after=after,tids=target.tids,pid=target.p.pid)
        record('target',label=label,before=before,after=after,tids=target.tids,pid=target.p.pid)
        return r
    finally:target.close()


def kernel_deadline(target,runtime,deadline,period):
    target.check()
    class Attr(ctypes.Structure):
        _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),
                  ('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),
                  ('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
    a=Attr();a.size=ctypes.sizeof(a);a.policy=6;a.runtime=runtime;a.deadline=deadline;a.period=period
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    rc=libc.syscall(314,target.p.pid,ctypes.byref(a),0);error=ctypes.get_errno() if rc<0 else 0
    target.check();record('deadline-kernel',pid=target.p.pid,runtime=runtime,deadline=deadline,period=period,result=int(rc),errno=error);return int(rc),error


def setup(which):
    effective=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    rtprio=resource.getrlimit(resource.RLIMIT_RTPRIO)
    if effective & (1<<23) or rtprio!=(0,0):raise RuntimeError('fixture requires uid-2000 without CAP_SYS_NICE and RLIMIT_RTPRIO 0')
    record('scheduler-prerequisites',cap_effective_hex='%x'%effective,rlimit_rtprio=list(rtprio))
    install_probe();ref='/opt/bash-5.3.15/bin/bash'
    for label,flags,expected in [('control-main',['-b','-p'],[3,0,0]),('control-all',['-b','-a','-p'],[3,3,3]),('control-reset',['-o','-R','-p'],[RESET,0,0])]:
        r=target_call(ref,label,True,flags)
        assert r['status']==0 and r['data'].get('result')=='0' and r['before']==[0,0,0] and r['after']==expected and not r['err']
    for flag,policy in [('-o',0),('-b',3),('-i',5)]:
        r=command(ref,'control-'+flag[1:],True,[flag],0)
        assert r['status']==0 and r['data'].get('result')=='7' and r['probe'] and r['probe']['policy']==policy and r['probe']['arguments']==['with spaces','','-leading']
    target=Target('control-deadline')
    try:
        invalid=kernel_deadline(target,3000000,2000000,4000000);valid=kernel_deadline(target,1000000,10000000,10000000)
        assert invalid==(-1,errno.EINVAL) and valid==(-1,errno.EPERM) and target.policies()==[0,0,0]
    finally:target.close()
    record('controls',which=which,owned_thread_policies='verified',reference_command='verified',deadline_kernel=[invalid,valid])
    print('controls=verified')


def same_parent(r):return r['status']==0 and r['data'].get('before')==r['data'].get('after')=='0'


def command_case(shell):
    results={}
    for name,flags,expected in [('other',['-o'],0),('batch',['-b'],3),('idle',['-i'],5),('reset',['-o','-R'],RESET)]:
        r=command(shell,'candidate-'+name,False,flags,0)
        results[name]=same_parent(r) and r['data'].get('result')=='7' and r['probe'] is not None and r['probe']['policy']==expected and r['probe']['priority']==0 and r['probe']['arguments']==['with spaces','','-leading']
    sig=command(shell,'candidate-signal',False,['-o'],0,'signal')
    signal_ok=same_parent(sig) and sig['data'].get('result')=='143' and sig['probe'] is not None
    invalid=[]
    for i,(flag,priority) in enumerate([('-o',1),('-b',1),('-i',1),('-f',0),('-f',100),('-r',0),('-r',100)]):
        c=command(shell,'invalid-c-%d'%i,False,[flag],priority);r=command(shell,'invalid-r-%d'%i,True,[flag],priority)
        invalid.append(same_parent(c) and same_parent(r) and c['data'].get('result')==r['data'].get('result')=='1' and c['probe'] is None and r['probe'] is None and bool(c['err']) and bool(r['err']))
    denied=[]
    for i,flag in enumerate(('-f','-r')):
        c=command(shell,'denied-c-%d'%i,False,[flag],1);r=command(shell,'denied-r-%d'%i,True,[flag],1)
        denied.append(same_parent(c) and same_parent(r) and c['data'].get('result')==r['data'].get('result')=='1' and c['probe'] is None and r['probe'] is None and b'Operation not permitted' in c['err'] and b'Operation not permitted' in r['err'])
    record('command-outcome',policies=results,signal=signal_ok,invalid=invalid,denied=denied)
    print('chrt-command other=%s batch=%s idle=%s reset=%s args=%s exit-signal=%s invalid=%s privileged-deny=%s parent=%s' %
          (yes(results['other']),yes(results['batch']),yes(results['idle']),yes(results['reset']),yes(all(results.values())),yes(signal_ok),yes(all(invalid)),yes(all(denied)),yes(all(results.values()) and signal_ok)))


def pid_case(shell):
    main=target_call(shell,'candidate-main',False,['-b','-p']);alltasks=target_call(shell,'candidate-all',False,['-b','-a','-p']);reset=target_call(shell,'candidate-reset',False,['-o','-R','-p'])
    single=same_parent(main) and main['data'].get('result')=='0' and main['before']==[0,0,0] and main['after']==[3,0,0] and not main['err']
    every=same_parent(alltasks) and alltasks['data'].get('result')=='0' and alltasks['before']==[0,0,0] and alltasks['after']==[3,3,3] and not alltasks['err']
    flag=same_parent(reset) and reset['data'].get('result')=='0' and reset['after']==[RESET,0,0] and not reset['err']
    target=Target('candidate-errors')
    try:
        before=target.policies();target.check()
        vals=[(3000000,2000000,4000000,errno.EINVAL),(1000000,3000000,2000000,errno.EINVAL),(512,1000000,1000000,errno.EINVAL),(1000000,10000000,10000000,errno.EPERM)]
        deadline=[]
        for runtime,end,period,want in vals:
            k=kernel_deadline(target,runtime,end,period)
            args=['-d','-T',str(runtime),'-D',str(end),'-P',str(period),'-p','0',str(target.p.pid)]
            c=invoke(shell,False,args);r=invoke(shell,True,args)
            expected=os.strerror(want).encode()
            deadline.append(k==(-1,want) and same_parent(c) and same_parent(r) and c['data'].get('result')==r['data'].get('result')=='1' and expected in c['err'] and expected in r['err'] and target.policies()==before)
        nonexistent=2147483647;assert not Path('/proc/%d'%nonexistent).exists()
        failures=[]
        for args,needle in [(['-b','-p','0',str(nonexistent)],b'No such process'),(['-f','-p','1',str(target.p.pid)],b'Operation not permitted')]:
            c=invoke(shell,False,args);r=invoke(shell,True,args)
            failures.append(same_parent(c) and same_parent(r) and c['data'].get('result')==r['data'].get('result')=='1' and needle in c['err'] and needle in r['err'] and target.policies()==before)
        c=invoke(shell,False,['-p','bad-pid']);r=invoke(shell,True,['-p','bad-pid'])
        failures.append(same_parent(c) and same_parent(r) and c['data'].get('result')==r['data'].get('result')=='1' and bool(c['err']) and bool(r['err']) and target.policies()==before)
    finally:target.close()
    record('pid-outcome',single=single,all_tasks=every,reset=flag,deadline=deadline,failures=failures)
    print('chrt-pid single=%s all-tasks=%s reset=%s deadline=%s failures=%s' % (yes(single),yes(every),yes(flag),yes(all(deadline)),yes(all(failures))))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='target':child_target(sys.argv[2])
        elif len(sys.argv)>=4 and sys.argv[1]=='probe':child_probe(sys.argv[2],sys.argv[3],sys.argv[4:])
        elif len(sys.argv)==3 and sys.argv[1]=='setup':setup(sys.argv[2])
        else:
            shell,mode=sys.argv[1:];{'command':command_case,'pid':pid_case}[mode](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
