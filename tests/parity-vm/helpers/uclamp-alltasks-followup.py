#!/usr/bin/python3
"""Guest-only all-task preflight and syscall sequence observer."""
import ctypes,json,os,select,subprocess,sys,time,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case')
SEQ='/opt/bashos-parity/harness/helpers/system-sequence.py';TASK='/opt/bashos-parity/harness/helpers/uclamp-owned-task.py';ERRNO_SEQ='/opt/bashos-parity/harness/helpers/uclamp-target-errno-sequence.py'
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
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
    return {'argv':argv,'status':p.returncode,'stdout':p.stdout.decode('utf8','backslashreplace'),'stderr':p.stderr.decode('utf8','backslashreplace')}
def seq(target,cmd,tag):
    log=H/(tag+'.jsonl')
    argv=(['/usr/bin/python3','-I',ERRNO_SEQ,str(target),str(log),'--',*cmd] if target is not None else
          ['/usr/bin/python3','-I',SEQ,'--notify','sched_getattr','--notify','sched_setattr','--log',str(log),'--log-args','sched_getattr=0','--log-args','sched_setattr=0','--',*cmd])
    result=run(argv)
    try:result['trace']=[json.loads(x) for x in log.read_text().splitlines()] if log.exists() else None
    except (OSError,ValueError,TypeError) as e:result['trace']=None;result['trace_error']=str(e)
    if target is not None:
        try:result['observer_outcome']=json.loads(log.with_suffix('.outcome.json').read_text())
        except (OSError,ValueError,TypeError) as e:result['observer_outcome']=None;result['observer_error']=str(e)
    return result
def delivery(result,target):
    outcome=result.get('observer_outcome');trace=result.get('trace')
    if not isinstance(outcome,dict) or outcome.get('schema')!='uclamp-notify-outcome-v1' or outcome.get('target')!=target or outcome.get('observer_status')!='completed' or type(outcome.get('program_status')) is not int or outcome['program_status']!=result['status'] or not isinstance(trace,list):return False
    calls=[e for e in trace if e.get('kind')=='request' and e.get('syscall')=='sched_getattr' and e.get('arg0')==target and e.get('requested_reply')=='errno:3']
    if len(calls)!=1:return False
    sent=[(i,e) for i,e in enumerate(trace) if e.get('kind')=='send-ack' and e.get('id')==calls[0].get('id') and e.get('syscall')=='sched_getattr' and e.get('arg0')==target and e.get('sent_reply')=='errno:3']
    return len(sent)==1 and sent[0][0]>trace.index(calls[0])
def save(v):(H/'alltasks-report.json').write_text(json.dumps(v,sort_keys=True)+'\n')
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
def main():
    mode,shell=sys.argv[1:3];report={'mode':mode,'control_valid':False,'candidate_checks':{},'events':{}};p=None
    try:
        p=subprocess.Popen(['/usr/bin/python3','-I',TASK,'threads'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        task=json.loads(read_line(p.stdout));ids=[int(x) for x in os.listdir('/proc/%d/task'%task['pid'])];owned={task['tid'],*[v['tid'] for v in task['peers']]}
        if len(ids)!=3 or len(set(ids))!=3 or set(ids)!=owned:raise RuntimeError('owned thread inventory differs')
        last=ids[-1];events=report['events'];events['task_self_read']=task;events['enumerated_tids']=ids
        native=seq(None,['/usr/bin/uclampset','-a','-m','100','-M','900','-p',str(task['pid'])],'native-alltasks')
        snapshot=lambda:{str(t):get(t) for t in ids}
        native_after=snapshot();events['native']=native;events['native_after']=native_after
        if native['status']!=0 or any((x['util_min'],x['util_max'])!=(100,900) for x in native_after.values()) or not isinstance(native['trace'],list) or {e.get('arg0') for e in native['trace'] if e.get('syscall')=='sched_getattr'}!=set(ids) or {e.get('arg0') for e in native['trace'] if e.get('syscall')=='sched_setattr'}!=set(ids):raise RuntimeError('native all-thread control failed')
        reset=run(['/usr/bin/uclampset','-a','-m','0','-M','1024','-p',str(task['pid'])]);events['reset_control']=reset
        if reset['status']!=0:raise RuntimeError('native all-thread reset failed')
        if mode=='validation':
            seed=run(['/usr/bin/uclampset','-M','100','-p',str(last)]);events['seed_control']=seed
            if seed['status']!=0 or get(last)['util_max']!=100:raise RuntimeError('late-thread setup failed')
            extra=None;args=['-a','-m','900','-p',str(task['pid'])]
        elif mode=='readfail':
            control=seq(last,['/usr/bin/uclampset','-p',str(last)],'native-readfail');events['readfail_control']=control
            if not delivery(control,last) or control['observer_outcome']['program_status']==0 or not control['stderr']:raise RuntimeError('read-failure notification delivery or program control failed')
            extra=last;args=['-a','-m','100','-p',str(task['pid'])]
        elif mode=='success':extra=None;args=['-a','-m','100','-M','900','-p',str(task['pid'])]
        else:raise RuntimeError('unknown mode')
        before=snapshot();events['before']=before;report['control_valid']=True
        cand=seq(extra,[shell,'--noprofile','--norc','-c','uclampset "$@"','alltasks',*args],'candidate-alltasks');events['candidate']=cand;save(report)
        if mode=='readfail' and not delivery(cand,last):raise RuntimeError('candidate read-failure delivery or observer outcome not established')
        after=snapshot();events['after']=after;trace=cand['trace']
        if not isinstance(trace,list):raise RuntimeError('candidate trace absent')
        gets=[e for e in trace if e.get('syscall')=='sched_getattr' and e.get('kind','request')=='request'];sets=[e for e in trace if e.get('syscall')=='sched_setattr' and e.get('kind','request')=='request']
        if mode=='success':
            first_set=next((j for j,e in enumerate(trace) if e.get('syscall')=='sched_setattr'),len(trace))
            checks={'status':cand['status']==0,'get_each':[e.get('arg0') for e in gets]==ids,'set_each':[e.get('arg0') for e in sets]==ids,'get_before_set':len(trace)==2*len(ids) and first_set==len(ids) and all(e.get('syscall')=='sched_getattr' for e in trace[:first_set]),'readback':all((x['util_min'],x['util_max'])==(100,900) for x in after.values())}
        else:
            checks={'rejected':cand['status']!=0 and bool(cand['stderr']),'no_sets':not sets,'unchanged':before==after}
            if mode=='validation':checks['later_thread_read']=[e.get('arg0') for e in gets]==ids
            else:
                checks['prior_thread_reads']=[e.get('arg0') for e in gets]==ids
                checks['later_failure_witness']=(len(gets)==len(ids) and gets[-1].get('arg0')==last and gets[-1].get('requested_reply')=='errno:3' and delivery(cand,last))
        report['candidate_checks']=checks;save(report)
        if not all(checks.values()):raise SystemExit(1)
        print('owned uclamp all-task checks ok')
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,subprocess.TimeoutExpired) as e:
        report['incomplete']=type(e).__name__+': '+str(e);save(report);raise SystemExit(125)
    finally:
        if p is not None:
            try:p.stdin.write(b'exit\n');p.stdin.flush();p.wait(timeout=5)
            except (BrokenPipeError,subprocess.TimeoutExpired):p.kill();p.wait()
if __name__=='__main__':main()
