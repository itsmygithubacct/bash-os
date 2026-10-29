#!/usr/bin/python3
"""Disposable-VM owned-target uclamp observer, no host or global changes."""
import ctypes,errno,json,os,platform,subprocess,sys,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case')
if os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=C or os.environ.get('HOME')!=str(H): raise SystemExit(125)
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or platform.machine()!='x86_64' or platform.release()!='7.2.11+deb13-amd64': raise SystemExit(125)
try: uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
except (OSError,ValueError): raise SystemExit(125)
class A(ctypes.Structure):
    _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
L=ctypes.CDLL(None,use_errno=True);L.syscall.restype=ctypes.c_long
def get(pid):
    a=A();a.size=ctypes.sizeof(a);ctypes.set_errno(0)
    if L.syscall(315,pid,ctypes.byref(a),ctypes.sizeof(a),0): raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return {k:getattr(a,k) for k,_ in A._fields_}
def save(name,data): (H/name).write_text(json.dumps(data,sort_keys=True)+'\n')
def run(argv):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    return {'argv':argv,'status':p.returncode,'stdout':p.stdout.decode('utf-8','backslashreplace'),'stderr':p.stderr.decode('utf-8','backslashreplace')}
def main():
    mode=sys.argv[1]
    if mode=='read': print(json.dumps(get(int(sys.argv[2])),sort_keys=True));return
    if mode=='child': print(json.dumps({'attr':get(0),'argv':sys.argv[2:]},sort_keys=True));sys.exit(7)
    proc=subprocess.Popen(['/usr/bin/python3','-c','import sys; sys.stdin.buffer.read(1)'],stdin=subprocess.PIPE)
    pid=proc.pid;events=[];refproc=None
    def record(label,op,after):
        events.append({'label':label,'operation':op,'after':after});save('uclamp-events.json',events)
    try:
        before=get(pid);save('uclamp-before.json',before)
        if mode=='preflight':
            check=run(['/usr/bin/uclampset','-m','100','-M','900','-p',str(pid)])
            actual=get(pid);record('independent-util-linux-control',check,actual)
            if check['status']!=0 or (actual['util_min'],actual['util_max'])!=(100,900):
                print('SETUP-INVALID uclamp kernel or util-linux control: '+check['stderr'],file=sys.stderr);sys.exit(125)
            reset=run(['/usr/bin/uclampset','-m','-1','-M','-1','-p',str(pid)])
            reset_attr=get(pid);record('independent-reset-control',reset,reset_attr)
            if reset['status']!=0 or (reset_attr['util_min'],reset_attr['util_max'])!=(0,1024): sys.exit(125)
            command=run(['/usr/bin/uclampset','-m','100','-M','800','/usr/bin/python3','-I',str(Path(__file__)),'child','a b',''])
            try: payload=json.loads(command['stdout'])
            except (ValueError,TypeError): sys.exit(125)
            record('independent-command-control',command,payload)
            if command['status']!=7 or payload['argv']!=['a b',''] or (payload['attr']['util_min'],payload['attr']['util_max'])!=(100,800): sys.exit(125)
            print('uclamp positive control ok');return
        shell=sys.argv[2]
        def candidate(args): return run([shell,'--noprofile','--norc','-c','uclampset "$@"','uclamp',*args])
        if mode=='query':
            ref=run(['/usr/bin/uclampset','-p',str(pid)]);op=candidate(['-p',str(pid)]);record('query',op,None);after=get(pid);events[-1]['after']=after;save('uclamp-events.json',events)
            save('uclamp-reference.json',ref)
            comm=Path('/proc/%d/comm'%pid).read_text().strip() or str(pid)
            expected=f"{comm} ({pid}) util_clamp: min: {before['util_min']} max: {before['util_max']}\n"
            ok=ref['status']==0 and ref['stdout']==expected and op['status']==0 and op['stdout']==expected and op['stderr']=='' and before==after
        elif mode=='setter':
            steps=[(['-m','100'],(100,before['util_max']),0),(['-M','800'],(100,800),0),(['-m','200','-M','700'],(200,700),0),(['-m','-1','-M','-1'],(0,1024),0),(['-m','900','-M','100'],(0,1024),1)]
            refproc=subprocess.Popen(['/usr/bin/python3','-c','import sys; sys.stdin.buffer.read(1)'],stdin=subprocess.PIPE)
            refs=[];ok=True
            for i,(options,values,status) in enumerate(steps):
                prior=get(pid);op=candidate([*options,'-p',str(pid)]);record(str(i),op,None);after=get(pid);events[-1]['after']=after;save('uclamp-events.json',events)
                ok &= op['status']==status and (after['util_min'],after['util_max'])==values
                ok &= (after['policy'],after['nice'],after['priority'],after['runtime'],after['deadline'],after['period'])==(prior['policy'],prior['nice'],prior['priority'],prior['runtime'],prior['deadline'],prior['period'])
                if status: ok &= bool(op['stderr']) and after==prior
                ref=run(['/usr/bin/uclampset',*options,'-p',str(refproc.pid)]);refattr=get(refproc.pid);refs.append({'operation':ref,'after':refattr});save('uclamp-reference.json',refs)
                # Reversed-pair error is candidate contract; util-linux is recorded but not imposed.
                if status==0: ok &= ref['status']==0 and (refattr['util_min'],refattr['util_max'])==values
            refproc.stdin.close();refproc.wait(timeout=5)
        else: raise ValueError('bad mode')
        save('uclamp-check.json',{'pass':bool(ok),'mode':mode,'target_pid':pid})
        if not ok: sys.exit(1)
        print('uclamp '+mode+' checks ok')
    finally:
        if refproc is not None and refproc.poll() is None:
            refproc.stdin.close()
            try: refproc.wait(timeout=5)
            except subprocess.TimeoutExpired: refproc.kill();refproc.wait()
        proc.stdin.close()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill();proc.wait()
if __name__=='__main__': main()
