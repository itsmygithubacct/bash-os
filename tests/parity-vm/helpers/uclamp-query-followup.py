#!/usr/bin/python3
"""Guest-only owned-process UCLAMP query and seccomp-control observer."""
import ctypes,json,os,re,select,signal,subprocess,sys,time,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case')
SEQ='/opt/bashos-parity/harness/helpers/system-sequence.py'
TASK='/opt/bashos-parity/harness/helpers/uclamp-owned-task.py'
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
    p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=5)
        raise subprocess.TimeoutExpired(argv,20,output=out,stderr=err)
    return {'argv':argv,'status':p.returncode,'stdout':out.decode('utf8','backslashreplace'),'stderr':err.decode('utf8','backslashreplace')}
def filtered(argv):return ['/usr/bin/python3','-I',SEQ,'--kill','sched_setattr','--']+argv
def save(v): (H/'query-report.json').write_text(json.dumps(v,sort_keys=True)+'\n')
def saved_p0():
    result={}
    for name in ('p0-opstatus','p0-operation.out','p0-operation.err'):
        try:
            fd=os.open(H/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                data=os.read(fd,65537)
                if len(data)>65536:raise ValueError('p0 observation exceeds cap')
                result[name]=data.decode('utf8','backslashreplace')
            finally:os.close(fd)
        except FileNotFoundError:result[name]=None
    return result
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
    mode,shell=sys.argv[1:3];report={'mode':mode,'control_valid':False,'candidate_checks':{},'events':{}}
    p=None
    try:
        kill=run(filtered(['/usr/bin/python3','-I','-c','import ctypes;ctypes.CDLL(None).syscall(314,0,0,0)']))
        report['events']['filter_kill_control']=kill
        if kill['status']!=159:raise RuntimeError('kill-filter positive control failed')
        taskmode='empty' if mode=='empty' else 'threads' if mode=='threads' else 'single'
        p=subprocess.Popen(['/usr/bin/python3','-I',TASK,taskmode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        task=json.loads(read_line(p.stdout));report['events']['task_self_read']=task
        ids=[task['tid']]+[x['tid'] for x in task['peers']]
        if len(ids)!=len(set(ids)) or task['tid']!=task['pid']:raise RuntimeError('owned task identity differs')
        before={str(t):get(t) for t in ids}
        self_records=[{'tid':task['tid'],'attr':task['self_attr']}]+task['peers']
        if any(x['attr']!=before[str(x['tid'])] for x in self_records):raise RuntimeError('thread self-read and independent per-TID readback differ')
        if mode=='threads' and (len(ids)!=3 or {(x['attr']['util_min'],x['attr']['util_max']) for x in task['peers']}!={(100,900),(200,800)} or len({(x['util_min'],x['util_max']) for x in before.values()})!=3):raise RuntimeError('seeded per-thread clamp values differ or are not distinct')
        report['events']['before']=before
        opts=['-a','-p',str(task['pid'])] if mode=='threads' else ['-p',str(task['pid'])]
        native=run(filtered(['/usr/bin/uclampset',*opts]));report['events']['native']=native
        if native['status']!=0:raise RuntimeError('native query control failed')
        pattern=re.compile(r'^(.*) \(([0-9]+)\) util_clamp: min: ([0-9]+) max: ([0-9]+)$')
        def parsed(output):
            rows=[pattern.fullmatch(x) for x in output.splitlines()]
            if any(x is None for x in rows):return None
            return [(x.group(1),int(x.group(2)),int(x.group(3)),int(x.group(4))) for x in rows]
        want={t:(before[str(t)]['util_min'],before[str(t)]['util_max']) for t in ids}
        native_rows=parsed(native['stdout'])
        native_ok=(native_rows is not None and len(native_rows)==len(ids) and {t:(lo,hi) for _,t,lo,hi in native_rows}==want and len({r[1] for r in native_rows})==len(ids))
        if not native_ok:raise RuntimeError('native output control differs')
        report['control_valid']=True
        if mode=='p0':
            script='printf "%s\\n" "$$" > "$HOME/p0-pid"; /usr/bin/python3 -I "$1" read "$$" > "$HOME/p0-before" || exit 125; uclampset -p 0 > "$HOME/p0-operation.out" 2> "$HOME/p0-operation.err"; r=$?; printf "%s\\n" "$r" > "$HOME/p0-opstatus"; /usr/bin/python3 -I "$1" read "$$" > "$HOME/p0-after" || exit 125; exit "$r"'
            try:candidate=run(filtered([shell,'--noprofile','--norc','-c',script,'query-p0',str(Path(__file__))]))
            except subprocess.TimeoutExpired as timeout:
                report['events']['candidate_transport_timeout']={'stdout':(timeout.output or b'').decode('utf8','backslashreplace'),'stderr':(timeout.stderr or b'').decode('utf8','backslashreplace')}
                report['events']['p0_retained']=saved_p0();save(report)
                raise
            report['events']['candidate_transport']=candidate;report['events']['p0_retained']=saved_p0();save(report)
            opstatus=int((H/'p0-opstatus').read_text());report['events']['p0_operation_status']=opstatus;report['candidate_checks']={'operation_status':opstatus==0};save(report)
            candidate=dict(candidate,stdout=(H/'p0-operation.out').read_text(),stderr=(H/'p0-operation.err').read_text())
            pid=int((H/'p0-pid').read_text());a=json.loads((H/'p0-before').read_text());b=json.loads((H/'p0-after').read_text());rows=parsed(candidate['stdout'])
            checks={'status':candidate['status']==0 and opstatus==0,'real_pid':rows is not None and len(rows)==1 and rows[0][1]==pid,'values':rows is not None and len(rows)==1 and rows[0][2:]==(a['util_min'],a['util_max']),'unchanged':a==b,'stderr':candidate['stderr']==''}
            report['events'].update(p0_pid=pid,p0_before=a,p0_after=b)
        else:
            candidate=run(filtered([shell,'--noprofile','--norc','-c','uclampset "$@"','query',*opts]))
            report['events']['candidate']=candidate;report['candidate_checks']={'status':candidate['status']==0};save(report)
            rows=parsed(candidate['stdout'])
            after={str(t):get(t) for t in ids}
            checks={'status':candidate['status']==0,'format_and_values':rows is not None and len(rows)==len(ids) and {t:(lo,hi) for _,t,lo,hi in rows}==want and len({r[1] for r in rows})==len(ids),'unchanged':before==after,'stderr':candidate['stderr']==''}
            if mode=='self':checks['native_bytes']=candidate['stdout']==native['stdout']
            if mode=='empty':checks['empty_comm_fallback']=bool(rows and rows[0][0]==str(task['pid']))
            if mode=='self':checks['self_read_matches']=(task['self_attr']==before[str(task['tid'])])
            report['events']['after']=after
        report['events'].update(candidate=candidate,before=before);report['candidate_checks']=checks
        save(report)
        if not all(checks.values()):raise SystemExit(1)
        print('owned uclamp query checks ok')
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,subprocess.TimeoutExpired) as e:
        report['incomplete']=type(e).__name__+': '+str(e);save(report);raise SystemExit(125)
    finally:
        if p is not None:
            try:p.stdin.write(b'exit\n');p.stdin.flush();p.wait(timeout=5)
            except (BrokenPipeError,subprocess.TimeoutExpired):p.kill();p.wait()
if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='read':print(json.dumps(get(int(sys.argv[2])),sort_keys=True))
    else:main()
