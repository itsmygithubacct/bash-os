#!/usr/bin/python3
"""Guest-only notification observer: log the selected getattr then reply ESRCH."""
import ctypes,errno,fcntl,importlib.util,json,os,select,signal,struct,sys
from pathlib import Path

if len(sys.argv)<5 or sys.argv[3]!='--':raise SystemExit(125)
target=int(sys.argv[1]);log=Path(sys.argv[2]);program=sys.argv[4:]
if target<=1 or log.parent!=Path('/tmp/parity-home') or not log.name.endswith('.jsonl'):raise SystemExit(125)
source='/opt/bashos-parity/harness/helpers/system-sequence.py'
spec=importlib.util.spec_from_file_location('target_seq',source);seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq)
state={'supervisor_completed':False,'program_status':None}
def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,unused):
    status=None
    try:
        with log.open('x') as out:
            count=0
            while status is None:
                done,wstatus=os.waitpid(child,os.WNOHANG)
                if done:status=wstatus;break
                if not select.select([listener],[],[],0.05)[0]:continue
                req=bytearray(80)
                try:fcntl.ioctl(listener,seq.NOTIF_RECV,req,True)
                except OSError as e:
                    if e.errno in (errno.ENOENT,errno.EINTR):continue
                    raise
                ident,caller,_,nr,_,_=struct.unpack_from('<QIIiIQ',req);args=struct.unpack_from('<6Q',req,32)
                raw=lib.seccomp_syscall_resolve_num_arch(0,nr);name=ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                tid=args[0]&0xffffffff;inject=name=='sched_getattr' and tid==target
                entry={'kind':'request','id':ident,'syscall':name,'arg0':tid,'caller':caller,'requested_reply':'errno:3' if inject else 'continue'}
                count+=1
                if count>128:raise RuntimeError('notification bound exceeded')
                out.write(json.dumps(entry,sort_keys=True)+'\n');out.flush();os.fsync(out.fileno())
                response=struct.pack('<QqiI',ident,0,-errno.ESRCH if inject else 0,0 if inject else seq.FLAG_CONTINUE)
                fcntl.ioctl(listener,seq.NOTIF_SEND,response)
                ack={'kind':'send-ack','id':ident,'syscall':name,'arg0':tid,'sent_reply':entry['requested_reply']}
                out.write(json.dumps(ack,sort_keys=True)+'\n');out.flush();os.fsync(out.fileno())
    finally:
        if status is None:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
    state['program_status']=os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 128+os.WTERMSIG(status)
    state['supervisor_completed']=True
    return status
seq.supervise=supervise
sys.argv=[source,'--notify','sched_getattr','--notify','sched_setattr','--',*program]
outcome={'schema':'uclamp-notify-outcome-v1','target':target,'observer_status':'incomplete','program_status':None}
rc=125
try:
    try:seq.main()
    except SystemExit as e:
        if type(e.code) is int:rc=e.code
        if state['supervisor_completed'] and rc==state['program_status']:
            outcome.update(observer_status='completed',program_status=state['program_status'])
except BaseException as e:
    outcome['observer_error']=(type(e).__name__+': '+str(e))[:500]
finally:
    path=log.with_suffix('.outcome.json')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'w') as out:
        json.dump(outcome,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
sys.exit(rc)
