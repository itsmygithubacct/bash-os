#!/usr/bin/python3
"""Guest-only disposable UID-2000 fixture for bounded su failure observations."""
import base64,fcntl,hashlib,importlib.util,json,os,pty,re,select,signal,stat,subprocess,sys,termios,time,uuid
from pathlib import Path
CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home');OBS='/opt/bashos-parity/harness/helpers/su-notify-observer-r1.py';KDF='/opt/bashos-parity/harness/helpers/auth-client-argon2-cli-r1.py';DEVICE=Path('/dev/bashos-auth');PASSWORD=b'password'

def guard():
    if not __debug__ or os.getresuid()!=(2000,2000,2000) or os.getresgid()!=(2000,2000,2000) or Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME):raise RuntimeError('fixture identity')
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise RuntimeError('fixture guest')

def absent():
    try:DEVICE.lstat()
    except FileNotFoundError:return True
    return False

def put(kind,**data):
    data['kind']=kind;data['monotonic_ns']=time.monotonic_ns()
    with (HOME/'su-bounded-observations.jsonl').open('a') as f:f.write(json.dumps(data,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())

def parse_status_record(output):
    """Parse one complete canonical integer record from a PTY byte stream."""
    if not isinstance(output,bytes) or output.count(b'su-status')!=1:
        raise ValueError('status record missing or duplicated')
    records=list(re.finditer(rb'(?m)^su-status=(0|[1-9][0-9]{0,2})\r?\n',output))
    if len(records)!=1:
        raise ValueError('status record malformed or truncated')
    value=int(records[0].group(1))
    if value>255:
        raise ValueError('status outside shell exit range')
    return value


def rows(name):
    p=HOME/('su-bounded-'+name+'.jsonl');return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

def config(label,mode,program):
    armed=HOME/('su-bounded-'+label+'.armed');child=HOME/('su-bounded-'+label+'.child');trace=HOME/('su-bounded-'+label+'.jsonl')
    for p in (armed,child,trace):
        if p.exists():raise RuntimeError('reused fixture artifacts')
    c=CASE/('su-bounded-'+label+'.config');c.write_text(json.dumps({'mode':mode,'trace':str(trace),'armed':str(armed),'child_file':str(child),'program':program}));return c,armed,child,trace

def bounded(label,mode,program,argv,env,tty=False,send_password=False):
    cfg,armed,child,trace=config(label,mode,program);cmd=['/usr/bin/python3',OBS,str(cfg),program,*argv];output=bytearray();echo_off=None;sent=False
    master=slave=None
    def init_tty():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    if tty:
        master,slave=pty.openpty();before=termios.tcgetattr(master)
        p=subprocess.Popen(cmd,cwd=CASE,env=env,stdin=slave,stdout=slave,stderr=slave,preexec_fn=init_tty,close_fds=True)
    else:
        p=subprocess.Popen(cmd,cwd=CASE,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    timed=False
    try:
        if not tty:
            try:data,_=p.communicate(timeout=25);output.extend(data)
            except subprocess.TimeoutExpired as exc:
                timed=True;output.extend(exc.output or b'')
        else:
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],.05)
                if ready:
                    try:chunk=os.read(master,4096)
                    except OSError:chunk=b''
                    output.extend(chunk)
                    with (HOME/('su-bounded-'+label+'.output')).open('wb') as retained:
                        retained.write(output);retained.flush();os.fsync(retained.fileno())
                    if len(output)>65536:raise RuntimeError('output cap')
                if send_password and not sent and b'Password: ' in output:
                    echo_off=not bool(termios.tcgetattr(master)[3]&termios.ECHO);os.write(master,PASSWORD+b'\n');sent=True
                if p.poll() is not None:
                    for _ in range(4):
                        ready,_,_=select.select([master],[],[],.03)
                        if ready:
                            try:output.extend(os.read(master,4096))
                            except OSError:break
                    break
            if p.poll() is None:timed=True
            after=termios.tcgetattr(master)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=4)
        if tty:os.close(master);os.close(slave)
    result={'label':label,'mode':mode,'observer_exit':p.returncode,'timeout':timed,'output_base64':base64.b64encode(output).decode(),'password_sent':sent,'echo_off':echo_off,'tty_restored':before==after if tty else None,'trace_exists':trace.exists(),'device_absent_after':absent()}
    put('run-retained',**result)
    return result,rows(label)

CONTROL_FORK='''import errno,os\nfrom pathlib import Path\nPath(os.environ["ARMED"]).write_text(str(os.getpid())+"\\n")\ntry: os.fork()\nexcept OSError as e:\n assert e.errno==errno.EAGAIN\n print("native-fork-eagain=ok")\nelse: raise RuntimeError("fork was not denied")\n'''
CONTROL_WAIT='''import ctypes,errno,os\nfrom pathlib import Path\nPath(os.environ["ARMED"]).write_text(str(os.getpid())+"\\n")\np=os.fork()\nif p==0:\n assert ctypes.CDLL(None,use_errno=True).prctl(4,0,0,0,0)==0\n os._exit(7)\ntry: os.waitpid(p,0)\nexcept OSError as e: assert e.errno==errno.ECHILD\nelse: raise RuntimeError("wait was not denied")\npid,status=os.waitpid(p,0)\nassert pid==p and os.WIFEXITED(status) and os.WEXITSTATUS(status)==7\nprint("native-wait-echild-reap=ok")\n'''
CONTROL_EXEC='''import errno,os\ntry: os.execve("/bin/true",["/bin/true"],{})\nexcept OSError as e: assert e.errno==errno.EACCES\nelse: raise RuntimeError("exec not intercepted")\nprint("native-exec-denied=ok")\n'''
REAPER='''import json,os,sys\npid=int(sys.argv[1]);got,status=os.waitpid(pid,0)\nassert got==pid and os.WIFEXITED(status)\nprint("owned-reap=%d:%d"%(got,os.WEXITSTATUS(status)))\n'''
CANDIDATE='''IFS= read -r __uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__uuid =~ ^[0-9a-fA-F-]{36}$ && $__vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case ]] || exit 125
printf '%s\\n' "$BASHPID" > "$ARMED" || exit 125
su --no-login -c ': > /tmp/parity-case/su-target-marker' fixture; rc=$?
printf 'su-status=%s\\n' "$rc"
if [[ $MODE == wait ]]; then
 IFS= read -r child < "$CHILD_FILE" || exit 125
 exec /usr/bin/python3 -I -B /tmp/parity-case/su-owned-reaper.py "$child"
fi
exit 0
'''

def invoke(label,mode,program,argv,tty=False,send_password=False,env=None):
    full=dict(os.environ);full.update(env or {});full['ARMED']=str(HOME/('su-bounded-'+label+'.armed'));full['CHILD_FILE']=str(HOME/('su-bounded-'+label+'.child'));full['MODE']=mode
    return bounded(label,mode,program,argv,full,tty,send_password)

def setup():
    if not absent():raise RuntimeError('authority device present')
    spec=importlib.util.spec_from_file_location('argon_cli',KDF);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    rec=lambda kind,**kw:put(kind,**kw)
    if m.derive(b'password',b'somesalt',2,65536,1,32,rec).hex()!='09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7':raise RuntimeError('argon KAT')
    digest=m.derive(PASSWORD,b'somesalt',1,1024,1,32,rec)
    phc='$argon2id$v=19$m=1024,t=1,p=1$'+b'somesalt'.hex()+'$'+digest.hex()
    db=CASE/'su-bounded-db';db.mkdir(mode=0o700);(db/'passwd').write_text('fixture:x:2000:2000:Fixture:'+str(HOME)+':/tmp/parity-case/su-target-shell\n');(db/'group').write_text('fixture:x:2000:\n');(db/'shadow').write_text('fixture:'+phc+':19000:0:99999:7:::\n');os.chmod(db/'shadow',0o600)
    (CASE/'su-target-shell').write_text('#!/bin/sh\nprintf TARGET-EXECUTED > /tmp/parity-case/su-target-marker\n');os.chmod(CASE/'su-target-shell',0o700)
    (CASE/'su-owned-reaper.py').write_text(REAPER)
    for name,src in [('fork',CONTROL_FORK),('wait',CONTROL_WAIT),('exec',CONTROL_EXEC)]:
        p=CASE/('su-native-'+name+'.py');p.write_text(src);mode='control-'+name
        result,events=invoke('control-'+name,mode,'/usr/bin/python3',['-I','-B',str(p)])
        expected={'fork':'native-fork-eagain=ok','wait':'native-wait-echild-reap=ok','exec':'native-exec-denied=ok'}[name]
        if result['observer_exit']!=0 or expected.encode() not in base64.b64decode(result['output_base64']):raise RuntimeError('independent control '+name)
        injected=[x for x in events if x.get('phase') in ('armed-owned-parent-creation','owned-wait-injection','independent-positive-exec') and x.get('reply','').startswith('errno:')]
        if len(injected)!=1 or not injected[0].get('notifying',{}).get('birth'):raise RuntimeError('independent attribution '+name)
        put('native-control',name=name,notification=injected[0])
    if not absent():raise RuntimeError('authority appeared')
    put('setup-complete',authority_absent=True,passwd_sha256=hashlib.sha256((db/'passwd').read_bytes()).hexdigest(),shadow_sha256=hashlib.sha256((db/'shadow').read_bytes()).hexdigest(),group_sha256=hashlib.sha256((db/'group').read_bytes()).hexdigest())
    print('controls=verified')

def run(shell,mode):
    if not absent():raise RuntimeError('authority device present')
    db=CASE/'su-bounded-db';env={'PHCLIB_PASSWD':str(db/'passwd'),'PHCLIB_SHADOW':str(db/'shadow'),'PHCLIB_GROUP':str(db/'group'),'BPW_LOCK_DIR':str(CASE/'su-bounded-lock'),'PHCLIB_M':'1024','PHCLIB_T':'1','PHCLIB_P':'1'}
    result,events=invoke('candidate',mode,shell,['--noprofile','--norc','-c',CANDIDATE],tty=True,send_password=mode in ('noexec','wait'),env=env)
    out=base64.b64decode(result['output_base64']);subject=[x for x in events if x.get('phase') in ('actual-unemulated-authority-open','armed-owned-parent-creation','owned-wait-injection','unexpected-target-exec')]
    put('candidate-raw-assertions',mode=mode,observer_exit=result['observer_exit'],timeout=result['timeout'],output_base64=result['output_base64'],subject_events=subject,marker_exists=(CASE/'su-target-marker').exists(),authority_absent=absent())
    if mode=='fork':
        reached=[x for x in subject if x.get('phase')=='armed-owned-parent-creation' and x.get('reply')=='errno:11'];diagnostic=b'fork: Resource temporarily unavailable' in out
    elif mode=='wait':
        reached=[x for x in subject if x.get('phase')=='owned-wait-injection' and x.get('reply')=='errno:10'];diagnostic=b'waitpid: No child processes' in out
    else:
        reached=[x for x in subject if x.get('phase')=='actual-unemulated-authority-open'];diagnostic=b'kernel auth: /dev/bashos-auth: No such file or directory' in out
    target_attempt=any(x.get('phase')=='unexpected-target-exec' for x in subject) or (CASE/'su-target-marker').exists()
    if mode=='noexec' and target_attempt:
        put('assertion-result',mode=mode,classification='REACHED_FAIL',reason='target exec attempted',witness=subject,later_infrastructure_unknown=True)
        print('su-bounded reached-fail');return 1
    if len(reached)!=1:raise RuntimeError('required attributed witness unavailable')
    try:
        su_status=parse_status_record(out)
    except ValueError as exc:
        put('status-record-incomplete',mode=mode,reason=str(exc),witness=reached[0])
        raise RuntimeError('missing, malformed, duplicate or truncated status record') from exc
    mismatch=not diagnostic or su_status!=1
    if mismatch:
        put('assertion-result',mode=mode,classification='REACHED_FAIL',su_status=su_status,witness=reached[0],later_infrastructure_unknown=True)
        print('su-bounded reached-fail');return 1
    incomplete=(result['timeout'] or not result['trace_exists'] or not result['device_absent_after'] or result['observer_exit']!=0 or not result['tty_restored'] or (mode in ('noexec','wait') and (not result['password_sent'] or not result['echo_off'] or PASSWORD in out)) or (mode=='wait' and b'owned-reap=' not in out))
    if incomplete:raise RuntimeError('candidate or cleanup incomplete after retained observation')
    put('assertion-result',mode=mode,classification='BOUNDED_PASS',su_status=su_status,witness=reached[0])
    print('su-bounded observed');return 0

if __name__=='__main__':
    try:
        guard()
        if len(sys.argv)==2 and sys.argv[1]=='setup':setup()
        elif len(sys.argv)==3 and sys.argv[2] in ('noexec','fork','wait'):raise SystemExit(run(sys.argv[1],sys.argv[2]))
        else:raise RuntimeError('bad arguments')
    except Exception as exc:
        try:put('incomplete',error=repr(exc))
        except Exception:pass
        print('su-bounded incomplete: '+repr(exc),file=sys.stderr);raise SystemExit(125)
