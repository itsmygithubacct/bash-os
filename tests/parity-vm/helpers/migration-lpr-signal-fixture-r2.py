#!/usr/bin/python3
"""Guest-only lpr cancellation signal and stale-job observer."""
import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

ROOT=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
OBSERVER='/opt/bashos-parity/harness/helpers/migration-lpr-signal-observer-r1.py'
NAMES=('kill','tkill','tgkill','rt_sigqueueinfo','rt_tgsigqueueinfo','pidfd_send_signal')
RAW=HOME/'lpr-signals-report.json'


def save(data):
    RAW.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def observe(log, argv):
    args=['/usr/bin/python3',OBSERVER,'--log',str(log)]
    for n in NAMES:
        args+=['--notify',n,'--log-args',n+'=0,1,2']
    return args+['--']+argv


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def wait_file(path,seconds,process=None):
    end=time.monotonic()+seconds
    while not path.exists():
        if process is not None and process.poll() is not None: raise RuntimeError('process ended before barrier')
        if time.monotonic()>end: raise RuntimeError('barrier timeout')
        time.sleep(.02)


def tree(path):
    return [{'name':p.relative_to(path).as_posix(),'mode':p.lstat().st_mode,
             'content_hex':p.read_bytes().hex() if p.is_file() and not p.is_symlink() else None}
            for p in sorted(path.rglob('*'))]


def proc(pid):
    p=Path('/proc')/str(pid)
    return {'stat':(p/'stat').read_text(),'status':(p/'status').read_text()}


def control():
    log=HOME/'lpr-signal-control.jsonl'; log.write_text('')
    # x86-64 Linux syscall numbers. Signal 0 does not deliver a signal; all targets
    # are the Python control's own live child. Even invalid siginfo pointers are
    # continued to the kernel and serve only as notification controls.
    script=r'''import ctypes,json,os,subprocess,sys
lib=ctypes.CDLL(None,use_errno=True)
p=subprocess.Popen(['/usr/bin/python3','-c','import sys;sys.stdin.readline()'],stdin=subprocess.PIPE)
try:
 print(json.dumps({'target':p.pid,'caller':os.getpid()}),flush=True)
 for nr,args in [(62,(p.pid,0)),(200,(p.pid,0)),(234,(p.pid,p.pid,0)),(129,(p.pid,0,0)),(297,(p.pid,p.pid,0,0))]: lib.syscall(nr,*args)
 fd=lib.syscall(434,p.pid,0)
 if fd < 0: sys.exit(77)
 lib.syscall(424,fd,0,0,0);os.close(fd)
finally:
 p.communicate(b'done\n',timeout=3)
'''
    run=subprocess.run(observe(log,['/usr/bin/python3','-c',script]),capture_output=True,timeout=10)
    if run.returncode != 0: raise RuntimeError('signal observer control unavailable: '+repr(run.stderr[:300]))
    meta=json.loads(run.stdout); rec=records(log)
    if [x['syscall'] for x in rec] != list(NAMES): raise RuntimeError('control notifications incomplete: '+repr(rec))
    if any(x.get('caller_pid')!=meta['caller'] or x.get('reply')!='continue' for x in rec): raise RuntimeError('control caller or response mismatch')
    if any(rec[i].get('arg0') != meta['target'] for i in range(5)): raise RuntimeError('control target mismatch')
    if not re.search(r'^Pid:\s*'+str(meta['target'])+r'\s*$',rec[5].get('pidfd_fdinfo',''),re.M): raise RuntimeError('pidfd identity control failed')
    return {'meta':meta,'events':rec,'stdout_hex':run.stdout.hex(),'stderr_hex':run.stderr.hex()}


def verdict_events(events,expected_caller,backend):
    bad=[]
    for e in events:
        if e.get('caller_pid')!=expected_caller or e.get('reply')!='continue':bad.append(e);continue
        if e['syscall']=='kill': target=e.get('arg0'); sig=e.get('arg1')
        elif e['syscall']=='pidfd_send_signal':
            m=re.search(r'^Pid:\s*(\d+)\s*$',e.get('pidfd_fdinfo',''),re.M)
            if not m: raise RuntimeError('unresolved pidfd signal target')
            target=int(m.group(1));sig=e.get('arg1')
        elif e['syscall'] in ('tkill','rt_sigqueueinfo'):target=e.get('arg0');sig=e.get('arg1')
        elif e['syscall'] in ('tgkill','rt_tgsigqueueinfo'):target=e.get('arg0');sig=e.get('arg2')
        else:raise RuntimeError('unrecognized signal syscall')
        if target!=backend or sig!=signal.SIGTERM:bad.append(e)
    return bad


def main():
    if len(sys.argv)!=3 or sys.argv[2] not in ('live','stale') or os.geteuid()!=2000 or Path.cwd()!=ROOT or Path(os.environ['HOME'])!=HOME:raise RuntimeError('invalid invocation or guest identity')
    if os.uname().machine!='x86_64' or Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise RuntimeError('unsupported guest')
    runid=str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    for n in ('lpr-signal-control.jsonl','lpr-submit-signals.jsonl','lpr-cancel-signals.jsonl'): (HOME/n).write_text('')
    RAW.write_text('{}\n')
    state={'mode':sys.argv[2],'vm_uuid':runid,'control':control()};save(state)
    spool=ROOT/'spool';spool.mkdir(mode=0o700);(spool/'keep').write_bytes(b'sentinel'); (ROOT/'input').write_bytes(b'job bytes\n')
    backend=ROOT/'backend';backend.write_text('''#!/usr/bin/python3
import json,os,signal,sys,time
raw=sys.stdin.buffer.read()
def stop(sig,frame):
 open(os.environ['HOME']+'/lpr-backend-term','w').write(str(sig)+'\\n');sys.exit(42)
signal.signal(signal.SIGTERM,stop)
p=os.environ['HOME']+'/lpr-backend-ready'
with open(p+'.tmp','w') as f: json.dump({'pid':os.getpid(),'ppid':os.getppid(),'argv':sys.argv[1:],'data_hex':raw.hex()},f)
os.replace(p+'.tmp',p)
while True: time.sleep(.05)
''');backend.chmod(0o700)
    env=dict(os.environ,BASHLPR_SPOOL=str(spool),BASHLPR_BACKEND=str(backend),BASHLPR_TIMEOUT='15');candidate=sys.argv[1]
    witness=subprocess.Popen(['/usr/bin/python3','-c','import sys; sys.stdin.readline()'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    submit=None;dead=None;backend_fd=None
    try:
        state['witness_before']={'pid':witness.pid,**proc(witness.pid)};save(state)
        if sys.argv[2]=='live':
            cmd=[candidate,'--noprofile','--norc','-c','printf "%s\\n" "$$" > "$HOME/lpr-submitter-pid"; type -t lpr >&2; lpr submit input']
            submit=subprocess.Popen(observe(HOME/'lpr-submit-signals.jsonl',cmd),cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            wait_file(HOME/'lpr-backend-ready',6,submit);info=json.loads((HOME/'lpr-backend-ready').read_text());owner=int((HOME/'lpr-submitter-pid').read_text());job=info['argv'][0]
            if info['ppid']!=owner or not re.fullmatch('[0-9a-f]{16}',job) or not (spool/(job+'.lpr')).is_file() or not (spool/(job+'.ctl')).exists():raise RuntimeError('live backend identity or barrier invalid')
            backend_fd=os.pidfd_open(info['pid'],0)
            state.update(submitter_pid=owner,backend=info,submitter_before=proc(owner),backend_before=proc(info['pid']),before=tree(spool));save(state)
        else:
            dead=subprocess.Popen(['/usr/bin/python3','-c','pass'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            end=time.monotonic()+5
            while True:
                q=proc(dead.pid)
                if q['stat'].rsplit(')',1)[1].split()[0]=='Z':break
                if time.monotonic()>end:raise RuntimeError('dead owner not observed as zombie')
                time.sleep(.02)
            job='0123456789abcdef';(spool/(job+'.lpr')).write_bytes(b'stale');(spool/(job+'.lpr.pid')).write_text(str(dead.pid)+'\n');os.mkfifo(spool/(job+'.ctl'),0o600)
            state.update(dead_submitter_pid=dead.pid,dead_before=q,before=tree(spool));save(state)
        command=[candidate,'--noprofile','--norc','-c','printf "%s\\n" "$$" > "$HOME/lpr-canceller-pid"; type -t lpr >&2; lpr cancel "$1"','fixture',job]
        cancel=subprocess.Popen(observe(HOME/'lpr-cancel-signals.jsonl',command),cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            cancel_out,cancel_err=cancel.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(cancel.pid,signal.SIGKILL)
            cancel_out,cancel_err=cancel.communicate(timeout=3)
            state['cancel_timeout']={'stdout_hex':cancel_out.hex(),'stderr_hex':cancel_err.hex(),'events':records(HOME/'lpr-cancel-signals.jsonl')};save(state)
            raise RuntimeError('canceller deadline exceeded')
        state['cancel']={'status':cancel.returncode,'stdout_hex':cancel_out.hex(),'stderr_hex':cancel_err.hex(),'pid':int((HOME/'lpr-canceller-pid').read_text())};state['cancel_events']=records(HOME/'lpr-cancel-signals.jsonl');save(state)
        if submit is not None:
            state['submit_events_before_wait']=records(HOME/'lpr-submit-signals.jsonl');save(state)
            out,err=submit.communicate(timeout=8);state['submit']={'status':submit.returncode,'stdout_hex':out.hex(),'stderr_hex':err.hex()};state['submit_events']=records(HOME/'lpr-submit-signals.jsonl');state['backend_term']=(HOME/'lpr-backend-term').read_text() if (HOME/'lpr-backend-term').exists() else None
        else:
            state['dead_after']=proc(dead.pid)
        state['after']=tree(spool);save(state)
        alive=witness.poll() is None
        if alive:
            try: state['witness_after']={'alive':True,**proc(witness.pid)}
            except OSError as exc: state['witness_after']={'alive':False,'proc_error':str(exc)}
        else: state['witness_after']={'alive':False,'returncode':witness.returncode}
        save(state)
        if not cancel_err.startswith(b'builtin\n'):raise RuntimeError('canceller builtin identity missing')
        cleaned=len(state['after'])==1 and state['after'][0]['name']=='keep' and state['after'][0]['content_hex']==b'sentinel'.hex()
        if sys.argv[2]=='live':
            if not bytes.fromhex(state['submit']['stderr_hex']).startswith(b'builtin\n'):raise RuntimeError('submitter builtin identity missing')
            bad=verdict_events(state['submit_events'],state['submitter_pid'],state['backend']['pid'])+state['cancel_events']
            ok=not bad and len(state['submit_events'])>=1 and state['backend_term']=='15\n' and state['submit']['status']==3 and cancel.returncode==0 and cleaned and state['witness_after']['alive']
        else:
            ok=not state['cancel_events'] and cancel.returncode==0 and cleaned and state['witness_after']['alive'] and state['dead_after']['stat'].rsplit(')',1)[1].split()[0]=='Z'
        print('signal_and_cleanup='+('yes' if ok else 'no'))
    finally:
        if submit is not None and submit.poll() is None:
            os.killpg(submit.pid,signal.SIGKILL);submit.communicate(timeout=3)
        if backend_fd is not None:
            try: signal.pidfd_send_signal(backend_fd,signal.SIGKILL)
            except ProcessLookupError: pass
            finally: os.close(backend_fd)
        if witness.poll() is None:
            try:witness.communicate(b'done\n',timeout=3)
            except subprocess.TimeoutExpired:witness.kill();witness.communicate(timeout=3)
        if dead is not None:dead.wait(timeout=3)


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('CONTROL-INCOMPLETE: '+repr(exc),file=sys.stderr);sys.exit(97)
