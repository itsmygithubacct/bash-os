#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-guest-only SU client observations; actual credentials stay unchanged."""
import base64
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
MOCK='/opt/bashos-parity/harness/helpers/auth-client-su-exec-bootstrap-r1.py'
PASSWORD=b'password';WRONG=b'wrong'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert Path.cwd()==CASE and os.getresuid()==(2000,2000,2000) and os.getresgid()==(2000,2000,2000)


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**data):
    data['kind']=kind
    with (HOME/'su-client-observations.jsonl').open('a') as f:f.write(json.dumps(data,sort_keys=True)+'\n')


def termios_data(value):
    return {'iflag':value[0],'oflag':value[1],'cflag':value[2],'lflag':value[3],
            'ispeed':value[4],'ospeed':value[5],
            'cc':[x.hex() if isinstance(x,bytes) else x for x in value[6]]}


def kdf(password,salt,t,m,p,n):
    import importlib.util
    path='/opt/bashos-parity/harness/helpers/auth-client-argon2-cli-r1.py'
    spec=importlib.util.spec_from_file_location('auth_argon2_cli',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.derive(password,salt,t,m,p,n,record)


def rows(path):return [json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []


CONTROL=r'''import errno,fcntl,os,struct,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.getresuid()==(2000,2000,2000) and os.getresgid()==(2000,2000,2000) and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
before=(os.getresuid(),os.getresgid(),os.getgroups());f=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC)
m=bytearray(struct.pack('<IIII32s64sII',2000,2000,2,5,bytes(32),b'fixture',0,0));fcntl.ioctl(f,0xc078ba08,m,True)
bad=bytearray(m);bad[16]^=1
try:fcntl.ioctl(f,0x4078ba09,bad,True);raise AssertionError('modified token accepted')
except OSError as e:assert e.errno==errno.EPERM
assert os.geteuid()==2000
fcntl.ioctl(f,0x4078ba09,bytearray(m),True);assert os.geteuid()==0
try:os.setgroups([2001]);raise AssertionError('wrong group accepted')
except OSError as e:assert e.errno==errno.EPERM
os.setgroups([2000])
try:os.setresgid(2001,2001,2001);raise AssertionError('wrong gid accepted')
except OSError as e:assert e.errno==errno.EPERM
os.setresgid(2000,2000,2000)
try:os.setresuid(2001,2001,2001);raise AssertionError('wrong uid accepted')
except OSError as e:assert e.errno==errno.EPERM
os.setresuid(2000,2000,2000)
assert (os.getresuid(),os.getresgid(),os.getgroups())==before and os.geteuid()==2000
os.execve('/bin/bash',['/bin/bash','-c','exit 7'],{'PATH':'/usr/bin:/bin'})
'''


def setup(scenario):
    assert not os.path.lexists('/dev/bashos-auth')
    assert kdf(b'password',b'somesalt',2,65536,1,32).hex()=='09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'
    base=CASE/'su-control';base.mkdir(mode=0o700);control=base/'control.py';control.write_text(CONTROL)
    trace=HOME/'su-client-trace-control.jsonl';cfg=base/'control.json'
    cfg.write_text(json.dumps({'trace':str(trace),'capture_credentials':True,'expected_exec':'/bin/bash'}))
    p=subprocess.run(['/usr/bin/python3',MOCK,str(cfg),'/usr/bin/python3',str(control)],cwd=base,
                     env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
    trace_rows=rows(trace);cred=[x for x in trace_rows if x['syscall'] in ('setgroups','setresgid','setresuid')]
    assert p.returncode==7 and not p.stdout and not p.stderr
    assert [(x['syscall'],x['reply']) for x in cred]==[('setgroups','errno:1'),('setgroups','value:0'),('setresgid','errno:1'),('setresgid','value:0'),('setresuid','errno:1'),('setresuid','value:0')]
    assert sum(x['syscall']=='geteuid' and x['reply']=='value:0' for x in trace_rows)==1
    assert any(x.get('request')=='0x4078ba09' and x.get('reply')=='errno:1' for x in trace_rows)
    ex=[x for x in trace_rows if x['syscall']=='execve'];assert len(ex)==1 and ex[0]['reply']=='continue'
    assert [base64.b64decode(x) for x in ex[0]['argv_base64']]==[b'/bin/bash',b'-c',b'exit 7']
    record('control',scenario=scenario,credential_events=cred,exec_event=ex[0],status=p.returncode)
    print('controls=verified')


def make_case(label,target='/bin/bash'):
    base=CASE/('su-client-'+label);base.mkdir(mode=0o700);db=base/'db';db.mkdir(mode=0o700)
    work=base/'work';work.mkdir();home=base/'home';home.mkdir()
    digest=kdf(PASSWORD,b'somesalt',1,1024,1,32)
    phc='$argon2id$v=19$m=1024,t=1,p=1$'+b'somesalt'.hex()+'$'+digest.hex()
    (db/'passwd').write_text('other:x:2001:2001:Other:/tmp:/bin/false\nfixture:x:2000:2000:Fixture:'+str(home)+':'+target+'\n')
    (db/'shadow').write_text('fixture:'+phc+':19000:0:99999:7:::\n');os.chmod(db/'shadow',0o600)
    env={'HOME':str(base),'PATH':'/usr/bin:/bin','TERM':'vt100','LANG':'C',
         'PHCLIB_PASSWD':str(db/'passwd'),'PHCLIB_SHADOW':str(db/'shadow'),'BPW_LOCK_DIR':str(base/'lock'),
         'KEEP_ME':'retained-value','PYTHONPATH':str(base/'unused-pythonpath'),'BASHSU_TEST':'must-not-leak'}
    record('private-account',label=label,passwd=(db/'passwd').read_text(),shadow=(db/'shadow').read_text(),input_digest_hex=digest.hex())
    return base,work,home,env


ONE=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
identity() { while IFS= read -r line; do case $line in Uid:*|Gid:*|Groups:*) printf '%s %s\n' "$1" "$line";; esac; done < /proc/$BASHPID/status; }
identity parent-id-before
printf 'parent-before=%s:%s\n' "$UID" "$EUID"
[[ -e /proc/$BASHPID/fd/$1 ]] && printf 'inherited=yes\n' || printf 'inherited=no\n'
shift
su "$@"; result=$?
printf 'su-status=%d\n' "$result"
printf 'parent-after=%s:%s\n' "$UID" "$EUID"
identity parent-id-after
'''
TWO=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
identity() { while IFS= read -r line; do case $line in Uid:*|Gid:*|Groups:*) printf '%s %s\n' "$1" "$line";; esac; done < /proc/$BASHPID/status; }
identity parent-id-before
printf 'parent-before=%s:%s\n' "$UID" "$EUID"
[[ -e /proc/$BASHPID/fd/$1 ]] && printf 'inherited=yes\n' || printf 'inherited=no\n'
su --no-login -c "$2" fixture; printf 'su-first=%d\n' "$?"
su --no-login -c "$3" fixture; printf 'su-second=%d\n' "$?"
printf 'parent-after=%s:%s\n' "$UID" "$EUID"
identity parent-id-after
'''


def process_identity(pid):
    data=Path('/proc/%d/stat'%pid).read_text();fields=data[data.rindex(')')+2:].split()
    lines=Path('/proc/%d/status'%pid).read_text().splitlines()
    uid=next([int(x) for x in line.split()[1:]] for line in lines if line.startswith('Uid:'))
    if fields[0]=='Z' or uid[:2]!=[2000,2000]:raise RuntimeError('unowned or exited process')
    return (int(fields[1]),int(fields[19]),tuple(uid))


def signal_owned_child(supervisor,event):
    pid=event.get('pid');fd=None
    evidence={'selected_notification_pid':pid,'selected_notification':event,'supervisor_pid':supervisor.pid,
              'observer_pid':os.getpid(),'signal_number':int(signal.SIGINT)}
    record('owned-signal-selection',**evidence)
    def describe(chain):
        return [{'pid':n,'ppid':identity[0],'starttime_ticks':identity[1],'uids':list(identity[2])} for n,identity in chain]
    try:
        if not isinstance(pid,int) or pid<=1 or supervisor.poll() is not None or pid==supervisor.pid:
            raise RuntimeError('invalid signal target')
        root=process_identity(supervisor.pid)
        if root[0]!=os.getpid():raise RuntimeError('supervisor is not our live child')
        chain=[];current=pid
        for _ in range(32):
            if current<=1 or current in [p for p,_ in chain]:raise RuntimeError('invalid descendant chain')
            identity=process_identity(current);chain.append((current,identity))
            if current==supervisor.pid:
                if identity!=root:raise RuntimeError('supervisor identity changed')
                break
            current=identity[0]
        else:raise RuntimeError('descendant chain too long')
        if chain[-1][0]!=supervisor.pid:raise RuntimeError('signal target is not an owned descendant')
        evidence['verified_chain']=describe(chain)
        fd=os.pidfd_open(pid,0)
        evidence['pidfd_opened']=True;evidence['pidfd_number']=fd
        evidence['pidfd_link']=os.readlink('/proc/self/fd/%d'%fd)
        evidence['pidfd_fdinfo']=Path('/proc/self/fdinfo/%d'%fd).read_text()
        rechecked=[(n,process_identity(n)) for n,_ in chain]
        evidence['rechecked_chain']=describe(rechecked)
        if supervisor.poll() is not None or rechecked!=chain:raise RuntimeError('signal target identity changed')
        signal.pidfd_send_signal(fd,signal.SIGINT)
        evidence['signal_result']='sent'
    except Exception as exc:
        evidence['signal_result']='error';evidence['error']=repr(exc)
        record('owned-signal-evidence',**evidence)
        raise
    finally:
        if fd is not None:os.close(fd)
    record('owned-signal-evidence',**evidence)


def run_tty(shell,label,args,mode='good',target='/bin/bash',exec_error=False,repeat=False):
    base,work,home,env=make_case(label,target);trace=HOME/('su-client-trace-'+label+'.jsonl');cfg=base/'mock.json'
    options={'trace':str(trace),'capture_credentials':True,'expected_exec':target,'exec_error':exec_error}
    if mode in ('eof','eio'):options['read_end']=mode
    cfg.write_text(json.dumps(options))
    fd0=os.open('/dev/null',os.O_RDONLY);fd=fcntl.fcntl(fd0,fcntl.F_DUPFD,63);os.close(fd0);os.set_inheritable(fd,True)
    master,slave=pty.openpty();before=termios.tcgetattr(master);output=bytearray();samples=[];prompt_snapshots=[];sent=0;signalled=False
    def session():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    script=TWO if repeat else ONE
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),shell,'--noprofile','--norc','-c',script,'parent',str(fd),*args],
                       cwd=work,env=env,stdin=slave,stdout=slave,stderr=slave,pass_fds=(fd,),preexec_fn=session)
    os.close(fd)
    try:
        end=time.monotonic()+22
        while p.poll() is None and time.monotonic()<end:
            ready,_,_=select.select([master],[],[],.05)
            if ready:
                try:output.extend(os.read(master,8192))
                except OSError as e:
                    if e.errno!=errno.EIO:raise
            prompts=output.count(b'Password: ')
            while sent<prompts:
                prompt=termios.tcgetattr(master);prompt_snapshots.append(termios_data(prompt))
                samples.append(not bool(prompt[3]&termios.ECHO));sent+=1
                if mode in ('good','wrong'):os.write(master,(PASSWORD if mode=='good' else WRONG)+b'\n')
                elif mode=='signal':
                    candidates=[x for x in rows(trace) if x['syscall']=='prctl']
                    if not candidates:raise RuntimeError('missing owned signal target')
                    signal_owned_child(p,candidates[-1]);signalled=True
        if p.poll() is None:raise RuntimeError(label+' timeout')
        for _ in range(10):
            ready,_,_=select.select([master],[],[],.02)
            if not ready:break
            try:output.extend(os.read(master,8192))
            except OSError as e:
                if e.errno!=errno.EIO:raise
                break
        result=p.wait(timeout=3);after=termios.tcgetattr(master)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=3)
        os.close(master);os.close(slave)
    data=bytes(output);trace_rows=rows(trace);restore=before==after
    record('pty-run',label=label,status=result,output_base64=b64(data),echo_off_samples=samples,
           termios_before=termios_data(before),termios_at_prompts=prompt_snapshots,termios_after=termios_data(after),
           restored=restore,trace_rows=len(trace_rows),signal_sent_to_owned_child=signalled)
    return {'status':result,'out':data,'rows':trace_rows,'off':samples,'restored':restore,'base':base,'work':work,'home':home,'fd':fd,'signalled':signalled}


def real_identity(event):
    d={line.split(':',1)[0]:line.split(':',1)[1] for line in event['actual_identity']}
    return all([int(x) for x in d[name].split()]==[2000]*4 for name in ('Uid','Gid'))


def exec_info(run):
    matches=[x for x in run['rows'] if x['syscall']=='execve']
    if len(matches)!=1:return None
    x=matches[0];argv=[base64.b64decode(y).decode() for y in x['argv_base64']]
    env={}
    for item in x['env_base64']:
        key,sep,value=base64.b64decode(item).decode().partition('=')
        if not sep or key in env:return None
        env[key]=value
    return x,argv,env


def stages(run,count=1):
    changes=[x for x in run['rows'] if x['syscall'] in ('setgroups','setresgid','setresuid')]
    return ([(x['syscall'],x['reply']) for x in changes]==[('setgroups','value:0'),('setresgid','value:0'),('setresuid','value:0')]*count
            and all(real_identity(x) for x in changes))


def parent_ok(run):
    out=run['out']
    before=[x[len(b'parent-id-before '):] for x in out.splitlines() if x.startswith(b'parent-id-before ')]
    after=[x[len(b'parent-id-after '):] for x in out.splitlines() if x.startswith(b'parent-id-after ')]
    return (run['status']==0 and b'parent-before=2000:2000\r\n' in out and b'parent-after=2000:2000\r\n' in out
            and b'inherited=yes\r\n' in out and len(before)==3 and before==after and run['restored'])


def shell_case(shell):
    login=run_tty(shell,'login',['--login','-c','exit 0','fixture'])
    no=run_tty(shell,'no-login',['--no-login','-c','exit 0','fixture'])
    keep=run_tty(shell,'keep',['--keep-env','--no-login','-c','exit 0','fixture'])
    li=exec_info(login);ni=exec_info(no);ki=exec_info(keep)
    good_login=bool(li and parent_ok(login) and b'su-status=0\r\n' in login['out'] and stages(login) and li[0]['cwd']==str(login['home']) and li[1]==['-bash','-c','exit 0'] and li[0]['fds']==[0,1,2] and real_identity(li[0]))
    good_no=bool(ni and parent_ok(no) and b'su-status=0\r\n' in no['out'] and stages(no) and ni[0]['cwd']==str(no['work']) and ni[1]==['/bin/bash','-c','exit 0'] and ni[0]['fds']==[0,1,2] and real_identity(ni[0]))
    base_env=lambda x,r: x.get('USER')=='fixture' and x.get('LOGNAME')=='fixture' and x.get('HOME')==str(r['home']) and x.get('SHELL')=='/bin/bash' and x.get('PATH')=='/bin:/bash-os:/usr/bin' and x.get('TERM')=='vt100' and x.get('LANG')=='C'
    environment=bool(li and ki and base_env(li[2],login) and base_env(ki[2],keep) and 'KEEP_ME' not in li[2] and ki[2].get('KEEP_ME')=='retained-value' and 'PYTHONPATH' not in ki[2] and 'BASHSU_TEST' not in ki[2] and parent_ok(keep) and b'su-status=0\r\n' in keep['out'] and stages(keep))
    mints=[x for x in login['rows'] if x.get('request')=='0xc078ba08'];lookup=bool(good_login and len(mints)==1 and struct.unpack_from('<III',bytes.fromhex(mints[0]['input_hex']))==(2000,2000,2) and bytes.fromhex(mints[0]['input_hex'])[48:112].split(b'\0',1)[0]==b'fixture')
    interactive=run_tty(shell,'interactive',['--login','fixture'],exec_error=True)
    simple=run_tty(shell,'simple',['--no-login','fixture'],exec_error=True)
    ii=exec_info(interactive);si=exec_info(simple)
    argv=bool(ii and si and ii[1]==['-bash','-i'] and si[1]==['/bin/bash'] and ii[0]['reply']=='errno:2' and si[0]['reply']=='errno:2' and b'su-status=126\r\n' in interactive['out'] and b'su-status=126\r\n' in simple['out'] and stages(interactive) and stages(simple))
    missing=CASE/'su-client-missing'/'missing-shell';missing_run=run_tty(shell,'missing',['--no-login','-c','exit 0','fixture'],target=str(missing))
    badpath=CASE/'su-client-nonexec'/'noexec-shell';base=CASE/'su-client-nonexec';base.mkdir(mode=0o700);badpath.write_text('# not executable\n');os.chmod(badpath,0o600)
    # make_case owns creation of the case directory; provision the target after it creates the directory in a separate parent.
    # The non-executable target is deliberately outside the account-case directory but inside CASE.
    denied_run=run_tty(shell,'nonexec-run',['--no-login','-c','exit 0','fixture'],target=str(badpath))
    errors=(parent_ok(missing_run) and parent_ok(denied_run) and stages(missing_run) and stages(denied_run) and b'su-status=126\r\n' in missing_run['out'] and b'su-status=126\r\n' in denied_run['out'] and b'execve' in missing_run['out'] and b'execve' in denied_run['out'])
    record('shell-result',lookup=lookup,login=good_login,no_login=good_no,env=environment,argv=argv,exec_errors=errors)
    print('su-shell lookup=%s login=%s no-login=%s env=%s argv=%s exec-errors=%s' % tuple(yes(x) for x in (lookup,good_login,good_no,environment,argv,errors)))


def child_case(shell):
    run=run_tty(shell,'child',['exit 7','kill -TERM "$$"'],repeat=True)
    ex=[x for x in run['rows'] if x['syscall']=='execve']
    ok=parent_ok(run) and run['off']==[True,True] and b'su-first=7\r\n' in run['out'] and b'su-second=143\r\n' in run['out'] and len(ex)==2 and stages(run,2) and all(real_identity(x) for x in ex)
    record('child-result',valid=ok,exec_events=ex)
    print('su-child exits=%s signal=%s repeat-parent=%s' % (yes(ok),yes(ok),yes(ok)))


def tty_case(shell):
    runs={name:run_tty(shell,'tty-'+name,['--no-login','-c','exit 0','fixture'],mode=mode) for name,mode in [('success','good'),('failure','wrong'),('eof','eof'),('eio','eio'),('cancel','signal')]}
    a=runs['success'];b=runs['failure'];c=runs['eof'];d=runs['eio'];e=runs['cancel']
    echo=bool(a['off']==[True] and b['off']==[True] and PASSWORD not in a['out'] and WRONG not in b['out'])
    success=parent_ok(a) and b'su-status=0\r\n' in a['out'] and stages(a)
    failure=parent_ok(b) and b'su-status=1\r\n' in b['out'] and not any(x.get('request')=='0xc078ba08' for x in b['rows'])
    eof=parent_ok(c) and b'su-status=1\r\n' in c['out'] and any(x['syscall']=='read' and x['reply']=='value:0' for x in c['rows'])
    eio=parent_ok(d) and b'su-status=2\r\n' in d['out'] and any(x['syscall']=='read' and x['reply']=='errno:5' for x in d['rows'])
    cancel=parent_ok(e) and e['off']==[True] and e['signalled'] and b'su-status=130\r\n' in e['out'] and not any(x.get('request')=='0xc078ba08' for x in e['rows'])
    record('tty-result',echo=echo,success=success,failure=failure,eof=eof,read_error=eio,cancel=cancel)
    print('su-tty echo=%s success=%s failure=%s eof=%s read-error=%s cancel=%s' % tuple(yes(x) for x in (echo,success,failure,eof,eio,cancel)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('shell','child','tty');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:];{'shell':shell_case,'child':child_case,'tty':tty_case}[scenario](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
