#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only independent request, decision and owned-child authority fixtures."""
import base64
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
MOCK='/opt/bashos-parity/harness/helpers/auth-client-authority-bootstrap-r1.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def raw(data):return base64.b64encode(data[:65536]).decode()
def yes(v):return 'yes' if v else 'no'
def record(kind,**values):
    values['kind']=kind
    with (HOME/'authority-observations.jsonl').open('a') as f:f.write(json.dumps(values,sort_keys=True)+'\n')


CHILD=r'''import json,os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd()==Path('/tmp/parity-case')
p=Path(sys.argv[1]).resolve();assert p.is_relative_to(Path('/tmp/parity-case'))
p.write_text(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'argv':sys.argv[1:]}))
sys.exit(int(sys.argv[2]))
'''

CONTROL=r'''import ctypes,errno,fcntl,hashlib,os,struct,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
fd=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC)
argv=[x.encode() for x in sys.argv[1:]];ab=b''.join(x+b'\0' for x in argv);eb=b'CONTROL=yes\0'
a=ctypes.create_string_buffer(ab);e=ctypes.create_string_buffer(eb)
u=os.getuid();g=os.getgid();fields=(1,0,0,u,g,u,g,len(argv),1,len(ab),len(eb))
strings=[str(u).encode(),str(u).encode(),os.getcwd().encode()]
wire=b'bashos-privcmd-v'+struct.pack('<11I',*fields)
for s in strings:wire+=struct.pack('<I',len(s))+s
buf=bytearray(832);struct.pack_into('<I',buf,0,832);struct.pack_into('<11I',buf,4,*fields)
struct.pack_into('<QQ',buf,48,ctypes.addressof(a),ctypes.addressof(e));buf[96:128]=hashlib.sha256(wire+ab+eb).digest()
for offset,s in zip((128,192,256),strings):buf[offset:offset+len(s)]=s
fcntl.ioctl(fd,0xc340ba0b,buf,True);assert struct.unpack_from('<I',buf,512)[0]==2
handle=struct.unpack_from('<Q',buf,768)[0];assert handle==77
h=bytearray(296);struct.pack_into('<IIII',h,0,296,1,0,len(argv));struct.pack_into('<Q',h,32,handle)
struct.pack_into('<Q',h,216,ctypes.addressof(a));struct.pack_into('<I',h,224,len(ab))
fcntl.ioctl(fd,0xc128ba0d,h,True);assert struct.unpack_from('<II',h,228)==(7,1)
buf[96]^=1
try:fcntl.ioctl(fd,0xc340ba0b,buf,True);raise AssertionError('bad digest accepted')
except OSError as ex:assert ex.errno==errno.EPROTO
os.close(fd);print('authority-control=ok')
'''


def step(mode,decision,argv,*,flags=0,noninteractive=0,target_user='parity',env_contains=(),handle=0):
    account=pwd.getpwnam('parity')
    return {'mode':mode,'decision':decision,'flags':flags,'noninteractive':noninteractive,
            'target_uid':account.pw_uid,'target_gid':account.pw_gid,'target_user':target_user,
            'argv':argv,'env_contains':list(env_contains),'handle':handle}


def run(base,label,shell_script,argv,steps,command,extra=None):
    trace=HOME/('authority-trace-'+label+'.jsonl');cfg=base/(label+'.json')
    cfg.write_text(json.dumps({'trace':str(trace),'steps':steps,'allowed_argv':command,**(extra or {})}))
    commandline=['/usr/bin/python3',MOCK,str(cfg)]+list(map(str,argv))
    p=subprocess.Popen(commandline,cwd=base,env=dict(os.environ),stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError(label+' timed out')
    rows=[json.loads(x) for x in trace.read_text().splitlines()] if trace.exists() else []
    record('run',label=label,program=commandline[3:],status=p.returncode,stdout_base64=raw(out),stderr_base64=raw(err),trace_rows=len(rows))
    if label.startswith('auth-'):
        before=base/'identity-before';after=base/'identity-after'
        record('shell-identity',label=label,
               before_base64=raw(before.read_bytes()) if before.exists() else None,
               after_base64=raw(after.read_bytes()) if after.exists() else None)
    return p.returncode,out,err,rows


def command_for(base,label,code=7):
    stub=base/'child.py'
    if not stub.exists():stub.write_text(CHILD)
    marker=base/(label+'.marker')
    return ['/usr/bin/python3',str(stub),str(marker),str(code)],marker


def calls(rows):return [x for x in rows if x['syscall']=='ioctl']


def setup(scenario):
    assert not os.path.lexists('/dev/bashos-auth')
    base=CASE/'authority-control';base.mkdir(mode=0o700);control=base/'control.py';control.write_text(CONTROL)
    command,marker=command_for(base,'control')
    uid=os.getuid();gid=os.getgid()
    plan={'mode':1,'decision':2,'flags':0,'noninteractive':0,'target_uid':uid,'target_gid':gid,
          'target_user':str(uid),'argv':command,'env_contains':['CONTROL=yes'],'handle':77}
    status,out,err,rows=run(base,'control','',['/usr/bin/python3',control,*command],[plan],command)
    io=calls(rows);trans=[x.get('transition',{}).get('op') for x in io if x.get('transition')]
    assert status==0 and out==b'authority-control=ok\n' and not err
    assert trans==['authz','handoff-owned-child'] and marker.is_file()
    child=json.loads(marker.read_text());assert child['uid']==uid and child['gid']==gid
    assert sum(x.get('reply')=='errno:71' and not x.get('valid') for x in io)==1
    assert [x['request'] for x in io]==['0xc340ba0b','0xc128ba0d','0xc340ba0b']
    record('setup-control',scenario=scenario,child=child,transitions=trans,bad_digest_rejected=True)
    print('controls=verified')


AUTH_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
snapshot_identity() {
 while IFS= read -r line; do
  case "$line" in Uid:*|Gid:*|Groups:*|CapInh:*|CapPrm:*|CapEff:*) printf '%s\n' "$line" ;; esac
 done < "/proc/$BASHPID/status"
}
snapshot_identity > identity-before
auth open fd || exit 80
"$1" "$fd" exec "$2" "$3" -- "${@:4}"; rc=$?
printf 'operation-status=%d\n' "$rc"
snapshot_identity > identity-after
exec {fd}>&-
'''


def marker_snapshot(path):
    try:
        st=path.lstat()
    except FileNotFoundError:
        return {'exists':False}
    data=path.read_bytes() if path.is_file() and not path.is_symlink() else None
    return {'exists':True,'device':st.st_dev,'inode':st.st_ino,'mode':st.st_mode,
            'uid':st.st_uid,'gid':st.st_gid,'contents_base64':raw(data) if data is not None else None}


def auth_case(shell):
    base=CASE/'authority-auth';base.mkdir(mode=0o700)
    uid=os.getuid();gid=os.getgid()
    def identity_ok():
        before=base/'identity-before';after=base/'identity-after'
        if not before.exists() or not after.exists():return False
        x=before.read_bytes();y=after.read_bytes()
        return x==y and b'Uid:\t2000\t2000\t2000\t2000\n' in x and b'Gid:\t' in x and b'Groups:' in x
    def one(label,decision,verb,handoff_error=False):
        command,marker=command_for(base,label);before=marker_snapshot(marker)
        if before['exists']:raise RuntimeError('unexpected pre-existing child marker')
        plan=step(1,decision,command,target_user=str(uid),handle=77 if decision==2 else 0)
        script=AUTH_SCRIPT.replace('"$1" "$fd"','auth '+verb+' "$fd"')
        args=[shell,'--noprofile','--norc','-c',script,'fixture','ignored',uid,gid,*command]
        status,out,err,rows=run(base,label,script,args,[plan],command,{'handoff_error':True} if handoff_error else None)
        after=marker_snapshot(marker)
        record('subcase-child-marker',label=label,marker=str(marker),before=before,after=after)
        return status,out,err,rows,before,after
    status,out,err,rows,before,after=one('auth-deny',1,'privcmd-authz')
    request=[x for x in calls(rows) if x.get('request')=='0xc340ba0b']
    denied=(status==0 and b'decision=deny ' in out and b'operation-status=1\n' in out and
            len(request)==1 and request[0].get('valid') and not before['exists'] and not after['exists'] and identity_ok())
    status,out,err,rows,before,after=one('auth-inspect-allow',2,'privcmd-authz')
    request=[x for x in calls(rows) if x.get('request')=='0xc340ba0b']
    inspect_allow=(status==0 and b'decision=allow_exec ' in out and len(request)==1 and
                   request[0].get('valid') and not before['exists'] and not after['exists'] and identity_ok() and
                   not any(x.get('request')=='0xc128ba0d' for x in calls(rows)))
    status,out,err,rows,before,after=one('auth-error',2,'privcmd-exec',True)
    hand=[x for x in calls(rows) if x.get('request')=='0xc128ba0d']
    failed=(status==0 and b'approval=ioctl-error' in out and b'operation-status=1\n' in out and
            bool(err) and len(hand)==1 and hand[0].get('valid') and hand[0].get('reply')=='errno:5' and
            not before['exists'] and not after['exists'] and identity_ok())
    status,out,err,rows,before,after=one('auth-allow',2,'privcmd-exec')
    io=calls(rows);ops=[x.get('transition',{}).get('op') for x in io if x.get('transition')]
    child=json.loads(base64.b64decode(after['contents_base64'])) if after.get('contents_base64') is not None else None
    # Retain the strict shell status 7 expectation as well as reported exit_code=7.
    allowed=(status==0 and b'decision=allow_exec handle_id=77 approval=allowed exit_code=7' in out and
             b'operation-status=7\n' in out and ops==['authz','handoff-owned-child'] and
             not before['exists'] and child is not None and child['uid']==uid and child['gid']==gid and identity_ok())
    record('auth-outcome',deny=denied,inspect_allow=inspect_allow,failure_no_child=failed,allow_child_status=allowed,child=child)
    print('authority-auth deny=%s inspect-allow=%s failure-no-child=%s allow-owned-child-status=%s' %
          (yes(denied),yes(inspect_allow),yes(failed),yes(allowed)))


CMD_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
"$@"; rc=$?
printf 'operation-status=%d\n' "$rc"
'''


def command_case(shell,kind):
    base=CASE/('authority-'+kind);base.mkdir(mode=0o700)
    results={}
    for label,decision in (('allow',2),('deny',1),('auth-required',6)):
        command,marker=command_for(base,label)
        opts=[kind,'-n','-u','parity','--']
        if kind=='sudo':opts+=['TRACE=fixture']
        expected_env=['BASHOS_INLINE_TRACE=fixture'] if kind=='sudo' else ['BASHOS_CALLER_HOME=/tmp/parity-home']
        p=step(1,decision,command,noninteractive=1,env_contains=expected_env,handle=77 if decision==2 else 0)
        argv=[shell,'--noprofile','--norc','-c',CMD_SCRIPT,'fixture',*opts,*command]
        status,out,err,rows=run(base,kind+'-'+label,CMD_SCRIPT,argv,[p],command)
        io=calls(rows);auth=[x for x in io if x.get('request')=='0xc340ba0b'];hand=[x for x in io if x.get('request')=='0xc128ba0d']
        child=json.loads(marker.read_text()) if marker.exists() else None
        if label=='allow':
            good=(status==0 and out==b'operation-status=7\n' and not err and len(auth)==len(hand)==1 and
                  auth[0].get('valid') and hand[0].get('valid') and child is not None and
                  child['uid']==os.getuid() and child['gid']==os.getgid())
        else:
            good=(status==0 and out==b'operation-status=1\n' and bool(err) and len(auth)==1 and auth[0].get('valid') and
                  not hand and not marker.exists() and not any(x.get('request')=='0xc0b0ba0f' for x in io))
        results[label]=good
        record('command-outcome',client_kind=kind,label=label,correct=good,child=child)
    if kind=='sudo':
        # Same argv, target and cwd under two equal-length inline values.
        # The peer recomputes each digest over the exact received wire bytes.
        command,marker=command_for(base,'env-binding'); observed=[]
        for value in ('alpha','bravo'):
            p=step(1,1,command,noninteractive=1,env_contains=['BASHOS_INLINE_TRACE='+value])
            opts=['sudo','-n','-u','parity','--','TRACE='+value]
            argv=[shell,'--noprofile','--norc','-c',CMD_SCRIPT,'fixture',*opts,*command]
            status,out,err,rows=run(base,'sudo-env-'+value,CMD_SCRIPT,argv,[p],command)
            req=[x for x in calls(rows) if x.get('request')=='0xc340ba0b']
            observed.append((status,out,err,req))
        env_ok=False
        if all(len(x[3])==1 and x[3][0].get('valid') for x in observed):
            a,b=(x[3][0] for x in observed)
            ea=base64.b64decode(a['env_base64']);eb=base64.b64decode(b['env_base64'])
            env_ok=(all(x[0]==0 and x[1]==b'operation-status=1\n' and x[2] for x in observed) and
                    not marker.exists() and a['argv_base64']==b['argv_base64'] and
                    ea.replace(b'BASHOS_INLINE_TRACE=alpha\0',b'BASHOS_INLINE_TRACE=bravo\0')==eb and
                    a['received_digest']!=b['received_digest'])
        record('environment-binding',correct=env_ok)
        print('sudo allow=%s deny=%s noninteractive=%s env-binding=%s' %
              (yes(results['allow']),yes(results['deny']),yes(results['auth-required']),yes(env_ok)))
    else:
        print('doas allow=%s deny=%s noninteractive=%s' %
              (yes(results['allow']),yes(results['deny']),yes(results['auth-required'])))


def timestamp(shell):
    base=CASE/'authority-timestamp';base.mkdir(mode=0o700);results={}
    for label,option,mode,flags,decision in [('reset','-k',5,0,4),('reset-all','-K',5,1,4),('validate','-v',4,0,5)]:
        p=step(mode,decision,[],flags=flags)
        args=[shell,'--noprofile','--norc','-c',CMD_SCRIPT,'fixture','sudo','-u','parity',option]
        status,out,err,rows=run(base,'time-'+label,CMD_SCRIPT,args,[p],[])
        io=calls(rows);requests=[x for x in io if x.get('request')=='0xc340ba0b']
        results[label]=(status==0 and out==b'operation-status=0\n' and not err and len(requests)==1 and requests[0].get('valid'))
    for label,reset_decision in [('reset-failure',1),('reset-success',4)]:
        command,marker=command_for(base,label)
        steps=[step(5,reset_decision,[])]
        if reset_decision==4:steps.append(step(1,2,command,handle=77))
        args=[shell,'--noprofile','--norc','-c',CMD_SCRIPT,'fixture','sudo','-u','parity','-k','--',*command]
        status,out,err,rows=run(base,'time-'+label,CMD_SCRIPT,args,steps,command)
        io=calls(rows);auth=[x for x in io if x.get('request')=='0xc340ba0b'];hand=[x for x in io if x.get('request')=='0xc128ba0d']
        if reset_decision==1:
            results[label]=(status==0 and out==b'operation-status=1\n' and bool(err) and len(auth)==1 and auth[0].get('valid') and not hand and not marker.exists())
        else:
            results[label]=(status==0 and out==b'operation-status=7\n' and not err and len(auth)==2 and
                            all(x.get('valid') for x in auth) and len(hand)==1 and hand[0].get('valid') and marker.exists())
    record('timestamp-outcome',results=results)
    print('timestamp reset=%s reset-all=%s validate=%s failed-reset-stops=%s successful-reset-runs=%s' %
          tuple(yes(results[x]) for x in ('reset','reset-all','validate','reset-failure','reset-success')))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('auth','sudo','doas','timestamp');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:]
            if scenario=='auth':auth_case(shell)
            elif scenario in ('sudo','doas'):command_case(shell,scenario)
            elif scenario=='timestamp':timestamp(shell)
            else:raise ValueError('unknown scenario')
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
