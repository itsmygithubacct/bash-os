#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM sudoedit client checks; no privileged file access."""
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
MOCK='/opt/bashos-parity/harness/helpers/auth-client-edit-peer-bootstrap-r1.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'sudo-edit-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def rows(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


CONTROL=r'''import ctypes,errno,fcntl,hashlib,os,struct,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
target=Path(sys.argv[1]);other=Path(sys.argv[2]);fd=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC)
ab=os.fsencode(target)+b'\0';eb=b'CONTROL=yes\0';a=ctypes.create_string_buffer(ab);e=ctypes.create_string_buffer(eb)
u=os.getuid();g=os.getgid();fields=(6,0,0,u,g,u,g,1,1,len(ab),len(eb));strings=[str(u).encode(),b'parity',os.getcwd().encode()]
wire=b'bashos-privcmd-v'+struct.pack('<11I',*fields)
for s in strings:wire+=struct.pack('<I',len(s))+s
original=bytearray(832);struct.pack_into('<I',original,0,832);struct.pack_into('<11I',original,4,*fields)
struct.pack_into('<QQ',original,48,ctypes.addressof(a),ctypes.addressof(e));original[96:128]=hashlib.sha256(wire+ab+eb).digest()
for offset,s in zip((128,192,256),strings):original[offset:offset+len(s)]=s
bad=bytearray(original);bad[96]^=1
try:fcntl.ioctl(fd,0xc340ba0b,bad,True);raise AssertionError('digest accepted')
except OSError as ex:assert ex.errno==errno.EPROTO
first=bytearray(original);fcntl.ioctl(fd,0xc340ba0b,first,True);assert struct.unpack_from('<I',first,512)[0]==3
h1=struct.unpack_from('<Q',first,768)[0];assert h1==77
paths=ctypes.create_string_buffer(256);opening=bytearray(296);struct.pack_into('<IIII',opening,0,296,1,1,1)
struct.pack_into('<Q',opening,32,h1);struct.pack_into('<QI',opening,216,ctypes.addressof(a),len(ab))
struct.pack_into('<QI',opening,256,ctypes.addressof(paths),256)
fcntl.ioctl(fd,0xc128ba0d,opening,True);assert struct.unpack_from('<I',opening,232)[0]==1 and struct.unpack_from('<I',opening,252)[0]==1
size=struct.unpack_from('<I',opening,268)[0];temp=Path(os.fsdecode(paths.raw[:size].split(b'\0')[0]));assert temp.read_bytes()==b'control-before\n'
temp.write_bytes(b'control-after\n')
second=bytearray(original);fcntl.ioctl(fd,0xc340ba0b,second,True);h2=struct.unpack_from('<Q',second,768)[0];assert h2==78 and h2!=h1
badfd=os.open(other,os.O_RDONLY);goodfd=os.open(temp,os.O_RDONLY);vector=(ctypes.c_uint32*1)(badfd)
h=bytearray(296);struct.pack_into('<IIII',h,0,296,1,2,1);struct.pack_into('<Q',h,32,h2)
struct.pack_into('<QI',h,216,ctypes.addressof(a),len(ab));struct.pack_into('<QI',h,272,ctypes.addressof(vector),1)
try:fcntl.ioctl(fd,0xc128ba0d,h,True);raise AssertionError('wrong fd accepted')
except OSError as ex:assert ex.errno==errno.EPERM
vector[0]=goodfd;fcntl.ioctl(fd,0xc128ba0d,h,True);assert struct.unpack_from('<I',h,232)[0]==1
assert target.read_bytes()==b'control-after\n';os.close(badfd);os.close(goodfd);os.close(fd);temp.unlink();print('edit-control=ok')
'''


EDITOR=r'''import json,os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
files=[Path(x) for x in sys.argv[1:]];assert 1<=len(files)<=16
marker=Path(os.environ['EDIT_MARKER']).resolve();assert marker.is_relative_to(Path('/tmp/parity-case'))
for i,p in enumerate(files):
 assert p.resolve().is_relative_to(Path('/tmp/parity-case'))
 fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW);st=os.fstat(fd);assert st.st_uid==2000
 try:os.lseek(fd,0,os.SEEK_END);os.write(fd,('edited-%d\n'%i).encode())
 finally:os.close(fd)
marker.write_text(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'files':[str(x) for x in files]}))
sys.exit(3 if os.environ.get('EDITOR_FAIL')=='1' else 0)
'''


SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
sudo -n -u parity -e "$@"; result=$?
printf 'status=%d\n' "$result"
'''


def step(argv,decision,handle=0,noninteractive=1):
    user=pwd.getpwnam('parity');return {'mode':6,'decision':decision,'flags':0,'noninteractive':noninteractive,
        'target_uid':user.pw_uid,'target_gid':user.pw_gid,'target_user':'parity','argv':list(map(str,argv)),
        'env_contains':[],'handle':handle}


def invoke(base,label,argv,targets,plans,**options):
    trace=HOME/('sudo-edit-trace-'+label+'.jsonl');temp=base/'temps';temp.mkdir(exist_ok=True);cfg=base/(label+'.json')
    cfg.write_text(json.dumps({'trace':str(trace),'allowed_argv':list(map(str,targets)),'temp_dir':str(temp),'steps':plans,**options}))
    editor=base/'editor.py';editor.write_text(EDITOR);marker=base/(label+'.editor-marker')
    env=dict(os.environ,SUDO_EDITOR='/usr/bin/python3 '+str(editor),EDIT_MARKER=str(marker))
    if options.get('editor_fail'):env['EDITOR_FAIL']='1'
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),*map(str,argv)],cwd=base,env=env,stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=4);raise RuntimeError(label+' timed out')
    ev=rows(trace);mark=json.loads(marker.read_text()) if marker.exists() else None
    record('run',label=label,status=p.returncode,stdout_base64=b64(out),stderr_base64=b64(err),editor=mark,events=len(ev))
    return {'rc':p.returncode,'out':out,'err':err,'rows':ev,'editor':mark,'tempdir':temp}


def setup(scenario):
    assert not os.path.lexists('/dev/bashos-auth')
    user=pwd.getpwnam('parity');assert user.pw_uid==user.pw_gid==2000
    base=CASE/'sudo-edit-control';base.mkdir(mode=0o700);target=base/'target';target.write_bytes(b'control-before\n')
    other=base/'other';other.write_bytes(b'other\n');control=base/'control.py';control.write_text(CONTROL)
    plans=[step([target],3,77,0),step([target],3,78,0)]
    for p in plans:p['env_contains']=['CONTROL=yes']
    result=invoke(base,'control',['/usr/bin/python3',control,target,other],[target],plans)
    ops=[x.get('transition',{}).get('op') for x in result['rows'] if x.get('transition')]
    errors=[x.get('reply') for x in result['rows'] if x['syscall']=='ioctl' and str(x.get('reply','')).startswith('errno:')]
    assert result['rc']==0 and result['out']==b'edit-control=ok\n' and not result['err']
    assert ops==['authz','edit-open-synthetic','authz','edit-copyback-synthetic'] and 'errno:71' in errors and 'errno:1' in errors
    assert not list(result['tempdir'].iterdir())
    record('control',scenario=scenario,operations=ops,rejected_digest=True,rejected_wrong_fd=True)
    print('controls=verified')


def run_case(shell,label,n,kind):
    base=CASE/('sudo-edit-'+label);base.mkdir(mode=0o700)
    targets=[base/('target-%02d'%i) for i in range(n)]
    before=[('before-%d\n'%i).encode() for i in range(n)]
    for p,data in zip(targets,before):p.write_bytes(data);os.chmod(p,0o600)
    plans=[step(targets,3,77),step(targets,1 if kind=='deny' else 3,78 if kind!='deny' else 0)]
    options={'copyback_error':kind=='copyback','open_error':kind=='open','editor_fail':kind=='editor'}
    args=[shell,'--noprofile','--norc','-c',SCRIPT,'edit',*targets]
    result=invoke(base,label,args,targets,plans,**options)
    result.update(targets=targets,before=before,after=[p.read_bytes() for p in targets]);return result


def details(result):
    r=result['rows'];auth=[x for x in r if x.get('request')=='0xc340ba0b'];handoff=[x for x in r if x.get('request')=='0xc128ba0d']
    ops=[x.get('transition',{}).get('op') for x in r if x.get('transition')]
    return auth,handoff,ops


def success(shell):
    outcomes=[]
    for n in (1,2,16):
        result=run_case(shell,'ok-%d'%n,n,'ok');auth,hand,ops=details(result)
        wanted=[old+('edited-%d\n'%i).encode() for i,old in enumerate(result['before'])]
        passed=(result['rc']==0 and result['out']==b'status=0\n' and not result['err'] and result['after']==wanted and
                result['editor'] is not None and result['editor']['uid']==2000 and result['editor']['gid']==2000 and
                len(result['editor']['files'])==n and not list(result['tempdir'].iterdir()) and
                len(auth)==2 and all(x.get('valid') for x in auth) and auth[0]['received_digest']==auth[1]['received_digest'] and
                len(hand)==2 and all(x.get('valid') for x in hand) and [x['flags'] for x in hand]==[1,2] and
                hand[0]['handle']==77 and hand[1]['handle']==78 and hand[1]['temp_fds'] and len(hand[1]['temp_fds'])==n and
                [base64.b64decode(x) for x in hand[1]['edited_base64']]==wanted and
                ops==['authz','edit-open-synthetic','authz','edit-copyback-synthetic'])
        outcomes.append(passed);record('success-result',count=n,valid=passed,operations=ops,auth=auth,handoff=hand)
    print('sudo-edit single=%s multi=%s max16=%s' % tuple(yes(x) for x in outcomes))


def reject(shell):
    outcomes={}
    for kind in ('deny','copyback','editor','open'):
        result=run_case(shell,'reject-'+kind,2,kind);auth,hand,ops=details(result)
        base=(result['rc']==0 and result['out']==b'status=1\n' and bool(result['err']) and result['after']==result['before'] and not list(result['tempdir'].iterdir()))
        if kind=='deny':ok=base and result['editor'] is not None and len(auth)==2 and len(hand)==1 and ops==['authz','edit-open-synthetic','authz']
        elif kind=='copyback':ok=base and result['editor'] is not None and len(auth)==2 and len(hand)==2 and hand[-1]['reply']=='errno:13' and hand[-1]['valid']
        elif kind=='editor':ok=base and result['editor'] is not None and len(auth)==1 and len(hand)==1 and ops==['authz','edit-open-synthetic']
        else:ok=base and result['editor'] is None and len(auth)==1 and len(hand)==1 and hand[0]['reply']=='errno:13'
        outcomes[kind]=ok;record('reject-result',scenario=kind,valid=ok,operations=ops,auth=auth,handoff=hand)
    base=CASE/'sudo-edit-invalid';base.mkdir(mode=0o700);paths=[base/('target-%02d'%i) for i in range(17)]
    for p in paths:p.write_text('unchanged\n')
    over=invoke(base,'over17',[shell,'--noprofile','--norc','-c',SCRIPT,'edit',*paths],paths,[])
    relative=invoke(base,'relative',[shell,'--noprofile','--norc','-c',SCRIPT,'edit','relative-target'],[],[])
    valid=lambda r:r['rc']==0 and r['out']==b'status=2\n' and bool(r['err']) and r['editor'] is None and not any(x.get('request') in ('0xc340ba0b','0xc128ba0d') for x in r['rows'])
    invalid=valid(over) and valid(relative) and all(p.read_text()=='unchanged\n' for p in paths)
    record('invalid-result',count_and_relative=invalid)
    print('sudo-edit reauth-denied=%s copyback-denied=%s editor-failed=%s open-failed=%s invalid=%s' % tuple(yes(x) for x in (outcomes['deny'],outcomes['copyback'],outcomes['editor'],outcomes['open'],invalid)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('success','reject');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:];{'success':success,'reject':reject}[scenario](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
