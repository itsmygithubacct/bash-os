#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only verifier request/fail-closed reauthorization observations."""
import base64
import fcntl
import json
import os
from pathlib import Path
import pty
import pwd
import select
import signal
import subprocess
import sys
import termios
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home');MOCK='/opt/bashos-parity/harness/helpers/auth-client-verify-peer-bootstrap-r1.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'auth-verify-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def rows(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


CONTROL=r'''import ctypes,errno,fcntl,hashlib,os,struct,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
fail=sys.argv[1]=='fail';argv=[x.encode() for x in sys.argv[2:]];ab=b''.join(x+b'\0' for x in argv);eb=b'CONTROL=yes\0'
a=ctypes.create_string_buffer(ab);e=ctypes.create_string_buffer(eb);u=os.getuid();g=os.getgid()
fields=(1,0,0,u,g,u,g,len(argv),1,len(ab),len(eb));strings=[str(u).encode(),b'parity',os.getcwd().encode()]
wire=b'bashos-privcmd-v'+struct.pack('<11I',*fields)
for s in strings:wire+=struct.pack('<I',len(s))+s
req=bytearray(832);struct.pack_into('<I',req,0,832);struct.pack_into('<11I',req,4,*fields)
struct.pack_into('<QQ',req,48,ctypes.addressof(a),ctypes.addressof(e));req[96:128]=hashlib.sha256(wire+ab+eb).digest()
for off,s in zip((128,192,256),strings):req[off:off+len(s)]=s
fd=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC);fcntl.ioctl(fd,0xc340ba0b,req,True)
assert struct.unpack_from('<I',req,512)[0]==6
verify=bytearray(176);struct.pack_into('<12I',verify,0,176,0,1,u,g,u,g,17,0,30,0,0)
verify[48:80]=req[96:128];verify[80:112]=bytes.fromhex('22'*32);bad=bytearray(verify);bad[48]^=1
try:fcntl.ioctl(fd,0xc0b0ba0f,bad,True);raise AssertionError('bad verify binding accepted')
except OSError as ex:assert ex.errno==errno.EPROTO
try:
 fcntl.ioctl(fd,0xc0b0ba0f,verify,True)
 if fail:raise AssertionError('expected injected failure')
except OSError as ex:assert fail and ex.errno==errno.EACCES
os.close(fd);print('verify-control=ok')
'''


CHILD=r'''import os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
p=Path(sys.argv[1]).resolve();assert p.is_relative_to(Path('/tmp/parity-case'));p.write_text('unexpected child\n')
sys.exit(7)
'''


SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
printf 'parent-before=%s:%s\n' "$UID" "$EUID"
"$@"; rc=$?
printf 'operation-status=%d\n' "$rc"
printf 'parent-after=%s:%s\n' "$UID" "$EUID"
'''


def step(argv,decision,env=()):
    u=pwd.getpwnam('parity');return {'mode':1,'decision':decision,'flags':0,'noninteractive':0,'target_uid':u.pw_uid,'target_gid':u.pw_gid,
                                     'target_user':'parity','argv':list(map(str,argv)),'env_contains':list(env),'handle':0}


def config(base,label,command,plans,fail):
    trace=HOME/('auth-verify-trace-'+label+'.jsonl');cfg=base/(label+'.json')
    cfg.write_text(json.dumps({'trace':str(trace),'steps':plans,'allowed_argv':list(map(str,command)),'verify_error':fail}))
    return cfg,trace


def setup(kind):
    assert not os.path.lexists('/dev/bashos-auth');u=pwd.getpwnam('parity');assert u.pw_uid==u.pw_gid==2000
    base=CASE/'auth-verify-control';base.mkdir(mode=0o700);control=base/'control.py';control.write_text(CONTROL)
    command=['/usr/bin/python3',str(base/'child.py'),str(base/'marker'),'7']
    for mode in ('ok','fail'):
        cfg,trace=config(base,'control-'+mode,command,[step(command,6,['CONTROL=yes'])],mode=='fail')
        proc=subprocess.run(['/usr/bin/python3',MOCK,str(cfg),'/usr/bin/python3',str(control),mode,*command],cwd=base,
                            env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        rr=rows(trace);verify=[x for x in rr if x.get('request')=='0xc0b0ba0f']
        assert proc.returncode==0 and proc.stdout==b'verify-control=ok\n' and not proc.stderr and len(verify)==2
        assert verify[0]['reply']=='errno:71' and not verify[0]['valid']
        assert verify[1]['valid'] and verify[1]['reply']==('errno:13' if mode=='fail' else 'value:0')
    record('controls',client_kind=kind,digest_mismatch='rejected',synthetic_success_and_failure='verified')
    print('controls=verified')


def run(shell,kind,label,decisions,fail):
    base=CASE/('auth-verify-'+kind+'-'+label);base.mkdir(mode=0o700);child=base/'child.py';child.write_text(CHILD);marker=base/'child-marker'
    command=['/usr/bin/python3',str(child),str(marker),'7'];plans=[step(command,d) for d in decisions];cfg,trace=config(base,label,command,plans,fail)
    argv=[kind,'-u','parity','--',*command]
    master,slave=pty.openpty();before=termios.tcgetattr(master);output=bytearray()
    def session():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),shell,'--noprofile','--norc','-c',SCRIPT,'verify',*argv],
                       cwd=base,env=dict(os.environ),stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,close_fds=True)
    try:
        end=time.monotonic()+18
        while p.poll() is None and time.monotonic()<end:
            r,_,_=select.select([master],[],[],.1)
            if r:output.extend(os.read(master,8192))
        if p.poll() is None:raise RuntimeError(label+' timeout')
        for _ in range(8):
            r,_,_=select.select([master],[],[],.02)
            if not r:break
            output.extend(os.read(master,8192))
        status=p.wait(timeout=3);after=termios.tcgetattr(master)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=3)
        os.close(master);os.close(slave)
    rr=rows(trace);out=bytes(output);auth=[x for x in rr if x.get('request')=='0xc340ba0b'];verify=[x for x in rr if x.get('request')=='0xc0b0ba0f']
    result={'status':status,'output':out,'auth':auth,'verify':verify,'rows':rr,'restored':before==after,'nochild':not marker.exists()}
    record('run',client_kind=kind,label=label,status=status,output_base64=b64(out),auth=auth,verify=verify,restored=before==after,nochild=not marker.exists())
    return result


def scenario(shell,kind):
    failure=run(shell,kind,kind+'-fail',[6],True)
    denied=run(shell,kind,kind+'-deny',[6,1],False)
    again=run(shell,kind,kind+'-again',[6,6],False)
    def common(r):
        return (r['status']==0 and r['restored'] and r['nochild'] and b'parent-before=2000:2000\r\n' in r['output'] and b'parent-after=2000:2000\r\n' in r['output'] and
                all(x.get('valid') for x in r['auth']+r['verify']) and not any(x.get('request') in ('0xc128ba0d','0xc128ba0e') for x in r['rows']))
    bad=(common(failure) and len(failure['auth'])==len(failure['verify'])==1 and failure['verify'][0]['reply']=='errno:13' and b'operation-status=126\r\n' in failure['output'])
    closed=(common(denied) and len(denied['auth'])==2 and len(denied['verify'])==1 and denied['verify'][0]['reply']=='value:0' and denied['auth'][0]['received_digest']==denied['auth'][1]['received_digest'] and b'operation-status=125\r\n' in denied['output'])
    repeated=(common(again) and len(again['auth'])==2 and len(again['verify'])==2 and all(x['reply']=='value:0' for x in again['verify']) and b'operation-status=1\r\n' in again['output'])
    record('outcome',client_kind=kind,failed=bad,denied=closed,still_required=repeated)
    print('%s-verifier failed=%s denied=%s still-required=%s' % (kind,yes(bad),yes(closed),yes(repeated)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('doas','sudo');setup(sys.argv[2])
        else:
            shell,kind=sys.argv[1:];assert kind in ('doas','sudo');scenario(shell,kind)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
