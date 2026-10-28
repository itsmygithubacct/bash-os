#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only passwd and su client protocol cases; no credential transition."""
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
import stat
import struct
import subprocess
import sys
import termios
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
MOCK='/opt/bashos-parity/harness/helpers/auth-client-dependent-bootstrap-r1.py'
PASSWORD=b'password';WRONG=b'wrong'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def b64(x):return base64.b64encode(x[:65536]).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'dependent-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def kdf(password,salt,t,m,p,n):
    import importlib.util
    path='/opt/bashos-parity/harness/helpers/auth-client-argon2-cli-r1.py'
    spec=importlib.util.spec_from_file_location('auth_argon2_cli',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.derive(password,salt,t,m,p,n,record)


def phc_digest(phc,password):
    try:
        fields=phc.split('$'); assert len(fields)==6 and fields[1]=='argon2id' and fields[2]=='v=19'
        params=dict(x.split('=',1) for x in fields[3].split(','));m=int(params['m']);t=int(params['t']);p=int(params['p'])
        decode=lambda x:base64.b64decode(x+'='*((-len(x))%4),validate=True)
        salt=decode(fields[4]);digest=decode(fields[5])
        if m!=1024 or t!=1 or p!=1 or len(salt)!=16 or len(digest)!=32:return False
        return kdf(password,salt,t,m,p,len(digest))==digest
    except (ValueError,AssertionError,KeyError):return False


def fixture(base):
    base.mkdir(mode=0o700);db=base/'db';db.mkdir(mode=0o700)
    digest=kdf(PASSWORD,b'somesalt',1,1024,1,32)
    standard='$argon2id$v=19$m=1024,t=1,p=1$'+b'somesalt'.hex()+'$'+digest.hex()
    record('synthetic-shadow',format='project-hex-fields',value=standard,salt_hex=b'somesalt'.hex(),independent_digest_hex=digest.hex())
    (db/'passwd').write_text('alice:x:1000:1000:Alice:'+str(base)+':/bin/bash\nfixture:x:2000:2000:Fixture:'+str(base)+':/bin/bash\n')
    (db/'group').write_text('alice:x:1000:\nfixture:x:2000:\n')
    (db/'shadow').write_text('alice:'+standard+':19000:0:99999:7:::\nfixture:'+standard+':19000:0:99999:7:::\n');os.chmod(db/'shadow',0o600)
    (base/'good').write_bytes(PASSWORD+b'\n');(base/'wrong').write_bytes(WRONG+b'\n')
    env=dict(os.environ,PHCLIB_PASSWD=str(db/'passwd'),PHCLIB_GROUP=str(db/'group'),PHCLIB_SHADOW=str(db/'shadow'),
             BPW_LOCK_DIR=str(base/'lock'),PHCLIB_M='1024',PHCLIB_T='1',PHCLIB_P='1',BASHPASSWD_REQUIRE_KERNEL_SECRETS='1')
    env.pop('BASHPASSWD_KERNEL_SECRETS',None)
    return db,env


def cfg(base,label,**kwargs):
    path=base/(label+'.json');trace=HOME/('dependent-trace-'+label+'.jsonl')
    path.write_text(json.dumps({'trace':str(trace),**kwargs}));return path,trace


def trace_rows(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def plain(base,label,argv,env,**options):
    path,trace=cfg(base,label,**options)
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(path),*map(str,argv)],cwd=base,env=env,stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=25)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError(label+' timeout')
    rows=trace_rows(trace);record('run',label=label,status=p.returncode,stdout_base64=b64(out),stderr_base64=b64(err),events=len(rows))
    return p.returncode,out,err,rows


CONTROL=r'''import ctypes,errno,fcntl,os,struct,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
f=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC);g=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC)
h=bytearray(8);fcntl.ioctl(f,0xc008ba02,h,True);ident=struct.unpack_from('<I',h)[0]
for chunk in (b'one',b'two'):
 v=ctypes.create_string_buffer(chunk);w=bytearray(struct.pack('<IIQ',ident,len(chunk),ctypes.addressof(v)));fcntl.ioctl(f,0x4010ba03,w,True)
fcntl.ioctl(f,0x4008ba04,bytearray(h),True)
try:fcntl.ioctl(g,0x4008ba04,bytearray(h),True);raise AssertionError('cross-descriptor handle')
except OSError as e:assert e.errno==errno.ENOENT
v=ctypes.create_string_buffer(64);e=bytearray(struct.pack('<IIQ',ident,64,ctypes.addressof(v)));fcntl.ioctl(f,0xc010ba06,e,True)
assert v.raw[:6]==b'onetwo' and struct.unpack_from('<I',e,4)[0]==6
try:fcntl.ioctl(f,0xc010ba06,e,True);raise AssertionError('second export')
except OSError as ex:assert ex.errno==errno.EPERM
assert os.geteuid()==2000
mint=bytearray(struct.pack('<IIII32s64sII',2000,2000,2,5,bytes(32),b'fixture',0,0))
fcntl.ioctl(f,0xc078ba08,mint,True)
bad=bytearray(mint);bad[16]^=1
try:fcntl.ioctl(f,0x4078ba09,bad,True);raise AssertionError('bad token accepted')
except OSError as ex:assert ex.errno==errno.EPERM
assert os.geteuid()==2000
fcntl.ioctl(f,0x4078ba09,bytearray(mint),True)
assert os.geteuid()==0
line=next(x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('Uid:'))
assert [int(x) for x in line.split()[1:]]==[2000,2000,2000,2000]
assert os.geteuid()==2000
try:os.setgroups([]);raise AssertionError('credential mutation accepted')
except OSError as ex:assert ex.errno==errno.EPERM
os.close(f);os.close(g);print('control=ok')
'''


def setup(scenario):
    assert not os.path.lexists('/dev/bashos-auth')
    assert kdf(b'password',b'somesalt',2,65536,1,32).hex()=='09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'
    base=CASE/'dependent-control';base.mkdir(mode=0o700);control=base/'control.py';control.write_text(CONTROL)
    rc,out,err,rows=plain(base,'control',['/usr/bin/python3',control],dict(os.environ),capture_credentials=True)
    ops=[x.get('transition',{}).get('op') for x in rows if x.get('transition')]
    assert rc==0 and out==b'control=ok\n' and not err and ops==['new','write','write','seal','export-once','mint-synthetic','consume-synthetic']
    spoof=[x for x in rows if x['syscall']=='geteuid']
    assert len(spoof)==1 and spoof[0]['reply']=='value:0' and [int(n) for n in spoof[0]['actual_uid_status'].split()[1:]]==[2000]*4
    assert any(x['syscall']=='setgroups' and x.get('reply')=='errno:1' for x in rows)
    assert any(x.get('reply')=='errno:2' for x in rows) and any(x.get('reply')=='errno:1' and x.get('syscall')=='ioctl' for x in rows)
    record('controls',scenario=scenario,operations=ops,credential_interception='verified',scoped_euid_response='verified-once-after-consume',reference_kat='verified')
    print('controls=verified')


def slot_protocol(rows,expected):
    opens=[x for x in rows if x['syscall'] in ('open','openat')]
    io=[x for x in rows if x['syscall']=='ioctl']
    if len(opens)!=len(expected):return False
    for index,want in enumerate(expected,1):
        mine=[x for x in io if x.get('ordinal')==index]
        ops=[x.get('transition',{}).get('op') for x in mine if x.get('transition')]
        writes=[base64.b64decode(x['transition']['data_base64']) for x in mine if x.get('transition',{}).get('op')=='write']
        if ops!=['new']+['write']*len(writes)+['seal','export-once','clear'] or b''.join(writes)!=want:return False
        if any(x.get('reply')!='value:0' for x in mine):return False
    return True


SET_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
passwd set-fd alice 3 3< "$1"; rc=$?
printf 'set-status=%d\n' "$rc"
'''


def password_set(shell):
    base=CASE/'dependent-set';db,env=fixture(base);before=(db/'shadow').read_bytes();pwb=(db/'passwd').read_bytes();grb=(db/'group').read_bytes()
    rc,out,err,rows=plain(base,'set',[shell,'--noprofile','--norc','-c',SET_SCRIPT,'fixture',base/'good'],env)
    shadow=(db/'shadow').read_text();row=next((x for x in shadow.splitlines() if x.startswith('alice:')),'');parts=row.split(':');phc=parts[1] if len(parts)>1 else ''
    exact=(rc==0 and out==b'set-status=0\n' and not err and (db/'passwd').read_bytes()==pwb and
           (db/'group').read_bytes()==grb and stat.S_IMODE((db/'shadow').stat().st_mode)==0o600 and
           parts[2:] == ['%d'%(int(time.time())//86400),'0','99999','7','','',''])
    kdf_ok=phc_digest(phc,PASSWORD);protocol=slot_protocol(rows,[PASSWORD])
    record('set-result',shadow_before_base64=b64(before),shadow_after_base64=b64(shadow.encode()),stdout_base64=b64(out),
           exact=exact,standard_phc_kdf=kdf_ok,protocol=protocol)
    print('passwd-set device-path=%s update=%s independent-phc=%s' % (yes(protocol),yes(exact),yes(kdf_ok)))


VERIFY_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
for ((i=1;i<=4;i++)); do passwd verify-fd alice 3 3< "$1"; printf 'w%d=%d\n' "$i" "$?"; done
printf '%s\n' "$(<"$3/fail.1000")" > state-four
passwd verify-fd alice 3 3< "$2"; printf 'good=%d\n' "$?"
[[ -e "$3/fail.1000" ]] && printf 'good-cleared=no\n' || printf 'good-cleared=yes\n'
for ((i=1;i<=5;i++)); do passwd verify-fd alice 3 3< "$1"; printf 'lock%d=%d\n' "$i" "$?"; done
printf '%s\n' "$(<"$3/fail.1000")" > state-locked
passwd verify-fd alice 3 3< "$2"; printf 'locked-good=%d\n' "$?"
printf 'COUNT=5\nLAST=1\nLOCKED_UNTIL=1\n' > "$3/fail.1000"
passwd verify-fd alice 3 3< "$2"; printf 'expired-good=%d\n' "$?"
[[ -e "$3/fail.1000" ]] && printf 'expired-cleared=no\n' || printf 'expired-cleared=yes\n'
'''


def parse_state(path):
    try:return dict(line.split('=',1) for line in path.read_text().splitlines())
    except (OSError,ValueError):return {}


def password_verify(shell):
    base=CASE/'dependent-verify';db,env=fixture(base)
    rc,out,err,rows=plain(base,'verify',[shell,'--noprofile','--norc','-c',VERIFY_SCRIPT,'fixture',base/'wrong',base/'good',base/'lock'],env)
    expected=(b'w1=1\nw2=1\nw3=1\nw4=1\ngood=0\ngood-cleared=yes\n'
              b'lock1=1\nlock2=1\nlock3=1\nlock4=1\nlock5=1\nlocked-good=1\nexpired-good=0\nexpired-cleared=yes\n')
    four=parse_state(base/'state-four');locked=parse_state(base/'state-locked')
    try:state_ok=(four['COUNT']=='4' and four['LOCKED_UNTIL']=='0' and locked['COUNT']=='5' and
                  int(locked['LOCKED_UNTIL'])-int(locked['LAST'])==900)
    except (KeyError,ValueError):state_ok=False
    protocol=slot_protocol(rows,[WRONG]*4+[PASSWORD]+[WRONG]*5+[PASSWORD,PASSWORD])
    statuses=rc==0 and out==expected and b'account locked' in err
    record('verify-result',stdout_base64=b64(out),stderr_base64=b64(err),state_four=four,state_locked=locked,
           statuses=statuses,lock_state=state_ok,protocol=protocol)
    print('passwd-verify device-path=%s statuses=%s lockout=%s' % (yes(protocol),yes(statuses),yes(state_ok)))


SU_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
su --no-login -c "$1" fixture; rc=$?
printf 'su-status=%d\n' "$rc"
'''


def tty_run(base,label,shell,env,secret,expect_prompt=True,**options):
    path,trace=cfg(base,label,capture_credentials=True,**options)
    marker=base/(label+'.child-marker');command=': > '+str(marker)
    master,slave=pty.openpty();before=termios.tcgetattr(master);output=bytearray();off=False
    def session():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(path),shell,'--noprofile','--norc','-c',SU_SCRIPT,'fixture',command],
                       cwd=base,env=env,stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,close_fds=True)
    try:
        end=time.monotonic()+15
        if expect_prompt:
            while b'Password: ' not in output and p.poll() is None and time.monotonic()<end:
                ready,_,_=select.select([master],[],[],.1)
                if ready:output.extend(os.read(master,4096))
            if b'Password: ' not in output:raise RuntimeError(label+' missing password prompt')
            off=not bool(termios.tcgetattr(master)[3]&termios.ECHO);os.write(master,secret+b'\n')
        while p.poll() is None and time.monotonic()<end:
            ready,_,_=select.select([master],[],[],.1)
            if ready:output.extend(os.read(master,4096))
        if p.poll() is None:raise RuntimeError(label+' timeout')
        for _ in range(10):
            ready,_,_=select.select([master],[],[],.02)
            if not ready:break
            output.extend(os.read(master,4096))
        status=p.wait(timeout=3);after=termios.tcgetattr(master)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=3)
        os.close(master);os.close(slave)
    rows=trace_rows(trace);output=bytes(output)
    record('tty-run',label=label,status=status,output_base64=b64(output),echo_off=off,
           restored=before==after,secret_absent=secret not in output,marker_exists=marker.exists(),events=len(rows))
    return status,output,rows,off,before==after,not marker.exists()


def su_token(shell):
    base=CASE/'dependent-su-token';db,env=fixture(base);results={}
    scenarios=[('success',{}),('mint-failure',{'mint_error':True}),('consume-failure',{'consume_error':'reject'}),('expired',{'consume_error':'expired'})]
    for label,opts in scenarios:
        status,out,rows,off,restored,nochild=tty_run(base,'su-'+label,shell,env,PASSWORD,**opts)
        mint=[x for x in rows if x.get('request')=='0xc078ba08'];consume=[x for x in rows if x.get('request')=='0x4078ba09']
        changes=[x for x in rows if x['syscall'] in ('setgroups','setresgid','setresuid','setgid','setuid','setregid','setreuid')]
        spoof=[x for x in rows if x['syscall']=='geteuid']
        valid_mint=(len(mint)==1 and len(bytes.fromhex(mint[0]['input_hex']))==120)
        if valid_mint:
            uid,gid,purpose,expires=struct.unpack_from('<IIII',bytes.fromhex(mint[0]['input_hex']))
            valid_mint=(uid==2000 and gid==2000 and purpose==2 and expires==5 and
                        bytes.fromhex(mint[0]['input_hex'])[48:112].split(b'\0',1)[0]==b'fixture')
        common=status==0 and b'su-status=1\r\n' in out and off and restored and PASSWORD not in out and nochild and valid_mint
        if label=='success':
            good=(common and len(consume)==1 and consume[0].get('token_match') and consume[0]['reply']=='value:0' and
                  len(spoof)==1 and spoof[0]['reply']=='value:0' and [int(n) for n in spoof[0]['actual_uid_status'].split()[1:]]==[2000]*4 and
                  len(changes)==1 and changes[0]['syscall']=='setgroups' and changes[0]['reply']=='errno:1' and
                  mint[0]['sequence']<consume[0]['sequence']<spoof[0]['sequence']<changes[0]['sequence'] and b'privdrop' in out)
        elif label=='mint-failure':
            good=common and mint[0]['reply']=='errno:13' and not consume and not spoof and not changes and b'token mint failed' in out
        else:
            expected_errno='errno:110' if label=='expired' else 'errno:13'
            good=common and len(consume)==1 and consume[0].get('token_match') and consume[0]['reply']==expected_errno and not spoof and not changes and b'token rejected' in out
        results[label]=good;record('su-token-result',label=label,valid=good,mint=mint,consume=consume,synthetic_euid=spoof,credential_attempts=changes)
    print('su-token mint-and-consume-order=%s mint-failure=%s consume-failure=%s expiry-failure=%s' %
          tuple(yes(results[x]) for x in ('success','mint-failure','consume-failure','expired')))


def su_lockout(shell):
    base=CASE/'dependent-su-lockout';db,env=fixture(base);lock=base/'lock'/'fail.2000';wrong=[]
    for i in range(1,6):
        status,out,rows,off,restored,nochild=tty_run(base,'lock-wrong-%d'%i,shell,env,WRONG)
        state=parse_state(lock)
        wrong.append(status==0 and b'su-status=1\r\n' in out and off and restored and nochild and
                     state.get('COUNT')==str(i) and not any(x.get('request')=='0xc078ba08' for x in rows))
    locked=parse_state(lock)
    try:period=int(locked['LOCKED_UNTIL'])-int(locked['LAST'])==900
    except (KeyError,ValueError):period=False
    status,out,rows,off,restored,nochild=tty_run(base,'lock-active',shell,env,PASSWORD,expect_prompt=False)
    active=(status==0 and b'account locked' in out and b'su-status=1\r\n' in out and b'Password: ' not in out and
            restored and nochild and not any(x.get('request')=='0xc078ba08' for x in rows))
    lock.write_text('COUNT=5\nLAST=1\nLOCKED_UNTIL=1\n');os.chmod(lock,0o600)
    status,out,rows,off,restored,nochild=tty_run(base,'lock-expired',shell,env,PASSWORD)
    expired=(status==0 and b'su-status=1\r\n' in out and off and restored and nochild and not lock.exists() and
             any(x.get('transition',{}).get('op')=='consume-synthetic' for x in rows))
    record('su-lockout-result',wrong=wrong,locked_state=locked,period=period,active=active,expired_success_clears=expired)
    print('su-lockout failures=%s duration=%s active-denied=%s expired-success-clears=%s' %
          (yes(all(wrong)),yes(period),yes(active),yes(expired)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('set','verify','su-token','su-lockout');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:]
            {'set':password_set,'verify':password_verify,'su-token':su_token,'su-lockout':su_lockout}[scenario](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
