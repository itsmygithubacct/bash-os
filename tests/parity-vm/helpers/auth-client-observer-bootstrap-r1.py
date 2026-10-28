#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guarded VM-only client-protocol observers for a synthetic auth device."""
import base64
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import pwd
import select
import signal
import socket
import subprocess
import sys
import termios
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
MOCK='/opt/bashos-parity/harness/helpers/auth-client-device-bootstrap-r1.py'
DEV='/dev/bashos-auth'; SYNTHETIC=b'terra-fixture-secret-42'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def record(kind,**values):
    values['kind']=kind
    with (HOME/'auth-observations.jsonl').open('a') as f:f.write(json.dumps(values,sort_keys=True)+'\n')


def b64(data):return base64.b64encode(data[:65536]).decode()
def yes(v):return 'yes' if v else 'no'


def termios_data(value):
    return {'iflag':value[0],'oflag':value[1],'cflag':value[2],'lflag':value[3],
            'ispeed':value[4],'ospeed':value[5],
            'cc':[x.hex() if isinstance(x,bytes) else x for x in value[6]]}


def config(base,label):
    path=base/(label+'.json');trace=HOME/('auth-trace-'+label+'.jsonl')
    path.write_text(json.dumps({'trace':str(trace)}));return path,trace


def trace_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def run(base,label,argv):
    cfg,trace=config(base,label)
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),*map(str,argv)],cwd=base,env=dict(os.environ),
                       stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError(label+' timed out')
    rows=trace_rows(trace)
    record('run',label=label,status=p.returncode,stdout_base64=b64(out),stderr_base64=b64(err),trace_rows=len(rows))
    return p.returncode,out,err,rows


CONTROL=r'''import ctypes,errno,fcntl,json,os,struct,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
c=ctypes.CDLL(None,use_errno=True); assert c.prctl(4,0,0,0,0)==0 and c.prctl(3,0,0,0,0)==1
f=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC);g=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC)
assert fcntl.fcntl(f,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
v=bytearray(32);fcntl.ioctl(f,0x8020ba01,v,True);assert bytes(v)==struct.pack('<IIQ16s',1,5,15,b'\0'*16)
a=bytearray(8);fcntl.ioctl(f,0xc008ba02,a,True);ident,flags=struct.unpack('<II',a);assert ident==4097 and flags==0
try:fcntl.ioctl(g,0x4008ba04,bytearray(a),True);raise AssertionError('cross-fd handle accepted')
except OSError as e:assert e.errno==errno.ENOENT
raw=ctypes.create_string_buffer(b'control-secret');w=bytearray(struct.pack('<IIQ',ident,14,ctypes.addressof(raw)))
fcntl.ioctl(f,0x4010ba03,w,True);fcntl.ioctl(f,0x4008ba04,bytearray(a),True)
try:fcntl.ioctl(f,0x4010ba03,w,True);raise AssertionError('sealed write accepted')
except OSError as e:assert e.errno==errno.EPERM
out=ctypes.create_string_buffer(64);ex=bytearray(struct.pack('<IIQ',ident,64,ctypes.addressof(out)))
fcntl.ioctl(f,0xc010ba06,ex,True);assert struct.unpack('<IIQ',ex)[1]==14 and out.raw[:14]==b'control-secret'
try:fcntl.ioctl(f,0xc010ba06,bytearray(struct.pack('<IIQ',ident,64,ctypes.addressof(out))),True);raise AssertionError('double export accepted')
except OSError as e:assert e.errno==errno.EPERM
fcntl.ioctl(f,0x4008ba05,bytearray(a),True)
try:fcntl.ioctl(f,0x0000ba7f,0);raise AssertionError('unknown ioctl accepted')
except OSError as e:assert e.errno==errno.ENOTTY
z=bytearray(128);fcntl.ioctl(f,0x8080ba0a,z,True);assert struct.unpack('<6Q',z[:48])==(102,103,103,104,105,106)
z=bytearray(128);fcntl.ioctl(g,0x8080ba0a,z,True);assert struct.unpack('<6Q',z[:48])==(201,202,203,204,205,206)
plain=os.open('/dev/null',os.O_RDWR|os.O_CLOEXEC)
try:fcntl.ioctl(plain,0x0000ba7f,0);raise AssertionError('unrelated ioctl accepted')
except OSError as e:assert e.errno==errno.ENOTTY
os.close(plain);os.close(f);os.close(g)
print('control=ok')
'''


FD_PROBE=r'''import json,os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
assert sys.argv[1].isdecimal()
pid=int(sys.argv[1]);assert pid==os.getppid()
def identity():
 raw=Path('/proc/%d/stat'%pid).read_text();fields=raw[raw.rindex(')')+2:].split()
 status=Path('/proc/%d/status'%pid).read_text().splitlines()
 uid=next([int(x) for x in row.split()[1:]] for row in status if row.startswith('Uid:'))
 assert fields[0]!='Z' and uid[:2]==[2000,2000]
 return (int(fields[1]),int(fields[19]),uid)
before=identity();res=[]
for fd in sys.argv[2:]:
 info=Path('/proc/%s/fdinfo/%s'%(pid,fd)).read_text()
 flags=int(next(x.split()[1] for x in info.splitlines() if x.startswith('flags:')),8)
 target=os.readlink('/proc/%s/fd/%s'%(pid,fd))
 try:child=os.readlink('/proc/self/fd/%s'%fd)
 except OSError:child=None
 res.append({'fd':int(fd),'parent':target,'child':child,'flags':flags,'fdinfo':info})
assert pid==os.getppid() and identity()==before
print(json.dumps(res,sort_keys=True))
'''


def setup(scenario):
    assert not os.path.lexists(DEV), 'real device present: use an isolated standard guest'
    base=CASE/'auth-control';base.mkdir(mode=0o700)
    control=base/'control.py';control.write_text(CONTROL)
    rc,out,err,rows=run(base,'control',['/usr/bin/python3',control])
    assert rc==0 and out==b'control=ok\n' and not err
    ops=[x.get('transition',{}).get('op') for x in rows if x.get('transition')]
    assert ops==['new','write','seal','export-once','clear'],ops
    assert sum(x.get('deviation')=='PR_SET_DUMPABLE(0) acknowledged, not applied' for x in rows)==1
    assert sum(x.get('reply')=='errno:1' for x in rows)>=2
    assert any(x.get('reply')=='errno:2' for x in rows) and any(x.get('reply')=='errno:25' for x in rows)
    probe=base/'fd-control.py';probe.write_text(FD_PROBE)
    a,b=socket.socketpair()
    try:
        cmd=['/usr/bin/python3',str(probe),str(os.getpid()),str(a.fileno())]
        negative=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        positive=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(a.fileno(),),timeout=5)
        assert negative.returncode==positive.returncode==0 and not negative.stderr and not positive.stderr
        nr=json.loads(negative.stdout)[0];pr=json.loads(positive.stdout)[0]
        assert nr['child'] is None and pr['parent']==pr['child'] and (nr['flags']&os.O_CLOEXEC)
        record('fd-control',negative=nr,positive=pr)
    finally:a.close();b.close()
    if scenario in ('pty','synthetic'):
        master,slave=pty.openpty()
        try:
            before=termios.tcgetattr(master);changed=termios.tcgetattr(slave)
            changed[3] &= ~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,changed)
            during=termios.tcgetattr(master);termios.tcsetattr(slave,termios.TCSANOW,before)
            after=termios.tcgetattr(master)
            assert not (during[3]&termios.ECHO) and before==after
            assert SYNTHETIC in b'prefix-'+SYNTHETIC and SYNTHETIC not in b'prefix-only'
            record('pty-control',before=termios_data(before),during=termios_data(during),after=termios_data(after))
        finally:os.close(master);os.close(slave)
    if scenario=='synthetic':
        raw_cmd=['/usr/bin/argon2','somesalt','-id','-t','1','-k','1024','-p','1','-l','32','-r']
        encoded_cmd=raw_cmd[:-1]+['-e']
        rawrun=subprocess.run(raw_cmd,input=b'password',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        encrun=subprocess.run(encoded_cmd,input=b'password',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        digest=rawrun.stdout.strip()
        assert rawrun.returncode==encrun.returncode==0 and not rawrun.stderr and not encrun.stderr
        assert len(digest)==64 and all(c in b'0123456789abcdef' for c in digest)
        assert encrun.stdout.startswith(b'$argon2id$v=19$m=1024,t=1,p=1$')
        record('argon2-reference-control',raw_base64=b64(rawrun.stdout),encoded_base64=b64(encrun.stdout))
    record('controls',scenario=scenario,transition_order=ops,result='verified')
    print('controls=verified')


DEVICE_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
auth probe || exit 11
auth open first || exit 12
auth open second || exit 13
auth stats "$first" || exit 14
auth stats "$second" || exit 15
/usr/bin/python3 "$1" "$BASHPID" "$first" "$second" > "$2" || exit 16
exec {first}>&-
exec {second}>&-
'''


def device(shell):
    base=CASE/'auth-device';base.mkdir(mode=0o700);probe=base/'fd-probe.py';probe.write_text(FD_PROBE)
    fdfile=base/'fds.json'
    rc,out,err,rows=run(base,'device',[shell,'--noprofile','--norc','-c',DEVICE_SCRIPT,'fixture',probe,fdfile])
    expected=(b'abi=1.5 features=0xf\n'
              b'created_secrets=201 cleared_secrets=202 refused_exports=203 minted_tokens=204 consumed_tokens=205 expired_tokens=206\n'
              b'created_secrets=301 cleared_secrets=302 refused_exports=303 minted_tokens=304 consumed_tokens=305 expired_tokens=306\n')
    data=json.loads(fdfile.read_text()) if fdfile.exists() else []
    opens=[x for x in rows if x['syscall'] in ('open','openat')]
    calls=[x for x in rows if x['syscall']=='ioctl']
    version=(len(opens)==3 and [x['request'] for x in calls]==['0x8020ba01','0x8080ba0a','0x8080ba0a'] and
             rc==0 and out==expected and not err)
    distinct=len(data)==2 and data[0]['fd']!=data[1]['fd'] and data[0]['parent']!=data[1]['parent']
    cloexec=len(data)==2 and all(x['flags']&os.O_CLOEXEC and x['child'] is None for x in data)
    prctls=[x for x in rows if x['syscall']=='prctl']
    deviation=len(prctls)==2 and all(x['deviation']=='PR_SET_DUMPABLE(0) acknowledged, not applied' for x in prctls)
    record('device-fds',items=data,opens=opens,ioctls=calls,dumpable_deviation=deviation)
    print('device version-and-stats=%s distinct=%s cloexec=%s mock-deviation-recorded=%s' %
          (yes(version),yes(distinct),yes(cloexec),yes(deviation)))


PTY_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
auth open d || exit 21
auth read-secret "$d" -p 'Fixture: ' handle || exit 22
printf 'handle=%s\n' "$handle"
exec {d}>&-
'''


def process_identity(pid):
    raw=Path('/proc/%d/stat'%pid).read_text();fields=raw[raw.rindex(')')+2:].split()
    status=Path('/proc/%d/status'%pid).read_text().splitlines()
    uid=next([int(x) for x in row.split()[1:]] for row in status if row.startswith('Uid:'))
    if fields[0]=='Z' or uid[:2]!=[2000,2000]:raise RuntimeError('unowned or exited process')
    return (int(fields[1]),int(fields[19]),tuple(uid))


def owned_process_bytes(supervisor,pid):
    if not isinstance(pid,int) or pid<=1 or supervisor.poll() is not None:raise RuntimeError('invalid owned process')
    root=process_identity(supervisor.pid)
    if root[0]!=os.getpid() or pid==supervisor.pid:raise RuntimeError('invalid supervisor relationship')
    chain=[];current=pid
    for _ in range(32):
        if current<=1 or current in [p for p,_ in chain]:raise RuntimeError('invalid descendant chain')
        ident=process_identity(current);chain.append((current,ident))
        if current==supervisor.pid:
            if ident!=root:raise RuntimeError('supervisor identity changed')
            break
        current=ident[0]
    else:raise RuntimeError('descendant chain too long')
    if chain[-1][0]!=supervisor.pid:raise RuntimeError('process is not an owned descendant')
    cmd=Path('/proc/%d/cmdline'%pid).read_bytes()
    env=Path('/proc/%d/environ'%pid).read_bytes()
    if supervisor.poll() is not None or any(process_identity(n)!=ident for n,ident in chain):
        raise RuntimeError('owned process identity changed during inspection')
    return cmd,env


def pty_case(shell):
    base=CASE/'auth-pty';base.mkdir(mode=0o700);cfg,trace=config(base,'pty')
    master,slave=pty.openpty();before=termios.tcgetattr(master);out=bytearray();echo_off=False;argv=b'';environment=b''
    def session():
        os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),shell,'--noprofile','--norc','-c',PTY_SCRIPT],
                       cwd=base,env=dict(os.environ),stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,close_fds=True)
    try:
        end=time.monotonic()+15
        while b'Fixture: ' not in out and p.poll() is None and time.monotonic()<end:
            r,_,_=select.select([master],[],[],.1)
            if r:out.extend(os.read(master,4096))
        if b'Fixture: ' not in out:raise RuntimeError('secret prompt missing')
        during=termios.tcgetattr(master);echo_off=not bool(during[3]&termios.ECHO)
        rows=trace_rows(trace);new=[x for x in rows if x.get('request')=='0xc008ba02']
        if len(new)!=1:raise RuntimeError('NEW_SECRET trace missing')
        pid=new[0]['pid'];argv,environment=owned_process_bytes(p,pid)
        os.write(master,SYNTHETIC+b'\n')
        end=time.monotonic()+15
        while p.poll() is None and time.monotonic()<end:
            r,_,_=select.select([master],[],[],.1)
            if r:out.extend(os.read(master,4096))
        if p.poll() is None:raise RuntimeError('secret child timeout')
        for _ in range(10):
            r,_,_=select.select([master],[],[],.02)
            if not r:break
            out.extend(os.read(master,4096))
        rc=p.wait(timeout=3);after=termios.tcgetattr(master)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=3)
        os.close(master);os.close(slave)
    rows=trace_rows(trace);calls=[x for x in rows if x['syscall']=='ioctl'];ops=[x.get('transition',{}).get('op') for x in calls]
    writes=[x['transition'] for x in calls if x.get('transition',{}).get('op')=='write']
    exact=(rc==0 and bytes(out)==b'Fixture: \r\nhandle=4097\r\n' and ops==['new','write','seal'] and
           len(writes)==1 and base64.b64decode(writes[0]['data_base64'])==SYNTHETIC)
    no_leak=SYNTHETIC not in bytes(out) and SYNTHETIC not in argv and SYNTHETIC not in environment
    restored=before==after
    record('pty',status=rc,output_base64=b64(bytes(out)),argv_base64=b64(argv),environment_base64=b64(environment),
           before=termios_data(before),during=termios_data(during),after=termios_data(after),
           echo_off=echo_off,restored=restored,protocol_exact=exact,no_leak=no_leak)
    print('secret tty-noecho=%s restored=%s protocol=%s no-argv-env-output-leak=%s' %
          (yes(echo_off),yes(restored),yes(exact),yes(no_leak)))


SYNTHETIC_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
IFS= read -r expected_phc < "$1"
auth open d || exit 31
auth read-secret "$d" -p 'Hash: ' h1 || exit 32
auth hash-secret "$d" "$h1" 736f6d6573616c74 1 1024 1 32 phc; rc=$?
printf 'hash-status=%d phc=%s\n' "$rc" "${phc-}"
auth read-secret "$d" -p 'Good: ' h2 || exit 33
unset token
auth verify-login "$d" "$h2" parity "$expected_phc" token; rc=$?
[[ ${token+x} && -n ${token-} ]] && bound=yes || bound=no
[[ ${token-} == "$(<"$2")" ]] && raw=yes || raw=no
printf 'good-status=%d bound=%s raw-token=%s\n' "$rc" "$bound" "$raw"
auth read-secret "$d" -p 'Bad: ' h3 || exit 34
unset wrong_token
auth verify-login "$d" "$h3" parity "$expected_phc" wrong_token; rc=$?
[[ ${wrong_token+x} ]] && bound=yes || bound=no
printf 'bad-status=%d bound=%s\n' "$rc" "$bound"
exec {d}>&-
'''


def synthetic(shell):
    base=CASE/'auth-synthetic';base.mkdir(mode=0o700)
    args=['/usr/bin/argon2','somesalt','-id','-t','1','-k','1024','-p','1','-l','32']
    rr=subprocess.run(args+['-r'],input=b'password',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    er=subprocess.run(args+['-e'],input=b'password',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    if rr.returncode or er.returncode or rr.stderr or er.stderr:raise RuntimeError('independent Argon2 oracle failed')
    digest=rr.stdout.strip();encoded=er.stdout.strip()
    if len(digest)!=64 or not encoded.startswith(b'$argon2id$v=19$m=1024,t=1,p=1$'):
        raise RuntimeError('invalid Argon2 oracle output')
    phc=base/'input-phc';phc.write_bytes(b'$argon2id$v=19$m=1024,t=1,p=1$736f6d6573616c74$'+digest+b'\n')
    token=bytes(range(128,160));tokenfile=base/'token';tokenfile.write_text(token.hex()+'\n')
    cfg,trace=config(base,'synthetic');master,slave=pty.openpty();before=termios.tcgetattr(master)
    output=bytearray();marker=0;off=[];cmdline=b'';environment=b''
    prompts=[(b'Hash: ',b'password'),(b'Good: ',b'password'),(b'Bad: ',b'wrong-fixture')]
    def session():
        os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
    p=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),shell,'--noprofile','--norc','-c',SYNTHETIC_SCRIPT,
                        'fixture',str(phc),str(tokenfile)],cwd=base,env=dict(os.environ),
                       stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,close_fds=True)
    try:
        end=time.monotonic()+45
        for prompt,secret in prompts:
            while prompt not in output[marker:] and p.poll() is None and time.monotonic()<end:
                ready,_,_=select.select([master],[],[],.1)
                if ready:output.extend(os.read(master,4096))
            if prompt not in output[marker:]:raise RuntimeError('missing prompt '+prompt.decode())
            marker=output.index(prompt,marker)+len(prompt)
            off.append(not bool(termios.tcgetattr(master)[3]&termios.ECHO))
            rows=trace_rows(trace);opens=[x for x in rows if x['syscall'] in ('open','openat')]
            if len(opens)!=1:raise RuntimeError('synthetic open trace missing')
            pid=opens[0]['pid'];cmdline,environment=owned_process_bytes(p,pid)
            os.write(master,secret+b'\n')
        while p.poll() is None and time.monotonic()<end:
            ready,_,_=select.select([master],[],[],.1)
            if ready:output.extend(os.read(master,4096))
        if p.poll() is None:raise RuntimeError('synthetic child timeout')
        for _ in range(10):
            ready,_,_=select.select([master],[],[],.02)
            if not ready:break
            output.extend(os.read(master,4096))
        rc=p.wait(timeout=3);after=termios.tcgetattr(master)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=3)
        os.close(master);os.close(slave)
    rows=trace_rows(trace);calls=[x for x in rows if x['syscall']=='ioctl']
    ops=[x.get('transition',{}).get('op') for x in calls]
    writes=[base64.b64decode(x['transition']['data_base64']) for x in calls if x.get('transition',{}).get('op')=='write']
    mints=[x['transition'] for x in calls if x.get('transition',{}).get('op')=='mint-synthetic']
    account=pwd.getpwnam('parity')
    output=bytes(output)
    expected_hash=b'hash-status=0 phc='+encoded+b'\r\n'
    hash_ok=expected_hash in output
    good=(b'good-status=0 bound=yes raw-token=' in output and len(mints)==1 and
          mints[0]['uid']==account.pw_uid and mints[0]['gid']==account.pw_gid and
          mints[0]['purpose']==1 and mints[0]['expires']==5 and base64.b64decode(mints[0]['user_base64'])==b'parity')
    opaque=b'good-status=0 bound=yes raw-token=no\r\n' in output and len(mints)==1
    bad=b'bad-status=1 bound=no\r\n' in output and len(mints)==1
    protocol=(rc==0 and writes==[b'password',b'password',b'wrong-fixture'] and
              ops==['new','write','seal','export-once','new','write','seal','export-once','mint-synthetic',
                    'new','write','seal','export-once'])
    no_leak=all(x not in output and x not in cmdline and x not in environment for x in
                (b'wrong-fixture',b'password',token,token.hex().encode()))
    record('synthetic',status=rc,output_base64=b64(output),argv_base64=b64(cmdline),environment_base64=b64(environment),
           raw_kdf_base64=b64(rr.stdout),standard_phc_base64=b64(er.stdout),trace_ops=ops,mints=mints,
           tty_echo_off=off,tty_restored=before==after,hash_ok=hash_ok,good=good,opaque=opaque,bad=bad,
           protocol=protocol,no_secret_or_token_leak=no_leak)
    print('synthetic phc-standard=%s good-accepted=%s token-opaque=%s wrong-denied=%s protocol=%s tty-restored=%s no-leak=%s' %
          (yes(hash_ok),yes(good),yes(opaque),yes(bad),yes(protocol),yes(len(off)==3 and all(off) and before==after),yes(no_leak)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('device','pty','synthetic');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:];{'device':device,'pty':pty_case,'synthetic':synthetic}[scenario](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
