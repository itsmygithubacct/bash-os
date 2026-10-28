#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only logger FD and xattr growth observers with deterministic controls."""
import base64
import errno
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
NOTIFY='/opt/bashos-parity/harness/helpers/terra-local-io-notify.py'
ATTRIBUTE='user.terra_fixture'; OLD=b'old'; NEW=b'new-value'


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert Path.cwd()==CASE and os.geteuid()==2000


def raw(data): return base64.b64encode(data[:65536]).decode()
def yes(value): return 'yes' if value else 'no'


def record(kind,**fields):
    fields['kind']=kind
    with (HOME/'fault-observations.jsonl').open('a') as f: f.write(json.dumps(fields,sort_keys=True)+'\n')


def notified(base,label,mode,argv,**extra):
    cfg=base/(label+'.json'); trace=HOME/('trace-'+label+'.jsonl')
    cfg.write_text(json.dumps({'mode':mode,'trace':str(trace),**extra}))
    command=['/usr/bin/python3',NOTIFY,str(cfg),*map(str,argv)]
    child=subprocess.Popen(command,cwd=base,env=dict(os.environ),stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:
        out,err=child.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        # This session contains only this observer's supervisor and its child.
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        out,err=child.communicate(timeout=3)
        record('timeout',label=label,stdout_base64=raw(out),stderr_base64=raw(err))
        raise RuntimeError('notification child timed out: '+label)
    p=subprocess.CompletedProcess(command,child.returncode,out,err)
    events=[json.loads(x) for x in trace.read_text().splitlines()] if trace.exists() else []
    record('notified',label=label,status=p.returncode,stdout_base64=raw(p.stdout),stderr_base64=raw(p.stderr),events=events)
    return p,events


def xconfig(path,syscall):
    return {'path':str(path),'syscall':syscall,'attribute':ATTRIBUTE,'new_value':raw(NEW)}


CONTROL_GROW=r'''import ctypes,errno,sys
c=ctypes.CDLL(None,use_errno=True)
f=c.getxattr; f.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]; f.restype=ctypes.c_ssize_t
path=sys.argv[1].encode(); name=b'user.terra_fixture'
n=f(path,name,None,0); buf=ctypes.create_string_buffer(n)
r=f(path,name,buf,n); e=ctypes.get_errno()
m=f(path,name,None,0); buf2=ctypes.create_string_buffer(m); r2=f(path,name,buf2,m)
print('probe=%d first=%d errno=%d reprobe=%d final=%d value=%s' % (n,r,e,m,r2,buf2.raw[:r2].decode()))
'''
CONTROL_ALWAYS=r'''import ctypes,errno,sys
c=ctypes.CDLL(None,use_errno=True)
f=c.getxattr; f.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]; f.restype=ctypes.c_ssize_t
p=sys.argv[1].encode(); n=b'user.terra_fixture'; s=f(p,n,None,0); b=ctypes.create_string_buffer(s)
r=f(p,n,b,s); print('probe=%d read=%d errno=%d' % (s,r,ctypes.get_errno()))
'''


def setup_xattr(base):
    path=base/'xcontrol';path.write_bytes(b'file'); os.setxattr(path,ATTRIBUTE,OLD)
    assert os.getxattr(path,ATTRIBUTE)==OLD
    p,e=notified(base,'control-grow','xgrow',['/usr/bin/python3','-c',CONTROL_GROW,path],**xconfig(path,'getxattr'))
    assert p.returncode==0 and not p.stderr and p.stdout==b'probe=3 first=-1 errno=34 reprobe=9 final=9 value=new-value\n'
    assert [x['size'] for x in e]==[0,3,0,9] and e[1].get('mutation')=='before-continued-read'
    os.setxattr(path,ATTRIBUTE,OLD)
    p,e=notified(base,'control-erange','xalways',['/usr/bin/python3','-c',CONTROL_ALWAYS,path],**xconfig(path,'getxattr'))
    assert p.returncode==0 and not p.stderr and p.stdout==b'probe=3 read=-1 errno=34\n'
    assert [x['size'] for x in e]==[0,3] and e[-1]['reply']=='errno:34'


def xattr(shell,base):
    forms=[('path','getxattr',r'builtin xattr read "$1" user.terra_fixture'),
           ('fd','fgetxattr',r'exec {fd}<"$1"; builtin xattr -F "$fd" read user.terra_fixture'),
           ('nofollow','lgetxattr',r'builtin xattr -L read "$1" user.terra_fixture')]
    for label,syscall,script in forms:
        path=base/(label+'.file');path.write_bytes(b'file');os.setxattr(path,ATTRIBUTE,OLD)
        p,e=notified(base,label+'-grow','xgrow',[shell,'--noprofile','--norc','-c',script,'fixture',path],**xconfig(path,syscall))
        growth=(p.returncode==0 and p.stdout==NEW and not p.stderr and
                [x.get('size') for x in e]==[0,3,0,len(NEW)] and
                e[1].get('mutation')=='before-continued-read' and
                base64.b64decode(e[1].get('old_base64',''))==OLD and
                base64.b64decode(e[1].get('new_base64',''))==NEW and
                os.getxattr(path,ATTRIBUTE)==NEW)
        os.setxattr(path,ATTRIBUTE,OLD)
        p,e=notified(base,label+'-exhaust','xalways',[shell,'--noprofile','--norc','-c',script,'fixture',path],**xconfig(path,syscall))
        sizes=[0]
        for n in (3,6,12,24,48,96,192,384): sizes += [n,0]
        exhaustion=(p.returncode==1 and not p.stdout and b'ERANGE retry limit exceeded' in p.stderr and
                    [x.get('size') for x in e]==sizes and
                    sum(x['reply']=='errno:34' for x in e)==8)
        record('xattr-result',form=label,growth=growth,exhaustion=exhaustion)
        print('xattr-%s growth=%s exhaustion=%s' % (label,yes(growth),yes(exhaustion)))


FD_PROBE=r'''import json,os,sys
p='/proc/%s/fd' % sys.argv[1]; rows={}
for name in sorted(os.listdir(p), key=int):
 try: rows[name]=os.readlink(p+'/'+name)
 except FileNotFoundError: pass
print(json.dumps(rows,sort_keys=True))
'''
LOGGER_SCRIPT=r'''/usr/bin/python3 "$1" "$BASHPID" > parent-before
/usr/bin/python3 "$1" self > child-before
builtin bashlogger hello 2> logger.err; rc=$?
/usr/bin/python3 "$1" "$BASHPID" > parent-after
/usr/bin/python3 "$1" self > child-after
printf 'rc=%d\n' "$rc"
'''
LOGGER_CONTROL=r'''import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
try:
 n=s.sendto(b'probe',sys.argv[1]); print('returned=%d' % n)
except OSError as e: print('errno=%d' % e.errno)
'''


def recv_all(s):
    s.settimeout(.15); out=[]
    while len(out)<8:
        try: out.append(s.recv(4096))
        except socket.timeout: break
    return out


def logger_common(base,label,mode,argv,control=False):
    path=base/('recv-'+label); receiver=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); receiver.bind(str(path))
    old=os.environ.get('BASHLOGGER_SOCKET');os.environ['BASHLOGGER_SOCKET']=str(path)
    try:
        p,e=notified(base,label,mode,argv)
        packets=recv_all(receiver)
    finally:
        receiver.close();path.unlink()
        if old is None: os.environ.pop('BASHLOGGER_SOCKET',None)
        else: os.environ['BASHLOGGER_SOCKET']=old
    sockets=[x for x in e if x['syscall']=='socket']; sends=[x for x in e if x['syscall']=='sendto']
    creation=(len(sockets)==1 and sockets[0]['args'][0]==socket.AF_UNIX and
              sockets[0]['args'][1] == socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    live=bool(sends) and all(x.get('cloexec') and x.get('fd_target','').startswith('socket:[') for x in sends)
    if mode=='logger-intr': replies=['errno:4','continue']
    elif mode=='logger-short': replies=['value:1']
    elif mode=='logger-fail': replies=['errno:5']
    else: replies=['continue']
    trace_ok=[x['reply'] for x in sends]==replies and all(x['args'][2]>1 for x in sends)
    want = ([b'probe'] if control else [b'<13> user: hello']) if mode in ('logger-pass','logger-intr') else []
    packet_ok=packets==want
    record('logger-peer',label=label,packets_base64=[raw(x) for x in packets],creation=creation,live_cloexec=live,
           trace_ok=trace_ok,packet_ok=packet_ok)
    return p, creation,live,trace_ok,packet_ok


def setup_logger(base):
    probe=base/'probe.py';probe.write_text(FD_PROBE)
    a,b=socket.socketpair()
    try:
        positive=subprocess.run(['/usr/bin/python3',str(probe),'self'],pass_fds=(a.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        negative=subprocess.run(['/usr/bin/python3',str(probe),'self'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        assert positive.returncode==negative.returncode==0 and not positive.stderr and not negative.stderr
        pos=json.loads(positive.stdout); neg=json.loads(negative.stdout)
        assert any(x.startswith('socket:[') for x in pos.values()) and not any(x.startswith('socket:[') for x in neg.values())
        record('fd-detector-controls',positive=pos,negative=neg)
    finally:a.close();b.close()
    for label,mode in [('control-pass','logger-pass'),('control-intr','logger-intr'),('control-short','logger-short'),('control-fail','logger-fail')]:
        # Path is deterministic and supplied to the independent Python sender.
        p,creation,live,trace,packets=logger_common(base,label,mode,['/usr/bin/python3','-c',LOGGER_CONTROL,base/('recv-'+label)],True)
        expected={'logger-pass':b'returned=5\n','logger-intr':b'returned=5\n',
                  'logger-short':b'returned=1\n','logger-fail':b'errno=5\n'}[mode]
        assert p.returncode==0 and p.stdout==expected and not p.stderr and creation and live and trace and packets


def logger(shell,base):
    probe=base/'probe.py';probe.write_text(FD_PROBE)
    for label,mode in [('pass','logger-pass'),('intr','logger-intr'),('fail','logger-fail'),('short','logger-short')]:
        run=base/label;run.mkdir()
        p,creation,live,trace,packets=logger_common(run,label,mode,[shell,'--noprofile','--norc','-c',LOGGER_SCRIPT,'fixture',probe])
        def data(name): return json.loads((run/name).read_text())
        before=data('parent-before');after=data('parent-after'); child_before=data('child-before');child_after=data('child-after')
        same=before==after
        child_sockets=lambda x: sorted(v for v in x.values() if v.startswith('socket:['))
        inherited=child_sockets(child_before)==child_sockets(child_after) and not child_sockets(child_after)
        diag=(run/'logger.err').read_bytes()
        expected_rc=0 if mode in ('logger-pass','logger-intr') else 1
        status=p.returncode==0 and p.stdout==('rc=%d\n'%expected_rc).encode() and not p.stderr
        diag_ok=(not diag if expected_rc==0 else b'sendto ' in diag and b'Input/output error' in diag)
        record('logger-result',label=label,parent_before=before,parent_after=after,child_before=child_before,
               child_after=child_after,diagnostic_base64=raw(diag),status=status,same_fds=same,no_inheritance=inherited)
        print('logger-%s creation=%s live-cloexec=%s trace=%s packet=%s status=%s diagnostic=%s fd-closed=%s exec-clean=%s' %
              (label,yes(creation),yes(live),yes(trace),yes(packets),yes(status),yes(diag_ok),yes(same),yes(inherited)))


def setup(scenario):
    base=CASE/'fault-controls';base.mkdir(mode=0o700)
    if scenario=='xattr':setup_xattr(base)
    else:setup_logger(base)
    record('setup',scenario=scenario,result='verified')
    print('controls=verified')


if __name__=='__main__':
    try:
        guard()
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('xattr','logger');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:];base=CASE/'fault-case';base.mkdir(mode=0o700)
            {'xattr':xattr,'logger':logger}[scenario](shell,base)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
