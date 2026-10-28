#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only logger FD and xattr growth observers with deterministic controls."""
import base64
import copy
import errno
import json
import os
from pathlib import Path
import re
import socket
import signal
import subprocess
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
NOTIFY='/opt/bashos-parity/harness/helpers/terra-local-io-notify-r2.py'
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
printf 'LIO-LOGGER-BEGIN:%s\n' "$BASHPID"
builtin bashlogger hello 2> logger.err; rc=$?
/usr/bin/python3 "$1" "$BASHPID" > parent-after
/usr/bin/python3 "$1" self > child-after
printf 'rc=%d\n' "$rc"
'''
LOGGER_CONTROL=r'''import socket,sys
import os
# Unrelated AF_UNIX calls occur on both sides of the boundary, including
# one after the target datagram socket is created. Keep all of them open.
noise=[socket.socket(socket.AF_UNIX,socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC) for _ in range(2)]
os.write(1,('LIO-LOGGER-BEGIN:%d\n' % os.getpid()).encode())
noise.append(socket.socket(socket.AF_UNIX,socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC))
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
noise.append(socket.socket(socket.AF_UNIX,socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC))
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


def attribution(events):
    """Associate the logger's live send fd with a boundary-scoped creation.

    The marker includes the tracee PID. At the selected socket call the target
    inode must be absent from that PID's fd table; it must be present at every
    later notified fd-producing syscall and at sendto. This links the live fd
    to the one scoped Unix datagram creation without treating unrelated stream
    sockets as logger sockets. Ambiguity or unreadable observations fail closed.
    """
    markers=[]
    for i, event in enumerate(events):
        if event['syscall'] != 'write': continue
        memory=event.get('write_memory',{})
        try: data=bytes.fromhex(memory.get('hex',''))
        except ValueError: continue
        match=re.fullmatch(rb'LIO-LOGGER-BEGIN:([0-9]+)\n',data)
        if match and len(data)==event['args'][2] and int(match.group(1))==event['pid']:
            markers.append((i,event['pid']))
    details={'marker_count':len(markers)}
    if len(markers)!=1:return False,details
    boundary,pid=markers[0];details.update(boundary_index=boundary,pid=pid)
    sends=[(i,x) for i,x in enumerate(events) if i>boundary and x['syscall']=='sendto' and
           x['pid']==pid and x.get('logger_scoped')]
    if not sends:return False,details
    send_index,send=sends[0];target=send.get('fd_target');fd=send.get('fd')
    providers={'socket','socketpair','accept','accept4','recvmsg','recvmmsg','pidfd_getfd'}
    window=[(i,x) for i,x in enumerate(events) if boundary<i<send_index and x['pid']==pid and x['syscall'] in providers]
    candidates=[(i,x) for i,x in window if x['syscall']=='socket' and x['args'][0]==socket.AF_UNIX
                and (x['args'][1]&0xf)==socket.SOCK_DGRAM]
    details.update(send_index=send_index,send_fd=fd,send_target=target,
                   candidate_indices=[i for i,_ in candidates])
    if len(candidates)!=1:return False,details
    create_index,create=candidates[0];before=create.get('fd_snapshot',{})
    later=[(i,x) for i,x in window if i>create_index]+[(send_index,send)]
    live_after=all(target in x.get('fd_snapshot',{}).values() for _,x in later)
    direct=(send.get('fd_snapshot',{}).get(str(fd))==target)
    new=bool(target and target.startswith('socket:[') and target not in before.values())
    creation=bool(create['args'][1]&socket.SOCK_CLOEXEC)
    streams=lambda seq: sum(x['syscall']=='socket' and x['args'][0]==socket.AF_UNIX and
                            (x['args'][1]&0xf)==socket.SOCK_STREAM for _,x in seq)
    prior=[(i,x) for i,x in enumerate(events) if i<boundary and x['pid']==pid]
    details.update(creator_index=create_index,creator_socket_type=create['args'][1],
                   creator_before_fds=before,send_fds=send.get('fd_snapshot',{}),
                   later_provider_indices=[i for i,_ in later],target_new=new,
                   target_stays_open=live_after,send_fd_matches=direct,cloexec_requested=creation,
                   pre_boundary_streams=streams(prior),
                   before_creator_streams=streams([(i,x) for i,x in window if i<create_index]),
                   after_creator_streams=streams([(i,x) for i,x in window if i>create_index]))
    return new and live_after and direct and creation,details


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
    sends=[x for x in e if x['syscall']=='sendto' and x.get('logger_scoped')]
    creation,creator=attribution(e)
    live=bool(sends) and all(x.get('cloexec') and x.get('fd_target','').startswith('socket:[') for x in sends)
    if mode=='logger-intr': replies=['errno:4','continue']
    elif mode=='logger-short': replies=['value:1']
    elif mode=='logger-fail': replies=['errno:5']
    else: replies=['continue']
    trace_ok=([x['reply'] for x in sends]==replies and all(x['args'][2]>1 for x in sends) and
              all(x['pid']==creator.get('pid') and x['fd_target']==creator.get('send_target') for x in sends))
    want = ([b'probe'] if control else [b'<13> user: hello']) if mode in ('logger-pass','logger-intr') else []
    packet_ok=packets==want
    record('logger-peer',label=label,packets_base64=[raw(x) for x in packets],creation=creation,live_cloexec=live,
           trace_ok=trace_ok,packet_ok=packet_ok,attribution=creator)
    return p,creation,live,trace_ok,packet_ok,creator,e


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
        p,creation,live,trace,packets,creator,events=logger_common(base,label,mode,['/usr/bin/python3','-c',LOGGER_CONTROL,base/('recv-'+label)],True)
        expected={'logger-pass':b'returned=5\n','logger-intr':b'returned=5\n',
                  'logger-short':b'returned=1\n','logger-fail':b'errno=5\n'}[mode]
        marker=('LIO-LOGGER-BEGIN:%d\n' % creator['pid']).encode()
        assert p.returncode==0 and p.stdout==marker+expected and not p.stderr and creation and live and trace and packets
        assert creator['pre_boundary_streams']>=2 and creator['before_creator_streams']>=1 and creator['after_creator_streams']>=1
        altered=copy.deepcopy(events)
        altered[creator['creator_index']]['args'][1] &= ~socket.SOCK_CLOEXEC
        rejected, negative=attribution(altered)
        assert not rejected and not negative['cloexec_requested'] and negative['target_new'] and negative['send_fd_matches']
        altered=copy.deepcopy(events)
        old_target=next(x for x in creator['creator_before_fds'].values() if x.startswith('socket:['))
        altered[creator['send_index']]['fd_target']=old_target
        altered[creator['send_index']]['fd_snapshot'][str(creator['send_fd'])]=old_target
        rejected, negative=attribution(altered)
        assert not rejected and not negative['target_new'] and negative['target_stays_open'] and negative['send_fd_matches']
        record('logger-attribution-controls',label=label,extra_pre_boundary=creator['pre_boundary_streams'],
               extra_before_creator=creator['before_creator_streams'],extra_after_creator=creator['after_creator_streams'],
               missing_cloexec_rejected=True,preexisting_socket_rejected=True)


def logger(shell,base):
    probe=base/'probe.py';probe.write_text(FD_PROBE)
    for label,mode in [('pass','logger-pass'),('intr','logger-intr'),('fail','logger-fail'),('short','logger-short')]:
        run=base/label;run.mkdir()
        p,creation,live,trace,packets,creator,_=logger_common(run,label,mode,[shell,'--noprofile','--norc','-c',LOGGER_SCRIPT,'fixture',probe])
        def data(name): return json.loads((run/name).read_text())
        before=data('parent-before');after=data('parent-after'); child_before=data('child-before');child_after=data('child-after')
        same=before==after
        child_sockets=lambda x: sorted(v for v in x.values() if v.startswith('socket:['))
        inherited=child_sockets(child_before)==child_sockets(child_after) and not child_sockets(child_after)
        diag=(run/'logger.err').read_bytes()
        expected_rc=0 if mode in ('logger-pass','logger-intr') else 1
        marker=('LIO-LOGGER-BEGIN:%d\n' % creator.get('pid',-1)).encode()
        status=p.returncode==0 and p.stdout==marker+('rc=%d\n'%expected_rc).encode() and not p.stderr
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
