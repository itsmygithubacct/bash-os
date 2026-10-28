#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM local syslog, forwarding and queue observations."""
import base64
import errno
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
PEER='/opt/bashos-parity/harness/helpers/system-client-followup-syslog-peer.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or Path.cwd()!=CASE:raise SystemExit(125)


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'syslog-followup-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def trace(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
def qbytes(p):return p.read_bytes() if p.exists() else b''


def ident(pid):
    raw=Path('/proc/%d/stat'%pid).read_text();fields=raw[raw.rindex(')')+2:].split()
    lines=Path('/proc/%d/status'%pid).read_text().splitlines()
    uid=next(tuple(int(x) for x in l.split()[1:]) for l in lines if l.startswith('Uid:'))
    if fields[0]=='Z' or uid[:2]!=(2000,2000):raise RuntimeError('process is not a live owned uid')
    return int(fields[1]),int(fields[19]),uid


def signal_descendant(supervisor,pid,sig):
    if supervisor.poll() is not None or pid<=1 or pid==supervisor.pid:raise RuntimeError('invalid signal target')
    root=ident(supervisor.pid)
    if root[0]!=os.getpid():raise RuntimeError('supervisor is not the remembered child')
    chain=[];current=pid
    for _ in range(32):
        if current<=1 or current in [x[0] for x in chain]:raise RuntimeError('invalid process ancestry')
        item=ident(current);chain.append((current,item))
        if current==supervisor.pid:
            if item!=root:raise RuntimeError('supervisor identity changed')
            break
        current=item[0]
    else:raise RuntimeError('process ancestry too long')
    if chain[-1][0]!=supervisor.pid:raise RuntimeError('target not an owned descendant')
    fd=os.pidfd_open(pid,0)
    try:
        if supervisor.poll() is not None or any(ident(n)!=i for n,i in chain):raise RuntimeError('signal identity changed')
        signal.pidfd_send_signal(fd,sig)
    finally:os.close(fd)
    record('owned-signal',pid=pid,signal=sig,identity=chain,time_ns=time.monotonic_ns())


CONTROL=r'''import errno,os,socket,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or not Path.cwd().is_relative_to(Path('/tmp/parity-case')):raise SystemExit(125)
target=int(sys.argv[1]);other=int(sys.argv[2]);unix=sys.argv[3];ordinary=Path(sys.argv[4]);assert ordinary.resolve().is_relative_to(Path('/tmp/parity-case'))
a=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:a.sendto(b'target',('127.0.0.1',target));raise AssertionError('fault not applied')
except OSError as e:assert e.errno==errno.EIO
assert a.sendto(b'other',('127.0.0.1',other))==5
a.close();u=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);assert u.sendto(b'unix',unix)==4;u.close()
f=os.open('/dev/full',os.O_WRONLY)
try:os.write(f,b'full');raise AssertionError('/dev/full accepted write')
except OSError as e:assert e.errno==errno.ENOSPC
os.close(f);ordinary.write_bytes(b'ordinary-ok');print('syslog-control=ok')
'''


SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && ( $PWD == /tmp/parity-case || $PWD == /tmp/parity-case/* ) ]] || exit 125
mode=$1; shift
fds() { local x; printf '%s=' "$1"; for x in /proc/$BASHPID/fd/*; do [[ -e $x ]] && printf '%s,' "${x##*/}"; done; printf '\n'; }
trap 'printf "trap-hup\\n"' HUP
trap 'printf "trap-int\\n"' INT
trap 'printf "trap-term\\n"' TERM
fds before-fds
printf 'daemon-pid=%d\n' "$BASHPID"
bashsyslogd run "$@"; rc=$?
printf 'status=%d\n' "$rc"
fds after-fds
if [[ $mode == restore ]]; then
 kill -s HUP "$BASHPID"; kill -s INT "$BASHPID"; kill -s TERM "$BASHPID"
fi
'''


def run(argv,timeout=15):
    p=subprocess.Popen(list(map(str,argv)),cwd=CASE,env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError('owned control timed out')
    return p.returncode,out,err


def receiver():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(.08);return s


def receive(sock,count,timeout=4):
    got=[];end=time.monotonic()+timeout
    while len(got)<count and time.monotonic()<end:
        try:data,peer=sock.recvfrom(65536);got.append((data,time.monotonic_ns(),peer))
        except socket.timeout:pass
    record('udp-receive',port=sock.getsockname()[1],requested=count,datagrams=[{'bytes_base64':b64(x),'monotonic_ns':t,'peer':p} for x,t,p in got])
    return got


def wait_until(predicate,timeout=5):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate():return True
        time.sleep(.02)
    return bool(predicate())


def setup(scenario):
    base=CASE/'syslog-followup-control';base.mkdir(mode=0o700);ctrl=base/'control.py';ctrl.write_text(CONTROL)
    first=receiver();second=receiver();unix=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);unix.settimeout(2);path=base/'unix';unix.bind(str(path))
    log=HOME/'syslog-followup-control.jsonl';cfg=base/'cfg.json'
    cfg.write_text(json.dumps({'port':first.getsockname()[1],'send_steps':['EIO'],'write_target':'/dev/full','trace':str(log)}))
    ordinary=base/'ordinary'
    try:
        rc,out,err=run(['/usr/bin/python3',PEER,cfg,'/usr/bin/python3',ctrl,str(first.getsockname()[1]),str(second.getsockname()[1]),path,ordinary])
        a=receive(first,1,.25);b=receive(second,1,2);u=unix.recv(128);events=trace(log)
        sends=[x for x in events if x['syscall']=='sendto'];writes=[x for x in events if x['syscall']=='write']
        assert rc==0 and out==b'syslog-control=ok\n' and not err and not a and [x[0] for x in b]==[b'other'] and u==b'unix' and ordinary.read_bytes()==b'ordinary-ok'
        assert len(sends)==3 and sends[0]['matched_receiver'] and sends[0]['reply']=='errno:5' and all(not x['matched_receiver'] and x['reply']=='continue' for x in sends[1:])
        assert len(writes)==1 and writes[0]['fd_target']=='/dev/full' and writes[0]['fd']<120 and base64.b64decode(writes[0]['input_base64'])==b'full'
        record('control',scenario=scenario,events=events,other_udp=b64(b[0][0]),unix=b64(u),ordinary=b64(ordinary.read_bytes()))
    finally:first.close();second.close();unix.close()
    print('controls=verified')


class Daemon:
    def __init__(self,shell,label,steps=(),once=False,forward=True,queue_data=None,max_bytes=262144,output=None,restore=False,prepare=None):
        self.label=label;self.base=CASE/('syslog-'+label);self.base.mkdir(mode=0o700)
        self.sock=self.base/'socket';self.queue=self.base/'queue';self.log=HOME/('syslog-followup-trace-'+label+'.jsonl')
        self.rx=receiver();self.output=output or (self.base/'messages')
        if queue_data is not None:self.queue.write_bytes(queue_data)
        if prepare:prepare(self)
        record('daemon-input',label=label,queue_before_base64=b64(qbytes(self.queue)),queue_exists=self.queue.exists(),
               port=self.rx.getsockname()[1],steps=list(steps),max_bytes=max_bytes,forward=forward,once=once,output=str(self.output))
        self.cfg=self.base/'cfg.json';self.cfg.write_text(json.dumps({'port':self.rx.getsockname()[1],'send_steps':list(steps),'write_target':str(self.output) if output else None,'trace':str(self.log)}))
        args=['-s',self.sock,'-o',self.output,'--syslog',self.base/'syslog','--auth',self.base/'auth','--kern',self.base/'kern',
              '--queue',self.queue,'--queue-max-bytes',str(max_bytes)]
        if forward:args+=['--forward','127.0.0.1:%d'%self.rx.getsockname()[1]]
        if once:args+=['--once']
        self.p=subprocess.Popen(['/usr/bin/python3',PEER,str(self.cfg),shell,'--noprofile','--norc','-c',SCRIPT,'fixture','restore' if restore else 'plain',*map(str,args)],
                                cwd=CASE,env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        self.partial=bytearray();self.pid=None
        end=time.monotonic()+9
        while self.pid is None and time.monotonic()<end:
            ready,_,_=select.select([self.p.stdout],[],[],.1)
            if ready:
                chunk=os.read(self.p.stdout.fileno(),4096)
                if not chunk:break
                self.partial.extend(chunk);m=re.search(rb'daemon-pid=(\d+)\n',self.partial)
                if m:self.pid=int(m.group(1))
            elif self.p.poll() is not None:break
        if self.pid is None:
            self.close();raise RuntimeError(label+' did not report daemon identity')
    def ready(self,timeout=5):
        return wait_until(lambda:self.sock.exists() and stat.S_ISSOCK(self.sock.lstat().st_mode),timeout)
    def send(self,data):
        if not self.ready():raise RuntimeError(self.label+' socket not ready')
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as s:
            n=s.sendto(data,str(self.sock))
            if n!=len(data):raise RuntimeError('short local datagram')
    def signal(self,sig):signal_descendant(self.p,self.pid,sig)
    def finish(self,timeout=7):
        try:out,err=self.p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:raise RuntimeError(self.label+' did not stop')
        out=bytes(self.partial)+out;events=trace(self.log);queue=qbytes(self.queue)
        record('daemon',label=self.label,supervisor_status=self.p.returncode,stdout_base64=b64(out),stderr_base64=b64(err),
               events=events,queue_base64=b64(queue),bootstrap=trace(Path(str(self.log)+'.bootstrap')))
        return {'status':self.p.returncode,'out':out,'err':err,'events':events,'queue':queue}
    def close(self):
        if self.p.poll() is None:
            try:os.killpg(self.p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            self.p.communicate(timeout=3)
        self.rx.close()


def extract(out,key):
    prefix=key.encode()+b'='
    return next((x[len(prefix):] for x in out.splitlines() if x.startswith(prefix)),None)


def send_events(result):return [x for x in result['events'] if x['syscall']=='sendto' and x['matched_receiver']]


def local_clean(payload):return bytes(32 if (x<32 and x!=9) or x==127 else x for x in payload)


def forwarding(shell):
    msg=b'<13>alpha\x00beta\nline\tend\x7f';d=Daemon(shell,'forward',once=True)
    try:
        d.send(msg);datagrams=receive(d.rx,1);r=d.finish();extra=receive(d.rx,1,.25);sent=send_events(r)
        clean=(r['status']==0 and extract(r['out'],'status')==b'0' and [x[0] for x in datagrams]==[local_clean(msg)] and not extra and len(sent)==1 and sent[0]['reply']=='continue' and base64.b64decode(sent[0]['input_base64'])==local_clean(msg) and not r['queue'])
    finally:d.close()
    d=Daemon(shell,'enqueue',steps=['EIO'],once=True)
    try:
        d.send(msg);r=d.finish();sent=send_events(r)
        queued=(r['status']==0 and extract(r['out'],'status')==b'0' and r['queue']==msg.hex().encode()+b'\n' and len(sent)==1 and sent[0]['reply']=='errno:5')
    finally:d.close()
    d=Daemon(shell,'limit-empty',steps=['EIO'],once=True,max_bytes=1)
    try:
        d.send(msg);r=d.finish();sent=send_events(r)
        small=(r['status']==0 and extract(r['out'],'status')==b'1' and not r['queue'] and b'queue full or unwritable' in r['err'] and len(sent)==1 and sent[0]['reply']=='errno:5')
    finally:d.close()
    existing=b'old-one'.hex().encode()+b'\n'+b'old-two'.hex().encode()+b'\n';d=Daemon(shell,'limit-existing',steps=['EIO']*30,once=True,max_bytes=1,queue_data=existing)
    try:
        if not wait_until(lambda:len([x for x in trace(d.log) if x.get('matched_receiver')])>=1):raise RuntimeError('startup failure not reached')
        d.send(msg);r=d.finish();large=(r['status']==0 and extract(r['out'],'status')==b'1' and r['queue']==existing and b'queue full or unwritable' in r['err'])
    finally:d.close()
    record('forward-outcome',sanitized=clean,queue=queued,limit_empty=small,existing_unchanged=large)
    print('syslog-forward sanitized=%s queue=%s limit=%s preserve-existing=%s'%(yes(clean),yes(queued),yes(small),yes(large)))


def replay(shell):
    items=[b'first',b'second\x00raw',b'third'];encoded=b''.join(x.hex().encode()+b'\n' for x in items)
    d=Daemon(shell,'replay-start',once=True,queue_data=encoded)
    try:
        packets=receive(d.rx,3);ready=wait_until(lambda:not d.queue.exists());d.send(b'finish');last=receive(d.rx,1);r=d.finish()
        startup=(len(packets)==3 and [x[0] for x in packets]==[local_clean(x) for x in items] and ready and [x[0] for x in last]==[b'finish'] and extract(r['out'],'status')==b'0' and not r['queue'])
    finally:d.close()
    malformed=b'first'.hex().encode()+b'\nnot-hex\n4142\x00ff\n'+b'aa'*8193+b'\n'+b'after'.hex().encode()+b'\n'
    d=Daemon(shell,'replay-malformed',once=True,queue_data=malformed)
    try:
        packets=receive(d.rx,2);ready=wait_until(lambda:not d.queue.exists());d.send(b'finish');receive(d.rx,1);r=d.finish()
        invalid=(ready and [x[0] for x in packets]==[b'first',b'after'] and extract(r['out'],'status')==b'0' and not r['queue'])
    finally:d.close()
    d=Daemon(shell,'replay-fail',steps=['continue']+['EIO']*30,queue_data=encoded)
    try:
        packets=receive(d.rx,1);expected=b''.join(x.hex().encode()+b'\n' for x in items[1:])
        reached=wait_until(lambda:qbytes(d.queue)==expected and len(send_events({'events':trace(d.log)}))>=2)
        if not reached:raise RuntimeError('failed replay state not reached')
        d.signal(signal.SIGTERM);r=d.finish();events=send_events(r)
        kept=([x[0] for x in packets]==[b'first'] and r['queue']==expected and len(events)>=2 and events[0]['reply']=='continue' and events[1]['reply']=='errno:5' and extract(r['out'],'status')==b'0')
    finally:d.close()
    record('replay-outcome',startup=startup,malformed=invalid,failed_retained=kept)
    print('syslog-replay startup=%s malformed=%s failed-retained=%s'%(yes(startup),yes(invalid),yes(kept)))


def timed_one(shell,label,use_hup):
    while time.monotonic()%1>.2:time.sleep(.02)
    window_ns=time.monotonic_ns()
    d=Daemon(shell,label,once=True,queue_data=b'seed'.hex().encode()+b'\n')
    try:
        first=receive(d.rx,1,4)
        if not first or first[0][0]!=b'seed':raise RuntimeError('timing seed not replayed')
        if not wait_until(lambda:not d.queue.exists()):raise RuntimeError('seed queue not drained')
        seed_second=first[0][1]//1000000000
        if use_hup and (window_ns//1000000000!=seed_second or time.monotonic_ns()//1000000000!=seed_second):raise RuntimeError('HUP timing control missed startup second')
        d.queue.write_bytes(b'after'.hex().encode()+b'\n');signal_time=None
        if use_hup:signal_time=time.monotonic_ns();d.signal(signal.SIGHUP)
        second=receive(d.rx,1,3)
        if not second:raise RuntimeError('replay timing not reached')
        next_second=second[0][1]//1000000000
        if use_hup and (next_second!=seed_second or second[0][1]<signal_time):raise RuntimeError('HUP timing control did not isolate signal from periodic retry')
        if not use_hup and next_second<=seed_second:raise RuntimeError('periodic timing control did not cross a second')
        drained=wait_until(lambda:not d.queue.exists());d.send(b'finish');receive(d.rx,1);r=d.finish()
        good=second[0][0]==b'after' and drained and extract(r['out'],'status')==b'0' and not r['queue']
        record('timing',label=label,hup=use_hup,window_ns=window_ns,seed_ns=first[0][1],signal_ns=signal_time,replay_ns=second[0][1],valid=good)
        return good
    finally:d.close()


def timed(shell):
    hup=timed_one(shell,'replay-hup',True);periodic=timed_one(shell,'replay-periodic',False)
    print('syslog-replay hup=%s periodic=%s'%(yes(hup),yes(periodic)))


def safety(shell):
    collision_before={}
    def regular(d):
        d.sock.write_bytes(b'not a socket');st=d.sock.lstat()
        collision_before.update(dev=st.st_dev,inode=st.st_ino,mode=st.st_mode,bytes_base64=b64(d.sock.read_bytes()))
        record('collision-before',**collision_before)
    d=Daemon(shell,'collision',once=True,forward=False,prepare=regular)
    try:
        outcome=wait_until(lambda:d.p.poll() is not None or (d.sock.exists() and stat.S_ISSOCK(d.sock.lstat().st_mode)))
        if not outcome:raise RuntimeError('collision outcome not reached')
        if d.sock.exists() and stat.S_ISSOCK(d.sock.lstat().st_mode):d.send(b'collision-followup')
        r=d.finish()
        if d.sock.exists():
            after=d.sock.lstat();after_data=d.sock.read_bytes() if stat.S_ISREG(after.st_mode) else b''
            record('collision-after',exists=True,dev=after.st_dev,inode=after.st_ino,mode=after.st_mode,bytes_base64=b64(after_data))
            intact=(collision_before['dev'],collision_before['inode'],b'not a socket')==(after.st_dev,after.st_ino,after_data)
        else:
            record('collision-after',exists=False);intact=False
        collision=(extract(r['out'],'status')==b'1' and b'refusing to unlink non-socket' in r['err'] and intact)
    finally:d.close()
    stale={}
    def make_stale(d):
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as s:s.bind(str(d.sock));st=d.sock.lstat();stale.update(dev=st.st_dev,inode=st.st_ino)
    d=Daemon(shell,'stale',once=True,forward=False,prepare=make_stale,restore=True)
    try:
        replaced=wait_until(lambda:d.sock.exists() and stat.S_ISSOCK(d.sock.lstat().st_mode) and d.sock.lstat().st_ino!=stale['inode'])
        if replaced:
            new=d.sock.lstat();d.send(b'local message')
        else:
            new=None
            if d.p.poll() is None:d.signal(signal.SIGTERM)
        r=d.finish()
        before=extract(r['out'],'before-fds');after=extract(r['out'],'after-fds')
        replacement=replaced and new.st_ino!=stale['inode'] and not d.sock.exists() and extract(r['out'],'status')==b'0'
        record('stale-socket-evidence',original_dev=stale['dev'],original_inode=stale['inode'],replacement_dev=new.st_dev if new else None,replacement_inode=new.st_ino if new else None,replacement_mode=new.st_mode if new else None,final_exists=d.sock.exists())
        signals=all(x in r['out'] for x in (b'trap-hup\n',b'trap-int\n',b'trap-term\n'))
        fds=before is not None and before==after
    finally:d.close()
    d=Daemon(shell,'inode',forward=False)
    replacement_socket=None
    try:
        if not d.ready():raise RuntimeError('owned socket not ready')
        first=d.sock.lstat();d.sock.unlink();replacement_socket=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);replacement_socket.bind(str(d.sock));second=d.sock.lstat()
        d.signal(signal.SIGTERM);r=d.finish();after=d.sock.lstat() if d.sock.exists() else None
        record('replacement-socket',first_inode=first.st_ino,replacement_dev=second.st_dev,replacement_inode=second.st_ino,
               after_dev=after.st_dev if after else None,after_inode=after.st_ino if after else None,after_mode=after.st_mode if after else None)
        inode=(first.st_ino!=second.st_ino and after is not None and (second.st_dev,second.st_ino)==(after.st_dev,after.st_ino) and stat.S_ISSOCK(after.st_mode) and extract(r['out'],'status')==b'0')
    finally:
        if replacement_socket:replacement_socket.close()
        d.close()
    d=Daemon(shell,'full',once=True,forward=False,output=Path('/dev/full'))
    try:
        d.send(b'write-failure');r=d.finish();writes=[x for x in r['events'] if x['syscall']=='write' and x['fd_target']=='/dev/full']
        write=(extract(r['out'],'status')==b'1' and b'write /dev/full' in r['err'] and len(writes)>=1 and all(x['fd']<120 for x in writes))
    finally:d.close()
    record('safety-outcome',collision=collision,stale=replacement,write_error=write,inode=inode,signal_restoration=signals,fd_cleanup=fds)
    print('syslog-safety collision=%s stale=%s write=%s inode=%s signals=%s fds=%s'%(yes(collision),yes(replacement),yes(write),yes(inode),yes(signals),yes(fds)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':setup(sys.argv[2])
        else:
            shell,mode=sys.argv[1:];{'forward':forwarding,'replay':replay,'timed':timed,'safety':safety}[mode](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
