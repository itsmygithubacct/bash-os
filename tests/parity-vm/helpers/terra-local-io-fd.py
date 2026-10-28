#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only bashpoll descriptor-flag and owned-signal observers."""
import base64
import fcntl
import json
import os
from pathlib import Path
import pty
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home');WORK=CASE/'fd-case'


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert Path.cwd()==CASE and os.geteuid()==2000


def raw(data):return base64.b64encode(data[:65536]).decode()
def yes(v):return 'yes' if v else 'no'
def record(kind,**fields):
    fields['kind']=kind
    with (HOME/'fd-observations.jsonl').open('a') as f:f.write(json.dumps(fields,sort_keys=True)+'\n')


PROBE=r'''import json,os,sys
pid,fd,tag=sys.argv[1],sys.argv[2],sys.argv[3]
def target(path):
 try:return os.readlink(path)
 except OSError:return None
p='/proc/%s/fd/%s' % (pid,fd)
try:
 info=open('/proc/%s/fdinfo/%s' % (pid,fd)).read()
 flags=int(next(x.split()[1] for x in info.splitlines() if x.startswith('flags:')),8)
except OSError: info=None;flags=None
print(json.dumps({'tag':tag,'fd':int(fd),'parent':target(p),'child':target('/proc/self/fd/'+fd),'flags':flags,'fdinfo':info},sort_keys=True))
'''
MASK_PROBE=r'''import json,sys
pid,tag=sys.argv[1:];s=open('/proc/%s/status'%pid).read()
line=next(x for x in s.splitlines() if x.startswith('SigBlk:'))
print(json.dumps({'tag':tag,'mask':int(line.split()[1],16),'raw':line}))
'''
SIGNAL_READ=r'''import os,select,signal,struct,sys
fd=int(sys.argv[1]); mask=signal.pthread_sigmask(signal.SIG_BLOCK,[])
if signal.SIGUSR1 not in mask:
 print('mask-missing');sys.exit(1)
os.kill(os.getpid(),signal.SIGUSR1)
e=select.epoll();e.register(fd,select.EPOLLIN);ready=e.poll(1);e.close()
data=os.read(fd,128) if ready else b''
signum=struct.unpack('<I',data[:4])[0] if len(data)>=4 else -1
print('signo=%d size=%d readable=%s' % (signum,len(data),'yes' if ready else 'no'))
'''


def call(shell,script,*args,preblocked=False,pass_fds=()):
    def preexec():
        if preblocked:signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR2})
    p=subprocess.Popen([shell,'--noprofile','--norc','-c',script,'fixture',*map(str,args)],cwd=WORK,
                       env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       pass_fds=pass_fds,preexec_fn=preexec,start_new_session=True)
    return p


def done(p,label):
    try:out,err=p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill();out,err=p.communicate(timeout=3);raise RuntimeError('child timeout '+label)
    record('child',label=label,status=p.returncode,stdout_base64=raw(out),stderr_base64=raw(err))
    return p.returncode,out,err


def wait_ready(p):
    end=time.monotonic()+5
    while time.monotonic()<end and p.poll() is None:
        if (WORK/'ready').exists():return True
        time.sleep(.01)
    return (WORK/'ready').exists()


def free_port():
    s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();return port


FD_SCRIPT=r'''probe=$1; trace=$2; ptyfd=$3; server=$4; listenport=$5
builtin bashpoll listen "127.0.0.1:$listenport" l || exit 10
builtin bashpoll listen-unix relative.sock u || exit 11
builtin bashpoll listen-udp 127.0.0.1:0 d || exit 12
builtin bashpoll connect "127.0.0.1:$server" c -t 1000 || exit 13
printf ready > ready
builtin bashpoll accept "$l" a || exit 14
names=(l u d c a ptyfd)
for name in "${names[@]}"; do
 fd=${!name}
 /usr/bin/python3 "$probe" "$BASHPID" "$fd" "$name:before" >> "$trace"
 builtin bashpoll set-nonblock "$fd" on || exit 15
 /usr/bin/python3 "$probe" "$BASHPID" "$fd" "$name:on" >> "$trace"
 builtin bashpoll set-nonblock "$fd" off || exit 16
 /usr/bin/python3 "$probe" "$BASHPID" "$fd" "$name:off" >> "$trace"
 builtin bashpoll clear-cloexec "$fd" || exit 17
 /usr/bin/python3 "$probe" "$BASHPID" "$fd" "$name:clear" >> "$trace"
 builtin bashpoll close "$fd" || exit 18
 /usr/bin/python3 "$probe" "$BASHPID" "$fd" "$name:closed" >> "$trace"
done
printf 'BEGIN closed-set\n' >&2
builtin bashpoll set-nonblock "$a" on; rc=$?
printf 'END closed-set\n' >&2; printf 'closed-set=%d\n' "$rc"
printf 'BEGIN closed-clear\n' >&2
builtin bashpoll clear-cloexec "$a"; rc=$?
printf 'END closed-clear\n' >&2; printf 'closed-clear=%d\n' "$rc"
printf 'BEGIN closed-close\n' >&2
builtin bashpoll close "$a"; rc=$?
printf 'END closed-close\n' >&2; printf 'closed-close=%d\n' "$rc"
printf 'BEGIN bad-set\n' >&2
builtin bashpoll set-nonblock nonsense on; rc=$?
printf 'END bad-set\n' >&2; printf 'bad-set=%d\n' "$rc"
printf 'BEGIN bad-clear\n' >&2
builtin bashpoll clear-cloexec nonsense; rc=$?
printf 'END bad-clear\n' >&2; printf 'bad-clear=%d\n' "$rc"
printf 'BEGIN bad-close\n' >&2
builtin bashpoll close nonsense; rc=$?
printf 'END bad-close\n' >&2; printf 'bad-close=%d\n' "$rc"
'''


def descriptors(shell):
    WORK.mkdir(mode=0o700);probe=WORK/'probe.py';probe.write_text(PROBE);trace=HOME/'fd-trace.jsonl'
    server=socket.socket();server.bind(('127.0.0.1',0));server.listen(2);server.settimeout(5)
    master,slave=pty.openpty();listenport=free_port()
    p=call(shell,FD_SCRIPT,probe,trace,master,server.getsockname()[1],listenport,pass_fds=(master,))
    connection=None; inbound=None
    try:
        if not wait_ready(p):raise RuntimeError('descriptor listener did not become ready')
        connection,_=server.accept()
        inbound=socket.create_connection(('127.0.0.1',listenport),timeout=5)
        status,out,err=done(p,'descriptors')
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=3)
        if connection:connection.close()
        if inbound:inbound.close()
        server.close();os.close(master);os.close(slave)
    rows=[json.loads(x) for x in trace.read_text().splitlines()] if trace.exists() else []
    by={x['tag']:x for x in rows}
    def flags_ok(name):
        try:
            a,b,c,d,z=(by[name+':'+x] for x in ('before','on','off','clear','closed'))
            f=a['flags']; target=a['parent']
            return (target is not None and b['parent']==c['parent']==d['parent']==target and
                    b['flags']==(f|os.O_NONBLOCK) and c['flags']==(f&~os.O_NONBLOCK) and
                    d['flags']==(c['flags']&~os.O_CLOEXEC) and d['child']==target and
                    z['parent'] is None and z['child'] is None)
        except (KeyError,TypeError):return False
    sockets=all(flags_ok(n) for n in ('l','u','d','c','a'))
    terminals=flags_ok('ptyfd')
    created=all(by.get(n+':before',{}).get('flags',0)&os.O_CLOEXEC and
                by.get(n+':before',{}).get('child') is None for n in ('l','u','d','c','a'))
    expected=(b'closed-set=1\nclosed-clear=1\nclosed-close=1\n'
              b'bad-set=2\nbad-clear=2\nbad-close=2\n')
    def diagnostic(tag, fragment):
        begin=('BEGIN '+tag+'\n').encode(); end=('END '+tag+'\n').encode()
        if err.count(begin)!=1 or err.count(end)!=1:return False
        start=err.index(begin)+len(begin);stop=err.index(end)
        return stop>=start and fragment.lower() in err[start:stop].lower()
    closed_diag=all(diagnostic(tag,b'Bad file descriptor') for tag in ('closed-set','closed-clear','closed-close'))
    bad_diag=all(diagnostic(tag,b'invalid') for tag in ('bad-set','bad-clear','bad-close'))
    invalid=status==0 and out==expected and closed_diag and bad_diag
    record('fd-result',socket_flags=sockets,pty_flags=terminals,created_cloexec=bool(created),invalid=invalid,
           trace_rows=len(rows))
    print('descriptor socket-flags=%s pty-flags=%s created-cloexec=%s invalid-status-diagnostic=%s' %
          (yes(sockets),yes(terminals),yes(created),yes(invalid)))


MASK_SCRIPT=r'''probe=$1;trace=$2
/usr/bin/python3 "$probe" "$BASHPID" initial >> "$trace"
builtin bashpoll signalfd USR1 one || exit 21
/usr/bin/python3 "$probe" "$BASHPID" first >> "$trace"
builtin bashpoll signalfd USR1 two || exit 22
/usr/bin/python3 "$probe" "$BASHPID" overlap >> "$trace"
builtin bashpoll close "$one" || exit 23
/usr/bin/python3 "$probe" "$BASHPID" oneclosed >> "$trace"
builtin bashpoll close "$two" || exit 24
/usr/bin/python3 "$probe" "$BASHPID" bothclosed >> "$trace"
builtin bashpoll signalfd SIGUSR2 three || exit 25
/usr/bin/python3 "$probe" "$BASHPID" preblocked >> "$trace"
builtin bashpoll close "$three" || exit 26
/usr/bin/python3 "$probe" "$BASHPID" preblockedclosed >> "$trace"
builtin bashpoll signalfd 12 four; printf 'numeric=%d\n' "$?"
builtin bashpoll close "$four"
builtin bashpoll signalfd SIGBOGUS bad; printf 'bad=%d\n' "$?"
builtin bashpoll signalfd SIGKILL bad; printf 'kill=%d\n' "$?"
builtin bashpoll signalfd SIGSTOP bad; printf 'stop=%d\n' "$?"
'''
SIGNAL_WAIT=r'''builtin bashpoll signalfd USR1 s || exit 31
builtin kill -s USR1 "$BASHPID" || exit 32
builtin bashpoll wait -t 1000 "$s" > wait.out || exit 33
printf '%s\n' "$s" > signal-fd
'''
SIGNAL_EXEC=r'''builtin bashpoll signalfd USR1 s || exit 41
builtin bashpoll clear-cloexec "$s" || exit 42
exec /usr/bin/python3 "$1" "$s"
'''


def masks(shell):
    WORK.mkdir(mode=0o700);probe=WORK/'mask-probe.py';probe.write_text(MASK_PROBE);trace=HOME/'mask-trace.jsonl'
    status,out,err=done(call(shell,MASK_SCRIPT,probe,trace,preblocked=True),'masks')
    rows=[json.loads(x) for x in trace.read_text().splitlines()] if trace.exists() else []
    by={x['tag']:x['mask'] for x in rows}; bit1=1<<(signal.SIGUSR1-1);bit2=1<<(signal.SIGUSR2-1)
    try:
        overlap=(not by['initial']&bit1 and all(by[x]&bit1 for x in ('first','overlap','oneclosed')) and not by['bothclosed']&bit1)
        owned=(all(by[x]&bit2 for x in ('initial','first','overlap','oneclosed','bothclosed','preblocked','preblockedclosed')))
    except KeyError:overlap=owned=False
    names=(status==0 and out==b'numeric=0\nbad=2\nkill=2\nstop=2\n' and err.count(b'invalid or unblockable signal')>=3)
    print('signal masks-overlap=%s preblocked-preserved=%s names-invalid=%s' % (yes(overlap),yes(owned),yes(names)))
    status,out,err=done(call(shell,SIGNAL_WAIT),'self-wait')
    try:
        fd=int((WORK/'signal-fd').read_text()); observed=(WORK/'wait.out').read_bytes()
        ready=status==0 and not out and not err and observed==('%d readable\n'%fd).encode()
    except (OSError,ValueError):ready=False
    read=WORK/'signal-read.py';read.write_text(SIGNAL_READ)
    status,out,err=done(call(shell,SIGNAL_EXEC,read),'self-signo')
    signo=status==0 and out==('signo=%d size=128 readable=yes\n'%signal.SIGUSR1).encode() and not err
    record('signal-result',overlap=overlap,preblocked=owned,names=names,self_wait=ready,signo=signo)
    print('signal self-wait=%s siginfo=%s' % (yes(ready),yes(signo)))


SIGNAL_CONTROL=r'''import ctypes,os,select,signal,struct
lib=ctypes.CDLL(None,use_errno=True); words=(ctypes.c_ulong*16)()
assert lib.sigemptyset(ctypes.byref(words))==0
assert lib.sigaddset(ctypes.byref(words),signal.SIGUSR1)==0
old=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
lib.signalfd.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_int];lib.signalfd.restype=ctypes.c_int
fd=lib.signalfd(-1,ctypes.byref(words),os.O_CLOEXEC); assert fd>=0
os.kill(os.getpid(),signal.SIGUSR1)
e=select.epoll();e.register(fd,select.EPOLLIN); assert e.poll(1);e.close()
data=os.read(fd,128);assert len(data)==128 and struct.unpack('<I',data[:4])[0]==signal.SIGUSR1
os.close(fd);signal.pthread_sigmask(signal.SIG_SETMASK,old)
print('signalfd-control=ok')
'''


def setup(scenario):
    control=CASE/'fd-control';control.mkdir(mode=0o700)
    if scenario=='descriptors':
        probe=control/'probe.py';probe.write_text(PROBE)
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);fd=s.fileno()
        try:
            assert fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
            n=subprocess.run(['/usr/bin/python3',str(probe),str(os.getpid()),str(fd),'negative'],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
            p=subprocess.run(['/usr/bin/python3',str(probe),str(os.getpid()),str(fd),'positive'],
                             pass_fds=(fd,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
            assert n.returncode==p.returncode==0 and not n.stderr and not p.stderr
            nr=json.loads(n.stdout);pr=json.loads(p.stdout)
            assert nr['parent'].startswith('socket:[') and nr['child'] is None and pr['child']==pr['parent']
            assert nr['flags'] & os.O_CLOEXEC
            before=fcntl.fcntl(fd,fcntl.F_GETFL);fcntl.fcntl(fd,fcntl.F_SETFL,before|os.O_NONBLOCK)
            assert fcntl.fcntl(fd,fcntl.F_GETFL)==(before|os.O_NONBLOCK)
            fcntl.fcntl(fd,fcntl.F_SETFL,before)
            record('fd-controls',positive=pr,negative=nr)
        finally:s.close()
        m,sl=pty.openpty()
        try:
            f=fcntl.fcntl(m,fcntl.F_GETFL);fcntl.fcntl(m,fcntl.F_SETFL,f|os.O_NONBLOCK)
            assert fcntl.fcntl(m,fcntl.F_GETFL)==(f|os.O_NONBLOCK)
            fcntl.fcntl(m,fcntl.F_SETFL,f)
        finally:os.close(m);os.close(sl)
    else:
        p=subprocess.run(['/usr/bin/python3','-c',SIGNAL_CONTROL],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        assert p.returncode==0 and p.stdout==b'signalfd-control=ok\n' and not p.stderr
        def block():signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR2})
        p=subprocess.run(['/usr/bin/python3','-c',"import signal; print(int(signal.SIGUSR2 in signal.pthread_sigmask(signal.SIG_BLOCK, [])))"],
                         preexec_fn=block,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        assert p.returncode==0 and p.stdout==b'1\n' and not p.stderr
    record('setup-controls',scenario=scenario,result='verified')
    print('controls=verified')


if __name__=='__main__':
    try:
        guard()
        if len(sys.argv)==3 and sys.argv[1]=='setup':
            assert sys.argv[2] in ('descriptors','masks');setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:]
            {'descriptors':descriptors,'masks':masks}[scenario](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
