#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only positive short write on an owned real PTY, including side effect.

The supervisor answers only its remembered child's first write to the exact
recipient slave. It delivers the prefix through the actual kernel tty before
returning the matching count. Other calls continue normally. No project imports.
"""
import base64
import copy
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
import termios
import time
import uuid

SELF='/opt/bashos-parity/harness/helpers/terminal-platform-write-short-audit121-r3.py'
HOME=Path('/tmp/parity-home')
RECV=0xc0502100
SEND=0xc0182101


def guard():
    # Require the root-owned VM marker and the already identity-checked guest
    # evaluator as PID 1 in its private PID namespace before any behavior.
    # Setup uses assert statements, so optimized Python must never remove them.
    if sys.flags.optimize:
        raise RuntimeError('optimized Python would disable fixture controls')
    marker = Path('/etc/bashos-parity-vm')
    meta = marker.lstat()
    if meta.st_uid != 0 or meta.st_mode & 0o022 or (meta.st_mode & 0o170000) != 0o100000:
        raise RuntimeError('untrusted VM marker')
    token = marker.read_text().strip()
    uuid.UUID(token)
    init_args = Path('/proc/1/cmdline').read_bytes().split(b'\0')
    if (Path('/proc/1').stat().st_uid != 0 or len(init_args) < 4
            or init_args[:3] != [b'/usr/bin/python3', b'/opt/bashos-parity/harness/guest.py', b'--vm-token']
            or init_args[3] != token.encode('ascii')):
        raise RuntimeError('expected the identity-checked isolated guest evaluator as PID 1')
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.getuid()!=2000
            or os.geteuid()!=2000 or Path.cwd()!=Path('/tmp/parity-case') or Path.home()!=HOME
            or os.uname().machine!='x86_64'):
        raise RuntimeError('write-short refuses outside QEMU uid2000 fixture scratch')
    if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0):
        raise OSError(ctypes.get_errno(),'subreaper')


def b64(raw):return base64.b64encode(raw).decode()
def modes(value):return value[:6]+[[x if isinstance(x,int) else b64(x) for x in value[6]]]
def save(name,value):(HOME/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def native(path):
    fd=os.open(path,os.O_WRONLY|os.O_NOCTTY)
    target=b'abcdef\r\n'
    at,calls=0,[]
    try:
        while at<len(target):
            n=os.write(fd,target[at:])
            calls.append({'offset':at,'requested':len(target)-at,'returned':n})
            if n<=0:return 1
            at+=n
    finally:
        os.close(fd)
        save('native-writer.json',calls)
    return 0


def install():
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0):raise OSError(ctypes.get_errno(),'NO_NEW_PRIVS')
    lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.c_void_p]
    lib.seccomp_load.argtypes=[ctypes.c_void_p]
    lib.seccomp_notify_fd.argtypes=[ctypes.c_void_p]
    context=lib.seccomp_init(0x7fff0000)
    if not context or lib.seccomp_rule_add_array(context,0x7fc00000,1,0,None) or lib.seccomp_load(context):
        raise RuntimeError('unprivileged write notification install failed')
    listener=lib.seccomp_notify_fd(context)
    if listener<0:raise RuntimeError('notification listener missing')
    os.set_inheritable(listener,False)
    return listener


def exercise(argv,label):
    master,slave=os.openpty()
    original=copy.deepcopy(termios.tcgetattr(slave));profile=copy.deepcopy(original)
    profile[1]&=~termios.OPOST
    termios.tcsetattr(slave,termios.TCSANOW,profile)
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',12,40,400,240))
    path=os.ttyname(slave);os.chmod(path,0o620)
    program=[path if x=='@recipient' else x for x in argv]
    before=os.stat(path)
    parent,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    out_r,out_w=os.pipe();err_r,err_w=os.pipe()
    child=os.fork()
    if not child:
        try:
            parent.close();os.close(out_r);os.close(err_r)
            os.dup2(out_w,1);os.dup2(err_w,2)
            null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0)
            os.close(master);os.close(slave)
            listener=install()
            socket.send_fds(peer,[b'L'],[listener])
            env=dict(os.environ,LC_ALL='C',BASHWALL_NOBANNER='1',BASHWALL_FORCE_MESG='1',TP_RECIPIENT=path)
            os.execve(program[0],program,env)
        except BaseException:
            os._exit(126)
    peer.close();os.close(out_w);os.close(err_w)
    listener=None;status=None;raw=bytearray();stdout=bytearray();stderr=bytearray();records=[];events=[];short=False
    deadline=time.monotonic()+8
    try:
        if not select.select([parent],[],[],4)[0]:raise RuntimeError('child did not deliver notification listener')
        _,fds,_,_=socket.recv_fds(parent,16,1)
        if len(fds)!=1:raise RuntimeError('missing owned listener')
        listener=fds[0]
        pipes={out_r:stdout,err_r:stderr,master:raw}
        while time.monotonic()<deadline:
            if status is None:
                done,wait=os.waitpid(child,os.WNOHANG)
                if done:status=os.waitstatus_to_exitcode(wait)
            ready=select.select(list(pipes)+([] if status is not None else [listener]),[],[],.01)[0]
            for fd in ready:
                if fd!=listener:
                    data=os.read(fd,65536)
                    if data:
                        pipes[fd].extend(data)
                        if sum(map(len,(raw,stdout,stderr)))>1000000:raise RuntimeError('bounded captured output exceeded')
                        events.append({'fd_kind':'recipient' if fd==master else 'stdout' if fd==out_r else 'stderr','ns':time.monotonic_ns(),'base64':b64(data)})
                    elif fd!=master:
                        pipes.pop(fd,None)
                    continue
                request=bytearray(80)
                try:fcntl.ioctl(listener,RECV,request,True)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT,errno.EINTR):continue
                    raise
                ident,pid,flags,nr,arch,ip=struct.unpack_from('<QIIiIQ',request)
                args=struct.unpack_from('<6Q',request,32)
                if pid!=child or nr!=1 or arch!=0xc000003e:
                    raise RuntimeError('notification outside remembered x86_64 child write')
                fd=args[0]&0xffffffff
                try:target=os.readlink('/proc/%d/fd/%d'%(pid,fd))
                except OSError:target=None
                response=(ident,0,0,1)
                if target==path:
                    if args[2]>8192:raise RuntimeError('recipient write data bound')
                    with open('/proc/%d/mem'%pid,'rb',buffering=0) as memory:
                        payload=os.pread(memory.fileno(),args[2],args[1])
                    row={'ns':time.monotonic_ns(),'pid':pid,'fd':fd,'tty':target,'requested':args[2],
                        'buffer_base64':b64(payload),'recipient_isatty':os.isatty(slave)}
                    if not short:
                        if payload!=b'abcdef\r\n':raise RuntimeError('first controlled body differs from fixed expected bytes')
                        delivered=os.write(slave,payload[:3])
                        if delivered!=3:raise RuntimeError('native prefix delivery was short')
                        response=(ident,3,0,0);short=True
                        row.update(action='deliver-prefix-and-return-short',delivered_base64=b64(payload[:3]),returned=3)
                    else:row.update(action='continue-real-kernel-write')
                    records.append(row)
                    if len(records)>128:raise RuntimeError('bounded target write count exceeded')
                try:fcntl.ioctl(listener,SEND,struct.pack('<QqiI',*response))
                except OSError as exc:
                    if exc.errno!=errno.ENOENT:raise
            if status is not None:
                # The child completed all writes. Drain actual queued receiver
                # bytes, not a timeout-derived claim that output has finished.
                while select.select([master],[],[],0)[0]:
                    data=os.read(master,65536)
                    if not data:break
                    raw.extend(data);events.append({'fd_kind':'recipient','ns':time.monotonic_ns(),'base64':b64(data)})
                if not select.select([fd for fd in pipes if fd!=master],[],[],0)[0]:break
    finally:
        natural=status
        if status is None:
            os.kill(child,signal.SIGKILL);status=os.waitstatus_to_exitcode(os.waitpid(child,0)[1])
        final=termios.tcgetattr(slave)
        save(label+'.json',{'argv':program,'pid':child,'natural_status':natural,'status_after_cleanup':status,
            'controlled_env':{'LC_ALL':'C','BASHWALL_NOBANNER':'1','BASHWALL_FORCE_MESG':'1','TP_RECIPIENT':path},
            'tty':path,'tty_inode':before.st_ino,'tty_mode':stat.S_IMODE(before.st_mode),'tty_uid':before.st_uid,
            'initial_termios':modes(profile),'termios_before_cleanup':modes(final),'geometry':[12,40,400,240],
            'injections':records,'events':events,'short_return_reached':short})
        (HOME/(label+'-recipient.raw')).write_bytes(raw)
        (HOME/(label+'-stdout.raw')).write_bytes(stdout)
        (HOME/(label+'-stderr.raw')).write_bytes(stderr)
        termios.tcsetattr(slave,termios.TCSANOW,original)
        for fd in (master,slave,out_r,err_r):os.close(fd)
        if listener is not None:os.close(listener)
        parent.close()
    return natural,bytes(raw),records,final==profile


def setup():
    status,raw,records,restored=exercise(['/usr/bin/python3',SELF,'native','@recipient'],'control')
    assert status==0 and raw==b'abcdef\r\n' and restored
    assert len(records)==2 and records[0]['returned']==3 and records[1]['buffer_base64']==b64(b'def\r\n')
    assert json.loads((HOME/'native-writer.json').read_text())==[
        {'offset':0,'requested':8,'returned':3},{'offset':3,'requested':5,'returned':5}]
    print('independent-positive-short-real-PTY-control=PASS')
    return 0


def run(side,executable):
    argv=(['/usr/bin/python3',SELF,'native','@recipient'] if side=='reference' else
        [executable,'--noprofile','--norc','-c','write "$TP_RECIPIENT" abcdef'])
    status,raw,records,restored=exercise(argv,'session')
    rows=[{'label':'positive-short-write-reached','actual':bool(records) and records[0].get('returned')==3,'expected':True},
        {'label':'exact-recipient-bytes','actual':b64(raw),'expected':b64(b'abcdef\r\n')},
        {'label':'write-all-completion-status','actual':status,'expected':0},
        {'label':'receiver-termios-preserved','actual':restored,'expected':True},
        {'label':'real-followup-remainder-attempt','actual':len(records)>=2,'expected':True}]
    for row in rows:row['passed']=row['actual']==row['expected']
    save('assertions.json',rows)
    Path('recipient.raw').write_bytes(raw)
    Path('result.json').write_text(json.dumps({'status':status,'recipient_base64':b64(raw),'target_write_count':len(records)},indent=2)+'\n')
    failed=any(not r['passed'] for r in rows)
    print('all-explicit-assertions='+('FAIL' if failed else 'PASS'))
    return int(failed)


def main():
    guard()
    action,*args=sys.argv[1:]
    try:
        if action=='native':return native(*args)
        if action=='setup':return setup()
        if action=='run':return run(*args)
        raise ValueError(action)
    finally:
        for pid in map(int,Path('/proc/self/task/%d/children'%os.getpid()).read_text().split()):
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0)


if __name__=='__main__':sys.exit(main())
