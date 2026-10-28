#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM fd-attributed send and write supervisor for a private syslog peer."""
import base64
import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import struct
import sys
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
SEQUENCE=Path('/opt/bashos-parity/harness/helpers/system-client-followup-sequence.py')


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or
        not Path.cwd().is_relative_to(CASE) or platform.machine()!='x86_64'):raise SystemExit(125)


def readmem(pid,address,n):
    if not address or not 0<=n<=65536:raise ValueError('bad notification buffer')
    fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY|os.O_CLOEXEC)
    try:
        data=os.pread(fd,n,address)
        if len(data)!=n:raise ValueError('short notification buffer')
        return data
    finally:os.close(fd)


def identity(pid):
    raw=Path('/proc/%d/stat'%pid).read_text();fields=raw[raw.rindex(')')+2:].split()
    lines=Path('/proc/%d/status'%pid).read_text().splitlines()
    uid=next(tuple(int(x) for x in l.split()[1:]) for l in lines if l.startswith('Uid:'))
    if fields[0]=='Z' or uid[:2]!=(2000,2000):raise RuntimeError('notification process not owned')
    return int(fields[1]),int(fields[19]),uid


def owned(pid,child):
    seen=[];current=pid
    for _ in range(32):
        if current<=1 or current in [x[0] for x in seen]:raise RuntimeError('invalid process ancestry')
        item=identity(current);seen.append((current,item))
        if current==child:break
        current=item[0]
    else:raise RuntimeError('notification ancestry too long')
    if seen[-1][0]!=child or any(identity(n)!=v for n,v in seen):raise RuntimeError('notification outside owned child tree')
    return seen


def verify_owned(chain):
    if any(identity(n)!=v for n,v in chain):raise RuntimeError('notification identity changed during observation')


def main():
    guard();cfgpath=Path(sys.argv[1]).resolve()
    if not cfgpath.is_relative_to(CASE):raise ValueError('configuration outside scratch')
    cfg=json.loads(cfgpath.read_text());logpath=Path(cfg['trace']).resolve()
    if not logpath.is_relative_to(HOME):raise ValueError('trace outside private HOME')
    port=int(cfg['port']);assert 1<=port<=65535
    target=cfg.get('write_target');steps=cfg.get('send_steps',[]);position=0;event_index=0
    spec=importlib.util.spec_from_file_location('syslog_sequence',SEQUENCE);seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq)
    seq.BOOTSTRAP_LOG=Path(str(logpath)+'.bootstrap')
    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,unused):
        nonlocal position,event_index
        status=None
        with logpath.open('w') as log:
            def emit(event):
                nonlocal event_index
                event_index+=1
                if event_index>256:raise RuntimeError('notification record limit')
                event['sequence']=event_index;log.write(json.dumps(event,sort_keys=True)+'\n');log.flush()
            try:
                while status is None:
                    done,wstatus=os.waitpid(child,os.WNOHANG)
                    if done:status=wstatus;break
                    ready,_,_=select.select([listener],[],[],.05)
                    if not ready:continue
                    req=bytearray(80)
                    try:fcntl.ioctl(listener,seq.NOTIF_RECV,req,True)
                    except OSError as e:
                        if e.errno in (errno.EINTR,errno.ENOENT):continue
                        raise
                    ident,pid,_flags,nr,_arch,_ip=struct.unpack_from('<QIIiIQ',req);args=struct.unpack_from('<6Q',req,32)
                    ptr=lib.seccomp_syscall_resolve_num_arch(0,nr);name=ctypes.cast(ptr,ctypes.c_char_p).value.decode() if ptr else str(nr)
                    response='continue';value=0;event=None
                    if name=='sendto':
                        chain=owned(pid,child);fd=int(args[0]);count=int(args[2]);addrlen=int(args[5])
                        if count>65536 or addrlen>256:raise ValueError('oversized send notification')
                        data=readmem(pid,args[1],count) if count else b''
                        addr=readmem(pid,args[4],addrlen) if args[4] and addrlen else b''
                        try:link=os.readlink('/proc/%d/fd/%d'%(pid,fd))
                        except OSError:link=''
                        verify_owned(chain)
                        matched=(len(addr)>=16 and struct.unpack_from('<H',addr)[0]==2 and struct.unpack_from('!H',addr,2)[0]==port and addr[4:8]==bytes((127,0,0,1)) and link.startswith('socket:['))
                        step=steps[position] if matched and position<len(steps) else 'continue'
                        if matched:position+=1
                        if step=='EIO':response='errno';value=errno.EIO
                        elif step=='EAGAIN':response='errno';value=errno.EAGAIN
                        elif step.startswith('short:'):response='value';value=int(step.split(':',1)[1])
                        elif step!='continue':raise ValueError('unknown send action')
                        event={'syscall':name,'pid':pid,'fd':fd,'fd_target':link,'owned_chain':chain,'length':count,
                               'input_base64':base64.b64encode(data).decode(),'sockaddr_hex':addr.hex(),'matched_receiver':matched,
                               'plan_index':position if matched else None,'reply':response if response=='continue' else '%s:%d'%(response,value)}
                    elif name=='write' and target:
                        pid=int(pid);fd=int(args[0])
                        chain=owned(pid,child)
                        try:link=os.readlink('/proc/%d/fd/%d'%(pid,fd))
                        except OSError:link=''
                        if link==target:
                            n=int(args[2]);data=readmem(pid,args[1],min(n,65536)) if n else b''
                            event={'syscall':'write','pid':pid,'fd':fd,'fd_target':link,'owned_chain':chain,'length':n,
                                   'input_base64':base64.b64encode(data).decode(),'reply':'continue'}
                        verify_owned(chain)
                    if event:emit(event)
                    if response=='continue':reply=struct.pack('<QqiI',ident,0,0,seq.FLAG_CONTINUE)
                    elif response=='value':reply=struct.pack('<QqiI',ident,value,0,0)
                    else:reply=struct.pack('<QqiI',ident,0,-value,0)
                    try:fcntl.ioctl(listener,seq.NOTIF_SEND,reply)
                    except OSError as e:
                        if e.errno!=errno.ENOENT:raise
            finally:
                if status is None:os.kill(child,signal.SIGKILL);status=os.waitpid(child,0)[1]
        return status
    seq.supervise=supervise
    rules=['--notify','sendto']+(['--notify','write'] if target else [])
    sys.argv=[str(SEQUENCE),*rules,'--',*sys.argv[2:]];seq.main()


if __name__=='__main__':main()
