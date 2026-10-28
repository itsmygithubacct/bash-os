#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent one-ID user-namespace mapping controls; VM-only."""
import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HOME=Path('/tmp/parity-home')


def guard():
    marker=Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    if (os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=Path('/tmp/parity-case')
            or os.environ.get('HOME')!=str(HOME) or Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU'):
        raise RuntimeError('disposable guest identity mismatch')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'): raise RuntimeError('not a QEMU/KVM guest')


def snap():
    paths=['uid_map','gid_map','setgroups','status']
    return {'uid':os.getuid(),'gid':os.getgid(),
            'raw':{p:Path('/proc/self',p).read_text() for p in paths},
            'namespaces':{n:os.readlink('/proc/self/ns/'+n) for n in ('user','pid','mnt')}}


def write(path,data):
    result={'path':path,'request_hex':data.hex()}
    try:
        fd=os.open(path,os.O_WRONLY)
        try: result['result']=os.write(fd,data)
        finally: os.close(fd)
        result['errno']=0
    except OSError as exc:
        result.update(result=-1,errno=exc.errno,message=exc.strerror)
    return result


def control(mode):
    if os.uname().machine!='x86_64': raise RuntimeError('amd64 syscall table required')
    libc=ctypes.CDLL(None,use_errno=True)
    report={'mode':mode,'before':snap(),'unshare_request':{'number':272,'flags':0x10000000},'writes':[]}
    ctypes.set_errno(0); rc=libc.syscall(272,0x10000000)
    report['unshare_reply']={'result':int(rc),'errno':ctypes.get_errno() if rc<0 else 0}
    if rc<0:
        (HOME/('map-control-'+mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')
        raise RuntimeError('native unshare control failed')
    def push(path,data):
        value=write('/proc/self/'+path,data);report['writes'].append(value);return value['errno']
    if mode=='valid':
        got=[push('setgroups',b'deny'),push('uid_map',b'4242 2000 1\n'),push('gid_map',b'4242 2000 1\n')]
        want=[0,0,0]
    elif mode=='ordering':
        got=[push('gid_map',b'4242 2000 1\n')];want=[errno.EPERM]
    elif mode=='unowned':
        got=[push('uid_map',b'4242 2001 1\n')];want=[errno.EPERM]
    elif mode=='zero':
        got=[push('uid_map',b'4242 2000 0\n')];want=[errno.EINVAL]
    elif mode=='overlap':
        got=[push('uid_map',b'4242 2000 1\n4242 2000 1\n')];want=[errno.EINVAL]
    elif mode=='second':
        got=[push('uid_map',b'4242 2000 1\n'),push('uid_map',b'4242 2000 1\n')];want=[0,errno.EPERM]
    else: raise ValueError('unknown mode')
    report['after']=snap()
    (HOME/('map-control-'+mode+'.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    if got!=want: raise RuntimeError('mapping control errno mismatch: '+repr(got))
    if mode=='valid':
        if (os.getuid(),os.getgid())!=(4242,4242) or report['after']['raw']['setgroups'].strip()!='deny':
            raise RuntimeError('valid mapping readback mismatch')
        if [list(map(int,line.split())) for line in report['after']['raw']['uid_map'].splitlines()]!=[[4242,2000,1]]:
            raise RuntimeError('unexpected uid map')
        if [list(map(int,line.split())) for line in report['after']['raw']['gid_map'].splitlines()]!=[[4242,2000,1]]:
            raise RuntimeError('unexpected gid map')


def main():
    guard()
    if sys.argv[1]!='control': raise ValueError('unknown command')
    control(sys.argv[2])


if __name__=='__main__':
    main()
