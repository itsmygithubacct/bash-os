#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned-child UTS descriptor and user-namespace controls in the guest."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HOME=Path('/tmp/parity-home');CASE=Path('/tmp/parity-case')


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME) or os.getuid()!=os.geteuid()):
        raise RuntimeError('guest identity mismatch')
    if os.getuid()==0:
        uidmap=[list(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
        if uidmap!=[[0,2000,1]]: raise RuntimeError('unexpected mapped uid')
    elif os.getuid()!=2000: raise RuntimeError('unexpected guest uid')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'): raise RuntimeError('not a disposable guest')


def save(name,data): (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def snapshot(pid='self'):
    root=Path('/proc')/str(pid)
    return {'pid':pid,'namespaces':{p.name:os.readlink(p) for p in sorted((root/'ns').iterdir())},
            'status':(root/'status').read_text(),'uid_map':(root/'uid_map').read_text(),
            'gid_map':(root/'gid_map').read_text()}


def hold():
    print('READY',flush=True)
    if sys.stdin.readline().strip()!='done': raise RuntimeError('owned child not released')


def control_enter():
    if os.getuid()!=0: raise RuntimeError('mapped root required')
    child=subprocess.Popen(['/usr/bin/unshare','--uts','/usr/bin/python3',__file__,'hold'],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    report={'child_pid':child.pid}
    try:
        if child.stdout.readline()!='READY\n': raise RuntimeError('target child not ready')
        report['before']=snapshot();report['target']=snapshot(child.pid)
        fd=os.open('/proc/%d/ns/uts'%child.pid,os.O_RDONLY)
        try:
            ref=subprocess.Popen(['/usr/bin/nsenter','--uts=/proc/self/fd/%d'%fd,'--','/usr/bin/python3',__file__,'inspect','control'],
                                 pass_fds=(fd,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            stdout,stderr=ref.communicate(timeout=8)
            report['native_nsenter']={'status':ref.returncode,'stdout':stdout,'stderr':stderr,'fd':fd}
            if ref.returncode!=0: raise RuntimeError('native nsenter control failed')
            before=report['before']['namespaces']['uts']; target=report['target']['namespaces']['uts']
            native=json.loads((HOME/'inspect-control.json').read_text())
            if before==target or native['namespaces']['uts']!=target: raise RuntimeError('native namespace control mismatch')
            lib=ctypes.CDLL(None,use_errno=True);ctypes.set_errno(0)
            rc=lib.syscall(308,fd,0);report['setns_request']={'number':308,'fd':fd,'nstype':0}
            report['setns_reply']={'result':int(rc),'errno':ctypes.get_errno() if rc<0 else 0}
            report['after']=snapshot()
            if rc!=0 or report['after']['namespaces']['uts']!=target:
                raise RuntimeError('direct setns control failed')
        finally: os.close(fd)
    except Exception as exc:
        report['fatal_error']=str(exc);raise
    finally:
        save('enter-control.json',report)
        if child.poll() is None:
            try: child.stdin.write('done\n');child.stdin.flush()
            except (OSError,BrokenPipeError): pass
        child.wait(timeout=5)
        if child.returncode!=0: raise RuntimeError('owned target child failed to exit')


def compare(before_name,after_name,target_name):
    before=json.loads((HOME/before_name).read_text());after=json.loads((HOME/after_name).read_text());target=json.loads((HOME/target_name).read_text())
    left=before['namespaces'];right=after['namespaces'];target_ns=target['namespaces']
    changed={k for k in left if left[k]!=right[k]}
    report={'changed':sorted(changed),'before':before,'after':after,'target':target}
    save('compare.json',report)
    if changed!={'uts'} or right['uts']!=target_ns['uts']:
        raise RuntimeError('entered UTS namespace does not match owned target')
    print('namespace-entry=verified')


def compare_user(before_name,after_name):
    before=json.loads((HOME/before_name).read_text());after=json.loads((HOME/after_name).read_text())
    left=before['namespaces'];right=after['namespaces'];changed={k for k in left if left[k]!=right[k]}
    save('compare-user.json',{'before':before,'after':after,'changed':sorted(changed)})
    if changed!={'user'}: raise RuntimeError('user namespace changes differ')
    print('user-namespace=verified')


def main():
    guard();mode=sys.argv[1]
    if mode=='hold': hold()
    elif mode=='control-enter': control_enter()
    elif mode=='snapshot': save(sys.argv[3],snapshot(sys.argv[2]))
    elif mode=='inspect': save('inspect-'+sys.argv[2]+'.json',snapshot())
    elif mode=='compare': compare(*sys.argv[2:])
    elif mode=='compare-user': compare_user(*sys.argv[2:])
    else: raise ValueError('unknown mode')


if __name__=='__main__': main()
