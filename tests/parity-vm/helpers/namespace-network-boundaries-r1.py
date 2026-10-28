#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent nonroot and user-owned namespace boundary controls."""
import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        os.getuid()!=os.geteuid() or Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME)):
        raise RuntimeError('disposable guest identity mismatch')
    if os.getuid()==0:
        mapping=[list(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
        if mapping!=[[0,2000,1]]: raise RuntimeError('expected single-id mapped user namespace')
    elif os.getuid()!=2000: raise RuntimeError('unexpected guest uid')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'): raise RuntimeError('not a QEMU/KVM guest')


def private_mount():
    outer=os.environ.get('FIXTURE_OUTER_MNT')
    if os.getuid()!=0 or not outer or os.readlink('/proc/self/ns/mnt')==outer:
        raise RuntimeError('private user-owned mount namespace required')


def snapshot():
    return {'uid':os.getuid(),'pid':os.getpid(),'status':Path('/proc/self/status').read_text(),
            'uid_map':Path('/proc/self/uid_map').read_text(),
            'mnt':os.readlink('/proc/self/ns/mnt'),'mountinfo':Path('/proc/self/mountinfo').read_text()}


def save(name,data): (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def mount_call(source,target,flags,kind=None,data=None):
    lib=ctypes.CDLL(None,use_errno=True);ctypes.set_errno(0)
    rc=lib.mount(ctypes.c_char_p(os.fsencode(source)) if source else None,
                 ctypes.c_char_p(os.fsencode(target)),ctypes.c_char_p(os.fsencode(kind)) if kind else None,
                 ctypes.c_ulong(flags),ctypes.c_char_p(os.fsencode(data)) if data else None)
    return {'source':source,'target':target,'flags':flags,'kind':kind,'data':data,
            'result':int(rc),'errno':ctypes.get_errno() if rc<0 else 0}


def control_mount(mode):
    report={'mode':mode,'before':snapshot()}
    if mode=='denied':
        if os.getuid()!=2000: raise RuntimeError('expected nonroot guest caller')
        status=report['before']['status'];cap=int(next(x.split(':')[1] for x in status.splitlines() if x.startswith('CapEff:')).strip(),16)
        if cap & (1<<21): raise RuntimeError('caller unexpectedly has CAP_SYS_ADMIN')
        report['bind']=mount_call(str(CASE/'source.fixture'),str(CASE/'dest.fixture'),4096)
        report['private']=mount_call(None,'/',1<<18 | 1<<14)
        want=errno.EPERM
    elif mode=='missing':
        private_mount()
        report['bind']=mount_call(str(CASE/'missing.fixture'),str(CASE/'dest.fixture'),4096)
        want=errno.ENOENT
    else: raise ValueError('unknown mount control')
    report['after']=snapshot();save('mount-'+mode+'-control.json',report)
    if report['bind']['errno']!=want or (mode=='denied' and report['private']['errno']!=want):
        raise RuntimeError('mount native errno mismatch')


def pivot_control(mode):
    private_mount()
    report={'mode':mode,'before':snapshot()}
    fd=os.open(HOME/('pivot-'+mode+'-control.json'),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        root=CASE/('control-pivot-'+mode);root.mkdir()
        report['new_mount']=mount_call('fixture',str(root),0,'tmpfs','size=1m')
        if report['new_mount']['result']!=0: raise RuntimeError('tmpfs mount failed')
        if mode=='outside':
            old=CASE/'control-outside-old';old.mkdir()
        elif mode=='shared':
            old=root/'old';old.mkdir()
            report['make_shared']=mount_call(None,'/',(1<<20)|(1<<14))
            if report['make_shared']['result']!=0: raise RuntimeError('cannot make the isolated root shared')
        else: raise ValueError('unknown pivot control')
        report['before_pivot']=snapshot()
        if os.uname().machine!='x86_64': raise RuntimeError('amd64 syscall table required')
        lib=ctypes.CDLL(None,use_errno=True);ctypes.set_errno(0)
        rc=lib.syscall(155,ctypes.c_char_p(os.fsencode(root)),ctypes.c_char_p(os.fsencode(old)))
        report['pivot_request']={'number':155,'new':str(root),'old':str(old)}
        report['pivot_reply']={'result':int(rc),'errno':ctypes.get_errno() if rc<0 else 0}
        if rc>=0 or report['pivot_reply']['errno'] not in (errno.EINVAL,errno.EBUSY):
            raise RuntimeError('kernel did not reject layout as expected')
    except Exception as exc:
        report['fatal_error']=str(exc);raise
    finally:
        os.write(fd,(json.dumps(report,indent=2,sort_keys=True)+'\n').encode());os.close(fd)


def compare_pivot(mode):
    report=json.loads((HOME/('pivot-'+mode+'-control.json')).read_text())
    code=report['pivot_reply']['errno']
    diagnostic=(HOME/'pivot.err').read_text()
    if code not in (errno.EINVAL,errno.EBUSY) or os.strerror(code) not in diagnostic:
        raise RuntimeError('candidate pivot errno differs from direct kernel control')
    print('pivot-errno=matches')


def environment_check():
    raw=(HOME/'exported-environment.raw').read_bytes()
    observed={}
    for part in raw.split(b'\0'):
        if not part:continue
        key,sep,value=part.partition(b'=')
        if not sep or key in observed: raise RuntimeError('invalid environment baseline')
        observed[key]=value
    actual=dict(os.environb)
    # Bash intentionally updates the conventional underscore command-name
    # variable when launching an external command.
    baseline=observed.pop(b'_',None);current=actual.pop(b'_',None)
    expected={k.decode('utf-8','backslashreplace'):v.decode('utf-8','backslashreplace') for k,v in observed.items()}
    got={k.decode('utf-8','backslashreplace'):v.decode('utf-8','backslashreplace') for k,v in actual.items()}
    report={'exported':expected,'child':got,'baseline_underscore':repr(baseline),'child_underscore':repr(current),
            'missing':sorted(set(expected)-set(got)),'extra':sorted(set(got)-set(expected)),
            'different':sorted(k for k in set(expected)&set(got) if expected[k]!=got[k])}
    save('environment-check.json',report)
    if report['missing'] or report['extra'] or report['different']:
        raise RuntimeError('exported child environment differs')
    print('exported-environment=matches')


def main():
    guard();mode=sys.argv[1]
    if mode=='mount-control':control_mount(sys.argv[2])
    elif mode=='pivot-control':pivot_control(sys.argv[2])
    elif mode=='environment-check':environment_check()
    elif mode=='compare-pivot':compare_pivot(sys.argv[2])
    else:raise ValueError('unknown mode')


if __name__=='__main__':main()
