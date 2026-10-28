#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contained user/mount namespace controls and owned-child observations."""
import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME) or os.getuid()!=os.geteuid()):
        raise RuntimeError('disposable guest identity mismatch')
    if os.getuid()==0:
        rows=[list(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
        if rows!=[[0,2000,1]]: raise RuntimeError('not the one-id mapped guest user')
    elif os.getuid()!=2000: raise RuntimeError('wrong guest uid')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'): raise RuntimeError('not a QEMU/KVM guest')


def require_private_mount():
    if os.getuid()!=0 or not os.environ.get('FIXTURE_OUTER_MNT'):
        raise RuntimeError('user/mount namespace context missing')
    current=os.readlink('/proc/self/ns/mnt')
    if current==os.environ['FIXTURE_OUTER_MNT']:
        raise RuntimeError('mount namespace is not private to fixture')


def snap():
    return {'uid':os.getuid(),'gid':os.getgid(),'pid':os.getpid(),
            'ns':{n:os.readlink('/proc/self/ns/'+n) for n in ('mnt','net','uts','ipc','user','pid','time')},
            'uid_map':Path('/proc/self/uid_map').read_text(),
            'gid_map':Path('/proc/self/gid_map').read_text(),
            'status':Path('/proc/self/status').read_text(),
            'mountinfo':Path('/proc/self/mountinfo').read_text()}


def save(name, data):
    (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def command(args):
    proc=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
    return {'argv':args,'status':proc.returncode,'stdout':proc.stdout.decode('utf-8','replace'),
            'stderr':proc.stderr.decode('utf-8','replace')}


def mount_control():
    require_private_mount()
    report={'before':snap(),'commands':[]}
    base=CASE/'control-mount'; base.mkdir(); tmp=base/'tmp'; tmp.mkdir()
    def run(args):
        out=command(args); report['commands'].append(out)
        if out['status']!=0: raise RuntimeError('native mount control failed')
    try:
        run(['/usr/bin/mount','--make-rprivate','/'])
        run(['/usr/bin/mount','-t','tmpfs','-o','size=1m','tmpfs',str(tmp)])
        for n in ('src','rw','ro','fs'): (tmp/n).mkdir()
        (tmp/'src'/'data').write_text('before\n')
        run(['/usr/bin/mount','--bind',str(tmp/'src'),str(tmp/'rw')])
        (tmp/'rw'/'data').write_text('through-bind\n')
        if (tmp/'src'/'data').read_text()!='through-bind\n': raise RuntimeError('rw bind control mismatch')
        run(['/usr/bin/mount','--bind',str(tmp/'src'),str(tmp/'ro')])
        run(['/usr/bin/mount','-o','remount,bind,ro',str(tmp/'ro')])
        try: (tmp/'ro'/'denied').write_text('x'); ro_errno=0
        except OSError as exc: ro_errno=exc.errno
        (tmp/'src'/'still-writable').write_text('x')
        run(['/usr/bin/mount','-t','tmpfs','-o','size=1m','tmpfs',str(tmp/'fs')])
        run(['/usr/bin/mount','-o','remount,ro',str(tmp/'fs')])
        try: (tmp/'fs'/'denied').write_text('x'); remount_errno=0
        except OSError as exc: remount_errno=exc.errno
        report.update(bind_ro_errno=ro_errno,remount_errno=remount_errno,after=snap())
        if (ro_errno,remount_errno)!=(errno.EROFS,errno.EROFS): raise RuntimeError('read-only control mismatch')
    finally:
        save('mount-control.json',report)


def pivot_control(mode):
    require_private_mount()
    report={'before':snap(),'mode':mode,'commands':[]}
    # Retain a descriptor to the log, since the old HOME is unreachable at its
    # old path after a successful pivot; no other process is affected.
    fd=os.open(HOME/('pivot-control-'+mode+'.json'),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        base=CASE/('control-pivot-'+mode); base.mkdir()
        mount=command(['/usr/bin/mount','-t','tmpfs','-o','size=1m','tmpfs',str(base)])
        report['commands'].append(mount)
        if mount['status']!=0: raise RuntimeError('pivot tmpfs control failed')
        new=base if mode=='valid' else base/'non-mountpoint'
        if mode=='invalid': new.mkdir()
        old=new/'old'; old.mkdir()
        (new/'marker').write_text('pivot-fixture\n')
        rootfd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            oldstat=os.fstat(rootfd)
            libc=ctypes.CDLL(None,use_errno=True)
            ctypes.set_errno(0)
            rc=libc.syscall(155,ctypes.c_char_p(os.fsencode(new)),ctypes.c_char_p(os.fsencode(old)))
            code=ctypes.get_errno() if rc<0 else 0
            report['pivot_request']={'number':155,'new':str(new),'old':str(old)}
            report['pivot_reply']={'result':int(rc),'errno':code}
            if mode=='invalid':
                if code!=errno.EINVAL: raise RuntimeError('invalid pivot control was not EINVAL')
                report['after']=snap()
            else:
                if rc!=0: raise RuntimeError('valid pivot control failed')
                os.chdir('/')
                newinfo=os.stat('/'); oldinfo=os.stat('/old')
                report['after']={'cwd':os.getcwd(),'new_root_dev_ino':[newinfo.st_dev,newinfo.st_ino],
                    'old_root_dev_ino':[oldinfo.st_dev,oldinfo.st_ino],
                    'old_fd_dev_ino':[oldstat.st_dev,oldstat.st_ino],
                    'marker':Path('/marker').read_text(),
                    'rootlink':os.readlink('/old/proc/self/root')}
                if (oldinfo.st_dev,oldinfo.st_ino)!=(oldstat.st_dev,oldstat.st_ino):
                    raise RuntimeError('old root is not reachable at put_old')
                if report['after']['marker']!='pivot-fixture\n': raise RuntimeError('new root marker missing')
        finally: os.close(rootfd)
    finally:
        os.write(fd,(json.dumps(report,indent=2,sort_keys=True)+'\n').encode());os.close(fd)


def child(label):
    value={'label':label,'argv':sys.argv[2:],'environment':dict(os.environ),'snapshot':snap()}
    save('child-'+label+'.json',value)
    print('child-'+label+'=recorded')


def snapshot(label):
    save('snapshot-'+label+'.json',snap())


def check_spawn(label, expected_nnp, expected_pid_one, *args):
    data=json.loads((HOME/('child-'+label+'.json')).read_text())
    child_status=data['snapshot']['status']
    nnp=int(next(line.split(':',1)[1] for line in child_status.splitlines() if line.startswith('NoNewPrivs:')).strip())
    errors=[]
    if data['argv'] != [label]+list(args): errors.append('argv mismatch')
    if data['environment'].get('NN_TOKEN') != 'value with spaces' or data['environment'].get('NN_EMPTY') != '':
        errors.append('exported fixture environment mismatch')
    if nnp != int(expected_nnp): errors.append('no-new-privs mismatch')
    if int(expected_pid_one) and data['snapshot']['pid']!=1: errors.append('child is not PID 1')
    if int(expected_pid_one):
        parent=json.loads((HOME/'snapshot-parent.json').read_text())
        if parent['ns']['pid']==data['snapshot']['ns']['pid']: errors.append('child PID namespace unchanged')
    save('child-check-'+label+'.json',{'errors':errors,'nnp':nnp,'child':data})
    if errors: raise RuntimeError('spawn child observations failed: '+repr(errors))
    print('child-'+label+'=verified')


def check_native_pid():
    data=json.loads((HOME/'child-native-pid.json').read_text())
    nnp=int(next(line.split(':',1)[1] for line in data['snapshot']['status'].splitlines() if line.startswith('NoNewPrivs:')).strip())
    errors=[]
    if data['snapshot']['pid']!=1: errors.append('native child is not PID 1')
    if data['argv']!=['native-pid','one','two words']: errors.append('native argv mismatch')
    if data['environment'].get('NN_TOKEN')!='value with spaces' or data['environment'].get('NN_EMPTY')!='': errors.append('native environment mismatch')
    if nnp!=0: errors.append('native no-new-privs was already set')
    save('native-pid-check.json',{'errors':errors,'child':data})
    if errors: raise RuntimeError('native PID child control failed: '+repr(errors))


def main():
    guard()
    mode=sys.argv[1]
    if mode=='mount-control': mount_control()
    elif mode=='pivot-control': pivot_control(sys.argv[2])
    elif mode=='child': child(sys.argv[2])
    elif mode=='child-exit': raise SystemExit(int(sys.argv[2]))
    elif mode=='snapshot': snapshot(sys.argv[2])
    elif mode=='check-spawn': check_spawn(*sys.argv[2:])
    elif mode=='check-native-pid': check_native_pid()
    else: raise ValueError('unknown mode')


if __name__=='__main__': main()
