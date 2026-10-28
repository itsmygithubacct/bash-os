#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM read-only Yama views in a single-ID user/mount namespace."""
import base64
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
SELF='/opt/bashos-parity/harness/helpers/system-client-followup-ptrace-mountinfo-r2.py'
TARGET=Path('/proc/sys/kernel/yama/ptrace_scope');PARENT=TARGET.parent
MS_RDONLY=1;MS_NOSUID=2;MS_NODEV=4;MS_NOEXEC=8;MS_REMOUNT=32;MS_BIND=4096


def vm_common():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or not Path.cwd().is_relative_to(CASE):raise SystemExit(125)


def guard_outer():
    vm_common()
    if os.getuid()!=2000 or os.geteuid()!=2000:raise SystemExit(125)


def guard_namespace():
    vm_common()
    uidmap=Path('/proc/self/uid_map').read_text();gidmap=Path('/proc/self/gid_map').read_text()
    def parse(text):return [tuple(int(x) for x in row.split()) for row in text.splitlines() if row.strip()]
    if os.getuid()!=0 or os.geteuid()!=0 or parse(uidmap)!=[(0,2000,1)] or parse(gidmap)!=[(0,2000,1)]:raise SystemExit(125)
    return uidmap,gidmap


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'ptrace-followup-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def mount(source,target,flags):
    libc=ctypes.CDLL(None,use_errno=True);libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p]
    if libc.mount(os.fsencode(source) if source else None,os.fsencode(target),None,flags,None)!=0:
        raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()),str(target))


def namespace(outer,mode,source,action,program):
    uidmap,gidmap=guard_namespace();inner=os.readlink('/proc/self/ns/mnt')
    if inner==outer:raise RuntimeError('mount namespace was not isolated')
    mountinfo=Path('/proc/self/mountinfo').read_text()
    for line in mountinfo.splitlines():
        optional=line.split(' - ',1)[0].split()[6:]
        if any(x.startswith('shared:') for x in optional):raise RuntimeError('mount propagation is not private')
    src=Path(source).resolve()
    if not src.is_relative_to(CASE):raise RuntimeError('namespace source outside private case')
    if mode=='absent':
        if not src.is_dir() or any(src.iterdir()):raise RuntimeError('absence source not empty')
        target=PARENT
    else:
        if not src.is_file():raise RuntimeError('missing private source')
        target=TARGET
    mount(str(src),str(target),MS_BIND)
    mount(None,str(target),MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC)
    a=os.stat(src);b=os.stat(target)
    if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino) or not (os.statvfs(target).f_flag & os.ST_RDONLY):
        raise RuntimeError('read-only bind control failed')
    if mode=='absent':
        if TARGET.exists():raise RuntimeError('absence mount left target visible')
        payload=None
    else:
        payload=TARGET.read_bytes()
        if payload!=src.read_bytes():raise RuntimeError('bind contents differ')
    record('namespace',mode=mode,outer_mount=outer,inner_mount=inner,uid_map=uidmap,gid_map=gidmap,
           source=str(src),target=str(target),source_inode=a.st_ino,mounted_inode=b.st_ino,
           readonly=True,mountinfo_base64=b64(mountinfo.encode()),bytes_base64=None if payload is None else b64(payload))
    if action=='check':print('namespace-control='+mode);return
    if action!='exec' or len(program)!=2:raise ValueError('invalid namespace action')
    shell,script=program
    os.execv(shell,[shell,'--noprofile','--norc','-c',script,'ptrace'])


NS_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
read -r __ui __uo __un < /proc/self/uid_map || exit 125
read -r __gi __go __gn < /proc/self/gid_map || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 0 && $__ui == 0 && $__uo == 2000 && $__un == 1 && $__gi == 0 && $__go == 2000 && $__gn == 1 && $PWD == /tmp/parity-case* ]] || exit 125
mlock ptrace-scope; result=$?
printf 'status=%d\n' "$result"
'''


LIVE_SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case* ]] || exit 125
IFS= read -r level < /proc/sys/kernel/yama/ptrace_scope || exit 125
printf 'live-level=%s\n' "$level"
mlock ptrace-scope; result=$?
printf 'status=%d\n' "$result"
'''


def run(argv,timeout=12):
    p=subprocess.Popen(list(map(str,argv)),cwd=CASE,env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError('owned namespace timed out')
    return p.returncode,out,err


def fixture():
    base=CASE/'ptrace-followup-input';base.mkdir(exist_ok=True,mode=0o700)
    for value in ('0','1','2','3','7','x'):
        path=base/value
        if not path.exists():path.write_text(value+'\n');os.chmod(path,0o400)
    absent=base/'empty';absent.mkdir(exist_ok=True,mode=0o500)
    return base


def invoke_ns(base,mode,action,shell=None):
    source=base/('empty' if mode=='absent' else mode);outer=os.readlink('/proc/self/ns/mnt')
    argv=['/usr/bin/unshare','--user','--map-root-user','--mount','/usr/bin/python3',SELF,'ns',outer,mode,str(source),action]
    if action=='exec':argv.extend([shell,NS_SCRIPT])
    rc,out,err=run(argv)
    record('namespace-run',mode=mode,action=action,status=rc,stdout_base64=b64(out),stderr_base64=b64(err))
    return rc,out,err


def setup():
    if not TARGET.is_file():raise RuntimeError('guest Yama ptrace_scope file unavailable for bind controls')
    base=fixture()
    for mode in ('0','x','absent'):
        rc,out,err=invoke_ns(base,mode,'check')
        if rc or err or out!=('namespace-control='+mode+'\n').encode():raise RuntimeError('namespace control failed for '+mode)
    record('controls',single_uid_gid_map='0:2000:1',isolated_mounts='read-only and private',sampled_modes=['0','x','absent'])
    print('controls=verified')


def scenario(shell):
    base=fixture();rc,live,err=run([shell,'--noprofile','--norc','-c',LIVE_SCRIPT,'live'])
    m=next((x.split(b'=',1)[1] for x in live.splitlines() if x.startswith(b'live-level=')),b'')
    values={'0':'0 (classic — any process can ptrace any same-uid process)','1':'1 (restricted — only descendants via PR_SET_PTRACER)',
            '2':'2 (admin-only — requires CAP_SYS_PTRACE)','3':'3 (no-attach — no process may ptrace)','7':'unknown'}
    live_desc=values.get(m.decode(errors='replace'),'unknown')
    live_ok=rc==0 and not err and live==('live-level=%s\nptrace_scope=%s  %s\nstatus=0\n'%(m.decode(),m.decode(),live_desc)).encode()
    results={}
    for value in ('0','1','2','3','7','x','absent'):
        n,out,er=invoke_ns(base,value,'exec',shell)
        if value in values:ok=n==0 and not er and out==('ptrace_scope=%s  %s\nstatus=0\n'%(value,values[value])).encode()
        elif value=='x':ok=n==0 and out==b'status=1\n' and b'ptrace-scope: failed to parse level' in er
        else:ok=n==0 and out==b'status=1\n' and b'ptrace-scope: open /proc/sys/kernel/yama/ptrace_scope: No such file or directory' in er
        results[value]=ok
    record('result',live_stdout_base64=b64(live),live_stderr_base64=b64(err),live=live_ok,values=results)
    print('ptrace-scope live=%s levels=%s unknown=%s malformed=%s absent=%s' %
          (yes(live_ok),yes(all(results[x] for x in ('0','1','2','3'))),yes(results['7']),yes(results['x']),yes(results['absent'])))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='ns':guard_namespace()
    else:guard_outer()
    try:
        if len(sys.argv)==2 and sys.argv[1]=='setup':setup()
        elif len(sys.argv)>=6 and sys.argv[1]=='ns':namespace(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6:])
        else:
            assert len(sys.argv)==2;scenario(sys.argv[1])
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
