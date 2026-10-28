#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM memory-lock failure and unlock client observations."""
import base64
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
SEQUENCE='/opt/bashos-parity/harness/helpers/system-client-followup-guarded-sequence.py'
CANDIDATE='/opt/bashos-parity/candidate'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or Path.cwd()!=CASE:
        raise SystemExit(125)


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'mlock-followup-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def trace(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


CONTROL=r'''import ctypes,errno,os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or not Path.cwd().is_relative_to(Path('/tmp/parity-case')):raise SystemExit(125)
def locked():
 return int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('VmLck:')))
c=ctypes.CDLL(None,use_errno=True);before=locked();mode=sys.argv[1]
if mode=='all':rc=c.mlockall(3);expected=errno.ENOMEM
else:rc=c.munlockall();expected=errno.EIO if mode=='unlock-fail' else 0
err=ctypes.get_errno();after=locked()
assert before==after==0 and ((rc==-1 and err==expected) if expected else rc==0)
print('control=%s errno=%d lck=%d:%d'%(mode,err if rc else 0,before,after))
'''


SHELL=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case* ]] || exit 125
snapshot() { local key value unit; while read -r key value unit; do case $key in VmLck:|VmRSS:) printf '%s-%s=%s\n' "$1" "${key%:}" "$value";; esac; done < /proc/self/status; }
snapshot before
if [[ $1 == preflight ]]; then
 read -r total resident rest < /proc/self/statm
 printf 'statm-total=%s resident=%s\n' "$total" "$resident"
else
 mlock "$1"; rc=$?
 printf 'status=%s\n' "$rc"
 snapshot after
fi
'''


def run(argv,*,soft=None,timeout=15):
    def limits():
        if soft is not None:
            _,hard=resource.getrlimit(resource.RLIMIT_MEMLOCK)
            resource.setrlimit(resource.RLIMIT_MEMLOCK,(hard if soft=='hard' else soft,hard))
    p=subprocess.Popen(list(map(str,argv)),cwd=CASE,env=dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       start_new_session=True,preexec_fn=limits)
    try:out,err=p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError('owned process timed out')
    return p.returncode,out,err


def inject(name,error,path,cmd):
    return ['/usr/bin/python3',SEQUENCE,'--notify',name,'--reply',name+'='+error,'--log-args',name+'=0','--log',str(path),'--',*cmd]


def setup(scenario):
    base=CASE/'mlock-followup-control';base.mkdir(mode=0o700);control=base/'control.py';control.write_text(CONTROL)
    for mode,name,error in [('all','mlockall','ENOMEM'),('unlock-fail','munlockall','EIO')]:
        path=HOME/('mlock-followup-control-'+mode+'.jsonl')
        rc,out,err=run(inject(name,error,path,['/usr/bin/python3',str(control),mode]))
        rows=trace(path);assert rc==0 and out==('control=%s errno=%d lck=0:0\n'%(mode,12 if mode=='all' else 5)).encode() and not err
        assert len(rows)==1 and rows[0]['syscall']==name and rows[0]['reply']=='errno:%d'%(12 if mode=='all' else 5)
        if mode=='all':assert rows[0]['arg0']==3
    rc,out,err=run(['/usr/bin/python3',str(control),'unlock-real'])
    assert rc==0 and out==b'control=unlock-real errno=0 lck=0:0\n' and not err
    if scenario=='all-enomem':
        hard=resource.getrlimit(resource.RLIMIT_MEMLOCK)[1]
        rc,out,err=run([CANDIDATE,'--noprofile','--norc','-c',SHELL,'preflight','preflight'],soft='hard')
        m=re.search(rb'statm-total=(\d+) resident=(\d+)',out)
        assert rc==0 and not err and m
        pages=int(m.group(2)) or int(m.group(1)) or 1
        needed=pages*os.sysconf('SC_PAGESIZE')+2*1024*1024
        record('memory-preflight',hard_bytes=hard,observed_resident_pages=pages,needed_hard_bytes=needed,raw_base64=b64(out))
        if hard!=resource.RLIM_INFINITY and hard<needed:
            raise RuntimeError('guest RLIMIT_MEMLOCK hard limit needs at least %d bytes'%needed)
    record('setup',scenario=scenario,control='real-unlock and exact errno injections verified')
    print('controls=verified')


def parsed(out):
    d={}
    for line in out.decode().splitlines():
        if '=' in line:
            k,v=line.split('=',1);d[k]=v
    return d


def scenario(shell,mode):
    if mode=='all-low':args=[shell,'--noprofile','--norc','-c',SHELL,'fixture','all'];rc,out,err=run(args,soft=0);rows=[]
    elif mode=='all-enomem':
        path=HOME/'mlock-followup-trace-enomem.jsonl';args=[shell,'--noprofile','--norc','-c',SHELL,'fixture','all']
        rc,out,err=run(inject('mlockall','ENOMEM',path,args),soft='hard');rows=trace(path)
    elif mode=='unlock-ok':args=[shell,'--noprofile','--norc','-c',SHELL,'fixture','unlock'];rc,out,err=run(args);rows=[]
    elif mode=='unlock-eio':
        path=HOME/'mlock-followup-trace-unlock.jsonl';args=[shell,'--noprofile','--norc','-c',SHELL,'fixture','unlock']
        rc,out,err=run(inject('munlockall','EIO',path,args));rows=trace(path)
    else:raise ValueError('unknown mode')
    d=parsed(out);clean=(rc==0 and d.get('before-VmLck')==d.get('after-VmLck')=='0' and int(d.get('before-VmRSS','0'))>0)
    hard=resource.getrlimit(resource.RLIMIT_MEMLOCK)[1];h='unlimited' if hard==resource.RLIM_INFINITY else str(hard)
    if mode=='all-low':
        m=re.search(rb'rlimit: needed=(\d+) soft=0 hard=(\d+|unlimited) - set ulimit -l before continuing',err)
        passed=clean and d.get('status')=='1' and m is not None and int(m.group(1))>0 and m.group(2).decode()==h
    elif mode=='all-enomem':passed=(clean and d.get('status')=='1' and b'mlockall: Cannot allocate memory' in err and
        (b'current RLIMIT_MEMLOCK: unlimited' if h=='unlimited' else ('current RLIMIT_MEMLOCK: soft=%s hard=%s'%(h,h)).encode()) in err and len(rows)==1 and rows[0]['syscall']=='mlockall' and rows[0]['arg0']==3 and rows[0]['reply']=='errno:12')
    elif mode=='unlock-ok':passed=clean and d.get('status')=='0' and not err
    else:passed=clean and d.get('status')=='1' and b'munlockall: Input/output error' in err and len(rows)==1 and rows[0]['reply']=='errno:5'
    record('result',mode=mode,status=rc,stdout_base64=b64(out),stderr_base64=b64(err),trace=rows,hard_bytes=hard,valid=passed)
    print('mlock-%s=%s'%(mode,yes(passed)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':setup(sys.argv[2])
        else:
            shell,mode=sys.argv[1:];scenario(shell,mode)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
