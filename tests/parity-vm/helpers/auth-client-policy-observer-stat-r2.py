#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only sudo policy-list client with synthetic root metadata and private data."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import struct
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
MOCK='/opt/bashos-parity/harness/helpers/auth-client-policy-peer-bootstrap-r1.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'sudo-list-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def rows(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


CONTROL=r'''import errno,fcntl,hashlib,os,struct,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
policy=Path(sys.argv[1]);other=Path(sys.argv[2]);expected_uid=int(sys.argv[3])
a=os.stat(policy);assert a.st_uid==2000
fd=os.open(policy,os.O_RDONLY);b=os.fstat(fd)
assert (b.st_uid,b.st_ino,b.st_mode,b.st_gid,b.st_size,b.st_mtime_ns,b.st_ctime_ns)==(expected_uid,a.st_ino,a.st_mode,a.st_gid,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
f=os.open(other,os.O_RDONLY);assert os.fstat(f).st_uid==2000;os.close(f);os.close(fd)
d=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC);p=bytearray(512);struct.pack_into('<I',p,0,512)
fcntl.ioctl(d,0xc200ba0c,p,True)
assert struct.unpack_from('<II',p)==(512,0) and struct.unpack_from('<I',p,12)[0]==0
assert struct.unpack_from('<Q',p,24)[0]==a.st_ino and p[64:96]==hashlib.sha256(policy.read_bytes()).digest()
assert p[128:384].split(b'\0',1)[0]==os.fsencode(policy)
struct.pack_into('<I',p,0,511)
try:fcntl.ioctl(d,0xc200ba0c,p,True);raise AssertionError('bad size accepted')
except OSError as e:assert e.errno==errno.EINVAL
os.close(d);print('policy-control=ok')
'''


SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
sudo "$@"; result=$?
printf 'status=%d\n' "$result"
'''


def invoke(base,label,argv,policy,**options):
    trace=HOME/('sudo-list-trace-'+label+'.jsonl');cfg=base/(label+'.json')
    cfg.write_text(json.dumps({'policy':str(policy),'trace':str(trace),**options}))
    p=subprocess.run(['/usr/bin/python3',MOCK,str(cfg),*map(str,argv)],cwd=base,env=dict(os.environ),
                     stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=18)
    trace_events=rows(trace);record('run',label=label,status=p.returncode,stdout_base64=b64(p.stdout),stderr_base64=b64(p.stderr),trace_events=len(trace_events))
    return p.returncode,p.stdout,p.stderr,trace_events


def setup():
    assert not os.path.lexists('/dev/bashos-auth')
    base=CASE/'sudo-list-control';base.mkdir(mode=0o700);policy=base/'policy';policy.write_bytes(b'parity ALL = (root) /usr/bin/true\n');os.chmod(policy,0o600)
    other=base/'other';other.write_text('unrelated');control=base/'control.py';control.write_text(CONTROL)
    for label,spoof,uid in [('spoof',True,0),('real',False,2000)]:
        rc,out,err,trace=invoke(base,'control-'+label,['/usr/bin/python3',control,policy,other,str(uid)],policy,spoof_root=spoof)
        infos=[x for x in trace if x.get('request')=='0xc200ba0c']
        stats=[x for x in trace if x['syscall'] in ('fstat','newfstatat')]
        target=policy.stat()
        record('stat-control',label=label,target_dev=target.st_dev,target_inode=target.st_ino,target_mode=target.st_mode,
               target_uid=target.st_uid,target_gid=target.st_gid,events=stats)
        assert rc==0 and out==b'policy-control=ok\n' and not err and len(infos)==2 and infos[0]['reply']=='value:0' and infos[1]['reply']=='errno:22'
        if spoof:
            assert stats
            for event in stats:
                data=bytes.fromhex(event['output_hex'])
                dev,inode,nlink,mode,reported_uid,gid=struct.unpack_from('<QQQIII',data)
                assert event['actual_uid']==target.st_uid==2000 and event['actual_inode']==target.st_ino
                assert event['synthetic_uid']==reported_uid==0 and event['reply']=='value:0'
                assert (dev,inode,mode,gid,nlink)==(target.st_dev,target.st_ino,target.st_mode,target.st_gid,target.st_nlink)
        else:
            assert not stats
    record('control',real_owner=2000,synthetic_stat='scoped-to-one-inode',invalid_ioctl_size='rejected')
    print('controls=verified')


POLICY=b'parity ALL = (root) /usr/bin/true\nbob ALL = (root) /usr/bin/false\n'


def scenario(shell):
    base=CASE/'sudo-list';base.mkdir(mode=0o700)
    def run(label,contents,args,**opts):
        p=base/(label+'.policy');p.write_bytes(contents);os.chmod(p,0o600)
        return invoke(base,label,[shell,'--noprofile','--norc','-c',SCRIPT,'sudo-list',*args],p,**opts)
    short=run('short',POLICY,['-l'],spoof_root=True)
    long=run('long',POLICY,['-ll'],spoof_root=True)
    alias=run('alias',POLICY,['--list'],spoof_root=True)
    empty=run('empty',b'', ['-l'],spoof_root=True)
    none=run('nomatch',b'bob ALL = (root) /usr/bin/false\n',['-l'],spoof_root=True)
    bad=run('digest',POLICY,['-l'],spoof_root=True,bad_digest=True)
    changed=run('generation',POLICY,['-l'],spoof_root=True,change_generation=True)
    real=run('real-owner',POLICY,['-l'],spoof_root=False)
    unsafe=run('unsafe',POLICY,['-l'],spoof_root=True,unsafe_uid=True)
    marker=base/'command-must-not-run'
    command=run('command',POLICY,['-l','/usr/bin/touch',str(marker)],spoof_root=True)
    header=b'Policy projection for parity (generation 17; not an execution approval):\n'
    summary=lambda data,n:bool(re.search(rb'^summary entries='+str(n).encode()+rb' digest_sha256=[0-9a-f]{64}$',data,re.M))
    shortline=b'list user=parity host=ALL runas=root runas_group=- nopasswd=0 setenv=0 commands=/usr/bin/true\n'
    longline=b'entry user=parity host=ALL runas=root runas_group=- nopasswd=0 setenv=0 cmd=/usr/bin/true\n'
    projection=(short[0]==0 and long[0]==0 and alias[0]==0 and short[1].startswith(header) and long[1].startswith(header)
                and shortline in short[1] and longline in long[1] and short[1]==alias[1] and summary(short[1],1) and summary(long[1],1)
                and all(b'/usr/bin/false' not in x[1] and x[1].endswith(b'status=0\n') and not x[2] for x in (short,long,alias)))
    noentries=all(x[0]==0 and x[1].startswith(header) and summary(x[1],0) and x[1].endswith(b'status=1\n') and not x[2] for x in (empty,none))
    rejected=(bad[0]==changed[0]==real[0]==unsafe[0]==0 and all(x[1]==b'status=1\n' and x[2] for x in (bad,changed,real,unsafe)))
    info_order=all([x.get('transition',{}).get('generation') for x in runresult[3] if x.get('transition',{}).get('op')=='policy-info']==[17,17] for runresult in (short,long,alias,empty,none))
    changed_order=[x.get('transition',{}).get('generation') for x in changed[3] if x.get('transition',{}).get('op')=='policy-info']==[17,18]
    noauth=all(not any(x.get('request') in ('0xc340ba0b','0xc128ba0d') for x in result[3]) for result in (short,long,alias,empty,none,bad,changed,real,unsafe,command))
    noexec=command[0]==0 and command[1]==b'status=2\n' and bool(command[2]) and noauth and not marker.exists()
    record('outcome',projection=projection,noentries=noentries,rejections=rejected,stable_policy_info=info_order,changed_policy_info=changed_order,no_execution_approval=noexec)
    print('sudo-list projection=%s empty=%s binding=%s metadata=%s no-approval=%s' % (yes(projection),yes(noentries),yes(rejected and info_order and changed_order),yes(rejected),yes(noexec)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==2 and sys.argv[1]=='setup':setup()
        else:
            assert len(sys.argv)==2;scenario(sys.argv[1])
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
