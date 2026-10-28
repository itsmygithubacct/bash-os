#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM modprobe policy and owned-directive observations."""
import base64
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home');SEQUENCE='/opt/bashos-parity/harness/helpers/system-client-followup-guarded-sequence.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or
        not Path.cwd().is_relative_to(CASE) or platform.machine()!='x86_64'):raise SystemExit(125)


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**v):
    v['kind']=kind
    with (HOME/'kmod-followup-observations.jsonl').open('a') as f:f.write(json.dumps(v,sort_keys=True)+'\n')


def trace(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


CONTROL=r'''import ctypes,errno,os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or not Path.cwd().is_relative_to(Path('/tmp/parity-case')):raise SystemExit(125)
lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long
for nr,args in [(175,(0,0,0)),(313,(-1,ctypes.c_char_p(b''),0)),(176,(ctypes.c_char_p(b'fixture_missing_module'),0))]:
 ctypes.set_errno(0);rc=lib.syscall(nr,*args);assert rc==-1 and ctypes.get_errno()==errno.EPERM
print('module-controls=ok')
'''


EFFECT=r'''import json,os,sys,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or not Path.cwd().is_relative_to(Path('/tmp/parity-case')):raise SystemExit(125)
log=Path(os.environ['KMOD_EFFECT_LOG']).resolve();assert log.is_relative_to(Path('/tmp/parity-home'))
with log.open('a') as f:f.write(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'argv':sys.argv[1:]},sort_keys=True)+'\n')
sys.exit(int(sys.argv[2]))
'''


SCRIPT=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case* ]] || exit 125
bashkmod "$@"; rc=$?
printf 'result=%d\n' "$rc"
'''


def run(argv,env=None,timeout=18):
    p=subprocess.Popen(list(map(str,argv)),cwd=CASE,env=env or dict(os.environ),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=3);raise RuntimeError('owned command timed out')
    return p.returncode,out,err


def guarded(argv,log):
    rules=[]
    for syscall in ('init_module','finit_module','delete_module'):rules+=['--notify',syscall,'--reply',syscall+'=EPERM']
    return ['/usr/bin/python3',SEQUENCE,*rules,'--log',str(log),'--',*argv]


def fixture():
    base=CASE/'kmod-followup';base.mkdir(mode=0o700,exist_ok=True);mods=base/'modules';mods.mkdir(exist_ok=True);conf=base/'conf';conf.mkdir(exist_ok=True)
    effect=base/'effect.py';effect.write_text(EFFECT)
    dep='kernel/chain.ko: kernel/dep_a.ko kernel/dep_b.ko\nkernel/dep_a.ko:\nkernel/dep_b.ko:\n'
    (mods/'modules.dep').write_text(dep);(mods/'modules.alias').write_text('alias device:from-db blocked\n');(mods/'modules.builtin').write_text('kernel/report.ko\n')
    lines=[f'blacklist report',f'install report /usr/bin/python3 {effect} report 0',f'remove report /usr/bin/python3 {effect} remove_report 0',
           'softdep report pre: pre_a post: post_a','options report alpha=1','options report beta=two','alias report alias_target',
           f'install main /usr/bin/python3 {effect} main 0',f'remove main /usr/bin/python3 {effect} remove 0',
           'softdep main pre: pre_a pre_b post: post_a',f'install pre_a /usr/bin/python3 {effect} pre_a 0',
           f'install pre_b /usr/bin/python3 {effect} pre_b 0',f'install post_a /usr/bin/python3 {effect} post_a 0',
           'options chain option=one','blacklist blocked','alias device:sample blocked',f'install blocked /usr/bin/python3 {effect} blocked 0',
           f'install badexit /usr/bin/python3 {effect} badexit 7',f'install unsafe /usr/bin/python3 {effect} unsafe 0; /usr/bin/false',
           'softdep cycle_a pre: cycle_b','softdep cycle_b pre: cycle_a',f'install cycle_a /usr/bin/python3 {effect} cycle_a 0',
           f'install cycle_b /usr/bin/python3 {effect} cycle_b 0']
    for i in range(10):
        lines.append(f'install depth{i} /usr/bin/python3 {effect} depth{i} 0')
        if i<9:lines.append(f'softdep depth{i} pre: depth{i+1}')
    (conf/'fixture.conf').write_text('\n'.join(lines)+'\n')
    return base,mods,conf,effect


def invoke(shell,label,args,mods,conf,extra_env=None):
    ev=HOME/('kmod-followup-effects-'+label+'.jsonl');log=HOME/('kmod-followup-trace-'+label+'.jsonl')
    env=dict(os.environ,BASHKMOD_MODULES_DIR=str(mods),BASHKMOD_MODPROBE_DIR=str(conf),KMOD_EFFECT_LOG=str(ev));env.pop('BASHKMOD_MODPROBE_DIRS',None)
    if extra_env:env.update(extra_env)
    rc,out,err=run(guarded([shell,'--noprofile','--norc','-c',SCRIPT,'case',*args],log),env)
    result={'rc':rc,'stdout':out,'stderr':err,'calls':trace(log),'effects':trace(ev)}
    record('run',label=label,args=args,status=rc,stdout_base64=b64(out),stderr_base64=b64(err),module_calls=result['calls'],effects=result['effects'])
    return result


def setup(which):
    base,mods,conf,effect=fixture();control=base/'control.py';control.write_text(CONTROL)
    log=HOME/'kmod-followup-trace-control.jsonl';rc,out,err=run(guarded(['/usr/bin/python3',control],log))
    calls=trace(log);assert rc==0 and out==b'module-controls=ok\n' and not err
    assert [(x['syscall'],x['reply']) for x in calls]==[('init_module','errno:1'),('finit_module','errno:1'),('delete_module','errno:1')]
    ev=HOME/'kmod-followup-effect-control.jsonl';env=dict(os.environ,KMOD_EFFECT_LOG=str(ev))
    first=run(['/usr/bin/python3',effect,'control', '0'],env);second=run(['/usr/bin/python3',effect,'failure','7'],env)
    effects=trace(ev);assert first[0]==0 and second[0]==7 and len(effects)==2 and effects[0]['argv']==['control','0'] and effects[1]['argv']==['failure','7']
    if which=='reference':prepare_reference(base)
    record('controls',scenario=which,module_syscalls='denied and logged',owned_effects=effects)
    print('controls=verified')


def policy_case(shell):
    base,mods,conf,effect=fixture();r=invoke(shell,'policy',['policy','report'],mods,conf)
    wanted=('builtin=yes\nblacklist=yes\ninstall=/usr/bin/python3 %s report 0\nremove=/usr/bin/python3 %s remove_report 0\nsoftdep=pre: pre_a post: post_a\noptions=alpha=1 beta=two\nalias-target=alias_target\nresult=0\n'%(effect,effect)).encode()
    policy=r['rc']==0 and r['stdout']==wanted and not r['stderr'] and not r['calls'] and not r['effects']
    plan=invoke(shell,'plan',['modprobe','-n','main'],mods,conf)
    expected=''.join('install /usr/bin/python3 %s %s 0\n'%(effect,x) for x in ('pre_a','pre_b','main','post_a'))+'result=0\n'
    soft=plan['rc']==0 and plan['stdout']==expected.encode() and not plan['stderr'] and not plan['calls'] and not plan['effects']
    chain=invoke(shell,'chain',['modprobe','-n','chain','extra=two'],mods,conf)
    expected=''.join('insmod %s/kernel/%s.ko%s\n'%(mods,x,' option=one extra=two' if x=='chain' else '') for x in ('dep_b','dep_a','chain'))+'result=0\n'
    chain_ok=chain['rc']==0 and chain['stdout']==expected.encode() and not chain['stderr'] and not chain['calls']
    reverse=invoke(shell,'reverse',['modprobe','-n','-r','chain'],mods,conf)
    reverse_ok=reverse['rc']==0 and reverse['stdout']==b'rmmod chain\nrmmod dep_a\nrmmod dep_b\nresult=0\n' and not reverse['stderr'] and not reverse['calls']
    remove=invoke(shell,'remove-plan',['modprobe','-n','-r','main'],mods,conf)
    remove_ok=remove['rc']==0 and remove['stdout']==('remove /usr/bin/python3 %s remove 0\nresult=0\n'%effect).encode() and not remove['stderr'] and not remove['calls']
    alias=invoke(shell,'alias',['modprobe','-n','device:sample'],mods,conf)
    direct=invoke(shell,'direct',['modprobe','-n','blocked'],mods,conf)
    black=alias['rc']==0 and alias['stdout']==b'result=1\n' and b'blacklisted' in alias['stderr'] and not alias['calls'] and not alias['effects'] and direct['rc']==0 and direct['stdout']==('install /usr/bin/python3 %s blocked 0\nresult=0\n'%effect).encode()
    cycle=invoke(shell,'cycle',['modprobe','-n','cycle_a'],mods,conf);deep=invoke(shell,'depth',['modprobe','-n','depth0'],mods,conf)
    graph=cycle['rc']==deep['rc']==0 and cycle['stdout']==deep['stdout']==b'result=2\n' and b'cycle detected' in cycle['stderr'] and b'recursion too deep' in deep['stderr'] and not cycle['calls'] and not deep['calls']
    record('policy-outcome',policy=policy,softdep=soft,chain=chain_ok,reverse=reverse_ok,remove=remove_ok,blacklist=black,cycles=graph)
    print('kmod-policy projection=%s softdep=%s chain=%s reverse=%s remove=%s blacklist=%s graph=%s' % tuple(yes(x) for x in (policy,soft,chain_ok,reverse_ok,remove_ok,black,graph)))


def effects_case(shell):
    base,mods,conf,effect=fixture();install=invoke(shell,'install',['modprobe','main'],mods,conf)
    labels=[x['argv'] for x in install['effects']]
    installed=install['rc']==0 and install['stdout']==b'result=0\n' and not install['stderr'] and not install['calls'] and labels==[[x,'0'] for x in ('pre_a','pre_b','main','post_a')] and all(x['uid']==2000 for x in install['effects'])
    remove=invoke(shell,'remove',['modprobe','-r','main'],mods,conf)
    removed=remove['rc']==0 and remove['stdout']==b'result=0\n' and not remove['stderr'] and not remove['calls'] and [x['argv'] for x in remove['effects']]==[['remove','0']]
    failure=invoke(shell,'badexit',['modprobe','badexit'],mods,conf)
    propagated=failure['rc']==0 and failure['stdout']==b'result=7\n' and bool(failure['stderr']) and not failure['calls'] and [x['argv'] for x in failure['effects']]==[['badexit','7']]
    unsafe=invoke(shell,'unsafe',['modprobe','unsafe'],mods,conf)
    meta=unsafe['rc']==0 and unsafe['stdout']==b'result=2\n' and b'metacharacters' in unsafe['stderr'] and not unsafe['effects'] and not unsafe['calls']
    alias=invoke(shell,'live-alias',['modprobe','device:sample'],mods,conf);direct=invoke(shell,'live-direct',['modprobe','blocked'],mods,conf)
    black=alias['rc']==0 and alias['stdout']==b'result=1\n' and not alias['effects'] and not alias['calls'] and direct['rc']==0 and direct['stdout']==b'result=0\n' and [x['argv'] for x in direct['effects']]==[['blocked','0']] and not direct['calls']
    record('effects-outcome',installed=installed,removed=removed,exit_propagated=propagated,metachar_rejected=meta,blacklist=black)
    print('kmod-effects install=%s remove=%s exit=%s metachar=%s blacklist=%s' % tuple(yes(x) for x in (installed,removed,propagated,meta,black)))


def prepare_reference(base):
    source=Path('/lib/modules')/os.uname().release;dep=source/'modules.dep'
    if not dep.is_file():raise RuntimeError('guest modules.dep needed for kmod reference')
    candidates=[]
    for row in dep.read_text().splitlines():
        left,sep,right=row.partition(':')
        if not sep or right.strip():continue
        p=source/left
        if p.is_file() and p.resolve().is_relative_to(source.resolve()) and any(left.endswith(x) for x in ('.ko','.ko.xz','.ko.gz','.ko.zst')):
            candidates.append((left,p))
    if not candidates:raise RuntimeError('guest needs one readable dependency-free module for reference')
    relative,real=sorted(candidates)[0];destbase=base/'reference';version='1.0-fixture';tree=destbase/'lib/modules'/version
    target=tree/relative;target.parent.mkdir(parents=True);shutil.copyfile(real,target)
    (tree/'modules.order').write_text(relative+'\n');(tree/'modules.builtin').write_text('')
    rc,out,err=run(['/usr/sbin/depmod','-b',destbase,version])
    if rc:raise RuntimeError('private depmod failed '+repr(err[:300]))
    name=Path(relative).name.split('.ko',1)[0];conf=base/'reference.conf';conf.write_text('')
    (base/'reference.json').write_text(json.dumps({'base':str(destbase),'version':version,'tree':str(tree),'relative':relative,'name':name,'config':str(conf)}))
    record('reference-setup',source=str(real),relative=relative,name=name,depmod_stdout_base64=b64(out),depmod_stderr_base64=b64(err))


def reference_case(shell):
    base,_,_,_=fixture();data=json.loads((base/'reference.json').read_text());mods=Path(data['tree']);conf=Path(data['config'])
    ref_log=HOME/'kmod-followup-trace-reference.jsonl'
    argv=['/usr/sbin/modprobe','-d',data['base'],'-S',data['version'],'-C',str(conf),'--show-depends',data['name'],'fixture_opt=1']
    rc,out,err=run(guarded(argv,ref_log));candidate=invoke(shell,'reference-candidate',['modprobe','-n',data['name'],'fixture_opt=1'],mods,base/'conf-empty')
    expected=('insmod %s/%s fixture_opt=1\n'%(mods,data['relative'])).encode()
    good=rc==0 and out==expected and candidate['rc']==0 and candidate['stdout']==expected+b'result=0\n' and not candidate['stderr'] and not candidate['calls'] and not trace(ref_log)
    record('reference-result',argv=argv,status=rc,stdout_base64=b64(out),stderr_base64=b64(err),expected_base64=b64(expected),valid=good)
    print('kmod-reference plan=%s'%yes(good))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==3 and sys.argv[1]=='setup':setup(sys.argv[2])
        else:
            shell,mode=sys.argv[1:];{'policy':policy_case,'effects':effects_case,'reference':reference_case}[mode](shell)
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
