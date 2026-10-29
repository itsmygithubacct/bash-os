#!/usr/bin/python3
"""Guest-only child limit and held-lock lifecycle observer; no host execution."""
import json
import os
from pathlib import Path
import resource
import re
import select
import subprocess
import sys
import time
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home'); LIMIT=64*1024*1024
REPORT=HOME/'mlock-observer.json'


def save(record):
    tmp=HOME/'mlock-observer.tmp'
    tmp.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    os.replace(tmp,REPORT)


def snapshot(pid):
    p=Path('/proc')/str(pid)
    return {'status':(p/'status').read_text(),'stat':(p/'stat').read_text(),
            'limits':(p/'limits').read_text()}


def birth(s):return s['stat'].rsplit(')',1)[1].split()[19]


def lck(s):
    for line in s['status'].splitlines():
        if line.startswith('VmLck:'):return int(line.split()[1])
    return None


def wait_file(path,child,seconds):
    end=time.monotonic()+seconds
    while not path.is_file():
        if child.poll() is not None:return False
        if time.monotonic()>end:raise RuntimeError('deadline waiting for '+path.name)
        time.sleep(.02)
    return True


def main():
    if len(sys.argv)!=3 or sys.argv[2] not in ('future-unlock','exit-held'):
        raise RuntimeError('invalid mode')
    if os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME):raise RuntimeError('unexpected guest identity')
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise RuntimeError('not QEMU')
    guest=str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    parent_soft,parent_hard=resource.getrlimit(resource.RLIMIT_MEMLOCK)
    report={'mode':sys.argv[2],'vm_uuid':guest,'requested_soft_bytes':LIMIT,'observer_effective_before':{'soft':parent_soft,'hard':parent_hard}}
    save(report)
    if parent_hard!=resource.RLIM_INFINITY and parent_hard<LIMIT:raise RuntimeError('effective observer hard limit below 64 MiB')
    def set_child_limit():resource.setrlimit(resource.RLIMIT_MEMLOCK,(LIMIT,parent_hard))
    child=subprocess.Popen([sys.argv[1],'--noprofile','--norc',str(CASE/('mlock-'+sys.argv[2]+'.sh'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=set_child_limit,start_new_session=True)
    pidfd=None
    try:
        report['candidate_pid']=child.pid;save(report)
        if not wait_file(HOME/'candidate-preflight-ready',child,8):raise RuntimeError('child exited before limit observation')
        pidfd=os.pidfd_open(child.pid,0)
        report['preflight']=snapshot(child.pid);report['preflight_ns']=time.monotonic_ns();report['preflight_exe']=os.readlink('/proc/%d/exe'%child.pid)
        soft,hard=resource.prlimit(child.pid,resource.RLIMIT_MEMLOCK)
        report['candidate_effective_before']={'soft':soft,'hard':hard}
        report['child_reported_pid']=(HOME/'candidate-pid').read_text().strip()
        report['child_reported_limits']=(HOME/'candidate-limits').read_text()
        match=re.search(r'^Max locked memory\s+(\S+)\s+(\S+)\s+bytes\s*$',report['child_reported_limits'],re.M)
        if match:
            decode=lambda x: resource.RLIM_INFINITY if x=='unlimited' else int(x)
            report['candidate_self_effective']={'soft':decode(match.group(1)),'hard':decode(match.group(2))}
        save(report)
        if report['child_reported_pid']!=str(child.pid) or soft!=LIMIT or hard!=parent_hard or report.get('candidate_self_effective')!=report['candidate_effective_before']:
            raise RuntimeError('effective child limit or identity mismatch')
        child.stdin.write(b'go\n');child.stdin.flush()
        if sys.argv[2]=='exit-held':
            if not wait_file(HOME/'candidate-held-ready',child,12):
                out,err=child.communicate(timeout=3)
                report['early_candidate']={'status':child.returncode,'stdout_hex':out.hex(),'stderr_hex':err.hex()};save(report)
                print('held_exit=unreached')
                return 1
            held=snapshot(child.pid);report['held_before_release']=held
            report['held_effective']={'soft':resource.prlimit(child.pid,resource.RLIMIT_MEMLOCK)[0], 'hard':resource.prlimit(child.pid,resource.RLIMIT_MEMLOCK)[1]}
            poller=select.poll();poller.register(pidfd,select.POLLIN)
            report['held_lck_kb']=lck(held);report['held_ns']=time.monotonic_ns();report['pidfd_ready_before_exit']=bool(poller.poll(0))
            save(report)
            if birth(held)!=birth(report['preflight']) or not report['held_lck_kb'] or report['pidfd_ready_before_exit'] or report['held_effective']!=report['candidate_effective_before']:
                raise RuntimeError('held process identity, lock or limit not established')
            report['exit_release_ns']=time.monotonic_ns();save(report)
            child.stdin.write(b'exit\n');child.stdin.flush()
            deadline=time.monotonic()+8
            while True:
                event=os.waitid(os.P_PIDFD,pidfd,os.WEXITED|os.WNOWAIT|os.WNOHANG)
                if event is not None:break
                if time.monotonic()>deadline:raise RuntimeError('pidfd exit wait deadline')
                time.sleep(.02)
            report['waitid']={'si_pid':event.si_pid,'si_code':event.si_code,'si_status':event.si_status}
            zombie=snapshot(child.pid);report['zombie_before_reap']=zombie;report['zombie_lck_kb']=lck(zombie);report['zombie_ns']=time.monotonic_ns();save(report)
            if birth(zombie)!=birth(held) or zombie['stat'].rsplit(')',1)[1].split()[0]!='Z' or event.si_pid!=child.pid or report['zombie_lck_kb'] not in (None,0):raise RuntimeError('pidfd exit identity or zombie lock observation mismatch')
        out,err=child.communicate(timeout=8)
        report['candidate_exit']={'status':child.returncode,'stdout_hex':out.hex(),'stderr_hex':err.hex()}
        report['proc_gone_after_reap']=not Path('/proc/%d'%child.pid).exists();save(report)
        if child.returncode!=0 or not report['proc_gone_after_reap']:
            print('candidate_result=failed');return 1
        print('future_unlock=observed' if sys.argv[2]=='future-unlock' else 'held_exit=observed')
        return 0
    finally:
        if child.poll() is None:
            try:os.killpg(child.pid,9)
            except ProcessLookupError:pass
            child.communicate(timeout=3)
        if pidfd is not None:os.close(pidfd)


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        print('CONTROL-INCOMPLETE: '+repr(exc),file=sys.stderr);sys.exit(125)
