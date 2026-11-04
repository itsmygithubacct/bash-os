#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Initial-PID-namespace scaffold; coordinator-owned disposable guest only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode=True
CONTRACT_SHA='2fa29bf9cabdf1d3044d3b619d2f6365de1b62e586313143d800333e40272a06'
TRANSPORT_SHA='f7401859083b9c48552cc44dfb11fdde8b5bc10d08afb8ee386b75310540124e'


def load(name,pin):
    path=Path(__file__).with_name(name+'.py');st=path.lstat();data=path.read_bytes()
    if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_gid or st.st_mode&0o022 or hashlib.sha256(data).hexdigest()!=pin:
        raise RuntimeError('unprotected/pin-mismatched launcher input')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;exec(compile(data,str(path),'exec'),module.__dict__);return module


c=load('executor_observer_contract_r2',CONTRACT_SHA)
t=load('executor_observer_transport_r2',TRANSPORT_SHA)


def command(argv,timeout=10):
    # All commands/units are fixed by this script, never supplied by a fixture.
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
    c.require(len(result.stdout)+len(result.stderr)<=65536,'scaffold command output bound')
    return result


def wait_owned_cgroup_empty(fd,path,pidfd,identity,parent_fd,parent_identity):
    deadline=time.monotonic()+2;history=[]
    while True:
        state=t.cgroup_empty(fd,path,pidfd,identity,parent_fd,parent_identity)
        history.append({key:state[key] for key in ('empty','removed','path_present','broker_reaped',
                       'missing_control_files','fd_nlink_observed','fd_link','parent_link',
                       'relative_lookup_first','relative_lookup_second','absolute_path_present',
                       'observer_mnt_ns','observation')})
        c.require(len(history)<=41,'owned cgroup observation count exceeded')
        if state['empty']:return state,history
        c.require(time.monotonic()<deadline,'owned cgroup did not become empty before deadline')
        time.sleep(.05)


def main():
    parser=argparse.ArgumentParser()
    for name in ('vm-token','python-sha256','pins-sha256','candidate-sha256','outer-namespaces'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args();c.token(args.vm_token)
    for pin in (args.python_sha256,args.pins_sha256,args.candidate_sha256):
        c.require(re.fullmatch('[0-9a-f]{64}',pin) is not None,'explicit SHA256 pin required')
    pins=c.decode(t.protected(c.HARNESS+'/executor-observer-pins-r2.json',args.pins_sha256))
    c.require(pins['schema']=='ancestor-observer-source-pins-r1','wrong source pin schema')
    for path,pin in pins['files'].items():t.protected(path,pin)
    c.require(args.candidate_sha256 in pins['candidates'].values() and
              t.digest(c.ROOT+'/candidate')==args.candidate_sha256,'registered candidate image differs')
    initial={n:t.namespace('self',n) for n in ('pid','mnt','net','user')}
    c.require(all(t.namespace(1,n)==initial[n] for n in initial) and t.task(os.getpid())['nspid']==[os.getpid()] and
              t.task(1)['argv'][0] in ('/sbin/init','/lib/systemd/systemd','/usr/lib/systemd/systemd'),
              'launcher requires actual guest initial namespaces/procfs')
    c.require(t.task(os.getpid())['cgroup']==c.EVAL_CGROUP,'launcher must run in the existing evaluation unit')
    outer=c.decode(args.outer_namespaces)
    c.require(outer=={n:initial[n]['link'] for n in ('pid','net','mnt')},'controller outer namespace registration differs')
    parentfd=os.open(t.CGROUP_PARENT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    parentst=os.fstat(parentfd)
    c.require(t.fs_type(parentfd)==c.CGROUP2 and stat.S_ISDIR(parentst.st_mode) and
              os.readlink('/proc/self/fd/'+str(parentfd))==t.CGROUP_PARENT and
              not os.get_inheritable(parentfd),'trusted initial cgroup parent differs')
    parent_identity={'dev':parentst.st_dev,'ino':parentst.st_ino}
    evaluator=['/usr/bin/python3',c.HARNESS+'/guest.py','--vm-token',args.vm_token,
               '--outer-namespaces',json.dumps(outer,sort_keys=True),'--groups','shell',
               '--case-ids','qualification-014-takeover-executor-r1','--allow-root-fixtures']
    reg={'schema':'ancestor-observer-inputs-r1','token':args.vm_token,'python_sha256':args.python_sha256,
         'kernel_release':pins['kernel_release'],
         'candidate_sha256':args.candidate_sha256,'files':pins['files'],'initial':initial,'evaluator_argv':evaluator,
         'target_sha256':pins['target_sha256'],'executors':pins['executors'],'source_pins_sha256':args.pins_sha256,
         'cgroup_parent':parent_identity}
    t.guest(reg)
    directory=Path(c.directory(args.vm_token));directory.mkdir(mode=0o700)
    t.write(directory/'registry.json',reg);os.chmod(directory/'registry.json',0o444)
    regpin=t.sha(t.raw(directory/'registry.json',8192,True))
    record={'schema':'ancestor-observer-controller-r1','status':'ERROR','vm_uuid':args.vm_token,
            'registry_sha256':regpin,'registry':reg,'source_pins_sha256':args.pins_sha256,
            'coordinator_owned_disposable_guest':True,'broker_unit':c.unit(args.vm_token),
            'evaluator_argv':evaluator,'evaluator_guard_changed':False,'fallback_cleanup':False,
            'cgroup_parent':parent_identity,'cgroup_parent_link':t.CGROUP_PARENT}
    owned=False;cgfd=None;cgidentity=None;cgpath='/sys/fs/cgroup'+c.cgroup(args.vm_token)
    brokerpidfd=None;process=None;result=125
    try:
        # Never stop an unrelated pre-existing unit, even after a start error.
        prior=command(['/usr/bin/systemctl','show',c.unit(args.vm_token),'-p','LoadState'])
        c.require(prior.stdout.decode().strip()=='LoadState=not-found' and
                  not Path('/sys/fs/cgroup'+c.cgroup(args.vm_token)).exists(),'broker unit already exists')
        try:os.stat(c.unit(args.vm_token),dir_fd=parentfd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise RuntimeError('owned broker cgroup already exists under pinned parent')
        owned=True
        start=command(['/usr/bin/systemd-run','--quiet','--collect','--unit='+c.unit(args.vm_token),
                       '-p','MemoryMax=192M','-p','MemorySwapMax=0','-p','TasksMax=8','-p','RuntimeMaxSec=850',
                       '-p','LimitCORE=0','-p','LimitNOFILE=128',
                       '-p','TimeoutStopSec=5','-p','KillMode=control-group','-p','RemainAfterExit=yes',
                       '/usr/bin/python3','-B',c.HARNESS+'/executor_observer_broker_r2.py',
                       '--vm-token',args.vm_token,'--registry-sha256',regpin])
        c.require(start.returncode==0,'broker systemd start failed: '+start.stderr.decode(errors='replace'))
        deadline=time.monotonic()+10
        while not (directory/'ready.json').exists():
            c.require(time.monotonic()<deadline,'broker startup deadline exceeded');time.sleep(.05)
        ready=c.decode(t.raw(directory/'ready.json',8192,True))
        c.require(ready['registry_sha256']==regpin and ready['initial']==initial and ready['cgroup']==c.cgroup(args.vm_token),
                  'broker readiness differs')
        brokerpidfd=os.pidfd_open(ready['pid'])
        broker=t.task(ready['pid'])
        c.require(t.live(brokerpidfd) and broker['exe_sha256']==args.python_sha256 and
                  broker['cgroup']==c.cgroup(args.vm_token) and
                  broker['argv']==['/usr/bin/python3','-B',c.HARNESS+'/executor_observer_broker_r2.py',
                                   '--vm-token',args.vm_token,'--registry-sha256',regpin] and
                  all(t.namespace(ready['pid'],n)==initial[n] for n in initial), 'broker identity differs')
        cgfd=os.open(c.unit(args.vm_token),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,
                     dir_fd=parentfd)
        cgst=os.fstat(cgfd);cgidentity=(cgst.st_dev,cgst.st_ino)
        c.require(t.fs_type(cgfd)==c.CGROUP2 and os.readlink('/proc/self/fd/'+str(cgfd))==cgpath,
                  'owned broker cgroup FD identity differs')
        verified_parent=t.cgroup_parent(cgfd,cgpath,parent_identity);os.close(verified_parent)
        record['cgroup_initial_relative_identity']={'dev':cgst.st_dev,'ino':cgst.st_ino}
        # The evaluator argv and original PID1 guard are unchanged. Only the
        # independent observer is placed outside this PID namespace.
        process=subprocess.Popen(['/usr/bin/unshare','--mount','--pid','--fork','--net','--mount-proc','--kill-child',*evaluator],
                                 stdin=subprocess.DEVNULL,close_fds=True)
        result=process.wait(timeout=750);record['evaluator_returncode']=result
        broker_receipt=json.loads(t.raw(directory/'broker.json',1024*1024,True))
        record['broker']=broker_receipt;record['broker_receipt_sha256']=t.sha(t.raw(directory/'broker.json',1024*1024,True))
        c.require(broker_receipt['registry_sha256']==regpin and broker_receipt['status']=='STOPPED' and
                  broker_receipt['cooperative_stop'] is True and broker_receipt['fixture_live_on_stop'] is True,
                  'broker was not stopped cooperatively before evaluator teardown')
        empty,history=wait_owned_cgroup_empty(cgfd,cgpath,brokerpidfd,cgidentity,parentfd,parent_identity)
        record['pre_stop_cgroup']=empty;record['pre_stop_cgroup_history']=history
        record['broker_reaped_at_evaluator_return']=t.pidfd_reaped(brokerpidfd)
        c.require(empty['empty'] and record['broker_reaped_at_evaluator_return'],
                  'broker not reaped/empty at evaluator return')
        state=command(['/usr/bin/systemctl','show',c.unit(args.vm_token),'-p','ActiveState','-p','SubState',
                       '-p','Result','-p','ExecMainCode','-p','ExecMainStatus'])
        record['unit_before_stop']=dict(line.split('=',1) for line in state.stdout.decode().splitlines())
        c.require(state.returncode==0 and record['unit_before_stop']=={
                  'ActiveState':'active','SubState':'exited','Result':'success','ExecMainCode':'1','ExecMainStatus':'0'},
                  'broker did not exit naturally with status zero')
        record['status']='CLEAN'  # Scaffold cleanup only, never a candidate verdict.
    except BaseException as error:
        record['error']=type(error).__name__+': '+str(error);record['fallback_cleanup']=True;result=125
    finally:
        # Cleanup failure never changes a retained case FAIL into PASS.
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGINT,signal.SIG_IGN)
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:record['evaluator_reap_error']=True
        if owned:
            try:
                stop=command(['/usr/bin/systemctl','stop',c.unit(args.vm_token)],12)
                record['unit_stop_returncode']=stop.returncode
                c.require(stop.returncode==0,'owned broker unit stop failed')
                if cgfd is not None:
                    state,history=wait_owned_cgroup_empty(cgfd,cgpath,brokerpidfd,cgidentity,parentfd,parent_identity)
                    record['post_stop_cgroup']=state;record['post_stop_cgroup_history']=history
                    c.require(record['post_stop_cgroup']['empty'],'broker cgroup nonempty after stop')
                else:
                    try:os.stat(c.unit(args.vm_token),dir_fd=parentfd,follow_symlinks=False)
                    except FileNotFoundError:pass
                    else:raise RuntimeError('unobserved broker cgroup remains under pinned parent')
                    c.require(not Path('/sys/fs/cgroup'+c.cgroup(args.vm_token)).exists(),'unobserved broker cgroup remains')
                check=command(['/usr/bin/systemctl','show',c.unit(args.vm_token),'-p','ActiveState','-p','SubState'])
                record['unit_after_stop']=check.stdout.decode(errors='replace')
                c.require('ActiveState=active' not in record['unit_after_stop'] and
                          'ActiveState=activating' not in record['unit_after_stop'],'broker unit still active')
                if brokerpidfd is not None:
                    record['broker_reaped_after_stop']=t.pidfd_reaped(brokerpidfd)
                    c.require(record['broker_reaped_after_stop'],'broker not reaped after unit stop')
            except BaseException as error:
                record['cleanup_error']=type(error).__name__+': '+str(error);record['status']='ERROR';result=125
        if cgfd is not None:os.close(cgfd)
        if brokerpidfd is not None:os.close(brokerpidfd)
        os.close(parentfd)
        if record.get('evaluator_reap_error'):record['status']='ERROR';result=125
        if 'broker' not in record and (directory/'broker.json').exists():
            record['broker']=json.loads(t.raw(directory/'broker.json',1024*1024,True))
        t.write(c.ROOT+'/ancestor-observer-control.json',record)
    return result


if __name__=='__main__':
    def interrupted(signum,frame):raise RuntimeError('launcher interrupted: '+str(signum))
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    raise SystemExit(main())
