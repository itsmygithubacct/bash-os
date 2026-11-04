#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed-operation observer broker. Run only by the reviewed guest launcher."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
import time
sys.dont_write_bytecode=True

CONTRACT_SHA='2fa29bf9cabdf1d3044d3b619d2f6365de1b62e586313143d800333e40272a06'
TRANSPORT_SHA='f7401859083b9c48552cc44dfb11fdde8b5bc10d08afb8ee386b75310540124e'


def load(name,pin,path=None):
    path=Path(path) if path else Path(__file__).with_name(name+'.py')
    st=path.lstat();raw=path.read_bytes()
    if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_gid or st.st_mode&0o022 or hashlib.sha256(raw).hexdigest()!=pin:
        raise RuntimeError('unprotected/pin-mismatched Python input')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;exec(compile(raw,str(path),'exec'),module.__dict__);return module


c=load('executor_observer_contract_r2',CONTRACT_SHA)
t=load('executor_observer_transport_r2',TRANSPORT_SHA)


def peer_directory(pid):
    fd=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for name in c.OUTPUT.strip('/').split('/'):
            nextfd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nextfd
        return fd
    except BaseException:os.close(fd);raise


def admission(pid,credentials,peerfd,fds,reg):
    configfd,outfd,mntfd,netfd=fds
    st=os.fstat(configfd)
    seals=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
    c.require(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and 0<st.st_size<=c.CONFIG_MAX and
              fcntl.fcntl(configfd,fcntl.F_GET_SEALS)&seals==seals,'immutable bounded memfd config required')
    raw=os.pread(configfd,c.CONFIG_MAX+1,0);c.require(len(raw)==st.st_size,'incomplete sealed config')
    config=c.decode(raw);peer=t.task(pid)
    peer.update(credentials=credentials,pidfd_live=t.live(peerfd),cwd=os.readlink('/proc/'+str(pid)+'/cwd'),
                script_sha256=t.sha(t.protected('/proc/'+str(pid)+'/root'+c.DRIVER,reg['files'][c.DRIVER])),
                user_ns=t.namespace(pid,'user'),ns={n:t.namespace(pid,n) for n in ('pid','net','mnt')},descriptors={})
    for name,fd,kind in (('mnt',mntfd,c.MNT),('net',netfd,c.NET)):
        c.require(t.fs_type(fd)==c.NSFS and fcntl.ioctl(fd,t.NS_GET_NSTYPE)==kind,'wrong namespace FD type')
        owner=fcntl.ioctl(fd,t.NS_GET_USERNS)
        try:peer['descriptors'][name]={'fs_type':t.fs_type(fd),'type':kind,'identity':t.ns_identity(fd,name),
                                     'owner_user_ns':t.ns_identity(owner,'user')}
        finally:os.close(owner)
    pidns=t.nsfd('/proc/'+str(pid)+'/ns/pid',c.PID)
    try:
        parent=fcntl.ioctl(pidns,t.NS_GET_PARENT)
        try:peer['pid_ns_parent']=t.ns_identity(parent,'pid')
        finally:os.close(parent)
    finally:os.close(pidns)
    peer['attestation']=c.decode(t.raw('/run/bashos-syslog-namespace-208.json',8192,True))
    peer['ancestor_pids']=[];ancestor=peer['ppid'];evaluator=None
    for _ in range(16):
        c.require(ancestor>1 and ancestor not in peer['ancestor_pids'],'missing/cyclic evaluator lineage')
        peer['ancestor_pids'].append(ancestor);item=t.task(ancestor)
        if item['nspid']==[ancestor,1]:
            evaluator={**item,'pid_ns':t.namespace(ancestor,'pid'),
                       'script_sha256':t.sha(t.protected('/proc/'+str(ancestor)+'/root'+c.HARNESS+'/guest.py',reg['files'][c.HARNESS+'/guest.py']))}
            break
        ancestor=item['ppid']
    c.require(evaluator is not None,'isolated evaluator ancestor absent');peer['evaluator']=evaluator
    actual=peer_directory(pid)
    try:
        a,b=os.fstat(actual),os.fstat(outfd)
        peer['output_matches']=(a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
        peer['output_root_owned_private']=stat.S_ISDIR(b.st_mode) and b.st_uid==b.st_gid==0 and stat.S_IMODE(b.st_mode)==0o700
    finally:os.close(actual)
    after=t.task(pid);peer['start_after']=after['start']
    peer['pidfd_live']=t.live(peerfd)
    c.require(after['argv']==peer['argv'] and after['exe_sha256']==peer['exe_sha256'] and
              all(t.namespace(pid,n)==peer['ns'][n] for n in ('pid','net','mnt')),'fixture exec/namespace changed during admission')
    c.authorize_peer(peer,reg)
    return config,peer,t.sha(raw)


def worker(control,outfd,mntfd,netfd,config,case,reg):
    me=os.getpid();stage='descriptor-close'
    try:
        keep={0,1,2,control.fileno(),outfd,mntfd,netfd}
        for name in os.listdir('/proc/self/fd'):
            if name.isdigit() and int(name) not in keep:
                try:os.close(int(name))
                except OSError:pass
        # No PID/user setns or unshare. The active initial PID namespace stays.
        stage='namespace-preparation'
        os.setns(mntfd,c.MNT)
        os.unshare(c.MNT)
        c.require(t.LIBC.mount(None,b'/',None,(1<<18)|16384,None)==0,'recursive-private mount propagation failed')
        c.require(t.LIBC.mount(b'proc',b'/proc',b'proc',2|4|8,None)==0,'fresh ancestor-view procfs mount failed')
        os.setns(netfd,c.NET)
        os.close(mntfd);os.close(netfd)
        c.require(t.namespace('self','pid')==reg['initial']['pid'] and
                  t.namespace('self','user')==reg['initial']['user'],'active PID/user namespace changed')
        stage='target-pin-check';target=Path(config['target']);st=target.lstat()
        c.require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022 and
                  [st.st_dev,st.st_ino]==config['target_identity'] and t.digest(target)==config['target_sha256'],
                  'fixture target inode/image differs in cloned mounts')
        parent=target.parent;executor=parent/'executor'
        c.require(t.sha(t.protected(executor,config['executor_sha256']))==config['executor_sha256'],'current executor differs')
        for suffix in ('-observer.json','-observer.jsonl'):
            try:os.stat(case+suffix,dir_fd=outfd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise RuntimeError('observer output already exists')
        stage='observer-init';observer=load('executor_observer',reg['files'][c.OBSERVER],c.OBSERVER)
        instance=observer.Observer(config,Path('/proc/self/fd/'+str(outfd))/(case+'-observer.json'))
        proof={'pid':me,'proc_self_pid':int(os.readlink('/proc/self')),
               'pid_ns':t.namespace('self','pid'),'proc_init_pid_ns':t.namespace(1,'pid'),
               'user_ns':t.namespace('self','user'),'net_ns':t.namespace('self','net'),'mnt_ns':t.namespace('self','mnt'),
               'private_mounts':not any(' shared:' in line or ' master:' in line for line in t.raw('/proc/self/mountinfo',524288).decode().splitlines()),
               'observer_bound':True}
        t.send(control,{'op':'READY','proof':proof});control.settimeout(3)
        message,_,_=t.receive(control);c.require(message=={'op':'RUN','case':case},'worker admission ACK missing')
        stage='observer-run'
        result=instance.run()  # Original observer, deadline, identity checks and verdict unchanged.
        os._exit(0 if result.get('completed') is True else 125)
    except BaseException as error:
        try:
            control.settimeout(1)
            t.send(control,{'op':'ERROR','case':case,'stage':stage,'error':(type(error).__name__+': '+str(error))[:2048]})
        except BaseException:pass
        os._exit(125)


def observe(connection,peerpid,peerfd,credentials,request,fds,reg,receipt):
    case=request.get('case');c.require(set(request)=={'op','case','config_sha256'} and request['op']=='OBSERVE','fixed OBSERVE request required')
    config,peer,config_sha=admission(peerpid,credentials,peerfd,fds,reg)
    c.require(request['config_sha256']==config_sha,'request/config hash differs')
    c.validate_config(case,config,reg,peer['ns']['net']['link'])
    c.require(case not in receipt['cases'],'case replay refused')
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
    pid=os.fork()
    if pid==0:
        parent.close();worker(child,fds[1],fds[2],fds[3],config,case,reg)
        os._exit(125)
    child.close()
    try:fd=os.pidfd_open(pid)
    except BaseException:
        # Still our unreaped child, so its PID cannot have been recycled.
        # Unit cleanup is a second bound if this exceptional reap times out.
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            if os.waitpid(pid,os.WNOHANG)[0]==pid:break
            time.sleep(.02)
        parent.close();raise
    status=None
    row={'case':case,'config_sha256':config_sha,'peer':peer,'status':'ERROR','cleanup':None}
    receipt['cases'][case]=row
    try:
        available=select.select([parent,fd,peerfd],[],[],5)[0]
        c.require(parent in available and t.live(peerfd),'worker ready timeout or peer death')
        parent.settimeout(1);message,_,_=t.receive(parent)
        if message.get('op')=='ERROR':row['worker_error']=message
        c.require(t.live(fd),'worker exited before readiness')
        c.require(message.get('op')=='READY','worker readiness absent');proof=message['proof']
        c.ready(proof,reg['initial'],peer['ns'],pid);row['ready']=proof
        nonce=os.urandom(16).hex();connection.settimeout(3)
        t.send(connection,{'op':'READY','case':case,'nonce':nonce,'proof':proof})
        ack,_,sender=t.receive(connection);c.require(sender==[peerpid,*credentials],'ready ACK sender changed');c.ack(ack,case,nonce)
        t.send(parent,{'op':'RUN','case':case});t.send(connection,{'op':'ARMED','case':case,'nonce':nonce})
        deadline=time.monotonic()+43;finished=False
        while time.monotonic()<deadline:
            ready=select.select([connection,fd,peerfd] if status is None else [connection,peerfd],[],[],.1)[0]
            c.require(peerfd not in ready,'fixture died during observer lease')
            if fd in ready and status is None:status=t.wait_child(pid,fd,0)
            if connection in ready:
                c.require(not finished,'duplicate FINISH request')
                message,_,sender=t.receive(connection)
                c.require(sender==[peerpid,*credentials],'lease sender changed')
                c.require(message in ({'op':'FINISH','case':case},{'op':'CANCEL','case':case}),'unknown lease operation')
                if message['op']=='CANCEL':raise RuntimeError('fixture cancelled observer lease')
                finished=True
            if finished and status is not None:break
        c.completed(finished,status,{'wait_status':status,'reaped':status is not None,'forced':False})
        row.update(status='COMPLETED',observer_completed=True,cleanup={'wait_status':status,'reaped':True,'forced':False})
        t.send(connection,{'op':'DONE','case':case,'completed':True,'cleanup':row['cleanup']})
    except BaseException as error:
        row['error']=type(error).__name__+': '+str(error)
        # After READY a worker may still report an observer/output exception.
        # This path is already failing: retain its bounded diagnostic without
        # replacing the original error or changing completion/cleanup verdicts.
        try:
            if select.select([parent],[],[],0)[0] and parent.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT):
                diagnostic,_,_=t.receive(parent)
                c.require(set(diagnostic)=={'op','case','stage','error'} and
                          diagnostic['op']=='ERROR' and diagnostic['case']==case and
                          isinstance(diagnostic['stage'],str) and len(diagnostic['stage'])<=128 and
                          isinstance(diagnostic['error'],str) and len(diagnostic['error'])<=2048,
                          'malformed worker failure diagnostic')
                row['worker_error']=diagnostic
        except BaseException as diagnostic_error:
            row['worker_error_read_error']=(type(diagnostic_error).__name__+': '+str(diagnostic_error))[:2048]
        raise
    finally:
        try:
            if status is None:row['cleanup']=t.stop_child(pid,fd)
            elif row['cleanup'] is None:row['cleanup']={'wait_status':status,'reaped':True,'forced':False}
        except BaseException as error:
            row['cleanup_error']=type(error).__name__+': '+str(error);raise
        finally:parent.close();os.close(fd)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--vm-token',required=True);parser.add_argument('--registry-sha256',required=True);args=parser.parse_args()
    directory=Path(c.directory(args.vm_token));reg=c.decode(t.protected(directory/'registry.json',args.registry_sha256))
    c.require(reg['token']==args.vm_token,'registry VM mismatch');t.guest(reg,True)
    for name,pin in reg['files'].items():t.protected(name,pin)
    os.umask(0o077);receipt={'schema':'ancestor-observer-broker-r1','status':'ERROR','registry_sha256':args.registry_sha256,
                           'cases':{},'cooperative_stop':False,'fixture_live_on_stop':False,'initial':reg['initial']}
    server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
    server.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);server.bind(str(directory/'control.sock'))
    os.chmod(directory/'control.sock',0o600);server.listen(1);server.settimeout(120)
    connection=None;peerfd=pidfd=cgfd=None
    try:
        t.write(directory/'ready.json',{'schema':'ancestor-observer-ready-r1','pid':os.getpid(),'registry_sha256':args.registry_sha256,
                                      'cgroup':c.cgroup(args.vm_token),'initial':reg['initial']})
        connection,_=server.accept();connection.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);connection.settimeout(10)
        pid,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        c.require(pid>1 and uid==gid==0,'visible root fixture connection required');peerfd=os.pidfd_open(pid)
        hello,fds,sender=t.receive(connection,4)
        try:
            c.require(hello=={'op':'HELLO','registry_sha256':args.registry_sha256} and sender==[pid,0,0],'untrusted HELLO')
            empty,peer,_=admission(pid,[0,0],peerfd,fds,reg)
            c.require(empty=={},'HELLO cannot select a case/config');receipt['hello_peer']=peer
        finally:
            for fd in fds:os.close(fd)
        pidfd=os.pidfd_open(os.getpid());cgfd=os.open('/sys/fs/cgroup'+c.cgroup(args.vm_token),
                                                 os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        parentfd=t.cgroup_parent(cgfd,'/sys/fs/cgroup'+c.cgroup(args.vm_token),reg['cgroup_parent'])
        os.close(parentfd)
        t.send(connection,{'op':'HELLO','pid':os.getpid(),'cgroup':c.cgroup(args.vm_token),'registry_sha256':args.registry_sha256},[pidfd,cgfd])
        connection.settimeout(45)
        for _ in range(30):
            # Request type determines descriptor count; recv parses/owns all rights first.
            connection.settimeout(45)
            request,fds,sender=receive_request(connection)
            try:
                c.require(sender==[pid,0,0] and t.live(peerfd),'fixture sender changed/died')
                if request=={'op':'STOP'}:
                    c.require(not fds,'STOP cannot pass descriptors')
                    stopping=t.task(pid)
                    c.require(stopping['start']==receipt['hello_peer']['start'] and
                              stopping['argv']==c.expected_argv(reg) and stopping['exe_sha256']==reg['python_sha256'] and
                              stopping['uids']==stopping['gids']==[0]*4 and stopping['cgroup']==c.EVAL_CGROUP,
                              'fixture identity changed before STOP')
                    receipt.update(status='STOPPED',cooperative_stop=True,fixture_live_on_stop=True)
                    t.send(connection,{'op':'STOPPING'});return 0
                c.require(len(fds)==4,'OBSERVE needs exactly config/output/mount/network descriptors')
                observe(connection,pid,peerfd,[0,0],request,fds,reg,receipt)
            finally:
                for fd in fds:os.close(fd)
        raise RuntimeError('registered case/request bound exceeded')
    except BaseException as error:
        receipt['error']=type(error).__name__+': '+str(error);return 125
    finally:
        if connection is not None:connection.close()
        server.close()
        for fd in (peerfd,pidfd,cgfd):
            if fd is not None:os.close(fd)
        (directory/'control.sock').unlink(missing_ok=True)
        t.write(directory/'broker.json',receipt)


def receive_request(connection):
    # Variable FD count is restricted to zero STOP or four OBSERVE descriptors.
    return t.receive(connection,expected_fds=None)


if __name__=='__main__':
    def interrupted(signum,frame):raise RuntimeError('broker interrupted: '+str(signum))
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    raise SystemExit(main())
