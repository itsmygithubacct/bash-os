#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed broker client for the pinned executor fixture; guest runtime only."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import time
import uuid
sys.dont_write_bytecode=True
CONTRACT_SHA='2fa29bf9cabdf1d3044d3b619d2f6365de1b62e586313143d800333e40272a06'
TRANSPORT_SHA='f7401859083b9c48552cc44dfb11fdde8b5bc10d08afb8ee386b75310540124e'


def load(name,pin):
    path=Path(__file__).with_name(name+'.py');st=path.lstat();data=path.read_bytes()
    if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_gid or st.st_mode&0o022 or hashlib.sha256(data).hexdigest()!=pin:
        raise RuntimeError('unprotected/pin-mismatched client input')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;exec(compile(data,str(path),'exec'),module.__dict__);return module


c=load('executor_observer_contract_r2',CONTRACT_SHA)
t=load('executor_observer_transport_r2',TRANSPORT_SHA)


class Client:
    def __init__(self,token):
        self.sock=None;self.pidfd=None;self.cgfd=None;self.cgparentfd=None;self.active=None;self.poisoned=False
        self.token=token;self.cgroup_path=None;self.cgroup_identity=None
        self.output=Path(c.OUTPUT);directory=Path(c.directory(token))
        st=directory.lstat()
        c.require(stat.S_ISDIR(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700,
                  'protected broker directory absent')
        encoded=t.raw(directory/'registry.json',8192,True);self.pin=t.sha(encoded);self.reg=c.decode(encoded)
        c.require(self.reg['token']==token,'client registry UUID differs')
        for path,pin in self.reg['files'].items():t.protected(path,pin)
        c.require(t.digest('/proc/self/exe')==self.reg['python_sha256'] and
                  t.task(os.getpid())['argv']==c.expected_argv(self.reg),'client is not the pinned fixture')
        ready=c.decode(t.raw(directory/'ready.json',8192,True))
        c.require(ready['registry_sha256']==self.pin and ready['initial']==self.reg['initial'] and
                  ready['cgroup']==c.cgroup(token),'broker readiness registration differs')
        endpoint=directory/'control.sock';st=endpoint.lstat()
        c.require(stat.S_ISSOCK(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600,
                  'unprotected broker socket')
        try:
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC);self.sock.settimeout(10)
            self.sock.connect(str(endpoint))
            peer=struct.unpack('3i',self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            # An ancestor can be invisible to this client. This is NOT the
            # executor observer's SO_PEERCRED check, which still requires PID>0.
            c.require(peer[1:]==(0,0),'broker socket owner differs')
            self.request({'op':'HELLO','registry_sha256':self.pin},{})
            reply,fds,_=t.receive(self.sock,2)
            self.pidfd,self.cgfd=fds
            c.require(reply=={'op':'HELLO','pid':ready['pid'],'cgroup':ready['cgroup'],'registry_sha256':self.pin},
                      'broker HELLO registration differs')
            c.require(os.readlink('/proc/self/fd/'+str(self.pidfd))=='anon_inode:[pidfd]' and t.live(self.pidfd),
                      'broker live pidfd absent')
            cgst=os.fstat(self.cgfd);self.cgroup_path='/sys/fs/cgroup'+ready['cgroup']
            self.cgroup_identity=(cgst.st_dev,cgst.st_ino)
            c.require(t.fs_type(self.cgfd)==c.CGROUP2 and stat.S_ISDIR(cgst.st_mode) and
                      os.readlink('/proc/self/fd/'+str(self.cgfd))==self.cgroup_path,
                      'registered broker cgroup FD differs')
            self.cgparentfd=t.cgroup_parent(self.cgfd,self.cgroup_path,self.reg['cgroup_parent'])
        except BaseException:
            self.dispose();raise

    def request(self,message,config):
        fds=[]
        try:
            wire=json.dumps(config,sort_keys=True).encode();c.require(0<len(wire)<=c.CONFIG_MAX,'config bound')
            fd=os.memfd_create('executor-observer-config',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);fds.append(fd)
            c.require(os.write(fd,wire)==len(wire),'short config write')
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            fds.append(os.open(c.OUTPUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC))
            fds.append(t.nsfd('/proc/self/ns/mnt',c.MNT));fds.append(t.nsfd('/proc/self/ns/net',c.NET))
            if message['op']=='OBSERVE':message={**message,'config_sha256':t.sha(wire)}
            t.send(self.sock,message,fds)
        finally:
            for fd in fds:os.close(fd)

    def begin(self,case,config):
        c.require(self.active is None and not self.poisoned,'client has an unfinished lease')
        fixture={n:t.namespace('self',n) for n in ('mnt','net')}
        c.validate_config(case,config,self.reg,fixture['net']['link'])
        self.active=case
        try:
            self.request({'op':'OBSERVE','case':case},config);self.sock.settimeout(7)
            reply,_,_=t.receive(self.sock)
            c.require(set(reply)=={'op','case','nonce','proof'} and reply['op']=='READY' and reply['case']==case and
                      isinstance(reply['nonce'],str) and len(reply['nonce'])==32,'invalid observer readiness')
            c.ready(reply['proof'],self.reg['initial'],fixture,reply['proof']['pid'])
            t.send(self.sock,{'op':'ACK','case':case,'nonce':reply['nonce']});self.sock.settimeout(4)
            armed,_,_=t.receive(self.sock)
            c.require(armed=={'op':'ARMED','case':case,'nonce':reply['nonce']},'observer ready ACK was not accepted')
            self.current={'case':case,'registry_sha256':self.pin,'ready':reply['proof'],'armed':True}
        except BaseException:
            self.poisoned=True;raise

    def finish(self):
        case=self.active;c.require(case is not None and not self.poisoned,'no live lease')
        try:
            t.send(self.sock,{'op':'FINISH','case':case});self.sock.settimeout(6)
            reply,_,_=t.receive(self.sock)
            c.require(reply=={'op':'DONE','case':case,'completed':True,
                             'cleanup':{'wait_status':0,'reaped':True,'forced':False}},'observer incomplete/unclean')
            c.completed(reply['completed'],reply['cleanup']['wait_status'],reply['cleanup'])
            self.current.update(completed=True,cleanup=reply['cleanup'])
            t.write(self.output/(case+'-broker.json'),self.current)
            self.active=None;return self.current
        except BaseException:
            self.poisoned=True;raise

    def cancel(self):
        if self.active is not None:
            self.poisoned=True
            try:t.send(self.sock,{'op':'CANCEL','case':self.active})
            except OSError:pass
            self.active=None

    def dispose(self):
        if self.sock is not None:self.sock.close();self.sock=None
        for name in ('pidfd','cgfd','cgparentfd'):
            fd=getattr(self,name)
            if fd is not None:os.close(fd);setattr(self,name,None)

    def close(self):
        record={'schema':'ancestor-observer-fixture-stop-r1','registry_sha256':self.pin,'status':'ERROR',
                'before_fixture_cleanup':True,'before_evaluator_exit':True}
        try:
            self.cancel()
            live=t.cgroup_empty(self.cgfd,self.cgroup_path,self.pidfd,self.cgroup_identity,
                                self.cgparentfd,self.reg['cgroup_parent'])
            c.require(not live['empty'] and not live['removed'] and not live['broker_reaped'] and
                      live['path_present'] is True and
                      live['relative_lookup_first']==live['relative_lookup_second'] and
                      live['parent_link']==t.CGROUP_PARENT and
                      live['observer_mnt_ns']!=self.reg['initial']['mnt']['link'] and
                      live['absolute_path_present'] is False and
                      'populated 1' in live['events'].splitlines(),
                      'live broker cgroup falsely appeared empty before STOP')
            record['pre_stop_live_cgroup']=live
            other=str(uuid.UUID(int=uuid.UUID(self.token).int ^ 1))
            wrong_path='/sys/fs/cgroup'+c.cgroup(other)
            try:t.cgroup_empty(self.cgfd,wrong_path,self.pidfd,self.cgroup_identity,
                                   self.cgparentfd,self.reg['cgroup_parent'])
            except RuntimeError as error:
                c.require(str(error).startswith(('registered cgroup FD/path mismatch:',
                                                 'registered cgroup path rebound or wrong FD:')),
                          'wrong-path negative produced an unrelated error')
                record['wrong_owned_path_rejected']=True
            else:raise RuntimeError('wrong owned cgroup path was accepted')
            wrong_parent=dict(self.reg['cgroup_parent']);wrong_parent['ino']^=1
            try:t.cgroup_empty(self.cgfd,self.cgroup_path,self.pidfd,self.cgroup_identity,
                               self.cgparentfd,wrong_parent)
            except RuntimeError as error:
                c.require(str(error).startswith('pinned cgroup parent/child identity differs'),
                          'wrong-parent negative produced an unrelated error')
                record['wrong_parent_identity_rejected']=True
            else:raise RuntimeError('wrong cgroup parent identity was accepted')
            if not self.poisoned:
                t.send(self.sock,{'op':'STOP'});self.sock.settimeout(3)
                reply,_,_=t.receive(self.sock);c.require(reply=={'op':'STOPPING'},'broker STOP not acknowledged')
                record['cooperative_stop']=True
            c.require(select.select([self.pidfd],[],[],6)[0],'broker exit deadline exceeded')
            deadline=time.monotonic()+2;history=[]
            while True:
                empty=t.cgroup_empty(self.cgfd,self.cgroup_path,self.pidfd,self.cgroup_identity,
                                     self.cgparentfd,self.reg['cgroup_parent'])
                history.append(empty);c.require(len(history)<=41,'client cgroup observation count exceeded')
                reaped=t.pidfd_reaped(self.pidfd)
                if (empty['empty'] and reaped) or time.monotonic()>=deadline:break
                time.sleep(.05)
            record['cgroup']=empty;record['cgroup_history']=history;record['broker_exited']=True
            record['broker_reaped_by_systemd']=reaped
            c.require(empty['empty'] and reaped and not self.poisoned,'observer failure or broker not reaped/empty')
            record['status']='CLEAN';return record
        except BaseException as error:
            record['error']=type(error).__name__+': '+str(error);raise
        finally:
            self.dispose();t.write(self.output/'ancestor-broker-cleanup.json',record)
