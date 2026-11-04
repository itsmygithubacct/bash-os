#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only control checks for incomplete ACME tracer diagnostics.

These tests establish only that chosen controls appeared in the diagnostic
stream. They do not establish complete event coverage, credential isolation,
or r8 qualification. The candidate can access its own scratch output, so the
coordinator must retain independently protected evidence before product credit.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys

GUARD=Path('/opt/bashos-parity/harness/helpers/clock254_guard.py')
SELF=Path('/opt/bashos-parity/harness/helpers/acme-observer-controls-r1.py')
ATTEST=Path('/run/bashos-acme-observer-attestation.json')
PIN='6e40323524fac1bc4a0f4824b54190d0dc34989b02508fc972ae1b9c3c06e262'
def need(x,s):
    if not x: raise ValueError(s)
def gate():
    need(sys.flags.isolated==1 and sys.flags.no_site==1,'isolated no-site Python required')
    parent=GUARD.parent.stat();need(parent.st_uid==0 and not stat.S_IMODE(parent.st_mode)&0o022,'guard parent')
    fd=os.open(GUARD,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and st.st_nlink==1 and not stat.S_IMODE(st.st_mode)&0o022 and 0<st.st_size<131072,'guard metadata')
        data=b''
        while len(data)<st.st_size:
            chunk=os.read(fd,st.st_size-len(data));need(bool(chunk),'short guard');data+=chunk
        end=os.fstat(fd);need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns),'changed guard')
    finally:os.close(fd)
    need(hashlib.sha256(data).hexdigest()==PIN,'guard digest');ns={'__name__':'clock254_guard','__file__':str(GUARD)};exec(compile(data,str(GUARD),'exec'),ns);token=ns['guard']()
    need(Path(__file__)==SELF,'control not invoked from protected path')
    def protected(path,limit):
        parent=path.parent.stat();need(parent.st_uid==0 and not stat.S_IMODE(parent.st_mode)&0o022,'unprotected parent')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_gid==0 and before.st_nlink==1 and not stat.S_IMODE(before.st_mode)&0o022 and 0<before.st_size<=limit,'unprotected file')
            data=b''
            while len(data)<before.st_size:
                chunk=os.read(fd,before.st_size-len(data));need(bool(chunk),'short protected read');data+=chunk
            after=os.fstat(fd);need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'changed protected file')
            return data,before
        finally:os.close(fd)
    raw,info=protected(ATTEST,8192);need(stat.S_IMODE(info.st_mode)==0o444,'attestation mode')
    def unique(pairs):
        obj={}
        for k,v in pairs:need(k not in obj,'duplicate attestation key');obj[k]=v
        return obj
    att=json.loads(raw.decode('ascii'),object_pairs_hook=unique)
    need(set(att)=={'schema','token','candidate_sha256','observer_sha256','controls_sha256','cgroup'} and att['schema']=='bashos-acme-observer-attestation-v1' and att['token']==token,'attestation identity')
    own,_=protected(SELF,131072);need(hashlib.sha256(own).hexdigest()==att['controls_sha256'],'control source digest')
    cgroup=Path('/proc/self/cgroup').read_text('ascii').strip();need(cgroup==att['cgroup'] and cgroup.startswith('0::/') and cgroup!='0::/','control cgroup')

def main():
    gate();need(len(sys.argv)==2 and sys.argv[1] in ('network-canary','credential-canary','cleanup-canary','candidate'),'invalid mode')
    p=Path('/tmp/parity-home/acme-observer-record.json');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid==2000 and 0<st.st_size<1048576,'record metadata');raw=os.read(fd,st.st_size+1);need(len(raw)==st.st_size,'record truncated')
    finally:os.close(fd)
    doc=json.loads(raw);need(doc.get('schema')=='bashos-acme-observer-r1' and doc.get('state')=='INCOMPLETE' and doc.get('qualification_pass') is False and doc.get('mode')==sys.argv[1] and doc.get('all_traced_tasks_exited') is True,'observer incomplete or missing evidence')
    events=doc.get('events');need(isinstance(events,list),'events absent')
    if sys.argv[1]=='network-canary':
        need(any(e.get('name')=='connect' and e.get('address')=={'family':'inet','host':'127.0.0.1','port':5999} for e in events),'network attempt not seen')
    elif sys.argv[1]=='credential-canary':
        h=hashlib.sha256(b'/tmp/parity-home/acme-observer-canary').hexdigest();need(any(e.get('name') in ('open','openat','openat2') and e.get('path_sha256')==h for e in events),'file access not seen')
    elif sys.argv[1]=='cleanup-canary':
        need(bool(doc.get('root_exit_descendants')),'leaked descendant not seen at root exit')
    else:
        need(doc.get('root_status',{}).get('exit',0)!=0,'candidate fault did not fail')
        need(not doc.get('root_exit_descendants'),'descendant present when candidate exited')
        need(doc.get('temp_before')==doc.get('temp_after') and isinstance(doc.get('temp_before'),list),'ACME temporary paths changed')
        need(any(e.get('name')=='bind' and e.get('address')=={'family':'inet','host':'127.0.0.1','port':5812} and e.get('result')==0 for e in events),'challenge listener not observed')
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',5812))
        finally:s.close()
    print('observer-control-ok '+sys.argv[1])
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('observer-control-incomplete '+type(exc).__name__+': '+str(exc),file=sys.stderr);sys.exit(1)
