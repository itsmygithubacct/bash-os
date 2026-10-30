#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only synthetic proc lifecycle cases with an owned ptrace observer."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import uuid

from ns_guest_identity_r1 import verify as verify_guest_identity

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
LIVE = CASE/'proc-live'
HELPER = '/opt/bashos-parity/harness/helpers/farm600-top-proc-lifecycle-reviewed.py'
SOURCE = '/opt/bashos-parity/harness/helpers/farm600-top-proc-lifecycle-reviewed.c'
OBSERVER = CASE/'lifecycle-observer'
CPU_BASE = 'cpu 100 0 100 800 0 0 0 0 20 10\n'
CPU_NEXT = 'cpu 160 0 160 880 0 0 0 0 100 50\n'
MEM = 'MemTotal: 8000 kB\nMemAvailable: 3000 kB\nSwapTotal: 2000 kB\nSwapFree: 1250 kB\n'
LOAD = '1.25 1.50 1.75 1/4 402\n'
SCENARIOS = ('malformed','vanish','empty','proc-rollback','cpu-rollback','guest','lifecycle')
DIAGNOSTICS_ALLOWED = False


def read_at(fd, path, limit):
    handle=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
    try:
        data=b''
        while len(data)<=limit:
            part=os.read(handle,limit+1-len(data))
            if not part: break
            data+=part
        if len(data)>limit: raise RuntimeError('oversized proc control file')
        return data
    finally: os.close(handle)


def protected_identity(owner_uid,owner_gid):
    def read_file(directory,name):
        dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            parent=os.fstat(dfd)
            if parent.st_uid!=owner_uid or parent.st_gid!=owner_gid or stat.S_IMODE(parent.st_mode)&0o022:
                raise RuntimeError('unprotected identity directory')
            fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
            try:
                before=os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner_uid or before.st_gid!=owner_gid or
                    stat.S_IMODE(before.st_mode)!=0o444 or before.st_nlink!=1 or before.st_size!=37):
                    raise RuntimeError('unprotected identity file')
                data=os.read(fd,38); after=os.fstat(fd)
                entry=os.stat(name,dir_fd=dfd,follow_symlinks=False)
                def fields(st): return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns)
                if fields(before)!=fields(after) or fields(after)!=fields(entry): raise RuntimeError('identity changed')
            finally: os.close(fd)
        finally: os.close(dfd)
        if len(data)!=37 or not data.endswith(b'\n'): raise RuntimeError('invalid identity bytes')
        value=data[:-1].decode('ascii')
        if str(uuid.UUID(value))!=value: raise RuntimeError('noncanonical identity')
        return {'value':value,'owner_uid':before.st_uid,'owner_gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode),
                'size':before.st_size,'nlink':before.st_nlink,'parent_uid':parent.st_uid,
                'parent_gid':parent.st_gid,'parent_mode':stat.S_IMODE(parent.st_mode)}
    marker=read_file('/etc','bashos-parity-vm')
    attestation=read_file('/run','bashos-parity-vm-identity')
    if marker['value']!=attestation['value']: raise RuntimeError('attested identity differs')
    return {'marker':marker,'attestation':attestation}


def proc_context(fd, expected_ns=None, outer_ns=None):
    # Preserve a descriptor to the real procfs opened before the private mount.
    info=ctypes.create_string_buffer(256)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.fstatfs(fd,ctypes.byref(info))!=0 or struct.unpack_from('l',info.raw)[0]!=0x9fa0:
        raise RuntimeError('saved descriptor is not procfs')
    uidmap=read_at(fd,'self/uid_map',4096).decode().splitlines()
    gidmap=read_at(fd,'self/gid_map',4096).decode().splitlines()
    if [x.split() for x in uidmap]!=[['0','2000','1']] or [x.split() for x in gidmap]!=[['0','2000','1']]:
        raise RuntimeError('unexpected uid or gid map')
    ns=os.readlink('self/ns/mnt',dir_fd=fd)
    if expected_ns is not None and ns!=expected_ns: raise RuntimeError('mount namespace changed')
    if outer_ns is not None and ns==outer_ns: raise RuntimeError('mount namespace was not isolated')
    mountinfo=read_at(fd,'self/mountinfo',1024*1024).decode('utf-8','strict')
    for line in mountinfo.splitlines():
        if ' - ' not in line: raise RuntimeError('malformed mountinfo')
        optional=line.split(' - ',1)[0].split()[6:]
        if any(x.startswith(('shared:','master:','propagate_from:')) for x in optional):
            raise RuntimeError('mount propagation is not private')
    return {'uid_map':uidmap,'gid_map':gidmap,'mount_namespace':ns,'outer_namespace':outer_ns,
            'mountinfo':mountinfo,'overflow_uid':int(read_at(fd,'sys/kernel/overflowuid',64)),
            'overflow_gid':int(read_at(fd,'sys/kernel/overflowgid',64))}


def guard(outer=True,mounted=True):
    global DIAGNOSTICS_ALLOWED
    if (os.getuid() != (2000 if outer else 0) or os.geteuid() != (2000 if outer else 0)
        or os.getgid()!=(2000 if outer else 0) or os.getegid()!=(2000 if outer else 0)
        or Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME)
        or os.uname().machine!='x86_64'):
        raise RuntimeError('requires the isolated x86_64 uid-2000 parity guest')
    if outer or not mounted:
        verify_guest_identity()
        if outer:
            proof=protected_identity(0,0)
            DIAGNOSTICS_ALLOWED=True
            return proof
        return None
    fd=int(os.environ['LIFECYCLE_REALPROC_FD'])
    context=proc_context(fd,expected_ns=os.environ['LIFECYCLE_MNT_NS'],outer_ns=os.environ['LIFECYCLE_OUTER_NS'])
    identity=protected_identity(context['overflow_uid'],context['overflow_gid'])
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU': raise RuntimeError('unexpected vendor')
    a,b=os.stat('/proc'),os.stat(LIVE)
    if (a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino): raise RuntimeError('private proc is not mounted')
    mountinfo=context.pop('mountinfo')
    context['mountinfo_sha256']=hashlib.sha256(mountinfo.encode()).hexdigest()
    DIAGNOSTICS_ALLOWED=True
    return {'identity':identity,'context':context,'proc_dev':a.st_dev,'proc_inode':a.st_ino}


def dump(name, data):
    (HOME/name).write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')


def proc_stat(pid, name, state, utime, stime, start, rss):
    # Independent proc(5) positions: state=3, utime=14, stime=15,
    # starttime=22, vsize=23, rss=24; fields not used here are constants.
    fields = {3:state,4:1,5:1,6:1,7:0,8:-1,9:0,10:0,11:0,12:0,13:0,
              14:utime,15:stime,16:0,17:0,18:20,19:0,20:1,21:0,
              22:start,23:1048576,24:rss}
    return (str(pid)+' ('+name+') '+' '.join(str(fields[i]) for i in range(3,25))+'\n').encode()


def proc_entry(pid, name, state, utime, stime, start, rss):
    return {'stat':proc_stat(pid,name,state,utime,stime,start,rss),
            'status':f'Name:\t{name}\nState:\t{state}\nUid:\t0\t0\t0\t0\n'.encode(),
            'cmdline':(name+'\0--fixture\0').encode()}


def fixture(scenario):
    a=proc_entry(101,'steady','S',10,10,1001,4)
    b=proc_entry(101,'steady','S',30,10,1001,4)
    first={101:a}; second={101:b}; cpu0=CPU_BASE; cpu1=CPU_NEXT
    if scenario=='malformed':
        bad1={'stat':b'501 (truncated) S 1 2\n','status':b'Name:\ttruncated\nUid:\t0\t0\t0\t0\n','cmdline':b'truncated\0'}
        bad2={'stat':b'502 broken without parentheses\n','status':b'Name:\tbroken\nUid:\t0\t0\t0\t0\n','cmdline':b'broken\0'}
        first.update({501:bad1,502:bad2}); second.update({501:bad1,502:bad2})
    elif scenario=='vanish':
        second[777]=proc_entry(777,'vanishing','S',5,5,7771,2)
    elif scenario=='empty': first={}; second={}
    elif scenario=='proc-rollback':
        first={101:proc_entry(101,'steady','S',90,10,1001,4)}
        second={101:proc_entry(101,'steady','S',60,10,1001,4)}
    elif scenario=='cpu-rollback':
        first={101:proc_entry(101,'steady','S',90,10,1001,4)}
        second={101:proc_entry(101,'steady','S',110,10,1001,4)}
        cpu1='cpu 80 0 80 640 0 0 0 0 100 50\n'
    elif scenario=='guest':
        first={101:proc_entry(101,'steady','S',10,20,1001,4)}
        second={101:proc_entry(101,'steady','S',60,20,1001,4)}
    elif scenario=='lifecycle':
        first[202]=proc_entry(202,'old','S',90,10,2001,6)
        second[202]=proc_entry(202,'reused','S',890,10,9002,6)
        second[303]=proc_entry(303,'new','R',70,10,3001,8)
    return [(cpu0,first),(cpu1,second)]


def write_tree(path, cpu, procs):
    path.mkdir()
    (path/'stat').write_text(cpu); (path/'meminfo').write_text(MEM); (path/'loadavg').write_text(LOAD)
    for pid, files in procs.items():
        d=path/str(pid); d.mkdir()
        for name,data in files.items(): (d/name).write_bytes(data)


def manifest(path):
    result={}
    for f in sorted(path.rglob('*')):
        if f.is_file(): result[str(f.relative_to(path))]=f.read_bytes().hex()
    return result


def reset_live(scenario):
    # The root inode remains mounted; only the fixture's own children change.
    if LIVE.exists():
        if LIVE.is_symlink() or LIVE.parent!=CASE: raise RuntimeError('unsafe fixture path')
        for item in LIVE.iterdir():
            if item.is_dir() and not item.is_symlink(): shutil.rmtree(item)
            else: item.unlink()
    else: LIVE.mkdir()
    for item in (CASE/'snapshot-0').iterdir():
        if item.is_dir(): shutil.copytree(item,LIVE/item.name)
        else: shutil.copyfile(item,LIVE/item.name)
    if manifest(LIVE)!=manifest(CASE/'snapshot-0'): raise RuntimeError('initial fixture differs')


def action(mode, scenario, role):
    proof=guard(False)
    if scenario not in SCENARIOS or role not in ('native','candidate'): raise RuntimeError('unexpected action')
    if mode=='advance':
        for item in LIVE.iterdir():
            if item.is_dir() and not item.is_symlink(): shutil.rmtree(item)
            else: item.unlink()
        for item in (CASE/'snapshot-1').iterdir():
            if item.is_dir(): shutil.copytree(item,LIVE/item.name)
            else: shutil.copyfile(item,LIVE/item.name)
        actual=manifest(LIVE)
        if actual!=manifest(CASE/'snapshot-1'): raise RuntimeError('second fixture differs')
        print(json.dumps({'action':'advance','scenario':scenario,'role':role,'manifest':actual,'guard':proof},sort_keys=True))
    elif mode=='vanish':
        if scenario!='vanish': raise RuntimeError('vanish outside its case')
        path=LIVE/'777'
        before=manifest(path)
        if before!=manifest(CASE/'snapshot-1'/'777'): raise RuntimeError('vanishing record differs')
        shutil.rmtree(path)
        if path.exists(): raise RuntimeError('vanishing directory remains')
        print(json.dumps({'action':'vanish','role':role,'pid':777,'before':before,'absent':True,'guard':proof},sort_keys=True))
    else: raise RuntimeError('unknown action')


def native(scenario):
    proof=guard(False)
    os.close(int(os.environ.pop('LIFECYCLE_REALPROC_FD')))
    def read_once(path):
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
        try: return os.read(fd,4096).hex()
        finally: os.close(fd)
    observed=[]
    for _ in (0,1):
        with open('/proc/stat','rb',buffering=0) as stream:
            cpu=stream.read(4096).hex()
        names=sorted(x for x in os.listdir('/proc') if x.isdigit())
        records={}; missing=[]
        for name in names:
            p=Path('/proc')/name
            try: records[name]={k:read_once(p/k) for k in ('stat','status','cmdline')}
            except FileNotFoundError: missing.append(name)
        observed.append({'cpu':cpu,'names':names,'records':records,'missing':missing,
                         'meminfo':read_once('/proc/meminfo'),
                         'loadavg':read_once('/proc/loadavg')})
    print(json.dumps({'guard':proof,'observed':observed},sort_keys=True))


def run_observed(scenario, role):
    command=[str(OBSERVER),scenario,role,str(HOME/(role+'.out')),str(HOME/(role+'.err'))]
    if role=='native': command += ['/usr/bin/python3',HELPER,'native',scenario]
    else: command += ['/opt/bashos-parity/candidate','--noprofile','--norc','-c','builtin top --once']
    trace=HOME/(role+'.trace'); observer_err=HOME/(role+'.observer.err')
    status=None; timeout=False; child_cleanup={'signal_attempted':False}
    with trace.open('wb') as out, observer_err.open('wb') as err:
        old=resource.getrlimit(resource.RLIMIT_FSIZE); soft=old[0]
        resource.setrlimit(resource.RLIMIT_FSIZE,(min(soft,512*1024) if soft!=resource.RLIM_INFINITY else 512*1024,old[1]))
        try:
            p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                               pass_fds=(int(os.environ['LIFECYCLE_REALPROC_FD']),))
            try: status=p.wait(timeout=12)
            except subprocess.TimeoutExpired:
                timeout=True; child_cleanup={'signal_attempted':True,'unreaped_direct_child':True,'pid':p.pid}
                p.kill(); p.wait()
        finally: resource.setrlimit(resource.RLIMIT_FSIZE,old)
    paths={x:HOME/(role+'.'+x) for x in ('out','err','trace','observer.err')}
    sizes={k:v.stat().st_size if v.exists() else None for k,v in paths.items()}
    raw=trace.read_text(errors='strict')
    try: events=[json.loads(line) for line in raw.splitlines()]; parse_error=None
    except (ValueError,UnicodeError) as exc: events=[]; parse_error=repr(exc)
    meta={'role':role,'command':command,'observer_status':status,'timeout':timeout,'observer_cleanup':child_cleanup,'sizes':sizes,
          'complete':all(v is not None and v<512*1024 for v in sizes.values()) and raw.endswith('\n'),
          'observer_stderr_base64':base64.b64encode(observer_err.read_bytes()).decode(),
          'parse_error':parse_error,'events':events}
    dump(role+'.json',meta)
    return meta


def dirent_names(data):
    names=[]; off=0
    while off<len(data):
        if len(data)-off<20: raise ValueError('short dirent')
        length=struct.unpack_from('<H',data,off+16)[0]
        if length<20 or off+length>len(data): raise ValueError('invalid dirent length')
        name=data[off+19:off+length].split(b'\0',1)
        if len(name)!=2: raise ValueError('unterminated dirent')
        names.append(name[0].decode('ascii')); off+=length
    return names


def trace_checks(meta, scenario):
    events=meta['events']; errors=[]; expected=fixture(scenario)
    if meta['observer_status']!=0 or meta['timeout'] or not meta['complete'] or meta['parse_error'] or meta['observer_stderr_base64']:
        errors.append('observer incomplete or failed')
    if len([e for e in events if e.get('kind')=='start'])!=1 or len([e for e in events if e.get('kind')=='exit'])!=1:
        errors.append('missing or repeated start/exit')
    if meta['role']=='candidate':
        starts=[e for e in events if e.get('kind')=='start']
        if len(starts)!=1 or starts[0].get('live_proc_inherited') is not False:
            errors.append('candidate live-proc isolation not established')
    if any(e.get('kind')=='unsupported' for e in events): errors.append('unsupported traced operation')
    mount=json.loads((HOME/'mount.json').read_text())
    guard_events=[e for e in events if e.get('kind')=='guard']
    if (len(guard_events)!=1 or guard_events[0].get('identity')!=mount['identity']['marker']['value'] or
        guard_events[0].get('uid_map')!='0 2000 1' or guard_events[0].get('gid_map')!='0 2000 1' or
        guard_events[0].get('mount_ns')!=mount['before']['mount_namespace'] or
        guard_events[0].get('outer_ns')!=mount['before']['outer_namespace'] or
        guard_events[0].get('overflow_uid')!=mount['before']['overflow_uid'] or
        guard_events[0].get('overflow_gid')!=mount['before']['overflow_gid'] or guard_events[0].get('private') is not True):
        errors.append('observer identity/namespace guard not established')
    if len(guard_events)==1:
        try:
            raw_mountinfo=bytes.fromhex(guard_events[0]['mountinfo_hex'])
            if hashlib.sha256(raw_mountinfo).hexdigest()!=mount['mounted_guard']['context']['mountinfo_sha256']:
                errors.append('observer mountinfo differs')
        except (KeyError,ValueError): errors.append('observer mountinfo missing or malformed')
    image='/usr/bin/python3' if meta['role']=='native' else '/opt/bashos-parity/candidate'
    executions=[e for e in events if e.get('kind')=='exec']
    if (len(executions)!=1 or executions[0].get('result')!=0 or
        bytes.fromhex(executions[0].get('path_hex','')).decode('utf-8')!=image):
        errors.append('tracee exec identity not established')
    def path(e): return bytes.fromhex(e.get('path_hex','')).decode('utf-8')
    opens=[e for e in events if e.get('kind')=='open' and path(e)=='/proc/stat']
    reads=[e for e in events if e.get('kind')=='read' and path(e)=='/proc/stat' and e.get('result',0)>0]
    if len(opens)!=2 or [e.get('epoch') for e in opens]!=[1,2] or any(e.get('result',-1)<0 for e in opens):
        errors.append('two proc/stat opens not established')
    if [e['data_hex'] for e in reads]!=[x[0].encode().hex() for x in expected]:
        errors.append('two exact CPU reads not established')
    if any(e.get('kind')=='read' and path(e)=='/proc/stat' and e.get('result',-1)<=0 for e in events):
        errors.append('CPU EOF or failed read')
    advance=[(i,e) for i,e in enumerate(events) if e.get('kind')=='action' and e.get('name')=='advance' and e.get('status')==0]
    if len(advance)!=1: errors.append('snapshot transition not established')
    else:
        idx,event=advance[0]
        try: payload=json.loads(bytes.fromhex(event['output_hex']).decode())
        except (ValueError,UnicodeError): payload={}
        if (payload.get('scenario')!=scenario or payload.get('role')!=meta['role'] or
            payload.get('manifest')!=manifest(CASE/'snapshot-1') or
            payload.get('guard',{}).get('identity',{}).get('marker',{}).get('value')!=mount['identity']['marker']['value'] or
            payload.get('guard',{}).get('context',{}).get('mount_namespace')!=mount['before']['mount_namespace']):
            errors.append('transition manifest differs')
        index0=next((i for i,e in enumerate(events) if e in reads[:1]),-1)
        index1=next((i for i,e in enumerate(events) if e in reads[1:2]),-1)
        if not (0<=index0<idx<index1): errors.append('CPU transition ordering differs')
    for epoch,(_cpu,procs) in enumerate(expected,1):
        visible=[]
        for event in events:
            if event.get('kind')=='getdents' and event.get('epoch')==epoch and path(event)=='/proc' and event.get('result',0)>0:
                try: visible += dirent_names(bytes.fromhex(event['data_hex']))
                except (ValueError,UnicodeError): errors.append('invalid directory record')
        numeric=sorted(x for x in visible if x.isdigit())
        if numeric!=sorted(str(pid) for pid in procs): errors.append('directory entries differ in epoch '+str(epoch))
        for pid,files in procs.items():
            if scenario=='vanish' and epoch==2 and pid==777: continue
            read=[e for e in events if e.get('kind')=='read' and e.get('epoch')==epoch and
                  path(e)==f'/proc/{pid}/stat' and e.get('result',0)>0]
            if len(read)!=1 or read[0].get('data_hex')!=files['stat'].hex() or read[0].get('result')!=len(files['stat']):
                errors.append(f'PID {pid} stat bytes not established in epoch {epoch}')
    # The displayed second-sample header and row fields must be backed by
    # actual matching reads, rather than by coincidentally matching output.
    required={ '/proc/meminfo':MEM.encode(), '/proc/loadavg':LOAD.encode() }
    for pid,files in expected[1][1].items():
        if pid in (501,502) or (scenario=='vanish' and pid==777): continue
        for name in ('status','cmdline'):
            required[f'/proc/{pid}/{name}']=files[name]
    for filename,value in required.items():
        found=[e for e in events if e.get('kind')=='read' and e.get('epoch')==2 and
               path(e)==filename and e.get('result')==len(value) and e.get('data_hex')==value.hex()]
        if len(found)!=1: errors.append('rendered input not established: '+filename)
    if scenario=='vanish':
        gone=[(i,e) for i,e in enumerate(events) if e.get('kind')=='action' and e.get('name')=='vanish' and e.get('status')==0]
        failed=[i for i,e in enumerate(events) if e.get('kind')=='open' and e.get('epoch')==2 and path(e)=='/proc/777/stat' and e.get('result')==-2]
        scans=[i for i,e in enumerate(events) if e.get('kind')=='getdents' and e.get('epoch')==2 and path(e)=='/proc' and e.get('result',0)>0 and '777' in dirent_names(bytes.fromhex(e['data_hex']))]
        if len(gone)!=1 or not failed or not scans or not (scans[0]<gone[0][0]<failed[0]):
            errors.append('vanishing scan/delete/ENOENT sequence not established')
        else:
            payload=json.loads(bytes.fromhex(gone[0][1]['output_hex']).decode())
            if (not payload.get('absent') or payload.get('pid')!=777 or payload.get('role')!=meta['role']
                or payload.get('before')!=manifest(CASE/'snapshot-1'/'777')
                or payload.get('guard',{}).get('identity',{}).get('marker',{}).get('value')!=mount['identity']['marker']['value']
                or payload.get('guard',{}).get('context',{}).get('mount_namespace')!=mount['before']['mount_namespace']):
                errors.append('vanishing action manifest differs')
    return errors


def control(scenario, meta):
    problems=trace_checks(meta,scenario)
    if problems: raise RuntimeError('native trace: '+repr(problems))
    native_data=json.loads((HOME/'native.out').read_text())
    mount=json.loads((HOME/'mount.json').read_text())
    if (native_data.get('guard',{}).get('identity',{}).get('marker',{}).get('value')!=mount['identity']['marker']['value']
        or native_data.get('guard',{}).get('context',{}).get('mount_namespace')!=mount['before']['mount_namespace']):
        raise RuntimeError('native identity evidence missing')
    records=native_data['observed']
    expected=fixture(scenario)
    if len(records)!=2: raise RuntimeError('native control sample count')
    for epoch,(cpu,procs) in enumerate(expected):
        names=[str(i) for i in sorted(procs)]
        missing=['777'] if scenario=='vanish' and epoch==1 else []
        wanted={str(pid):{k:v.hex() for k,v in files.items()} for pid,files in procs.items() if str(pid) not in missing}
        row=records[epoch]
        if (row['cpu']!=cpu.encode().hex() or row['names']!=names or row['missing']!=missing or row['records']!=wanted
            or row['meminfo']!=MEM.encode().hex() or row['loadavg']!=LOAD.encode().hex()):
            raise RuntimeError('native snapshot mismatch: '+str(epoch))
    if (HOME/'native.err').read_bytes(): raise RuntimeError('native reader stderr')
    terminal=[e for e in meta['events'] if e.get('kind')=='exit'][0]
    if terminal['status']!=0 or terminal['signal']!=0: raise RuntimeError('native reader exit')


def parse_rows(data):
    if not data or not data.endswith(b'\n') or any(c<32 and c not in (9,10) for c in data):
        raise ValueError('empty, unterminated or control-containing output')
    text=data.decode('utf-8','strict')
    lines=text.splitlines(); cols=[i for i,line in enumerate(lines) if re.fullmatch(r'\s*PID\s+USER\s+%CPU\s+RSS\s+S\s+COMMAND\s*',line)]
    if len(cols)!=1: raise ValueError('missing or duplicate header')
    head=lines[:cols[0]]
    if (len(head) not in (3,4) or
        not re.fullmatch(r'top - load 1\.25 1\.50 1\.75  procs (?:0|[1-9][0-9]*)  sort CPU  every 0s',head[0]) or
        head[1]!='Mem: 8000 kB total, 5000 kB used, 3000 kB avail' or
        head[2]!='Swap: 2000 kB total, 750 kB used, 1250 kB free' or
        (len(head)==4 and head[3]!='(--once snapshot)')):
        raise ValueError('unexpected or incomplete documented header')
    rx=re.compile(r'\s*(\d+)\s+(\S+)\s+(\d+\.\d)\s+(\d+)\s+([A-Za-z])\s+(.+)')
    result=[]
    for line in lines[cols[0]+1:]:
        m=rx.fullmatch(line)
        if not m: raise ValueError('malformed extra row')
        row=(int(m[1]),m[2],float(m[3]),int(m[4]),m[5],m[6])
        if any(x[0]==row[0] for x in result): raise ValueError('duplicate PID')
        result.append(row)
    return head,result


def parser_controls():
    header=(b'top - load 1.25 1.50 1.75  procs 1  sort CPU  every 0s\n'
            b'Mem: 8000 kB total, 5000 kB used, 3000 kB avail\n'
            b'Swap: 2000 kB total, 750 kB used, 1250 kB free\n'
            b'(--once snapshot)\n  PID USER %CPU RSS S COMMAND\n')
    row=b'  101 root 10.0 16 S steady --fixture\n'
    if parse_rows(header+row)[1]!=[(101,'root',10.0,16,'S','steady --fixture')]: raise RuntimeError('positive row parser')
    if parse_rows(header)[1]!=[]: raise RuntimeError('empty row parser control')
    for bad in (b'',header+row+row,row+header+b'extra\n',header+b'broken\n',
                header.replace(b'(--once snapshot)\n',b'extra\n'),header+row[:-1],header+b'\xff\n'):
        try: parse_rows(bad)
        except (ValueError,UnicodeError): continue
        raise RuntimeError('negative row parser')
    entry=struct.pack('<QqHB',1,0,24,4)+b'777\0\0'
    if dirent_names(entry)!=['777']: raise RuntimeError('dirent positive control')
    for bad in (entry[:19], entry[:16]+struct.pack('<H',64)+entry[18:]):
        try: dirent_names(bad)
        except ValueError: continue
        raise RuntimeError('invalid dirent accepted')
    literal = b'101 (steady) S 1 1 1 0 -1 0 0 0 0 0 10 10 0 0 20 0 1 0 1001 1048576 4\n'
    if proc_stat(101,'steady','S',10,10,1001,4)!=literal:
        raise RuntimeError('proc(5) field position control')
    dump('parser-controls.json',{'positive':2,'negative':7,'dirent_positive':1,'dirent_negative':2,'literal_proc5_control':True,'complete':True})


def assess(scenario):
    meta=json.loads((HOME/'candidate.json').read_text()); result=[]
    terminal=[e for e in meta['events'] if e.get('kind')=='exit']
    if len(terminal)!=1 or terminal[0].get('status')!=0 or terminal[0].get('signal')!=0: result.append('candidate status')
    if (HOME/'candidate.err').read_bytes(): result.append('candidate stderr')
    try: header,rows=parse_rows((HOME/'candidate.out').read_bytes())
    except (ValueError,UnicodeError) as exc: header=[]; rows=[]; result.append('table: '+str(exc))
    unit=os.sysconf('SC_PAGE_SIZE')//1024
    expected={'malformed':[(101,'root',10.0,4*unit,'S','steady --fixture')],
              'vanish':[(101,'root',10.0,4*unit,'S','steady --fixture')],
              'empty':[], 'proc-rollback':[(101,'root',0.0,4*unit,'S','steady --fixture')],
              'cpu-rollback':[(101,'root',0.0,4*unit,'S','steady --fixture')],
              'guest':[(101,'root',25.0,4*unit,'S','steady --fixture')],
              'lifecycle':[(101,'root',10.0,4*unit,'S','steady --fixture'),
                           (303,'root',0.0,8*unit,'R','new --fixture'),
                           (202,'root',0.0,6*unit,'S','reused --fixture')]}[scenario]
    if rows!=expected: result.append('rows or values')
    count=len(expected)
    required_header=[f'top - load 1.25 1.50 1.75  procs {count}  sort CPU  every 0s',
                     'Mem: 8000 kB total, 5000 kB used, 3000 kB avail',
                     'Swap: 2000 kB total, 750 kB used, 1250 kB free']
    if any(header.count(line)!=1 for line in required_header): result.append('documented header fields')
    trace_problems=trace_checks(meta,scenario)
    if trace_problems: result.append('input observation inconclusive')
    dump('assertions.json',{'scenario':scenario,'expected_rows':expected,'actual_rows':rows,'header':header,
          'candidate_terminal':terminal,'observation_problems':trace_problems,'problems':result,
          'qualification':'raw comparison; primary per-clause evidence gate required'})
    if result: return 1
    print(scenario+'-ok'); return 0


def inner(scenario, outer_ns):
    global DIAGNOSTICS_ALLOWED
    guard(False,mounted=False)
    if scenario not in SCENARIOS: raise RuntimeError('unknown scenario')
    if os.getgid()!=0 or os.getegid()!=0: raise RuntimeError('unexpected namespace gid')
    realfd=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        before=proc_context(realfd,outer_ns=outer_ns)
        identity=protected_identity(before['overflow_uid'],before['overflow_gid'])
        DIAGNOSTICS_ALLOWED=True
        if pwd.getpwuid(0).pw_name!='root': raise RuntimeError('uid 0 name differs')
        os.environ['LIFECYCLE_REALPROC_FD']=str(realfd)
        os.environ['LIFECYCLE_OUTER_NS']=outer_ns
        os.environ['LIFECYCLE_MNT_NS']=before['mount_namespace']
        reset_live(scenario)
        mount=subprocess.run(['/usr/bin/mount','-n','--bind',str(LIVE),'/proc'],capture_output=True,timeout=5)
        record={'status':mount.returncode,'stdout_base64':base64.b64encode(mount.stdout).decode(),
                'stderr_base64':base64.b64encode(mount.stderr).decode(),'before':before,'identity':identity}
        dump('mount.json',record)
        if mount.returncode: raise RuntimeError('private proc mount failed')
        after=proc_context(realfd,expected_ns=before['mount_namespace'],outer_ns=outer_ns)
        proof=guard(False)
        record['after']=after; record['mounted_guard']=proof; dump('mount.json',record)
        controls=subprocess.run([str(OBSERVER),'descriptor-controls'],capture_output=True,timeout=5,pass_fds=(realfd,))
        record['descriptor_controls']={'status':controls.returncode,
            'stdout_base64':base64.b64encode(controls.stdout).decode(),
            'stderr_base64':base64.b64encode(controls.stderr).decode()}
        dump('mount.json',record)
        try: lines=[json.loads(line) for line in controls.stdout.splitlines()]
        except (ValueError,UnicodeError): raise RuntimeError('malformed descriptor controls')
        if (controls.returncode or controls.stderr or len(lines)!=2 or lines[0].get('kind')!='guard'
            or lines[1].get('kind')!='descriptor-controls' or not lines[1].get('complete')
            or any(lines[1].get(key) is not True for key in ('replacement','rebind','range','dup_source','failed_dup'))):
            raise RuntimeError('descriptor controls failed')
        native_result=run_observed(scenario,'native'); control(scenario,native_result)
        reset_live(scenario)
        proof=guard(False)
        dump('preconditions.json',{'guard':proof,'mounted':True,'native_control':True,
             'uid_map':before['uid_map'],'gid_map':before['gid_map'],
             'namespace_uid':os.getuid(),'namespace_euid':os.geteuid(),
             'namespace_gid':os.getgid(),'namespace_egid':os.getegid(),
             'initial_manifest':manifest(LIVE)})
        candidate_result=run_observed(scenario,'candidate')
        if (candidate_result['observer_status']!=0 or candidate_result['timeout'] or not candidate_result['complete']
            or candidate_result['parse_error'] or candidate_result['observer_stderr_base64']):
            raise RuntimeError('candidate observation infrastructure failure')
        dump('setup-stage.json',{'complete':True,'scenario':scenario})
        return 0
    finally: os.close(realfd)


def anchor(scenario, outer_ns):
    identity=guard()
    if os.readlink('/proc/self/ns/mnt')!=outer_ns: raise RuntimeError('outer mount namespace changed')
    command=['/usr/bin/unshare','--user','--map-root-user','--mount',
             '/usr/bin/python3',HELPER,'inner',scenario,outer_ns]
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    timed_out=False
    try: out,err=proc.communicate(timeout=32)
    except subprocess.TimeoutExpired as exc:
        # The outer controller cleans the whole group while this anchor lives.
        timed_out=True; out=exc.stdout or b''; err=exc.stderr or b''
    dump('namespace.json',{'status':proc.returncode,'timeout':timed_out,'outer_guard':identity,
         'stdout_base64':base64.b64encode(out).decode(),'stderr_base64':base64.b64encode(err).decode()})
    sys.stdout.write('ANCHOR_READY\n'); sys.stdout.flush()
    # Keep the group leader alive until the controller deliberately cleans it.
    if sys.stdin.buffer.read(1)!=b'Q': raise RuntimeError('anchor protocol ended unexpectedly')
    return 0


def setup(scenario):
    identity=guard()
    if scenario not in SCENARIOS: raise RuntimeError('unknown scenario')
    if not hasattr(os,'pidfd_open') or not hasattr(os,'P_PIDFD'):
        raise RuntimeError('pidfd support is required for anchored cleanup')
    probe=os.pidfd_open(os.getpid(),0)
    os.close(probe)
    outer_ns=os.readlink('/proc/self/ns/mnt')
    parser_controls()
    fixtures=fixture(scenario)
    for i,(cpu,records) in enumerate(fixtures): write_tree(CASE/('snapshot-'+str(i)),cpu,records)
    dump('snapshots.json',{'scenario':scenario,'epochs':[manifest(CASE/('snapshot-'+str(i))) for i in (0,1)],
         'guest_uid':os.getuid(),'guest_euid':os.geteuid(),'guard':identity,'outer_mount_namespace':outer_ns})
    result=subprocess.run(['/usr/bin/gcc','-O2','-Wall','-Wextra','-Werror',SOURCE,'-o',str(OBSERVER)],capture_output=True,timeout=15)
    dump('compile.json',{'status':result.returncode,'stdout_base64':base64.b64encode(result.stdout).decode(),
                         'stderr_base64':base64.b64encode(result.stderr).decode()})
    if result.returncode: raise RuntimeError('observer compilation failed')
    command=['/usr/bin/python3',HELPER,'anchor',scenario,outer_ns]
    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    cleanup={'anchor_pid':proc.pid,'ready':False,'live_proven':False,'group_signal_attempted':False}
    pidfd=None; ready=b''; error=None
    try:
        pidfd=os.pidfd_open(proc.pid,0)
        if select.select([proc.stdout],[],[],38)[0]: ready=proc.stdout.readline(128)
        cleanup['ready']=(ready==b'ANCHOR_READY\n')
        # WNOWAIT avoids reaping the leader and its pinned pidfd ensures that
        # an unexpected exit is never confused with a later reused PID.
        exited=os.waitid(os.P_PIDFD,pidfd,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if exited is not None:
            error='anchor exited before group cleanup'
        else:
            cleanup['live_proven']=True
            cleanup['group_signal_attempted']=True
            try: os.killpg(proc.pid,signal.SIGKILL); cleanup['group_signal']='SIGKILL'
            except ProcessLookupError: error='anchored group disappeared before cleanup'
        if not cleanup['ready'] and error is None: error='anchor did not report completion'
    except (OSError,ValueError) as exc:
        error='anchor/pidfd cleanup failed: '+repr(exc)
    finally:
        # Reap only after deciding whether the still-live anchor can be signaled.
        if cleanup['group_signal_attempted'] or not cleanup['live_proven']:
            try: out,err=proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                out=b''; err=b'anchor could not be reaped without unsafe signaling'
                error=error or 'anchor cleanup incomplete'
        else: out=b''; err=b''
        if pidfd is not None: os.close(pidfd)
    if cleanup['group_signal_attempted'] and proc.returncode!=-signal.SIGKILL:
        error=error or 'anchor termination not confirmed'
    cleanup.update({'anchor_status':proc.returncode,'anchor_stdout_tail_base64':base64.b64encode(out).decode(),
                    'anchor_stderr_base64':base64.b64encode(err).decode(),'error':error})
    namespace_file=HOME/'namespace.json'
    record=json.loads(namespace_file.read_text()) if namespace_file.exists() else {}
    record['cleanup']=cleanup; dump('namespace.json',record)
    if error: raise RuntimeError(error)
    if record.get('timeout') or record.get('status')!=0: raise RuntimeError('guest fixture setup failed')
    return 0


if __name__=='__main__':
    try:
        mode=sys.argv[1]; scenario=sys.argv[2]
        if mode=='setup': rc=setup(scenario)
        elif mode=='inner': rc=inner(scenario,sys.argv[3])
        elif mode=='anchor': rc=anchor(scenario,sys.argv[3])
        elif mode=='native': native(scenario); rc=0
        elif mode in ('advance','vanish'): action(mode,scenario,sys.argv[3]); rc=0
        elif mode=='assess': guard(); rc=assess(scenario)
        else: raise RuntimeError('unknown mode')
        raise SystemExit(rc)
    except Exception as exc:
        try:
            if DIAGNOSTICS_ALLOWED:
                with (HOME/'failures.jsonl').open('a') as failures:
                    failures.write(json.dumps({'mode':sys.argv[1],'error':repr(exc)})+'\n')
        except Exception: pass
        print('fixture error: '+repr(exc),file=sys.stderr); raise SystemExit(125)
