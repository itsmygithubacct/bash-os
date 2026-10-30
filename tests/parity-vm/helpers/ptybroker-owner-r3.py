#!/usr/bin/python3
"""Disposable guest only: provisional owner-path trace. Not source-qualified."""
import ctypes, errno, json, os, re, resource, signal, stat, struct, subprocess, sys, tempfile, time, uuid
from pathlib import Path
H=Path('/tmp/parity-home'); C=Path('/tmp/parity-case'); TARGET='/root'
PTRACE_TRACEME=0; PTRACE_PEEKDATA=2; PTRACE_SYSCALL=24; PTRACE_SETOPTIONS=0x4200; PTRACE_GET_SYSCALL_INFO=0x420e; PTRACE_GETEVENTMSG=0x4201
OPTIONS=1|2|4|8|16|0x100000; ARCH=0xc000003e
MAX_EVENTS=1000; MAX_BYTES=512*1024; DEADLINE=20
lib=ctypes.CDLL(None,use_errno=True);lib.ptrace.restype=ctypes.c_long
class Incomplete(Exception): pass

def ptrace(op,pid=0,addr=0,data=0):
    ctypes.set_errno(0); ret=lib.ptrace(op,pid,ctypes.c_void_p(addr),ctypes.c_void_p(data)); e=ctypes.get_errno()
    if ret==-1 and e: raise Incomplete('ptrace %s errno %s'%(op,e))
    return ret

def read_child(pid,addr,limit=512):
    result=bytearray()
    for off in range(0,limit,8):
        result.extend(struct.pack('=Q',ptrace(PTRACE_PEEKDATA,pid,addr+off)&((1<<64)-1)))
        if b'\0' in result:
            data=bytes(result).split(b'\0',1)[0]
            return data.decode('utf-8','strict'),data.hex()
    raise Incomplete('nonterminated path')

def read_exact(pid,addr,length):
    if not 0 < length <= 256: raise Incomplete('fixed read bounds')
    result=b''.join(struct.pack('=Q',ptrace(PTRACE_PEEKDATA,pid,addr+off)&((1<<64)-1)) for off in range(0,length,8))
    return result[:length]

def read_fixed(pid,addr,length):
    return read_exact(pid,addr,length).decode('ascii','replace')

def info(pid):
    buf=ctypes.create_string_buffer(128);n=ptrace(PTRACE_GET_SYSCALL_INFO,pid,128,ctypes.addressof(buf)); raw=buf.raw
    if n<24 or struct.unpack_from('=I',raw,4)[0]!=ARCH: raise Incomplete('unexpected syscall architecture')
    if raw[0]==1 and n>=80: return 'entry',struct.unpack_from('=7Q',raw,24),raw[:min(n,128)].hex()
    if raw[0]==2 and n>=33: return 'exit',struct.unpack_from('=q',raw,24)[0],raw[:min(n,128)].hex()
    raise Incomplete('unsupported syscall record')

def atomic(path,obj):
    temp=path.with_name(path.name+'.tmp'); data=(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(data)>MAX_BYTES: raise Incomplete('record cap')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f: f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)

def ident(pid):
    raw=Path('/proc/%d/stat'%pid).read_text();v=raw.rsplit(')',1)[1].split();status=Path('/proc/%d/status'%pid).read_text();uid=next(x.split()[1:5] for x in status.splitlines() if x.startswith('Uid:'))
    if uid!=['0']*4: raise Incomplete('child namespace uid differs')
    e=os.stat('/proc/%d/exe'%pid);return {'pid':pid,'ppid':int(v[1]),'pgrp':int(v[2]),'session':int(v[3]),'starttime':int(v[19]),'exe_dev':e.st_dev,'exe_ino':e.st_ino,'namespace_uid':[int(x) for x in uid]}

def fs(path):
    s=os.lstat(path);return {'path':path,'dev':s.st_dev,'ino':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'directory':stat.S_ISDIR(s.st_mode),'symlink':stat.S_ISLNK(s.st_mode)}

def waitstop(pid,deadline):
    while time.monotonic()<deadline:
        got,s=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
        if got:return s
        time.sleep(.001)
    raise Incomplete('owned trace deadline')

def descriptor_snapshot(pid,target):
    root=Path('/proc')/str(pid)/'fd';names=sorted(root.iterdir(),key=lambda p:int(p.name))
    if len(names)>128:raise Incomplete('descriptor snapshot cap')
    expected=os.lstat(target);records=[]
    for item in names:
        if not item.name.isdigit():raise Incomplete('invalid fd name')
        dest=os.readlink(item);st=os.stat(item)
        if (st.st_dev,st.st_ino)==(expected.st_dev,expected.st_ino) or dest==target or dest.startswith(target+'/'):
            raise Incomplete('target preopened before begin')
        records.append({'fd':int(item.name),'link':dest,'dev':st.st_dev,'ino':st.st_ino,'mode':st.st_mode})
    return records


def trace(candidate, target, tag, token, native=False):
    out=tempfile.TemporaryFile(dir=H);err=tempfile.TemporaryFile(dir=H);pidfd=None;p=None;reaped=False;events=[];stage=0;active=None;result=None;begin_fds=None
    # Only builtins execute after BEGIN; stdout result is read from the actual traced write.
    script='type -t ptybroker > "$HOME/owner-builtin-kind" || exit 125; IFS= read -r k < "$HOME/owner-builtin-kind" || exit 125; [[ $k == builtin ]] || exit 125; printf "BEGIN\\n"; ptybroker list "$1"; r=$?; printf "RESULT %d\\n" "$r"; exit 0'
    native_script='import os,sys; os.write(1,b"BEGIN\\n"); os.lstat(sys.argv[1]);\ntry:\n f=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY); os.close(f); n=0\nexcept OSError as e: n=e.errno\nos.write(1,("RESULT %d\\n"%n).encode())'
    def before():
        resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_BYTES,MAX_BYTES));resource.setrlimit(resource.RLIMIT_CORE,(0,0));ptrace(PTRACE_TRACEME)
    try:
        argv=[candidate,'-I','-c',native_script,target] if native else [candidate,'--noprofile','--norc','-c',script,'owner-fixture',target]
        p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,preexec_fn=before,start_new_session=True,env={'HOME':str(H),'PATH':'/empty','LC_ALL':'C','BASH_ENV':'','ENV':''})
        deadline=time.monotonic()+DEADLINE;pidfd=os.pidfd_open(p.pid,0);s=waitstop(p.pid,deadline)
        if not os.WIFSTOPPED(s) or os.WSTOPSIG(s)!=signal.SIGTRAP:raise Incomplete('missing exec stop')
        child=ident(p.pid);st=os.stat(candidate)
        if child['ppid']!=os.getpid() or child['pgrp']!=p.pid or child['session']!=p.pid or (child['exe_dev'],child['exe_ino'])!=(st.st_dev,st.st_ino):raise Incomplete('child identity mismatch')
        atomic(H/(tag+'-identity.json'),child)
        ack=H/(tag+'-outer-uid.json');end=time.monotonic()+5
        while not ack.is_file():
            if time.monotonic()>end:raise Incomplete('outer uid proof deadline')
            time.sleep(.01)
        external=json.loads(ack.read_text())
        if external.get('identity')!=child or external.get('outer_uid')!=[2000]*4 or external.get('namespace_uid')!=[0]*4 or external.get('ancestry_proven') is not True:
            raise Incomplete('outer uid proof mismatch')
        ptrace(PTRACE_SETOPTIONS,p.pid,0,OPTIONS);ptrace(PTRACE_SYSCALL,p.pid)
        while True:
            s=waitstop(p.pid,deadline)
            if os.WIFEXITED(s) or os.WIFSIGNALED(s):reaped=True;break
            event=s>>16
            if event:
                # Fork/clone descendants are automatically traced. Never trust a
                # result from an expanded tree; identify the exact event child,
                # stop it by pidfd, and retain the event as infrastructure data.
                msg=ctypes.c_ulonglong();ptrace(PTRACE_GETEVENTMSG,p.pid,0,ctypes.addressof(msg))
                fault={'event':event,'event_message':msg.value,'parent':child,'stage':stage,'wait_status':s}
                atomic(H/(tag+'-trace-fault.json'),fault)
                if event in (1,2,3) and msg.value:
                    dfd=os.pidfd_open(msg.value,0)
                    try:
                        signal.pidfd_send_signal(dfd,signal.SIGKILL)
                    finally:os.close(dfd)
                raise Incomplete('fork/clone/exec event; candidate result not promoted')
            if not os.WIFSTOPPED(s) or os.WSTOPSIG(s)!=(signal.SIGTRAP|0x80):raise Incomplete('unexpected trace stop')
            op,data,raw=info(p.pid)
            if op=='entry':
                nr=data[0]; args=data[1:]; entry={'nr':nr,'args':list(args),'entry_raw':raw};active=entry
                if nr in (2,4,6,80): entry['path'],entry['path_hex']=read_child(p.pid,args[0])
                elif nr in (257,262,332,437): entry['path'],entry['path_hex']=read_child(p.pid,args[1])
                if nr==1 and args[0]==1 and 0<args[2]<=64:entry['stdout_write']=read_fixed(p.pid,args[1],args[2])
            else:
                if active is None: raise Incomplete('unpaired syscall exit')
                active['ret']=data;active['exit_raw']=raw
                if data==0 and active.get('nr') in (6,262) and active.get('path')==target:
                    address=active['args'][1] if active['nr']==6 else active['args'][2]
                    active['stat_hex']=read_exact(p.pid,address,144).hex()
                if active.get('stdout_write')=='BEGIN\n' and data==6:
                    if stage!=0:raise Incomplete('duplicate begin marker')
                    begin_fds=descriptor_snapshot(p.pid,target)
                    stage=1
                if stage==1:
                    if active['nr']==318 and ((active['args'][1],active['args'][2],active['ret']) not in ((8,1,8),(32,0,32))):
                        # Save exact ptrace bytes before rejecting; never a product verdict.
                        atomic(H/(tag+'-getrandom-rejected.json'),{'schema':'owner-getrandom-rejected-v1','token':token,'tag':tag,'target':target,'stage':stage,'identity':child,'event':active})
                        dirfd=os.open(H,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                        try:os.fsync(dirfd)
                        finally:os.close(dirfd)
                        raise Incomplete('unreviewed getrandom observation')
                    events.append(active)
                    if len(events)>MAX_EVENTS:raise Incomplete('event cap')
                    marker=active.get('stdout_write','')
                    if marker.startswith('RESULT ') and marker.endswith('\n') and data==len(marker.encode()):
                        result=int(marker[7:-1]);stage=2
                        out.flush();err.flush();out.seek(0);err.seek(0);rawout=out.read(MAX_BYTES+1);rawerr=err.read(MAX_BYTES+1)
                        if len(rawout)>MAX_BYTES or len(rawerr)>MAX_BYTES:raise Incomplete('output cap')
                        atomic(H/(tag+'-reached.json'),{'candidate_identity':child,'target':target,'status':result,'begin_fds':begin_fds,'stdout_hex':rawout.hex(),'stderr_hex':rawerr.hex(),'events':events})
                active=None
            ptrace(PTRACE_SYSCALL,p.pid)
        if result is None or not os.WIFEXITED(s) or os.WEXITSTATUS(s)!=0:raise Incomplete('no completed trace and clean shell')
        return {'status':result,'identity':child,'reached':True,'raw_wait_status':s,'reaped':True}
    finally:
        if p is not None and not reaped:
            if pidfd is not None:
                try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                except ProcessLookupError:pass
            try:os.waitpid(p.pid,0)
            except ChildProcessError:pass
        if pidfd is not None:os.close(pidfd)
        out.close();err.close()

def classify(record, expected):
    events=record['events']; st_events=[]; path_events=[]
    path_syscalls={2,4,6,21,80,81,82,83,85,87,89,161,165,257,258,262,263,264,267,269,304,316,322,332,437,439}
    nonpath={0,1,3,5,8,9,10,11,12,13,14,15,16,20,39,60,72,96,102,104,107,108,110,131,158,186,202,218,228,230,231,273,302,318,334}
    for event in events:
        nr=event['nr'];path=event.get('path')
        if nr not in path_syscalls and nr not in nonpath:raise Incomplete('unreviewed syscall during owner observation: %d'%nr)
        if nr==318 and ((event['args'][1],event['args'][2],event['ret']) not in ((8,1,8),(32,0,32))):raise Incomplete('unreviewed getrandom observation')
        if nr in path_syscalls:
            if nr in (6,262) and path==expected['path'] and event['ret']==0:
                if nr==262 and (event['args'][0] not in (0xffffffffffffff9c,0xffffff9c) or event['args'][3]!=0x100):
                    raise Incomplete('target stat form differs')
                raw=bytes.fromhex(event['stat_hex']);dev,ino=struct.unpack_from('=QQ',raw,0);mode,uid,gid=struct.unpack_from('=III',raw,24)
                if (dev,ino,mode&0o777,uid,gid)!=(expected['dev'],expected['ino'],expected['mode'],expected['uid'],expected['gid']):raise Incomplete('candidate stat target mismatch')
                st_events.append(event)
            else:path_events.append(event)
    if not st_events:raise Incomplete('candidate target stat not observed')
    if record['status']==0:return 'FAIL'
    if path_events:raise Incomplete('additional path syscall may explain refusal')
    stderr=bytes.fromhex(record['stderr_hex']);stdout=bytes.fromhex(record['stdout_hex'])
    if stdout!=('BEGIN\nRESULT %d\n'%record['status']).encode():raise Incomplete('candidate output is ambiguous')
    if re.fullmatch(rb'(?:owner-fixture: (?:line [0-9]+: )?)?ptybroker: list: Permission denied\n',stderr):return 'PASS'
    raise Incomplete('nonzero result is not an attributable list EACCES')

def main():
    if len(sys.argv)!=2 or os.getuid()!=0 or os.geteuid()!=0 or Path.cwd()!=C or os.environ.get('HOME')!=str(H):raise Incomplete('mapped namespace uid or paths')
    uid_map=Path('/proc/self/uid_map').read_text().split();gid_map=Path('/proc/self/gid_map').read_text().split()
    if uid_map!=['0','2000','1'] or gid_map!=['0','2000','1'] or os.getgid()!=0 or os.getegid()!=0:raise Incomplete('namespace is not singly mapped from guest UID/GID 2000')
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise Incomplete('guest vendor')
    token=str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()));before=fs(TARGET)
    if not before['directory'] or before['symlink'] or before['uid']==os.geteuid() or before['mode']!=0o700:raise Incomplete('foreign owner 0700 target absent')
    owned=H/'owner-good';owned.mkdir(mode=0o700);good_before=fs(str(owned))
    if good_before['uid']!=os.geteuid() or good_before['mode']!=0o700:raise Incomplete('owned control invalid')
    data={'token':token,'uid_map':uid_map,'gid_map':gid_map,'parent_before':fs('/'),'target_before':before,'owned_before':good_before};atomic(H/'owner-preflight.json',data)
    native=trace('/usr/bin/python3',TARGET,'owner-native',token,native=True)
    native_raw=json.loads((H/'owner-native-reached.json').read_text()); native_ops=native_raw['events']
    if bytes.fromhex(native_raw['stdout_hex'])!=b'BEGIN\nRESULT 13\n' or bytes.fromhex(native_raw['stderr_hex'])!=b'':raise Incomplete('native control output differs')
    if native['status']!=errno.EACCES or not any(e.get('path')==TARGET and e['nr'] in (6,262) and e['ret']==0 for e in native_ops) or not any(e.get('path')==TARGET and e['nr'] in (2,257) and e['ret']==-errno.EACCES for e in native_ops):raise Incomplete('native target stat/open calibration differs')
    good=trace(sys.argv[1],str(owned),'owner-control',token)
    good_raw=json.loads((H/'owner-control-reached.json').read_text())
    if good['status']!=0 or bytes.fromhex(good_raw['stdout_hex'])!=b'BEGIN\nRESULT 0\n' or bytes.fromhex(good_raw['stderr_hex'])!=b'':raise Incomplete('owned positive control failed')
    if not any(e.get('path')==str(owned) and e['nr'] in (6,262) and e['ret']==0 and 'stat_hex' in e for e in good_raw['events']):raise Incomplete('owned control stat missing')
    result=trace(sys.argv[1],TARGET,'owner-candidate',token);after=fs(TARGET)
    atomic(H/'owner-final.json',{'token':token,'target_before':before,'target_after':after,'owned_before':good_before,'native':native,'control':good,'candidate':result})
    if before!=after:raise Incomplete('target changed')
    reached=json.loads((H/'owner-candidate-reached.json').read_text())
    verdict=classify(reached,before)
    atomic(H/'owner-verdict.json',{'candidate_behavior':verdict,'product_credit':False,'scope':'requires independent provenance and raw validation'})
    if verdict=='FAIL':
        print('owner-mismatch');return 1
    print('owner-observed');return 0
if __name__=='__main__':
    try:status=main()
    except BaseException as e:print('OWNER-INCOMPLETE: '+repr(e),file=sys.stderr);sys.exit(125)
    else:sys.exit(status)
