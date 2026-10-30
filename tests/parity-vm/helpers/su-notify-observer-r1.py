#!/usr/bin/python3
"""Guest-only owned SU notification observer; never an authority-device emulator."""
import ctypes,errno,fcntl,importlib.util,json,os,platform,select,signal,struct,sys,time,uuid
from pathlib import Path
CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home');DEVICE='/dev/bashos-auth'
LISTENER=Path('/opt/bashos-parity/harness/helpers/auth-client-listener.py')

def proc(pid):
    p=Path('/proc')/str(pid);s=(p/'stat').read_text().rsplit(')',1)[1].split();lines=(p/'status').read_text().splitlines()
    uid=next([int(v) for v in line.split()[1:]] for line in lines if line.startswith('Uid:'))
    gid=next([int(v) for v in line.split()[1:]] for line in lines if line.startswith('Gid:'))
    if uid!=[2000]*4 or gid!=[2000]*4:raise RuntimeError('tracee UID/GID not 2000')
    return {'pid':pid,'ppid':int(s[1]),'birth':int(s[19]),'state':s[0],'uid':uid,'gid':gid}

def pathmem(pid,address):
    fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY|os.O_CLOEXEC)
    try:
        out=bytearray()
        while len(out)<4096:
            pos=address+len(out);data=os.pread(fd,min(128,4096-(pos%4096)),pos)
            if not data:raise RuntimeError('unreadable pathname')
            n=data.find(b'\0')
            if n>=0:return os.fsdecode(bytes(out)+data[:n])
            out.extend(data)
        raise RuntimeError('overlong pathname')
    finally:os.close(fd)

def main():
    if not __debug__ or os.getresuid()!=(2000,2000,2000) or os.getresgid()!=(2000,2000,2000) or not Path.cwd().is_relative_to(CASE) or platform.machine()!='x86_64':raise RuntimeError('nonroot guest guard')
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise RuntimeError('not guest')
    cfg=json.loads(Path(sys.argv[1]).read_text());mode=cfg['mode'];trace=Path(cfg['trace']).resolve();armed=Path(cfg['armed']).resolve();child_file=Path(cfg['child_file']).resolve()
    if mode not in ('noexec','fork','wait','control-fork','control-wait','control-exec') or not trace.is_relative_to(HOME) or not armed.is_relative_to(HOME) or not child_file.is_relative_to(HOME):raise RuntimeError('invalid scope')
    spec=importlib.util.spec_from_file_location('owned_listener',LISTENER);seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq);seq.BOOTSTRAP_LOG=Path(str(trace)+'.bootstrap')
    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,unused):
        status=None;parent_identity=None;execs=0;injected=False;owned_child=None;events=0;pending_child=None;pending_reap=None
        with trace.open('w') as log:
            def emit(e):
                nonlocal events
                events+=1
                if events>4096:raise RuntimeError('notification limit')
                if 'notification_id' in e:
                    before=e['notifying'];after=proc(before['pid'])
                    if any(after[k]!=before[k] for k in ('pid','ppid','birth','uid','gid')):raise RuntimeError('notifying identity changed')
                    e['identity_rechecked']=True
                e['sequence']=events;e['monotonic_ns']=time.monotonic_ns();log.write(json.dumps(e,sort_keys=True)+'\n');log.flush();os.fsync(log.fileno())
            def reply(ident,kind,code=0):
                data=struct.pack('<QqiI',ident,0,-code if kind=='errno' else 0,seq.FLAG_CONTINUE if kind=='continue' else 0)
                fcntl.ioctl(listener,seq.NOTIF_SEND,data)
            try:
                while status is None:
                    done,w=os.waitpid(child,os.WNOHANG)
                    if done:status=w;break
                    ready,_,_=select.select([listener],[],[],.05)
                    if not ready:continue
                    request=bytearray(80)
                    try:fcntl.ioctl(listener,seq.NOTIF_RECV,request,True)
                    except OSError as ex:
                        if ex.errno in (errno.EINTR,errno.ENOENT):continue
                        raise
                    ident,pid,_,nr,arch,ip=struct.unpack_from('<QIIiIQ',request);args=struct.unpack_from('<6Q',request,32)
                    raw=lib.seccomp_syscall_resolve_num_arch(0,nr);name=ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                    identity=proc(pid);event={'syscall':name,'notification_id':ident,'notifying':identity,'arch':arch,'ip':ip,'args':list(args),'reply':'continue'}
                    if name in ('execve','execveat'):
                        event['path']=pathmem(pid,args[0] if name=='execve' else args[1]);execs+=1
                        if execs==1:
                            if pid!=child or event['path']!=cfg['program']:raise RuntimeError('unexpected bootstrap exec')
                            parent_identity=identity;event['phase']='bootstrap'
                        elif mode in ('wait','control-wait') and pid==child and event['path']=='/usr/bin/python3' and injected:
                            event['phase']='owned-reaper'
                        elif mode=='control-exec' and pid==child:
                            event['phase']='independent-positive-exec';event['reply']='errno:13';emit(event);reply(ident,'errno',errno.EACCES);continue
                        else:
                            event['phase']='unexpected-target-exec';event['reply']='errno:13';emit(event);reply(ident,'errno',errno.EACCES);continue
                    elif name in ('fork','vfork','clone','clone3'):
                        if parent_identity is None or pid!=child or identity['birth']!=parent_identity['birth'] or not armed.is_file() or armed.read_text().strip()!=str(child):raise RuntimeError('unattributed creation notification')
                        if name=='clone':
                            flags=args[0]
                            if flags & 0x10000 or flags & 0xff != signal.SIGCHLD:raise RuntimeError('clone is not a process fork')
                            event['clone_flags']=flags
                        elif name=='clone3':
                            if args[1]<40:raise RuntimeError('short clone3 arguments')
                            fd=os.open('/proc/%d/mem'%pid,os.O_RDONLY|os.O_CLOEXEC)
                            try:data=os.pread(fd,40,args[0])
                            finally:os.close(fd)
                            if len(data)!=40:raise RuntimeError('unreadable clone3 arguments')
                            flags,_,_,_,exit_signal=struct.unpack('<5Q',data)
                            if flags & 0x10000 or exit_signal!=signal.SIGCHLD:raise RuntimeError('clone3 is not a process fork')
                            event['clone_flags']=flags;event['clone_exit_signal']=exit_signal
                        event['phase']='armed-owned-parent-creation'
                        if mode in ('fork','control-fork') and not injected:
                            injected=True;event['reply']='errno:11';emit(event);reply(ident,'errno',errno.EAGAIN);continue
                        if mode not in ('wait','control-wait','noexec','control-exec') or owned_child is not None:raise RuntimeError('unexpected further creation')
                    elif name in ('wait4','waitid'):
                        if parent_identity is None or pid!=child or identity['birth']!=parent_identity['birth']:raise RuntimeError('unattributed wait')
                        if mode in ('wait','control-wait') and not injected:
                            if name!='wait4' or args[2]!=0:raise RuntimeError('wait operation not blocking wait4; review architecture')
                            target=ctypes.c_int(args[0]&0xffffffff).value
                            if target<=1:raise RuntimeError('non-specific wait target')
                            initial=proc(target)
                            if initial['ppid']!=child:raise RuntimeError('wait target not direct owned child')
                            owned_child=initial;event['target_before']=initial;event['phase']='owned-wait-injection';event['reply']='errno:10'
                            child_file.write_text(str(target)+'\n');injected=True;emit(event);reply(ident,'errno',errno.ECHILD);continue
                        event['phase']='owned-post-injection-wait' if injected else 'other-wait'
                        if mode in ('wait','control-wait') and injected:
                            if name!='wait4' or ctypes.c_int(args[0]&0xffffffff).value!=owned_child['pid']:raise RuntimeError('unexpected reap target')
                            now=proc(owned_child['pid'])
                            if now['ppid']!=child or now['birth']!=owned_child['birth']:raise RuntimeError('reap target identity changed')
                            event['target_before_reap']=now;event['reply']='deferred-until-owned-child-held';emit(event);pending_reap=ident
                            if pending_child is not None:
                                held_id,held_identity=pending_child
                                if held_identity['pid']!=now['pid'] or held_identity['birth']!=now['birth']:raise RuntimeError('held child differs')
                                emit({'syscall':'release-owned-reap','notifying':now,'reply':'continue'});reply(held_id,'continue');reply(pending_reap,'continue');pending_child=None;pending_reap=None
                            continue
                    elif name=='prctl' and args[0]==4 and args[1]==0 and mode in ('wait','control-wait') and pid!=child:
                        if identity['ppid']!=child or pending_child is not None:raise RuntimeError('unexpected child hold')
                        event['phase']='owned-child-held-before-auth';event['reply']='deferred-until-parent-reaper';emit(event);pending_child=(ident,identity)
                        if pending_reap is not None:
                            if owned_child is None or identity['pid']!=owned_child['pid'] or identity['birth']!=owned_child['birth']:raise RuntimeError('held child differs from wait target')
                            emit({'syscall':'release-owned-reap','notifying':identity,'reply':'continue'});reply(ident,'continue');reply(pending_reap,'continue');pending_child=None;pending_reap=None
                        continue
                    elif name=='prctl' and args[0]==4 and args[1]==0 and mode=='noexec':
                        event['phase']='readable-owned-tracee';event['reply']='value:0';event['deviation']='non-dumpable request acknowledged without applying';emit(event);reply(ident,'value');continue
                    elif name in ('open','openat') and mode=='noexec':
                        path=pathmem(pid,args[0] if name=='open' else args[1]);event['path']=path
                        if path==DEVICE:
                            if pid==child or identity['ppid']!=child:raise RuntimeError('authority opener is not owned su child')
                            event['phase']='actual-unemulated-authority-open'
                    emit(event);reply(ident,'continue')
            finally:
                if status is None:
                    os.kill(child,signal.SIGKILL);status=os.waitpid(child,0)[1]
                emit({'syscall':'supervisor-end','notifying':None,'child':child,'raw_wait_status':status,'injected':injected,'bootstrap_exec_count':execs,'owned_child':owned_child})
        return status
    seq.supervise=supervise
    rules=[]
    for n in ('execve','execveat','fork','vfork','clone','clone3','wait4','waitid'):rules+=['--notify',n]
    if mode=='noexec':rules+=['--notify','open','--notify','openat','--notify','prctl:0=4,1=0']
    if mode in ('wait','control-wait'):rules+=['--notify','prctl:0=4,1=0']
    sys.argv=[str(LISTENER)]+rules+['--']+sys.argv[2:];seq.main()

if __name__=='__main__':
    try:main()
    except BaseException as e:
        if isinstance(e,SystemExit):raise
        print('owned observer incomplete: '+repr(e),file=sys.stderr);raise SystemExit(125)
