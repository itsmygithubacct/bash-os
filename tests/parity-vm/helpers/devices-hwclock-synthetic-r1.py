#!/usr/bin/python3
"""VM-only RTC/clock syscall simulator; never writes a real RTC or clock."""
import calendar, ctypes, errno, fcntl, importlib.util, json, os, select, signal, struct, sys, uuid
from pathlib import Path

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
SEQ=Path('/opt/bashos-parity/harness/helpers/system-sequence.py')
RD=0x80247009; SET=0x4024700a

def main():
    assert os.getuid()==os.geteuid()==2000 and Path.cwd()==CASE and os.environ.get('HOME')==str(HOME)
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    cfg=json.loads((CASE/'clock.json').read_text()); rtc=CASE/'rtc'; assert rtc.is_file() and not rtc.is_symlink()
    date=cfg['rtc']; assert len(date)==9 and all(type(n)==int for n in date)
    assert cfg['mode'] in ('show','hctosys','validate')
    spec=importlib.util.spec_from_file_location('seq',SEQ); seq=importlib.util.module_from_spec(spec); spec.loader.exec_module(seq)
    events=[]; state={'rd':0,'set':0,'clock':0}; trace=HOME/'clock-events.jsonl'
    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,log):
        status=None
        try:
            with trace.open('w') as output:
                while status is None:
                    done,wstatus=os.waitpid(child,os.WNOHANG)
                    if done: status=wstatus; break
                    if not select.select([listener],[],[],0.05)[0]: continue
                    req=bytearray(80)
                    try: fcntl.ioctl(listener,seq.NOTIF_RECV,req,True)
                    except OSError as e:
                        if e.errno in (errno.ENOENT,errno.EINTR): continue
                        raise
                    ident,pid,_,nr,_,_=struct.unpack_from('<QIIiIQ',req); args=struct.unpack_from('<6Q',req,32)
                    raw=lib.seccomp_syscall_resolve_num_arch(0,nr); name=ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                    event={'name':name,'pid':pid}; kind='continue'; val=0
                    if name=='openat':
                        path=seq.read_string(pid,args[1]); event['path']=path
                    elif name=='ioctl':
                        fd=int(args[0]); event.update(request=args[1],fd=fd,target=os.readlink('/proc/%d/fd/%d'%(pid,fd)))
                        if event['target']!=str(rtc): raise RuntimeError('RTC ioctl targeted unexpected descriptor')
                        if args[1]==RD:
                            state['rd']+=1; payload=struct.pack('<9i',*date)
                            with open('/proc/%d/mem'%pid,'r+b',buffering=0) as mem:
                                if os.pwrite(mem.fileno(),payload,args[2])!=len(payload): raise RuntimeError('short synthetic RTC write')
                            event['synthetic_output_hex']=payload.hex(); kind='value'
                        elif args[1]==SET:
                            state['set']+=1; event['input']=seq.read_memory(pid,args[2],36); kind='value'
                        else: raise RuntimeError('unexpected ioctl')
                    elif name=='clock_settime':
                        state['clock']+=1; event['clockid']=args[0]; event['timespec']=seq.read_memory(pid,args[1],16); kind='value'
                    event['reply']='synthetic-zero' if kind=='value' else 'continue'; events.append(event)
                    if len(events)>512: raise RuntimeError('notification limit')
                    output.write(json.dumps(event,sort_keys=True)+'\n');output.flush()
                    response=struct.pack('<QqiI',ident,0,0,0 if kind=='value' else seq.FLAG_CONTINUE)
                    fcntl.ioctl(listener,seq.NOTIF_SEND,response)
        finally:
            if status is None:
                os.kill(child,signal.SIGKILL);os.waitpid(child,0)
        return status
    seq.supervise=supervise
    sys.argv=[str(SEQ),'--notify','openat','--notify','ioctl:1=%d'%RD,'--notify','ioctl:1=%d'%SET,'--notify','clock_settime','--']+sys.argv[1:]
    # seq.main propagates child status via SystemExit; retain all observations first.
    try: seq.main()
    except SystemExit as exc: rc=exc.code
    (HOME/'clock-child-status').write_text(str(rc)+'\n')
    opens=[i for i,e in enumerate(events) if e['name']=='openat' and e.get('path')==str(rtc)]
    reads=[i for i,e in enumerate(events) if e['name']=='ioctl' and e.get('request')==RD]
    clocks=[i for i,e in enumerate(events) if e['name']=='clock_settime']
    passed=(rc==cfg['status'] and state['set']==0)
    if cfg['mode']=='validate': passed &= not opens and not reads
    else: passed &= len(opens)==1 and len(reads)==1 and opens[0]<reads[0]
    if cfg['mode']=='hctosys' and cfg['status']==0:
        if len(clocks)!=1 or not reads[0]<clocks[0]: passed=False
        else:
            e=events[clocks[0]]; m=e['timespec']; val=bytes.fromhex(m.get('hex',''))
            passed &= e['clockid']==0 and len(val)==16 and struct.unpack('<qq',val)==(cfg['epoch'],0)
    else: passed &= not clocks
    (HOME/'clock-check.json').write_text(json.dumps({'pass':bool(passed),'counts':state,'rtc_open_indices':opens,'read_indices':reads,'clock_indices':clocks,'child_status':rc},sort_keys=True)+'\n')
    if not passed: sys.exit(1)
    print('synthetic syscall checks ok')

if __name__=='__main__': main()
