#!/usr/bin/python3
"""Guest-only synthetic RTC with bounded, path-scoped fault injection.

RTC_RD_TIME and RTC_SET_TIME are simulated. All other calls are real except
exactly the one named fault on the fixture RTC or adjtime temp/rename. Logs
and prior file state are retained before assertions. This is not real RTC IO.
"""
import calendar, ctypes, errno, fcntl, importlib.util, json, os, select, signal, struct, sys, time, uuid
from pathlib import Path
CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
SEQ=Path('/opt/bashos-parity/harness/helpers/system-sequence.py')
RTC=str(CASE/'rtc'); ADJ=str(CASE/'adjtime'); RD=0x80247009; SET=0x4024700a

def stat_adj():
    p=Path(ADJ)
    if not p.exists(): return None
    s=p.stat(); return {'hex':p.read_bytes().hex(),'mode':s.st_mode & 0o777,'inode':s.st_ino,'nlink':s.st_nlink}

def main():
    assert os.getuid()==os.geteuid()==2000 and Path.cwd()==CASE and os.environ.get('HOME')==str(HOME)
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    cfg=json.loads((CASE/'effects.json').read_text()); rtc=Path(RTC)
    assert rtc.is_file() and not rtc.is_symlink()
    date=cfg['rtc']; assert len(date)==9 and all(type(n)==int for n in date)
    assert cfg['mode'] in ('adjust','systohc','read','validate')
    assert cfg.get('fault','none') in ('none','rtc-open','rtc-read','rtc-write','rtc-close','temp-open','temp-write','temp-close','rename')
    before=stat_adj(); alias=CASE/'adj-alias'; alias_before=alias.read_bytes().hex() if alias.exists() else None; (HOME/'effects-before.json').write_text(json.dumps(before,sort_keys=True)+'\n')
    spec=importlib.util.spec_from_file_location('seq',SEQ); seq=importlib.util.module_from_spec(spec); spec.loader.exec_module(seq)
    events=[]; state={'rd':0,'set':0,'clock':0,'faults':0}; trace=HOME/'effects-events.jsonl'; fault=cfg.get('fault','none')
    t0=time.time_ns()
    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,log):
        status=None
        try:
            with trace.open('w') as output:
                while status is None:
                    done,wstatus=os.waitpid(child,os.WNOHANG)
                    if done: status=wstatus;break
                    if not select.select([listener],[],[],.05)[0]: continue
                    req=bytearray(80)
                    try: fcntl.ioctl(listener,seq.NOTIF_RECV,req,True)
                    except OSError as e:
                        if e.errno in (errno.ENOENT,errno.EINTR): continue
                        raise
                    ident,pid,_,nr,_,_=struct.unpack_from('<QIIiIQ',req); args=struct.unpack_from('<6Q',req,32)
                    raw=lib.seccomp_syscall_resolve_num_arch(0,nr); name=ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                    event={'name':name,'pid':pid}; reply='continue'
                    if name=='openat':
                        path=seq.read_string(pid,args[1]);event['path']=path
                        if state['faults']==0 and ((fault=='rtc-open' and path==RTC) or (fault=='temp-open' and isinstance(path,str) and path.startswith(ADJ+'.'))): reply='eio'
                    elif name=='ioctl':
                        fd=int(args[0]); event.update(request=args[1] & 0xffffffff,fd=fd,target=os.readlink('/proc/%d/fd/%d'%(pid,fd)))
                        if event['target']!=RTC: raise RuntimeError('RTC ioctl on unexpected descriptor')
                        if (args[1] & 0xffffffff)==RD:
                            state['rd']+=1
                            if fault=='rtc-read': reply='eio'
                            else:
                                payload=struct.pack('<9i',*date)
                                with open('/proc/%d/mem'%pid,'r+b',buffering=0) as mem:
                                    if os.pwrite(mem.fileno(),payload,args[2])!=len(payload): raise RuntimeError('short RTC writeback')
                                event['synthetic_output_hex']=payload.hex(); reply='zero'
                        elif (args[1] & 0xffffffff)==SET:
                            state['set']+=1;event['input']=seq.read_memory(pid,args[2],36)
                            reply='eio' if fault=='rtc-write' else 'zero'
                        else: raise RuntimeError('unexpected ioctl')
                    elif name=='clock_settime':
                        state['clock']+=1; event['clockid']=args[0];event['input']=seq.read_memory(pid,args[1],16); reply='eio'
                    elif name in ('write','close'):
                        try: target=os.readlink('/proc/%d/fd/%d'%(pid,args[0]))
                        except FileNotFoundError: target='missing'
                        event.update(fd=args[0],target=target)
                        if state['faults']==0 and ((target.startswith(ADJ+'.') and fault=='temp-'+name) or (target==RTC and fault=='rtc-close' and name=='close')): reply='eio'
                    elif name in ('rename','renameat','renameat2'):
                        si,di=(0,1) if name=='rename' else (1,3)
                        event.update(source=seq.read_string(pid,args[si]),dest=seq.read_string(pid,args[di]))
                        if state['faults']==0 and fault=='rename' and event['dest']==ADJ: reply='eio'
                    if reply=='eio':
                        state['faults']+=1
                        if state['faults']>1: raise RuntimeError('fault was not unique')
                    event['reply']=reply;events.append(event)
                    if len(events)>4096: raise RuntimeError('notification bound exceeded')
                    output.write(json.dumps(event,sort_keys=True)+'\n');output.flush()
                    response=struct.pack('<QqiI',ident,0,-errno.EIO if reply=='eio' else 0,seq.FLAG_CONTINUE if reply=='continue' else 0)
                    fcntl.ioctl(listener,seq.NOTIF_SEND,response)
        finally:
            if status is None: os.kill(child,signal.SIGKILL);os.waitpid(child,0)
        return status
    seq.supervise=supervise
    args=[]
    for n in ('openat','write','close','rename','renameat','renameat2','clock_settime'): args+=['--notify',n]
    args+=['--notify','ioctl:1=%d'%RD,'--notify','ioctl:1=%d'%SET]
    sys.argv=[str(SEQ)]+args+['--']+sys.argv[1:]
    try: seq.main()
    except SystemExit as exc: rc=exc.code
    t1=time.time_ns();after=stat_adj();tmp=sorted(p.name for p in CASE.glob('adjtime.*'))
    report={'child_status':rc,'counts':state,'before':before,'after':after,'temp_names':tmp,'time_before_ns':t0,'time_after_ns':t1,'errors':[]}
    errs=report['errors']
    def check(ok,message):
        if not ok: errs.append(message)
    check(rc==cfg['status'],'child status');check(state['clock']==0,'unexpected clock_settime')
    check(state['faults']==(fault!='none'),'fault not reached exactly once')
    check(state['rd']==cfg['reads'],'RTC read count');check(state['set']==cfg['writes'],'RTC write count')
    writes=[e for e in events if e['name']=='ioctl' and e.get('request')==SET]
    if writes:
        data=writes[0].get('input',{});raw=bytes.fromhex(data.get('hex',''))
        check(len(raw)==36,'RTC_SET_TIME input unreadable')
        if len(raw)==36:
            vals=struct.unpack('<9i',raw);report['rtc_set_fields']=vals
            try:
                if cfg.get('tz')=='local':
                    os.environ['TZ']='EST5EDT,M3.2.0/2,M11.1.0/2';time.tzset(); sec=int(time.mktime((vals[5]+1900,vals[4]+1,vals[3],vals[2],vals[1],vals[0],0,0,-1)))
                else: sec=calendar.timegm((vals[5]+1900,vals[4]+1,vals[3],vals[2],vals[1],vals[0]))
                report['set_epoch']=sec
                if cfg['mode']=='systohc': check(t0//10**9 <= sec <= t1//10**9,'RTC write outside sampled time bracket')
                if 'expected_epoch' in cfg: check(sec==cfg['expected_epoch'],'RTC set epoch')
            except (OverflowError,ValueError): errs.append('invalid RTC_SET_TIME calendar')
    check(not tmp,'temporary file remains')
    if alias_before is not None: check(alias.exists() and alias.read_bytes().hex()==alias_before,'adjtime hardlink contents changed')
    if cfg.get('preserve'): check(after==before,'prior adjtime bytes/mode/inode/links changed')
    if cfg.get('adj_expected') is not None:
        check(after is not None,'adjtime missing')
        if after:
            actual=bytes.fromhex(after['hex']).decode('ascii');check(actual==cfg['adj_expected'],'adjtime content');check(after['inode']!=before['inode'] and after['mode']==before['mode'],'replacement inode/mode')
    if cfg.get('check_reset') and after and writes and 'set_epoch' in report:
        parts=bytes.fromhex(after['hex']).decode('ascii').splitlines()
        try:
            drift,last,remain=parts[0].split();calib=int(parts[1]);mode=parts[2]
            check(int(last)==calib==report['set_epoch'] and float(remain)==0 and mode==cfg['reset_mode'],'systohc adjtime reset')
            check(after['inode']!=before['inode'] and after['mode']==before['mode'],'replacement inode/mode')
        except (ValueError,IndexError): errs.append('invalid reset adjtime')
    (HOME/'effects-report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    if errs: sys.exit(1)
    print('synthetic effects checks ok')
if __name__=='__main__': main()
