#!/usr/bin/python3
"""Guest-only owned-task synthetic RT/deadline request preservation observer."""
import ctypes,fcntl,hashlib,importlib.util,json,os,select,signal,struct,sys,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case');SEQ='/opt/bashos-parity/harness/helpers/system-sequence.py'
if os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=C or os.environ.get('HOME')!=str(H):raise SystemExit(125)
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.uname().release!='7.2.11+deb13-amd64':raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
def run_observed(seq,pid,template,program):
    events=[]
    def supervise(lib,listener,child,replies,sequences,logargs,logstr,logmem,log):
        status=None
        try:
            while status is None:
                done,status_now=os.waitpid(child,os.WNOHANG)
                if done:status=status_now;break
                if not select.select([listener],[],[],0.05)[0]:continue
                req=bytearray(80)
                try:fcntl.ioctl(listener,seq.NOTIF_RECV,req,True)
                except OSError as e:
                    if e.errno in (2,4):continue
                    raise
                ident,caller,_,nr,_,_=struct.unpack_from('<QIIiIQ',req);args=struct.unpack_from('<6Q',req,32)
                raw=lib.seccomp_syscall_resolve_num_arch(0,nr);name=ctypes.cast(raw,ctypes.c_char_p).value.decode() if raw else str(nr)
                event={'syscall':name,'target':args[0]&0xffffffff};reply=seq.FLAG_CONTINUE
                if event['target']==pid and name=='sched_getattr':
                    with open('/proc/%d/mem'%caller,'r+b',buffering=0) as mem:
                        if os.pwrite(mem.fileno(),template,args[1])!=len(template):raise RuntimeError('short synthetic getter write')
                    event['synthetic_output_hex']=template.hex();reply=0
                elif event['target']==pid and name=='sched_setattr':
                    event['input']=seq.read_memory(caller,args[1],56);reply=0
                event['reply']='continue' if reply else 'synthetic-zero';events.append(event)
                if len(events)>64:raise RuntimeError('mock observation limit')
                fcntl.ioctl(listener,seq.NOTIF_SEND,struct.pack('<QqiI',ident,0,0,reply))
        finally:
            if status is None:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
        return status
    seq.supervise=supervise;sys.argv=[SEQ,'--notify','sched_getattr','--notify','sched_setattr','--',*program]
    try:seq.main()
    except SystemExit as e:status=e.code
    return {'status':status,'events':events}
def parse_request(result,pid):
    gets=[e for e in result['events'] if e['syscall']=='sched_getattr' and e['target']==pid]
    sets=[e for e in result['events'] if e['syscall']=='sched_setattr' and e['target']==pid]
    if len(gets)!=1 or len(sets)!=1:raise ValueError('synthetic getter/setter trace incomplete')
    data=sets[0]['input'];raw=bytes.fromhex(data.get('hex',''))
    if len(raw)!=56 or data.get('length')!=56:raise ValueError('synthetic request bytes incomplete')
    return {'size':struct.unpack_from('<I',raw,0)[0],'policy':struct.unpack_from('<I',raw,4)[0],'flags':struct.unpack_from('<Q',raw,8)[0],'nice':struct.unpack_from('<i',raw,16)[0],'priority':struct.unpack_from('<I',raw,20)[0],'runtime':struct.unpack_from('<Q',raw,24)[0],'deadline':struct.unpack_from('<Q',raw,32)[0],'period':struct.unpack_from('<Q',raw,40)[0]}
def main():
    mode,shell=sys.argv[1:3];report={'mode':mode,'control_valid':False,'candidate_checks':{},'events':{},'observation':'synthetic scheduler replies; no real RT/deadline scheduling'}
    try:
        import subprocess
        if shell!='/opt/bashos-parity/candidate':raise RuntimeError('candidate binary path differs')
        binary_sha256=hashlib.sha256(Path(shell).read_bytes()).hexdigest()
        target=subprocess.Popen(['/usr/bin/python3','-c','import sys;sys.stdin.read(1)'],stdin=subprocess.PIPE);pid=target.pid
        report.update(target_pid=pid,candidate_binary=shell,candidate_sha256=binary_sha256)
        try:
            spec=importlib.util.spec_from_file_location('seq',SEQ);seq=importlib.util.module_from_spec(spec);spec.loader.exec_module(seq)
            policy=1 if mode=='rt' else 6 if mode=='deadline' else None
            if policy is None:raise ValueError('unknown mode')
            priority=7 if mode=='rt' else 0;runtime,deadline,period=(1000000,10000000,10000000) if mode=='deadline' else (0,0,0)
            template=struct.pack('<IIQiIQQQII',56,policy,0,0,priority,runtime,deadline,period,100,900)
            probe="import ctypes,sys; b=ctypes.create_string_buffer(56); l=ctypes.CDLL(None); p=int(sys.argv[1]); assert l.syscall(315,p,b,56,0)==0; assert bytes(b.raw)==bytes.fromhex(sys.argv[2]); assert l.syscall(314,p,b,0)==0"
            control_argv=['/usr/bin/python3','-I','-c',probe,str(pid),template.hex()];report['control_argv']=control_argv
            control=run_observed(seq,pid,template,control_argv);report['events']['control']=control
            if control['status']!=0 or parse_request(control,pid)['policy']!=policy:raise RuntimeError('synthetic getter/setter control failed')
            report['control_valid']=True
            candidate_argv=[shell,'--noprofile','--norc','-c','uclampset -m 200 -p "$1"','mock',str(pid)];report['candidate_argv']=candidate_argv
            (H/'scheduler-mock-report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
            result=run_observed(seq,pid,template,candidate_argv);report['events']['candidate']=result
            (H/'scheduler-mock-report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
            observed=parse_request(result,pid);report['events']['candidate_request']=observed
            checks={'status':result['status']==0,'policy':observed['policy']==policy,'priority':observed['priority']==priority,'runtime':observed['runtime']==runtime,'deadline':observed['deadline']==deadline,'period':observed['period']==period}
            report['candidate_checks']=checks;(H/'scheduler-mock-report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
            if not all(checks.values()):raise SystemExit(1)
            print('synthetic uclamp scheduler checks ok')
        finally:target.stdin.close();target.wait(timeout=5)
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as e:
        report['incomplete']=type(e).__name__+': '+str(e);(H/'scheduler-mock-report.json').write_text(json.dumps(report,sort_keys=True)+'\n');raise SystemExit(125)
if __name__=='__main__':main()
