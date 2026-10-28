#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Inject one EIO into an owned tracee's controlling-tty read, guest only."""
import ctypes
import errno
import json
import os
import runpy
import select
import time
from pathlib import Path
import signal
import sys
import termios
import uuid


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker))!=marker.lower(): raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('wrong uid')
        if Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home': raise ValueError('wrong scratch directory')
        if os.uname().machine!='x86_64': raise ValueError('requires x86-64')
    except (OSError,ValueError,UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: '+str(exc))


require_guest()
HOME=Path('/tmp/parity-home');HELPER='./trace-vm-tty-fault-r2.py'
SUPERVISOR=runpy.run_path('./trace-vm-supervisor-r2.py')
OwnedChild=SUPERVISOR['OwnedChild']
EXITKILL=SUPERVISOR['PTRACE_O_EXITKILL']
lib=ctypes.CDLL(None,use_errno=True);lib.ptrace.restype=ctypes.c_long
TRACEME=0;SYSCALL=24;GETREGS=12;SETREGS=13;SETOPTIONS=0x4200;GETINFO=0x420e
GUARD=r'''[[ $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r v </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r u </etc/bashos-parity-vm || exit 125
[[ $v == QEMU && $u =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
'''


class Entry(ctypes.Structure):_fields_=[('nr',ctypes.c_uint64),('args',ctypes.c_uint64*6)]
class Exit(ctypes.Structure):_fields_=[('rval',ctypes.c_int64),('is_error',ctypes.c_uint8)]
class Union(ctypes.Union):_fields_=[('entry',Entry),('exit',Exit)]
class Info(ctypes.Structure):_fields_=[('op',ctypes.c_uint8),('pad',ctypes.c_uint8*3),('arch',ctypes.c_uint32),('ip',ctypes.c_uint64),('sp',ctypes.c_uint64),('data',Union)]
class Regs(ctypes.Structure):
    _fields_=[(name,ctypes.c_ulonglong) for name in ('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]


def ptrace(op,pid,addr=0,data=0):
    ctypes.set_errno(0);rc=lib.ptrace(ctypes.c_ulong(op),ctypes.c_ulong(pid),ctypes.c_void_p(addr),ctypes.c_void_p(data));err=ctypes.get_errno()
    if rc==-1 and err:raise OSError(err,os.strerror(err))
    return rc


def registers(pid):
    result=Regs();ptrace(GETREGS,pid,0,ctypes.addressof(result));return result


def probe(mode):
    # Independent POSIX control observes injected EIO or literal EOF and
    # restores all terminal fields after each read.
    observed=[];restored=[]
    prompts=[b'New password: '] if mode=='eio' else [b'New password: ',b'Retype new password: ']
    for prompt in prompts:
        fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY);old=termios.tcgetattr(fd)
        new=termios.tcgetattr(fd);new[3]&=~(termios.ECHO|termios.ICANON);new[6][termios.VMIN]=1;new[6][termios.VTIME]=0
        termios.tcsetattr(fd,termios.TCSAFLUSH,new);os.write(fd,prompt)
        try:
            try:observed.append(len(os.read(fd,1)))
            except OSError as exc:observed.append(-exc.errno)
        finally:
            termios.tcsetattr(fd,termios.TCSANOW,old);after=termios.tcgetattr(fd);os.write(fd,b'\n');os.close(fd)
        restored.append({'before':repr(old),'after':repr(after),'equal':old==after})
    expected=[-errno.EIO] if mode=='eio' else [0,0]
    (HOME/'tty-fault-probe.json').write_text(json.dumps({'mode':mode,'observed':observed,'expected':expected,
      'terminal_modes':restored},indent=2)+'\n')
    return 1 if observed==expected and all(x['equal'] for x in restored) else 3


class ControlledCleanup(Exception):
    pass


def append_lifecycle(record):
    with (HOME/'tty-fault-lifecycle.jsonl').open('a',encoding='utf8') as stream:
        stream.write(json.dumps(record,sort_keys=True)+'\n')


def run(side,shell,mode,fault_after_options=False):
    if side=='reference':argv=['/usr/bin/python3',HELPER,'--probe-'+mode]
    else:
        body=GUARD+'''export BASHPASSWD_KERNEL_SECRETS=0 PHCLIB_PASSWD="$PWD/db/passwd" PHCLIB_GROUP="$PWD/db/group" PHCLIB_SHADOW="$PWD/db/shadow" BPW_LOCK_DIR="$PWD/lock" PHCLIB_M=1024 PHCLIB_T=1 PHCLIB_P=1
passwd set alice
'''
        argv=[shell,'--noprofile','--norc','-c',body]
    child=None;ttyfd=None;old=None;events=[];failure=None;options=None;report=None
    try:
        # The control faults before the tracee can touch a tty, so it can run
        # in the plain setup driver. Actual cases keep a separate fd open for
        # non-destructive observation and failure-only restoration.
        if not fault_after_options:
            ttyfd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY);old=termios.tcgetattr(ttyfd)
        pid=os.fork()
        if pid==0:
            try:ptrace(TRACEME,0);os.execve(argv[0],argv,dict(os.environ))
            except BaseException as exc:os.write(2,('fault tracee launch: '+repr(exc)+'\n').encode());os._exit(125)
        child=OwnedChild(pid);deadline=time.monotonic()+25
        status=child.wait(deadline)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=signal.SIGTRAP:raise RuntimeError('tracee did not stop at exec')
        options=1|EXITKILL;ptrace(SETOPTIONS,pid,0,options)
        if fault_after_options:raise ControlledCleanup('deliberate exception after ptrace options')
        injected=0;wanted=1 if mode=='eio' else 2;pending=False
        while True:
            ptrace(SYSCALL,pid);status=child.wait(deadline)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):break
            if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=(signal.SIGTRAP|0x80):raise RuntimeError('unexpected tracee stop')
            info=Info();ptrace(GETINFO,pid,ctypes.sizeof(info),ctypes.addressof(info))
            if info.op==1 and int(info.data.entry.nr)==0 and injected<wanted:
                args=[int(x) for x in info.data.entry.args]
                try:target=os.readlink('/proc/%d/fd/%d'%(pid,args[0]))
                except OSError:target=None
                if target=='/dev/tty':
                    number=injected+1
                    events.append({'phase':'read-stopped','fd':args[0],'fd_path':target,'args':args,
                                   'terminal_modes':repr(termios.tcgetattr(ttyfd))})
                    os.write(1,('FAULT-OBSERVER-%d\n'%number).encode())
                    remaining=deadline-time.monotonic()
                    if remaining<=0 or not select.select([0],[],[],remaining)[0]:raise TimeoutError('driver gate timed out')
                    gate=os.read(0,1)
                    if gate!=bytes([ord('G')+injected]):raise RuntimeError('invalid driver gate')
                    regs=registers(pid);before=regs.orig_rax;regs.orig_rax=(1<<64)-1;ptrace(SETREGS,pid,0,ctypes.addressof(regs))
                    events.append({'phase':'read-entry','fd':args[0],'fd_path':target,'args':args,
                                   'original_syscall':before,'gate_hex':gate.hex(),'replacement_syscall':-1})
                    pending=True;injected+=1
            elif info.op==2 and pending:
                regs=registers(pid);kernel_return=ctypes.c_longlong(regs.rax).value
                replacement=-errno.EIO if mode=='eio' else 0
                regs.rax=replacement & ((1<<64)-1);ptrace(SETREGS,pid,0,ctypes.addressof(regs))
                events.append({'phase':'read-exit','skipped_kernel_return':kernel_return,'injected_return':replacement})
                pending=False
            if len(events)>16:raise RuntimeError('tty fault event bound exceeded')
        code=os.waitstatus_to_exitcode(status)
        exits=[event for event in events if event['phase']=='read-exit'];entries=[event for event in events if event['phase']=='read-entry']
        replacement=-errno.EIO if mode=='eio' else 0
        after=termios.tcgetattr(ttyfd)
        checks={'exact_read_count':injected==wanted and len(entries)==wanted and len(exits)==wanted,'target_status_one':code==1,
                'kernel_skipped_syscalls':len(exits)==wanted and all(x['skipped_kernel_return']==-errno.ENOSYS for x in exits),
                'injected_results':len(exits)==wanted and all(x['injected_return']==replacement for x in exits),
                'terminal_restored_by_tracee':after==old}
        if side=='reference':
            p=HOME/'tty-fault-probe.json';data=json.loads(p.read_text()) if p.exists() else {}
            expected=[-errno.EIO] if mode=='eio' else [0,0]
            checks['probe_observed_and_restored']=data.get('observed')==expected and all(x.get('equal') for x in data.get('terminal_modes',[])) and len(data.get('terminal_modes',[]))==wanted
        report={'side':side,'mode':mode,'tracee_pid':pid,'argv':argv,'exit_status':code,'events':events,
                'ptrace_options':options,'terminal_before':repr(old),'terminal_after_tracee':repr(after),'checks':checks}
        (HOME/'tty-fault-observation.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        if not all(checks.values()):raise AssertionError('tty fault mismatch: '+repr(checks))
        print('FAULT-READY-END',flush=True)
    except BaseException as exc:
        failure={'type':type(exc).__name__,'message':str(exc),'side':side,'mode':mode,'argv':argv,
                 'pid':child.pid if child else None,'ptrace_options':options,'events':events}
        if ttyfd is not None:
            try:failure['terminal_before_cleanup']=repr(termios.tcgetattr(ttyfd))
            except OSError as tty_error:failure['terminal_read_error']=repr(tty_error)
        append_lifecycle({'phase':'before-cleanup-failure',**failure})
        raise
    finally:
        lifecycle={'phase':'cleanup','pid':child.pid if child else None,'controlled_fault':fault_after_options,
                   'ptrace_options':options,'failure':failure}
        cleanup_error=None
        if child is not None:
            try:lifecycle['child']=child.cleanup()
            except BaseException as exc:
                cleanup_error=exc;lifecycle['child']={'pid':child.pid,'reaped':child.reaped,'events':child.events,'error':repr(exc)}
        if ttyfd is not None:
            try:
                before=termios.tcgetattr(ttyfd);lifecycle['terminal_before_cleanup']=repr(before)
                if failure is not None and old is not None and before!=old:
                    termios.tcsetattr(ttyfd,termios.TCSANOW,old);lifecycle['failure_only_terminal_restore']=True
                else:lifecycle['failure_only_terminal_restore']=False
                after=termios.tcgetattr(ttyfd);lifecycle['terminal_after_cleanup']=repr(after)
                lifecycle['terminal_matches_initial_after_cleanup']=after==old
            except BaseException as exc:lifecycle['terminal_cleanup_error']=repr(exc);cleanup_error=cleanup_error or exc
            try:os.close(ttyfd);lifecycle['tty_fd_closed']=True
            except OSError as exc:lifecycle['tty_fd_closed']=False;lifecycle['tty_fd_close_error']=repr(exc);cleanup_error=cleanup_error or exc
        append_lifecycle(lifecycle)
        if report is not None:report['cleanup']=lifecycle
        if cleanup_error:raise RuntimeError('tty tracee cleanup failed: '+repr(cleanup_error)) from cleanup_error


def control():
    caught=False
    try:run('reference','/opt/bash-5.3.15/bin/bash','eio',fault_after_options=True)
    except ControlledCleanup:caught=True
    lifecycle=[json.loads(x) for x in (HOME/'tty-fault-lifecycle.jsonl').read_text().splitlines()]
    item=lifecycle[-1]
    checks={'exception_seen':caught,'exitkill_set':item.get('ptrace_options')==(1|EXITKILL),
            'exact_child_reaped':item.get('child',{}).get('reaped') is True,
            'stopped_child_sigkill':item.get('child',{}).get('status',{}).get('signal')==signal.SIGKILL}
    (HOME/'tty-fault-cleanup-control.json').write_text(json.dumps({'checks':checks,'lifecycle':item},indent=2,sort_keys=True)+'\n')
    if not all(checks.values()):raise AssertionError('tty cleanup control failed: '+repr(checks))
    print('tty fault cleanup control ok')


if sys.argv[1:]==['--control']:control()
elif sys.argv[1:] in (['--probe-eio'],['--probe-eof']):raise SystemExit(probe(sys.argv[1][8:]))
elif len(sys.argv)==4 and sys.argv[1] in ('candidate','reference') and sys.argv[3] in ('eio','eof'):
    side,shell,mode=sys.argv[1:]
    if side=='candidate' and shell!='/opt/bashos-parity/candidate':raise SystemExit('candidate path refused')
    if side=='reference' and shell!='/opt/bash-5.3.15/bin/bash':raise SystemExit('reference path refused')
    run(side,shell,mode)
else:raise SystemExit('invalid invocation')
