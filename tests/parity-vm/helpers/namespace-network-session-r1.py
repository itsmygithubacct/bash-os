#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned live session and mapped-login controls in disposable guest namespaces."""
import base64
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import sys
import termios
import time
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME) or os.getuid()!=os.geteuid()):
        raise RuntimeError('disposable guest identity mismatch')
    if os.getuid()==0:
        maps=[list(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
        if maps!=[[0,2000,1]]: raise RuntimeError('unexpected guest user mapping')
    elif os.getuid()!=2000: raise RuntimeError('unexpected guest uid')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'): raise RuntimeError('not a disposable QEMU/KVM guest')


def require_private_mount():
    outer=os.environ.get('FIXTURE_OUTER_MNT')
    if os.getuid()!=0 or not outer or os.readlink('/proc/self/ns/mnt')==outer:
        raise RuntimeError('fixture-owned mount namespace required')


def save(name,data): (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def capture(args,env=None):
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    out,err=proc.communicate(timeout=12)
    if len(out)>256*1024 or len(err)>128*1024: raise RuntimeError('command output exceeds bound')
    return {'argv':args,'pid':proc.pid,'status':proc.returncode,
            'stdout_base64':base64.b64encode(out).decode(),'stderr_base64':base64.b64encode(err).decode()}


def out(record): return base64.b64decode(record['stdout_base64']).decode('utf-8','replace')


def mount(source,target,kind=None,flags=0,data=None):
    require_private_mount()
    lib=ctypes.CDLL(None,use_errno=True);ctypes.set_errno(0)
    result=lib.mount(ctypes.c_char_p(os.fsencode(source)),ctypes.c_char_p(os.fsencode(target)),
                     ctypes.c_char_p(os.fsencode(kind)) if kind else None,ctypes.c_ulong(flags),
                     ctypes.c_char_p(os.fsencode(data)) if data else None)
    return {'source':source,'target':target,'type':kind,'flags':flags,'data':data,
            'result':result,'errno':ctypes.get_errno() if result else 0}


def namespace_snapshot():
    return {'pid':os.getpid(),'uid':os.getuid(),'gid':os.getgid(),
            'user':os.readlink('/proc/self/ns/user'),'mnt':os.readlink('/proc/self/ns/mnt'),
            'pid_namespace':os.readlink('/proc/self/ns/pid'),
            'uid_map':Path('/proc/self/uid_map').read_text(),
            'gid_map':Path('/proc/self/gid_map').read_text(),
            'loginuid':Path('/proc/self/loginuid').read_text(),
            'status':Path('/proc/self/status').read_text()}


def login_wrap(mode,binary=None):
    if os.getuid()!=2000: raise RuntimeError('outer uid must be 2000')
    path=Path('/proc/self/loginuid'); before=path.read_text().strip()
    report={'before':before,'requested':'2000','namespace':namespace_snapshot()}
    if before=='4294967295':
        try: path.write_text('2000');report['write_result']='ok'
        except OSError as exc: report['write_result']={'errno':exc.errno,'message':exc.strerror}
    else: report['write_result']='not-needed'
    report['after']=path.read_text().strip();save('login-origin.json',report)
    if report['after']!='2000': raise RuntimeError('guest loginuid cannot be set to 2000 by this child')
    args=['/usr/bin/unshare','--user','--map-root-user','--mount','/usr/bin/python3',__file__,'login-inner',mode]
    if binary: args.append(binary)
    os.execv(args[0],args)


def login_inner(mode,binary=None):
    require_private_mount()
    report={'before':namespace_snapshot()}
    result=mount(str(CASE/'passwd.fixture'),'/etc/passwd',flags=4096);report['bind_request']=result
    if result['result']!=0:
        save('login-'+mode+'.json',report);raise RuntimeError('passwd bind control failed')
    report['after']=namespace_snapshot()
    report['source_inode']=[os.stat(CASE/'passwd.fixture').st_dev,os.stat(CASE/'passwd.fixture').st_ino]
    report['bound_inode']=[os.stat('/etc/passwd').st_dev,os.stat('/etc/passwd').st_ino]
    report['passwd']=Path('/etc/passwd').read_text()
    report['getent']=capture(['/usr/bin/getent','passwd','0'])
    env=dict(os.environ);env['LOGNAME']='spoofed-login';env['USER']='spoofed-user'
    report['native_plain']=capture(['/usr/bin/logname'])
    report['native_spoof']=capture(['/usr/bin/logname'],env)
    expected='namespace-login\n'
    valid=(report['after']['loginuid'].strip()=='0' and report['source_inode']==report['bound_inode'] and
           out(report['getent']).startswith('namespace-login:') and
           all(report[x]['status']==0 and out(report[x])==expected for x in ('native_plain','native_spoof')))
    if not valid:
        save('login-'+mode+'.json',report);raise RuntimeError('native mapped-login control failed')
    if mode=='control': save('login-control.json',report);return
    if mode!='run': raise ValueError('unknown login mode')
    script=r'''[[ $UID == 0 && $EUID == 0 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r vendor </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r marker </etc/bashos-parity-vm || exit 125
[[ $vendor == QEMU && $marker =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
mapfile -t maps </proc/self/uid_map || exit 125
(( ${#maps[@]} == 1 )) || exit 125
read -r a b n tail <<<"${maps[0]}"; [[ $a == 0 && $b == 2000 && $n == 1 && -z $tail ]] || exit 125
virt=$(/usr/bin/systemd-detect-virt --vm) || exit 125
[[ $virt == qemu || $virt == kvm ]] || exit 125
[[ $(type -t logname) == builtin ]] || exit 99
logname >"$HOME/logname-plain.out" 2>"$HOME/logname-plain.err"; a=$?
LOGNAME=spoofed-login USER=spoofed-user logname >"$HOME/logname-spoof.out" 2>"$HOME/logname-spoof.err"; b=$?
printf '%s %s\n' "$a" "$b"
'''
    report['candidate']=capture([binary,'--noprofile','--norc','-c',script])
    report['candidate_plain']=(HOME/'logname-plain.out').read_text()
    report['candidate_spoof']=(HOME/'logname-spoof.out').read_text()
    report['candidate_plain_stderr']=(HOME/'logname-plain.err').read_text()
    report['candidate_spoof_stderr']=(HOME/'logname-spoof.err').read_text()
    save('login-run.json',report)
    if (report['candidate']['status']!=0 or out(report['candidate'])!='0 0\n' or
        report['candidate_plain']!=expected or report['candidate_spoof']!=expected):
        raise RuntimeError('candidate login identity mismatch')
    print('login=ok')


def session_child():
    # This child is the sole process in its controlling-terminal session.
    until=time.process_time()+1.15
    while time.process_time()<until: pass
    print('READY',flush=True)
    if sys.stdin.readline().strip()!='done': raise RuntimeError('session release missing')


def parse_duration(value):
    if value.endswith('s'):
        return float(value[:-1])
    if ':' in value:
        a,b=value.split(':',1);return int(a)*60+float(b)
    if value.endswith('m'): return float(value[:-1])*60
    if value=='.': return 0.0
    raise ValueError('unsupported duration '+value)


def session_row(text):
    rows=[line.split(None,7) for line in text.splitlines() if line.split() and line.split()[0]=='fixture']
    if len(rows)!=1 or len(rows[0])!=8: raise RuntimeError('expected exactly one complete fixture session row')
    return rows[0]


def time_and_load():
    return {'wall':time.time(),'uptime':Path('/proc/uptime').read_text(),
            'loadavg':Path('/proc/loadavg').read_text()}


def parse_header(text):
    match=re.fullmatch(r'\s*(\d{1,2}):(\d{2}):(\d{2})\s+up\s+(.+?),\s*(\d+)\s+users?,\s+load averages?:\s*(\d+\.\d+),\s*(\d+\.\d+),\s*(\d+\.\d+)\s*',text)
    if not match: raise ValueError('unparseable uptime header')
    hour,minute,second=map(int,match.group(1,2,3))
    return {'clock_seconds':hour*3600+minute*60+second,'uptime':match.group(4).strip(),
            'users':int(match.group(5)),'loads':list(map(float,match.group(6,7,8)))}


def validate_header(header,before,after):
    if header['users']!=1: raise RuntimeError('header user count mismatch')
    clocks=[]
    for sample in (before,after):
        now=time.localtime(sample['wall']); clocks.append(now.tm_hour*3600+now.tm_min*60+now.tm_sec)
    if min(min((header['clock_seconds']-x)%86400,(x-header['clock_seconds'])%86400) for x in clocks)>5:
        raise RuntimeError('header clock differs from wall clock')
    loads=[list(map(float,sample['loadavg'].split()[:3])) for sample in (before,after)]
    if any(min(abs(header['loads'][i]-row[i]) for row in loads)>0.15 for i in range(3)):
        raise RuntimeError('header load differs from proc loadavg')


def validate_native(record,expected_tty,expected_cpu):
    if record['status']!=0: raise RuntimeError('native w failed')
    row=session_row(out(record))
    if row[1]!=expected_tty or 'python3' not in row[7]: raise RuntimeError('native session identity mismatch')
    if abs(parse_duration(row[4])-125)>12: raise RuntimeError('native tty idle control mismatch')
    for field in (row[5],row[6]):
        if abs(parse_duration(field)-expected_cpu)>1.5: raise RuntimeError('native process accounting control mismatch')
    return row


def w_session(mode,binary=None):
    require_private_mount()
    if os.getpid()!=1: raise RuntimeError('private PID namespace required')
    report={'mode':mode,'namespace':namespace_snapshot(),'mount':None,'child':{}}
    report['mount']=mount('fixture-run','/run','tmpfs',data='size=1m,mode=0755')
    if report['mount']['result']!=0:
        save('w-'+mode+'.json',report);raise RuntimeError('private run tmpfs unavailable')
    master,slave=os.openpty();tty_path=os.ttyname(slave);tty_line=tty_path.removeprefix('/dev/')
    def child_setup(): fcntl.ioctl(0,termios.TIOCSCTTY,0)
    child=subprocess.Popen(['/usr/bin/python3',__file__,'session-child'],stdin=slave,stdout=slave,stderr=slave,
                           start_new_session=True,preexec_fn=child_setup,close_fds=True)
    os.close(slave); raw=bytearray()
    try:
        deadline=time.monotonic()+10
        while b'READY' not in raw:
            if time.monotonic()>deadline: raise RuntimeError('session child readiness timeout')
            ready,_,_=select.select([master],[],[],0.2)
            if ready: raw.extend(os.read(master,4096))
            if len(raw)>32768: raise RuntimeError('session handshake too large')
        if os.tcgetpgrp(master)!=child.pid: raise RuntimeError('child is not foreground process group')
        stat_path=Path('/proc')/str(child.pid)/'stat'; stat_before=stat_path.read_text()
        rest=stat_before[stat_before.rfind(')')+2:].split()
        cpu=(int(rest[11])+int(rest[12]))/os.sysconf('SC_CLK_TCK')
        if cpu<1.0: raise RuntimeError('session CPU control below one second')
        owned=CASE/('owned-proc-'+mode);owned.mkdir();(owned/str(child.pid)).symlink_to('/proc/'+str(child.pid))
        now=int(time.time());fmt='<h2xi32s4s32s256shhiii4i20s'
        if struct.calcsize(fmt)!=384: raise RuntimeError('unexpected utmp ABI')
        entry=struct.pack(fmt,7,child.pid,tty_line.encode(),b'nn',b'fixture',b'fixture-host',0,0,0,now,0,0,0,0,0,b'')
        Path('/run/utmp').write_bytes(entry)
        target_ns=time.time_ns()-125_000_000_000;os.utime(tty_path,ns=(target_ns,target_ns))
        report['child']={'pid':child.pid,'tty':tty_path,'tty_line':tty_line,'ready_base64':base64.b64encode(raw).decode(),
                         'stat_before':stat_before,'status':Path('/proc/%d/status'%child.pid).read_text(),
                         'cmdline_base64':base64.b64encode(Path('/proc/%d/cmdline'%child.pid).read_bytes()).decode(),
                         'cpu_seconds':cpu,'utmp_base64':base64.b64encode(entry).decode(),'tty_atime':os.stat(tty_path).st_atime}
        report['before']=time_and_load()
        report['native_noheader']=capture(['/usr/bin/w','-h'])
        report['native']=capture(['/usr/bin/w'])
        report['native_row']=validate_native(report['native_noheader'],tty_line,cpu)
        first=out(report['native']).splitlines()[0]
        report['native_header']=parse_header(first)
        validate_header(report['native_header'],report['before'],time_and_load())
        if mode=='control':
            report['after']=time_and_load();save('w-control.json',report);return
        if mode!='run': raise ValueError('unknown w mode')
        env=dict(os.environ);env['BASHW_PROC_DIR']=str(owned);env['BASHW_DEV_DIR']='/dev'
        script=r'''[[ $UID == 0 && $EUID == 0 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r vendor </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r marker </etc/bashos-parity-vm || exit 125
[[ $vendor == QEMU && $marker =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
mapfile -t maps </proc/self/uid_map || exit 125
(( ${#maps[@]} == 1 )) || exit 125
read -r a b n tail <<<"${maps[0]}"; [[ $a == 0 && $b == 2000 && $n == 1 && -z $tail ]] || exit 125
virt=$(/usr/bin/systemd-detect-virt --vm) || exit 125
[[ $virt == qemu || $virt == kvm ]] || exit 125
[[ $(type -t w) == builtin ]] || exit 99
w
'''
        report['candidate']=capture([binary,'--noprofile','--norc','-c',script],env)
        report['native_after']=capture(['/usr/bin/w'])
        report['after']=time_and_load();report['child']['stat_after']=stat_path.read_text()
        errors=[]
        if report['candidate']['status']!=0: errors.append('candidate status')
        text=out(report['candidate']); lines=text.splitlines()
        try:
            row=session_row(text);report['candidate_row']=row
            if row[1]!=tty_line or 'python3' not in row[7]: errors.append('session tty or command mismatch')
            if abs(parse_duration(row[4])-125)>12: errors.append('tty idle mismatch')
            if any(abs(parse_duration(row[n])-cpu)>1.5 for n in (5,6)): errors.append('live CPU mismatch')
        except (ValueError,RuntimeError) as exc: errors.append('row: '+str(exc))
        try:
            candidate_header=parse_header(lines[0] if lines else '')
            native_after=parse_header(out(report['native_after']).splitlines()[0])
            validate_header(candidate_header,report['before'],report['after'])
            if candidate_header['uptime'] not in (report['native_header']['uptime'],native_after['uptime']):
                errors.append('uptime differs from native interval')
            report['candidate_header']=candidate_header
        except (ValueError,RuntimeError,IndexError) as exc:
            errors.append('uptime/user/load header: '+str(exc))
        report['errors']=errors;save('w-run.json',report)
        if errors: raise RuntimeError('candidate live w assertions failed: '+repr(errors))
        print('w-live=ok')
    except Exception as exc:
        report['fatal_error']=str(exc);save('w-'+mode+'.json',report);raise
    finally:
        try: os.write(master,b'done\n')
        except OSError: pass
        child.wait(timeout=5);os.close(master)
        if child.returncode!=0: raise RuntimeError('owned terminal child did not exit normally')


def main():
    guard();mode=sys.argv[1]
    if mode=='login-wrap': login_wrap(sys.argv[2],sys.argv[3] if len(sys.argv)>3 else None)
    elif mode=='login-inner': login_inner(sys.argv[2],sys.argv[3] if len(sys.argv)>3 else None)
    elif mode=='session-child': session_child()
    elif mode=='w-session': w_session(sys.argv[2],sys.argv[3] if len(sys.argv)>3 else None)
    else: raise ValueError('unknown mode')


if __name__=='__main__': main()
