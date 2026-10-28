#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Owned loopback SSH password client test for a synthetic auth device in a VM."""
import base64
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
MOCK='/opt/bashos-parity/harness/helpers/auth-client-device-bootstrap-r1.py'


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert os.geteuid()==2000 and Path.cwd()==CASE


def b64(x):return base64.b64encode(x).decode()
def yes(x):return 'yes' if x else 'no'
def record(kind,**values):
    values['kind']=kind
    with (HOME/'sshd-auth-observations.jsonl').open('a') as f:f.write(json.dumps(values,sort_keys=True)+'\n')


def kdf(password,salt,t,m,p,n):
    import importlib.util
    path='/opt/bashos-parity/harness/helpers/auth-client-argon2-cli-r1.py'
    spec=importlib.util.spec_from_file_location('auth_argon2_cli',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.derive(password,salt,t,m,p,n,record)


CONTROL=r'''import ctypes,errno,fcntl,os,struct,uuid
from pathlib import Path
if not __debug__:raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
assert os.geteuid()==2000 and Path.cwd().is_relative_to(Path('/tmp/parity-case'))
f=os.open('/dev/bashos-auth',os.O_RDWR);g=os.open('/dev/bashos-auth',os.O_RDWR)
h=bytearray(8);fcntl.ioctl(f,0xc008ba02,h,True);ident=struct.unpack_from('<I',h)[0]
s=ctypes.create_string_buffer(b'positive-control');w=bytearray(struct.pack('<IIQ',ident,16,ctypes.addressof(s)))
fcntl.ioctl(f,0x4010ba03,w,True);fcntl.ioctl(f,0x4008ba04,bytearray(h),True)
v=ctypes.create_string_buffer(64);e=bytearray(struct.pack('<IIQ',ident,64,ctypes.addressof(v)))
try:fcntl.ioctl(g,0xc010ba06,e,True);raise AssertionError('cross fd accepted')
except OSError as ex:assert ex.errno==errno.ENOENT
fcntl.ioctl(f,0xc010ba06,e,True);assert v.raw[:16]==b'positive-control'
try:fcntl.ioctl(f,0xc010ba06,e,True);raise AssertionError('duplicate export accepted')
except OSError as ex:assert ex.errno==errno.EPERM
m=bytearray(struct.pack('<IIII32s64sII',2000,2000,1,5,bytes(32),b'parity',0,0));fcntl.ioctl(f,0xc078ba08,m,True)
assert m[16:48]==bytes(range(128,160))
bad=bytearray(struct.pack('<IIII32s64sII',2000,2000,99,5,bytes(32),b'parity',0,0))
try:fcntl.ioctl(f,0xc078ba08,bad,True);raise AssertionError('bad purpose accepted')
except OSError as ex:assert ex.errno==errno.EINVAL
fcntl.ioctl(f,0x4008ba05,bytearray(h),True);os.close(f);os.close(g);print('auth-ssh-control=ok')
'''


ASKPASS=r'''#!/bin/bash
IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
[[ $AUTH_PASSWORD_FILE == /tmp/parity-case/* ]] || exit 125
IFS= read -r __fixture_password < "$AUTH_PASSWORD_FILE" || exit 1
printf '%s\n' "$__fixture_password"
'''
SERVER=r'''IFS= read -r __fixture_uuid < /etc/bashos-parity-vm || exit 125
IFS= read -r __fixture_vendor < /sys/class/dmi/id/sys_vendor || exit 125
[[ $__fixture_uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ && $__fixture_vendor == QEMU && $EUID == 2000 && $PWD == /tmp/parity-case/* ]] || exit 125
sshd run --encrypted -a 127.0.0.1 -p "$1" -k "$2" --auth-method password
'''


def trace_rows(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def setup():
    assert not os.path.lexists('/dev/bashos-auth')
    assert kdf(b'password',b'somesalt',2,65536,1,32).hex()=='09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'
    account=pwd.getpwnam('parity');assert account.pw_uid==account.pw_gid==2000
    base=CASE/'sshd-auth-control';base.mkdir(mode=0o700);p=base/'control.py';p.write_text(CONTROL)
    trace=HOME/'sshd-auth-trace-control.jsonl';cfg=base/'control.json';cfg.write_text(json.dumps({'trace':str(trace)}))
    r=subprocess.run(['/usr/bin/python3',MOCK,str(cfg),'/usr/bin/python3',str(p)],cwd=base,env=dict(os.environ),
                     stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    rows=trace_rows(trace);ops=[x.get('transition',{}).get('op') for x in rows if x.get('transition')]
    assert r.returncode==0 and r.stdout==b'auth-ssh-control=ok\n' and not r.stderr
    assert ops==['new','write','seal','export-once','mint-synthetic','clear']
    assert {x.get('reply') for x in rows}.issuperset({'errno:1','errno:2','errno:22'})
    record('setup',control_ops=ops,rejected_cross_fd=True,rejected_duplicate=True,rejected_purpose=True)
    print('controls=verified')


def listening(port):
    wanted='0100007F:%04X'%port
    return any(len(parts)>=4 and parts[1]==wanted and parts[3]=='0A' for parts in
               (line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]))


def client(base,port,password_file,known,ask):
    env=dict(os.environ,SSH_ASKPASS=str(ask),SSH_ASKPASS_REQUIRE='force',DISPLAY=':99',AUTH_PASSWORD_FILE=str(password_file))
    command=['/usr/bin/ssh','-F','/dev/null','-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
             '-o','KbdInteractiveAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=5',
             '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null',
             '-p',str(port),'parity@127.0.0.1','printf ssh-auth-ok']
    p=subprocess.run(command,cwd=base,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
    return p.returncode,p.stdout,p.stderr


def process_identity(pid):
    raw=Path('/proc/%d/stat'%pid).read_text();fields=raw[raw.rindex(')')+2:].split()
    status=Path('/proc/%d/status'%pid).read_text().splitlines()
    uid=next([int(x) for x in line.split()[1:]] for line in status if line.startswith('Uid:'))
    if fields[0]=='Z' or uid[:2]!=[2000,2000]:raise RuntimeError('server process not live and owned')
    return {'pid':pid,'ppid':int(fields[1]),'starttime_ticks':int(fields[19]),'uids':uid,
            'process_group':os.getpgid(pid),'session':os.getsid(pid)}


def stop_owned_server(server,trace,initial):
    evidence={'supervisor_pid':server.pid,'observer_pid':os.getpid(),'initial_supervisor':initial,
              'signals':[],'forced_cleanup':False};pidfd=None
    bootstrap_path=Path(str(trace)+'.bootstrap')
    try:
        bootstrap=trace_rows(bootstrap_path)
        received=[x for x in bootstrap if x.get('stage')=='listener-received']
        evidence['listener_received']=received
        if server.poll() is None:
            root=process_identity(server.pid)
            if root!=initial or root['ppid']!=os.getpid() or root['process_group']!=server.pid or root['session']!=server.pid:
                raise RuntimeError('server supervisor identity changed')
            if len(received)==1:
                child_pid=received[0].get('child_pid')
                if not isinstance(child_pid,int) or child_pid<=1 or child_pid==server.pid:raise RuntimeError('invalid server child')
                child=process_identity(child_pid)
                if child['ppid']!=server.pid or child['process_group']!=server.pid or child['session']!=server.pid:
                    raise RuntimeError('server child is not the owned direct descendant')
                evidence['server_child']=child
                pidfd=os.pidfd_open(child_pid,0)
                evidence['pidfd_opened']=True;evidence['pidfd_number']=pidfd
                evidence['pidfd_link']=os.readlink('/proc/self/fd/%d'%pidfd)
                evidence['pidfd_fdinfo_before']=Path('/proc/self/fdinfo/%d'%pidfd).read_text()
                root_again=process_identity(server.pid);child_again=process_identity(child_pid)
                evidence['supervisor_recheck']=root_again;evidence['server_child_recheck']=child_again
                if root_again!=root or child_again!=child or server.poll() is not None:raise RuntimeError('server identity changed before signal')
                try:
                    signal.pidfd_send_signal(pidfd,signal.SIGTERM)
                    evidence['signals'].append({'target':'verified-server-child','pid':child_pid,'signal':int(signal.SIGTERM),'result':'sent'})
                except OSError as exc:
                    evidence['signals'].append({'target':'verified-server-child','pid':child_pid,'signal':int(signal.SIGTERM),'result':'error','error':repr(exc)})
            else:
                evidence['reason']='listener child identity unavailable'
            try:server.wait(timeout=6)
            except subprocess.TimeoutExpired:evidence['reason']='graceful supervisor wait timed out'
    except Exception as exc:
        evidence['reason']='graceful cleanup unavailable: '+repr(exc)
    if server.poll() is None:
        evidence['forced_cleanup']=True
        try:
            root=process_identity(server.pid)
            if root!=initial or root['ppid']!=os.getpid() or root['process_group']!=server.pid or root['session']!=server.pid:
                raise RuntimeError('cannot verify owned process group for forced cleanup')
            os.killpg(server.pid,signal.SIGKILL)
            evidence['signals'].append({'target':'owned-process-group','pgid':server.pid,'signal':int(signal.SIGKILL),'result':'sent'})
        except (OSError,RuntimeError) as exc:
            evidence['signals'].append({'target':'owned-process-group','pgid':server.pid,'signal':int(signal.SIGKILL),'result':'error','error':repr(exc)})
    try:
        evidence['supervisor_wait_status']=server.wait(timeout=4);evidence['supervisor_reaped']=True
    except subprocess.TimeoutExpired:
        evidence['supervisor_wait_status']=None;evidence['supervisor_reaped']=False
    if server.poll() is None:
        evidence['forced_cleanup']=True
        try:
            server.kill()
            evidence['signals'].append({'target':'remembered-direct-child','pid':server.pid,'signal':int(signal.SIGKILL),'result':'sent'})
        except OSError as exc:
            evidence['signals'].append({'target':'remembered-direct-child','pid':server.pid,'signal':int(signal.SIGKILL),'result':'error','error':repr(exc)})
        try:
            evidence['supervisor_wait_status']=server.wait(timeout=4);evidence['supervisor_reaped']=True
        except subprocess.TimeoutExpired:pass
    if pidfd is not None:
        try:
            poll=select.poll();poll.register(pidfd,select.POLLIN)
            evidence['server_pidfd_reports_exit']=bool(poll.poll(0))
            evidence['pidfd_fdinfo_after']=Path('/proc/self/fdinfo/%d'%pidfd).read_text()
        finally:os.close(pidfd)
    bootstrap=trace_rows(bootstrap_path);complete=[x for x in bootstrap if x.get('stage')=='supervision-complete']
    evidence['bootstrap_final']=bootstrap;evidence['supervision_complete']=complete
    evidence['clean']=(not evidence['forced_cleanup'] and evidence.get('supervisor_reaped') and
                       evidence.get('supervisor_wait_status')==0 and evidence.get('server_pidfd_reports_exit') and
                       len(complete)==1 and complete[0].get('wait_status')==0 and
                       any(x.get('target')=='verified-server-child' and x.get('result')=='sent' for x in evidence['signals']))
    record('server-teardown',**evidence)
    return bool(evidence['clean'])


def scenario(shell):
    base=CASE/'sshd-auth';base.mkdir(mode=0o700);key=base/'host';ask=base/'askpass';ask.write_text(ASKPASS);os.chmod(ask,0o700)
    subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],cwd=base,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=8)
    ktype,kblob,*_=key.with_suffix('.pub').read_text().split()
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    known=base/'known';known.write_text('[127.0.0.1]:%d %s %s\n'%(port,ktype,kblob))
    good=base/'good';good.write_text('password\n');wrong=base/'wrong';wrong.write_text('wrong\n')
    digest=kdf(b'password',b'somesalt',1,1024,1,32)
    phc='$argon2id$v=19$m=1024,t=1,p=1$'+b'somesalt'.hex()+'$'+digest.hex()
    shadow=base/'shadow';shadow.write_text('parity:'+phc+':19000:0:99999:7:::\n');os.chmod(shadow,0o600)
    env=dict(os.environ,PHCLIB_SHADOW=str(shadow));trace=HOME/'sshd-auth-trace-server.jsonl';cfg=base/'mock.json';cfg.write_text(json.dumps({'trace':str(trace)}))
    logpath=HOME/'sshd-auth-server.log';log=logpath.open('wb')
    server=subprocess.Popen(['/usr/bin/python3',MOCK,str(cfg),shell,'--noprofile','--norc','-c',SERVER,'server',str(port),str(key)],
                            cwd=base,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    initial=None
    try:
        initial=process_identity(server.pid)
        if initial['ppid']!=os.getpid() or initial['process_group']!=server.pid or initial['session']!=server.pid:
            raise RuntimeError('server supervisor is not an owned session leader')
        record('server-start',identity=initial)
        end=time.monotonic()+12
        while server.poll() is None and not listening(port) and time.monotonic()<end:time.sleep(.05)
        if server.poll() is not None or not listening(port):raise RuntimeError('owned server did not listen')
        bad=client(base,port,wrong,known,ask)
        accepted=client(base,port,good,known,ask)
    finally:
        try:
            if initial is not None:
                cleanup=stop_owned_server(server,trace,initial)
            else:
                result='already-exited'
                if server.poll() is None:
                    try:server.kill();result='sent'
                    except OSError as exc:result='error: '+repr(exc)
                try:wait_status=server.wait(timeout=4);reaped=True
                except subprocess.TimeoutExpired:wait_status=None;reaped=False
                record('server-teardown',supervisor_pid=server.pid,forced_cleanup=True,
                       signals=[{'target':'remembered-direct-child','pid':server.pid,'signal':int(signal.SIGKILL),'result':result}],
                       supervisor_wait_status=wait_status,supervisor_reaped=reaped,clean=False)
                cleanup=False
        finally:log.close()
    still_listening=listening(port);record('server-port-after',port=port,still_listening=still_listening)
    cleanup=cleanup and not still_listening
    trace_events=trace_rows(trace);ops=[x.get('transition',{}).get('op') for x in trace_events if x.get('transition')]
    writes=[base64.b64decode(x['transition']['data_base64']) for x in trace_events if x.get('transition',{}).get('op')=='write']
    mints=[x for x in trace_events if x.get('transition',{}).get('op')=='mint-synthetic']
    expected_ops=['new','write','seal','export-once','clear','new','write','seal','export-once','mint-synthetic','clear']
    failure=bad[0]!=0 and bad[1]==b'' and bool(bad[2])
    success=accepted[0]==0 and accepted[1]==b'ssh-auth-ok' and not accepted[2]
    mint=(len(mints)==1 and mints[0]['transition']['uid']==2000 and mints[0]['transition']['gid']==2000 and
          mints[0]['transition']['purpose']==1 and base64.b64decode(mints[0]['transition']['user_base64'])==b'parity')
    protocol=ops==expected_ops and writes==[b'wrong',b'password'] and mint
    logdata=logpath.read_bytes()
    record('result',wrong_status=bad[0],wrong_stdout_base64=b64(bad[1]),wrong_stderr_base64=b64(bad[2]),
           success_status=accepted[0],success_stdout_base64=b64(accepted[1]),success_stderr_base64=b64(accepted[2]),
           server_log_base64=b64(logdata),ops=ops,writes_base64=[b64(x) for x in writes],mints=mints,
           input_phc=phc,independent_digest_hex=digest.hex(),failure=failure,success=success,protocol=protocol,clean_teardown=cleanup)
    if not cleanup:raise RuntimeError('owned server teardown was not proved clean')
    print('sshd-password wrong-denied=%s accepted=%s protocol=%s' % (yes(failure),yes(success),yes(protocol)))


if __name__=='__main__':
    guard()
    try:
        if len(sys.argv)==2 and sys.argv[1]=='setup':setup()
        else:
            assert len(sys.argv)==2;scenario(sys.argv[1])
    except Exception as exc:
        try:record('exception',error=repr(exc),traceback=traceback.format_exc())
        except Exception:pass
        print('scenario-error=%s'%type(exc).__name__);sys.exit(1)
