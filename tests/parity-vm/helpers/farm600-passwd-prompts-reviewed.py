#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only observation of passwd prompts with a synthetic auth device.

This observes prompt boundaries, not each read syscall. A primary-owned gate
must qualify every result and the uncovered per-read and interruption clauses.
"""
import base64
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import traceback

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
BOOTSTRAP = '/opt/bashos-parity/harness/helpers/farm600-passwd-prompts-reviewed-bootstrap.py'
LIMIT = 65536
TERMINAL_SHA256 = 'f112dac0dd8a55da1816fcae1de4dca95b071abc53468448fffdaf9c16c6b199'
OLD = b'password'
NEW = b'synthetic-pass-one'
OTHER = b'synthetic-pass-two'
VECTOR = '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'


def guard():
    path = '/opt/bashos-parity/harness/helpers/farm600-passwd-prompts-reviewed-guard.py'
    spec = importlib.util.spec_from_file_location('passwd_guest_guard', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.verify()
    if os.getuid() != 2000 or os.geteuid() != 2000:
        raise RuntimeError('unexpected scratch identity')
    if os.path.lexists('/dev/bashos-auth'):
        raise RuntimeError('real auth device must be absent')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def modes(fd):
    a = termios.tcgetattr(fd)
    return [a[0], a[1], a[2], a[3], a[4], a[5],
            [v if isinstance(v, int) else v[0] for v in a[6]]]


def derive(password, salt, memory, passes, parallel, n, diagnostics):
    if b'\x00' in salt:
        raise RuntimeError('independent argon2 CLI cannot take a NUL salt')
    argv = [b'/usr/bin/argon2', salt, b'-id', b'-t', str(passes).encode(),
            b'-k', str(memory).encode(), b'-p', str(parallel).encode(), b'-l', str(n).encode(), b'-r']
    p = subprocess.run(argv, input=password, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
    diagnostics.append({'argv_salt_hex': salt.hex(), 'm': memory, 't': passes, 'p': parallel,
                        'length': n, 'status': p.returncode,
                        'stdout_base64': base64.b64encode(p.stdout).decode(),
                        'stderr_base64': base64.b64encode(p.stderr).decode()})
    if p.returncode or p.stderr or len(p.stdout) != n * 2 + 1 or not p.stdout.endswith(b'\n'):
        raise RuntimeError('independent argon2 CLI unavailable or malformed output')
    try:
        return bytes.fromhex(p.stdout[:-1].decode('ascii'))
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError('independent argon2 CLI returned invalid hex') from exc


def verify_new(shadow, diagnostics):
    try:
        rows = shadow.decode('ascii').splitlines()
    except UnicodeDecodeError:
        return False
    alice = [line for line in rows if line.startswith('alice:')]
    if len(alice) != 1:
        return False
    fields = alice[0].split(':')
    phc = fields[1].split('$') if len(fields) == 9 else []
    if len(phc) != 6 or phc[1:4] != ['argon2id', 'v=19', 'm=1024,t=1,p=1']:
        return False
    try:
        if len(phc[4]) == 32 and len(phc[5]) == 64:
            salt = bytes.fromhex(phc[4]); result = bytes.fromhex(phc[5])
        else:
            salt = base64.b64decode(phc[4] + '=' * (-len(phc[4]) % 4), validate=True)
            result = base64.b64decode(phc[5] + '=' * (-len(phc[5]) % 4), validate=True)
    except (ValueError, TypeError):
        return False
    if len(salt) != 16 or len(result) != 32:
        return False
    return derive(NEW, salt, 1024, 1, 1, 32, diagnostics) == result


CONTROL = r'''import ctypes,fcntl,os,signal,struct,termios
fd=os.open('/dev/bashos-auth',os.O_RDWR|os.O_CLOEXEC)
version=bytearray(32); fcntl.ioctl(fd,0x8020ba01,version,True)
assert struct.unpack_from('<I',version)[0]==1 and struct.unpack_from('<Q',version,8)[0]&1
ids=[]
for s in (b'one',b'two'):
 h=bytearray(8); fcntl.ioctl(fd,0xc008ba02,h,True); ids.append(struct.unpack_from('<I',h)[0])
 buf=ctypes.create_string_buffer(s); w=bytearray(struct.pack('<IIQ',ids[-1],len(s),ctypes.addressof(buf)))
 fcntl.ioctl(fd,0x4010ba03,w,True); fcntl.ioctl(fd,0x4008ba04,h,True)
c=bytearray(struct.pack('<IIII',ids[0],ids[1],0,0)); fcntl.ioctl(fd,0xc010ba07,c,True)
assert struct.unpack_from('<I',c,8)[0]==0
c=bytearray(struct.pack('<IIII',ids[0],ids[0],0,0)); fcntl.ioctl(fd,0xc010ba07,c,True)
assert struct.unpack_from('<I',c,8)[0]==1
for i in ids: fcntl.ioctl(fd,0x4008ba05,bytearray(struct.pack('<II',i,0)),True)
os.close(fd)
t=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY); old=termios.tcgetattr(t); new=termios.tcgetattr(t)
new[3]&=~(termios.ECHO|termios.ICANON);new[6][termios.VMIN]=1;new[6][termios.VTIME]=0
try:
 termios.tcsetattr(t,termios.TCSANOW,new);os.write(t,b'CONTROL-INPUT: ')
 s=b''
 while not s.endswith(b'\n'): s+=os.read(t,1)
 assert s==b'control-token\n'
finally:
 termios.tcsetattr(t,termios.TCSANOW,old);os.close(t)
os.write(1,b'CONTROL-OK\n')
gate=int(os.environ['PTY_DRAIN_RELEASE_FD'])
signal.signal(signal.SIGHUP, signal.SIG_IGN)
child=os.fork()
if child==0:
 if os.read(gate,1)==b'G': os.write(1,b'CONTROL-LATE\n')
 os._exit(0)
os.write(1,('CONTROL-WRITER:%d\n' % child).encode())
os.close(gate)
'''


def private_db(folder):
    folder.mkdir(mode=0o700)
    db = folder / 'db'; db.mkdir(mode=0o700)
    passwd = b'alice:x:2000:2000:Fixture:/tmp:/bin/sh\n'
    group = b'alice:x:2000:\n'
    shadow = ('alice:$argon2id$v=19$m=65536,t=2,p=1$736f6d6573616c74$'+VECTOR+':19000:0:99999:7:::\n').encode()
    for name, data in (('passwd', passwd), ('group', group), ('shadow', shadow)):
        path = db / name
        path.write_bytes(data); path.chmod(0o600)
    return db, {'passwd': passwd, 'group': group, 'shadow': shadow}


def interact(folder, label, argv, prompts, answers, env):
    terminal_path = Path('/opt/bashos-parity/harness/terminal.py')
    if hashlib.sha256(terminal_path.read_bytes()).hexdigest() != TERMINAL_SHA256:
        raise RuntimeError('terminal lifecycle helper digest differs')
    sys.path.insert(0, '/opt/bashos-parity/harness')
    import terminal
    terminal.set_subreaper()
    trace = HOME / ('farm600-passwd-prompts-' + label + '-trace.jsonl')
    cfg = folder / (label + '-mock.json')
    cfg.write_text(json.dumps({'trace': str(trace)}))
    master, slave = pty.openpty()
    os.set_blocking(master, False)
    attrs = termios.tcgetattr(slave)
    attrs[3] |= termios.ECHO | termios.ICANON | termios.ISIG
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    before = modes(slave)
    events = []; output = bytearray(); failure = None; observer_error = None
    timeout = False; proc = None; status = None; after = None
    release_read = release_write = None
    teardown = {'slave_closed':False, 'eof':False, 'eof_kind':None,
                'forced':False, 'remaining':None, 'reaped':[], 'cleanup':[]}
    if label == 'control':
        release_read, release_write = os.pipe2(os.O_CLOEXEC)
        env = dict(env, PTY_DRAIN_RELEASE_FD=str(release_read))
    start = time.monotonic(); deadline = start + 30
    def event(name, **kw):
        events.append({'name': name, 'ms': round((time.monotonic()-start)*1000),
                       'offset': len(output), **kw})
    def spawn_child():
        os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    def pump():
        if time.monotonic() >= deadline: raise TimeoutError('observer deadline')
        ready, _, _ = select.select([master], [], [], min(.05, max(0, deadline-time.monotonic())))
        if ready:
            try: data = os.read(master, 4096)
            except BlockingIOError: return
            except OSError as exc:
                if exc.errno == errno.EIO and teardown['slave_closed']:
                    teardown['eof'] = True; teardown['eof_kind'] = 'EIO'; return
                raise
            if not data and teardown['slave_closed']:
                teardown['eof'] = True; teardown['eof_kind'] = 'EOF'; return
            if data:
                output.extend(data)
                if len(output) >= LIMIT: raise RuntimeError('transcript limit')
    def wait_for(prompt):
        until = min(deadline-2, time.monotonic()+7)
        while time.monotonic() < until:
            if prompt in output: return True
            if proc.poll() is not None:
                pump()
                return prompt in output
            pump()
        return False
    try:
        proc = subprocess.Popen(['/usr/bin/python3', BOOTSTRAP, str(cfg), *argv],
                                cwd=CASE, env=env, stdin=slave, stdout=slave, stderr=slave,
                                preexec_fn=spawn_child, close_fds=True,
                                pass_fds=(() if release_read is None else (release_read,)))
        if release_read is not None:
            os.close(release_read); release_read = None
        event('spawn', pid=proc.pid, initial_modes=before)
        for index, (prompt, answer) in enumerate(zip(prompts, answers)):
            event('wait-prompt', index=index, expected_base64=base64.b64encode(prompt).decode())
            if not wait_for(prompt):
                failure = 'missing prompt '+str(index)
                event('prompt-missing', index=index, leader_live=proc.poll() is None)
                break
            positions = [output.find(p) for p in prompts[:index+1]]
            current_modes = modes(slave)
            event('prompt', index=index, positions=positions, modes=current_modes,
                  leader_live=proc.poll() is None)
            if positions != sorted(positions) or any(p < 0 for p in positions) or current_modes[3] & termios.ECHO:
                failure = 'prompt order or echo at prompt '+str(index)
                break
            sent = os.write(master, answer+b'\n')
            event('input', index=index, intended_base64=base64.b64encode(answer+b'\n').decode(), bytes_written=sent)
            if sent != len(answer)+1: raise RuntimeError('short input write')
        while proc.poll() is None and time.monotonic() < deadline-1:
            pump()
        if proc.poll() is None:
            timeout = True
            if failure is None: failure = 'product did not exit'
        else:
            status = proc.wait(timeout=1)
            after = modes(slave)
            event('natural-exit', status=status, final_modes=after)
            os.close(slave); slave = None; teardown['slave_closed'] = True
            event('slave-closed')
            if release_write is not None:
                count = os.write(release_write, b'G')
                event('drain-control-release', bytes_written=count)
                if count != 1: raise RuntimeError('drain control release failed')
                os.close(release_write); release_write = None
            while not teardown['eof']:
                pump()
            event('drain-end', result=teardown['eof_kind'])
            # Orphaned descendants are reparented to this subreaper. Wait
            # briefly for natural exit and reap zombies; never treat a live
            # survivor as a complete observation.
            stop = min(deadline, time.monotonic()+2)
            while time.monotonic() < stop:
                found = terminal.owned_processes(proc.pid)
                for child in found:
                    if child['state'] == 'Z':
                        try:
                            got, wait_status = os.waitpid(child['pid'], os.WNOHANG)
                            if got: teardown['reaped'].append({'pid':got, 'wait_status':wait_status})
                        except ChildProcessError: pass
                found = terminal.owned_processes(proc.pid)
                if not found: break
                time.sleep(.02)
            teardown['remaining'] = terminal.owned_processes(proc.pid)
            if teardown['remaining']:
                raise RuntimeError('fixture-owned descendants remain after drain')
            event('teardown-complete', remaining=teardown['remaining'], reaped=teardown['reaped'])
    except Exception as exc:
        observer_error = type(exc).__name__ + ': ' + str(exc)
    finally:
        if proc is not None and proc.poll() is None:
            teardown['forced'] = True
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=3)
        if release_read is not None: os.close(release_read)
        if release_write is not None: os.close(release_write)
        if slave is not None: os.close(slave)
        if proc is not None and teardown['remaining'] != []:
            teardown['cleanup'] = terminal.cleanup(proc.pid)
        os.close(master)
    raw = bytes(output)
    raw_path = HOME / ('farm600-passwd-prompts-' + label + '-tty.raw')
    raw_path.write_bytes(raw)
    trace_raw = trace.read_bytes() if trace.exists() else b''
    bootstrap_path = Path(str(trace) + '.bootstrap')
    bootstrap_raw = bootstrap_path.read_bytes() if bootstrap_path.exists() else b''
    return {'label': label, 'failure': failure, 'observer_error': observer_error, 'timeout': timeout,
            'status': status, 'before': before, 'after': after, 'events': events, 'teardown': teardown,
            'terminal_sha256': TERMINAL_SHA256,
            'transcript': {'name': raw_path.name, 'length': len(raw), 'sha256': digest(raw)},
            'trace': {'name':trace.name, 'exists':trace.exists(), 'length':len(trace_raw), 'sha256':digest(trace_raw)},
            'trace_bootstrap': {'name':bootstrap_path.name, 'exists':bootstrap_path.exists(),
                                'length':len(bootstrap_raw), 'sha256':digest(bootstrap_raw)}}


def main():
    guard()
    if len(sys.argv) != 3 or sys.argv[1] not in ('setup', 'run') or sys.argv[2] not in ('set-success','set-mismatch','change-success'):
        raise SystemExit('invalid invocation')
    mode, scenario = sys.argv[1:]
    diagnostics = []; report = {'schema':'farm600-passwd-prompts-v1', 'mode':mode, 'scenario':scenario,
                                'complete':False, 'oracle':diagnostics}
    path = HOME / ('farm600-passwd-prompts-' + mode + '.json')
    try:
        if mode == 'setup' and derive(OLD, b'somesalt', 65536, 2, 1, 32, diagnostics).hex() != VECTOR:
            raise RuntimeError('independent Argon2 known-vector control failed')
        folder = CASE / ('prompt-'+mode)
        db, originals = private_db(folder)
        env = dict(os.environ, PHCLIB_PASSWD=str(db/'passwd'), PHCLIB_GROUP=str(db/'group'),
                   PHCLIB_SHADOW=str(db/'shadow'), BPW_LOCK_DIR=str(folder/'lock'),
                   PHCLIB_M='1024', PHCLIB_T='1', PHCLIB_P='1', BASHPASSWD_REQUIRE_KERNEL_SECRETS='1')
        env.pop('BASHPASSWD_KERNEL_SECRETS', None)
        if mode == 'setup':
            control = interact(folder, 'control', ['/usr/bin/python3','-c',CONTROL],
                               [b'CONTROL-INPUT: '], [b'control-token'], env)
            report['control'] = control
            raw = (HOME/control['transcript']['name']).read_bytes()
            trace = (HOME/control['trace']['name']).read_bytes()
            entries = [json.loads(line) for line in trace.splitlines()]
            comparisons = [row.get('transition', {}).get('result') for row in entries
                           if row.get('transition', {}).get('op') == 'compare']
            exits = [e for e in control['events'] if e['name'] == 'natural-exit']
            writer = re.search(rb'CONTROL-WRITER:(\d+)\r?\n', raw)
            if (control['failure'] or control['observer_error'] or control['timeout'] or control['status'] != 0
                    or control['before'] != control['after'] or b'CONTROL-OK' not in raw or b'control-token' in raw
                    or comparisons != [0, 1] or not control['trace_bootstrap']['exists']
                    or not control['teardown']['eof'] or control['teardown']['remaining'] != []
                    or len(exits) != 1 or raw.find(b'CONTROL-LATE', exits[0]['offset']) < 0
                    or not writer or not any(row['pid'] == int(writer.group(1)) and row['wait_status'] == 0
                                             for row in control['teardown']['reaped'])):
                raise RuntimeError('PTY or synthetic-device control failed')
            report['complete'] = True
        else:
            shell = '/opt/bashos-parity/candidate'
            command = 'passwd ' + ('change' if scenario == 'change-success' else 'set') + ' alice'
            prompts = ([b'Current password: '] if scenario == 'change-success' else []) + [b'New password: ', b'Retype new password: ']
            answers = ([OLD] if scenario == 'change-success' else []) + [NEW, OTHER if scenario == 'set-mismatch' else NEW]
            observation = interact(folder, 'candidate', [shell,'--noprofile','--norc','-c',command], prompts, answers, env)
            report['observation'] = observation
            after = {name:(db/name).read_bytes() for name in originals}
            for name, content in originals.items():
                (HOME/('farm600-passwd-prompts-'+name+'-before.raw')).write_bytes(content)
                (HOME/('farm600-passwd-prompts-'+name+'-after.raw')).write_bytes(after[name])
            report['files'] = {name:{'before_sha256':digest(originals[name]), 'after_sha256':digest(after[name]),
                                    'before_bytes':len(originals[name]), 'after_bytes':len(after[name]),
                                    'mode':(db/name).stat().st_mode & 0o777} for name in originals}
            report['shadow_unchanged'] = after['shadow'] == originals['shadow']
            report['account_files_unchanged'] = after['passwd'] == originals['passwd'] and after['group'] == originals['group']
            report['new_password_verified'] = None if scenario == 'set-mismatch' else verify_new(after['shadow'], diagnostics)
            raw = (HOME/observation['transcript']['name']).read_bytes()
            report['synthetic_inputs_absent_from_tty'] = all(x not in raw for x in answers)
            report['prompts_exact_once_in_order'] = (all(raw.count(p) == 1 for p in prompts)
                and [raw.index(p) for p in prompts] == sorted(raw.index(p) for p in prompts))
            report['complete'] = True
        record(path, report)
    except Exception as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        report['traceback'] = traceback.format_exc()
        record(path, report)
        raise SystemExit('observer unavailable; inspect private diagnostics')
    if mode == 'setup': return 0
    obs = report['observation']
    okay = (obs['failure'] is None and obs['observer_error'] is None and not obs['timeout']
            and obs['teardown']['eof'] and obs['teardown']['remaining'] == [] and not obs['teardown']['forced']
            and obs['before'] == obs['after'] and report['account_files_unchanged']
            and report['synthetic_inputs_absent_from_tty'] and report['prompts_exact_once_in_order']
            and ((obs['status'] == 1 and report['shadow_unchanged'])
                 if scenario == 'set-mismatch' else (obs['status'] == 0 and report['new_password_verified'])))
    print('observation=' + ('ok' if okay else 'not-ok'))
    return 0 if okay else 1


if __name__ == '__main__':
    sys.exit(main())
