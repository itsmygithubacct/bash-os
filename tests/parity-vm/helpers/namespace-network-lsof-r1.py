#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned process/descriptor checks in a private, single-id PID namespace."""
import base64
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import uuid

HOME = Path('/tmp/parity-home')
CASE = Path('/tmp/parity-case')


def guard():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
    if vendor != 'QEMU' or Path.cwd() != CASE or os.environ.get('HOME') != str(HOME):
        raise RuntimeError('fixture identity mismatch')
    if os.getuid() != os.geteuid():
        raise RuntimeError('guest uid mismatch')
    if os.getuid() != 0 or [list(map(int, line.split())) for line in
                            Path('/proc/self/uid_map').read_text().splitlines()] != [[0, 2000, 1]]:
        raise RuntimeError('expected one-id mapped guest user')
    virt = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                          text=True, timeout=3, check=True).stdout.strip()
    if virt not in ('qemu', 'kvm'):
        raise RuntimeError('not a disposable QEMU/KVM guest')


def record(name, data):
    (HOME / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def identity(pid):
    path = Path('/proc') / str(pid)
    return {'pid': pid, 'status': (path / 'status').read_text(),
            'stat': (path / 'stat').read_text(),
            'uid_map': (path / 'uid_map').read_text(),
            'namespaces': {n: os.readlink(path / 'ns' / n) for n in ('user', 'pid', 'mnt')}}


def descriptor_snapshot(pid):
    result = {}
    for entry in sorted((Path('/proc') / str(pid) / 'fd').iterdir(), key=lambda p: int(p.name)):
        try:
            target = os.readlink(entry)
            info = entry.stat()
        except FileNotFoundError:
            continue
        kind = ('REG' if stat.S_ISREG(info.st_mode) else 'DIR' if stat.S_ISDIR(info.st_mode)
                else 'FIFO' if stat.S_ISFIFO(info.st_mode) else 'SOCK' if stat.S_ISSOCK(info.st_mode)
                else 'CHR' if stat.S_ISCHR(info.st_mode) else 'BLK' if stat.S_ISBLK(info.st_mode)
                else 'OTHER')
        if target.startswith('socket:'):
            kind = 'sock'
        elif target.startswith('pipe:'):
            kind = 'pipe'
        elif target.startswith('anon_inode:'):
            kind = 'anon'
        result[entry.name] = {'target': target, 'kind': kind, 'inode': info.st_ino}
    return result


def hold(label):
    directory = CASE / ('fixture-' + label)
    directory.mkdir(mode=0o700)
    file_path = directory / 'regular'
    file_path.write_text('descriptor fixture\n')
    fifo_path = directory / 'fifo'
    os.mkfifo(fifo_path, 0o600)
    file_fd = os.open(file_path, os.O_RDONLY)
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    fifo_fd = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
    sockets = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    data = {'pid': os.getpid(), 'fds': {'regular': file_fd, 'directory': dir_fd,
             'fifo': fifo_fd, 'socket': sockets[0].fileno()}, 'directory': str(directory)}
    print(json.dumps(data, sort_keys=True), flush=True)
    if sys.stdin.readline() != 'done\n':
        raise RuntimeError('owned fixture child was not released')


def spawn(label):
    cmd = ['/usr/bin/python3', __file__, 'hold', label]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    info = json.loads(line)
    if info['pid'] != proc.pid:
        raise RuntimeError('child handshake pid differs')
    return proc, info


def release(children):
    for proc, _ in children:
        if proc.poll() is None:
            try:
                proc.stdin.write('done\n'); proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
    for proc, _ in children:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise RuntimeError('fixture child did not exit after release')
        if proc.returncode != 0:
            raise RuntimeError('fixture child exited with status ' + str(proc.returncode))


def capture(command):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=8)
    if len(stdout) > 512*1024 or len(stderr) > 512*1024:
        raise RuntimeError('output exceeds evidence bound')
    return {'pid': proc.pid, 'argv': command, 'status': proc.returncode,
            'stdout_base64': base64.b64encode(stdout).decode(),
            'stderr_base64': base64.b64encode(stderr).decode()}


def ref_rows(output):
    rows, pid, current = [], None, None
    for line in output.decode('utf-8', 'replace').splitlines():
        if not line:
            continue
        key, value = line[0], line[1:]
        if key == 'p':
            if current:
                rows.append(current)
            current = None; pid = int(value)
        elif key == 'f':
            if current:
                rows.append(current)
            match = re.match(r'^(\d+)', value)
            current = {'pid':pid, 'fd':int(match.group(1)) if match else None, 'f':value}
        elif current is not None and key in ('t', 'n', 'i'):
            current[key] = value
    if current:
        rows.append(current)
    return rows


def candidate_rows(output):
    lines = output.decode('utf-8','replace').splitlines()
    if not lines or lines[0].split() != ['COMMAND','PID','USER','FD','TYPE','PATH']:
        raise ValueError('unexpected candidate heading')
    rows=[]
    for line in lines[1:]:
        fields=line.split(None, 5)
        if len(fields) != 6 or not fields[1].isdigit() or not fields[3].isdigit():
            raise ValueError('unparseable candidate row: ' + line[:300])
        rows.append({'command':fields[0],'pid':int(fields[1]),'user':fields[2],
                     'fd':int(fields[3]),'type':fields[4],'path':fields[5]})
    return rows


def raw_output(recording):
    return base64.b64decode(recording['stdout_base64'])


def ref_run(args):
    return capture(['/usr/bin/lsof', '-nP', '-F', 'pftni'] + args)


def check_native_known(rows, info, proc_fds):
    problems=[]
    expected_types={'regular':{'REG'},'directory':{'DIR'},'fifo':{'FIFO'},'socket':{'unix'}}
    for label, fd in info['fds'].items():
        matches=[r for r in rows if r['pid']==info['pid'] and r['fd']==fd]
        if len(matches)!=1:
            problems.append('native count for %s: %d' % (label,len(matches))); continue
        row=matches[0]; kernel=proc_fds[str(fd)]
        if row.get('t') not in expected_types[label]:
            problems.append('native type for '+label+': '+str(row.get('t')))
        if label != 'socket' and row.get('n') != kernel['target']:
            problems.append('native pathname for '+label+': '+str(row.get('n')))
        if label == 'socket' and row.get('i') != str(kernel['inode']):
            problems.append('native socket inode: '+str(row.get('i')))
    return problems


def native_for_children(children, result):
    for _, info in children:
        pid=info['pid']; kernel=descriptor_snapshot(pid)
        native=ref_run(['-a','-p',str(pid)])
        rows=ref_rows(raw_output(native))
        result['children'].append({'handshake':info,'identity':identity(pid),'proc_fds':kernel,
                                   'native':native,'native_rows':rows})
        if native['status'] != 0:
            result['control_errors'].append('native lsof status for '+str(pid))
        result['control_errors'].extend(check_native_known(rows,info,kernel))


def candidate_command(binary, args, label):
    # The helper has already verified the disposable guest, and this separate
    # executable shell repeats the guard before any lsof behavior.
    script=r'''[[ $UID == 0 && $EUID == 0 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r vendor </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r marker </etc/bashos-parity-vm || exit 125
[[ $vendor == QEMU && $marker =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
mapfile -t maps </proc/self/uid_map || exit 125
(( ${#maps[@]} == 1 )) || exit 125
read -r a b n tail <<<"${maps[0]}"; [[ $a == 0 && $b == 2000 && $n == 1 && -z $tail ]] || exit 125
virt=$(/usr/bin/systemd-detect-virt --vm) || exit 125
[[ $virt == qemu || $virt == kvm ]] || exit 125
[[ $(type -t lsof) == builtin ]] || exit 99
printf 'READY\n'
IFS= read -r gate || exit 97
lsof "$@" >"$HOME/'''+label+r'''.out" 2>"$HOME/'''+label+r'''.err"; rc=$?
printf '%s\n' "$rc" >"$HOME/'''+label+r'''.status"
printf 'DONE\n'
IFS= read -r gate || exit 97
'''
    return subprocess.Popen([binary,'--noprofile','--norc','-c',script,'fixture']+args,
                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)


def invoke(binary,args,label,children):
    proc=candidate_command(binary,args,label)
    if proc.stdout.readline() != 'READY\n':
        raise RuntimeError('candidate shell failed guard or handshake')
    tracked=[os.getpid()]+[info['pid'] for _,info in children]+[proc.pid]
    visible=sorted(int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit())
    if set(visible)!=set(tracked):
        raise RuntimeError('private pid namespace has unexpected processes: '+repr(visible))
    before={str(pid):descriptor_snapshot(pid) for pid in tracked}
    proc.stdin.write('go\n'); proc.stdin.flush()
    if proc.stdout.readline() != 'DONE\n':
        raise RuntimeError('candidate shell did not complete command')
    after={str(pid):descriptor_snapshot(pid) for pid in tracked}
    out=(HOME/(label+'.out')).read_bytes(); err=(HOME/(label+'.err')).read_bytes()
    if len(out)>512*1024 or len(err)>512*1024:
        raise RuntimeError('candidate output exceeds evidence bound')
    rc=int((HOME/(label+'.status')).read_text().strip())
    shell_identity=identity(proc.pid)
    proc.stdin.write('done\n'); proc.stdin.flush()
    shellout,shellerr=proc.communicate(timeout=5)
    return {'args':args,'pid':proc.pid,'status':rc,'shell_status':proc.returncode,
            'stdout_base64':base64.b64encode(out).decode(),'stderr_base64':base64.b64encode(err).decode(),
            'shell_stdout':shellout,'shell_stderr':shellerr,'identity':shell_identity,
            'visible_pids':visible,'before':before,'after':after}


def candidate_known(rows, info, proc_fds):
    problems=[]
    for label,fd in info['fds'].items():
        found=[r for r in rows if r['pid']==info['pid'] and r['fd']==fd]
        if len(found)!=1:
            problems.append('%s fd count %d' % (label,len(found))); continue
        kernel=proc_fds[str(fd)]
        if found[0]['type']!=kernel['kind'] or found[0]['path']!=kernel['target']:
            problems.append('%s differs from proc target/type' % label)
    return problems


def selected_children(rows, children):
    return {info['pid'] for _,info in children if any(r['pid']==info['pid'] for r in rows)}


def run(mode, binary=None):
    if os.getpid()!=1 or pwd.getpwuid(0).pw_name!='root':
        raise RuntimeError('private PID namespace or passwd control invalid')
    children=[]; result={'mode':mode,'children':[],'control_errors':[],'checks':[], 'calls':{},
                          'self':identity(os.getpid())}
    try:
        children.append(spawn(mode+'-a')); children.append(spawn(mode+'-b'))
        native_for_children(children,result)
        if result['control_errors']:
            record(mode+'.json',result)
            raise RuntimeError('native lsof/proc control failed')
        p1,p2=[info['pid'] for _,info in children]
        if mode=='control':
            for label,args,want in [('name',['-u','root'],{p1,p2}),('numeric',['-u','0'],{p1,p2}),
                                    ('or',['-u','root','-p',str(p1)],{p1,p2}),
                                    ('and',['-a','-u','root','-p',str(p1)],{p1})]:
                ref=ref_run(args); rows=ref_rows(raw_output(ref)); selected={r['pid'] for r in rows if r['pid'] in {p1,p2}}
                result['calls'][label]={'native':ref,'native_rows':rows,'selected':sorted(selected)}
                if ref['status']!=0 or selected!=want:
                    result['control_errors'].append('native '+label+' selector did not match')
            record('control.json',result)
            if result['control_errors']:
                raise RuntimeError('native selector control failed')
            return
        calls={'pid':[('pid',['-p',str(p1)])],
               'scan':[('all',[]),('repeated',['-p',str(p1),'-p',str(p2)]),('bare',[str(p1),str(p2)])],
               'user':[('name',['-u','root']),('numeric',['-u','0']),('or',['-u','root','-p',str(p1)]),
                       ('and',['-a','-u','root','-p',str(p1)])]}[mode]
        failures=[]
        for label,args in calls:
            reference_args = (['-p',str(p1),'-p',str(p2)] if label=='bare' else args)
            reference=ref_run(reference_args)
            reference_rows=ref_rows(raw_output(reference))
            reference_selected={r['pid'] for r in reference_rows if r['pid'] in {p1,p2}}
            reference_want={p1} if label in ('pid','and') else {p1,p2}
            if reference['status'] != 0 or reference_selected != reference_want:
                result['control_errors'].append('same-child reference mismatch for '+label)
            call=invoke(binary,args,label,children)
            call['native']=reference
            call['native_rows']=reference_rows
            call['native_selected']=sorted(reference_selected)
            try:
                rows=candidate_rows(raw_output(call)); parse_error=None
            except ValueError as exc:
                rows=[]; parse_error=str(exc)
            call['rows']=rows; call['parse_error']=parse_error
            selected=selected_children(rows,children)
            want={p1} if label in ('pid','and') else {p1,p2}
            errors=[]
            if call['status']!=0 or call['shell_status']!=0 or parse_error:
                errors.append('command failed or output was unparseable')
            if selected!=want:
                errors.append('selected owned children differ: '+repr(sorted(selected)))
            if label=='pid' and any(r['pid']!=p1 for r in rows):
                errors.append('PID selection leaked unrelated rows')
            if label in ('repeated','bare') and any(r['pid'] not in {p1,p2} for r in rows):
                errors.append('explicit selection leaked unrelated rows')
            for index,(_,info) in enumerate(children):
                if info['pid'] in want:
                    errors.extend(candidate_known(rows,info,result['children'][index]['proc_fds']))
            if label=='all':
                if any(r['pid'] not in call['visible_pids'] for r in rows):
                    errors.append('enumeration included an untracked process')
                # Require stable descriptors on both owned children, and stable
                # stdio of supervisor and shell stdin (other shell fds are redirected).
                for pid_text,before in call['before'].items():
                    after=call['after'][pid_text]
                    for fd,data in before.items():
                        if after.get(fd)!=data:
                            continue
                        pid=int(pid_text)
                        if pid==os.getpid() and fd not in ('0','1','2'):
                            continue
                        if pid==call['pid'] and fd != '0':
                            continue
                        match=[r for r in rows if r['pid']==pid and r['fd']==int(fd) and
                               r['path']==data['target'] and r['type']==data['kind']]
                        if len(match)!=1:
                            errors.append('stable proc fd missing for pid=%d fd=%s' % (pid,fd))
            call['selected']=sorted(selected); call['errors']=errors
            result['calls'][label]=call
            failures.extend(label+': '+e for e in errors)
        result['checks']=failures
        record(mode+'.json',result)
        if result['control_errors']:
            raise RuntimeError('same-child reference failed; runtime result requires invalid-control review')
        if failures:
            raise RuntimeError('candidate selection/descriptor assertions failed: '+repr(failures[:20]))
        print(mode+'=ok')
    except Exception as exc:
        result['fatal_error']=str(exc)
        record(mode+'.json',result)
        raise
    finally:
        release(children)


def main():
    guard()
    mode=sys.argv[1]
    if mode=='hold':
        hold(sys.argv[2])
    elif mode in ('control','pid','scan','user'):
        run(mode,sys.argv[2] if len(sys.argv)>2 else None)
    else:
        raise ValueError('unknown mode')


if __name__ == '__main__':
    main()
