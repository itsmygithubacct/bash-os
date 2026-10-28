#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent Linux syscall controls for nonprivileged VM fixtures.

Every entry point checks the disposable guest marker before any test behavior.
The calling process is discarded after a seccomp filter or unshare request.
"""
import base64
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


def guard():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
    uuid.UUID(marker)
    uid = os.geteuid()
    if os.getuid() != uid:
        raise RuntimeError('real and effective uid differ')
    if uid == 0:
        mapping = [list(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
        if mapping != [[0, 2000, 1]]:
            raise RuntimeError('root is not the single-id mapped guest user')
    elif uid != 2000:
        raise RuntimeError('guest uid mismatch')
    if vendor != 'QEMU' or Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
        raise RuntimeError('disposable VM identity or scratch path mismatch')
    virt = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                          text=True, timeout=3, check=True).stdout.strip()
    if virt not in ('qemu', 'kvm'):
        raise RuntimeError('not a QEMU/KVM disposable guest')


def put(name, obj):
    (Path(os.environ['HOME']) / name).write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n')


def status():
    raw = Path('/proc/self/status').read_text()
    values = dict(line.split(':', 1) for line in raw.splitlines() if ':' in line)
    return {'raw': raw, 'nnp': int(values['NoNewPrivs'].strip()),
            'seccomp': int(values['Seccomp'].strip()),
            'filters': int(values['Seccomp_filters'].strip()) if 'Seccomp_filters' in values else None}


def syscall(lib, nr, *args):
    ctypes.set_errno(0)
    result = lib.syscall(nr, *args)
    err = ctypes.get_errno() if result < 0 else 0
    return {'number': nr, 'result': int(result), 'errno': err, 'error': os.strerror(err) if err else None}


class Instruction(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Instruction))]


def seccomp_control(mode, profile):
    # The locked guest is Debian amd64. Do not guess other syscall tables.
    if os.uname().machine != 'x86_64':
        raise RuntimeError('amd64 syscall table required')
    lib = ctypes.CDLL(None, use_errno=True)
    data = Path(profile).read_bytes()
    before = status()
    if mode == 'allow' and before['filters'] is None:
        raise RuntimeError('proc status lacks Seccomp_filters; cannot prove new filter')
    report = {'mode': mode, 'profile_base64': base64.b64encode(data).decode(), 'before': before,
              'request': {'syscall': 'seccomp', 'number': 317, 'operation': 1, 'flags': 0,
                          'sock_filter_size': ctypes.sizeof(Instruction)}}
    if mode != 'permission':
        ctypes.set_errno(0)
        rc = lib.prctl(38, 1, 0, 0, 0)
        report['prctl_set_no_new_privs'] = {'result': rc, 'errno': ctypes.get_errno() if rc else 0}
        if rc != 0:
            put('control.json', report)
            raise RuntimeError('cannot set no_new_privs')
    elif before['nnp'] != 0:
        put('control.json', report)
        raise RuntimeError('no_new_privs already set; cannot exercise EACCES')
    if not data or len(data) % ctypes.sizeof(Instruction):
        raise RuntimeError('control requires complete instructions')
    instructions = (Instruction * (len(data) // 8)).from_buffer_copy(data)
    program = Program(len(instructions), instructions)
    report['request']['instruction_count'] = len(instructions)
    report['reply'] = syscall(lib, 317, 1, 0, ctypes.byref(program))
    report['after'] = status()
    if mode == 'deny' and report['reply']['result'] == 0:
        space = ctypes.create_string_buffer(512)
        report['uname'] = syscall(lib, 63, ctypes.byref(space))
        report['getpid'] = syscall(lib, 39)
    put('control.json', report)
    wanted = {'allow': 0, 'deny': 0, 'invalid': errno.EINVAL, 'permission': errno.EACCES}[mode]
    if report['reply']['errno'] != wanted or (wanted == 0 and report['reply']['result'] != 0):
        raise RuntimeError('independent seccomp control differs from expected kernel result')
    if mode in ('allow', 'deny'):
        if report['after']['seccomp'] != 2 or (before['filters'] is not None and
            report['after']['filters'] != before['filters'] + 1):
            raise RuntimeError('filter not observed in proc status')
    if mode == 'deny' and (report['uname']['errno'] != errno.EDOM or report['getpid']['result'] <= 0):
        raise RuntimeError('deny filter did not isolate uname as expected')


def uname_probe():
    lib = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(512)
    result = {'uname': syscall(lib, 63, ctypes.byref(buf)), 'getpid': syscall(lib, 39),
              'status': status()}
    put('child-probe.json', result)
    if result['uname']['errno'] != errno.EDOM or result['getpid']['result'] <= 0:
        raise RuntimeError('child syscall behavior does not match EDOM control')
    print('child-uname=EDOM child-getpid=ok')


def namespace_map(pid):
    path = Path('/proc') / str(pid) / 'ns'
    return {p.name: os.readlink(p) for p in sorted(path.iterdir())}


def ns_control(mode):
    if os.uname().machine != 'x86_64':
        raise RuntimeError('amd64 syscall table required')
    lib = ctypes.CDLL(None, use_errno=True)
    report = {'before': namespace_map('self'), 'status': status(), 'requests': []}
    if mode == 'enter':
        fd = os.open('seed.txt', os.O_RDONLY)
        report['requests'].append({'kind': 'regular', 'fd': fd, 'flags': 0,
                                   'reply': syscall(lib, 308, fd, 0)})
        os.close(fd)
        report['requests'].append({'kind': 'closed', 'fd': fd, 'flags': 0,
                                   'reply': syscall(lib, 308, fd, 0)})
        fd = os.open('/proc/self/ns/uts', os.O_RDONLY)
        owner = fcntl.ioctl(fd, 0xb701)  # NS_GET_USERNS
        try:
            report['uts_userns_owner_inode'] = os.fstat(owner).st_ino
            report['caller_userns_inode'] = os.stat('/proc/self/ns/user').st_ino
        finally:
            os.close(owner)
        report['requests'].append({'kind': 'current-uts', 'fd': fd, 'flags': 0,
                                   'reply': syscall(lib, 308, fd, 0)})
        os.close(fd)
        expected = [errno.EINVAL, errno.EBADF, errno.EPERM]
    elif mode == 'unshare':
        report['requests'].append({'kind': 'uts', 'flags': 0x04000000,
                                   'reply': syscall(lib, 272, 0x04000000)})
        expected = [errno.EPERM]
    else:
        raise ValueError('unknown namespace control')
    report['after'] = namespace_map('self')
    put('control.json', report)
    if [x['reply']['errno'] for x in report['requests']] != expected:
        raise RuntimeError('independent namespace control does not match expected errno')
    if report['before'] != report['after']:
        raise RuntimeError('namespace control unexpectedly changed a namespace')
    if mode == 'enter' and report['uts_userns_owner_inode'] != report['caller_userns_inode']:
        raise RuntimeError('unexpected UTS owner namespace')


def check_list(pid):
    namespaces = namespace_map(pid)
    expected = {name: re.fullmatch(r'[^:]+:\[(\d+)\]', target).group(1)
                for name, target in namespaces.items()}
    observed = {}
    for name in ('list.raw', 'binding.raw'):
        lines = (Path(os.environ['HOME']) / name).read_text().splitlines()
        pairs = [line.split(': ', 1) for line in lines]
        if any(len(pair) != 2 for pair in pairs) or len(dict(pairs)) != len(pairs):
            raise RuntimeError('invalid or repeated list-ns row')
        observed[name] = dict(pairs)
    put('list-control.json', {'pid': pid, 'namespaces': namespaces, 'expected': expected,
                              'observed': observed})
    if any(value != expected for value in observed.values()):
        raise RuntimeError('list-ns did not match independently read namespace links')
    print('list=matches-proc binding=matches-proc')


def snapshot(pid, name):
    put(name, {'pid': pid, 'namespaces': namespace_map(pid)})


def check_changes(before_file, after_file, changed_text):
    root = Path(os.environ['HOME'])
    before = json.loads((root / before_file).read_text())
    after = json.loads((root / after_file).read_text())
    if before['pid'] != after['pid']:
        raise RuntimeError('snapshot pid changed')
    left, right = before['namespaces'], after['namespaces']
    if set(left) != set(right):
        raise RuntimeError('namespace entry set changed')
    changed = set(filter(None, changed_text.split(',')))
    actual = {key for key in left if left[key] != right[key]}
    put('changes.json', {'pid': before['pid'], 'expected_changed': sorted(changed),
                         'actual_changed': sorted(actual), 'before': left, 'after': right})
    if actual != changed:
        raise RuntimeError('namespace inode changes differ: ' + repr(sorted(actual)))
    print('namespace-changes=expected')


def hold():
    data = {'pid': os.getpid(), 'ppid': os.getppid(), 'namespaces': namespace_map('self'),
            'uid_map': Path('/proc/self/uid_map').read_text(), 'status': status()}
    put('pid-child.json', data)
    print('READY', flush=True)
    line = sys.stdin.readline()
    if line != 'done\n':
        raise RuntimeError('missing bounded child release')


def check_pid_children():
    root = Path(os.environ['HOME'])
    before = json.loads((root / 'inner-before.json').read_text())['namespaces']
    after = json.loads((root / 'inner-after.json').read_text())['namespaces']
    repeat = json.loads((root / 'inner-repeat.json').read_text())['namespaces']
    child = json.loads((root / 'pid-child.json').read_text())
    checks = {
        'pid_parent_unchanged': before['pid'] == after['pid'],
        'pid_children_changed': before['pid_for_children'] != after['pid_for_children'],
        'time_parent_unchanged': before['time'] == after['time'],
        'time_children_changed': before['time_for_children'] != after['time_for_children'],
        'child_pid_one': child['pid'] == 1,
        'child_pid_namespace': child['namespaces']['pid'] == after['pid_for_children'],
        'child_time_namespace': child['namespaces']['time'] == after['time_for_children'],
        'pid_repeated_unchanged': repeat == after,
    }
    put('pid-check.json', {'checks': checks, 'before': before, 'after': after,
                           'repeat': repeat, 'child': child})
    if not all(checks.values()):
        raise RuntimeError('pid/time namespace assertions failed: ' + repr(checks))
    print('pid-time-children=expected repeated-pid=unchanged')


def check_notify(name, expectation):
    path = Path(os.environ['HOME']) / name
    records = [json.loads(line) for line in path.read_text().splitlines() if line]
    seccomp = [row for row in records if row.get('syscall') == 'seccomp']
    if expectation == 'present':
        if not any(row.get('arg0') == 1 and row.get('arg1') == 0 and
                   row.get('reply') == 'continue' for row in seccomp):
            raise RuntimeError('seccomp notification control saw no matching request')
    elif expectation == 'absent':
        if seccomp:
            print('seccomp-syscalls=' + str(len(seccomp)))
            raise RuntimeError('malformed profiles reached seccomp syscall')
        print('seccomp-syscalls=0')
    else:
        raise ValueError('unknown notification expectation')


def main():
    guard()
    mode, *args = sys.argv[1:]
    if mode == 'seccomp-control':
        seccomp_control(*args)
    elif mode == 'uname-probe':
        uname_probe()
    elif mode == 'ns-control':
        ns_control(*args)
    elif mode == 'check-list':
        check_list(*args)
    elif mode == 'check-changes':
        check_changes(*args)
    elif mode == 'hold':
        hold()
    elif mode == 'check-pid-children':
        check_pid_children()
    elif mode == 'check-notify':
        check_notify(*args)
    elif mode == 'snapshot':
        snapshot(*args)
    else:
        raise ValueError('unknown mode')


if __name__ == '__main__':
    main()
