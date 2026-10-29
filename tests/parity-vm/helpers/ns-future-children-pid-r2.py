#!/usr/bin/env python3
"""Mapped-user-namespace control and observation for future-child namespaces."""
import ctypes
import json
import os
import select
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

H = Path('/tmp/parity-home')

def guard():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    sys.path.insert(0, '/opt/bashos-parity/harness/helpers')
    from ns_guest_identity_r1 import verify
    verify()
    rows = Path('/proc/self/uid_map').read_text().splitlines()
    maps = [list(map(int, row.split())) for row in rows]
    if (os.getuid() != 0 or os.geteuid() != 0 or maps != [[0, 2000, 1]] or
        Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(H) or
        Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'):
        raise RuntimeError('unexpected guest or user namespace')
    if subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True,
                      text=True, check=True, timeout=3).stdout.strip() not in ('qemu', 'kvm'):
        raise RuntimeError('unexpected virtualization')

def snap(pid):
    p = Path('/proc') / str(pid) / 'ns'
    return {n: os.readlink(p / n) for n in ('pid', 'pid_for_children', 'time', 'time_for_children')}

def save(name, value):
    fd, path = tempfile.mkstemp(prefix='.' + name + '.', dir=H)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value, sort_keys=True, indent=2) + '\n')
        os.replace(path, H / name)
    finally:
        if os.path.exists(path): os.unlink(path)

def control(kind):
    report = {'kind': kind, 'before': snap('self')}
    lib = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    rc = lib.unshare({'pid': 0x20000000, 'time': 0x80}[kind])
    report['request'] = {'flags': {'pid': 0x20000000, 'time': 0x80}[kind], 'result': rc,
                         'errno': ctypes.get_errno() if rc else 0}
    if rc:
        save('future-native-' + kind + '.json', report)
        raise RuntimeError('native unshare unavailable')
    if kind == 'pid':
        # Linux can expose no pid_for_children link until the first child has
        # entered the new namespace. Keep that PID 1 alive while sampling.
        read_fd, write_fd = os.pipe()
        release_read, release_write = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd); os.close(release_write)
            try:
                payload = json.dumps({'pid': os.getpid(), 'ns': snap('self')}).encode()
                os.write(write_fd, payload)
                os.close(write_fd)
                ready, _, _ = select.select([release_read], [], [], 10)
                if not ready or os.read(release_read, 1) != b'x': os._exit(2)
            except BaseException:
                os._exit(3)
            finally:
                os.close(release_read)
            os._exit(0)
        os.close(write_fd); os.close(release_read)
        try:
            ready, _, _ = select.select([read_fd], [], [], 5)
            if not ready: raise RuntimeError('native child readiness timeout')
            report['child'] = json.loads(os.read(read_fd, 8192))
            report['after'] = snap('self')
            validate(kind, report['before'], report['after'], report['child'])
        except BaseException as exc:
            report['error'] = type(exc).__name__ + ': ' + str(exc)
            raise
        finally:
            os.close(read_fd)
            try: os.write(release_write, b'x')
            except BrokenPipeError: pass
            os.close(release_write)
            _, status = os.waitpid(child, 0)
            report['child_wait_status'] = status
            save('future-native-' + kind + '.json', report)
        if status != 0: raise RuntimeError('native child failed')
        return
    report['after'] = snap('self')
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            data = json.dumps({'pid': os.getpid(), 'ns': snap('self')}).encode()
            os.write(write_fd, data)
        finally:
            os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, 'rb') as f:
        report['child'] = json.loads(f.read())
    _, status = os.waitpid(child, 0)
    report['child_wait_status'] = status
    save('future-native-' + kind + '.json', report)
    validate(kind, report['before'], report['after'], report['child'])
    if status != 0:
        raise RuntimeError('native child failed')

def validate(kind, before, after, child):
    key = kind + '_for_children'
    if (before[kind] != after[kind] or before[key] == after[key] or
        child['ns'][kind] != after[key] or (kind == 'pid' and child['pid'] != 1)):
        raise ValueError('future-child namespace mismatch')

def control_inodes():
    flags = {'mnt': 0x00020000, 'net': 0x40000000, 'ipc': 0x08000000,
             'uts': 0x04000000, 'cgroup': 0x02000000}
    report = {}
    for name, flag in flags.items():
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                def links():
                    root = Path('/proc/self/ns')
                    return {p.name: os.readlink(p) for p in sorted(root.iterdir())}
                before = links()
                lib = ctypes.CDLL(None, use_errno=True)
                ctypes.set_errno(0)
                rc = lib.unshare(flag)
                err = ctypes.get_errno() if rc else 0
                data = {'before': before, 'result': rc, 'errno': err, 'after': links()}
                os.write(w, json.dumps(data).encode())
            finally:
                os._exit(0)
        os.close(w)
        with os.fdopen(r, 'rb') as f:
            data = json.loads(f.read())
        _, status = os.waitpid(pid, 0)
        data['wait_status'] = status
        report[name] = data
    save('native-inodes.json', report)
    for name, data in report.items():
        changed = {k for k in data['before'] if data['before'][k] != data['after'][k]}
        if data['result'] != 0 or data['wait_status'] != 0 or changed != {name}:
            raise RuntimeError('native inode control incomplete: ' + name)

def main():
    guard()
    mode = sys.argv[1]
    if mode == 'control':
        control(sys.argv[2])
    elif mode == 'control-inodes':
        control_inodes()
    elif mode == 'snapshot':
        save(sys.argv[3], snap(sys.argv[2]))
    elif mode == 'hold':
        save('future-child.json', {'pid': os.getpid(), 'ns': snap('self')})
        if sys.stdin.readline().strip() != 'done':
            raise RuntimeError('child release missing')
    elif mode == 'compare':
        kind = sys.argv[2]
        before = json.loads((H / 'future-before.json').read_text())
        after = json.loads((H / 'future-after.json').read_text())
        child = json.loads((H / 'future-child.json').read_text())
        mid = json.loads((H / 'future-mid.json').read_text())
        report = {'before': before, 'mid': mid, 'after': after, 'child': child}
        try:
            validate(kind, before, after, child)
            if kind == 'pid' and mid != after:
                raise ValueError('repeat altered namespace inode')
            report['matches'] = True
        except ValueError:
            report['matches'] = False
        save('future-comparison.json', report)
        print('future-child=' + ('verified' if report['matches'] else 'mismatch'))
    else:
        raise ValueError('unknown mode')

if __name__ == '__main__':
    main()
