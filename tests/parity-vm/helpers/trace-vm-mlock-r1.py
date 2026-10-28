#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only kernel control and parent-shell procfs snapshots for mlock."""
import ctypes
import errno
import json
import mmap
import os
from pathlib import Path
import resource
import sys
import uuid


def require_guest():
    try:
        marker = Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker)) != marker.lower():
            raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip() != 'QEMU':
            raise ValueError('not QEMU')
        if os.getuid() != 2000 or os.geteuid() != 2000:
            raise ValueError('wrong uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('wrong scratch directory')
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: ' + str(exc))


require_guest()
HOME = Path('/tmp/parity-home')


def snapshot(pid):
    proc = Path('/proc') / str(pid)
    return {'pid': pid, 'status': (proc / 'status').read_text(), 'maps': (proc / 'maps').read_text()}


def locked(s):
    for line in s['status'].splitlines():
        if line.startswith('VmLck:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('VmLck unavailable')


def large_anonymous(s):
    result = []
    for line in s['maps'].splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise RuntimeError('malformed maps line')
        begin, end = (int(n, 16) for n in fields[0].split('-'))
        if len(fields) == 5 and end - begin >= 1024 * 1024:
            result.append(line)
    return sorted(result)


def write(name, data):
    (HOME / name).write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')


def control():
    # Direct libc calls are independent of the Bash builtin. This controls the
    # page size, inherited limit, successful lock/unlock, and rounded ENOMEM.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mlock.argtypes = libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.mlock.restype = libc.munlock.restype = ctypes.c_int
    page = resource.getpagesize()
    limits = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    record = {'page_size': page, 'initial_limits': limits, 'runs': []}
    write('mlock-control.json', record)
    if page != 4096 or (limits[0] != resource.RLIM_INFINITY and limits[0] < 1048576):
        raise RuntimeError('control requires 4096-byte pages and >= 1 MiB soft memlock')
    for size in (1, 1048576):
        before = snapshot(os.getpid())
        mm = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(mm))
        ctypes.set_errno(0)
        rc = libc.mlock(addr, size)
        err = ctypes.get_errno()
        during = snapshot(os.getpid())
        unrc = libc.munlock(addr, size) if rc == 0 else -1
        mm.close()
        after = snapshot(os.getpid())
        run = {'size': size, 'address': addr, 'mlock_return': rc, 'errno': err,
               'munlock_return': unrc, 'before': before, 'during': during, 'after': after}
        record['runs'].append(run)
        write('mlock-control.json', record)
        if not (rc == 0 and unrc == 0 and locked(during) - locked(before) == ((size + page - 1) // page) * page
                and locked(after) == locked(before)):
            raise RuntimeError('kernel lock/unlock control failed')
    soft = 1023 * 1024
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (soft, limits[1]))
    size = soft
    before = snapshot(os.getpid())
    mm = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                   prot=mmap.PROT_READ | mmap.PROT_WRITE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mm))
    ctypes.set_errno(0)
    rc = libc.mlock(addr, size)
    err = ctypes.get_errno()
    mm.close()
    after = snapshot(os.getpid())
    record['rounding'] = {'size': size, 'soft': soft, 'address': addr, 'return': rc, 'errno': err,
                          'before': before, 'after': after}
    write('mlock-control.json', record)
    if not (rc == -1 and err == errno.ENOMEM and locked(after) == locked(before)):
        raise RuntimeError('kernel page-rounding control failed')
    print('kernel mlock controls ok')


def main():
    if sys.argv[1:] == ['--control']:
        control()
        return
    if len(sys.argv) == 4 and sys.argv[1] == '--snapshot':
        pid = int(sys.argv[2])
        name = sys.argv[3]
        if pid != os.getppid() or name not in ('before', 'after'):
            raise ValueError('snapshot must target the direct parent and a fixed label')
        write('mlock-' + name + '.json', snapshot(pid))
        return
    if sys.argv[1:] == ['--compare']:
        before = json.loads((HOME / 'mlock-before.json').read_text())
        after = json.loads((HOME / 'mlock-after.json').read_text())
        if before['pid'] != os.getppid() or after['pid'] != os.getppid():
            raise ValueError('snapshots are not of the parent shell')
        a, b = large_anonymous(before), large_anonymous(after)
        checks = {'locked_bytes_before': locked(before), 'locked_bytes_after': locked(after),
                  'large_anon_before': a, 'large_anon_after': b,
                  'locked_unchanged': locked(before) == locked(after),
                  'large_anon_unchanged': a == b}
        write('mlock-comparison.json', checks)
        if not checks['locked_unchanged'] or not checks['large_anon_unchanged']:
            raise AssertionError('parent shell mappings or locked pages changed')
        print('procfs cleanup checks ok')
        return
    raise SystemExit('invalid invocation')


main()
