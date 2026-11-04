#!/usr/bin/python3
"""Independent controls for the disposable clamp guest, before candidate use."""
import ctypes
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid

RELEASE = '6.12.113-clamp-parity-r1'
H = Path('/tmp/parity-home')
SYS = Path('/proc/sys/kernel')
NAMES = ('sched_util_clamp_min', 'sched_util_clamp_max')
FIELDS = [('size', ctypes.c_uint32), ('policy', ctypes.c_uint32),
          ('flags', ctypes.c_uint64), ('nice', ctypes.c_int32),
          ('priority', ctypes.c_uint32), ('runtime', ctypes.c_uint64),
          ('deadline', ctypes.c_uint64), ('period', ctypes.c_uint64),
          ('util_min', ctypes.c_uint32), ('util_max', ctypes.c_uint32)]


class Attr(ctypes.Structure):
    _fields_ = FIELDS


def guard(uid=2000):
    if (os.getuid(), os.geteuid()) != (uid, uid):
        raise RuntimeError('fixture uid differs')
    if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(H):
        raise RuntimeError('fixture workspace differs')
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
        raise RuntimeError('disposable guest identity absent')
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if os.uname().machine != 'x86_64' or os.uname().release != RELEASE:
        raise RuntimeError('unqualified kernel release/architecture')
    if 'BASHOS_PROC_ROOT' in os.environ:
        raise RuntimeError('live procfs cannot use a redirected root')
    manifest = json.loads(Path('/etc/bashos-clamp-profile.json').read_text())
    data = Path('/boot/config-' + RELEASE).read_bytes()
    if manifest.get('kernel_release') != RELEASE or hashlib.sha256(data).hexdigest() != manifest.get('config_sha256'):
        raise RuntimeError('installed configuration does not match build receipt')
    running = gzip.decompress(Path('/proc/config.gz').read_bytes())
    # IKCONFIG embeds the full build configuration, not a claimed uname string.
    if running != data:
        raise RuntimeError('running kernel configuration differs from installed configuration')
    for symbol in ('UCLAMP_TASK', 'UCLAMP_TASK_GROUP', 'CPU_FREQ_GOV_SCHEDUTIL',
                   'CGROUP_SCHED', 'FAIR_GROUP_SCHED', 'SYSCTL', 'PROC_SYSCTL',
                   'SECCOMP', 'SECCOMP_FILTER', 'PID_NS', 'NET_NS', 'USER_NS'):
        if ('CONFIG_' + symbol + '=y\n').encode() not in data:
            raise RuntimeError('required kernel configuration absent: ' + symbol)
    values = [int((SYS / name).read_text()) for name in NAMES]
    if not 0 <= values[0] <= values[1] <= 1024:
        raise RuntimeError('system clamp controls invalid')
    return {'kernel_release': RELEASE, 'config_sha256': manifest['config_sha256'],
            'system_clamps': values, 'uid': uid}


def get(pid=0):
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    attr = Attr()
    attr.size = ctypes.sizeof(attr)
    if lib.syscall(315, pid, ctypes.byref(attr), ctypes.sizeof(attr), 0):
        raise OSError(ctypes.get_errno(), 'sched_getattr')
    if attr.size < 56:
        raise RuntimeError('sched_attr lacks clamp members')
    return {name: getattr(attr, name) for name, _ in FIELDS}


def set_self(low=None, high=None, reset_fork=False):
    before = get()
    attr = Attr(**before)
    attr.size = ctypes.sizeof(attr)
    attr.flags = 0x11 if reset_fork else 0x18  # KEEP_PARAMS plus RESET_ON_FORK or KEEP_POLICY
    if low is not None:
        attr.flags |= 0x20
        attr.util_min = low
    if high is not None:
        attr.flags |= 0x40
        attr.util_max = high
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    rc = lib.syscall(314, 0, ctypes.byref(attr), 0)
    error = ctypes.get_errno() if rc else 0
    return {'before': before, 'request_hex': bytes(attr).hex(), 'status': rc,
            'errno': error, 'after': get()}


def owned():
    guard()
    signal.alarm(50)
    print(json.dumps({'pid': os.getpid(), 'ppid': os.getppid(), 'attr': get()}), flush=True)
    for raw in sys.stdin:
        if len(raw) > 512:
            raise RuntimeError('request exceeds bound')
        command = json.loads(raw)
        if command['op'] == 'exit':
            return
        if command['op'] == 'read':
            response = get()
        elif command['op'] == 'set':
            response = set_self(command.get('min'), command.get('max'), command.get('fork', False))
        elif command['op'] == 'fork':
            before = get()
            rfd, wfd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(rfd)
                try:
                    os.write(wfd, json.dumps({'pid': os.getpid(), 'ppid': os.getppid(), 'attr': get()}).encode())
                finally:
                    os._exit(0)
            os.close(wfd)
            with os.fdopen(rfd, 'rb') as stream:
                record = json.loads(stream.read(8192))
            waited, status = os.waitpid(child, 0)
            response = {'child': record, 'wait_pid': waited, 'wait_status': status,
                        'parent_before': before, 'parent_after': get(), 'parent_pid': os.getpid()}
        else:
            raise RuntimeError('unknown owned task command')
        print(json.dumps(response), flush=True)


def line(stream):
    end = time.monotonic() + 8
    data = bytearray()
    while len(data) < 16384:
        delay = end - time.monotonic()
        if delay <= 0 or not select.select([stream], [], [], delay)[0]:
            raise RuntimeError('owned task response timeout')
        char = os.read(stream.fileno(), 1)
        if char == b'\n':
            return json.loads(data)
        if not char:
            raise RuntimeError('owned task exited before response')
        data.extend(char)
    raise RuntimeError('owned task response exceeds bound')


def run(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    return {'argv': argv, 'status': result.returncode,
            'stdout': result.stdout.decode('utf8', 'backslashreplace'),
            'stderr': result.stderr.decode('utf8', 'backslashreplace')}


def qualify():
    report = {'schema': 1, 'control_valid': False, 'events': []}
    process = None
    pidfd = None
    try:
        report['profile'] = guard()
        report['native_sha256'] = hashlib.sha256(Path('/usr/bin/uclampset').read_bytes()).hexdigest()
        report['native_version'] = run(['/usr/bin/uclampset', '--version'])
        process = subprocess.Popen(['/usr/bin/python3', '-I', __file__, '--owned'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        ready = line(process.stdout)
        if ready['pid'] != process.pid or ready['ppid'] != os.getpid():
            raise RuntimeError('owned target creation binding differs')
        stat = Path(f'/proc/{process.pid}/stat').read_text()
        birth = stat[stat.rfind(')') + 1:].split()[19]
        pidfd = os.pidfd_open(process.pid)
        report['target'] = {'pid': process.pid, 'ppid': os.getpid(), 'start_ticks': int(birth)}

        def ask(command):
            poll = select.poll()
            poll.register(pidfd, select.POLLIN)
            if poll.poll(0) or process.poll() is not None:
                raise RuntimeError('owned target no longer live')
            process.stdin.write(json.dumps(command).encode() + b'\n')
            result = line(process.stdout)
            report['events'].append({'command': command, 'result': result})
            return result

        for low, high, expected_error in [(100, 900, 0), (900, 100, errno.EINVAL),
                                          (1025, 1025, errno.EINVAL), (-1, None, 0),
                                          (None, -1, 0)]:
            result = ask({'op': 'set', 'min': low, 'max': high})
            if result['errno'] != expected_error or result['status'] != (-1 if expected_error else 0):
                raise RuntimeError('direct setter/error control differs')
            if expected_error:
                if result['before'] != result['after']:
                    raise RuntimeError('rejected direct request mutated target')
            else:
                pair = (result['after']['util_min'], result['after']['util_max'])
                expected = (0 if low == -1 else low if low is not None else result['before']['util_min'],
                            1024 if high == -1 else high if high is not None else result['before']['util_max'])
                if pair != expected:
                    raise RuntimeError('direct setter readback differs')
            if get(process.pid) != result['after']:
                raise RuntimeError('target self-read differs from parent syscall oracle')
        for options, expected in [(['-m', '100', '-M', '900'], (100, 900)),
                                  (['-m', '-1', '-M', '-1'], (0, 1024))]:
            result = run(['/usr/bin/uclampset', *options, '-p', str(process.pid)])
            report['events'].append({'native': result})
            after = ask({'op': 'read'})
            if result['status'] or (after['util_min'], after['util_max']) != expected:
                raise RuntimeError('util-linux setter/reset control failed')
        seeded = ask({'op': 'set', 'min': 100, 'max': 800, 'fork': True})
        if seeded['status'] or not seeded['after']['flags'] & 1:
            raise RuntimeError('direct reset-on-fork flag control failed')
        fork = ask({'op': 'fork'})
        if (fork['child']['attr']['util_min'], fork['child']['attr']['util_max']) != (0, 1024):
            raise RuntimeError('direct fork reset readback failed')
        if fork['wait_pid'] != fork['child']['pid'] or fork['wait_status'] != 0 or fork['child']['ppid'] != process.pid:
            raise RuntimeError('fork lineage/wait control failed')
        if fork['parent_before'] != fork['parent_after'] or ask({'op': 'read'}) != seeded['after']:
            raise RuntimeError('fork changed parent state')
        process.stdin.write(b'{"op":"exit"}\n')
        if process.wait(timeout=5) != 0:
            raise RuntimeError('owned target cleanup failed')
        report['reaped'] = True
        report['control_valid'] = True
    except Exception as error:
        report['incomplete'] = type(error).__name__ + ': ' + str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if pidfd is not None:
            os.close(pidfd)
        (H / 'clamp-profile-control.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['control_valid']:
        raise SystemExit(125)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--owned']:
            owned()
        elif not sys.argv[1:]:
            qualify()
        else:
            raise RuntimeError('invalid control mode')
    except Exception as error:
        print('clamp control incomplete: ' + str(error), file=sys.stderr)
        raise SystemExit(125)
