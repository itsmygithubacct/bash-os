#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only PTY control, bounded child, and raw-event assertions."""
import json
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import pty
import platform
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import tty

HOME = Path('/tmp/parity-home')
PRE = b'\x1b[31mPRE\x00\xff\r\n'
LIVE = b'\x1b[0mPOST\x00\x80\n'
FINAL = b'FINAL\x00\xfe\n'
HERE = '/opt/bashos-parity/harness/helpers/ptybroker-lifecycle-reviewed.py'


GUARD_PATH = '/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py'
GUARD_SHA256 = 'a74d97058d313388948010d1033f50dde7151c2d204d221ed3aeb4da3e9e1762'


def guest():
    # Execute only the exact pinned guard bytes, read once without following a
    # final-component symlink. The guard validates protected identity files,
    # canonical UUID equality, mapped ownership and VM identity before effects.
    fd = os.open(GUARD_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 65536:
            raise ValueError('invalid pinned guest guard')
        source = bytearray()
        while len(source) <= 65536:
            chunk = os.read(fd, 65537 - len(source))
            if not chunk:
                break
            source.extend(chunk)
        if len(source) > 65536 or hashlib.sha256(source).hexdigest() != GUARD_SHA256:
            raise ValueError('guest guard digest mismatch')
    finally:
        os.close(fd)
    namespace = {'__name__': '_ptybroker_pinned_guard'}
    exec(compile(bytes(source), GUARD_PATH, 'exec'), namespace)
    namespace['verify']()
    uid, gid = os.getuid(), os.getgid()
    if (os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or
            os.getgroups() or (uid, gid) not in ((2000, 2000), (0, 0))):
        raise ValueError('unexpected guest credentials')
    maps = {}
    for kind in ('uid', 'gid'):
        rows = [list(map(int, line.split())) for line in
                Path('/proc/self/' + kind + '_map').read_text().splitlines()]
        if any(len(row) != 3 or min(row) < 0 or row[2] <= 0 for row in rows):
            raise ValueError('invalid guest namespace map')
        maps[kind] = rows
        inside = uid if kind == 'uid' else gid
        mapped = [outer + inside - start for start, outer, length in rows
                  if start <= inside < start + length]
        if mapped != [2000] or (uid == 0 and rows != [[0, 2000, 1]]):
            raise ValueError('unexpected guest namespace mapping')
    return {'guard_sha256': GUARD_SHA256, 'uid': uid, 'gid': gid,
            'uid_map': maps['uid'], 'gid_map': maps['gid'], 'groups': []}


def write_all(fd, data):
    while data:
        n = os.write(fd, data)
        if n <= 0:
            raise OSError('short write')
        data = data[n:]


def child():
    tty.setraw(0)
    write_all(1, PRE)
    (HOME / 'child-ready').write_text('raw-ready\n')
    if os.read(0, 1) != b'G':
        return 91
    write_all(1, LIVE)
    if os.read(0, 1) != b'E':
        return 92
    write_all(1, FINAL)
    return 37


def read_exact(fd, expected):
    result = b''
    deadline = time.monotonic() + 5
    while len(result) < len(expected):
        wait = deadline - time.monotonic()
        if wait <= 0 or not select.select([fd], [], [], wait)[0]:
            raise ValueError('native PTY read timeout: ' + result.hex())
        result += os.read(fd, len(expected) - len(result))
    if result != expected:
        raise ValueError('native PTY bytes differ: ' + result.hex())
    return result


def event(line):
    m = re.fullmatch(r'output size=([0-9]+) offset=([0-9]+)', line)
    if m:
        size, offset = map(int, m.groups())
        if not 0 < size <= 16384:
            raise ValueError('invalid output size')
        return ('output', size, offset)
    m = re.fullmatch(r'(attached|gap|exit) rows=([0-9]+) cols=([0-9]+) exit_status=(-?[0-9]+) oldest=([0-9]+) next=([0-9]+)', line)
    if not m:
        raise ValueError('invalid event: ' + line)
    return (m[1], *(int(v) for v in m.groups()[1:]))


def setup(authority=False):
    assert event('output size=3 offset=12') == ('output', 3, 12)
    assert event('gap rows=24 cols=80 exit_status=-1 oldest=0 next=12') == ('gap', 24, 80, -1, 0, 12)
    assert status_line('running=1 next=12') == {'running': '1', 'next': '12'}
    for invalid_status in ('running=1 running=0', 'bad-field'):
        try:
            status_line(invalid_status)
        except ValueError:
            continue
        raise ValueError('status parser accepted invalid control')
    for invalid in ('', 'output size=0 offset=0', 'output size=16385 offset=0',
                    'output size=3 offset=0 extra', 'exit next=0', 'gap rows=x cols=80 exit_status=-1 oldest=0 next=1'):
        try:
            event(invalid)
        except ValueError:
            continue
        raise ValueError('event parser accepted invalid control')
    controls = {'event_positive': 2, 'event_negative': 6, 'status_positive': 1, 'status_negative': 2}
    if authority:
        controls['authority'] = authority_controls()
        controls['authority_zero_seqpacket'] = authority_zero_control()
    (HOME / 'parser-controls.json').write_text(json.dumps(controls) + '\n')
    master, slave = pty.openpty()
    process = subprocess.Popen([sys.executable, '-I', HERE, 'child'], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    data = b''
    try:
        data += read_exact(master, PRE)
        write_all(master, b'G')
        data += read_exact(master, LIVE)
        write_all(master, b'E')
        data += read_exact(master, FINAL)
        status = process.wait(timeout=5)
        (HOME / 'native-control.bin').write_bytes(data)
        (HOME / 'native-control.json').write_text(json.dumps({'exit': status, 'expected_exit': 37, 'bytes_hex': data.hex()}) + '\n')
        if status != 37 or data != PRE + LIVE + FINAL:
            raise ValueError('native PTY control failed')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        (HOME / 'child-ready').unlink(missing_ok=True)


def status_line(line):
    fields = line.strip().split()
    result = {}
    for item in fields:
        if '=' not in item:
            raise ValueError('malformed status')
        key, value = item.split('=', 1)
        if key in result:
            raise ValueError('duplicate status field')
        result[key] = value
    return result


def check():
    errors = []
    data = {}
    try:
        lines = (HOME / 'candidate-events').read_text().splitlines()
        events = []
        for line in lines:
            rc, text = line.split('|', 1)
            if rc != '0':
                raise ValueError('receive failed: ' + rc)
            events.append(event(text))
        data['events'] = events
        if len(events) < 4 or events[0][0] != 'attached' or events[1][0] != 'gap':
            raise ValueError('missing ordered attached and gap events')
        for e in events[:2]:
            if e[4:] != (0, len(PRE)):
                raise ValueError('late attach offsets differ from fixed prehistory')
        if events[-1][0] != 'exit' or events[-1][3] != 37 or events[-1][5] != len(PRE + LIVE + FINAL):
            raise ValueError('missing final exit or wrong exit status/offset')
        outputs = events[2:-1]
        if not outputs or any(e[0] != 'output' for e in outputs):
            raise ValueError('missing live output or unexpected event ordering')
        offset = len(PRE)
        for e in outputs:
            if e[2] != offset:
                raise ValueError('noncontiguous live output')
            offset += e[1]
        if offset != len(PRE + LIVE + FINAL):
            raise ValueError('missing or extra live bytes')
        if (HOME / 'candidate-live.bin').read_bytes() != LIVE + FINAL:
            raise ValueError('live bytes differ or replayed history')
        if (HOME / 'candidate-capture.bin').read_bytes() != PRE + LIVE + FINAL:
            raise ValueError('capture does not equal exact raw history')
        before = status_line((HOME / 'candidate-before').read_text())
        after = status_line((HOME / 'candidate-after').read_text())
        if before.get('running') != '1' or before.get('oldest') != '0' or before.get('next') != str(len(PRE)):
            raise ValueError('pre-attach history precondition missing')
        if after.get('running') != '0' or after.get('exit_status') != '37' or after.get('next') != str(len(PRE + LIVE + FINAL)):
            raise ValueError('status did not retain child exit')
        if (HOME / 'candidate-steps').read_text() != 'create=0\nready=1\nattach=0\nsend_g=0\nsend_e=0\nreceive=0\nstatus=0\ncapture=0\ndetach=0\nterminate=0\n':
            raise ValueError('candidate operation or fixture handshake failed')
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    (HOME / 'assertions.json').write_text(json.dumps({'events': data.get('events', []), 'failures': errors}, indent=2) + '\n')
    if errors:
        print('; '.join(errors))
        return 1
    print('raw-exit-ok')
    return 0


def tree_child():
    child = os.getpid()
    grand = os.fork()
    if grand == 0:
        os.setsid()
        def held(sig, frame):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            (HOME / 'tree-blocked').write_text('SIGTERM-held\n')
        signal.signal(signal.SIGTERM, held)
        (HOME / 'tree-grandchild').write_text(str(os.getpid()) + '\n')
        while True:
            signal.pause()
    (HOME / 'tree-child').write_text(str(child) + '\n')
    while True:
        signal.pause()


def sentinel():
    (HOME / 'sentinel-pid').write_text(str(os.getpid()) + '\n')
    while True:
        signal.pause()


def proc_info(pid):
    data = Path('/proc/%d/stat' % pid).read_text()
    tail = data[data.rfind(')') + 2:].split()
    return {'state': tail[0], 'ppid': int(tail[1]), 'start': int(tail[19])}


def sentinel_observation(pid, fd, start):
    ready = bool(select.select([fd], [], [], 0)[0])
    try:
        info = proc_info(pid)
    except FileNotFoundError:
        info = None
    live = (not ready and info is not None and info['start'] == start and
            info['state'] not in ('Z', 'X', 'x'))
    return {'pidfd_readable': ready, 'proc': info, 'live': live}


def syscall_observation(pid):
    info = proc_info(pid)
    raw = Path('/proc/%d/syscall' % pid).read_text().strip()
    fields = raw.split()
    number = int(fields[0]) if fields and fields[0].lstrip('-').isdigit() else None
    wait_calls = {'x86_64': {7, 45, 271}, 'aarch64': {73, 207}}
    machine = platform.machine()
    if machine not in wait_calls:
        raise ValueError('unsupported syscall observation architecture')
    return {'state': info['state'], 'start': info['start'], 'raw': raw,
            'number': number, 'blocked_in_wait': info['state'] == 'S' and number in wait_calls[machine]}


def watch_tree():
    # This process is the parent of the candidate shell executing the public
    # builtin; a syscall witness prevents delayed shell output from being
    # mistaken for evidence that the builtin had not yet returned.
    record = {'stage': 'start', 'classification': 'observer_error', 'events': [],
              'observer_pid': os.getpid(), 'architecture': platform.machine()}
    fds = {}
    worker = None
    driver_err = None
    output = bytearray()
    def note(name, **detail):
        if len(record['events']) >= 24:
            raise ValueError('observer event bound exceeded')
        record['events'].append({'event': name, 'monotonic_ns': time.monotonic_ns(), **detail})
    try:
        pids = {name: int((HOME / filename).read_text()) for name, filename in
                [('child', 'tree-child'), ('grandchild', 'tree-grandchild'), ('sentinel', 'sentinel-pid')]}
        broker = int(sys.argv[2])
        candidate = sys.argv[3]
        if candidate != '/opt/bashos-parity/candidate':
            raise ValueError('unexpected candidate executable path')
        digest = hashlib.sha256()
        with open(candidate, 'rb') as binary:
            for chunk in iter(lambda: binary.read(1024 * 1024), b''):
                digest.update(chunk)
        record.update(candidate_path=candidate, candidate_sha256=digest.hexdigest())
        if len(set(pids.values()) | {broker, os.getpid()}) != 5 or any(p <= 1 for p in pids.values()):
            raise ValueError('non-distinct process identities')
        fds = {name: os.pidfd_open(pid, 0) for name, pid in pids.items()}
        before = {name: proc_info(pid) for name, pid in pids.items()}
        if (before['child']['ppid'] != broker or before['grandchild']['ppid'] != pids['child'] or
            before['sentinel']['ppid'] in (broker, pids['child'], pids['grandchild'])):
            raise ValueError('owned tree ancestry differs before termination')
        for fd in fds.values():
            if select.select([fd], [], [], 0)[0]: raise ValueError('process already exited before termination')
        sentinel_before = sentinel_observation(pids['sentinel'], fds['sentinel'], before['sentinel']['start'])
        if not sentinel_before['live']: raise ValueError('sentinel not live before request')
        record.update(pids=pids, broker=broker, before=before, sentinel_before=sentinel_before, stage='ready')
        note('ancestry-and-pidfds-ready')
        write_all(7, b'READY\n')
        if os.read(6, 1) != b'X': raise ValueError('driver closed before request')
        script = ("[[ $(type -t ptybroker) == builtin ]] || exit 125\n"
                  "printf 'ENTER\\n'\n"
                  "ptybroker terminate \"$1\" one >\"$2\" 2>\"$3\"\n"
                  "r=$?\n"
                  "printf 'RETURN=%s\\n' \"$r\"\n"
                  "exit \"$r\"\n")
        driver_err = (HOME / 'builtin-driver.err').open('wb')
        worker = subprocess.Popen([candidate, '--noprofile', '--norc', '-c', script, 'builtin-witness',
                                   str(HOME / 'broker-root'), str(HOME / 'builtin-terminate.out'),
                                   str(HOME / 'builtin-terminate.err')],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=driver_err,
                                  cwd='/tmp/parity-case', env=os.environ.copy(), close_fds=True)
        os.set_blocking(worker.stdout.fileno(), False)
        record['worker_pid'] = worker.pid
        record['worker_before'] = proc_info(worker.pid)
        if record['worker_before']['ppid'] != os.getpid():
            raise ValueError('candidate witness is not the observer child')
        record['stage'] = 'builtin-launched'
        note('builtin-launched')
        deadline = time.monotonic() + 7
        entered = False
        blocked = False
        reaped_before_return = False
        completed = False
        while time.monotonic() < deadline:
            # Once reaping is witnessed, do not poll an already-readable pidfd:
            # it would spin and produce an unbounded record.
            watched = [worker.stdout] if reaped_before_return else [worker.stdout, fds['grandchild']]
            readable, _, _ = select.select(watched, [], [], min(.02, max(0, deadline-time.monotonic())))
            if worker.stdout in readable:
                chunk = os.read(worker.stdout.fileno(), 4097 - len(output))
                output.extend(chunk)
                if len(output) > 4096:
                    record['classification'] = 'capture_incomplete'
                    note('builtin-output-limit')
                    break
                if not entered and output.startswith(b'ENTER\n'):
                    entered = True
                    note('builtin-entered')
                if b'RETURN=' in output or not chunk:
                    note('builtin-completion-readable')
                    grand_exited = bool(select.select([fds['grandchild']], [], [], 0)[0])
                    if not grand_exited and b'RETURN=' in output:
                        record['classification'] = 'candidate_early_return'
                    elif reaped_before_return:
                        record['classification'] = 'observed_order'
                    else:
                        record['classification'] = 'ambiguous_order'
                    completed = True
                    break
            if not entered:
                continue
            if not blocked and (HOME / 'tree-blocked').exists():
                if not select.select([fds['grandchild']], [], [], 0)[0]:
                    blocked = True
                    note('term-held-without-return')
            if not reaped_before_return and fds['grandchild'] in readable:
                if not blocked:
                    record['classification'] = 'observer_error'
                    note('grandchild-exited-before-blocked-handshake')
                    break
                gone = True
                for name in ('child', 'grandchild'):
                    try: current = proc_info(pids[name])
                    except FileNotFoundError: continue
                    if current['start'] == before[name]['start']: gone = False
                if gone:
                    # Only accept if the candidate shell is still inside a
                    # blocking socket wait after both descendants were reaped.
                    # Pipe unreadability alone cannot prove builtin return time.
                    try: witness = syscall_observation(worker.pid)
                    except FileNotFoundError: witness = {'blocked_in_wait': False, 'raw': 'process-gone'}
                    if (witness['blocked_in_wait'] and witness['start'] == record['worker_before']['start']
                            and not select.select([worker.stdout], [], [], 0)[0]):
                        reaped_before_return = True
                        record['worker_syscall_witness'] = witness
                        note('both-reaped-builtin-still-blocked')
                    else:
                        # A readable pipe or an unwitnessed/running syscall is
                        # inherently ambiguous: never infer return ordering.
                        if select.select([worker.stdout], [], [], 0)[0]:
                            continue
                if not reaped_before_return:
                    time.sleep(.01)
        else:
            record['classification'] = 'candidate_timeout' if entered else 'observer_error'
            note('builtin-timeout')
        record['blocked_handshake'] = blocked
        record['reaped_before_builtin_return'] = reaped_before_return
        timed_out = not completed and record['classification'] == 'candidate_timeout'
        record['worker_timed_out'] = timed_out
        if timed_out and worker.poll() is None:
            worker.kill()
        if completed or timed_out:
            try:
                status = worker.wait(timeout=2)
                while True:
                    chunk = os.read(worker.stdout.fileno(), 4097 - len(output))
                    if not chunk: break
                    output.extend(chunk)
                    if len(output) > 4096: raise ValueError('builtin output exceeds capture bound')
                record['worker_stdout_complete'] = True
            except (subprocess.TimeoutExpired, BlockingIOError, ValueError):
                record['classification'] = 'capture_incomplete'
                record['worker_stdout_complete'] = False
                status = None
            record['worker_status'] = status
            record['worker_stdout_hex'] = output.hex()
            # Complete malformed bytes are a candidate failure; incomplete
            # capture is never classified as a product mismatch.
            if not timed_out and status is not None and (output != b'ENTER\nRETURN=0\n' or status != 0):
                record['classification'] = 'candidate_bad_result'
        else:
            record['worker_stdout_hex'] = output.hex()
            record['worker_stdout_complete'] = False
        after = sentinel_observation(pids['sentinel'], fds['sentinel'], before['sentinel']['start'])
        record['sentinel_after'] = after
        if not after['live'] and record['classification'] not in ('observer_error', 'capture_incomplete'):
            record['classification'] = 'candidate_sentinel_lost'
        record['stage'] = 'complete'
    except Exception as exc:
        record['error'] = type(exc).__name__ + ': ' + str(exc)
        try: note('observer-error', error=record['error'])
        except ValueError: pass
    finally:
        if worker is not None:
            if worker.poll() is None:
                worker.kill()
                try: worker.wait(timeout=3)
                except subprocess.TimeoutExpired: record['classification'] = 'observer_error'
            if worker.stdout is not None: worker.stdout.close()
        if driver_err is not None: driver_err.close()
        for fd in fds.values(): os.close(fd)
        # Write, read back, and atomically publish a bounded complete record
        # before notifying the shell; a persistence error cannot signal DONE.
        try:
            payload = (json.dumps(record, indent=2) + '\n').encode()
            if len(payload) > 131072: raise ValueError('observer record exceeds bound')
            temp = HOME / 'observer-record.tmp'
            temp.write_bytes(payload)
            if temp.read_bytes() != payload: raise OSError('observer record readback differs')
            os.replace(temp, HOME / 'observer-record.json')
            if (HOME / 'observer-record.json').read_bytes() != payload: raise OSError('published record differs')
            write_all(7, b'DONE\n' if record['stage'] == 'complete' else b'ERROR\n')
        except Exception as exc:
            try: write_all(7, b'ERROR\n')
            except OSError: pass
            print('observer persistence error: ' + str(exc), file=sys.stderr)


def capability():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'subreaper unavailable')
    read_end, write_end = os.pipe()
    release_r, release_w = os.pipe()
    parent = os.fork()
    if parent == 0:
        os.close(read_end); os.close(release_w)
        grand = os.fork()
        if grand == 0:
            write_all(write_end, (str(os.getpid()) + '\n').encode())
            os.read(release_r, 1)
            os._exit(0)
        os._exit(0)
    os.close(write_end); os.close(release_r)
    grand = None
    try:
        line = b''
        while not line.endswith(b'\n'):
            if not select.select([read_end], [], [], 5)[0]:
                raise ValueError('subreaper control handshake timed out')
            part = os.read(read_end, 32)
            if not part:
                raise ValueError('subreaper control pipe closed')
            line += part
        grand = int(line)
        os.waitpid(parent, 0)
        if proc_info(grand)['ppid'] != os.getpid():
            raise ValueError('subreaper adoption unavailable')
        fd = os.pidfd_open(grand, 0)
        try:
            signal.pidfd_send_signal(fd, 0)
            write_all(release_w, b'X')
            if not select.select([fd], [], [], 5)[0]:
                raise ValueError('pidfd did not observe child exit')
            waited, status = os.waitpid(grand, 0)
            grand = None
            if waited <= 1 or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise ValueError('adopted child did not exit cleanly')
        finally:
            os.close(fd)
    finally:
        os.close(read_end); os.close(release_w)
        if grand is not None:
            try:
                os.kill(grand, signal.SIGKILL)
                os.waitpid(grand, 0)
            except (ProcessLookupError, ChildProcessError):
                pass


def check_cleanup():
    errors = []
    report = {}
    try:
        lines = (HOME / 'candidate-steps').read_text().splitlines()
        expected = ['create=0', 'ready=1', 'watcher=1', 'watch_done=1', 'watch_rc=0', 'sentinel_kill=0', 'sentinel_wait=143']
        if lines != expected:
            raise ValueError('candidate or watcher step failed: ' + repr(lines))
        report = json.loads((HOME / 'observer-record.json').read_text())
        if (report.get('classification') != 'observed_order' or not report.get('blocked_handshake') or
                not report.get('reaped_before_builtin_return')):
            raise ValueError('cleanup/reply ordering not established: ' + str(report.get('classification')))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    (HOME / 'assertions.json').write_text(json.dumps({'observed': report, 'failures': errors}, indent=2) + '\n')
    if errors:
        print('; '.join(errors))
        return 1
    print('cleanup-ok')
    return 0


ROLE_PHASES = {
    'ready': ('role-before', {'running': '1', 'oldest': '0', 'next': str(len(PRE))}),
    'control': ('control-active', {'running': '1', 'controller': '1'}),
    'observers': ('role-before', {'running': '1', 'controller': '1', 'observers': '8',
                                  'oldest': '0', 'next': str(len(PRE))}),
    'released': ('role-released', {'running': '1', 'controller': '0', 'observers': '8'}),
}


def strict_role_status(raw):
    # A complete response is exactly one printable ASCII line, with distinct
    # key=value tokens; candidate output cannot manufacture a second poll.
    if not re.fullmatch(rb'[ -~]+\n', raw):
        raise ValueError('status is not one printable newline-terminated line')
    text = raw[:-1].decode('ascii')
    if any(not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*=[^=\s]+', item)
           for item in text.split()):
        raise ValueError('invalid status token')
    fields = status_line(text)
    if not fields:
        raise ValueError('empty status')
    return fields


def role_poll(seq, phase, rc):
    if phase not in ROLE_PHASES or not 1 <= seq <= 10000 or not 0 <= rc <= 255:
        raise ValueError('invalid poll metadata')
    def capture(name):
        path = HOME / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1:
                raise ValueError('unsafe poll capture')
            data = b''
            while len(data) < min(before.st_size, 4096):
                chunk = os.read(fd, min(before.st_size, 4096) - len(data))
                if not chunk: break
                data += chunk
            after = os.fstat(fd)
            linked = os.stat(path, follow_symlinks=False)
            key = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid, x.st_nlink,
                             x.st_size, x.st_mtime_ns, x.st_ctime_ns)
            if key(before) != key(after) or key(after) != key(linked) or len(data) != min(before.st_size, 4096):
                raise ValueError('unstable poll capture')
            return {'hex': data.hex(), 'size': before.st_size, 'captured': len(data),
                    'truncated': before.st_size > len(data)}
        finally:
            os.close(fd)
    out, err = capture(ROLE_PHASES[phase][0]), capture('role-poll.err')
    complete = not out['truncated'] and not err['truncated']
    record = {'schema': 'ptybroker-role-journal-v1', 'seq': seq, 'kind': 'poll',
              'phase': phase, 'rc': rc, 'stdout': out, 'stderr': err, 'complete': complete}
    raw = (json.dumps(record, separators=(',', ':')) + '\n').encode()
    fd = os.open(HOME / 'candidate-polls', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                len(raw) > 20000 or info.st_size + len(raw) > 240 * 1024):
            raise ValueError('role journal capture bound')
        write_all(fd, raw)
    finally:
        os.close(fd)
    if not complete:
        return 125
    try:
        fields = strict_role_status(bytes.fromhex(out['hex']))
    except ValueError:
        return 10
    return 0 if rc == 0 and all(fields.get(k) == v for k, v in ROLE_PHASES[phase][1].items()) else 10



def role_event(seq, phase, observer, ordinal, rc, text):
    if (not 1 <= seq <= 1000 or phase not in ('initial', 'live') or
            not 0 <= observer < 8 or not 0 <= ordinal < 32 or not 0 <= rc <= 255):
        raise ValueError('invalid receive metadata')
    raw_text = os.fsencode(text)
    row = {'schema': 'ptybroker-role-event-v1', 'seq': seq, 'phase': phase,
           'observer': observer, 'ordinal': ordinal, 'rc': rc, 'size': len(raw_text),
           'event_hex': raw_text[:4096].hex(), 'complete': len(raw_text) <= 4096}
    raw = (json.dumps(row, separators=(',', ':')) + '\n').encode()
    fd = os.open(HOME / 'role-events', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or
                len(raw) > 10000 or info.st_size + len(raw) > 240 * 1024):
            raise ValueError('role event capture bound')
        write_all(fd, raw)
    finally:
        os.close(fd)
    return 0 if row['complete'] else 125

def read_role_journal():
    raw = (HOME / 'candidate-polls').read_bytes()
    if len(raw) > 240 * 1024 or not raw.endswith(b'\n'):
        raise ValueError('role journal missing complete ending')
    rows, steps, prior = [], {}, {}
    for seq, line in enumerate(raw.splitlines(), 1):
        row = json.loads(line)
        if (row.get('schema') != 'ptybroker-role-journal-v1' or row.get('seq') != seq or
                row.get('complete') is not True or row.get('kind') not in ('step', 'poll')):
            raise ValueError('invalid role journal framing')
        if row['kind'] == 'step':
            name, value = row.get('name'), row.get('value')
            if (not isinstance(name, str) or not re.fullmatch(r'[a-z_0-9]+', name) or
                    not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,3}', value) or
                    int(value) > 255 or name in steps):
                raise ValueError('invalid or duplicate role step')
            steps[name] = value
            prior[name] = rows[-1] if rows else None
        else:
            if row.get('phase') not in ROLE_PHASES or type(row.get('rc')) is not int or not 0 <= row['rc'] <= 255:
                raise ValueError('invalid role poll')
            for key in ('stdout', 'stderr'):
                capture = row[key]
                data = bytes.fromhex(capture['hex'])
                if (capture['truncated'] is not False or capture['size'] != len(data) or
                        capture['captured'] != len(data) or len(data) > 4096):
                    raise ValueError('incomplete role poll bytes')
        rows.append(row)
    lines = (HOME / 'candidate-steps').read_text().splitlines()
    if lines != [row['name'] + '=' + row['value'] for row in rows if row['kind'] == 'step']:
        raise ValueError('step mirror differs from journal')
    return rows, steps, prior


def role_prior_status(prior, step, phase):
    row = prior.get(step)
    if not row or row.get('kind') != 'poll' or row.get('phase') != phase:
        raise ValueError('missing immediately preceding ' + phase + ' poll')
    if row['rc'] != 0:
        raise ValueError('status poll failed')
    raw = bytes.fromhex(row['stdout']['hex'])
    return raw, strict_role_status(raw)


def check_roles():
    """Record independently reached role clauses; auxiliary authority is separate."""
    report = {'schema': 'ptybroker-roles-requirements-v6', 'requirements': {},
              'observer_controller_permission': 'uncovered', 'precondition': {}, 'cleanup': {}}
    try:
        rows, steps, prior = read_role_journal()
        ready_marker = (HOME / 'child-ready').read_bytes()
        ready_raw, ready_fields = role_prior_status(prior, 'ready', 'ready')
        precondition = (steps.get('create') == '0' and steps.get('ready') == '1' and
                        ready_marker == b'raw-ready\n' and
                        all(ready_fields.get(k) == v for k, v in ROLE_PHASES['ready'][1].items()))
        report['precondition'] = {'ok': precondition, 'create': steps.get('create'),
                                  'ready': steps.get('ready'), 'child_ready_hex': ready_marker.hex(),
                                  'ready_poll_hex': ready_raw.hex()}
        report['steps'] = steps
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        precondition = False
        steps, prior = {}, {}
        report['precondition'] = {'ok': False, 'error': str(exc)}

    def assess(name, step_expectations, files=(), status=None, events=False, prerequisites=()):
        errors, missing, evidence = [], [], {}
        if not precondition:
            missing.append('fixture precondition not established')
        else:
            for key in prerequisites:
                if steps.get(key) != '0': missing.append('prerequisite ' + key + ' not established')
            if not missing:
                for key, expected in step_expectations.items():
                    actual = steps.get(key)
                    evidence[key] = actual
                    if actual is None: missing.append('step ' + key + ' not reached')
                    elif actual != expected: errors.append('step ' + key + ' differs')
                for filename, text, status_key in files:
                    # The diagnostic only bears on the correctly reached rejection.
                    if steps.get(status_key) != step_expectations.get(status_key): continue
                    try:
                        data = (HOME / filename).read_bytes()
                        evidence[filename + '_hex'] = data.hex()
                        if text not in data: errors.append(filename + ' diagnostic differs')
                    except OSError: missing.append(filename + ' absent or unreadable')
                if status:
                    filename, required, reached_step = status
                    if reached_step not in steps:
                        missing.append(filename + ' status phase not reached')
                        status = None
                if status:
                    try:
                        phases = {'control-active': 'control', 'role-before': 'observers', 'role-released': 'released'}
                        raw, fields = role_prior_status(prior, reached_step, phases[filename])
                        evidence[filename + '_hex'] = raw.hex()
                        evidence[filename + '_fields'] = fields
                        if any(fields.get(k) != v for k, v in required.items()):
                            errors.append(filename + ' fields differ')
                    except (ValueError, KeyError, TypeError) as exc:
                        missing.append(filename + ' poll incomplete or malformed: ' + str(exc))
                if events and steps.get('observers_complete') != '1':
                    missing.append('observer capture phase not complete')
                if events and steps.get('observers_complete') == '1':
                    try:
                        groups = [[] for _ in range(8)]
                        raw_events = (HOME / 'role-events').read_bytes()
                        if len(raw_events) > 240 * 1024 or not raw_events.endswith(b'\n'):
                            raise ValueError('observer event capture incomplete')
                        event_rows = [json.loads(line) for line in raw_events.splitlines()]
                        initial = [(i, j) for i in range(8) for j in range(2)]
                        if len(event_rows) < len(initial):
                            raise ValueError('observer initial events incomplete')
                        for seq, row in enumerate(event_rows, 1):
                            if (row.get('schema') != 'ptybroker-role-event-v1' or row.get('seq') != seq or
                                    row.get('complete') is not True or row.get('rc') != 0):
                                raise ValueError('invalid observer receive record')
                            raw_event = bytes.fromhex(row['event_hex'])
                            if row.get('size') != len(raw_event) or len(raw_event) > 4096:
                                raise ValueError('observer event bytes incomplete')
                            i, j, phase = row['observer'], row['ordinal'], row['phase']
                            if seq <= len(initial):
                                if phase != 'initial' or (i, j) != initial[seq - 1]:
                                    raise ValueError('observer initial order differs')
                            else:
                                if phase != 'live' or type(i) is not int or not 0 <= i < 8:
                                    raise ValueError('observer live order differs')
                                prior_live = [r for r in event_rows[len(initial):seq - 1] if r['phase'] == 'live']
                                if j != sum(r['observer'] == i for r in prior_live) or (prior_live and i < prior_live[-1]['observer']):
                                    raise ValueError('observer live sequence differs')
                            groups[i].append(event(raw_event.decode('ascii')))
                        for index, group in enumerate(groups):
                            if len(group) < 3 or group[0][0] != 'attached' or group[1][0] != 'gap':
                                raise ValueError('observer %d lacks initial events or live output' % index)
                            if any(e[4:] != (0, len(PRE)) for e in group[:2]):
                                raise ValueError('observer %d has wrong initial offsets' % index)
                            offset = len(PRE)
                            for e in group[2:]:
                                if e[0] != 'output' or e[2] != offset:
                                    raise ValueError('observer %d output is not contiguous' % index)
                                offset += e[1]
                            if offset != len(PRE + LIVE):
                                raise ValueError('observer %d has incomplete live output' % index)
                        raw = (HOME / 'role-bytes').read_bytes()
                        evidence['events'] = groups
                        evidence['role_bytes_hex'] = raw.hex()
                        if raw != LIVE * 8: errors.append('observer bytes differ')
                    except OSError: missing.append('observer events or bytes absent')
                    except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc: errors.append(str(exc))
        state = 'candidate_mismatch' if errors else 'incomplete' if missing else 'satisfied'
        report['requirements'][name] = {'state': state, 'errors': errors, 'missing': missing, 'evidence': evidence}

    assess('r1', {'control':'0', 'control_status':'0', 'control_busy':'1'},
           [('control-busy.err', b'Device or resource busy', 'control_busy')],
           ('control-active', {'running':'1', 'controller':'1'}, 'control_status'))
    observer_steps = {'observer_' + str(i):'0' for i in range(8)}
    observer_steps.update({'observer_busy':'1', 'role_status':'0', 'send_g':'0'})
    assess('r2_attachment_limit_and_output', observer_steps,
           [('observer-busy.err', b'Device or resource busy', 'observer_busy')],
           ('role-before', {'running':'1', 'controller':'1', 'observers':'8', 'oldest':'0', 'next':str(len(PRE))}, 'role_status'),
           events=True, prerequisites=('control',))
    assess('r3', {'detach_control':'0', 'released':'1', 'new_control':'0', 'detach_new':'0'},
           status=('role-released', {'running':'1', 'controller':'0', 'observers':'8'}, 'released'), prerequisites=('control',))
    assess('r4_cross_process', {'cross_process':'1'},
           [('cross-process.err', b'Invalid argument', 'cross_process')], prerequisites=('control', 'control_fd'))
    assess('r4_stale', {'stale':'1'}, [('stale.err', b'Invalid argument', 'stale')],
           prerequisites=('control', 'control_fd', 'detach_control'))
    cross, stale = (report['requirements'][key] for key in ('r4_cross_process', 'r4_stale'))
    states = [cross['state'], stale['state']]
    report['requirements']['r4'] = {
        'state': 'candidate_mismatch' if 'candidate_mismatch' in states else
                 'incomplete' if 'incomplete' in states else 'satisfied',
        'cross_process': cross, 'stale': stale}

    report['cleanup'] = {'terminate': steps.get('terminate')}
    (HOME / 'assertions.json').write_text(json.dumps(report, indent=2) + '\n')
    states = [row['state'] for row in report['requirements'].values()]
    if 'candidate_mismatch' in states:
        print('role requirement mismatch')
        return 1
    if 'incomplete' in states or steps.get('terminate') != '0':
        print('role observation incomplete')
        return 2
    print('roles-ok')
    return 0


def check_authority():
    """Auxiliary protocol evidence never decides the role requirement records."""
    rows, errors = [], []
    try:
        for line in (HOME / 'authority.jsonl').read_text().splitlines():
            row = json.loads(line)
            rows.append({'role': row.get('role'), 'classification': authority_classify(row),
                         'record': row})
        if len(rows) != 2 or [row['role'] for row in rows] != ['control', 'observe']:
            errors.append('authority records absent, duplicate, or out of order')
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    report = {'schema': 'ptybroker-auxiliary-authority-v6', 'observations': rows,
              'errors': errors, 'observer_controller_permission': 'uncovered'}
    (HOME / 'assertions.json').write_text(json.dumps(report, indent=2) + '\n')
    verdicts = [row['classification'] for row in rows]
    if any(value.startswith('candidate_') for value in verdicts):
        print('authority-candidate-mismatch')
        return 1
    if errors or any(value != 'rejected' for value in verdicts):
        print('authority-inconclusive')
        return 2
    print('authority-rejected')
    return 0


# Fixed protocol requests and conservative timeout threshold. A timeout is a
# product observation only after a full send to the verified broker peer.
AUTH_POSITIVE = struct.pack('=IIIIQ', 0x42505431, 1, 0, 0, 0)
AUTH_NEGATIVE = struct.pack('=IIIIQ', 0x42505431, 3, 1, 0, 0) + b'Z'
AUTH_MIN_WAIT_NS = 2_990_000_000


def authority_classify(rec, positive_only=False):
    """Classify completed phase evidence in order; later phases cannot erase it."""
    try:
        if (rec.get('record_complete') is not True or rec.get('schema') != 'ptybroker-authority-v5' or
                rec.get('role') not in ('control', 'observe') or type(rec.get('broker_pid')) is not int or rec['broker_pid'] <= 1):
            return 'observer_error'
        phases = rec['phases']
        for phase_name, request in (('positive', AUTH_POSITIVE), ('negative', AUTH_NEGATIVE)):
            phase = phases[phase_name]
            peer = phase['peer']
            sent = phase['request']
            if (phase.get('reached') is not True or phase.get('terminal') is not True or peer.get('verified') is not True or
                peer.get('pid') != rec.get('broker_pid') or peer.get('uid') != os.geteuid() or
                peer.get('socket_type') != socket.SOCK_SEQPACKET or
                sent.get('state') != 'sent' or sent.get('hex') != request.hex() or
                sent.get('sent_bytes') != len(request) or type(sent.get('start_ns')) is not int or
                type(sent.get('end_ns')) is not int or sent['end_ns'] < sent['start_ns']):
                return 'observer_error'
            reply = phase['reply']
            if (type(reply.get('start_ns')) is not int or type(reply.get('end_ns')) is not int or
                    reply['start_ns'] < sent['end_ns'] or reply['end_ns'] < reply['start_ns']):
                return 'observer_error'
            kind = reply.get('state')
            if kind == 'timeout':
                if (type(reply.get('start_ns')) is not int or type(reply.get('end_ns')) is not int or
                    reply['end_ns'] - reply['start_ns'] < AUTH_MIN_WAIT_NS or
                    reply.get('timeout_ns') != 3_000_000_000 or reply.get('error_type') != 'TimeoutError'):
                    return 'observer_error'
                return 'candidate_timeout_' + phase_name
            if kind in ('closed', 'ambiguous_zero_or_close'):
                if (reply.get('received_bytes') != 0 or reply.get('hex') != '' or reply.get('truncated') is not False or
                        type(reply.get('flags')) is not int or reply['flags'] & socket.MSG_TRUNC or
                        type(reply.get('poll_mask')) is not int):
                    return 'observer_error'
                # EOF and a queued empty datagram followed by close can both
                # appear as zero bytes with HUP. Neither proves rejection.
                return 'inconclusive_zero_or_close'
            if kind == 'peer_reset':
                if (reply.get('error_type') != 'ConnectionResetError' or reply.get('errno') != errno.ECONNRESET or
                        reply.get('received_bytes', 0) != 0 or reply.get('hex', '') != ''):
                    return 'observer_error'
                return 'candidate_closed_positive' if phase_name == 'positive' else 'rejected'
            if (kind != 'packet' or reply.get('truncated') is not False or
                    type(reply.get('flags')) is not int or reply['flags'] & socket.MSG_TRUNC):
                return 'observer_error'
            data = bytes.fromhex(reply['hex'])
            if type(reply.get('received_bytes')) is not int or reply['received_bytes'] != len(data):
                return 'observer_error'
            if not data:
                return 'inconclusive_zero_or_close'
            if phase_name == 'positive':
                if len(data) != 80 or struct.unpack('=IIIIQ', data[:24])[:4] != (0x42505431, 33, 56, 0):
                    return 'candidate_bad_positive'
                if positive_only:
                    return 'positive_ok'
            else:
                return 'candidate_accepted_or_unexpected'
        return 'observer_error'
    except (KeyError, TypeError, ValueError, struct.error):
        return 'observer_error'


def authority_controls():
    # Guest-only classifier controls: terminal positive evidence takes priority
    # over an unreached negative phase; malformed/incomplete provenance does not.
    peer = {'verified': True, 'pid': 1234, 'uid': os.geteuid(), 'gid': os.getegid(), 'socket_type': socket.SOCK_SEQPACKET}
    pos = {'reached': True, 'terminal': True, 'peer': peer, 'request': {'state': 'sent', 'hex': AUTH_POSITIVE.hex(), 'sent_bytes': len(AUTH_POSITIVE), 'start_ns': 1, 'end_ns': 2},
           'reply': {'state': 'packet', 'truncated': False, 'hex': '00', 'received_bytes': 1, 'flags': 0, 'start_ns': 3, 'end_ns': 4}}
    neg = {'reached': False, 'terminal': False, 'peer': {}, 'request': {'state': 'not_reached'}, 'reply': {'state': 'not_reached'}}
    base = {'schema': 'ptybroker-authority-v5', 'role': 'control', 'record_complete': True, 'broker_pid': 1234, 'phases': {'positive': pos, 'negative': neg}}
    if authority_classify(base) != 'candidate_bad_positive': raise ValueError('malformed positive control')
    original_reply = pos['reply']
    pos['reply'] = {'state': 'ambiguous_zero_or_close', 'start_ns': 3, 'end_ns': 4, 'received_bytes': 0, 'hex': '', 'flags': 0, 'truncated': False, 'poll_mask': select.POLLHUP}
    if authority_classify(base) != 'inconclusive_zero_or_close': raise ValueError('positive zero and HUP control')
    pos['reply'] = original_reply
    pos['peer'] = dict(peer, pid=1235)
    if authority_classify(base) != 'observer_error': raise ValueError('positive wrong peer control')
    pos['peer'] = peer
    pos['request']['sent_bytes'] -= 1
    if authority_classify(base) != 'observer_error': raise ValueError('short request control')
    pos['request']['sent_bytes'] += 1
    reply = pos['reply']
    pos['reply'] = {'state': 'timeout', 'error_type': 'TimeoutError', 'start_ns': 10, 'end_ns': 10 + AUTH_MIN_WAIT_NS, 'timeout_ns': 3_000_000_000}
    if authority_classify(base) != 'candidate_timeout_positive': raise ValueError('positive timeout control')
    pos['reply']['end_ns'] -= 1
    if authority_classify(base) != 'observer_error': raise ValueError('short timeout control')
    pos['reply'] = {'state': 'transport_error', 'error_type': 'OSError', 'start_ns': 3, 'end_ns': 4}
    if authority_classify(base) != 'observer_error': raise ValueError('transport error control')
    pos['reply'] = dict(reply, truncated=True)
    if authority_classify(base) != 'observer_error': raise ValueError('truncation control')
    pos['reply'] = {'state': 'packet', 'truncated': False, 'hex': (struct.pack('=IIIIQ', 0x42505431, 33, 56, 0, 0) + bytes(56)).hex(), 'received_bytes': 80, 'flags': 0, 'start_ns': 3, 'end_ns': 4}
    if authority_classify(base, positive_only=True) != 'positive_ok': raise ValueError('valid positive control')
    if authority_classify(base) != 'observer_error': raise ValueError('unreached negative control')
    neg.update(reached=True, terminal=True, peer=peer, request={'state': 'sent', 'hex': AUTH_NEGATIVE.hex(), 'sent_bytes': len(AUTH_NEGATIVE), 'start_ns': 5, 'end_ns': 6}, reply={'state': 'closed', 'start_ns': 7, 'end_ns': 8, 'received_bytes': 0, 'hex': '', 'flags': 0, 'truncated': False, 'poll_mask': select.POLLHUP})
    if authority_classify(base) != 'inconclusive_zero_or_close': raise ValueError('zero and HUP control')
    neg['reply']['state'] = 'ambiguous_zero_or_close'
    if authority_classify(base) != 'inconclusive_zero_or_close': raise ValueError('ambiguous zero control')
    neg['reply']['poll_mask'] = 0
    if authority_classify(base) != 'inconclusive_zero_or_close': raise ValueError('zero without HUP control')
    neg['reply'] = {'state': 'packet', 'hex': '', 'received_bytes': 0, 'truncated': False, 'flags': 0, 'start_ns': 7, 'end_ns': 8}
    if authority_classify(base) != 'inconclusive_zero_or_close': raise ValueError('zero packet control')
    neg['reply'] = {'state': 'peer_reset', 'error_type': 'ConnectionResetError', 'errno': errno.ECONNRESET, 'start_ns': 7, 'end_ns': 8}
    if authority_classify(base) != 'rejected': raise ValueError('reset rejection control')
    neg['reply']['hex'] = '00'
    neg['reply']['received_bytes'] = 1
    if authority_classify(base) != 'observer_error': raise ValueError('reset and packet conflict control')
    neg['reply'] = {'state': 'timeout', 'error_type': 'TimeoutError', 'start_ns': 7, 'end_ns': 7 + AUTH_MIN_WAIT_NS, 'timeout_ns': 3_000_000_000}
    if authority_classify(base) != 'candidate_timeout_negative': raise ValueError('negative timeout control')
    neg['reply'] = {'state': 'packet', 'hex': '00', 'received_bytes': 1, 'truncated': False, 'flags': 0, 'start_ns': 7, 'end_ns': 8}
    if authority_classify(base) != 'candidate_accepted_or_unexpected': raise ValueError('negative packet control')
    neg['peer'] = dict(peer, pid=1235)
    if authority_classify(base) != 'observer_error': raise ValueError('wrong peer control')
    neg['peer'] = peer
    base['record_complete'] = False
    if authority_classify(base) != 'observer_error': raise ValueError('incomplete record control')
    return {'malformed_positive': True, 'positive_zero_hup_inconclusive': True, 'positive_timeout': True, 'short_timeout': True,
            'transport_error': True, 'truncation': True, 'valid_positive': True, 'unreached_negative': True,
            'zero_hup_inconclusive': True, 'zero_without_hup_inconclusive': True, 'zero_packet_inconclusive': True, 'reset_rejection': True, 'reset_packet_conflict': True, 'negative_timeout': True, 'negative_packet': True,
            'wrong_peer': True, 'short_request': True, 'incomplete_record': True}


def authority_zero_control():
    """Guest-only native record/EOF control; never uses the candidate."""
    def mask(sock):
        poller = select.poll()
        poller.register(sock, select.POLLIN | select.POLLHUP | select.POLLERR)
        events = poller.poll(0)
        return events[0][1] if events else 0

    def observe(queue_empty, close_first):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            receiver.settimeout(3)
            sent = sender.send(b'') if queue_empty else None
            if queue_empty and sent != 0:
                raise ValueError('native empty record send count differs')
            if close_first:
                sender.close()
            if not select.select([receiver], [], [], 3)[0]:
                raise ValueError('native zero record or EOF was not readable')
            before = mask(receiver)
            data, ancillary, flags, _ = receiver.recvmsg(16384 + 24)
            after = mask(receiver)
            if data != b'' or flags & socket.MSG_TRUNC:
                raise ValueError('native zero record or EOF observation differs')
            if not close_first and before & select.POLLHUP:
                raise ValueError('open native peer unexpectedly reports HUP')
            return {'empty_record_sent': queue_empty, 'peer_closed_before_recv': close_first,
                    'send_count': sent, 'data_hex': data.hex(), 'received_bytes': len(data),
                    'recv_flags': flags, 'ancillary_count': len(ancillary),
                    'poll_before_recv': before, 'poll_after_recv': after}
        finally:
            receiver.close()
            sender.close()

    # The open-peer observation establishes that an empty record is readable
    # independently of EOF. The other two retain the raw close observations.
    open_empty = observe(True, False)
    close_only = observe(False, True)
    empty_then_close = observe(True, True)
    keys = ('data_hex', 'received_bytes', 'recv_flags', 'ancillary_count', 'poll_after_recv')
    return {'open_empty': open_empty, 'close_only': close_only,
            'empty_then_close': empty_then_close,
            'retained_observations_equal': all(close_only[k] == empty_then_close[k] for k in keys),
            'policy': 'all zero-byte receives are inconclusive'}


def authority_probe(role, broker):
    # Fresh PB_STATUS is a positive channel control; the attached channel is
    # then tested with PB_INPUT. Both phases retain exact bounded provenance.
    empty = lambda: {'reached': False, 'terminal': False, 'peer': {'verified': False},
                     'request': {'state': 'not_reached'}, 'reply': {'state': 'not_reached'}}
    rec = {'schema': 'ptybroker-authority-v5', 'role': role, 'broker_pid': broker,
           'stage': 'start', 'record_complete': False, 'classification': 'observer_error',
           'phases': {'positive': empty(), 'negative': empty()}}
    active = None
    operation = 'start'
    attached = None

    def verify_peer(sock, phase):
        socket_type = sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        pid, uid, gid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        phase['peer'] = {'verified': socket_type == socket.SOCK_SEQPACKET and pid == broker and uid == os.geteuid(),
                         'socket_type': socket_type, 'pid': pid, 'uid': uid, 'gid': gid}
        if not phase['peer']['verified']:
            raise ValueError('socket peer or type does not match the fixture broker')

    def request(sock, phase, payload):
        start = time.monotonic_ns()
        phase['request'] = {'state': 'sending', 'hex': payload.hex(), 'sent_bytes': None, 'start_ns': start}
        count = sock.send(payload)
        phase['request'].update(sent_bytes=count, end_ns=time.monotonic_ns(),
                                state='sent' if count == len(payload) else 'short_send')
        if count != len(payload): raise OSError('short seqpacket send')

    def receive(sock, phase):
        start = time.monotonic_ns()
        reply = {'state': 'receiving', 'start_ns': start, 'timeout_ns': 3_000_000_000}
        phase['reply'] = reply
        try:
            data, anc, flags, _ = sock.recvmsg(16384 + 24)
            end = time.monotonic_ns()
            reply.update(end_ns=end, hex=data.hex(), received_bytes=len(data), flags=flags,
                         truncated=bool(flags & socket.MSG_TRUNC), ancillary_count=len(anc))
            if reply['truncated']:
                reply['state'] = 'truncated'
            elif not data:
                poller = select.poll()
                poller.register(sock, select.POLLIN | select.POLLHUP | select.POLLERR)
                events = poller.poll(0)
                mask = events[0][1] if events else 0
                reply['poll_mask'] = mask
                reply['state'] = 'ambiguous_zero_or_close'
            else:
                reply['state'] = 'packet'
        except TimeoutError as exc:
            reply.update(state='timeout', end_ns=time.monotonic_ns(), error_type=type(exc).__name__,
                         errno=getattr(exc, 'errno', None), error=str(exc))
        except ConnectionResetError as exc:
            reply.update(state='peer_reset', end_ns=time.monotonic_ns(), error_type=type(exc).__name__,
                         errno=exc.errno, error=str(exc))
        except OSError as exc:
            reply.update(state='transport_error', end_ns=time.monotonic_ns(), error_type=type(exc).__name__,
                         errno=exc.errno, error=str(exc))

    try:
        active = rec['phases']['positive']
        active['reached'] = True
        operation = 'positive_connect'
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as ordinary:
            ordinary.settimeout(3)
            active['connect'] = {'state': 'connecting', 'start_ns': time.monotonic_ns(), 'timeout_ns': 3_000_000_000}
            try:
                ordinary.connect(str(HOME / 'broker-root/one/control.sock'))
            except OSError as exc:
                active['connect'].update(state='error', end_ns=time.monotonic_ns(), error_type=type(exc).__name__,
                                         errno=exc.errno, error=str(exc))
                raise
            active['connect'].update(state='connected', end_ns=time.monotonic_ns())
            operation = 'positive_peer'
            verify_peer(ordinary, active)
            operation = 'positive_send'
            request(ordinary, active, AUTH_POSITIVE)
            operation = 'positive_receive'
            receive(ordinary, active)
            active['terminal'] = True
        # Classify the terminal positive phase before attempting the negative.
        rec['record_complete'] = True
        verdict = authority_classify(rec, positive_only=True)
        rec['record_complete'] = False
        if verdict == 'positive_ok':
            active = rec['phases']['negative']
            active['reached'] = True
            active['connect'] = {'state': 'inherited_fd', 'fd': 9}
            operation = 'negative_socket'
            attached = socket.socket(fileno=9)
            attached.settimeout(3)
            operation = 'negative_peer'
            verify_peer(attached, active)
            operation = 'negative_send'
            request(attached, active, AUTH_NEGATIVE)
            operation = 'negative_receive'
            receive(attached, active)
            active['terminal'] = True
            rec['stage'] = 'negative_terminal'
        else:
            rec['stage'] = 'positive_terminal'
        rec['record_complete'] = True
        rec['classification'] = authority_classify(rec)
        return 0 if rec['classification'] == 'rejected' else 1
    except Exception as exc:
        if active is not None:
            active['terminal'] = True
            active['error_operation'] = operation
        rec['failure'] = {'operation': operation, 'error_type': type(exc).__name__,
                          'errno': getattr(exc, 'errno', None), 'error': str(exc)}
        rec['stage'] = 'observer_error'
        rec['record_complete'] = True
        rec['classification'] = authority_classify(rec)
        return 1
    finally:
        if attached is not None: attached.close()
        with (HOME / 'authority.jsonl').open('a') as output:
            output.write(json.dumps(rec) + '\n')


def sentinel_negative_control():
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        write_all(ready_w, b'R')
        while True: signal.pause()
    os.close(ready_w)
    fd = None
    reaped = False
    try:
        if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'R':
            raise ValueError('sentinel control did not start')
        fd = os.pidfd_open(pid, 0)
        start = proc_info(pid)['start']
        live = sentinel_observation(pid, fd, start)
        if not live['live']: raise ValueError('sentinel positive control not live')
        signal.pidfd_send_signal(fd, signal.SIGKILL)
        if not select.select([fd], [], [], 3)[0]: raise ValueError('sentinel kill not observed')
        dead = sentinel_observation(pid, fd, start)
        if dead['live'] or not dead['pidfd_readable'] or dead['proc'] is None or dead['proc']['state'] != 'Z':
            raise ValueError('zombie sentinel negative control not rejected')
        os.waitpid(pid, 0); reaped = True
        return {'positive': live, 'killed_before_observation': dead}
    finally:
        os.close(ready_r)
        if fd is not None: os.close(fd)
        if not reaped:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(pid, 0)
            except ChildProcessError: pass


def ordering_control():
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        os.close(ready_r); os.close(release_w); first.close(); second.close()
        write_all(ready_w, b'R')
        wait = select.poll()
        wait.register(release_r, select.POLLIN)
        wait.poll(5000)
        os.read(release_r, 1)
        os._exit(0)
    os.close(ready_w); os.close(release_r)
    pidfd = None
    reaped = False
    try:
        if not select.select([ready_r], [], [], 3)[0] or os.read(ready_r, 1) != b'R':
            raise ValueError('native ordering child readiness failed')
        pidfd = os.pidfd_open(pid, 0)
        if select.select([pidfd, first], [], [], 0)[0]:
            raise ValueError('native ordering child not held')
        syscall_ready = False
        witness = None
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            witness = syscall_observation(pid)
            if witness['blocked_in_wait']:
                syscall_ready = True
                break
            time.sleep(.01)
        if not syscall_ready: raise ValueError('parent cannot witness blocked child wait syscall')
        second.sendall(b'early')
        early = select.select([first, pidfd], [], [], 1)[0]
        if first not in early or pidfd in early or first.recv(10) != b'early':
            raise ValueError('early reply negative control not observed')
        write_all(release_w, b'X')
        if not select.select([pidfd], [], [], 3)[0]:
            raise ValueError('native ordering child exit not observed')
        os.waitpid(pid, 0); reaped = True
        try:
            proc_info(pid)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('native ordering child was not reaped')
        if select.select([first], [], [], 0)[0]:
            raise ValueError('reply arrived before native reaping control')
        second.sendall(b'late')
        if not select.select([first], [], [], 1)[0] or first.recv(10) != b'late':
            raise ValueError('late reply positive control not observed')
        return {'early_live_reply_detected': True, 'reaped_before_late_reply': True, 'parent_syscall_observation': witness}
    finally:
        os.close(ready_r); os.close(release_w); first.close(); second.close()
        if pidfd is not None: os.close(pidfd)
        if not reaped:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(pid, 0)
            except ChildProcessError: pass


def infrastructure_control(cleanup):
    # Exercise only the facilities required by this case; a missing pidfd or
    # FIFO must not invalidate unrelated raw-output or role observations.
    root = HOME / 'setup-private'
    root.mkdir(mode=0o700)
    first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    report = {'private_root': True}
    try:
        packet = struct.pack('=IIIIQ', 0x42505431, 5, 0, 0, 0)
        first.sendall(packet)
        if second.recv(1024) != packet: raise ValueError('seqpacket control differs')
        response = struct.pack('=IIIIQ', 0x42505431, 33, 56, 0, 0) + bytes(56)
        second.sendall(response)
        if first.recv(1024) != response: raise ValueError('positive framing control differs')
        attached, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            request = struct.pack('=IIIIQ', 0x42505431, 3, 1, 0, 0) + b'Z'
            attached.sendall(request)
            if server.recv(1024) != request: raise ValueError('negative request framing differs')
            server.close()
            if attached.recv(1) != b'': raise ValueError('negative close control differs')
        finally:
            attached.close(); server.close()
        report.update(seqpacket=True, authority_positive_negative_framing=True)
        earlier = time.monotonic_ns()
        time.sleep(0.01)
        if time.monotonic_ns() <= earlier: raise ValueError('monotonic clock did not advance')
        report['monotonic'] = True
        if cleanup:
            fifo = root / 'probe.fifo'
            os.mkfifo(fifo, 0o600)
            fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                write_all(fd, b'F')
                if os.read(fd, 1) != b'F': raise ValueError('FIFO control differs')
            finally:
                os.close(fd); fifo.unlink()
            if proc_info(os.getpid())['start'] <= 0: raise ValueError('proc control differs')
            pidfd = os.pidfd_open(os.getpid(), 0)
            try: signal.pidfd_send_signal(pidfd, 0)
            finally: os.close(pidfd)
            report.update(fifo=True, proc_pidfd=True)
        return report
    finally:
        first.close(); second.close(); root.rmdir()


def run_setup(cleanup, authority=False, identity=None):
    record = {'stage': 'identity', 'state': 'running', 'identity': identity}
    try:
        record['stage'] = 'infrastructure'
        record['infrastructure'] = infrastructure_control(cleanup)
        if cleanup:
            record['stage'] = 'native-ordering-controls'
            record['ordering'] = ordering_control()
            record['stage'] = 'sentinel-negative-control'
            record['sentinel_control'] = sentinel_negative_control()
        record['stage'] = 'parser-and-pty'
        setup(authority)
        if cleanup:
            record['stage'] = 'subreaper-pidfd'
            result = subprocess.run([sys.executable, '-I', HERE, 'capability'], capture_output=True, timeout=12)
            (HOME / 'capability.out').write_bytes(result.stdout)
            (HOME / 'capability.err').write_bytes(result.stderr)
            (HOME / 'capability.status').write_text(str(result.returncode) + '\n')
            if result.returncode != 0:
                raise ValueError('subreaper or pidfd native control unavailable')
        record['stage'] = 'complete'
        record['state'] = 'complete'
    except Exception as exc:
        record['state'] = 'error'
        record['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        (HOME / 'setup-record.json').write_text(json.dumps(record, indent=2) + '\n')


def main():
    identity = guest()
    if len(sys.argv) == 8 and sys.argv[1] == 'role-event':
        try:
            return role_event(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]), sys.argv[7])
        except (OSError, ValueError) as exc:
            print('role event capture error: ' + str(exc), file=sys.stderr)
            return 125
    if len(sys.argv) == 5 and sys.argv[1] == 'role-poll':
        try:
            return role_poll(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
        except (OSError, ValueError) as exc:
            print('role poll capture error: ' + str(exc), file=sys.stderr)
            return 125
    if sys.argv[1:] == ['guard']:
        return 0
    if sys.argv[1:] == ['setup']:
        run_setup(False, identity=identity)
        return 0
    if sys.argv[1:] == ['setup-roles']:
        run_setup(False, True, identity=identity)
        return 0
    if sys.argv[1:] == ['setup-cleanup']:
        run_setup(True, identity=identity)
        return 0
    if sys.argv[1:] == ['deadline']:
        print(time.monotonic_ns() + 8_000_000_000)
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'before':
        return 0 if time.monotonic_ns() < int(sys.argv[2]) else 1
    if len(sys.argv) == 4 and sys.argv[1] == 'authority' and sys.argv[2] in ('control', 'observe'):
        return authority_probe(sys.argv[2], int(sys.argv[3]))
    if sys.argv[1:] == ['child']:
        return child()
    if sys.argv[1:] == ['tree-child']:
        return tree_child()
    if sys.argv[1:] == ['sentinel']:
        return sentinel()
    if len(sys.argv) == 4 and sys.argv[1] == 'watch-tree':
        watch_tree()
        return 0
    if sys.argv[1:] == ['capability']:
        capability()
        return 0
    if sys.argv[1:] == ['check-cleanup']:
        return check_cleanup()
    if sys.argv[1:] == ['check']:
        return check()
    if sys.argv[1:] == ['check-roles']:
        return check_roles()
    if sys.argv[1:] == ['check-authority']:
        return check_authority()
    raise ValueError('expected setup, child, or check')


if __name__ == '__main__':
    raise SystemExit(main())
