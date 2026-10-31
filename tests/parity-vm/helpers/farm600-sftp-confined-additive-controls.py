#!/usr/bin/python3
"""Independent byte-level controls for the guest-only confined transfer peer."""
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
SERVER = '/opt/bashos-parity/harness/helpers/farm600-sftp-confined-additive-server.py'
LIFEPATH = '/opt/bashos-parity/harness/helpers/farm600-sftp-confined-additive-lifecycle.py'
GUARD = '/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py'
GUARD_SHA = 'a74d97058d313388948010d1033f50dde7151c2d204d221ed3aeb4da3e9e1762'
PAYLOAD = bytes(range(256))
LIFE = None


def guard():
    if hashlib.sha256(Path(GUARD).read_bytes()).hexdigest() != GUARD_SHA: raise ValueError('guard digest')
    runpy.run_path(GUARD)['verify']()
    if os.getuid() != 2000 or os.geteuid() != 2000: raise ValueError('uid')
    for p in (CASE, HOME):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 2000 or s.st_mode & 0o022: raise ValueError('scratch')


def b64(b): return base64.b64encode(b).decode('ascii')
def p32(n): return struct.pack('>I', n)
def p64(n): return struct.pack('>Q', n)
def string(b): return p32(len(b)) + b


def current_umask():
    previous = os.umask(0o077); os.umask(previous)
    return format(previous, '04o')


def read_exact(fd, length, timeout=3):
    end = time.monotonic() + timeout; out = bytearray()
    while len(out) < length:
        remain = end - time.monotonic()
        if remain <= 0 or not select.select([fd], [], [], remain)[0]: raise TimeoutError('peer read timeout')
        part = os.read(fd, length - len(out))
        if not part: raise EOFError('short peer response')
        out.extend(part)
    return bytes(out)


def read_port(proc):
    deadline = time.monotonic() + 5; line = bytearray()
    while not line.endswith(b'\n'):
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('port deadline')
        line.extend(read_exact(proc.stdout.fileno(), 1, timeout=remaining))
        if len(line) > 6: raise ValueError('port line')
    port = int(line)
    if not 1 <= port <= 65535: raise ValueError('port')
    return port


def packet(p, body, records):
    raw = p32(len(body)) + body
    p.stdin.write(raw); p.stdin.flush()
    header = read_exact(p.stdout.fileno(), 4)
    n = struct.unpack('>I', header)[0]
    if not 1 <= n <= 65536: raise ValueError('response size')
    response = header + read_exact(p.stdout.fileno(), n)
    records.append({'request': b64(raw), 'response': b64(response)})
    return response[4:]


def response(body, typ, ident):
    if len(body) < 5 or body[0] != typ or body[1:5] != p32(ident): raise ValueError('response type/id')
    return body[5:]


def handle(body, ident):
    b = response(body, 102, ident)
    if len(b) < 4: raise ValueError('short handle')
    n = struct.unpack('>I', b[:4])[0]
    if n != len(b[4:]) or not n: raise ValueError('bad handle')
    return b[4:]


def status(body, ident, wanted):
    b = response(body, 101, ident)
    if len(b) < 4: raise ValueError('short status')
    code = struct.unpack('>I', b[:4])[0]
    if (code == 0) != wanted: raise ValueError('unexpected status %d' % code)
    return code


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 2000 or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('unsafe or oversized control file')
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, limit + 1 - len(data))
            if not part: break
            data.extend(part)
        after = os.fstat(fd)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if fields(before) != fields(after) or len(data) != before.st_size:
            raise ValueError('control file changed during read')
        return bytes(data), before
    finally: os.close(fd)


def snapshot():
    p = CASE / 'sftp-confined-external' / 'sentinel'
    data, s = read_regular(p, 4096)
    return {'bytes': b64(data), 'mode': stat.S_IMODE(s.st_mode),
            'dev': s.st_dev, 'ino': s.st_ino, 'nlink': s.st_nlink, 'size': s.st_size}


def commands():
    return ['/tmp/parity-case/sftp-confined-external/sentinel',
            '../sftp-confined-external/sentinel', 'escape-link', 'escape-dir/sentinel']


def control_tree(root):
    """Independently collect the parity runner's path, kind, mode and bytes."""
    names = sorted(p.name for p in root.iterdir())
    if len(names) > 16: raise ValueError('control tree entry limit')
    result = {}
    for name in names:
        path = root / name; info = path.lstat()
        entry = {'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            entry.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            data, actual = read_regular(path, 4096)
            if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino): raise ValueError('control tree changed')
            entry.update(kind='file', base64=b64(data))
        else:
            raise ValueError('unexpected control tree object')
        result[name] = entry
    return result


def finish(p):
    return LIFE['finish'](p, timeout=4)


def sftp_controls(env, result):
    LIFE['before_spawn']()
    p = LIFE['spawn'](['/usr/bin/python3', '-I', SERVER, 'sftp'], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0,
                         start_new_session=True)
    result['pid'] = p.pid
    rows = result['packets'] = []
    try:
        if packet(p, b'\x01' + p32(3), rows) != b'\x02' + p32(3): raise ValueError('version')
        ident = 1
        def op(t, args):
            nonlocal ident
            number = ident; ident += 1
            return number, packet(p, bytes([t]) + p32(number) + args, rows)
        i, r = op(3, string(b'positive file.bin') + p32(26) + p32(0)); h = handle(r, i)
        i, r = op(6, string(h) + p64(0) + string(PAYLOAD)); status(r, i, True)
        i, r = op(4, string(h)); status(r, i, True)
        i, r = op(3, string(b'positive file.bin') + p32(1) + p32(0)); h = handle(r, i)
        i, r = op(5, string(h) + p64(0) + p32(256)); data = response(r, 103, i)
        if data != string(PAYLOAD): raise ValueError('positive bytes')
        i, r = op(4, string(h)); status(r, i, True)
        if read_regular(CASE / 'sftp-confined-control' / 'positive file.bin', 256)[0] != PAYLOAD: raise ValueError('positive tree')
        result['negatives'] = []
        for path in commands():
            for flags in (1, 26):
                before = snapshot()
                i, r = op(3, string(path.encode()) + p32(flags) + p32(0))
                code = status(r, i, False); after = snapshot()
                result['negatives'].append({'path': path, 'flags': flags, 'code': code, 'before': before, 'after': after})
                if before != after: raise ValueError('external sentinel changed')
        result['positive'] = b64(PAYLOAD)
    finally:
        try: p.stdin.close()
        finally:
            p.stdin = None
            result['lifecycle'] = finish(p)
    life = result['lifecycle']
    if not life['complete'] or life['forced'] or life['rc'] != 0 or life['stdout'] or life['stderr']:
        raise ValueError('SFTP peer lifecycle')


def exchange(port, command, data, records, extra=b''):
    raw = b'BASHSSH1\ncmd-len %d\nstdin-len %d\n\n' % (len(command), len(data)) + command + data + extra
    deadline = time.monotonic() + 7
    with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
        local, remote = list(s.getsockname()), list(s.getpeername())
        def budget():
            left = deadline - time.monotonic()
            if left <= 0: raise TimeoutError('control exchange deadline')
            s.settimeout(left)
        budget(); s.sendall(raw); s.shutdown(socket.SHUT_WR)
        head = bytearray()
        while not head.endswith(b'\n\n'):
            budget()
            b = s.recv(1)
            if not b: raise EOFError('short native response')
            head.extend(b)
            if len(head) > 512: raise ValueError('response header limit')
        lines = bytes(head[:-2]).split(b'\n')
        if len(lines) != 4 or lines[0] != b'BASHSSH1-RESP': raise ValueError('response header')
        fields = dict(x.split(b' ', 1) for x in lines[1:])
        if set(fields) != {b'rc', b'stdout-len', b'stderr-len'}: raise ValueError('response fields')
        rc, a, b = (int(fields[k]) for k in (b'rc', b'stdout-len', b'stderr-len'))
        if not 0 <= a + b <= 65536: raise ValueError('response length')
        body = bytearray()
        while len(body) < a + b:
            budget()
            piece = s.recv(a + b - len(body))
            if not piece: raise EOFError('short native body')
            body.extend(piece)
        budget()
        if s.recv(1): raise ValueError('trailing native response')
        records.append({'request': b64(raw), 'response': b64(bytes(head) + body), 'eof': True,
                        'client_pid': os.getpid(), 'client_local': local, 'client_remote': remote})
        return rc, bytes(body[:a]), bytes(body[a:])


def native_controls(env, result):
    LIFE['before_spawn']()
    p = LIFE['spawn'](['/usr/bin/python3', '-I', SERVER, 'native', '10'], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0, start_new_session=True)
    result['pid'] = p.pid; records = result['frames'] = []
    try:
        port = read_port(p); result['port'] = port
        a = exchange(port, b"cd '/fixture' && cat > 'positive file.bin'", PAYLOAD, records)
        b = exchange(port, b"cd '/fixture' && cat -- 'positive file.bin'", b'', records)
        if a != (0, b'', b'') or b != (0, PAYLOAD, b''): raise ValueError('native positive')
        result['positive'] = b64(PAYLOAD); result['negatives'] = []
        for path in commands():
            for op in ('read', 'write'):
                before = snapshot(); verb = 'cat --' if op == 'read' else 'cat >'
                cmd = ("cd '/fixture' && " + verb + " '" + path + "'").encode()
                rc, out, err = exchange(port, cmd, b'' if op == 'read' else PAYLOAD, records)
                after = snapshot()
                result['negatives'].append({'path': path, 'operation': op, 'rc': rc, 'stdout': b64(out), 'stderr': b64(err), 'before': before, 'after': after})
                if rc == 0 or before != after: raise ValueError('native escape')
        if read_regular(CASE / 'sftp-confined-control' / 'positive file.bin', 256)[0] != PAYLOAD: raise ValueError('native tree')
    finally:
        result['lifecycle'] = finish(p)
    life = result['lifecycle']
    if not life['complete'] or life['forced'] or life['rc'] != 0 or life['stdout'] or life['stderr']:
        raise ValueError('native peer lifecycle')


def frame_controls(env, result):
    for label in ('extra', 'short'):
        record = result[label] = {'frames': []}
        LIFE['before_spawn']()
        p = LIFE['spawn'](['/usr/bin/python3', '-I', SERVER, 'native', '1'], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0, start_new_session=True)
        record['pid'] = p.pid
        try:
            port = read_port(p); record['port'] = port
            if label == 'extra':
                if exchange(port, b'pwd', b'', record['frames'], b'extra') != (0, b'/fixture\n', b''):
                    raise ValueError('extra-byte response')
            else:
                raw = b'BASHSSH1\ncmd-len 9\nstdin-len 0\n\npwd'
                with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
                    s.settimeout(3); s.sendall(raw); s.shutdown(socket.SHUT_WR)
                    reply = s.recv(1)
                record['frames'].append({'request': b64(raw), 'response': b64(reply), 'eof': not reply})
                if reply: raise ValueError('short frame answered')
        finally:
            record['lifecycle'] = finish(p)
        life = record['lifecycle']
        if life['forced'] or not life['complete'] or life['stdout']:
            raise ValueError('frame control lifecycle')
        if label == 'extra' and (life['rc'] != 0 or life['stderr']): raise ValueError('extra control')
        if label == 'short' and (life['rc'] != 125 or b'short body' not in base64.b64decode(life['stderr'])):
            raise ValueError('short control')


def deadline_controls(env, result):
    """Observe absolute time limits and the largest permitted stdin frame."""
    for label in ('header', 'body', 'eof', 'limit', 'repeat'):
        LIFE['before_spawn'](); peer_env = dict(env, SFTP_CONFINED_LOG='deadline-' + label)
        if label == 'repeat': peer_env['SFTP_CONFINED_TEST_BUDGET'] = '4'
        p = LIFE['spawn'](['/usr/bin/python3', '-I', SERVER, 'native', '16' if label == 'repeat' else '1'], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=peer_env, bufsize=0, start_new_session=True)
        row = result[label] = {'peer_pid': p.pid, 'sends': [], 'started_ns': time.monotonic_ns()}
        try:
            port = read_port(p); row['port'] = port
            if label == 'repeat':
                row['exchanges'] = []
                for _ in range(4):
                    reply = exchange(port, b'pwd', b'', row['exchanges'])
                    if reply != (0, b'/fixture\n', b''): raise ValueError('repeat response')
                    time.sleep(.65)
                time.sleep(1.6)
            elif label == 'limit':
                payload = bytes(range(256)) * 256; records = []
                reply = exchange(port, b"cd '/fixture' && cat > 'limit file.bin'", payload, records)
                row['exchange'] = records
                target = CASE / 'sftp-confined-control' / 'limit file.bin'
                data, _info = read_regular(target, 65536)
                row['file'] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                if reply != (0, b'', b'') or data != payload: raise ValueError('exact-limit transfer')
                target.unlink()
            else:
                with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
                    deadline = time.monotonic() + 7; row['client_local'] = list(s.getsockname())
                    def budget():
                        left = deadline - time.monotonic()
                        if left <= 0: raise TimeoutError('deadline control client budget')
                        s.settimeout(left)
                    if label == 'eof':
                        request = b'BASHSSH1\ncmd-len 3\nstdin-len 0\n\npwd'
                        budget(); s.sendall(request); row['sends'].append({'bytes': b64(request), 'ns': time.monotonic_ns()})
                        expected = b'BASHSSH1-RESP\nrc 0\nstdout-len 9\nstderr-len 0\n\n/fixture\n'
                        response = bytearray()
                        while len(response) < len(expected):
                            budget()
                            part = s.recv(len(expected) - len(response))
                            if not part: raise EOFError('short no-EOF response')
                            response.extend(part)
                        row['response'] = b64(bytes(response))
                        if bytes(response) != expected: raise ValueError('no-EOF response')
                        budget(); row['peer_eof'] = s.recv(1) == b''; row['peer_eof_ns'] = time.monotonic_ns()
                        if not row['peer_eof']: raise ValueError('unexpected trailing response')
                    else:
                        if label == 'body':
                            prefix = b'BASHSSH1\ncmd-len 3\nstdin-len 32\n\npwd'
                            budget(); s.sendall(prefix); row['sends'].append({'bytes': b64(prefix), 'ns': time.monotonic_ns()})
                            drip = b'abcdefgh'
                        else: drip = b'BASHSSH1'
                        for byte in drip:
                            try:
                                budget(); s.sendall(bytes([byte])); row['sends'].append({'bytes': b64(bytes([byte])), 'ns': time.monotonic_ns()})
                            except OSError as exc:
                                row['send_error'] = repr(exc); break
                            time.sleep(.8)
                        try: budget(); row['after_drip'] = b64(s.recv(1))
                        except OSError as exc: row['receive_error'] = repr(exc)
        finally:
            row['lifecycle'] = finish(p); row['finished_ns'] = time.monotonic_ns()
        logfile = HOME / ('sftp-confined-deadline-' + label + '.jsonl')
        fd = os.open(logfile, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_nlink != 1:
                raise ValueError('unsafe deadline log')
            raw = bytearray()
            while len(raw) <= 262144:
                part = os.read(fd, 262145 - len(raw))
                if not part: break
                raw.extend(part)
        finally: os.close(fd)
        if len(raw) > 262144: raise ValueError('deadline log limit')
        row['peer_events'] = [json.loads(item) for item in bytes(raw).splitlines()]
        life = row['lifecycle']
        if not life['complete'] or life['forced']: raise ValueError('deadline peer lifecycle')
        if label == 'repeat':
            ready = [x for x in row['peer_events'] if x.get('event') == 'native-ready']
            end = [x for x in row['peer_events'] if x.get('event') == 'native-finished']
            if (life['rc'] != 0 or len(row['exchanges']) != 4 or len(ready) != 1 or len(end) != 1 or
                    ready[0].get('server_budget_seconds') != 4.0 or
                    end[0].get('requests') != 4 or end[0].get('finished_ns', 0) < ready[0].get('server_deadline_ns', 1)):
                raise ValueError('absolute server lifetime control')
        elif label == 'limit':
            if life['rc'] != 0 or not any(x.get('event') == 'native-request' and x.get('eof') for x in row['peer_events']):
                raise ValueError('exact-limit peer')
        else:
            failures = [x for x in row['peer_events'] if x.get('event') == 'native-error']
            if (life['rc'] != 125 or len(failures) != 1 or failures[0].get('phase') != ('trailing' if label == 'eof' else label) or
                    failures[0].get('observed_ns', 0) < failures[0].get('frame_deadline_ns', 1)):
                raise ValueError('absolute deadline control')


def attribution_controls(env, result):
    LIFE['before_spawn']()
    peer_env = dict(env, SFTP_CONFINED_LOG='attribution')
    p = LIFE['spawn'](['/usr/bin/python3', '-I', SERVER, 'native', '2'], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=peer_env, bufsize=0, start_new_session=True)
    result['peer_pid'] = p.pid; rows = result['expected_client'] = []
    competitor = '''import base64, json, os, socket, sys
port = int(sys.argv[1]); request = b'BASHSSH1\\ncmd-len 3\\nstdin-len 0\\n\\npwd'
with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
    s.settimeout(3); local = list(s.getsockname()); remote = list(s.getpeername())
    s.sendall(request); s.shutdown(socket.SHUT_WR); data = bytearray()
    while True:
        part = s.recv(4096)
        if not part: break
        data.extend(part)
        if len(data) > 4096: raise ValueError('response limit')
print(json.dumps({'pid': os.getpid(), 'local': local, 'remote': remote,
                  'request': base64.b64encode(request).decode(),
                  'response': base64.b64encode(data).decode()}))
'''
    try:
        port = read_port(p); result['port'] = port
        if exchange(port, b'pwd', b'', rows) != (0, b'/fixture\n', b''): raise ValueError('expected client')
        if LIFE['children']() != [p.pid]: raise ValueError('unexpected children before competitor')
        child = LIFE['spawn'](['/usr/bin/python3', '-I', '-c', competitor, str(port)], excluded_children=(p.pid,),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env, bufsize=0, start_new_session=True)
        child_life = LIFE['finish'](child, timeout=5, excluded_children=(p.pid,))
        result['competitor_process'] = child_life
        child_stdout = base64.b64decode(child_life['stdout'])
        if (not child_life['complete'] or child_life['forced'] or child_life['rc'] != 0 or
                child_life['stderr'] or len(child_stdout) > 4096): raise ValueError('competitor control')
        other = json.loads(child_stdout); result['competitor'] = other
        if other['pid'] != child.pid or other['pid'] == os.getpid() or other['local'] == rows[0]['client_local']:
            raise ValueError('competitor identity or tuple')
    finally:
        result['lifecycle'] = finish(p)
    if not result['lifecycle']['complete'] or result['lifecycle']['rc'] != 0 or result['lifecycle']['forced']:
        raise ValueError('attribution peer lifecycle')
    path = HOME / 'sftp-confined-attribution.jsonl'
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 2000 or info.st_nlink != 1:
            raise ValueError('unsafe attribution log')
        raw = bytearray()
        while len(raw) <= 131072:
            part = os.read(fd, 131073 - len(raw))
            if not part: break
            raw.extend(part)
    finally: os.close(fd)
    result['peer_log_base64'] = b64(bytes(raw[:131072]))
    if len(raw) > 131072: raise ValueError('attribution log limit')
    events = [json.loads(line) for line in bytes(raw).splitlines()]
    result['peer_events'] = events
    checks = [x for x in events if x.get('pid') == p.pid and x.get('event') == 'native-attribution']
    if len(checks) != 2: raise ValueError('attribution event count')
    for item, client, matched in ((checks[0], rows[0]['client_local'], True), (checks[1], other['local'], False)):
        witness = item['witness']
        if (item['endpoint']['remote'] != client or witness['status'] != 'observed' or
                witness['matched'] is not matched or witness['seed']['pid'] != os.getpid()):
            raise ValueError('attribution control mismatch')


def lifecycle_controls(env, result):
    normal = "import sys; sys.stdout.write('normal\\n'); sys.stdout.flush()"
    timeout = 'import time; time.sleep(5)'
    detached = '''import os, time
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r); os.setsid(); os.close(0); os.close(1); os.close(2)
    os.write(w, b'R'); os.close(w); time.sleep(10); os._exit(0)
os.close(w)
if os.read(r, 1) != b'R': os._exit(3)
os.close(r); print('detached=%d' % pid, flush=True)
os._exit(0)
'''
    ready_detached = '''import os, time
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r); os.setsid(); os.close(0); os.close(1); os.close(2)
    os.write(w, b'R'); os.close(w); time.sleep(10); os._exit(0)
os.close(w)
if os.read(r, 1) != b'R': os._exit(3)
os.close(r); print('detached=%d' % pid, flush=True); time.sleep(10)
'''
    for name, script, limit, injected, fault in (
            ('normal', normal, 3, False, None), ('timeout', timeout, .25, False, None),
            ('detached', detached, 3, False, None), ('cleanup_failure', detached, 3, True, None),
            ('failed_leader_pidfd', ready_detached, 3, False, 'leader_pidfd'),
            ('failed_leader_identity', ready_detached, 3, False, 'leader_identity'),
            ('failed_leader_wait', ready_detached, 3, False, 'leader_wait'),
            ('failed_leader_signal', ready_detached, .25, False, 'leader_signal'),
            ('failed_adopted_pidfd', detached, 3, False, 'adopted_pidfd'),
            ('failed_adopted_identity', detached, 3, False, 'adopted_identity'),
            ('failed_enumeration', detached, 3, False, 'enumeration')):
        LIFE['before_spawn']()
        p = LIFE['spawn'](['/usr/bin/python3', '-I', '-c', script], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                             bufsize=0, start_new_session=True)
        reported = None; line = bytearray(); readiness_error = None
        try:
            if script == ready_detached:
                end = time.monotonic() + 5
                while not line.endswith(b'\n'):
                    left = end - time.monotonic()
                    if left <= 0: raise TimeoutError('fault-control readiness deadline')
                    line.extend(read_exact(p.stdout.fileno(), 1, timeout=left))
                    if len(line) > 64: raise ValueError('fault-control readiness limit')
                if not line.startswith(b'detached='): raise ValueError('fault-control readiness')
                reported = int(line[len(b'detached='):-1])
        except (OSError, ValueError, EOFError, TimeoutError) as exc:
            readiness_error = repr(exc)
        finally:
            record = LIFE['finish'](p, timeout=limit, injected_error=injected, fault=fault)
            record['readiness_base64'] = b64(bytes(line)); record['readiness_error'] = readiness_error
            if reported is not None: record['reported_detached_pid'] = reported
            result[name] = record
        if readiness_error: raise ValueError('fault-control readiness failed')
        if not record['leader_reaped'] or not (record.get('leader_waitid_wnowait') or
                                               record.get('leader_fallback', {}).get('exit_waitid_wnowait')):
            raise ValueError('lifecycle leader not independently observed')
        if name == 'normal' and (not record['complete'] or record['forced'] or record['rc'] != 0 or
                                 base64.b64decode(record['stdout']) != b'normal\n'):
            raise ValueError('normal lifecycle control')
        if name == 'timeout' and (not record['complete'] or not record['forced'] or not record['timeout'] or
                                  record['rc'] != -signal.SIGKILL or record.get('leader_signal') != 'SIGKILL-via-pidfd'):
            raise ValueError('timeout lifecycle control')
        if name == 'detached':
            raw = base64.b64decode(record['stdout'])
            if not raw.startswith(b'detached=') or not raw.endswith(b'\n'): raise ValueError('detached identity')
            pid = int(raw[len(b'detached='):-1])
            children = [x for x in record['adopted'] if x['pid'] == pid]
            if (not record['complete'] or not record['forced'] or record['rc'] != 0 or len(children) != 1 or
                    children[0].get('signal') != 'SIGKILL-via-pidfd' or
                    children[0].get('waitpid', {}).get('exitcode') != -signal.SIGKILL):
                raise ValueError('detached lifecycle control')
        if name == 'cleanup_failure' and (record['complete'] or record['rc'] != 0 or not record['forced'] or
                                           not record['adopted'] or
                                           'injected-adopted-observation-failure-control' not in record['errors']):
            raise ValueError('failure lifecycle control')
        if name.startswith('failed_'):
            if record['complete'] or not record['errors'] or record.get('children_after') != []:
                raise ValueError('fault control was not incomplete or cleaned')
            if name in ('failed_leader_pidfd', 'failed_leader_identity'):
                fallback = record.get('leader_fallback', {})
                if not fallback.get('reaped') or not fallback.get('exit_waitid_wnowait'):
                    raise ValueError('leader fallback did not reap')
            if name in ('failed_adopted_pidfd', 'failed_adopted_identity'):
                raw = base64.b64decode(record['stdout'])
                if not raw.startswith(b'detached=') or not raw.endswith(b'\n'): raise ValueError('adopted fault identity')
                target = int(raw[len(b'detached='):-1])
                if not any(x['pid'] == target and x.get('fallback', {}).get('reaped') for x in record['adopted']):
                    raise ValueError('adopted fallback did not reap')
            if reported is not None and not any(x['pid'] == reported and
                    (x.get('waitpid', {}).get('exitcode') == -signal.SIGKILL or
                     x.get('fallback', {}).get('waitpid', {}).get('exitcode') == -signal.SIGKILL)
                    for x in record['adopted']):
                raise ValueError('fault-control detached child not reaped')


def interrupted_observer_control(env, result):
    supervisor = '''import os, runpy, subprocess, sys, time
life = runpy.run_path('/opt/bashos-parity/harness/helpers/farm600-sftp-confined-additive-lifecycle.py')
life['prepare'](); life['before_spawn']()
program = """import os,time
r,w=os.pipe(); child=os.fork()
if child==0:
 os.close(r); os.setsid(); os.close(0); os.close(1); os.close(2); os.write(w,b'R'); os.close(w); time.sleep(20); os._exit(0)
os.close(w)
if os.read(r,1)!=b'R': os._exit(3)
print('%d %d'%(os.getpid(),child),flush=True); time.sleep(20)
"""
p = life['spawn'](['/usr/bin/python3','-I','-c',program], stdin=subprocess.DEVNULL,
                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
line = p.stdout.readline()
print(line.decode('ascii').strip(), flush=True)
time.sleep(20)
'''
    LIFE['before_spawn']()
    p = LIFE['spawn'](['/usr/bin/python3', '-I', '-c', supervisor], stdin=subprocess.DEVNULL,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0, start_new_session=True)
    result['supervisor_pid'] = p.pid
    try:
        line = bytearray(); deadline = time.monotonic() + 5
        while not line.endswith(b'\n'):
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('interrupted identity deadline')
            line.extend(read_exact(p.stdout.fileno(), 1, timeout=remaining))
            if len(line) > 64: raise ValueError('interrupted control identity limit')
        leader, detached = (int(x) for x in line.split()); result['reported_line'] = b64(bytes(line))
        result['leader_pid'] = leader; result['detached_pid'] = detached
        before = LIFE['proc_stat'](p.pid); result['supervisor_identity'] = before
        if before['ppid'] != os.getpid() or LIFE['observed_exit'](p.pid) is not None:
            raise ValueError('supervisor is not live owned child')
        fd = os.pidfd_open(p.pid, 0)
        try: signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally: os.close(fd)
        result['interrupt'] = 'SIGKILL-via-pidfd'
        end = time.monotonic() + 4; event = None
        while event is None and time.monotonic() < end:
            try: event = LIFE['observed_exit'](leader)
            except ChildProcessError: pass
            if event is None: time.sleep(.02)
        result['leader_parent_death_waitid'] = event
        if event is None or event['code'] != os.CLD_KILLED or event['status'] != signal.SIGKILL:
            raise ValueError('leader parent-death termination not observed')
    finally:
        result['lifecycle'] = LIFE['finish'](p, timeout=4)
    life = result['lifecycle']; adopted = {x['pid']: x for x in life['adopted']}
    if (not life['complete'] or life['rc'] != -signal.SIGKILL or leader not in adopted or detached not in adopted or
            adopted[leader].get('signal') is not None or adopted[leader].get('waitpid', {}).get('exitcode') != -signal.SIGKILL or
            adopted[detached].get('waitpid', {}).get('exitcode') != -signal.SIGKILL):
        raise ValueError('interrupted observer descendants not terminated and reaped')


def main():
    global LIFE
    guard(); LIFE = runpy.run_path(LIFEPATH); LIFE['prepare']()
    result = {'schema': 1, 'passed': False, 'sftp': {}, 'native': {}, 'framing': {}, 'tree_control': {},
              'lifecycle_controls': {}, 'interrupted_observer': {}, 'deadline_controls': {}, 'attribution_controls': {},
                       'identity': {'token': Path('/etc/bashos-parity-vm').read_text().strip(), 'umask': current_umask(),
                                    'uid': os.getuid(), 'euid': os.geteuid(), 'cwd': os.getcwd(),
                                    'home': os.environ.get('HOME')}}
    try:
        root = CASE / 'sftp-confined-control'; external = CASE / 'sftp-confined-external'
        root.mkdir(mode=0o700); external.mkdir(mode=0o700)
        (external / 'sentinel').write_bytes(b'external sentinel: immutable\x00\xff\n')
        (root / 'escape-link').symlink_to(external / 'sentinel')
        (root / 'escape-dir').symlink_to(external, target_is_directory=True)
        env = dict(os.environ, SFTP_CONFINED_ROOT='control', SFTP_CONFINED_LOG='control',
                   SFTP_CONFINED_EXPECTED_PID=str(os.getpid()), PATH='/usr/bin:/bin')
        trees = result['tree_control']; trees['before'] = control_tree(root)
        baseline = {'escape-link': {'mode': 0o777, 'kind': 'symlink', 'target': str(external / 'sentinel')},
                    'escape-dir': {'mode': 0o777, 'kind': 'symlink', 'target': str(external)}}
        if trees['before'] != baseline: raise ValueError('control baseline differs')
        sftp_controls(env, result['sftp']); trees['sftp_after'] = control_tree(root)
        expected = dict(trees['before'])
        expected['positive file.bin'] = {'mode': 0o600, 'kind': 'file', 'base64': b64(PAYLOAD)}
        if trees['sftp_after'] != expected: raise ValueError('SFTP control tree differs')
        (root / 'positive file.bin').unlink()
        trees['after_reset'] = control_tree(root)
        if trees['after_reset'] != trees['before']: raise ValueError('control tree reset differs')
        native_controls(env, result['native']); trees['native_after'] = control_tree(root)
        if trees['native_after'] != expected: raise ValueError('native control tree differs')
        wrong_bytes = dict(expected); wrong_bytes['positive file.bin'] = {'mode': 0o600, 'kind': 'file', 'base64': b64(PAYLOAD[:-1])}
        wrong_mode = dict(expected); wrong_mode['positive file.bin'] = {'mode': 0o644, 'kind': 'file', 'base64': b64(PAYLOAD)}
        wrong_path = dict(expected); wrong_path['different file.bin'] = wrong_path.pop('positive file.bin')
        trees['negative_samples'] = {'wrong_bytes': wrong_bytes, 'wrong_mode': wrong_mode, 'wrong_path': wrong_path}
        trees['negative_checks'] = {'wrong_bytes_rejected': wrong_bytes != expected,
                                    'wrong_mode_rejected': wrong_mode != expected,
                                    'wrong_path_rejected': wrong_path != expected}
        if not all(trees['negative_checks'].values()): raise ValueError('tree comparison negative control')
        frame_controls(env, result['framing']); lifecycle_controls(env, result['lifecycle_controls'])
        interrupted_observer_control(env, result['interrupted_observer']); deadline_controls(env, result['deadline_controls'])
        attribution_controls(env, result['attribution_controls'])
        result['passed'] = True
    except (OSError, ValueError, EOFError, TimeoutError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        result['error'] = repr(exc)
    (HOME / 'sftp-confined-controls.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    if not result['passed']: raise SystemExit(98)


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, RuntimeError) as exc:
        print('confined controls: ' + repr(exc), file=sys.stderr); sys.exit(125)
