#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM-only bashpoll peer and kernel-epoll observers.

All endpoints are private AF_UNIX or 127.0.0.1. Shells and sockets are owned by
this observer; all waits and output are bounded. Readiness expectations come
from an independent epoll instance on the *same* stable descriptors. The TCP
timeout uses the separately pinned seccomp supervisor with a positive and a
negative filter control; the other cases do not depend on syscall injection.
"""
import base64
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
WORK = CASE / 'poll-work'
SEQ = '/opt/bashos-parity/harness/helpers/system-sequence.py'
LIMIT = time.monotonic() + 45
CHILDREN = []


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert Path.cwd() == CASE and os.geteuid() == 2000


def record(kind, **fields):
    fields['kind'] = kind
    with (HOME / 'bashpoll-observations.jsonl').open('a') as f:
        f.write(json.dumps(fields, sort_keys=True) + '\n')


def raw(data): return base64.b64encode(data[:65536]).decode()
def yes(v): return 'yes' if v else 'no'


def wait_for(predicate, seconds=5):
    end = min(LIMIT, time.monotonic() + seconds)
    while True:
        value = predicate()
        if value or time.monotonic() >= end: return value
        time.sleep(.01)


def init():
    WORK.mkdir(mode=0o700)
    os.chmod(WORK, 0o700)


def spawn(shell, script, *args, fds=()):
    proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script, 'fixture', *map(str,args)],
                            cwd=WORK, env=dict(os.environ), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=tuple(fds),
                            start_new_session=True)
    CHILDREN.append(proc)
    record('spawn', pid=proc.pid, script=script, args=list(map(str,args)), fds=list(fds))
    return proc


def done(proc, label, timeout=5):
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill(); out, err = proc.communicate(timeout=3)
        record('child-timeout', label=label, stdout_base64=raw(out), stderr_base64=raw(err))
        raise RuntimeError('child timed out: ' + label)
    record('child', label=label, status=proc.returncode, stdout_base64=raw(out), stderr_base64=raw(err))
    return proc.returncode, out, err


def wait_marker(proc, path):
    if not wait_for(lambda: path.exists() or proc.poll() is not None) or not path.exists():
        raise RuntimeError('child exited or failed to make ready marker: ' + str(path))


def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0)); s.listen(8); s.settimeout(5)
    return s


def free_port(kind):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    return port


def read_eof(conn):
    data = bytearray(); conn.settimeout(5)
    while len(data) < 1024:
        part = conn.recv(1024 - len(data))
        if not part: return bytes(data), True
        data.extend(part)
    return bytes(data), False


def tcp(shell):
    init(); port = free_port(socket.SOCK_STREAM)
    script = r'''builtin bashpoll listen "127.0.0.1:$1" l || exit 11
printf 'ready\n' > listen.ready
builtin bashpoll accept "$l" c || exit 12
IFS= read -r -t 3 msg <&"$c" || exit 13
printf 'reply:%s\n' "$msg" >&"$c" || exit 14
builtin bashpoll close "$c" || exit 15
builtin bashpoll close "$l" || exit 16
printf 'listen-accept=ok\n'
'''
    proc = spawn(shell, script, port); wait_marker(proc, WORK / 'listen.ready')
    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
        client.sendall(b'hello\n'); data, eof = read_eof(client)
    status, out, err = done(proc, 'tcp-listen')
    ok = status == 0 and out == b'listen-accept=ok\n' and not err and data == b'reply:hello\n' and eof
    record('tcp-listen-peer', data_base64=raw(data), eof=eof, ok=ok, port=port)
    print('tcp-listen accept-exchange-eof=%s' % yes(ok))

    server = listener(); port = server.getsockname()[1]
    script = r'''builtin bashpoll connect "127.0.0.1:$1" c -t 1000 || exit 21
printf 'A\000\377B' >&"$c" || exit 22
IFS= read -r -t 3 msg <&"$c" || exit 23
printf 'received:%s\n' "$msg"
builtin bashpoll close "$c" || exit 24
'''
    proc = spawn(shell, script, port)
    try:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(5)
            data = bytearray()
            while len(data) < 4:
                part = conn.recv(4 - len(data))
                if not part: break
                data.extend(part)
            conn.sendall(b'answer\n')
            tail, eof = read_eof(conn)
        status, out, err = done(proc, 'tcp-connect')
    finally: server.close()
    ok = bytes(data) == b'A\x00\xffB' and not tail and eof and status == 0 and out == b'received:answer\n' and not err
    record('tcp-connect-peer', data_base64=raw(bytes(data)), tail_base64=raw(tail), eof=eof, ok=ok, port=port)
    print('tcp-connect binary-reply-eof=%s' % yes(ok))

    # A bound, non-listening TCP socket reserves the port but refuses connects.
    refused = socket.socket(socket.AF_INET, socket.SOCK_STREAM); refused.bind(('127.0.0.1', 0))
    port = refused.getsockname()[1]
    script = r'''builtin bashpoll connect "127.0.0.1:$1" c -t 500; rc=$?
printf 'rc=%d\n' "$rc"
'''
    try: status, out, err = done(spawn(shell, script, port), 'tcp-refused')
    finally: refused.close()
    ok = status == 0 and out == b'rc=1\n' and b'Connection refused' in err and b'connect ' in err
    print('tcp-refused status-diagnostic=%s' % yes(ok))


def udp(shell):
    init(); port = free_port(socket.SOCK_DGRAM)
    script = r'''builtin bashpoll listen-udp "127.0.0.1:$1" u || exit 31
printf ready > udp.ready
builtin bashpoll recv-udp "$u" -t 2000 -o from -x > binary.hex || exit 32
printf '%s\n' "$from" > address
builtin bashpoll recv-udp "$u" -t 2000 > inline || exit 33
builtin bashpoll recv-udp "$u" -t 100 > timeout.out; rc=$?
printf 'timeout=%d\n' "$rc"
builtin bashpoll close "$u" || exit 34
'''
    proc = spawn(shell, script, port); wait_marker(proc, WORK / 'udp.ready')
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sender.bind(('127.0.0.1', 0))
    source = '127.0.0.1:%d' % sender.getsockname()[1]
    try:
        sender.sendto(b'\x00A\xff\n', ('127.0.0.1', port)); sender.sendto(b'plain-data', ('127.0.0.1', port))
        status, out, err = done(proc, 'udp-recv')
    finally: sender.close()
    hexdata = (WORK/'binary.hex').read_bytes() if (WORK/'binary.hex').exists() else b''
    address = (WORK/'address').read_bytes() if (WORK/'address').exists() else b''
    inline = (WORK/'inline').read_bytes() if (WORK/'inline').exists() else b''
    timeout_out = (WORK/'timeout.out').read_bytes() if (WORK/'timeout.out').exists() else b'!missing!'
    receive = (status == 0 and not err and hexdata == b'0041ff0a\n' and
               address == (source+'\n').encode() and inline == (source+'\n').encode()+b'plain-data')
    timeout = out == b'timeout=1\n' and timeout_out == b''
    record('udp-recv', source=source, hex_base64=raw(hexdata), address_base64=raw(address),
           inline_base64=raw(inline), timeout_base64=raw(timeout_out), receive=receive, timeout=timeout)
    print('udp-recv source-inline-hex=%s timeout=%s' % (yes(receive),yes(timeout)))

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); receiver.bind(('127.0.0.1', 0)); receiver.settimeout(2)
    port = receiver.getsockname()[1]
    script = r'''printf 'A\000\377B' > payload
: > empty
builtin bashpoll send-udp "127.0.0.1:$1" < payload || exit 41
builtin bashpoll send-udp "127.0.0.1:$1" < empty || exit 42
printf 'sent=2\n'
'''
    try:
        status, out, err = done(spawn(shell, script, port), 'udp-send')
        packets = [receiver.recvfrom(65536)[0], receiver.recvfrom(65536)[0]]
        receiver.settimeout(.15)
        try: packets.append(receiver.recvfrom(65536)[0])
        except socket.timeout: pass
    finally: receiver.close()
    ok = status == 0 and out == b'sent=2\n' and not err and packets == [b'A\x00\xffB', b'']
    record('udp-send', packets_base64=[raw(x) for x in packets], ok=ok)
    print('udp-send binary-empty-exact=%s' % yes(ok))


def unix(shell):
    init(); stale = WORK / 'stale.sock'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(str(stale))
    held = os.open(stale, os.O_PATH | os.O_CLOEXEC); s.close()
    old = os.fstat(held).st_ino
    script = r'''builtin bashpoll listen-unix stale.sock l || exit 51
printf ready > unix.ready
builtin bashpoll accept "$l" c || exit 52
IFS= read -r -t 3 msg <&"$c" || exit 53
printf 'unix:%s\n' "$msg" >&"$c" || exit 54
builtin bashpoll close "$c" || exit 55
builtin bashpoll close "$l" || exit 56
printf 'unix=ok\n'
'''
    proc = spawn(shell, script); wait_marker(proc, WORK/'unix.ready')
    new = stale.lstat().st_ino; replaced = stat.S_ISSOCK(stale.lstat().st_mode) and old != new
    os.close(held)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(5); peer.connect(str(stale)); peer.sendall(b'hello\n'); data, eof = read_eof(peer)
    status, out, err = done(proc, 'unix-stale')
    exchange = status == 0 and out == b'unix=ok\n' and not err and data == b'unix:hello\n' and eof
    removed = not stale.exists()
    record('unix-stale', old_inode=old, new_inode=new, replaced=replaced, response_base64=raw(data), eof=eof,
           path_after_close_exists=not removed)
    print('unix-stale replaced=%s accept-exchange=%s close-removes-path=%s' % (yes(replaced),yes(exchange),yes(removed)))
    blocked = WORK/'blocked'; blocked.write_bytes(b'keep-exact\n'); before = blocked.lstat()
    script = r'''builtin bashpoll listen-unix blocked x; rc=$?
printf 'rc=%d\n' "$rc"
'''
    status, out, err = done(spawn(shell, script), 'unix-refuse')
    after = blocked.lstat()
    intact = (status == 0 and out == b'rc=1\n' and b'refusing to unlink non-socket' in err and
              blocked.read_bytes() == b'keep-exact\n' and before.st_ino == after.st_ino and
              stat.S_ISREG(after.st_mode))
    record('unix-nonsocket', before_inode=before.st_ino, after_inode=after.st_ino, data_base64=raw(blocked.read_bytes()), ok=intact)
    print('unix-nonsocket refused-and-intact=%s' % yes(intact))


EVENTS = [(select.EPOLLIN, 'readable'), (select.EPOLLOUT, 'writable'), (select.EPOLLPRI, 'pri'),
          (select.EPOLLHUP, 'hup'), (select.EPOLLRDHUP, 'rdhup'), (select.EPOLLERR, 'error')]


def oracle(fds):
    ep = select.epoll()
    try:
        for fd in fds: ep.register(fd, select.EPOLLIN | select.EPOLLPRI | select.EPOLLRDHUP)
        events = ep.poll(1, maxevents=len(fds))
    finally: ep.close()
    return {fd: [name for bit,name in EVENTS if flags & bit] for fd,flags in events}


def observe_wait(shell, label, fds, required):
    expected = oracle(fds)
    actual_script = r'''builtin bashpoll wait -t 1000 "$@"'''
    proc = spawn(shell, actual_script, *fds, fds=fds)
    status, out, err = done(proc, 'wait-'+label)
    parsed = {}; parse_ok = True
    for line in out.splitlines():
        try:
            fd, names = line.decode('ascii').split(' ')
            fd = int(fd)
            if fd in parsed: parse_ok = False
            parsed[fd] = names.split(',')
        except (UnicodeError, ValueError): parse_ok = False
    supported = all(fd in expected and set(names).issubset(expected[fd]) for fd,names in required.items())
    ok = status == 0 and not err and parse_ok and parsed == expected and supported and len(parsed) == len(fds)
    record('wait-observation', label=label, fds=fds, kernel_oracle=expected, output=parsed,
           required=required, supported=supported, ok=ok)
    print('wait-%s kernel-and-labels=%s' % (label,yes(ok)))


def readiness(shell):
    init()
    a,b = socket.socketpair()
    try:
        b.shutdown(socket.SHUT_WR)
        observe_wait(shell, 'half-close', [a.fileno()], {a.fileno():['readable','rdhup']})
    finally: a.close(); b.close()
    server = listener(); client = socket.create_connection(server.getsockname(), timeout=5)
    peer,_ = server.accept(); server.close()
    try:
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii',1,0)); peer.close()
        if not wait_for(lambda: set(['hup','error']).issubset(oracle([client.fileno()]).get(client.fileno(),[])), 4):
            raise RuntimeError('kernel did not present TCP reset hup/error control')
        observe_wait(shell, 'reset', [client.fileno()], {client.fileno():['hup','error']})
    finally: client.close()
    master, slave = pty.openpty()
    try:
        os.write(slave,b'pty-data')
        observe_wait(shell, 'pty-readable', [master], {master:['readable']})
        assert os.read(master,128) == b'pty-data'
        os.close(slave); slave = -1
        observe_wait(shell, 'pty-hup', [master], {master:['hup']})
    finally:
        os.close(master)
        if slave >= 0: os.close(slave)
    a,b = socket.socketpair(); master,slave = pty.openpty()
    try:
        b.shutdown(socket.SHUT_WR); os.write(slave,b'mixed')
        observe_wait(shell, 'mixed', [a.fileno(),master], {a.fileno():['readable','rdhup'],master:['readable']})
    finally: a.close(); b.close(); os.close(master); os.close(slave)

def timeout_case(shell):
    init(); server = listener(); port = server.getsockname()[1]
    trace = HOME / 'poll-timeout-trace.jsonl'
    script = r'''builtin bashpoll connect "127.0.0.1:$1" c -t 500; rc=$?
printf 'rc=%d\n' "$rc"
'''
    argv = ['/usr/bin/python3', SEQ, '--notify', 'poll:1=1,2=500',
            '--reply', 'poll=0', '--log-args', 'poll=1,2', '--log', str(trace), '--',
            shell, '--noprofile', '--norc', '-c', script, 'fixture', str(port)]
    try:
        proc = subprocess.Popen(argv, cwd=WORK, env=dict(os.environ), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        CHILDREN.append(proc); status,out,err = done(proc, 'tcp-timeout', timeout=10)
    finally: server.close()
    events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
    injected = len(events) == 1 and events[0].get('syscall') == 'poll' and events[0].get('arg1') == 1 and events[0].get('arg2') == 500 and events[0].get('reply') == 'value:0'
    outcome = status == 0 and out == b'rc=1\n' and b'connect ' in err and b'Connection timed out' in err
    record('timeout', events=events, injected=injected, outcome=outcome)
    print('tcp-timeout injected-once=%s status-diagnostic=%s' % (yes(injected),yes(outcome)))


def timeout_control(control):
    # A readable pipe makes a real poll return one event. The filtered copy
    # must return zero, and the log must contain exactly that poll/reply.
    program = ('import os,select; r,w=os.pipe(); os.write(w,b"x"); '
               'p=select.poll(); p.register(r,select.POLLIN); print(len(p.poll(500)))')
    log = control/'poll-control.jsonl'
    plain = subprocess.run(['/usr/bin/python3','-c',program], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    fake = subprocess.run(['/usr/bin/python3',SEQ,'--notify','poll:1=1,2=500',
                           '--reply','poll=0','--log-args','poll=1,2','--log',str(log),'--',
                           '/usr/bin/python3','-c',program], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    record('timeout-control', plain_status=plain.returncode, plain_out=raw(plain.stdout), plain_err=raw(plain.stderr),
           filtered_status=fake.returncode, filtered_out=raw(fake.stdout), filtered_err=raw(fake.stderr), events=events)
    assert plain.returncode == 0 and plain.stdout == b'1\n' and not plain.stderr
    assert fake.returncode == 0 and fake.stdout == b'0\n' and not fake.stderr
    assert len(events) == 1 and events[0].get('arg1') == 1 and events[0].get('arg2') == 500 and events[0].get('reply') == 'value:0'


def setup(scenario):
    control = HOME / 'bashpoll-control'; control.mkdir(mode=0o700)
    if scenario in ('tcp', 'timeout'):
        server=listener()
        client=socket.create_connection(server.getsockname(), timeout=3)
        peer,_=server.accept()
        client.sendall(b'peer-control'); assert peer.recv(12) == b'peer-control'
        client.close(); assert peer.recv(1) == b''
        peer.close(); server.close()
    if scenario == 'timeout': timeout_control(control)
    if scenario == 'udp':
        recv = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); recv.bind(('127.0.0.1',0)); recv.settimeout(3)
        send = socket.socket(socket.AF_INET,socket.SOCK_DGRAM); send.bind(('127.0.0.1',0))
        try:
            send.sendto(b'\x00\xff',recv.getsockname()); send.sendto(b'',recv.getsockname())
            one,source = recv.recvfrom(64); two,source2=recv.recvfrom(64)
            assert one == b'\x00\xff' and two == b'' and source == source2 == send.getsockname()
        finally: recv.close(); send.close()
    if scenario == 'unix':
        path=control/'s'; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.bind(str(path)); s.close(); assert stat.S_ISSOCK(path.lstat().st_mode)
        hold=os.open(path,os.O_PATH|os.O_CLOEXEC); old=os.fstat(hold).st_ino
        path.unlink(); t=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        t.bind(str(path)); assert path.lstat().st_ino != old
        t.close(); os.close(hold); path.unlink()
    if scenario == 'readiness':
        a,b=socket.socketpair()
        try:
            assert oracle([a.fileno()]) == {}
            b.shutdown(socket.SHUT_WR)
            assert set(['readable','rdhup']).issubset(oracle([a.fileno()])[a.fileno()])
        finally: a.close(); b.close()
        master,slave=pty.openpty()
        try:
            os.write(slave,b'c'); assert 'readable' in oracle([master])[master]
            assert os.read(master,8) == b'c'; os.close(slave); slave=-1
            assert 'hup' in oracle([master])[master]
        finally:
            os.close(master)
            if slave >= 0: os.close(slave)
    record('setup-controls', scenario=scenario, result='verified')
    print('controls=verified')


SCENARIOS={'tcp':tcp, 'timeout':timeout_case, 'udp':udp, 'unix':unix, 'readiness':readiness}


if __name__ == '__main__':
    try:
        guard()
        if len(sys.argv) == 3 and sys.argv[1] == 'setup':
            assert sys.argv[2] in SCENARIOS
            setup(sys.argv[2])
        else:
            shell,scenario=sys.argv[1:]
            SCENARIOS[scenario](shell)
    except Exception as exc:
        try: record('exception', error=repr(exc), traceback=traceback.format_exc())
        except Exception: pass
        print('scenario-error=%s' % type(exc).__name__)
        sys.exit(1)
    finally:
        for child in CHILDREN:
            if child.poll() is None:
                child.kill(); child.wait(timeout=3)
                record('forced-cleanup', pid=child.pid)
