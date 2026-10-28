#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private mail protocol peers, executable only through disposable-VM fixtures.
Framing and queue expectations are informed by tests/sol-mail-check.py as data.
"""
import json
import os
import re
import select
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
import uuid

DIAG = Path(os.environ.get('HOME', '.')) / 'mail-trace.json'
MAX = 32768
SENDER = 'sender@fixture.invalid'
RCPTS = ['one@fixture.invalid', 'two@fixture.invalid']
MSG = b'Subject: fixture\n\n.one\n..two\nlast\n'
SEQUENCE = '/opt/bashos-parity/harness/helpers/system-sequence.py'
SIGNAL_CALLS = ('kill', 'tkill', 'tgkill', 'pidfd_send_signal', 'rt_sigqueueinfo', 'rt_tgsigqueueinfo')
SIGNAL_PROBE = r'''import ctypes, errno, json, os, threading
libc = ctypes.CDLL(None, use_errno=True)
sec = ctypes.CDLL('libseccomp.so.2')
sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
pid, tid = os.getpid(), threading.get_native_id()
calls = [('kill', (pid, 0)), ('tkill', (tid, 0)), ('tgkill', (pid, tid, 0)),
         ('pidfd_send_signal', (-1, 0, 0, 0)), ('rt_sigqueueinfo', (pid, 0, 0)),
         ('rt_tgsigqueueinfo', (pid, tid, 0, 0))]
results = []
for name, args in calls:
    number = sec.seccomp_syscall_resolve_name(name.encode())
    ctypes.set_errno(0)
    value = libc.syscall(number, *args)
    results.append({'name': name, 'number': number, 'args': args,
                    'result': value, 'errno': ctypes.get_errno()})
print(json.dumps({'pid': pid, 'tid': tid, 'calls': results}), flush=True)
raise SystemExit(0 if all(x['number'] >= 0 and x['result'] == -1 and x['errno'] == errno.EPERM for x in results) else 1)
'''


def check(ok, why):
    if not ok: raise AssertionError(why)


def command(shell, script, data=b'', timeout=5, pass_fds=()):
    p = subprocess.run([shell, '--noprofile', '--norc', '-c', script], input=data,
                       capture_output=True, timeout=timeout, pass_fds=pass_fds)
    return {'status': p.returncode, 'stdout': p.stdout[:MAX], 'stderr': p.stderr[:MAX]}


def log_result(result):
    return {'status': result['status'], 'stdout_hex': result['stdout'].hex(),
            'stderr': result['stderr'].decode('utf8', 'replace')}


def signal_observer(program, log):
    rules = []
    for name in SIGNAL_CALLS:
        rules += ['--notify', name, '--reply', name + '=EPERM',
                  '--log-args', name + '=0,1,2,3']
    return [sys.executable, SEQUENCE] + rules + ['--log', str(log), '--'] + program


def signal_probe(trace):
    log = Path(os.environ['HOME']) / 'signal-control.jsonl'
    process = subprocess.run(signal_observer([sys.executable, '-c', SIGNAL_PROBE], log),
                             capture_output=True, timeout=8)
    raw = log.read_bytes()[:MAX] if log.exists() else b''
    rows = [json.loads(line) for line in raw.splitlines()]
    detail = {'status': process.returncode, 'stdout': process.stdout[:MAX].decode('utf8', 'replace'),
              'stderr': process.stderr[:MAX].decode('utf8', 'replace'), 'records': rows,
              'log_hex': raw.hex()}
    trace['signal_control'] = detail
    check(process.returncode == 0 and len(rows) == len(SIGNAL_CALLS), 'signal observer positive control failed')
    check([r.get('syscall') for r in rows] == list(SIGNAL_CALLS) and
          all(r.get('reply') == 'errno:1' for r in rows), 'signal observer did not intercept every probe')
    child = json.loads(detail['stdout'])
    check(rows[0].get('arg0') == child['pid'] and rows[0].get('arg1') == 0,
          'signal observer recorded the wrong target or signal')


def frame(message):
    def field(name, data): return name + b' ' + str(len(data)).encode() + b'\n' + data
    return b'BASHMAIL1\n' + field(b'FROM', SENDER.encode()) + b''.join(field(b'RCPT', x.encode()) for x in RCPTS) + field(b'DATA', message) + b'END\n'


def split_message(message):
    m = re.search(b'\r\n\r\n|\n\n', message)
    if not m: return message, b''
    return message[:m.start() + len(m.group()) // 2], message[m.end():]


def entry(queue, subdir, qid, message, sender=SENDER, rcpts=RCPTS):
    check(re.fullmatch(r'[0-9A-F]{15,23}', qid) is not None, 'invalid queue id')
    path = Path(queue) / subdir / qid
    check(path.is_dir(), 'queued entry is missing')
    check({p.name for p in path.iterdir()} == {'headers', 'body', 'envelope', 'meta'}, 'queued members differ')
    header, body = split_message(message)
    check((path/'headers').read_bytes() == header and (path/'body').read_bytes() == body, 'queued message differs')
    expected_env = ('from ' + sender + '\n' + ''.join('rcpt ' + r + '\n' for r in rcpts)).encode()
    check((path/'envelope').read_bytes() == expected_env, 'queue envelope mismatch')
    meta = dict(line.split('=', 1) for line in (path/'meta').read_text().splitlines())
    check(meta.get('qid') == qid and meta.get('sender') == sender and meta.get('nrcpt') == str(len(rcpts)), 'queue metadata mismatch')
    return meta


def control():
    message = b'Subject: fixture\n\n.a\x00b\n'
    wire = frame(message)
    trace = {'scenario': 'control', 'message_hex': message.hex(), 'frame_hex': wire.hex()}
    check(wire.startswith(b'BASHMAIL1\nFROM 22\nsender@fixture.invalid') and wire.endswith(message+b'END\n'), 'framing control failed')
    check(frame(message + b'x') != wire, 'framing negative control failed')
    s, r = socket.socketpair()
    try:
        s.sendall(b'abc'); s.shutdown(socket.SHUT_WR)
        first, last = r.recv(3), r.recv(1)
        trace['socket_first_hex'] = first.hex(); trace['socket_eof_hex'] = last.hex()
        check(first == b'abc' and last == b'', 'EOF socket control failed')
    finally: s.close(); r.close()
    DIAG.write_text(json.dumps(trace, indent=2) + '\n')
    print('mail-control=ok')


def start_daemon(shell, script, prefix):
    p = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        ready, _, _ = select.select([p.stdout], [], [], 4)
        check(ready, 'daemon did not print readiness')
        line = p.stdout.readline(MAX)
        check(line.startswith(prefix), 'unexpected daemon readiness: ' + repr(line))
        return p, line
    except BaseException:
        if p.poll() is None: p.kill()
        p.communicate(timeout=2)
        raise


def stop_daemon(proc, trace):
    if proc.poll() is None: proc.send_signal(signal.SIGTERM)
    out, err = proc.communicate(timeout=4)
    trace['daemon'] = {'status': proc.returncode, 'stdout_hex': out[:MAX].hex(), 'stderr': err[:MAX].decode('utf8', 'replace')}
    check(proc.returncode == 0, 'daemon did not exit cleanly on SIGTERM')


def exchange(path, payload, fragment=False):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(3); s.connect(str(path))
        if fragment:
            for i in range(0, len(payload), 3): s.sendall(payload[i:i+3])
        else: s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        data = bytearray()
        while b'\n' not in data and len(data) < 4096:
            chunk = s.recv(512)
            if not chunk: break
            data.extend(chunk)
        return bytes(data)


def unix_server(shell, trace):
    proc = None
    try:
        proc, ready = start_daemon(shell, 'mail serve --socket submit.sock --queue queue', b'mail: serving submissions on ')
        trace['ready'] = ready.decode('utf8', 'replace')
        check(Path('submit.sock').is_socket(), 'submission socket not created')
        messages = [b'Subject: direct\n\nhello\n', b'Subject: fragment\n\na\x00b\n']
        replies = []; trace['unix_frames'] = []
        for i, message in enumerate(messages):
            reply = exchange('submit.sock', frame(message), fragment=bool(i)); replies.append(reply.decode('ascii', 'replace'))
            trace['unix_frames'].append({'frame_hex': frame(message).hex(), 'reply_hex': reply.hex(),
                                         'fragment_size': 3 if i else None})
            m = re.fullmatch(rb'OK ([0-9A-F]{15,23})\n', reply); check(m is not None, 'valid frame not acknowledged')
            entry('queue', 'active', m.group(1).decode(), message)
        before = {p.name for p in Path('queue/active').iterdir()}
        trace['queue_before_bad_frames'] = sorted(before)
        bads = [b'NOTMAIL\n', b'BASHMAIL1\nFROM -1\n', b'BASHMAIL1\nFROM 3\na']
        for bad in bads:
            reply = exchange('submit.sock', bad); replies.append(reply.decode('ascii', 'replace'))
            trace['unix_frames'].append({'frame_hex': bad.hex(), 'reply_hex': reply.hex(),
                                         'queue_after': sorted(p.name for p in Path('queue/active').iterdir())})
            check(not reply or re.fullmatch(rb'ERR \d+ [^\n]*\n', reply) is not None, 'malformed frame not rejected')
            check({p.name for p in Path('queue/active').iterdir()} == before, 'malformed frame enqueued data')
        trace['replies'] = replies
    finally:
        if proc is not None: stop_daemon(proc, trace)
    check(not Path('submit.sock').exists(), 'daemon did not unlink socket')


def unix_client(shell, trace):
    path = Path('oracle.sock'); server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path)); server.listen(1); server.settimeout(4)
    expected = frame(b'Subject: input\n\nhi\x00bye\n'); observation = {}
    def worker():
        try:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(3); buf = bytearray()
                while len(buf) < len(expected):
                    b = conn.recv(min(4096, len(expected)-len(buf)))
                    if not b: break
                    buf.extend(b)
                observation['wire_hex'] = bytes(buf).hex()
                check(bytes(buf) == expected, 'submit frame differs')
                conn.settimeout(.15)
                try: extra = conn.recv(1, socket.MSG_PEEK)
                except socket.timeout: extra = b''
                check(not extra, 'unexpected extra frame bytes')
                conn.sendall(b'OK ABCDEF123456789\n')
        except Exception as exc: observation['error'] = type(exc).__name__ + ': ' + str(exc)
        finally: server.close()
    th = threading.Thread(target=worker, daemon=True); th.start()
    try: result = command(shell, 'mail submit --socket oracle.sock -f '+shlex.quote(SENDER)+' -- '+shlex.join(RCPTS), b'Subject: input\n\nhi\x00bye\n')
    finally: th.join(5); trace['peer'] = observation
    trace['result'] = log_result(result)
    check(not th.is_alive() and 'error' not in observation, 'submission oracle failed')
    check(result['status'] == 0 and result['stdout'] == b'ABCDEF123456789\n' and not result['stderr'], 'submit reply handling mismatch')


def unix_absent(shell, trace):
    result = command(shell, 'mail submit --socket missing.sock -- one@fixture.invalid', b'x')
    trace['result'] = log_result(result)
    check(result['status'] == 75 and bool(result['stderr']), 'absent submission socket did not return 75')


def smtp_inbound(shell, trace):
    reserve = socket.socket(); reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]; reserve.close()
    proc = None; replies = []
    try:
        script = 'mail smtpd --bind 127.0.0.1:%d --queue queue --user "" --ehlo fixture.invalid' % port
        proc, ready = start_daemon(shell, script, b'mail: smtpd listening on ')
        trace['ready'] = ready.decode('ascii', 'replace')
        check(ready == ('mail: smtpd listening on 127.0.0.1:%d (queue queue)\n' % port).encode(), 'listening line mismatch')
        with socket.create_connection(('127.0.0.1', port), timeout=3) as conn:
            conn.settimeout(3); f = conn.makefile('rb')
            def response(code, multi=False):
                line = f.readline(4096); replies.append(line.decode('ascii', 'replace'))
                check(line.startswith(str(code).encode()) and line.endswith(b'\r\n'), 'SMTP response code or framing mismatch')
                if multi:
                    check(line[3:4] == b'-', 'expected multiline EHLO')
                    line = f.readline(4096); replies.append(line.decode('ascii', 'replace'))
                    check(line.startswith(b'250 '), 'bad multiline EHLO terminator')
                return line
            def send(line, code, multi=False): conn.sendall(line + b'\r\n'); return response(code, multi)
            response(220); send(b'DATA', 554); send(b'BOGUS', 500); send(b'NOOP', 250)
            send(b'EHLO peer.fixture', 250, True); send(b'MAIL FROM:<sender@fixture.invalid>', 250)
            send(b'RCPT TO:<one@fixture.invalid>', 250); send(b'RSET', 250)
            send(b'MAIL FROM:<sender@fixture.invalid>', 250); send(b'RCPT TO:<one@fixture.invalid>', 250)
            send(b'DATA', 354); conn.sendall(b'Subject: inbound\r\n\r\n..one\r\n...two\r\nlast\r\n.\r\n')
            line = response(250); m = re.search(rb'queued as ([0-9A-F]{15,23})\r\n$', line); check(m is not None, 'queue id missing')
            send(b'QUIT', 221); f.close()
        qid = m.group(1).decode()
        meta = entry('queue', 'incoming', qid, b'Subject: inbound\n\n.one\n..two\nlast\n', rcpts=RCPTS[:1])
        qdir = Path('queue/incoming') / qid
        trace['inbound_queue'] = {'qid': qid, 'meta': meta,
                                  'members_hex': {p.name: p.read_bytes()[:MAX].hex()
                                                  for p in qdir.iterdir() if p.is_file()}}
        check(meta.get('source') == 'inbound' and meta.get('client_ip') == '127.0.0.1' and meta.get('helo') == 'peer.fixture' and meta.get('mail_from') == SENDER, 'inbound metadata differs')
    finally:
        trace['replies'] = replies
        if proc is not None: stop_daemon(proc, trace)


def smtp_outbound(shell, scenario, trace):
    statuses = {'smtp-success':[250,250], 'smtp-mixed-temp':[250,450], 'smtp-mixed-perm':[250,550],
                'smtp-all-temp':[450,550], 'smtp-all-perm':[550,550]}[scenario]
    q = Path('queue/active/ABCDEF123456789'); q.mkdir(parents=True)
    (q/'headers').write_bytes(b'Subject: fixture\n'); (q/'body').write_bytes(b'.one\n..two\nlast\n')
    (q/'meta').write_text('separator=1\n'); (q/'envelope').write_text('fixture envelope\n')
    def snapshot():
        paths = [q] + sorted(q.iterdir())
        return {p.name: {'contents': p.read_bytes().hex() if p.is_file() else None,
                         'mode': p.stat().st_mode, 'uid': p.stat().st_uid,
                         'gid': p.stat().st_gid, 'mtime_ns': p.stat().st_mtime_ns}
                for p in paths}
    before = snapshot()
    trace['queue_snapshot_before'] = before
    client, peer = socket.socketpair(); peer.settimeout(4); observed = {'commands': [], 'data_hex': ''}
    def sink():
        try:
            with peer:
                f = peer.makefile('rb'); peer.sendall(b'220 fixture ESMTP\r\n')
                def line(expected, reply):
                    actual = f.readline(4096); observed['commands'].append(actual.decode('ascii', 'replace'))
                    check(actual == expected, 'SMTP command mismatch: ' + repr(actual))
                    peer.sendall(reply)
                line(b'EHLO client.fixture.invalid\r\n', b'250 fixture\r\n')
                line(b'MAIL FROM:<sender@fixture.invalid>\r\n', b'250 sender\r\n')
                for address, code in zip(RCPTS, statuses):
                    line(('RCPT TO:<'+address+'>\r\n').encode(), ('%d recipient\r\n' % code).encode())
                if any(code == 250 for code in statuses):
                    line(b'DATA\r\n', b'354 send data\r\n'); chunks=[]
                    while True:
                        data = f.readline(4096); check(bool(data) and data.endswith(b'\r\n'), 'invalid DATA line')
                        chunks.append(data)
                        if data == b'.\r\n': break
                        check(sum(map(len,chunks)) < MAX, 'SMTP body exceeds capture bound')
                    observed['data_hex'] = b''.join(chunks).hex()
                    peer.sendall(b'250 queued\r\n'); line(b'QUIT\r\n', b'221 goodbye\r\n')
                f.close()
        except Exception as exc: observed['error'] = type(exc).__name__ + ': ' + str(exc)
    th = threading.Thread(target=sink, daemon=True); th.start()
    script = ('mail deliver-fd --queue queue --qid ABCDEF123456789 --from ' + shlex.quote(SENDER) +
              ' --ehlo client.fixture.invalid --tls off --timeout 1000 --fd %d -- ' % client.fileno() + shlex.join(RCPTS))
    proc = None
    try:
        proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(client.fileno(),))
        client.close(); out, err = proc.communicate(timeout=5)
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill(); proc.communicate(timeout=2)
        client.close(); th.join(5); trace['peer'] = observed
    trace['result'] = {'status': proc.returncode, 'stdout_hex': out[:MAX].hex(), 'stderr': err[:MAX].decode('utf8', 'replace')}
    check(not th.is_alive() and 'error' not in observed, 'SMTP peer failure')
    wanted = 0 if statuses == [250,250] else 75 if 450 in statuses else 69
    output = b''.join(('delivered '+addr+'\n').encode() for addr, code in zip(RCPTS, statuses) if code == 250)
    check(proc.returncode == wanted and out == output, 'recipient outcome/status mismatch')
    if any(code == 250 for code in statuses):
        expected = b'Subject: fixture\r\n\r\n..one\r\n...two\r\nlast\r\n.\r\n'
        check(bytes.fromhex(observed['data_hex']) == expected, 'SMTP CRLF or dot-stuffed data mismatch')
    after = snapshot()
    trace['queue_snapshot_after'] = after
    check(after == before, 'queue entry changed during delivery')


def queue_flush(shell, trace):
    signal_probe(trace)
    child = subprocess.Popen([sys.executable, '-c',
        'import signal,time; n=[0]; signal.signal(signal.SIGUSR1, lambda s,f: n.__setitem__(0,n[0]+1)); print("READY",flush=True); '
        'end=time.monotonic()+5\nwhile n[0]==0 and time.monotonic()<end: time.sleep(.02)\ntime.sleep(.25)\nprint("COUNT",n[0],flush=True)'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    records = []
    try:
        ready, _, _ = select.select([child.stdout], [], [], 3); check(ready and child.stdout.readline() == b'READY\n', 'owned runner not ready')
        r = command(shell, 'mail queue-flush --pidfile absent.pid'); records.append(log_result(r))
        check(r['status'] == 0 and r['stdout'] == b'queue-flush: no runner (pidfile absent.pid absent)\n', 'absent pidfile behavior mismatch')
        trace['invalid_signal_observations'] = []
        for index, text in enumerate(('nonnumeric', '0', '-2')):
            Path('runner.pid').write_text(text+'\n')
            log = Path(os.environ['HOME']) / ('signal-invalid-%d.jsonl' % index)
            program = [shell, '--noprofile', '--norc', '-c', 'mail queue-flush --pidfile runner.pid']
            filtered = subprocess.run(signal_observer(program, log), capture_output=True, timeout=8)
            raw = log.read_bytes()[:MAX] if log.exists() else b''
            rows = [json.loads(line) for line in raw.splitlines()]
            r = {'status': filtered.returncode, 'stdout': filtered.stdout[:MAX], 'stderr': filtered.stderr[:MAX]}
            records.append(log_result(r))
            trace['invalid_signal_observations'].append({'pidfile': text, 'result': log_result(r),
                                                          'records': rows, 'log_hex': raw.hex()})
            check(r['status'] == 1 and b'bad pidfile' in r['stderr'] and child.poll() is None,
                  'invalid pidfile behavior mismatch')
            check(not rows, 'invalid pidfile attempted a signal syscall')
        Path('runner.pid').write_text(str(child.pid)+'\n'); r=command(shell, 'mail queue-flush --pidfile runner.pid'); records.append(log_result(r))
        check(r['status'] == 0 and r['stdout'] == ('queue-flush: woke runner pid %d\n' % child.pid).encode(), 'runner wakeup status/output mismatch')
        out, err = child.communicate(timeout=4)
        check(child.returncode == 0 and out == b'COUNT 1\n', 'runner did not receive exactly one SIGUSR1')
        gone = subprocess.Popen([sys.executable, '-c', 'pass']); stale = gone.pid; gone.wait(timeout=3)
        check(not Path('/proc/%d' % stale).exists(), 'stale owned child still exists')
        Path('runner.pid').write_text(str(stale)+'\n'); r=command(shell, 'mail queue-flush --pidfile runner.pid'); records.append(log_result(r))
        check(r['status'] == 1 and b'signal pid' in r['stderr'], 'stale pid was not reported')
        trace['runner_count'] = out.decode(); trace['stale_pid'] = stale
    finally:
        trace['observations'] = records
        if child.poll() is None: child.kill(); child.communicate(timeout=2)


def main(shell, scenario):
    trace = {'scenario': scenario}
    try:
        if scenario == 'unix-server': unix_server(shell, trace)
        elif scenario == 'unix-client': unix_client(shell, trace)
        elif scenario == 'unix-absent': unix_absent(shell, trace)
        elif scenario == 'smtp-inbound': smtp_inbound(shell, trace)
        elif scenario.startswith('smtp-'): smtp_outbound(shell, scenario, trace)
        elif scenario == 'queue-flush': queue_flush(shell, trace)
        elif scenario == 'signal-control': signal_probe(trace)
        else: raise ValueError('unknown scenario')
        print('mail-' + scenario + '=ok')
    except Exception as exc:
        trace['error'] = type(exc).__name__ + ': ' + str(exc)
        print('mail fixture failed: ' + trace['error'], file=sys.stderr)
        raise SystemExit(1)
    finally: DIAG.write_text(json.dumps(trace, indent=2) + '\n')


def require_guest():
    """Fail closed before helper behavior; the guest evaluator checks UUID equality."""
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        parsed = uuid.UUID(marker)
        if str(parsed) != marker.lower():
            raise ValueError('non-canonical VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
        if os.getuid() != 2000 or os.geteuid() != 2000:
            raise ValueError('unexpected guest uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('unexpected guest scratch directory')
    except (OSError, ValueError) as exc:
        raise SystemExit('disposable-VM guard refused helper: ' + str(exc))


if __name__ == '__main__':
    require_guest()
    if len(sys.argv) == 2 and sys.argv[1] == 'control': control()
    elif len(sys.argv) == 3: main(sys.argv[1], sys.argv[2])
    else: raise SystemExit('usage: helper control | helper SHELL SCENARIO')
