#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private mail protocol peers, executable only through disposable-VM fixtures.
Framing and queue expectations are informed by tests/sol-mail-check.py as data.
"""
import json
import ctypes
import struct
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



def send_piece(conn, data, rows, label):
    """Record each attempted local send and its returned count, not peer receipt."""
    offset=0
    while offset<len(data):
        part=data[offset:]
        row={'label':label,'attempt_hex':part.hex(),'started_ns':time.monotonic_ns(),
             'accepted':0,'error':None}
        rows.append(row)
        try:
            n=conn.send(part); row['accepted']=n
            if n<=0: raise OSError('zero-length send')
            offset+=n
        except OSError as exc:
            row['error']=type(exc).__name__+': '+str(exc); raise
        finally: row['ended_ns']=time.monotonic_ns()


def capture_control(trace):
    class Fake:
        def __init__(self,fail): self.fail=fail; self.calls=0
        def send(self,data):
            self.calls+=1
            if self.fail and self.calls==2: raise BrokenPipeError('controlled failure')
            return min(len(data),2)
    good=[]; send_piece(Fake(False),b'abcde',good,'partial')
    bad=[]
    try: send_piece(Fake(True),b'abcde',bad,'error')
    except BrokenPipeError: pass
    else: raise AssertionError('send error control did not fail')
    a,b=socket.socketpair(); actual=[]
    try: send_piece(a,b'wire',actual,'real'); received=b.recv(4)
    finally: a.close(); b.close()
    trace['capture_control']={'short_writes':good,'error_writes':bad,'socket_writes':actual,'received_hex':received.hex()}
    check([r['accepted'] for r in good]==[2,2,1] and [r['accepted'] for r in bad]==[2,0]
          and bad[-1]['error'].startswith('BrokenPipeError') and received==b'wire', 'capture control failed')


def ptrace(op,pid,addr=0,data=0):
    libc=ctypes.CDLL(None,use_errno=True); libc.ptrace.restype=ctypes.c_long
    ctypes.set_errno(0)
    value=libc.ptrace(ctypes.c_ulong(op),ctypes.c_ulong(pid),ctypes.c_void_p(addr),ctypes.c_void_p(data))
    err=ctypes.get_errno()
    if value==-1 and err: raise OSError(err,os.strerror(err))
    return value


def identity(pid):
    status=Path('/proc/%d/status'%pid).read_text()
    fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines()
            if line.startswith(('Name:','State:','Pid:','PPid:','TracerPid:','Uid:'))}
    stat=Path('/proc/%d/stat'%pid).read_text().rsplit(')',1)[1].split()
    fields['starttime_ticks']=int(stat[19])
    return fields


def wait_stop(pid,seconds):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        p,status=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
        if p: return status
        time.sleep(.01)
    raise TimeoutError('owned tracee did not reach wait state')


def stop_daemon(proc, trace):
    sig={'target_pid':proc.pid,'signal':int(signal.SIGTERM),'sender_pid':os.getpid(),
         'send_attempted':False,'send_result':None,'delivery_observed':False,'reinject_result':None}
    trace['signal']=sig
    attached=False
    try:
        check(proc.poll() is None,'owned daemon exited before signal')
        sig['before_attach']=identity(proc.pid)
        check(sig['before_attach']['PPid']==str(os.getpid()),'target is not owned child')
        ptrace(16,proc.pid); attached=True  # PTRACE_ATTACH, parent-owned child only
        status=wait_stop(proc.pid,3)
        check(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'ptrace attach stop missing')
        sig['attach_wait_status']=status; sig['attached_identity']=identity(proc.pid)
        check(sig['attached_identity']['starttime_ticks']==sig['before_attach']['starttime_ticks'], 'child identity changed')
        ptrace(7,proc.pid)  # PTRACE_CONT
        sig['send_attempted']=True; sig['send_started_ns']=time.monotonic_ns()
        try: os.kill(proc.pid,signal.SIGTERM); sig['send_result']='ok'
        except OSError as exc: sig['send_result']=type(exc).__name__+': '+str(exc); raise
        finally: sig['send_ended_ns']=time.monotonic_ns()
        status=wait_stop(proc.pid,4); sig['delivery_wait_status']=status
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            proc.returncode=os.waitstatus_to_exitcode(status); raise RuntimeError('child exited without observed delivery stop')
        check(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGTERM,'unexpected tracee stop')
        info=ctypes.create_string_buffer(128)
        ptrace(0x4202,proc.pid,0,ctypes.addressof(info))  # PTRACE_GETSIGINFO
        signo,si_errno,si_code=struct.unpack_from('=iii',info.raw,0)
        sender,uid=struct.unpack_from('=iI',info.raw,16)
        sig['siginfo']={'signo':signo,'errno':si_errno,'code':si_code,'sender_pid':sender,'sender_uid':uid,
                        'raw_hex':info.raw.hex()}
        check(signo==int(signal.SIGTERM) and si_code==0 and sender==os.getpid(), 'SIGTERM siginfo mismatch')
        sig['delivery_observed']=True
        ptrace(7,proc.pid,0,int(signal.SIGTERM)); sig['reinject_result']='ok'
        terminal=wait_stop(proc.pid,4); sig['terminal_wait_status']=terminal
        check(os.WIFEXITED(terminal) or os.WIFSIGNALED(terminal),'unexpected post-signal tracee stop')
        proc.returncode=os.waitstatus_to_exitcode(terminal); attached=False
        out,err=proc.communicate(timeout=2)
        sig['terminal']={'returncode':proc.returncode,'stdout_hex':out[:MAX].hex(),'stderr_hex':err[:MAX].hex()}
        trace['daemon']={'status':proc.returncode,'stdout_hex':out[:MAX].hex(),'stderr':err[:MAX].decode('utf8','replace')}
        check(proc.returncode==0,'daemon did not exit cleanly on SIGTERM')
    except BaseException as exc:
        sig['observer_error']=type(exc).__name__+': '+str(exc)
        if attached:
            try: ptrace(17,proc.pid,0,0)  # PTRACE_DETACH
            except OSError: pass
        if proc.returncode is None:
            try: proc.kill()
            except ProcessLookupError: pass
            try:
                out,err=proc.communicate(timeout=3)
                sig['cleanup_terminal']={'returncode':proc.returncode,'stdout_hex':out[:MAX].hex(),'stderr_hex':err[:MAX].hex()}
            except (ChildProcessError,subprocess.TimeoutExpired): pass
        raise


def signal_delivery_control(trace):
    code=('import signal,time\n'
          'def handler(sig,frame): print("HANDLED",flush=True); raise SystemExit(0)\n'
          'signal.signal(signal.SIGTERM,handler); print("READY",flush=True)\n'
          'while True: time.sleep(.05)\n')
    child=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    try:
        ready,_,_=select.select([child.stdout],[],[],3)
        check(ready and child.stdout.readline()==b'READY\n','signal control child not ready')
        observation={}; trace['signal_delivery_control']=observation
        stop_daemon(child,observation)
        check(bytes.fromhex(observation['daemon']['stdout_hex'])==b'HANDLED\n', 'positive signal handler control missing')
    finally:
        if child.returncode is None:
            child.kill(); child.communicate(timeout=2)

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


def exchange(path,payload,fragment=False,observation=None):
    observation=observation if observation is not None else {}
    observation.update({'payload_hex':payload.hex(),'writes':[],'reads':[]})
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3); conn.connect(str(path))
        chunks=[payload[i:i+3] for i in range(0,len(payload),3)] if fragment else [payload]
        for i,part in enumerate(chunks): send_piece(conn,part,observation['writes'],'fragment-'+str(i))
        conn.shutdown(socket.SHUT_WR)
        data=bytearray()
        while b'\n' not in data and len(data)<4096:
            chunk=conn.recv(512); observation['reads'].append({'bytes_hex':chunk.hex(),'time_ns':time.monotonic_ns()})
            if not chunk: break
            data.extend(chunk)
        observation['reply_hex']=bytes(data).hex()
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
            event={'frame_hex':frame(message).hex(),'fragment_size':3 if i else None}; trace['unix_frames'].append(event)
            reply = exchange('submit.sock', frame(message), fragment=bool(i),observation=event); replies.append(reply.decode('ascii', 'replace'))
            m = re.fullmatch(rb'OK ([0-9A-F]{15,23})\n', reply); check(m is not None, 'valid frame not acknowledged')
            qdir=Path('queue/active')/m.group(1).decode()
            event['queue_members_hex']={p.name:p.read_bytes()[:MAX].hex() for p in qdir.iterdir() if p.is_file()}
            entry('queue', 'active', m.group(1).decode(), message)
        before = {p.name for p in Path('queue/active').iterdir()}
        trace['queue_before_bad_frames'] = sorted(before)
        bads = [b'NOTMAIL\n', b'BASHMAIL1\nFROM -1\n', b'BASHMAIL1\nFROM 3\na']
        for bad in bads:
            event={'frame_hex':bad.hex()}; trace['unix_frames'].append(event)
            reply = exchange('submit.sock', bad,observation=event); replies.append(reply.decode('ascii', 'replace'))
            event['queue_after']=sorted(p.name for p in Path('queue/active').iterdir())
            check(not reply or re.fullmatch(rb'ERR \d+ [^\n]*\n', reply) is not None, 'malformed frame not rejected')
            check({p.name for p in Path('queue/active').iterdir()} == before, 'malformed frame enqueued data')
        trace['replies'] = replies
    finally:
        try:
            if proc is not None: stop_daemon(proc, trace)
        finally: trace['socket_after_exit_exists']=Path('submit.sock').exists()
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
                observation['reply_hex']=b'OK ABCDEF123456789\n'.hex(); observation['reply_writes']=[]
                send_piece(conn,b'OK ABCDEF123456789\n',observation['reply_writes'],'unix-reply')
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
    proc = None; replies = []; trace['smtp_events']=[]
    try:
        script = 'mail smtpd --bind 127.0.0.1:%d --queue queue --user "" --ehlo fixture.invalid' % port
        proc, ready = start_daemon(shell, script, b'mail: smtpd listening on ')
        trace['ready'] = ready.decode('ascii', 'replace')
        check(ready == ('mail: smtpd listening on 127.0.0.1:%d (queue queue)\n' % port).encode(), 'listening line mismatch')
        with socket.create_connection(('127.0.0.1', port), timeout=3) as conn:
            conn.settimeout(3); f = conn.makefile('rb')
            def response(code, multi=False, event=None):
                if event is None:
                    event={'label':'greeting','writes':[]}; trace['smtp_events'].append(event)
                event['reply_lines_hex']=[]
                line = f.readline(4096); event['reply_lines_hex'].append(line.hex()); replies.append(line.decode('ascii', 'replace'))
                check(line.startswith(str(code).encode()) and line.endswith(b'\r\n'), 'SMTP response code or framing mismatch')
                if multi:
                    check(line[3:4] == b'-', 'expected multiline EHLO')
                    line = f.readline(4096); event['reply_lines_hex'].append(line.hex()); replies.append(line.decode('ascii', 'replace'))
                    check(line.startswith(b'250 '), 'bad multiline EHLO terminator')
                return line
            def send(line, code, multi=False):
                event={'label':'command','bytes_hex':(line+b'\r\n').hex(),'writes':[]}; trace['smtp_events'].append(event)
                send_piece(conn,line+b'\r\n',event['writes'],'command')
                return response(code,multi,event)
            response(220); send(b'DATA', 554); send(b'BOGUS', 500); send(b'NOOP', 250)
            send(b'EHLO peer.fixture', 250, True); send(b'MAIL FROM:<sender@fixture.invalid>', 250)
            send(b'RCPT TO:<one@fixture.invalid>', 250); send(b'RSET', 250)
            send(b'MAIL FROM:<sender@fixture.invalid>', 250); send(b'RCPT TO:<one@fixture.invalid>', 250)
            send(b'DATA', 354)
            wire=b'Subject: inbound\r\n\r\n..one\r\n...two\r\nlast\r\n.\r\n'
            data_event={'label':'DATA','bytes_hex':wire.hex(),'writes':[]}; trace['smtp_events'].append(data_event)
            send_piece(conn,wire,data_event['writes'],'DATA')
            line = response(250,event=data_event); m = re.search(rb'queued as ([0-9A-F]{15,23})\r\n$', line); check(m is not None, 'queue id missing')
            send(b'QUIT', 221); f.close()
        qid = m.group(1).decode()
        qdir = Path('queue/incoming') / qid
        trace['queue_raw_before_checks']={p.name:p.read_bytes()[:MAX].hex() for p in qdir.iterdir() if p.is_file()}
        wire=bytes.fromhex(data_event['bytes_hex'])
        check(wire.endswith(b'.\r\n'),'missing DATA terminator')
        lines=wire[:-3].split(b'\r\n')
        decoded=b'\n'.join(line[1:] if line.startswith(b'..') else line for line in lines)
        trace['independent_unstuffed_lf_hex']=decoded.hex()
        check(decoded==b'Subject: inbound\n\n.one\n..two\nlast\n','wire decode control mismatch')
        meta = entry('queue', 'incoming', qid, decoded, rcpts=RCPTS[:1])
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
        if not q.exists(): return {'queue_missing':True}
        paths = [q] + sorted(q.iterdir())
        return {p.name: {'contents': p.read_bytes().hex() if p.is_file() else None,
                         'mode': p.stat().st_mode, 'uid': p.stat().st_uid,
                         'gid': p.stat().st_gid, 'mtime_ns': p.stat().st_mtime_ns}
                for p in paths}
    before = snapshot()
    trace['queue_snapshot_before'] = before
    client, peer = socket.socketpair(); peer.settimeout(4); observed = {'commands': [], 'commands_hex': [], 'data_hex': '', 'data_lines_hex': [], 'responses': []}
    def sink():
        try:
            with peer:
                f = peer.makefile('rb')
                def reply(label,data):
                    event={'after':label,'bytes_hex':data.hex(),'writes':[]}; observed['responses'].append(event)
                    send_piece(peer,data,event['writes'],label)
                reply('connect',b'220 fixture ESMTP\r\n')
                def line(expected, reply):
                    actual = f.readline(4096); observed['commands'].append(actual.decode('ascii', 'replace')); observed['commands_hex'].append(actual.hex())
                    check(actual == expected, 'SMTP command mismatch: ' + repr(actual))
                    send_reply=reply; reply_event={'after':actual.hex(),'bytes_hex':send_reply.hex(),'writes':[]}; observed['responses'].append(reply_event)
                    send_piece(peer,send_reply,reply_event['writes'],'command-reply')
                line(b'EHLO client.fixture.invalid\r\n', b'250 fixture\r\n')
                line(b'MAIL FROM:<sender@fixture.invalid>\r\n', b'250 sender\r\n')
                for address, code in zip(RCPTS, statuses):
                    line(('RCPT TO:<'+address+'>\r\n').encode(), ('%d recipient\r\n' % code).encode())
                if any(code == 250 for code in statuses):
                    line(b'DATA\r\n', b'354 send data\r\n'); chunks=[]
                    while True:
                        data = f.readline(4096); chunks.append(data); observed['data_lines_hex'].append(data.hex()); observed['data_hex']=b''.join(chunks).hex()
                        check(bool(data) and data.endswith(b'\r\n'), 'invalid DATA line')
                        if data == b'.\r\n': break
                        check(sum(map(len,chunks)) < MAX, 'SMTP body exceeds capture bound')
                    observed['data_hex'] = b''.join(chunks).hex()
                    reply('DATA',b'250 queued\r\n'); line(b'QUIT\r\n', b'221 goodbye\r\n')
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
        trace['queue_snapshot_after'] = snapshot()
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
        if scenario in ('unix-server','smtp-inbound'): signal_delivery_control(trace)
        if scenario == 'capture-control': capture_control(trace)
        elif scenario == 'delivery-control': signal_delivery_control(trace)
        elif scenario == 'unix-server': unix_server(shell, trace)
        elif scenario == 'unix-client': unix_client(shell, trace)
        elif scenario == 'unix-absent': unix_absent(shell, trace)
        elif scenario == 'smtp-inbound': smtp_inbound(shell, trace)
        elif scenario.startswith('smtp-'): smtp_outbound(shell, scenario, trace)
        elif scenario == 'queue-flush': queue_flush(shell, trace)
        elif scenario == 'signal-control': signal_probe(trace)
        else: raise ValueError('unknown scenario')
        print('mail-' + scenario + '=ok')
    except Exception as exc:
        trace['classification'] = 'requires raw evidence review; observer failures invalidate signal observation'
        trace['error'] = type(exc).__name__ + ': ' + str(exc)
        if exc.__context__ is not None: trace['prior_error'] = type(exc.__context__).__name__ + ': ' + str(exc.__context__)
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
