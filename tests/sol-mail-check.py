#!/usr/bin/env python3
"""Private production mail submission/SMTP fixtures; no host spool or mail config.

Also imported by bench/sol-mail.py. No compilation or timing experiments here.
"""
import argparse
import os
from pathlib import Path
import re
import select
import shlex
import signal
import socket
import subprocess
import tempfile
import threading
import time

FROM = 'sender@fixture.invalid'
RCPTS = ['one@fixture.invalid', 'two@fixture.invalid']


def words(*args):
    return shlex.join(list(map(str, args)))


class Shell:
    def __init__(self, binary):
        env = {**os.environ, 'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC'}
        env.pop('BASH_ENV', None)
        if os.environ.get('SOL_MAIL_LOAD_ENV'):
            env.update(BASH_ENV=os.environ['SOL_MAIL_LOAD_ENV'],
                       LD_PRELOAD=os.environ['SOL_MAIL_ASAN_LIB'],
                       ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        self.p = subprocess.Popen([str(binary), '--noprofile', '--norc'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=env)
        self.buf = b''
        assert self.command('type -t mail') == b'builtin\n'
        self.command('mail_status() { return "$1"; }; unset BASHMAIL_QUEUE_DIR BASHMAIL_SUBMIT_SOCK BASHMAIL_ALIASES BASHMAIL_ALIASES_DB BASHMAIL_FORWARD_ROOT')

    def send(self, script):
        self.p.stdin.write((script + '\nprintf "__MAIL_STATUS %s\\n" "$?"\n').encode())
        self.p.stdin.flush()

    def receive(self):
        output = b''
        while True:
            while b'\n' in self.buf:
                line, self.buf = self.buf.split(b'\n', 1)
                if line.startswith(b'__MAIL_STATUS '):
                    return int(line.split()[-1]), output
                output += line + b'\n'
            assert select.select([self.p.stdout], [], [], 12)[0], 'shell stalled'
            chunk = os.read(self.p.stdout.fileno(), 65536)
            assert chunk, ('shell exited', self.p.poll(), self.p.stderr.read())
            self.buf += chunk

    def command(self, script, rc=0):
        self.send(script)
        status, output = self.receive()
        assert status == rc, (script, status, rc, output)
        return output

    def close(self):
        if self.p.poll() is None:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        errors = self.p.stderr.read()
        assert b'AddressSanitizer' not in errors and b'runtime error:' not in errors, errors
        assert self.p.returncode == 0, (self.p.returncode, errors)
        self.p.stdout.close()
        self.p.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if exc[0] and self.p.poll() is None:
            self.p.kill()
            self.p.wait()
        else:
            self.close()


class Daemon:
    def __init__(self, shell, root, limit=None):
        self.shell = shell
        self.sock = root/'submit.sock'
        self.queue = root/'queue'
        args = ['mail', 'serve', '--socket', self.sock, '--queue', self.queue]
        if limit:
            conf = root/'mail.conf'
            conf.write_text(f'max_message_bytes = {limit}\n')
            args += ['--conf', conf]
        shell.send(words(*args))
        for _ in range(500):
            if self.sock.exists():
                break
            assert shell.p.poll() is None
            time.sleep(.01)
        else:
            raise AssertionError('submission socket did not appear')

    def stop(self, sig=signal.SIGTERM):
        os.kill(self.shell.p.pid, sig)
        rc, output = self.shell.receive()
        assert rc == 0 and b'serving submissions' in output, (rc, output)
        assert not self.sock.exists()


def frame(message, sender=FROM.encode(), recipients=None):
    recipients = recipients if recipients is not None else [r.encode() for r in RCPTS]
    return (b'BASHMAIL1\nFROM '+str(len(sender)).encode()+b'\n'+sender +
            b''.join(b'RCPT '+str(len(r)).encode()+b'\n'+r for r in recipients) +
            b'DATA '+str(len(message)).encode()+b'\n'+message+b'END\n')


def exchange(path, data, fragment=False):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(str(path))
        if fragment:
            for i in range(0, len(data), 3):
                s.sendall(data[i:i+3])
        else:
            s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        return s.makefile('rb').readline()


def split_message(msg):
    # Independent oracle for the documented queue split.
    match = re.search(b'\r\n\r\n|\n\n', msg)
    if not match:
        return msg, b''
    separator = match.group()
    return msg[:match.start()+len(separator)//2], msg[match.end():]


def canonical(msg):
    # SMTP line ending normalization and a final line ending if missing.
    lines = msg.split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    return b''.join(line.removesuffix(b'\r')+b'\r\n' for line in lines)


def check_entry(queue, qid, msg, sender=FROM, recipients=RCPTS):
    assert re.fullmatch('[0-9A-F]{15,23}', qid), qid
    entry = queue/'active'/qid
    assert {p.name for p in entry.iterdir()} == {'headers', 'body', 'envelope', 'meta'}
    h, b = split_message(msg)
    assert (entry/'headers').read_bytes() == h
    assert (entry/'body').read_bytes() == b
    assert (entry/'envelope').read_bytes() == ('from '+sender+'\n'+''.join('rcpt '+r+'\n' for r in recipients)).encode()
    meta = dict(line.split('=', 1) for line in (entry/'meta').read_text().splitlines())
    assert meta['qid'] == qid and meta['size'] == str(len(msg))
    assert meta['sender'] == sender and meta['nrcpt'] == str(len(recipients))
    assert int(meta['arrival']) > 0
    assert entry.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in entry.iterdir())
    return {p.name: p.read_bytes() for p in entry.iterdir()}


def submit(shell, root, msg, daemon=None, rc=0, sender=FROM, recipients=RCPTS):
    source = root/'message'
    source.write_bytes(msg)
    args = ['mail', 'submit', '-f', sender]
    args += ['--socket', daemon.sock] if daemon else ['--direct', '--queue', root/'queue']
    output = shell.command(words(*args, '--', *recipients)+' < '+words(source), rc)
    return output.strip().decode()


class Sink:
    """Strict loopback SMTP oracle, one connection; failures at a chosen stage."""
    def __init__(self, fail=None, code=451, rcpt_codes=None, malformed=None):
        self.fail, self.code, self.rcpt_codes, self.malformed = fail, code, rcpt_codes, malformed
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.sock.settimeout(10)
        self.port = self.sock.getsockname()[1]
        self.error = None
        self.received = None
        self.envelope = []
        self.wire = b''
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            with self.sock.accept()[0] as s:
                s.settimeout(5)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with s.makefile('rb') as f:
                    def reply(stage, ok):
                        data = self.malformed if stage == 'greeting' and self.malformed else ((str(self.code)+' fixture failure\r\n').encode() if self.fail == stage else ok)
                        # Force the client to tolerate fragmented replies.
                        s.sendall(data[:2]); s.sendall(data[2:])
                        return self.fail == stage or bool(self.malformed)
                    if reply('greeting', b'220 fixture.invalid ESMTP\r\n'):
                        return
                    assert f.readline() == b'EHLO client.fixture.invalid\r\n'
                    if reply('ehlo', b'250-fixture.invalid\r\n250 PIPELINING\r\n'):
                        assert f.readline() == b'HELO client.fixture.invalid\r\n'
                        s.sendall((str(self.code)+' no HELO\r\n').encode())
                        return
                    self.envelope.append(f.readline())
                    assert self.envelope[-1] == f'MAIL FROM:<{FROM}>\r\n'.encode()
                    if reply('mail', b'250 sender ok\r\n'):
                        return
                    accepted = 0
                    for i, recipient in enumerate(RCPTS):
                        line = f.readline(); self.envelope.append(line)
                        assert line == f'RCPT TO:<{recipient}>\r\n'.encode(), line
                        code = self.rcpt_codes[i] if self.rcpt_codes else (self.code if self.fail == 'rcpt' else 250)
                        s.sendall(f'{code} recipient\r\n'.encode())
                        accepted += code // 100 == 2
                    if not accepted:
                        return
                    assert f.readline() == b'DATA\r\n'
                    if reply('data', b'354 send data\r\n'):
                        return
                    body = []
                    while True:
                        line = f.readline()
                        assert line and line.endswith(b'\r\n'), line
                        self.wire += line
                        if line == b'.\r\n':
                            break
                        if line.startswith(b'.'):
                            assert line.startswith(b'..'), line
                            line = line[1:]
                        body.append(line)
                    self.received = b''.join(body)
                    if reply('final', b'250 committed\r\n'):
                        return
                    assert f.readline() == b'QUIT\r\n'
                    s.sendall(b'221 goodbye\r\n')
        except BaseException as exc:
            self.error = exc
        finally:
            self.sock.close()

    def finish(self):
        self.thread.join(12)
        assert not self.thread.is_alive(), 'SMTP sink stalled'
        if self.error:
            raise self.error


MAIL_DELIVER_TIMEOUT = 1000


def deliver(shell, queue, qid, sink, rc=0, extra=(), output_path=None):
    command = ('exec {mailfd}<>/dev/tcp/127.0.0.1/'+str(sink.port)+'; '+
               words('mail', 'deliver-fd', '--queue', queue, '--qid', qid,
                     '--from', FROM, '--ehlo', 'client.fixture.invalid', '--tls', 'off',
                     '--timeout', MAIL_DELIVER_TIMEOUT, *extra)+' --fd "$mailfd" -- '+words(*RCPTS)+
               '; mailrc=$?; exec {mailfd}>&-; mail_status "$mailrc"')
    if output_path:
        command = '{ '+command+'; } > '+words(output_path)
    output = shell.command(command, rc)
    sink.finish()
    return output


def main():
    global MAIL_DELIVER_TIMEOUT
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', type=Path)
    ap.add_argument('--case', choices=['all', 'submission', 'delivery', 'framing', 'lifecycle', 'aliases'], default='all')
    ap.add_argument('--timeout', type=int, default=1000)
    args = ap.parse_args()
    MAIL_DELIVER_TIMEOUT = args.timeout
    with tempfile.TemporaryDirectory(prefix='sol-mail-', dir='/tmp') as tmp, Shell(args.binary.resolve()) as sh:
        root = Path(tmp)
        queue = root/'queue'
        initial_fds = len(list(Path(f'/proc/{sh.p.pid}/fd').iterdir()))
        cases = ['aliases', 'submission', 'delivery', 'framing', 'lifecycle'] if args.case == 'all' else [args.case]
        for case in cases:
            if case == 'aliases':
                aliases, db = root/'aliases', root/'aliasdb'
                aliases.write_text('team: fixturea, fixtureb\n')
                sh.command(words('mail', 'newaliases', '--aliases', aliases, '--db', db))
                assert sh.command(words('mail', 'expand', '--aliases-db', db, '--aliases', aliases,
                                        '--forward-root', root/'forward', 'team')).splitlines() == [b'fixturea', b'fixtureb']
                aliases.write_text('')
                sh.command(words('mail', 'newaliases', '--aliases', aliases, '--db', db))
                assert db.read_bytes() == b'# mail-aliases-db v1 (0 entries)\n'
                aliases.write_text('invalid alias\n')
                sh.command(words('mail', 'newaliases', '--aliases', aliases, '--db', db), 78)
                assert db.read_bytes() == b'# mail-aliases-db v1 (0 entries)\n'
            elif case == 'submission':
                daemon = Daemon(sh, root)
                with Shell(args.binary.resolve()) as client:
                    client_fds = len(list(Path(f'/proc/{client.p.pid}/fd').iterdir()))
                    ids = set()
                    for msg in [b'', b'Subject: LF\n\n.\n..two\nlast', b'Subject: CRLF\r\n\r\na\x00b\r\n', b'Subject: big\n\n'+b'x'*1100000]:
                        for via in [None, daemon]:
                            qid = submit(client, root, msg, via)
                            assert qid not in ids; ids.add(qid)
                            check_entry(queue, qid, msg)
                    client.command(words('mail', 'submit', '--direct', '--queue', queue)+' < /dev/null', 67)
                    client.command(words('mail', 'submit', '--bad-option'), 2)
                    client.command(words('mail', 'submit', '--socket', root/'absent', 'a')+' < /dev/null', 75)
                    badqueue = root/'not-dir'; badqueue.write_text('x')
                    client.command(words('mail', 'submit', '--direct', '--queue', badqueue, 'a')+' < /dev/null', 75)
                    submit(client, root, b'\n\n', sender='bad\nrcpt injected', rc=2)
                    client.command(words('mail', 'queue-delete', '../outside', '--queue', queue), 2)
                    client.command(words('mail', 'queue-show', '../outside', '--queue', queue), 2)
                    client.command(words('mail', 'queue-list', '--queue', queue)+' > /dev/full', 1)
                    assert len(list((queue/'active').iterdir())) == len(ids)
                    before = set((queue/'active').iterdir())
                    client.command(words('mail', 'submit', '--direct', '--queue', queue, '-f', FROM, '--', *RCPTS)+' < '+words(root/'message')+' > /dev/full', 1)
                    added = set((queue/'active').iterdir()) - before
                    assert len(added) == 1
                    check_entry(queue, added.pop().name, (root/'message').read_bytes())
                    assert b'Queue ID' in client.command(words('mail', 'queue-list', '--queue', queue))
                    assert len(list(Path(f'/proc/{client.p.pid}/fd').iterdir())) == client_fds
                daemon.stop()
            elif case == 'delivery':
                for msg in [b'', b'headers without separator', b'\n\n', b'Subject: LF\n\n.\n..two\nlast', b'Subject: CRLF\r\n\r\na\x00b\r\n', b'Subject: big\n\n'+b'x'*1100000+b'\n'] + [b'Subject: boundary\n\n'+b'x'*n+b'\n.\n..\nlast' for n in [65519, 65520, 65521, 65535, 65536, 65537]]:
                    qid = submit(sh, root, msg)
                    snapshot = check_entry(queue, qid, msg)
                    shown = root/'shown'
                    sh.command(words('mail', 'queue-show', qid, '--queue', queue)+' > '+words(shown))
                    assert shown.read_bytes() == snapshot['envelope']+b'--\n'+msg
                    sink = Sink()
                    assert deliver(sh, queue, qid, sink) == b''.join(f'delivered {r}\n'.encode() for r in RCPTS)
                    assert sink.received == canonical(msg), (len(sink.received), len(canonical(msg)))
                    assert check_entry(queue, qid, msg) == snapshot
                msg = b'Subject: retry\n\n.retry\n'
                qid = submit(sh, root, msg)
                snapshot = check_entry(queue, qid, msg)
                for stage in ['greeting', 'ehlo', 'mail', 'rcpt', 'data', 'final']:
                    for code, rc in [(451, 75), (550, 69)]:
                        sink = Sink(fail=stage, code=code)
                        assert deliver(sh, queue, qid, sink, rc) == b''
                        assert check_entry(queue, qid, msg) == snapshot
                        sink = Sink()
                        deliver(sh, queue, qid, sink)
                        assert sink.received == canonical(msg)
                sink = Sink()
                deliver(sh, queue, qid, sink, 1, output_path='/dev/full')
                assert sink.received == canonical(msg)
                for codes, rc in [([250, 450], 75), ([250, 550], 69), ([450, 550], 75), ([250, 350], 75), ([350, 350], 75)]:
                    sink = Sink(rcpt_codes=codes)
                    expected = f'delivered {RCPTS[0]}\n'.encode() if codes[0] == 250 else b''
                    assert deliver(sh, queue, qid, sink, rc) == expected
                    assert sink.received == (canonical(msg) if codes[0] == 250 else None)
                for malformed in [b'220 truncated', b'220-hi\r\n250 mismatch\r\n', b'220x broken\r\n', b'220 '+b'x'*1100+b'\r\n']:
                    sink = Sink(malformed=malformed)
                    deliver(sh, queue, qid, sink, 75)
                assert check_entry(queue, qid, msg) == snapshot
                sh.command(words('mail', 'deliver-fd', '--fd', 0, '--from', FROM, '--qid', '../bad', '--queue', queue, '--', *RCPTS), 2)
                for extra in [('--fd', 'bad'), ('--timeout', '0'), ('--timeout', '999999999999999999999999'), ('--tls', 'bad'), ('--tls-verify', 'bad'), ('--from', 'a\r\nb')]:
                    sh.command(words('mail', 'deliver-fd', '--fd', 0, '--from', FROM, '--qid', qid, '--queue', queue, *extra, '--', *RCPTS), 2)
                (queue/'active'/qid/'body').unlink()
                sh.command(words('mail', 'deliver-fd', '--fd', 0, '--from', FROM, '--qid', qid, '--queue', queue, '--', *RCPTS), 69)
                sh.command(words('mail', 'queue-delete', qid, '--queue', queue))
                assert not (queue/'active'/qid).exists()
                sh.command(words('mail', 'queue-show', qid, '--queue', queue), 1)
            elif case == 'framing':
                occupied = root/'occupied.sock'
                occupied.write_text('keep')
                sh.command(words('mail', 'serve', '--socket', occupied, '--queue', queue), 1)
                assert occupied.read_text() == 'keep'
                daemon = Daemon(sh, root, limit=512)
                with Shell(args.binary.resolve()) as competitor:
                    competitor.command(words('mail', 'serve', '--socket', daemon.sock, '--queue', queue), 1)
                    assert daemon.sock.exists()
                msg = b'Subject: frame\n\na\x00b\n.\n'
                reply = exchange(daemon.sock, frame(msg), fragment=True)
                assert reply.startswith(b'OK '), reply
                check_entry(queue, reply[3:].strip().decode(), msg)
                assert exchange(daemon.sock, frame(b'x'*512)).startswith(b'OK ')
                before = set((queue/'active').iterdir())
                bad = [b'NO\n', b'BASHMAIL1\x00ignored\n', b'BASHMAIL1\nFROM -1\n', b'BASHMAIL1\nFROM 1 garbage\nxEND\n',
                       b'BASHMAIL1\nFROM 1024\n', b'BASHMAIL1\nDATA 513\n',
                       b'BASHMAIL1\nUNKNOWN 0\n', b'BASHMAIL1\nRCPT 3\na',
                       b'BASHMAIL1\nRCPT 1\naDATA 5\nxx', frame(b'x', sender=b'a\nb'),
                       frame(b'x', sender=b'a\x00b'), frame(b'x', recipients=[b'a\rb']),
                       b'BASHMAIL1\nRCPT 1\naEND\n',
                       frame(b'x').replace(b'DATA 1\nx', b'DATA 1\nxDATA 0\n'),
                       b'BASHMAIL1\nFROM 0\nFROM 0\nRCPT 1\naDATA 0\nEND\n']
                for data in bad:
                    assert exchange(daemon.sock, data).startswith(b'ERR 75 '), data
                    assert set((queue/'active').iterdir()) == before
                # Peer aborts must not terminate the daemon via SIGPIPE.
                with socket.socket(socket.AF_UNIX) as s:
                    s.connect(str(daemon.sock)); s.sendall(b'bad\n')
                assert exchange(daemon.sock, frame(b'')).startswith(b'OK ')
                daemon.stop()
            elif case == 'lifecycle':
                sh.command("trap ':' TERM; trap ':' INT; trap ':' PIPE")
                traps = sh.command('trap -p TERM INT PIPE')
                for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGTERM]:
                    daemon = Daemon(sh, root)
                    with socket.socket(socket.AF_UNIX) as stalled:
                        stalled.connect(str(daemon.sock))
                        stalled.sendall(b'BASHMAIL1\nDATA 100\nx')
                        # Ensure the daemon entered its incomplete-frame read.
                        time.sleep(.05)
                        daemon.stop(sig)
                    assert sh.command('trap -p TERM INT PIPE') == traps
                for sig in [signal.SIGTERM, signal.SIGINT]:
                    with socket.socket() as reserved:
                        reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
                    sh.send(words('mail', 'smtpd', '--bind', f'127.0.0.1:{port}', '--queue', queue, '--user', '', '--ehlo', 'fixture.invalid'))
                    for _ in range(500):
                        try:
                            peer = socket.create_connection(('127.0.0.1', port), timeout=1)
                            break
                        except ConnectionRefusedError:
                            time.sleep(.01)
                    else:
                        raise AssertionError('smtpd did not start')
                    with peer:
                        assert peer.recv(1024).startswith(b'220 ')
                        peer.sendall(b'EHL')
                        time.sleep(.05)
                        os.kill(sh.p.pid, sig)
                        status, output = sh.receive()
                        assert status == 0 and b'smtpd listening' in output
                    assert sh.command('trap -p TERM INT PIPE') == traps
                assert not list((queue/'active').glob('.tmp.*'))
            assert len(list(Path(f'/proc/{sh.p.pid}/fd').iterdir())) == initial_fds, case
            print('PASS', case, flush=True)
    print('PASS all selected mail fixtures')


if __name__ == '__main__':
    main()
