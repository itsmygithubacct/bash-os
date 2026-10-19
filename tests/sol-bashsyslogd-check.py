#!/usr/bin/env python3
"""Owned-socket behavioral tests. No build, external daemon, or host log access."""
import argparse
import contextlib
import errno
import os
from pathlib import Path
import shlex
import signal
import select
import socket
import stat
import subprocess
import tempfile
import time
import traceback


INJECT_ENV = {}
PREFIX = ""


def wait_for(predicate, what, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.005)
    raise AssertionError('timeout: ' + what)


def scrub(data):
    return bytes(32 if (c < 32 and c != 9) or c == 127 else c for c in data[:8192])


def readline(process):
    ready, _, _ = select.select([process.stdout], [], [], 5)
    assert ready, 'shell output timeout'
    return process.stdout.readline()


def records(path):
    """Validate timestamp/host envelope separately; compare entire payload bytes."""
    import re
    data = path.read_bytes() if path.exists() else b''
    out = []
    host = socket.gethostname().encode()[:127]
    for line in data.splitlines(keepends=True):
        assert re.match(rb'^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} ', line), line[:32]
        assert line[16:16+len(host)+1] == host + b' ', line[:160]
        assert line.endswith(b'\n')
        out.append(line[17+len(host):-1])
    return out


class Daemon:
    def __init__(self, binary, root, extra=(), script=None, env=None):
        self.root = root
        self.sock = root/'log.sock'
        self.output = root/'messages'
        self.queue = root/'forward.queue'
        args = ['bashsyslogd', 'run', '-s', str(self.sock), '-o', str(self.output), '--queue', str(self.queue), *extra]
        command = shlex.join(args)
        self.errfile = (root/'stderr').open('w+b')
        self.process = subprocess.Popen([binary, '--noprofile', '--norc', '-c', PREFIX + (script or command)],
                                        env={**os.environ, 'PATH': '', 'LC_ALL': 'C', **INJECT_ENV, **(env or {})},
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errfile, bufsize=0)
        self.stdout = self.stderr = b''

    def ready(self):
        def bound():
            if self.process.poll() is not None:
                return True
            try:
                # Connecting an AF_UNIX datagram probe sends no data. It
                # distinguishes a live receiver from a preexisting stale path.
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as probe:
                    probe.connect(str(self.sock))
                return True
            except OSError as e:
                if e.errno in (errno.ENOENT, errno.ECONNREFUSED):
                    return False
                raise
        wait_for(bound, 'bind')
        assert self.process.poll() is None, self.finish()
        return self

    def send(self, data):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(data, str(self.sock))

    def received(self, count):
        wait_for(lambda: self.output.exists() and self.output.read_bytes().count(b'\n') >= count, 'local records')

    def finish(self, stop=False, expected=0):
        if stop and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
        self.stdout, _ = self.process.communicate(timeout=6)
        self.stderr = self.readerr()
        assert self.process.returncode == expected, (self.process.returncode, self.stdout, self.stderr)
        assert not self.sock.exists(), 'socket leaked'
        assert not list(self.root.glob('forward.queue.tmp.*')), 'queue temporary leaked'
        return self.stderr

    def readerr(self):
        return (self.root/'stderr').read_bytes()

    def cleanup(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.communicate()
        self.errfile.close()


@contextlib.contextmanager
def daemon(binary, extra=(), script=None, setup=None):
    with tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        if setup:
            setup(root)
        d = Daemon(binary, root, extra, script)
        try:
            yield d
        finally:
            d.cleanup()


@contextlib.contextmanager
def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(3)
        yield server, '127.0.0.1:' + str(server.getsockname()[1])


def routing(binary):
    messages = [b'<0>kernel', b'<7>debug', b'<32>auth', b'<87>private', b'<13>user',
                b'<191>last', b'body <32>spoof', b'<x>bad', b'<1234>bad', b'<>bad',
                b'<-1>bad', b'<32\x00>bad', b'<32>a\x00b\nc\rd\x1be\x07f\x7fg\t\xff',
                bytes(range(256)), b'<13>' + b'X'*9000]
    with udp() as (server, target), daemon(binary, ['--mode', '0620', '--forward', target]) as d:
        d.ready()
        assert stat.S_IMODE(d.sock.stat().st_mode) == 0o620
        for index, msg in enumerate(messages, 1):
            d.send(msg)
            assert server.recv(10000) == scrub(msg)
            d.received(index)
        d.finish(stop=True)
        expected = [scrub(m) for m in messages]
        assert records(d.output) == expected
        assert records(d.root/'kern.log') == expected[:2]
        assert records(d.root/'auth.log') == [expected[2], expected[3], expected[12]]
        assert records(d.root/'syslog') == [m for i, m in enumerate(expected) if i not in (0, 1, 2, 3, 12)]
        assert b'truncated' in d.stderr
        assert not d.queue.exists()
        # Restart and append without altering prior bytes.
        before = d.output.read_bytes()
        again = Daemon(binary, d.root, ['--once']).ready()
        try:
            again.send(b'<13>append')
            again.finish()
            assert d.output.read_bytes().startswith(before)
            assert records(d.output) == expected + [b'<13>append']
        finally:
            again.cleanup()


def once_empty(binary):
    with daemon(binary, ['--once']) as d:
        d.ready().send(b'')
        d.finish()
        assert not d.output.exists()


def collisions(binary):
    for kind in ('file', 'symlink', 'directory', 'fifo'):
        with tempfile.TemporaryDirectory(prefix='bsd-') as directory:
            root = Path(directory)
            path = root/'log.sock'
            if kind == 'file':
                path.write_bytes(b'preserve')
            elif kind == 'symlink':
                (root/'target').write_bytes(b'preserve')
                path.symlink_to(root/'target')
            elif kind == 'directory':
                path.mkdir()
            else:
                os.mkfifo(path)
            d = Daemon(binary, root)
            try:
                d.process.communicate(timeout=5)
                err = d.readerr()
                assert d.process.returncode == 1 and b'non-socket' in err
                assert path.lstat()
                if kind in ('file', 'symlink'):
                    assert path.read_bytes() == b'preserve'
            finally:
                d.cleanup()
    # Stale socket replacement is supported.
    def stale(root):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.bind(str(root/'log.sock'))
    with daemon(binary, ['--once'], setup=stale) as d:
        d.ready().send(b'<13>stale')
        d.finish()
        assert records(d.output) == [b'<13>stale']


def invalid_options(binary):
    cases = [['--mode', v] for v in ('', '-1', '888', '1000', '7x', '+7', ' 7')]
    cases += [['--queue-max-bytes', v] for v in ('', '-1', '+1', ' 1', 'x', '18446744073709551616')]
    cases += [['--socket'], ['--wat'], ['stop']]
    with tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        private = ['--socket', str(root/'log.sock'), '--output', str(root/'messages'), '--queue', str(root/'queue')]
        for options in cases:
            p = subprocess.Popen([binary, '-c', PREFIX + 'bashsyslogd ' + shlex.join(options + private if options == ['stop'] else private + options)],
                                 env={**os.environ, 'PATH': '', **INJECT_ENV}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                _, err = p.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate()
                raise AssertionError(('invalid options entered receive loop', options))
            assert p.returncode == 2, (options, p.returncode, err)


def config(binary):
    with udp() as (one, first), udp() as (two, second), tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        conf = root/'config'
        conf.write_text("# ignored\nUNRELATED=x\n BASHSYSLOGD_FORWARD = '" + first + "' # comment\n")
        d = Daemon(binary, root, ['--config', str(conf)]).ready()
        try:
            d.send(b'<13>first')
            assert one.recv(10000) == b'<13>first'
            d.received(1)
            conf.write_text('BASHSYSLOGD_FORWARD="' + second + '"\n')
            d.process.send_signal(signal.SIGHUP)
            time.sleep(.1)
            d.send(b'<13>second')
            assert two.recv(10000) == b'<13>second'
            # An incomplete quote must preserve the working destination.
            conf.write_text('BASHSYSLOGD_FORWARD="' + first + '\n')
            d.process.send_signal(signal.SIGHUP)
            time.sleep(.1)
            d.send(b'<13>retained')
            assert two.recv(10000) == b'<13>retained'
            conf.write_text('BASHSYSLOGD_FORWARD=""\n')
            d.process.send_signal(signal.SIGHUP)
            time.sleep(.1)
            d.send(b'<13>disabled')
            d.received(4)
            d.finish(stop=True)
            assert records(d.output) == [b'<13>first', b'<13>second', b'<13>retained', b'<13>disabled']
            two.settimeout(.1)
            try:
                raise AssertionError(('unexpected copy', two.recv(10000)))
            except socket.timeout:
                pass
        finally:
            d.cleanup()
        # Explicit command target wins at startup.
        conf.write_text('BASHSYSLOGD_FORWARD=' + first + '\n')
        d = Daemon(binary, root, ['--config', str(conf), '--forward', second, '--once']).ready()
        try:
            d.send(b'override')
            assert two.recv(10000) == b'override'
            d.finish()
        finally:
            d.cleanup()


def queue(binary):
    msg = b'<13>queued\x00\n\x1b\t'
    encoded = msg.hex().encode() + b'\n'
    with tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        d = Daemon(binary, root, ['--forward', 'bad-target', '--queue-max-bytes', str(len(encoded)*2)]).ready()
        try:
            for i in range(3):
                d.send(msg)
                d.received(i+1)
            assert d.queue.read_bytes() == encoded*2, d.queue.read_bytes()
            d.finish(stop=True, expected=1)
            assert b'queue' in d.stderr and b'drop' in d.stderr
            assert records(d.output) == [scrub(msg)]*3
        finally:
            d.cleanup()
        with udp() as (server, target):
            # Malformed queue entries are discarded, valid entries retain order.
            with (root/'forward.queue').open('ab') as f:
                f.write(b'zz\n1\n\n00\x00dead\n' + b'00' * 9000 + b'\n' + b'74726967676572\n')
            d = Daemon(binary, root, ['--forward', target, '--once']).ready()
            try:
                assert [server.recv(10000) for _ in range(3)] == [scrub(msg), scrub(msg), b'trigger']
                wait_for(lambda: not d.queue.exists(), 'drained queue')
                d.send(b'live')
                assert server.recv(10000) == b'live'
                d.finish()
            finally:
                d.cleanup()


def output_errors(binary):
    # /dev/full is private through a task-owned symlink; no host log files.
    for stream in ('messages', 'syslog'):
        def setup(root):
            (root/stream).symlink_to('/dev/full')
        with daemon(binary, ['--once'], setup=setup) as d:
            d.ready().send(b'<13>write-failure')
            d.finish(expected=1)
            assert b'write' in d.stderr


def repeated(binary):
    with udp() as (server, target), tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        command = shlex.join(['bashsyslogd', '-s', str(root/'log.sock'), '-o', str(root/'messages'), '--queue', str(root/'forward.queue'), '--forward', target, '--once'])
        script = 'trap "echo restored" HUP; echo ready; read -r go; ' + command + '; echo first; read -r go; ' + command + '; echo second; kill -HUP $$; echo survived; read -r done'
        d = Daemon(binary, root, script=script)
        def resume():
            d.process.stdin.write(b'go\n')
            d.process.stdin.flush()
        def fds():
            return set(os.listdir('/proc/' + str(d.process.pid) + '/fd'))
        try:
            assert readline(d.process) == b'ready\n'
            before = fds()
            resume()
            d.ready().send(b'one')
            assert server.recv(9000) == b'one'
            assert readline(d.process) == b'first\n'
            assert fds() == before, (before, fds())
            assert not d.sock.exists()
            resume()
            d.ready().send(b'two')
            assert server.recv(9000) == b'two'
            assert readline(d.process) == b'second\n'
            assert readline(d.process) == b'restored\n'
            assert readline(d.process) == b'survived\n'
            assert fds() == before, (before, fds())
            resume()
            d.process.communicate(timeout=3)
            assert d.process.returncode == 0
            assert records(d.output) == [b'one', b'two']
            assert not d.sock.exists()
        finally:
            d.cleanup()


def controlled_queue(binary):
    assert INJECT_ENV.get('LD_PRELOAD'), '--fixture required for syscall fixtures'
    with udp() as (server, target), tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        marker = root/'blocked'
        marker.touch()
        d = Daemon(binary, root, ['--forward', target], env={
            'BASHSYSLOGD_TEST_BLOCK': str(marker), 'BASHSYSLOGD_TEST_CLOCK': '1', 'TZ': 'UTC0'}).ready()
        try:
            messages = [b'<13>one\x00\n', b'<32>two', b'<0>three']
            for i, msg in enumerate(messages, 1):
                d.send(msg)
                d.received(i)
            encoded = b''.join(m.hex().encode() + b'\n' for m in messages)
            wait_for(lambda: d.queue.exists() and d.queue.read_bytes() == encoded, 'exact queue')
            # Let a failed replay rewrite the queue, then verify its bytes again.
            time.sleep(1.2)
            assert d.queue.read_bytes() == encoded
            marker.unlink()
            assert [server.recv(10000) for _ in messages] == [scrub(m) for m in messages]
            wait_for(lambda: not d.queue.exists(), 'idle replay cleanup')
            d.finish(stop=True)
            prefix = b'Nov 14 22:13:20 ' + socket.gethostname().encode()[:127] + b' '
            assert d.output.read_bytes() == b''.join(prefix + scrub(m) + b'\n' for m in messages)
            assert (root/'syslog').read_bytes() == prefix + scrub(messages[0]) + b'\n'
            assert (root/'auth.log').read_bytes() == prefix + scrub(messages[1]) + b'\n'
            assert (root/'kern.log').read_bytes() == prefix + scrub(messages[2]) + b'\n'
        finally:
            d.cleanup()


def disabled_queue(binary):
    with daemon(binary, ['--once', '--forward', 'bad-target', '--queue-max-bytes', '0']) as d:
        d.ready().send(b'<13>drop')
        d.finish(expected=1)
        assert not d.queue.exists()
        assert records(d.output) == [b'<13>drop']
        assert b'dropped' in d.stderr


def cleanup_replacement(binary):
    with daemon(binary) as d:
        d.ready().send(b'<13>replacement')
        d.received(1)
        d.sock.unlink()
        d.sock.write_bytes(b'owned-by-someone-else')
        d.process.send_signal(signal.SIGTERM)
        d.process.communicate(timeout=5)
        err = d.readerr()
        assert d.process.returncode == 0, err
        assert d.sock.read_bytes() == b'owned-by-someone-else'


def invalid_config(binary):
    for text in ('BASHSYSLOGD_FORWARD="unterminated',
                 'BASHSYSLOGD_FORWARD="x" garbage',
                 'BASHSYSLOGD_FORWARD=' + 'x'*300,
                 'BASHSYSLOGD_FORWARD=bad\x00hidden'):
        with tempfile.TemporaryDirectory(prefix='bsd-') as directory:
            root = Path(directory)
            conf = root/'config'
            conf.write_text(text)
            d = Daemon(binary, root, ['--config', str(conf)])
            try:
                assert b'configuration' in d.finish(expected=1)
            finally:
                d.cleanup()


def replay_disk_failure(binary):
    with udp() as (server, target), tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        marker = root/'rewrite-blocked'
        marker.touch()
        queued = [b'<13>old1', b'<32>old2', b'<0>old3']
        raw = b''.join(m.hex().encode()+b'\n' for m in queued)
        (root/'forward.queue').write_bytes(raw)
        d = Daemon(binary, root, ['--forward', target, '--queue-max-bytes', '1'],
                   env={'BASHSYSLOGD_TEST_REWRITE_BLOCK': str(marker)}).ready()
        try:
            wait_for(lambda: b'queue replay failed' in d.readerr(), 'replay failure')
            assert d.queue.read_bytes() == raw
            server.settimeout(.1)
            try:
                raise AssertionError(('sent without safe rewrite', server.recv(9000)))
            except socket.timeout:
                pass
            marker.unlink()
            server.settimeout(3)
            assert [server.recv(9000) for _ in queued] == queued
            wait_for(lambda: not d.queue.exists(), 'recovered queue')
            d.finish(stop=True, expected=1)
        finally:
            d.cleanup()


def stream_overrides(binary):
    with tempfile.TemporaryDirectory(prefix='bsd-') as directory:
        root = Path(directory)
        custom = root/'custom'
        d = Daemon(binary, root, ['--syslog', str(custom), '--auth', str(custom), '--kern', str(custom)]).ready()
        try:
            values = [b'<13>user', b'<32>auth', b'<0>kern']
            for i, value in enumerate(values, 1):
                d.send(value)
                d.received(i)
            d.finish(stop=True)
            assert records(d.output) == values == records(custom)
            assert not any((root/p).exists() for p in ('syslog', 'auth.log', 'kern.log'))
        finally:
            d.cleanup()
        # An identical stream/output path must not append twice.
        d = Daemon(binary, root, ['--once', '--syslog', str(root/'messages')]).ready()
        try:
            d.send(b'<13>one-copy')
            d.finish()
            assert records(d.output) == values + [b'<13>one-copy']
        finally:
            d.cleanup()


def queue_unwritable(binary):
    def setup(root):
        (root/'forward.queue').mkdir()
    with daemon(binary, ['--once', '--forward', 'bad-target'], setup=setup) as d:
        d.ready().send(b'<13>unwritable')
        d.finish(expected=1)
        assert records(d.output) == [b'<13>unwritable']
        assert b'dropped copy' in d.stderr


def idle_shutdown(binary):
    for sig in (signal.SIGTERM, signal.SIGINT):
        with daemon(binary) as d:
            d.ready()
            d.process.send_signal(sig)
            d.finish()
            assert not d.output.exists()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary')
    p.add_argument('--case')
    p.add_argument('--fixture')
    p.add_argument('--module')
    p.add_argument('--asan')
    args = p.parse_args()
    global INJECT_ENV, PREFIX
    if args.fixture:
        assert Path(args.fixture).is_file(), 'missing fixture module'
        INJECT_ENV['LD_PRELOAD'] = str(Path(args.fixture).resolve())
    if args.asan:
        INJECT_ENV['LD_PRELOAD'] = args.asan + ':' + INJECT_ENV.get('LD_PRELOAD', '')
        INJECT_ENV['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        INJECT_ENV['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    if args.module:
        assert Path(args.module).is_file(), 'missing instrumented module'
        PREFIX = shlex.join(['enable', '-f', str(Path(args.module).resolve()), 'bashsyslogd']) + ' || exit 99; '
    binary = str(Path(args.binary).resolve())
    cases = [routing, once_empty, collisions, invalid_options, config, queue, output_errors, repeated, disabled_queue, cleanup_replacement, invalid_config, stream_overrides, queue_unwritable, idle_shutdown]
    if args.fixture:
        cases.extend([controlled_queue, replay_disk_failure])
    if args.case and args.case not in {case.__name__ for case in cases}:
        p.error('unknown case or fixture required for this case')
    failures = 0
    executed = 0
    for case in cases:
        if args.case and case.__name__ != args.case:
            continue
        executed += 1
        try:
            case(binary)
            print('PASS', case.__name__, flush=True)
        except Exception:
            failures += 1
            print('FAIL', case.__name__, flush=True)
            traceback.print_exc()
    print(f'{executed-failures}/{executed} case groups passed', flush=True)
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
