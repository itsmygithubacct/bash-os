#!/usr/bin/env python3
"""Validated API/syscall-fixture timings; run through the campaign bench gate.

One warm-up and >=7 samples for each fixed workload. No external ratios.
The fixture fixes timestamps and, only in bounded-spool, injects sendto EAGAIN.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('behavior', ROOT/'tests/sol-bashsyslogd-check.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def messages(count):
    out = []
    for n in range(count):
        pri = (13, 32, 0, 87)[n % 4]
        head = f'<{pri}>seq={n:08d} '.encode()
        out.append(head + b'x' * (128-len(head)-8) + b'\x00\n\r\x1b\t\xff!?')
    assert all(len(m) == 128 for m in out)
    return out


class Collector:
    def __init__(self, server):
        self.server = server
        self.data = []
        self.stop = threading.Event()
        self.error = None
        self.changed = threading.Condition()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    record = self.server.recv(9000)
                    with self.changed:
                        self.data.append(record)
                        self.changed.notify_all()
                except socket.timeout:
                    pass
        except Exception as e:
            self.error = repr(e)

    def start(self):
        self.server.settimeout(.02)
        self.thread.start()

    def await_count(self, count):
        with self.changed:
            assert self.changed.wait_for(lambda: len(self.data) >= count or self.error, timeout=15), ('missing UDP', count, len(self.data))
            assert self.error is None, self.error

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive() and self.error is None, self.error


def run(binary, fixture, mode, data):
    with tempfile.TemporaryDirectory(prefix='b-') as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        root = Path(directory)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096 if mode == 'udp-overload' else 4*1024*1024)
        server.bind(('127.0.0.1', 0))
        marker = root/'blocked'
        capacity = 64
        if mode == 'bounded-spool':
            marker.touch()
        t.INJECT_ENV = {'LD_PRELOAD': fixture, 'BASHSYSLOGD_TEST_CLOCK': '1', 'TZ': 'UTC0'}
        if mode == 'bounded-spool':
            t.INJECT_ENV['BASHSYSLOGD_TEST_BLOCK'] = str(marker)
        extra = ['--forward', '127.0.0.1:' + str(server.getsockname()[1])]
        if mode == 'bounded-spool':
            extra += ['--queue-max-bytes', str(capacity * 257)]
        d = t.Daemon(binary, root, extra).ready()
        collector = Collector(server)
        if mode != 'udp-overload':
            collector.start()
        expected = [t.scrub(m) for m in data]
        prefix = b'Nov 14 22:13:20 ' + socket.gethostname().encode()[:127] + b' '
        expected_files = {'messages': b''.join(prefix + m + b'\n' for m in expected),
                          'syslog': b''.join(prefix + m + b'\n' for i, m in enumerate(expected) if i % 4 == 0),
                          'auth.log': b''.join(prefix + m + b'\n' for i, m in enumerate(expected) if i % 4 in (1, 3)),
                          'kern.log': b''.join(prefix + m + b'\n' for i, m in enumerate(expected) if i % 4 == 2)}
        retries = 0
        progress = [{'sent': 0, 'queue_bytes': 0}]
        accepted_while_stopped = 0
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                sender_buffer = client.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                client.setblocking(False)
                # Exercise actual receive-queue backpressure on the owned child.
                # This setup is excluded from sustained routing time.
                d.process.send_signal(signal.SIGSTOP)
                t.wait_for(lambda: 'State:\tT' in Path(f'/proc/{d.process.pid}/status').read_text(), 'owned child stop')
                for m in data:
                    try:
                        client.sendto(m, str(d.sock))
                        accepted_while_stopped += 1
                    except BlockingIOError:
                        break
                assert 0 < accepted_while_stopped < 16, accepted_while_stopped
                start = time.perf_counter_ns()
                d.process.send_signal(signal.SIGCONT)
                for index in range(accepted_while_stopped, len(data)):
                    while True:
                        try:
                            client.sendto(data[index], str(d.sock))
                            break
                        except BlockingIOError:
                            retries += 1
                            time.sleep(.0001)
                    # Controlled receiver: cap outstanding loopback copies so
                    # sustained mode measures a validated no-loss workload.
                    if mode == 'sustained' and (index+1) % 32 == 0:
                        collector.await_count(index+1)
                    if (index+1) % 512 == 0 or (mode == 'bounded-spool' and (index+1) in (16, 32, 48, 64, 128)):
                        if mode == 'bounded-spool' and index+1 <= capacity:
                            # Deliberately pause the producer at each checkpoint;
                            # independently predicted hex sizes prove growth.
                            want = (index+1)*257
                            t.wait_for(lambda: d.queue.exists() and d.queue.stat().st_size == want, 'exact queue growth')
                        progress.append({'sent': index+1, 'queue_bytes': d.queue.stat().st_size if d.queue.exists() else 0})
                sent_at = time.perf_counter_ns()
                total = len(expected_files['messages'])
                t.wait_for(lambda: d.output.exists() and d.output.stat().st_size == total, 'routed byte count', timeout=20)
                if mode == 'bounded-spool':
                    t.wait_for(lambda: d.queue.exists() and d.queue.stat().st_size == capacity*257, 'bounded queue')
                    # Wait for the last forwarding decision, after local append.
                    t.wait_for(lambda: d.readerr().count(b'dropped copy') == len(data)-capacity, 'drop accounting', timeout=20)
                routed_at = time.perf_counter_ns()
                queue_bytes = d.queue.stat().st_size if d.queue.exists() else 0
                if mode == 'bounded-spool':
                    assert d.queue.read_bytes() == b''.join(m.hex().encode()+b'\n' for m in data[:capacity])
                    marker.unlink()
                    t.wait_for(lambda: len(collector.data) == capacity, 'idle queue recovery', timeout=5)
                    t.wait_for(lambda: not d.queue.exists(), 'queue removed')
                    forwarded_expected = expected[:capacity]
                elif mode == 'sustained':
                    t.wait_for(lambda: len(collector.data) == len(data), 'all loopback copies', timeout=10)
                    forwarded_expected = expected
                else:
                    # Receiver deliberately reads only after the daemon has
                    # attempted every copy. These drops are outside the spool.
                    d.finish(stop=True)
                    server.settimeout(.05)
                    while True:
                        try:
                            collector.data.append(server.recv(9000))
                        except socket.timeout:
                            break
                    forwarded_expected = expected[:len(collector.data)]
                    assert 0 < len(collector.data) < len(data), 'overload did not cause loss'
                forward_at = time.perf_counter_ns()
                if d.process.poll() is None:
                    d.finish(stop=True, expected=1 if mode == 'bounded-spool' else 0)
            if mode != 'udp-overload':
                collector.finish()
            assert collector.data == forwarded_expected, 'wrong, duplicate, or reordered UDP bytes'
            for filename, content in expected_files.items():
                assert (root/filename).read_bytes() == content, filename
            assert not d.queue.exists(), 'spool left after recovery'
            if mode != 'bounded-spool':
                assert not d.stderr, d.stderr
            else:
                assert d.stderr.count(b'dropped copy') == len(data)-capacity
            elapsed = (routed_at-start)/1e9
            return {'status': 'pass', 'routing_seconds': elapsed,
                    'sender_seconds': (sent_at-start)/1e9,
                    'forward_completion_seconds': (forward_at-start)/1e9,
                    'received_messages': len(data), 'received_bytes': sum(map(len, data)),
                    'routed_records': len(data)*2,
                    'routed_file_bytes': sum(map(len, expected_files.values())),
                    'forwarded_messages': len(collector.data), 'forwarded_bytes': sum(map(len, collector.data)),
                    'forward_loss_messages': len(data)-len(collector.data),
                    'forward_loss_bytes': sum(map(len, data))-sum(map(len, collector.data)),
                    'receive_loss_messages': 0, 'route_loss_records': 0,
                    'queue_peak_bytes': max([queue_bytes, *[p['queue_bytes'] for p in progress]]), 'queue_progress': progress,
                    'queue_capacity_bytes': capacity*257 if mode == 'bounded-spool' else 262144,
                    'queue_drop_messages': len(data)-capacity if mode == 'bounded-spool' else 0,
                    'queue_drop_payload_bytes': (len(data)-capacity)*128 if mode == 'bounded-spool' else 0,
                    'queue_final_bytes': 0, 'unix_queue_accepted_while_stopped': accepted_while_stopped,
                    'unix_backpressure_retries': retries,
                    'messages_per_second': len(data)/elapsed,
                    'input_bytes_per_second': sum(map(len, data))/elapsed,
                    'validated_file_sha256': {k: hashlib.sha256(v).hexdigest() for k, v in expected_files.items()},
                    'forwarded_sha256': hashlib.sha256(b''.join(collector.data)).hexdigest(),
                    'daemon_status': d.process.returncode, 'socket_removed': not d.sock.exists(),
                    'unix_sender_buffer_bytes': sender_buffer,
                    'udp_receive_buffer_bytes': server.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)}
        finally:
            if mode != 'udp-overload' and collector.thread.is_alive():
                collector.finish()
            if d.process.poll() is None:
                d.process.send_signal(signal.SIGCONT)
            d.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--runs', type=int, default=7)
    args = parser.parse_args()
    assert args.runs >= 7
    binary, fixture = str(Path(args.binary).resolve()), str(Path(args.fixture).resolve())
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'use fixed CPU affinity through the bench gate'
    report = {'kind': 'syscall-shim', 'external_ratio': None, 'method': __doc__,
              'affinity': affinity, 'python': sys.version, 'platform': platform.platform(),
              'kernel_buffers': {p: Path('/proc/sys', p).read_text().strip() for p in ('net/unix/max_dgram_qlen', 'net/core/rmem_max', 'net/core/wmem_max')},
              'cpu': next((s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')), 'unknown'),
              'binary_version': subprocess.check_output([binary, '--version'], text=True).splitlines()[0],
              'compiler_version': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'loadables/bashsyslogd.c'], text=True).strip()),
              'source_sha256': digest(ROOT/'loadables/bashsyslogd.c'), 'binary_sha256': digest(binary),
              'fixture_sha256': digest(fixture), 'fixture_source_sha256': digest(ROOT/'tests/sol-bashsyslogd-faults.c'),
              'harness_sha256': digest(__file__), 'cases': {}}
    try:
        for mode, count in [('sustained', 20000), ('udp-overload', 4096), ('bounded-spool', 4096)]:
            data = messages(count)
            case = {'status': 'running', 'count': count, 'datagram_bytes': 128,
                    'fixture_sha256': hashlib.sha256(b''.join(data)).hexdigest(),
                    'reset': 'fresh owned shell, socket, empty log tree and queue; private loopback port each pass',
                    'options': {'unix_sender_buffer_requested': 4096, 'queue_growth_checkpoints': [16, 32, 48, 64] if mode == 'bounded-spool' else [], 'queue_capacity_records': 64 if mode == 'bounded-spool' else None,
                                'outstanding_udp_batch': 32 if mode == 'sustained' else None}, 'samples': []}
            report['cases'][mode] = case
            case['warmup'] = run(binary, fixture, mode, data)
            for sample in range(args.runs):
                case['samples'].append(run(binary, fixture, mode, data))
                print(mode, sample+1, case['samples'][-1]['routing_seconds'], flush=True)
            times = [s['routing_seconds'] for s in case['samples']]
            case['distribution_seconds'] = {'min': min(times), 'median': statistics.median(times), 'max': max(times), 'stdev': statistics.stdev(times)}
            case['status'] = 'pass'
        report['status'] = 'pass'
    except Exception as exc:
        report['status'] = 'fail'
        report['error'] = repr(exc)
        raise
    finally:
        Path(args.output).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
