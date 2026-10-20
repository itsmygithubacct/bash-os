#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verified private PTY workloads. Timing is enabled only by the bench adapter."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location('broker_tests', HERE.with_name('ptybroker.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
PATTERN = bytes((i * 73 + i // 251 + 17) % 256 for i in range(65536))


def expected(size):
    return (PATTERN * ((size + len(PATTERN) - 1) // len(PATTERN)))[:size]


def child(mode, ready):
    import tty
    tty.setraw(0)
    temporary = Path(ready + '.tmp')
    temporary.write_text(json.dumps(base.identity(os.getpid())))
    temporary.replace(ready)
    def read_exact(n):
        data = bytearray()
        while len(data) < n:
            block = os.read(0, n - len(data))
            if not block:
                raise EOFError
            data.extend(block)
        return data
    def write(data):
        while data:
            data = data[os.write(1, data):]
    if mode in ('relay', 'slow-relay'):
        while True:
            data = os.read(0, 4096 if mode == 'slow-relay' else 16384)
            if not data:
                return
            write(data)
            if mode == 'slow-relay':
                time.sleep(.0005)
    else:
        pattern = PATTERN
        while True:
            size, block, delay = struct.unpack('!III', read_exact(12))
            offset = 0
            while offset < size:
                n = min(block, size - offset)
                # The fixture's generator is independent of the parent's helper.
                data = pattern
                start = offset % 65536
                write((data + data)[start:start+n])
                offset += n
                if delay:
                    time.sleep(delay / 1000000)


def setup(args, mode):
    h = base.Harness(args)
    h.env['PATH'] = ''
    h.sessions.add('stream')
    try:
        result = h.run('''ptybroker create "$BROKER_TEST_ROOT" stream -- \
    "$BROKER_TEST_PYTHON" "$1" --child "$2" "$BROKER_TEST_DIR/stream.ready.json"
    ''', HERE, mode)
        st = base.status_dict(result.stdout)
        h.remember(st)
        h.ready('stream')
        return h, st
    except BaseException:
        h.close()
        raise


def reader(h, tag, size, offset=0, role='observe'):
    proc = h.start_client('''exec 7> "$BROKER_TEST_DIR/$1.bytes"
exec 6> "$BROKER_TEST_DIR/$1.events"
ptybroker attach "$BROKER_TEST_ROOT" stream "$4" handle
ptybroker receive "$handle" 7 event 2000
[[ $event == attached* ]]
printf '%s\n' "$event" >&6
printf ready > "$BROKER_TEST_DIR/$1.ready"
n=0
while (( n < $2 )); do
  ptybroker receive "$handle" 7 event 5000
  printf '%s\n' "$event" >&6
  if [[ $event == output* ]]; then
    rest=${event#output size=}; bytes=${rest%% *}; off=${rest##*offset=}
    [[ $off == $((n+$3)) ]] || exit 91
    (( n+=bytes ))
  fi
done
[[ $n == "$2" ]]
ptybroker detach "$handle"
''', tag, size, offset, role)
    base.eventually(lambda: (h.directory / f'{tag}.ready').exists() or proc.poll() is not None,
                    f'{tag} attached')
    assert proc.poll() is None, proc.communicate()
    return proc


def rss(pid):
    values = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())
    return {key: int(values[key].split()[0]) * 1024 for key in ('VmRSS', 'VmHWM')}


def finish_readers(h, readers, data, broker, measure=False):
    peak = rss(broker)
    deadline = time.monotonic() + 20
    while any(p.poll() is None for _, p in readers):
        current = rss(broker)
        peak = {k: max(peak[k], current[k]) for k in peak}
        assert time.monotonic() < deadline, 'stream timed out'
        time.sleep(.001)
    completed = time.perf_counter_ns() if measure else None
    for tag, proc in readers:
        out, err = proc.communicate(timeout=2)
        assert proc.returncode == 0, (tag, proc.returncode, out, err)
        actual = (h.directory / f'{tag}.bytes').read_bytes()
        assert actual == data, (tag, len(actual), len(data), hashlib.sha256(actual).hexdigest())
    assert peak['VmHWM'] < 32 * 1024**2, peak
    return (peak, completed) if measure else peak


def stream(args, name, size, block, delay, observers, slow=False, measure=False):
    h, st = setup(args, 'source')
    try:
        broker = st['broker_pid']
        idle = rss(broker)
        readers = [(f'r{i}', reader(h, f'r{i}', size, role='control' if i == 0 else 'observe'))
                   for i in range(observers)]
        if slow:
            h.hold('stream', name='slow')
        data = expected(size)
        start = time.perf_counter_ns() if measure else 0
        # Sleeping in the producer cannot guarantee subscriber scheduling.
        # Bound outstanding output below the subscriber queue size and wait
        # for every active reader to write each window before producing more.
        # The nonreading observer is deliberately excluded from this barrier:
        # it must still overflow and disconnect. All byte/offset oracles below
        # remain unchanged. A full pattern per window preserves the source's
        # independent generator even though each request starts at offset zero.
        window = len(PATTERN)
        sent = 0
        while sent < size:
            n = min(window, size - sent)
            h.send_bytes('stream', struct.pack('!III', n, min(block, n), delay))
            sent += n
            base.eventually(
                lambda: all((h.directory / f'{tag}.bytes').stat().st_size >= sent
                            for tag, _ in readers)
                        or any(proc.poll() is not None and proc.returncode != 0
                               for _, proc in readers),
                f'active readers consumed {sent} bytes', timeout=10)
            for tag, proc in readers:
                if proc.poll() is not None:
                    assert proc.returncode == 0, (tag, proc.returncode, proc.communicate())
        completion = finish_readers(h, readers, data, broker, measure)
        peak, end = completion if measure else (completion, None)
        elapsed = (end - start) / 1e9 if measure else None
        final = h.status('stream')
        assert final['next'] == size and final['oldest'] == max(0, size - 1048576), final
        if slow:
            assert final['observers'] == 0, final
        assert h.capture('stream') == expected(size)[-1048576:]
        # Reattach starts at next, reports the exact retained range, and emits
        # only new bytes; validate live offsets after the gap as well.
        again = reader(h, 'again', 8192, size)
        h.send_bytes('stream', struct.pack('!III', 8192, 8192, 0))
        finish_readers(h, [('again', again)], expected(8192), broker)
        events = (h.directory / 'again.events').read_text().splitlines()
        gaps = [event for event in events if event.startswith('gap ')]
        assert len(gaps) == 1 and f'oldest={final["oldest"]} next={size}' in gaps[0], events
        return dict(name=name, passed=True, bytes=size, delivered_bytes=size*observers,
                    observers=observers, block_bytes=block, delay_us=delay, window_bytes=window,
                    seconds=elapsed, bytes_per_second=size/elapsed if measure else None,
                    broker_idle=idle, broker_peak=peak,
                    fixture_sha256=hashlib.sha256(expected(size)).hexdigest())
    finally:
        h.close()


def relay(args, measure=False):
    h, st = setup(args, 'relay')
    size = 2 * 1024**2 + 719
    data = expected(size)
    try:
        (h.directory / 'relay.input').write_bytes(data)
        start = time.perf_counter_ns() if measure else 0
        proc = h.start_client('''exec 8< "$BROKER_TEST_DIR/relay.input"
exec 7> "$BROKER_TEST_DIR/relay.bytes"
ptybroker attach "$BROKER_TEST_ROOT" stream control handle
ptybroker receive "$handle" 7 event 2000
[[ $event == attached* ]]
total=0
while :; do
  ptybroker send-fd "$BROKER_TEST_ROOT" stream 8 count
  (( count )) || break
  n=0
  while (( n<count )); do
    ptybroker receive "$handle" 7 event 5000
    [[ $event == output* ]]
    rest=${event#output size=}; bytes=${rest%% *}; off=${rest##*offset=}
    [[ $off == $((total+n)) ]]
    ((n+=bytes))
  done
  [[ $n == "$count" ]]
  (( total+=count ))
done
[[ $total == "$1" ]]
ptybroker detach "$handle"
''', size)
        completion = finish_readers(h, [('relay', proc)], data, st['broker_pid'], measure)
        peak, end = completion if measure else (completion, None)
        elapsed = (end - start) / 1e9 if measure else None
        return dict(name='binary-relay', passed=True, bytes=size, delivered_bytes=size, window_bytes=16384,
                    seconds=elapsed, bytes_per_second=size/elapsed if measure else None,
                    broker_peak=peak, fixture_sha256=hashlib.sha256(data).hexdigest())
    finally:
        h.close()



def latency(args, measure=False):
    h, st = setup(args, 'relay')
    payload = expected(256)
    operations = 64
    try:
        (h.directory / 'ping.input').write_bytes(payload)
        proc = h.start_client('''exec 7> "$BROKER_TEST_DIR/ping.bytes"
ptybroker attach "$BROKER_TEST_ROOT" stream control handle
ptybroker receive "$handle" 7 event 2000
[[ $event == attached* ]]
printf 'ready\n'
for ((i=0; i<$1; i++)); do
  read -r go
  exec 8< "$BROKER_TEST_DIR/ping.input"
  ptybroker send-fd "$BROKER_TEST_ROOT" stream 8 count
  [[ $count == 256 ]]
  n=0
  while (( n<256 )); do
    ptybroker receive "$handle" 7 event 2000
    [[ $event == output* ]]
    rest=${event#output size=}; bytes=${rest%% *}; off=${rest##*offset=}
    [[ $off == $((i*256+n)) ]]
    ((n+=bytes))
  done
  [[ $n == 256 ]]
  printf 'done\n'
done
ptybroker detach "$handle"
''', operations)
        def line():
            assert select.select([proc.stdout], [], [], 5)[0], 'roundtrip timed out'
            return proc.stdout.readline()
        assert line() == b'ready\n'
        samples = []
        for _ in range(operations):
            start = time.perf_counter_ns() if measure else 0
            proc.stdin.write(b'go\n')
            proc.stdin.flush()
            assert line() == b'done\n'
            if measure:
                samples.append((time.perf_counter_ns()-start)/1e9)
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, (out, err)
        assert (h.directory/'ping.bytes').read_bytes() == payload*operations
        return dict(name='roundtrip-256', passed=True, bytes=256*operations,
                    operations=operations, latency_seconds=samples,
                    seconds=sum(samples) if measure else None,
                    fixture_sha256=hashlib.sha256(payload*operations).hexdigest(),
                    broker_peak=rss(st['broker_pid']))
    finally:
        h.close()


def input_limit(args):
    h, st = setup(args, 'slow-relay')
    try:
        os.kill(st['child_pid'], signal.SIGSTOP)
        # Raw stopped PTY holds only a small kernel queue in addition to the
        # specified 1 MiB broker ring. Failed send-fd input is never retried.
        chunk = expected(16384)
        (h.directory / 'queue.input').write_bytes(chunk * 100)
        result = h.run('''exec 8< "$BROKER_TEST_DIR/queue.input"
total=0
for ((i=0; i<100; i++)); do
  if ptybroker send-fd "$BROKER_TEST_ROOT" stream 8 count; then
    (( total+=count ))
  else
    printf '%s\n' "$total"
    exit 0
  fi
done
exit 92
''')
        accepted = int(result.stdout)
        assert 1048576 <= accepted <= 1048576 + 65536, accepted
        before = rss(st['broker_pid'])
        assert before['VmHWM'] < 32 * 1024**2, before
        p = reader(h, 'drain', accepted)
        os.kill(st['child_pid'], signal.SIGCONT)
        finish_readers(h, [('drain', p)], chunk * (accepted//16384), st['broker_pid'])
        # Ring wrap and renewed acceptance after EAGAIN.
        p = reader(h, 'recovered', 16384, accepted)
        h.send_bytes('stream', chunk)
        finish_readers(h, [('recovered', p)], chunk, st['broker_pid'])
        return dict(name='input-queue-limit', passed=True, accepted_bytes=accepted, broker_peak=before)
    finally:
        if base.same_process(h.processes[st['child_pid']]):
            os.kill(st['child_pid'], signal.SIGCONT)
        h.close()


def api_checks(args):
    h, st = setup(args, 'relay')
    h.sessions.add('lost-output')
    try:
        subscription = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            subscription.settimeout(3)
            subscription.connect(str(h.root / 'stream/control.sock'))
            def packet(kind, payload=b''):
                return struct.pack('=IIIIQ', 0x42505431, kind, len(payload), 0, 0)+payload
            subscription.sendall(packet(7))
            assert struct.unpack('=IIIIQ', subscription.recv(20000)[:24])[1] == 39
            assert struct.unpack('=IIIIQ', subscription.recv(20000)[:24])[1] == 65
            subscription.sendall(packet(3, b'observer-must-not-inject'))
            assert subscription.recv(20000) == b''
            assert h.capture('stream') == b''
        finally:
            subscription.close()
        result = h.run('''before=(/proc/$BASHPID/fd/*)
readonly locked=unchanged
declare -a array
for bad in locked array 'bad-name' 'a[$(printf injected)]'; do
  if ptybroker attach "$BROKER_TEST_ROOT" stream observe "$bad"; then exit 98; fi
done
for ((i=0; i<64; i++)); do
  ptybroker attach "$BROKER_TEST_ROOT" stream observe handle
  ptybroker fd "$handle" fd
  if ptybroker receive "$handle" "$fd" event 0; then exit 93; fi
  if ptybroker receive "$handle" 1 event 60001; then exit 94; fi
  ptybroker detach "$handle"
  if ptybroker fd "$handle" fd; then exit 95; fi
done
after=(/proc/$BASHPID/fd/*)
[[ ${#before[@]} == ${#after[@]} ]]
for op in status list; do
  if [[ $op == list ]]; then
    if ptybroker list "$BROKER_TEST_ROOT" > /dev/full; then exit 96; fi
  else
    if ptybroker status "$BROKER_TEST_ROOT" stream > /dev/full; then exit 97; fi
  fi
done
ptybroker status "$BROKER_TEST_ROOT" stream
if ptybroker create "$BROKER_TEST_ROOT" lost-output -- /bin/true > /dev/full; then exit 99; fi
ptybroker status "$BROKER_TEST_ROOT" lost-output
ptybroker terminate "$BROKER_TEST_ROOT" lost-output
''')
        lines = result.stdout.splitlines()
        assert len(lines) == 2 and base.status_dict(lines[0])['running'] == 1
        for line in lines:
            h.remember(base.status_dict(line))
        h.sessions.discard('lost-output')
        return dict(name='empty-path-repeat-fds-invalid-output', passed=True)
    finally:
        if (h.root/'lost-output').exists():
            h.status('lost-output')
        h.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child(sys.argv[2], sys.argv[3])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bash', type=Path, required=True)
    parser.add_argument('--loadable', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--only', choices=['binary-relay', 'burst-observers', 'sustained', 'input-queue-limit', 'roundtrip-256', 'api'])
    args = parser.parse_args()
    args.bash = args.bash.resolve()
    if args.loadable:
        args.loadable = args.loadable.resolve()
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    cases = {'binary-relay': lambda: relay(args),
             'burst-observers': lambda: stream(args, 'burst-observers', 4*1024**2, 16384, 250, 3, True),
             'sustained': lambda: stream(args, 'sustained', 8*1024**2, 8192, 1000, 2),
             'roundtrip-256': lambda: latency(args),
             'input-queue-limit': lambda: input_limit(args), 'api': lambda: api_checks(args)}
    results = []
    for name, run in cases.items():
        if args.only and name != args.only:
            continue
        try:
            result = run()
        except Exception as error:
            result = dict(name=name, passed=False, error=repr(error))
        results.append(result)
        print(json.dumps(result), flush=True)
    report = dict(passed=all(r['passed'] for r in results), results=results)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
