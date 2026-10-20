#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private live screen relay checks; no compilation. See docs/sol-screen.md."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import termios
import threading
import time

spec = importlib.util.spec_from_file_location("screen_broker", Path(__file__).with_name("screen-broker.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

PATTERN = bytes((i * 73 + i // 256 + 19) % 256 for i in range(65536))
TOTAL = 8 * 1024 * 1024
WINDOW = 65536
LITERAL = ["", "two words", "$(touch forbidden)", "; exit 99", "*?[abc]", "'\"\\", "line\nbreak"]
CHILD = r'''
import json, os, pathlib, sys, tty
directory = pathlib.Path(os.environ["SCREEN_TEST_DIR"])
tag = sys.argv[1]
tty.setraw(0)
fields = pathlib.Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()
(directory / (tag + ".argv")).write_text(json.dumps(sys.argv[2:]))
(directory / (tag + ".pid.tmp")).write_text(json.dumps(
    {"pid": os.getpid(), "starttime": int(fields[19])}))
(directory / (tag + ".pid.tmp")).replace(directory / (tag + ".pid"))
pattern = bytes((i * 73 + i // 256 + 19) % 256 for i in range(65536))
def write(data):
    while data:
        data = data[os.write(1, data):]
def read(n):
    data = bytearray()
    while len(data) < n:
        chunk = os.read(0, n - len(data))
        if not chunk: raise EOFError()
        data.extend(chunk)
    return bytes(data)
while True:
    line = bytearray()
    while not line.endswith(b"\n"): line.extend(read(1))
    command, count = line.decode().split()
    count = int(count)
    if command == "emit":
        write((pattern * ((count + len(pattern) - 1) // len(pattern)))[:count])
    elif command == "echo":
        data = read(count)
        if count == 1:
            (directory / (tag + ".received.tmp")).write_bytes(data)
            (directory / (tag + ".received.tmp")).replace(directory / (tag + ".received"))
        write(data)
    elif command == "exit":
        write(b"FINAL\x00\xff\n")
        sys.exit(count)
'''


class Reader:
    """A bounded-window oracle: retain a digest and compare each byte immediately."""
    def __init__(self, process, delay=0):
        self.process, self.delay = process, delay
        self.count = 0
        self.error = None
        self.stop = threading.Event()
        self.digest = hashlib.sha256()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.process.stdout], [], [], .1)
                if not ready:
                    continue
                data = os.read(self.process.stdout.fileno(), 4096)
                if not data:
                    break
                expected = (PATTERN * 2)[self.count % len(PATTERN):
                                         self.count % len(PATTERN) + len(data)]
                assert data == expected, ("stream mismatch", self.count)
                self.digest.update(data)
                self.count += len(data)
                if self.delay:
                    time.sleep(self.delay)
        except BaseException as error:
            self.error = error

    def reached(self, count):
        if self.error:
            raise self.error
        assert self.count <= count, ("unexpected extra bytes", self.count, count)
        if self.count < count:
            assert self.process.poll() is None, ("active reader exited", self.process.returncode)
        return self.count == count

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive()
        if self.error:
            raise self.error


def wait(operation, description, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if operation():
            return
        time.sleep(.001)
    raise AssertionError("timed out: " + description)


def rss(pid):
    fields = Path(f"/proc/{pid}/status").read_text().splitlines()
    return {line.split(":")[0]: int(line.split()[1]) * 1024
            for line in fields if line.startswith(("VmRSS:", "VmHWM:"))}


def start(h, tag="A"):
    h.sessions.add("demo")
    h.run("screen", "run", "-n", "demo", "--", sys.executable, h.fixture, tag, *LITERAL)
    h.track(tag)
    assert json.loads((h.directory / (tag + ".argv")).read_text()) == LITERAL


def cleanup(h):
    h.run("screen", "kill", "demo")
    assert not (h.root / "demo").exists()
    def stopped():
        h.reap()
        return not any(base.same_process(record) for record in h.processes.values())
    wait(stopped, "production cleanup, before emergency cleanup")
    for process in h.clients:
        if process.poll() is None:
            process.wait(timeout=5)


def sustained(h, measured=False):
    start(h)
    # Mutate another live pane while the focused stream is in flight.
    h.run("screen", "pane-split", "demo", "0", "h", "--",
          sys.executable, h.fixture, "B", *LITERAL)
    h.track("B")
    assert json.loads((h.directory / "B.argv").read_text()) == LITERAL
    h.run("screen", "pane-select", "demo", "0", "0")
    controller = h.attach()
    observer = h.attach(observer=True)
    stalled = h.attach(observer=True)
    wait(lambda: h.status("demo", "0:0")["observers"] == 2 and
         h.status("demo", "0:0")["controller"] == 1, "three live subscriptions")
    readers = [Reader(controller), Reader(observer, .001)]
    errors = []
    mutation_count = 24
    def mutate():
        try:
            for i in range(mutation_count):
                h.run("screen", "pane-resize", "demo", "0", "1", f"0 41 {10+i%5} 31")
                h.run("screen", "pane-swap", "demo", "0", "0", "1")
        except BaseException as error:
            errors.append(error)
    mutator = threading.Thread(target=mutate)
    status = h.status("demo", "0:0")
    broker_pid = status["broker_pid"]
    before = status["next"]
    peak = {}
    history_peak = 0
    eviction_observed = None
    started = time.perf_counter()
    mutator.start()
    try:
        for offset in range(0, TOTAL, WINDOW):
            controller.stdin.write(f"emit {WINDOW}\n".encode())
            controller.stdin.flush()
            wait(lambda: all(r.reached(offset + WINDOW) for r in readers), "live window")
            for key, value in rss(broker_pid).items():
                peak[key] = max(peak.get(key, 0), value)
            status = h.status("demo", "0:0")
            assert status["next"] - before == offset + WINDOW
            history_size = status["next"] - status["oldest"]
            assert history_size <= 1024 * 1024
            history_peak = max(history_peak, history_size)
            if status["observers"] == 1 and eviction_observed is None:
                eviction_observed = offset + WINDOW
        mutator.join(timeout=20)
        assert not mutator.is_alive()
        if errors:
            raise errors[0]
        elapsed = time.perf_counter() - started
        expected_hash = hashlib.sha256(PATTERN * (TOTAL // len(PATTERN))).hexdigest()
        assert all(r.count == TOTAL and r.digest.hexdigest() == expected_hash for r in readers)
        wait(lambda: h.status("demo", "0:0")["observers"] == 1, "stalled observer eviction")
        assert stalled.wait(timeout=8) == 1, "stalled output must fail visibly"
        status = h.status("demo", "0:0")
        assert status["next"] - before == TOTAL
        assert status["next"] - status["oldest"] == 1024 * 1024
        assert h.capture(target="0:0") == PATTERN * 16
        assert peak["VmHWM"] < 32 * 1024 * 1024, peak
        assert eviction_observed is not None
        # Same stream still works after a slow subscriber has been evicted.
        assert controller.poll() is None and observer.poll() is None
    finally:
        mutator.join(timeout=20)
        for reader in readers:
            reader.close()
    controller.stdin.close()
    assert controller.wait(timeout=5) == 0
    assert controller.stdout.read() == b"", "extra controller output"
    assert h.read(observer, .05) == b"", "extra observer output"
    wait(lambda: h.status("demo", "0:0")["controller"] == 0, "controller EOF")
    observer.stdout.close()
    h.send("emit 65536", target="0:0")
    assert observer.wait(timeout=5) == 1
    wait(lambda: h.status("demo", "0:0")["observers"] == 0, "observer output loss")
    assert base.same_process(json.loads((h.directory / "A.pid").read_text()))
    cleanup(h)
    result = dict(case="sustained", passed=True, unique_bytes=TOTAL,
                  delivered_bytes=TOTAL * 2, sha256=expected_hash, broker_memory=peak,
                  window_bytes=WINDOW, slow_read_bytes=4096, slow_read_delay_s=.001,
                  concurrent_mutations=mutation_count * 2, stalled_observer_exit=1,
                  history_peak_bytes=history_peak,
                  stalled_eviction_observed_by_output_bytes=eviction_observed)
    if measured:
        result.update(seconds=elapsed, mib_per_second=TOTAL / elapsed / 1024**2)
    return result


def read_exact(process, size):
    data = bytearray()
    deadline = time.monotonic() + 10
    while len(data) < size:
        assert time.monotonic() < deadline, ("short output", len(data), size)
        ready, _, _ = select.select([process.stdout], [], [], .1)
        if ready:
            chunk = os.read(process.stdout.fileno(), size - len(data))
            assert chunk, ("early EOF", process.poll(), len(data), size)
            data.extend(chunk)
    return bytes(data)


def roundtrip(h, measured=False):
    start(h)
    controller = h.attach()
    wait(lambda: h.status("demo", "0:0")["controller"], "controller")
    samples = []
    for i in range(64):
        data = PATTERN[i:i+256]
        # screen's prefix is an intentional input protocol, so quote literal ^A.
        packet = b"echo 256\n" + data.replace(b"\x01", b"\x01\x01")
        started = time.perf_counter()
        controller.stdin.write(packet)
        controller.stdin.flush()
        assert read_exact(controller, 256) == data
        samples.append(time.perf_counter() - started)
    h.send("exit 17")
    assert read_exact(controller, 8) == b"FINAL\x00\xff\n"
    assert controller.wait(timeout=5) == 0
    assert controller.stdout.read() == b"", "extra bytes after child exit"
    status = h.status("demo", "0:0")
    assert status["running"] == 0 and status["exit_status"] == 17, status
    cleanup(h)
    result = dict(case="roundtrip", passed=True, requests=64, request_bytes=256,
                  delivered_bytes=64*256, child_exit=17)
    if measured:
        result["latency_seconds"] = samples
    return result


def binary_relay(h, measured=False):
    start(h)
    controller = h.attach()
    wait(lambda: h.status("demo", "0:0")["controller"], "controller")
    size = 2 * 1024 * 1024 + 719
    data = (PATTERN * ((size + len(PATTERN) - 1) // len(PATTERN)))[:size]
    digest = hashlib.sha256()
    started = time.perf_counter()
    for offset in range(0, size, 16384):
        chunk = data[offset:offset + 16384]
        controller.stdin.write(f"echo {len(chunk)}\n".encode() +
                               chunk.replace(b"\x01", b"\x01\x01"))
        controller.stdin.flush()
        received = read_exact(controller, len(chunk))
        assert received == chunk, offset
        digest.update(received)
    elapsed = time.perf_counter() - started
    assert digest.hexdigest() == hashlib.sha256(data).hexdigest()
    controller.stdin.write(b"\x01d")
    controller.stdin.flush()
    assert controller.wait(timeout=5) == 0
    assert controller.stdout.read() == b"", "extra bytes after final echo"
    cleanup(h)
    result = dict(case="binary-relay", passed=True, input_bytes=size, delivered_bytes=size,
                  window_bytes=16384, sha256=digest.hexdigest())
    if measured:
        result.update(seconds=elapsed, mib_per_second=size / elapsed / 1024**2)
    return result


def eof_prefix(h, measured=False):
    start(h)
    controller = h.attach()
    wait(lambda: h.status("demo", "0:0")["controller"], "controller")
    controller.stdin.write(b"echo 1\n\x01")
    controller.stdin.flush()
    # Wait for the input read to retain the prefix, then close its pipe.
    time.sleep(.15)
    controller.stdin.close()
    assert controller.wait(timeout=5) == 0
    path = h.directory / "A.received"
    wait(lambda: path.exists(), "literal pending prefix delivered at pipe EOF", timeout=3)
    assert path.read_bytes() == b"\x01"
    cleanup(h)
    return dict(case="eof-prefix", passed=True)


def repeated(h, measured=False):
    start(h)
    index = h.run("screen", "win-create", "demo", "literal", "--",
                  sys.executable, h.fixture, "C", *LITERAL).decode().strip()
    h.track("C")
    assert json.loads((h.directory / "C.argv").read_text()) == LITERAL
    h.run("screen", "win-switch", "demo", "0")
    code = h.prefix + '''
before=(/proc/$$/fd/*)
for ((i=0; i<32; i++)); do
    screen attach demo </dev/null >/dev/null
    screen state demo >/dev/null
    if screen pane-resize demo 0 0 '0 0 0 80' 2>/dev/null; then exit 90; fi
done
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]]
'''
    result = subprocess.run([str(h.args.bash.resolve()), "--noprofile", "--norc", "-c", code],
                            env=h.env, capture_output=True, timeout=30)
    assert result.returncode == 0, (result.stdout, result.stderr)
    # Exercise raw-mode setup/restoration on an owned frontend PTY.
    master, slave = os.openpty()
    saved = termios.tcgetattr(slave)
    try:
        process = subprocess.Popen(h.argv(["screen", "attach", "demo"]), env=h.env,
                                   stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        h.clients.append(process)
        wait(lambda: h.status("demo", "0:0")["controller"], "private frontend attached")
        assert not (termios.tcgetattr(slave)[3] & termios.ICANON)
        os.write(master, b"\x01d")
        assert process.wait(timeout=5) == 0
        assert termios.tcgetattr(slave) == saved
    finally:
        os.close(master)
        os.close(slave)
    cleanup(h)
    return dict(case="repeated", passed=True, same_shell_attach_cycles=32,
                frontend_termios_restored=True, literal_window=index)


CASES = {"sustained": sustained, "binary-relay": binary_relay, "roundtrip": roundtrip,
         "eof-prefix": eof_prefix, "repeated": repeated}


def run_case(args, case, measured=False):
    h = base.Harness(args)
    h.env["PATH"] = ""
    h.fixture.write_text(CHILD)
    try:
        return CASES[case](h, measured)
    finally:
        h.close()


def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", type=Path, required=True)
    parser.add_argument("--load-dir", type=Path)
    parser.add_argument("--case", choices=CASES, action="append")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    subreaper()
    results = []
    try:
        for case in args.case or CASES:
            result = run_case(args, case)
            results.append(result)
            print(json.dumps(result), flush=True)
    except BaseException as error:
        results.append(dict(case=case, passed=False, error=repr(error)))
        raise
    finally:
        args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
