#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise screen's real panes using private services and raw PTY children.

Use --bash out/bash. For shared builds also supply --load-dir DIR containing
ptybroker.so and screen.so. No fixture uses an existing terminal or session.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import time


CHILD = r'''
import fcntl, json, os, pathlib, signal, struct, sys, termios, time, tty
directory = pathlib.Path(os.environ['SCREEN_TEST_DIR'])
tag = sys.argv[1]
tty.setraw(0)
def identity():
    fields = pathlib.Path('/proc/self/stat').read_text().rsplit(') ', 1)[1].split()
    return {'pid': os.getpid(), 'starttime': int(fields[19])}
def record(suffix):
    temporary = directory / (tag + suffix + '.tmp')
    temporary.write_text(json.dumps(identity()))
    temporary.replace(directory / (tag + suffix))
record('.pid')
os.write(1, ('READY ' + tag + '\n').encode() + b'\x1b[6n')
pending = b''
while True:
    chunk = os.read(0, 4096)
    if not chunk: break
    pending += chunk
    while b'\n' in pending:
        line, pending = pending.split(b'\n', 1)
        with (directory / (tag + '.input')).open('ab') as log:
            log.write(line + b'\n')
        if line == b'size':
            rows, cols, _, _ = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))
            os.write(1, ('SIZE %s %d %d\n' % (tag, rows, cols)).encode())
        elif line == b'bytes':
            os.write(1, b'BINARY:' + bytes(range(256)) + b':END\n')
        elif line == b'flood':
            data = b'F' * (2 * 1024 * 1024) + b'\nFLOOD-END\n\x1b[6n'
            while data:
                data = data[os.write(1, data):]
        elif line == b'fork':
            pid = os.fork()
            if pid == 0:
                os.setsid()
                for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
                    signal.signal(sig, signal.SIG_IGN)
                record('.descendant')
                while True: time.sleep(1)
            os.write(1, b'FORKED\n')
        elif line == b'exit':
            os._exit(17)
        else:
            os.write(1, b'ACK ' + tag.encode() + b' ' + line + b'\n')
'''


def eventually(operation, description, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = operation()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError(f"timed out: {description}")


def identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "starttime": int(fields[19]), "state": fields[0],
                "parent": int(fields[1])}
    except FileNotFoundError:
        return None


def same_process(record):
    current = identity(record["pid"])
    return current and current["starttime"] == record["starttime"]


class Harness:
    def __init__(self, args):
        self.args = args
        self.temporary = tempfile.TemporaryDirectory(prefix="scpb-")
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "state"
        self.fixture = self.directory / "child.py"
        self.fixture.write_text(CHILD)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")
                    and not k.startswith(("BASH_FUNC_", "BASHSCREEN_"))}
        self.env.update(BASHSCREEN_STATE_DIR=str(self.root), SCREEN_TEST_DIR=str(self.directory),
                        SHELL="/does-not-select-the-default-shell")
        self.prefix = "set -e\n"
        if args.load_dir:
            self.env["SCREEN_TEST_LOAD_DIR"] = str(args.load_dir.resolve())
            self.prefix += ('enable -f "$SCREEN_TEST_LOAD_DIR/ptybroker.so" ptybroker\n'
                            'enable -f "$SCREEN_TEST_LOAD_DIR/screen.so" screen\n')
        self.processes = {}
        self.clients = []
        self.sessions = set()
        self.checks = []

    def argv(self, command):
        return [str(self.args.bash.resolve()), "--noprofile", "--norc", "-c",
                self.prefix + '"$@"', "_", *map(str, command)]

    def run(self, *command, rc=0, extra=None):
        result = subprocess.run(self.argv(command), env={**self.env, **(extra or {})},
                                input=b"", capture_output=True, timeout=15)
        assert result.returncode == rc, (command, result.returncode, result.stdout, result.stderr)
        return result.stdout

    def start(self, name, tag):
        self.sessions.add(name)
        self.run("screen", "run", "-n", name, "--", sys.executable, self.fixture, tag)
        self.track(tag)

    def track(self, tag):
        path = self.directory / (tag + ".pid")
        eventually(path.exists, f"{tag} readiness")
        record = json.loads(path.read_text())
        self.track_pid(record["pid"])
        return record

    def track_pid(self, pid):
        record = identity(pid)
        assert record, pid
        self.processes[record["pid"]] = record
        child = identity(record["pid"])
        assert child, pid
        parent = identity(child["parent"])
        if parent and parent["pid"] > 1 and parent["pid"] != os.getpid():
            self.processes[parent["pid"]] = parent

    def capture(self, name="demo", target=None, lines=None):
        command = ["screen", "capture-pane", name]
        if target:
            command += ["-p", target]
        if lines is not None:
            command += ["-N", lines]
        return self.run(*command)

    def input(self, tag):
        path = self.directory / (tag + ".input")
        return path.read_bytes() if path.exists() else b""

    def send(self, text, *, target=None, name="demo"):
        command = ["screen", "send-keys", name]
        if target:
            command += ["-p", target]
        self.run(*command, text)

    def size(self, target, tag, rows, cols):
        self.send("size", target=target)
        expected = f"SIZE {tag} {rows} {cols}\n".encode()
        eventually(lambda: expected in self.capture(target=target), expected)

    def status(self, name, target):
        window, pane = target.split(":")
        broker_id = (self.root / name / "windows" / window / "panes" / pane / "broker-id").read_text().strip()
        output = self.run("ptybroker", "status", self.root / name / "brokers", broker_id).decode().strip()
        if output.startswith("{"):
            return json.loads(output)
        return {k: int(v) if v.lstrip("-").isdigit() else v
                for field in shlex.split(output) if "=" in field
                for k, v in [field.split("=", 1)]}

    def attach(self, name="demo", observer=False):
        command = ["screen", "attach", name]
        if observer:
            command += ["-x"]
        process = subprocess.Popen(self.argv(command), env=self.env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.clients.append(process)
        return process

    def read(self, process, timeout=0.2):
        result = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout], [], [], max(0, deadline-time.monotonic()))
            if not ready:
                break
            data = os.read(process.stdout.fileno(), 65536)
            if not data:
                break
            result.extend(data)
        return bytes(result)

    def expect_output(self, process, expected):
        data = bytearray()
        eventually(lambda: (data.extend(self.read(process, 0.1)) or expected in data), expected)
        return bytes(data)

    def capture_pipe(self, unread):
        reader, writer = os.pipe()
        if not unread:
            os.close(reader)
            reader = -1
        before = os.get_blocking(writer)
        code = self.prefix + ('if screen capture-pane demo -p 0:0; then exit 97; fi\n'
                              'printf "caller-returned\\n" >&2\n')
        try:
            started = time.monotonic()
            result = subprocess.run([str(self.args.bash.resolve()), "--noprofile", "--norc", "-c", code],
                                    env=self.env, stdin=subprocess.DEVNULL, stdout=writer,
                                    stderr=subprocess.PIPE, timeout=10)
            elapsed = time.monotonic() - started
            assert result.returncode == 0 and b"caller-returned" in result.stderr, result
            assert os.get_blocking(writer) == before, "capture changed the shared FD flags"
            if unread:
                assert 2.5 <= elapsed < 8, elapsed
        finally:
            os.close(writer)
            if reader >= 0:
                os.close(reader)

    def reap(self):
        for pid in list(self.processes):
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass

    def close(self):
        for process in self.clients:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    stream.close()
        for name in self.sessions:
            if (self.root / name).exists():
                subprocess.run(self.argv(["screen", "kill", name]), env=self.env,
                               capture_output=True, timeout=15)
        for path in self.directory.glob("*.descendant"):
            record = json.loads(path.read_text())
            self.processes[record["pid"]] = record
        for record in self.processes.values():
            if same_process(record):
                try:
                    os.kill(record["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            self.reap()
            if not any(same_process(record) for record in self.processes.values()):
                break
            time.sleep(0.02)
        survivors = [record for record in self.processes.values() if same_process(record)]
        self.temporary.cleanup()
        assert not survivors, ("fixture processes survived", survivors)


def exercise(h):
    h.start("demo", "A")
    first = json.loads((h.directory / "A.pid").read_text())
    h.run("screen", "run", "-n", "demo", rc=1)
    assert same_process(first)
    h.checks.append("creator exits; duplicate run preserves the existing pane")

    h.run("screen", "win-create", "demo", "second", "--", sys.executable, h.fixture, "B")
    h.track("B")
    h.run("screen", "pane-split", "demo", "0", "h", "--", sys.executable, h.fixture, "C")
    h.track("C")
    assert len(h.run("screen", "pane-list", "demo", "0").splitlines()) == 2
    for target, tag in (("0:0", "A"), ("0:1", "C"), ("1:0", "B")):
        h.send("target-" + tag, target=target)
        eventually(lambda: ("target-" + tag).encode() in h.input(tag), tag)
        for other in {"A", "B", "C"} - {tag}:
            assert ("target-" + tag).encode() not in h.input(other)
    h.checks.append("new windows and split panes are persistent, independently targeted PTYs")

    h.size("0:0", "A", 24, 40)
    h.size("0:1", "C", 24, 39)
    h.run("screen", "pane-resize", "demo", "0", "1", "0 41 9 31")
    h.size("0:1", "C", 9, 31)
    h.run("screen", "pane-swap", "demo", "0", "0", "1")
    h.size("0:0", "A", 9, 31)
    h.size("0:1", "C", 24, 40)
    h.run("screen", "pane-resize-dir", "demo", "0", "0", "D", "2")
    h.size("0:0", "A", 11, 31)
    h.checks.append("split, resize, directional resize and swap reach the actual PTY geometry")

    h.run("screen", "pane-select", "demo", "0", "0")
    h.send("focused-A")
    eventually(lambda: b"focused-A" in h.input("A"), "selected pane input")
    h.run("screen", "win-switch", "demo", "1")
    h.send("focused-B")
    eventually(lambda: b"focused-B" in h.input("B"), "selected window input")
    h.run("screen", "win-next", "demo")
    h.send("remembered-A")
    eventually(lambda: b"remembered-A" in h.input("A"), "remembered pane focus")
    h.checks.append("focused input and window cycling preserve each window's selected pane")

    h.send("bytes", target="0:0")
    eventually(lambda: b"BINARY:" + bytes(range(256)) + b":END\n" in h.capture(target="0:0"),
               "binary capture")
    h.send("capture-tail", target="0:0")
    eventually(lambda: h.capture(target="0:0", lines=1) == b"ACK A capture-tail\n", "capture tail")
    h.checks.append("raw capture preserves all 256 byte values and bounds line-tail selection")

    before_offset = h.status("demo", "0:0")["next"]
    h.send("flood", target="0:0")
    flood_size = 2 * 1024 * 1024 + len(b"\nFLOOD-END\n\x1b[6n")
    eventually(lambda: h.status("demo", "0:0")["next"] >= before_offset + flood_size,
               "bounded history flood completion")
    assert len(h.capture(target="0:0")) == 1024 * 1024
    h.capture_pipe(unread=False)
    h.capture_pipe(unread=True)
    h.checks.append("history stays bounded; closed and unread capture pipes return to the shell and restore FD flags")

    before = h.run("screen", "pane-list", "demo", "0")
    h.run("screen", "pane-resize", "demo", "0", "0", "0 0 0 31", rc=1)
    h.run("screen", "pane-split", "demo", "0", "bad", rc=2)
    assert before == h.run("screen", "pane-list", "demo", "0")
    h.checks.append("invalid geometry and split arguments leave the layout intact")

    controller = h.attach()
    eventually(lambda: h.status("demo", "0:0").get("controller"), "controller attachment")
    assert h.read(controller) == b"", "attach replayed historical output or terminal queries"
    h.send("live-A")
    h.expect_output(controller, b"ACK A live-A\n")
    observer = h.attach(observer=True)
    eventually(lambda: h.status("demo", "0:0").get("observers"), "observer attachment")
    assert h.read(observer) == b""
    observer.stdin.write(b"observer-must-not-send\n")
    observer.stdin.flush()
    h.send("broadcast-A")
    h.expect_output(controller, b"ACK A broadcast-A\n")
    h.expect_output(observer, b"ACK A broadcast-A\n")
    assert b"observer-must-not-send" not in h.input("A")
    h.run("screen", "attach", "demo", rc=1)
    h.checks.append("attach has no raw replay; observer input is suppressed and controller ownership is exclusive")

    h.run("screen", "win-switch", "demo", "1")
    eventually(lambda: h.status("demo", "1:0").get("controller") and
               h.status("demo", "1:0").get("observers"), "live focus switch")
    assert h.read(controller) == b"" and h.read(observer) == b""
    h.send("live-B")
    h.expect_output(controller, b"ACK B live-B\n")
    h.expect_output(observer, b"ACK B live-B\n")
    controller.stdin.write(b"\x01d")
    controller.stdin.flush()
    assert controller.wait(timeout=5) == 0
    h.run("screen", "attach", "demo", "-d")
    assert observer.wait(timeout=5) == 0
    assert same_process(first)
    h.checks.append("live clients follow focus and both local and external detach preserve the children")

    h.sessions.add("shell")
    h.run("screen", "run", "-n", "shell")
    h.track_pid(int((h.root / "shell/windows/0/panes/0/pid").read_text()))
    h.send('printf "%s\\n" "$BASH" > "$SCREEN_TEST_DIR/default-shell"', name="shell")
    proof = h.directory / "default-shell"
    eventually(proof.exists, "default shell identity")
    assert Path(proof.read_text().strip()).resolve() == h.args.bash.resolve()
    h.sessions.add("code")
    h.run("screen", "run", "-n", "code", "-c",
          'printf "%s\\n" "$BASH" > "$SCREEN_TEST_DIR/code-shell"; read -r')
    h.track_pid(int((h.root / "code/windows/0/panes/0/pid").read_text()))
    proof = h.directory / "code-shell"
    eventually(proof.exists, "explicit code shell identity")
    assert Path(proof.read_text().strip()).resolve() == h.args.bash.resolve()
    h.checks.append("default and explicit code execution use the current bash-os executable despite SHELL")

    h.start("tree", "tree")
    h.send("fork", name="tree")
    descendant_file = h.directory / "tree.descendant"
    eventually(descendant_file.exists, "resistant descendant")
    descendant = json.loads(descendant_file.read_text())
    h.processes[descendant["pid"]] = descendant
    h.send("exit", name="tree")
    eventually(lambda: h.status("tree", "0:0").get("running") == 0, "direct child exit")
    assert same_process(descendant), "fixture did not retain its resistant descendant"
    h.run("screen", "kill", "tree")
    eventually(lambda: not same_process(descendant), "descendant termination after leader exit")
    h.checks.append("session kill finishes resistant descendant termination after direct child exit")

    c_pid = json.loads((h.directory / "C.pid").read_text())
    h.run("screen", "pane-kill", "demo", "0", "1")
    eventually(lambda: not same_process(c_pid), "pane termination")
    assert h.run("screen", "pane-split", "demo", "0", "h", "--",
                 sys.executable, h.fixture, "reused") == b"1\n"
    h.track("reused")
    h.size("0:1", "reused", 11, 15)
    h.run("screen", "pane-kill", "demo", "0", "1")
    b_pid = json.loads((h.directory / "B.pid").read_text())
    h.run("screen", "win-kill", "demo", "1")
    eventually(lambda: not same_process(b_pid), "window termination")
    assert b"0:0" in h.run("screen", "state", "demo")
    h.checks.append("pane and window kill finish service cleanup, allow immediate ID reuse and repair focus")

    h.sessions.add("offline")
    h.run("screen", "run", "-n", "offline", "--metadata")
    assert not (h.root / "offline" / "brokers").exists()
    h.run("screen", "send-keys", "offline", "no-pretend-input", rc=1)
    h.run("screen", "kill", "offline")
    long_root = h.directory / ("long-" + "x" * 75)
    long_root.mkdir(mode=0o700)
    h.run("screen", "run", "-n", "too-long", rc=1,
          extra={"BASHSCREEN_STATE_DIR": str(long_root)})
    assert not (long_root / "too-long").exists()
    h.checks.append("offline mode is explicit and overlong service paths fail without abandoned layouts")

    # Independent creators contend on the layout lock; no ID or live pane
    # may be silently replaced when the calls come from different shells.
    creators = []
    for i in range(4):
        command = ["screen", "win-create", "demo", f"parallel-{i}", "--",
                   sys.executable, h.fixture, f"parallel-{i}"]
        creator = subprocess.Popen(h.argv(command), env=h.env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        creators.append(creator)
        h.clients.append(creator)
    indexes = []
    for i, creator in enumerate(creators):
        output, error = creator.communicate(timeout=15)
        assert creator.returncode == 0, (output, error)
        indexes.append(int(output))
        h.track(f"parallel-{i}")
    assert len(set(indexes)) == len(creators)
    h.checks.append("concurrent creators allocate distinct live windows without replacing sessions")

    for name in sorted(h.sessions):
        if (h.root / name).exists():
            h.run("screen", "kill", name)
    def stopped():
        h.reap()
        return not any(same_process(record) for record in h.processes.values())
    eventually(stopped, "all owned service processes gone")
    h.checks.append("all owned pane children and brokers are gone after session cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", type=Path, default=Path("out/bash"))
    parser.add_argument("--load-dir", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    # Reap orphaned fixture brokers without asking PID 1 to collect them.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
    h = Harness(args)
    try:
        exercise(h)
        result = {"passed": True, "checks": h.checks, "bash": str(args.bash.resolve()),
                  "mode": "shared" if args.load_dir else "compiled"}
    finally:
        h.close()
    if args.report:
        args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
