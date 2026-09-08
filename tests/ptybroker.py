#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the ptybroker builtin with private PTYs and real client processes.

Run against a compiled-in builtin with --bash out/bash, or additionally supply
--loadable /path/to/ptybroker.so to exercise a shared loadable. Linux /proc is
required. No test connects to an existing broker or a live desktop terminal.
"""
import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ptybroker-child.py"


def eventually(operation, description, timeout=5):
    deadline = time.monotonic() + timeout
    value = None
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {description}; last value: {value!r}")


def identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "starttime": int(fields[19]), "state": fields[0]}
    except FileNotFoundError:
        return None


def same_process(record):
    current = identity(record["pid"])
    return bool(current and current["starttime"] == record["starttime"])


def status_dict(output):
    text = output.decode().strip()
    if text.startswith("{"):
        return json.loads(text)
    result = {}
    for field in shlex.split(text):
        if "=" in field:
            key, value = field.split("=", 1)
            try:
                value = int(value)
            except ValueError:
                pass
            result[key] = value
    if not result:
        raise AssertionError(f"unrecognized broker status: {text!r}")
    return result


def field(status, name):
    aliases = {"broker_pid": ("broker",), "child_pid": ("child",),
               "cols": ("columns",), "controller": ("attached",),
               "exit_status": ("exit", "status"), "oldest": ("oldest_offset",),
               "next": ("next_offset",)}
    for key in (name, *aliases.get(name, ())):
        if key in status:
            return status[key]
    raise AssertionError(f"missing {name} in {status}")


class Harness:
    def __init__(self, args):
        self.args = args
        self.temporary = tempfile.TemporaryDirectory(prefix="bash-os-ptybroker-")
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "sessions"
        self.env = {key: value for key, value in os.environ.items()
                    if key not in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")
                    and not key.startswith("BASH_FUNC_")}
        self.env.update(BROKER_TEST_DIR=str(self.directory), BROKER_TEST_ROOT=str(self.root),
                        BROKER_TEST_FIXTURE=str(FIXTURE), BROKER_TEST_PYTHON=sys.executable)
        self.prefix = "set -e\n"
        if args.loadable:
            self.env["BROKER_TEST_LOADABLE"] = str(args.loadable)
            self.prefix += 'enable -f "$BROKER_TEST_LOADABLE" ptybroker\n'
        self.sessions = set()
        self.processes = {}
        self.clients = []

    def argv(self, code, args):
        return [str(self.args.bash), "--noprofile", "--norc", "-c", self.prefix + code,
                "ptybroker-test", *map(str, args)]

    def run(self, code, *args, check=True, timeout=10, pass_fds=()):
        result = subprocess.run(self.argv(code, args), env=self.env, capture_output=True,
                                timeout=timeout, pass_fds=pass_fds)
        if check and result.returncode:
            raise AssertionError({"code": code, "args": list(map(str, args)),
                                  "returncode": result.returncode,
                                  "stdout": result.stdout.decode(errors="replace"),
                                  "stderr": result.stderr.decode(errors="replace")})
        return result

    def start_client(self, code, *args, pass_fds=()):
        client = subprocess.Popen(self.argv(code, args), env=self.env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds)
        self.clients.append(client)
        return client

    def stop_client(self, client, kill=False):
        if client.poll() is None:
            client.kill() if kill else client.terminate()
        output, errors = client.communicate(timeout=3)
        return output, errors

    def remember(self, status):
        for name in ("broker_pid", "child_pid"):
            record = identity(int(field(status, name)))
            if record:
                self.processes[record["pid"]] = record

    def status(self, session):
        result = self.run('ptybroker status "$BROKER_TEST_ROOT" "$1"', session)
        status = status_dict(result.stdout)
        self.remember(status)
        return status

    def fixture_state(self, session, kind="ready"):
        path = self.directory / f"{session}.{kind}.json"
        if not path.exists():
            return None
        state = json.loads(path.read_text())
        if "pid" in state and "starttime" in state:
            self.processes[state["pid"]] = state
        for record in state.get("descendants", []):
            self.processes[record["pid"]] = record
        return state

    def ready(self, session):
        return eventually(lambda: self.fixture_state(session), f"{session} fixture ready")

    def create(self, session, mode="echo", rows=24, cols=80, prefix=""):
        self.sessions.add(session)
        result = self.run(prefix + '''ptybroker create "$BROKER_TEST_ROOT" "$1" \
  --rows "$2" --cols "$3" --cwd "$BROKER_TEST_DIR" -- \
  "$BROKER_TEST_PYTHON" "$BROKER_TEST_FIXTURE" --state "$BROKER_TEST_DIR/$1" "$4"
''', session, rows, cols, mode)
        status = status_dict(result.stdout)
        self.remember(status)
        eventually(lambda: (state if (state := self.fixture_state(session))
                            and state.get("pid") == field(status, "child_pid") else None),
                   f"{session} current fixture ready")
        return status

    def send_bytes(self, session, data):
        payload = self.directory / "input"
        payload.write_bytes(data)
        result = self.run('''exec 8< "$BROKER_TEST_DIR/input"
ptybroker send-fd "$BROKER_TEST_ROOT" "$1" 8 count
printf '%s\n' "$count"
''', session)
        assert int(result.stdout) == len(data), (len(data), result.stdout)

    def fixture_event(self, session, command, timeout=5):
        def complete():
            result = self.fixture_state(session, "event")
            return result if result and result.get("command") == command else None
        return eventually(complete, f"{session} command {command}", timeout)

    def capture(self, session):
        self.run('''exec 7> "$BROKER_TEST_DIR/capture"
ptybroker capture "$BROKER_TEST_ROOT" "$1" 7
''', session)
        return (self.directory / "capture").read_bytes()

    def hold(self, session, role="observe", name="held"):
        marker = self.directory / (name + ".held")
        client = self.start_client('''ptybroker attach "$BROKER_TEST_ROOT" "$1" "$2" handle
printf '%s\n' "$handle" > "$3"
read -r _
''', session, role, marker)
        eventually(lambda: marker.exists() or client.poll() is not None, f"{name} attach")
        assert client.poll() is None, client.communicate()
        return client

    def terminate(self, session):
        self.run('ptybroker terminate "$BROKER_TEST_ROOT" "$1"', session, timeout=8)
        self.sessions.discard(session)

    def reap(self):
        for pid in list(self.processes):
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass

    def close(self):
        errors = []
        for client in self.clients:
            try:
                self.stop_client(client, kill=True)
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        for path in self.directory.glob("*.ready.json"):
            state = json.loads(path.read_text())
            for record in [state, *state.get("descendants", [])]:
                self.processes[record["pid"]] = record
        for session in sorted(self.sessions):
            try:
                result = self.run('ptybroker terminate "$BROKER_TEST_ROOT" "$1"', session,
                                  check=False, timeout=8)
                if result.returncode and any(same_process(p) for p in self.processes.values()):
                    errors.append(f"terminate {session}: {result.stderr.decode(errors='replace')}")
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.reap()
            if not any(same_process(record) for record in self.processes.values()):
                break
            time.sleep(0.02)
        survivors = [record for record in self.processes.values() if same_process(record)]
        for record in survivors:
            try:
                os.kill(record["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        if survivors:
            errors.append(f"cleanup required SIGKILL for {[p['pid'] for p in survivors]}")
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                self.reap()
                if not any(same_process(record) for record in survivors):
                    break
                time.sleep(0.02)
        self.temporary.cleanup()
        if errors:
            raise AssertionError("; ".join(errors))


def persistent_sessions(test):
    first = test.create("first")
    second = test.create("second")
    assert field(first, "child_pid") != field(second, "child_pid")
    for name, created in (("first", first), ("second", second)):
        current = test.status(name)
        assert field(current, "child_pid") == field(created, "child_pid")
        assert field(current, "running") == 1
        assert test.ready(name)["geometry"] == [24, 80]
    listing = test.run('ptybroker list "$BROKER_TEST_ROOT"').stdout
    assert b"first" in listing and b"second" in listing, listing


def binary_io_and_handles(test):
    test.create("binary")
    payload = bytes(range(256))
    (test.directory / "input").write_bytes(b"E" + struct.pack("!I", len(payload)) + payload)
    test.run('''ptybroker attach "$BROKER_TEST_ROOT" binary control handle
ptybroker fd "$handle" socket_fd
if (ptybroker fd "$handle" inherited_fd); then exit 81; fi
exec 7> "$BROKER_TEST_DIR/output"
exec 8< "$BROKER_TEST_DIR/input"
ptybroker send-fd "$BROKER_TEST_ROOT" binary 8 count
[[ $count == 261 ]]
while ptybroker receive "$handle" 7 event 1000; do
  printf '%s\n' "$event" >> "$BROKER_TEST_DIR/events"
done
old=$handle
ptybroker detach "$handle"
ptybroker attach "$BROKER_TEST_ROOT" binary control handle
[[ $old != "$handle" ]]
if ptybroker fd "$old" stale_fd; then exit 82; fi
ptybroker fd "$handle" socket_fd
ptybroker detach "$handle"
if [[ -n ${BROKER_TEST_LOADABLE-} ]]; then
  enable -d ptybroker
  enable -f "$BROKER_TEST_LOADABLE" ptybroker
  ptybroker attach "$BROKER_TEST_ROOT" binary control handle
  [[ $old != "$handle" ]]
  if ptybroker fd "$old" stale_fd; then exit 85; fi
  ptybroker detach "$handle"
fi
''', timeout=8)
    assert (test.directory / "output").read_bytes() == payload
    events = (test.directory / "events").read_text().splitlines()
    assert any(item.startswith("output") for item in events), events
    eventually(lambda: field(test.status("binary"), "controller") == 0, "controller detached")


def bounded_send_fd(test):
    test.create("bounded-input")
    payload = bytes(range(256)) * 128
    (test.directory / "input").write_bytes(b"E" + struct.pack("!I", len(payload)) + payload)
    test.run('''ptybroker attach "$BROKER_TEST_ROOT" bounded-input observe handle
exec 7> "$BROKER_TEST_DIR/output"
exec 8< "$BROKER_TEST_DIR/input"
ptybroker send-fd "$BROKER_TEST_ROOT" bounded-input 8 first
ptybroker send-fd "$BROKER_TEST_ROOT" bounded-input 8 second
ptybroker send-fd "$BROKER_TEST_ROOT" bounded-input 8 third
[[ $first == 16384 && $second == 16384 && $third == 5 ]]
while ptybroker receive "$handle" 7 event 1000; do :; done
ptybroker detach "$handle"
''')
    assert (test.directory / "output").read_bytes() == payload


def explicit_history_without_replay(test):
    test.create("history")
    test.run('ptybroker send "$BROKER_TEST_ROOT" history Q')
    test.fixture_event("history", "Q")
    eventually(lambda: test.capture("history") == b"\x1b[6n", "query captured")
    result = test.run('''ptybroker attach "$BROKER_TEST_ROOT" history observe handle
exec 7> "$BROKER_TEST_DIR/output"
while ptybroker receive "$handle" 7 event 300; do
  printf '%s\n' "$event"
done
ptybroker detach "$handle"
''')
    assert (test.directory / "output").read_bytes() == b"", result.stdout
    assert b"output" not in result.stdout, result.stdout
    assert field(test.status("history"), "running") == 1


def client_limits(test):
    test.create("limits")
    test.hold("limits", "control", "control")
    result = test.run('ptybroker attach "$BROKER_TEST_ROOT" limits control handle', check=False)
    assert result.returncode != 0
    for number in range(8):
        test.hold("limits", name=f"observer-{number}")
    result = test.run('ptybroker attach "$BROKER_TEST_ROOT" limits observe handle', check=False)
    assert result.returncode != 0
    status = test.status("limits")
    assert field(status, "controller") == 1 and field(status, "observers") == 8, status


def geometry_reaches_child(test):
    test.create("geometry", rows=19, cols=71)
    (test.directory / "input").write_bytes(b"S")
    result = test.run('''ptybroker attach "$BROKER_TEST_ROOT" geometry observe handle
exec 7> "$BROKER_TEST_DIR/output"
ptybroker resize "$BROKER_TEST_ROOT" geometry 13 47
exec 8< "$BROKER_TEST_DIR/input"
ptybroker send-fd "$BROKER_TEST_ROOT" geometry 8 count
while ptybroker receive "$handle" 7 event 1000; do
  printf '%s\n' "$event"
done
ptybroker detach "$handle"
''')
    assert (test.directory / "output").read_bytes() == b"SIZE 13 47\n"
    assert b"geometry" in result.stdout, result.stdout
    changed = eventually(lambda: test.fixture_state("geometry", "winch"), "child SIGWINCH")
    assert changed["geometry"] == [13, 47]
    status = test.status("geometry")
    assert field(status, "rows") == 13 and field(status, "cols") == 47, status


def abrupt_client_loss(test):
    test.sessions.add("abrupt")
    creator = test.start_client('''ptybroker create "$BROKER_TEST_ROOT" abrupt -- \
  "$BROKER_TEST_PYTHON" "$BROKER_TEST_FIXTURE" --state "$BROKER_TEST_DIR/abrupt" echo
printf 'ready' > "$BROKER_TEST_DIR/creator.ready"
read -r _
''')
    eventually(lambda: (test.directory / "creator.ready").exists() or creator.poll() is not None,
               "creator published service")
    assert creator.poll() is None, creator.communicate()
    before = test.status("abrupt")
    test.ready("abrupt")
    test.stop_client(creator, kill=True)
    frontend = test.hold("abrupt", "control", "frontend")
    test.stop_client(frontend, kill=True)
    eventually(lambda: field(test.status("abrupt"), "controller") == 0, "dead controller removed")
    after = test.status("abrupt")
    assert field(before, "child_pid") == field(after, "child_pid")
    assert field(after, "running") == 1
    test.send_bytes("abrupt", b"E" + struct.pack("!I", 5) + b"alive")
    test.fixture_event("abrupt", "E")
    assert test.capture("abrupt") == b"alive"


def concurrent_start_collision(test):
    test.sessions.add("collision")
    code = '''ptybroker create "$BROKER_TEST_ROOT" collision -- \
  "$BROKER_TEST_PYTHON" "$BROKER_TEST_FIXTURE" --state "$BROKER_TEST_DIR/collision" echo
'''
    clients = [test.start_client(code), test.start_client(code)]
    results = [client.communicate(timeout=8) for client in clients]
    codes = [client.returncode for client in clients]
    for exit_code, (output, _) in zip(codes, results):
        if exit_code == 0:
            test.remember(status_dict(output))
    assert sum(code == 0 for code in codes) == 1, (codes, results)
    state = test.ready("collision")
    status = test.status("collision")
    assert field(status, "child_pid") == state["pid"]
    before = field(status, "broker_pid")
    assert test.run(code, check=False).returncode != 0
    assert field(test.status("collision"), "broker_pid") == before


def unsafe_paths_rejected(test):
    insecure = test.directory / "insecure"
    insecure.mkdir(mode=0o700)
    insecure.chmod(0o777)
    target = test.directory / "target"
    target.mkdir(mode=0o700)
    link = test.directory / "link"
    link.symlink_to(target, target_is_directory=True)
    test.root.mkdir(mode=0o700)
    (test.root / "linked").symlink_to(target, target_is_directory=True)
    for root, session in ((insecure, "bad"), (link, "bad"), (test.root, "linked"),
                          (test.root, "../escape"), (test.root, "a/b")):
        result = test.run('ptybroker create "$1" "$2" -- /bin/true', root, session, check=False)
        if result.returncode == 0:
            test.remember(status_dict(result.stdout))
            test.run('ptybroker terminate "$1" "$2"', root, session, check=False)
        assert result.returncode != 0, (root, session, result.stdout)
    assert not list(target.iterdir())
    assert not (test.directory / "escape").exists()


def malformed_clients_do_not_stall(test):
    test.create("packets")
    sockets = [path for path in (test.root / "packets").iterdir() if path.is_socket()]
    assert len(sockets) == 1, sockets
    held = []
    try:
        for payload in (None, b"x", b"\0" * 12, b"\xff" * 65536):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            client.settimeout(1)
            client.connect(str(sockets[0]))
            held.append(client)
            if payload is not None:
                try:
                    client.send(payload)
                except OSError as error:
                    assert error.errno in (errno.EMSGSIZE, errno.EPIPE, errno.ECONNRESET)
        started = time.monotonic()
        assert field(test.status("packets"), "running") == 1
        assert time.monotonic() - started < 2, "invalid peers delayed an independent status request"
    finally:
        for client in held:
            client.close()


def output_pressure_is_bounded(test):
    test.create("pressure")
    test.hold("pressure", name="idle-observer")
    size = 8 * 1024 * 1024
    test.send_bytes("pressure", b"P" + struct.pack("!I", size))
    test.fixture_event("pressure", "P", timeout=10)
    status = eventually(lambda: (value if field(value := test.status("pressure"), "next") >= size else None),
                        "all output drained", timeout=5)
    assert field(status, "observers") == 0, status
    oldest, next_offset = field(status, "oldest"), field(status, "next")
    assert oldest > 0 and next_offset - oldest <= 1024 * 1024, status
    data = test.capture("pressure")
    assert len(data) == next_offset - oldest, (len(data), status)
    assert data == (bytes(range(256)) * ((len(data) + 255) // 256))[:len(data)]
    result = test.run('''ptybroker attach "$BROKER_TEST_ROOT" pressure observe handle
exec 7> "$BROKER_TEST_DIR/output"
while ptybroker receive "$handle" 7 event 300; do
  printf '%s\n' "$event"
done
ptybroker detach "$handle"
''')
    assert (test.directory / "output").read_bytes() == b""
    assert b"gap" in result.stdout, result.stdout


def natural_exit_status(test):
    test.create("exit")
    (test.directory / "input").write_bytes(b"X\x07")
    result = test.run('''ptybroker attach "$BROKER_TEST_ROOT" exit observe handle
exec 7> "$BROKER_TEST_DIR/output"
exec 8< "$BROKER_TEST_DIR/input"
ptybroker send-fd "$BROKER_TEST_ROOT" exit 8 count
while ptybroker receive "$handle" 7 event 1000; do
  printf '%s\n' "$event"
done
ptybroker detach "$handle"
''')
    assert b"exit" in result.stdout, result.stdout
    status = test.status("exit")
    assert field(status, "running") == 0 and field(status, "exit_status") == 7, status


def leader_exit_does_not_end_stream(test):
    test.create("leader-exit")
    test.send_bytes("leader-exit", b"F")
    descendant = test.fixture_event("leader-exit", "F")
    test.processes[descendant["pid"]] = descendant
    eventually(lambda: field(test.status("leader-exit"), "running") == 0,
               "original process exited")
    result = test.run('''ptybroker attach "$BROKER_TEST_ROOT" leader-exit observe handle
exec 7> "$BROKER_TEST_DIR/output"
ptybroker send "$BROKER_TEST_ROOT" leader-exit Q
while ptybroker receive "$handle" 7 event 300; do
  printf '%s\n' "$event"
done
ptybroker detach "$handle"
''')
    assert (test.directory / "output").read_bytes() == b"\x1b[6n", result.stdout
    assert not any(line.startswith(b"exit") for line in result.stdout.splitlines()), result.stdout


def termination_reaps_descendants(test):
    test.create("descendants", mode="descendants")
    ready = test.ready("descendants")
    records = [ready, *ready["descendants"], identity(field(test.status("descendants"), "broker_pid"))]
    started = time.monotonic()
    test.terminate("descendants")
    assert time.monotonic() - started < 6
    def all_gone():
        test.reap()
        return not any(same_process(record) for record in records)
    eventually(all_gone, "broker, child and resistant descendant reaped", timeout=3)


def service_drops_inherited_fds(test):
    (test.directory / "startup-hook").write_text(
        'printf ran > "$BROKER_TEST_DIR/startup-hook-ran"\nexit 97\n')
    test.create("fds", prefix='''exec 77> "$BROKER_TEST_DIR/inherited-file"
export BASH_ENV="$BROKER_TEST_DIR/startup-hook"
''')
    assert not (test.directory / "startup-hook-ran").exists()
    ready = test.ready("fds")
    assert not any(str(test.directory / "inherited-file") == target
                   for target in ready["fds"].values()), ready
    pid = field(test.status("fds"), "broker_pid")
    inherited = []
    for path in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if os.readlink(path) == str(test.directory / "inherited-file"):
                inherited.append(path.name)
        except FileNotFoundError:
            pass
    assert not inherited, inherited
    client = test.start_client('''ptybroker attach "$BROKER_TEST_ROOT" fds observe handle
ptybroker fd "$handle" socket_fd
printf '%s\n' "$socket_fd" > "$BROKER_TEST_DIR/socket-fd"
read -r _
''')
    marker = test.directory / "socket-fd"
    eventually(lambda: marker.exists() or client.poll() is not None, "connection FD exposed")
    assert client.poll() is None, client.communicate()
    descriptor = int(marker.read_text())
    info = Path(f"/proc/{client.pid}/fdinfo/{descriptor}").read_text()
    flags = int(info.split("flags:\t", 1)[1].splitlines()[0], 8)
    assert flags & os.O_NONBLOCK and flags & os.O_CLOEXEC, info


def traps_interrupt_receive(test):
    test.create("signals")
    client = test.start_client('''trap 'printf trapped > "$BROKER_TEST_DIR/trapped"' USR1
ptybroker attach "$BROKER_TEST_ROOT" signals observe handle
exec 7>> "$BROKER_TEST_DIR/output"
while ptybroker receive "$handle" 7 event 20; do :; done
printf ready > "$BROKER_TEST_DIR/waiting"
set +e
ptybroker receive "$handle" 7 event 10000
code=$?
printf '%s\n' "$code" > "$BROKER_TEST_DIR/result"
printf done > "$BROKER_TEST_DIR/done"
read -r _
''')
    eventually(lambda: (test.directory / "waiting").exists() or client.poll() is not None,
               "receive started")
    assert client.poll() is None, client.communicate()
    flags = Path(f"/proc/{client.pid}/fdinfo/7").read_text().split("flags:\t", 1)[1].splitlines()[0]
    time.sleep(0.05)
    os.kill(client.pid, signal.SIGUSR1)
    eventually(lambda: (test.directory / "trapped").exists(), "Bash trap executed", timeout=2)
    eventually(lambda: (test.directory / "done").exists(), "interrupted receive returned", timeout=2)
    code = int((test.directory / "result").read_text())
    assert code != 0 and code != 124, code
    after = Path(f"/proc/{client.pid}/fdinfo/7").read_text().split("flags:\t", 1)[1].splitlines()[0]
    assert flags == after, (flags, after)
    assert field(test.status("signals"), "running") == 1


def closed_output_returns_error(test):
    test.create("closed-output")
    test.send_bytes("closed-output", b"E" + struct.pack("!I", 5) + b"hello")
    test.fixture_event("closed-output", "E")
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    try:
        result = test.run('''exec 7>&"$1"
if ptybroker capture "$BROKER_TEST_ROOT" closed-output 7; then exit 83; fi
printf 'capture survived\n'
ptybroker attach "$BROKER_TEST_ROOT" closed-output observe handle
while ptybroker receive "$handle" 7 event 20; do :; done
ptybroker send "$BROKER_TEST_ROOT" closed-output Q
set +e
ptybroker receive "$handle" 7 event 1000
code=$?
[[ $code != 0 && $code != 124 ]] || exit 84
printf 'receive survived\n'
ptybroker detach "$handle"
''', write_fd, pass_fds=(write_fd,))
        assert result.stdout == b"capture survived\nreceive survived\n", result.stdout
        assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == flags
    finally:
        os.close(write_fd)


def unaccepted_start_is_cancelled(test):
    test.root.mkdir(mode=0o700)
    creator, service = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    creator.settimeout(5)
    test.sessions.add("unaccepted")
    process = None
    try:
        descriptor = service.fileno()
        process = test.start_client('''ready_fd=$1
exec 3>&"$ready_fd"
if [[ $ready_fd != 3 ]]; then exec {ready_fd}>&-; fi
export BASH_PTYBROKER_SERVICE=1
ptybroker serve "$BROKER_TEST_ROOT" unaccepted 24 80 "$BROKER_TEST_DIR" \
  "$BROKER_TEST_PYTHON" "$BROKER_TEST_FIXTURE" --state "$BROKER_TEST_DIR/unaccepted" echo
''', descriptor, pass_fds=(descriptor,))
        record = identity(process.pid)
        if record:
            test.processes[process.pid] = record
        service.close()
        ready = creator.recv(16384)
        assert ready, "service closed its readiness socket before reporting startup"
        child = test.ready("unaccepted")
        # Readiness is provisional. Closing without the explicit commit byte
        # simulates creator death or an interrupted create call at this point.
        creator.close()
        output, errors = process.communicate(timeout=6)
        assert process.returncode != 0, (output, errors)
        assert not (test.root / "unaccepted").exists()
        test.sessions.discard("unaccepted")
        def child_gone():
            test.reap()
            return not same_process(child)
        eventually(child_gone, "unaccepted startup child removed")
    finally:
        creator.close()
        service.close()


def renamed_session_cannot_remove_replacement(test):
    original = test.create("owned")
    (test.root / "owned").rename(test.root / "moved")
    test.sessions.add("moved")
    replacement = test.create("owned")
    assert field(original, "broker_pid") != field(replacement, "broker_pid")
    test.terminate("moved")
    assert not (test.root / "moved" / "control.sock").exists()
    assert (test.root / "owned" / "control.sock").is_socket()
    current = test.status("owned")
    assert field(current, "broker_pid") == field(replacement, "broker_pid")
    assert field(current, "running") == 1
    test.run('ptybroker send "$BROKER_TEST_ROOT" owned Q')
    test.fixture_event("owned", "Q")
    assert test.capture("owned") == b"\x1b[6n"


def restrictive_umask(test):
    test.create("umask", prefix="umask 0777\n")
    for path, mode in ((test.root, 0o700), (test.root / "umask", 0o700),
                       (test.root / "umask" / "control.sock", 0o600)):
        assert path.stat().st_mode & 0o777 == mode, (path, oct(path.stat().st_mode))
    assert field(test.status("umask"), "running") == 1
    test.terminate("umask")
    assert not (test.root / "umask").exists()


CASES = [persistent_sessions, binary_io_and_handles, bounded_send_fd, explicit_history_without_replay,
         client_limits, geometry_reaches_child, abrupt_client_loss, concurrent_start_collision,
         unsafe_paths_rejected, malformed_clients_do_not_stall, output_pressure_is_bounded,
         natural_exit_status, leader_exit_does_not_end_stream, termination_reaps_descendants, service_drops_inherited_fds,
         traps_interrupt_receive, closed_output_returns_error, unaccepted_start_is_cancelled,
         renamed_session_cannot_remove_replacement, restrictive_umask]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", type=Path, default=Path("out/bash"))
    parser.add_argument("--loadable", type=Path)
    parser.add_argument("--only", action="append", choices=[case.__name__ for case in CASES])
    parser.add_argument("--output", type=Path, help="also write the JSON report to this path")
    args = parser.parse_args()
    args.bash = args.bash.resolve()
    if args.loadable:
        args.loadable = args.loadable.resolve()
    # Adopt the private services when their creator Bash exits, allowing the
    # test to reap them even in containers whose PID 1 does not reap children.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
    results = []
    for case in CASES:
        if args.only and case.__name__ not in args.only:
            continue
        test = Harness(args)
        started = time.monotonic()
        entry = {"name": case.__name__, "passed": False}
        try:
            case(test)
            entry["passed"] = True
        except Exception as error:
            entry["error"] = repr(error)
        finally:
            try:
                test.close()
            except Exception as error:
                entry["passed"] = False
                entry["cleanup_error"] = repr(error)
        entry["seconds"] = round(time.monotonic() - started, 3)
        results.append(entry)
        print(f"ptybroker: {case.__name__}: {'PASS' if entry['passed'] else 'FAIL'}", file=sys.stderr)
    report = {"passed": bool(results) and all(entry["passed"] for entry in results), "results": results}
    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
