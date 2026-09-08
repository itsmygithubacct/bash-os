#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Force broker output backpressure without relying on PTY read chunk sizes.

A private, same-user protocol fixture sends one 10000-byte event. This lets
the tests distinguish a partially delivered event from a completely queued
event and detect both missing bytes and duplicate bytes after retry.
"""

import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time


MAGIC = 0x42505431
OPEN_OBSERVER, REPLY, OUTPUT, ATTACHED = 7, 32, 64, 65
PAYLOAD = (bytes(range(256)) * 40)[:10000]


class Status(ctypes.Structure):
    """The local protocol uses the service process's native C ABI."""

    _fields_ = [(name, ctypes.c_int32) for name in
                ("broker_pid", "child_pid", "running", "stopping", "exit_status")]
    _fields_ += [(name, ctypes.c_uint32) for name in
                 ("rows", "cols", "controller", "observers")]
    _fields_ += [("oldest", ctypes.c_uint64), ("next", ctypes.c_uint64)]


def packet(kind, data):
    return struct.pack("=IIIIQ", MAGIC, kind, len(data), 0, 0) + data


class Peer:
    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ptybroker-io-")
        self.root = Path(self.temporary.name)
        session = self.root / "session"
        session.mkdir(mode=0o700)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server.bind(str(session / "control.sock"))
        os.chmod(session / "control.sock", 0o600)
        self.server.listen()
        self.server.settimeout(5)
        self.errors = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        try:
            connection, _ = self.server.accept()
            with connection:
                connection.settimeout(5)
                header = connection.recv(20000)
                assert struct.unpack("=IIIIQ", header) == (MAGIC, OPEN_OBSERVER, 0, 0, 0)
                status = bytes(Status(os.getpid(), os.getpid(), 1, 0, -1,
                                      24, 80, 0, 1, 0, len(PAYLOAD)))
                connection.sendall(packet(OPEN_OBSERVER + REPLY, status))
                connection.sendall(packet(ATTACHED, status))
                connection.sendall(packet(OUTPUT, PAYLOAD))
                while connection.recv(20000):
                    pass
        except Exception as error:
            self.errors.append(repr(error))

    def __exit__(self, exc_type, exc, traceback):
        self.thread.join(5)
        self.server.close()
        self.temporary.cleanup()
        if exc_type is None:
            assert not self.thread.is_alive() and not self.errors, self.errors


def spawn(args, root, fd, script, blocked=()):
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")
                   and not key.startswith("BASH_FUNC_")}
    prefix = 'set -e\nif [[ -n $1 ]]; then enable -f "$1" ptybroker; fi\n'
    return subprocess.Popen(
        [str(args.bash), "--noprofile", "--norc", "-c", prefix + script,
         "ptybroker-io", str(args.loadable) if args.loadable else "", str(root), str(fd)],
        env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, pass_fds=(fd,),
        preexec_fn=(lambda: signal.pthread_sigmask(signal.SIG_BLOCK, blocked)) if blocked else None,
    )


def ready(child, expected):
    assert select.select([child.stdout], [], [], 4)[0], "client did not return from receive"
    actual = child.stdout.readline()
    assert actual == expected, (actual, child.communicate(timeout=2))


def finish(child):
    if child.poll() is None:
        child.kill()
        child.wait(timeout=2)


def partial_output(args):
    with Peer() as peer:
        read_fd, write_fd = os.pipe()
        fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
        original_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        child = spawn(args, peer.root, write_fd, r'''
readonly locked=unchanged
declare -u coerced
if ptybroker attach "$2" session observe locked; then exit 1; fi
if ptybroker attach "$2" session observe coerced; then exit 2; fi
ptybroker attach "$2" session observe handle
exec 7>&"$3"
if ptybroker receive "$handle" 7 locked 0; then exit 3; fi
ptybroker receive "$handle" 7 event 1000
[[ $event == attached* ]] || exit 4
set +e
ptybroker receive "$handle" 7 event 30
code=$?
[[ $code == 124 && $event == attached* ]] || exit 5
printf 'stalled\n'
read -r go
set -e
ptybroker receive "$handle" 7 event 1000
[[ $event == output* ]] || exit 6
ptybroker detach "$handle"
printf 'done\n'
''')
        try:
            ready(child, b"stalled\n")
            assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == original_flags
            received = bytearray(os.read(read_fd, 4096))
            assert received == PAYLOAD[:4096], len(received)
            child.stdin.write(b"continue\n")
            child.stdin.flush()
            deadline = time.monotonic() + 3
            while len(received) < len(PAYLOAD) and time.monotonic() < deadline:
                if select.select([read_fd], [], [], 0.1)[0]:
                    received.extend(os.read(read_fd, 4096))
            stdout, stderr = child.communicate(timeout=3)
            assert child.returncode == 0 and stdout == b"done\n", (child.returncode, stdout, stderr)
            assert received == PAYLOAD
            assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == original_flags
        finally:
            finish(child)
            os.close(read_fd)
            os.close(write_fd)


def blocked_sigpipe(args):
    with Peer() as peer:
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        original_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
        child = spawn(args, peer.root, write_fd, r'''
ptybroker attach "$2" session observe handle
exec 7>&"$3"
ptybroker receive "$handle" 7 event 1000
if ptybroker receive "$handle" 7 event 1000; then exit 1; fi
printf 'ready\n'
read -r go
ptybroker detach "$handle"
''', blocked={signal.SIGPIPE})
        try:
            ready(child, b"ready\n")
            status = dict(line.split(":", 1) for line in
                          Path(f"/proc/{child.pid}/status").read_text().splitlines())
            bit = 1 << (signal.SIGPIPE - 1)
            assert int(status["SigBlk"], 16) & bit
            assert not (int(status["SigPnd"], 16) | int(status["ShdPnd"], 16)) & bit
            assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == original_flags
            stdout, stderr = child.communicate(b"continue\n", timeout=3)
            assert child.returncode == 0, (stdout, stderr)
        finally:
            finish(child)
            os.close(write_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", type=Path, default=Path("out/bash"))
    parser.add_argument("--loadable", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    args.bash = args.bash.resolve()
    if args.loadable:
        args.loadable = args.loadable.resolve()
    results = []
    for test in (partial_output, blocked_sigpipe):
        test(args)
        results.append({"name": test.__name__, "passed": True})
        print(f"ptybroker-io: {test.__name__}: PASS")
    if args.output:
        args.output.write_text(json.dumps({"passed": True, "checks": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
