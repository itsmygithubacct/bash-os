#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only headless pipe controls with readiness established before exec."""
import base64
import errno
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time
import uuid


HOME = Path("/tmp/parity-home")
CANDIDATE = "/opt/bashos-parity/candidate"


def require_guest():
    marker = Path("/etc/bashos-parity-vm")
    info = marker.lstat()
    token = marker.read_text("ascii").strip()
    if (str(uuid.UUID(token)) != token.lower() or not stat.S_ISREG(info.st_mode) or
            info.st_uid != 0 or info.st_mode & 0o022 or
            Path("/sys/class/dmi/id/sys_vendor").read_text("ascii").strip() != "QEMU" or
            os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path("/tmp/parity-case") or os.environ.get("HOME") != str(HOME)):
        raise RuntimeError("refusing outside the unprivileged disposable parity VM")


def write(name, data):
    (HOME / name).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def child():
    # Popen starts a fresh session. Verify the actual input kind and absence of
    # a controlling terminal immediately before replacing this owned child.
    info = os.fstat(0)
    if not stat.S_ISFIFO(info.st_mode):
        raise RuntimeError("stdin is not the owned pipe")
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        if error.errno not in (errno.ENXIO, errno.ENOENT):
            raise
        tty_error = error.errno
    else:
        os.close(fd)
        raise RuntimeError("unexpected controlling terminal")
    write("termpixel-child.json", {"pid": os.getpid(), "sid": os.getsid(0),
          "uid": os.getuid(), "euid": os.geteuid(), "stdin_is_pipe": True,
          "stdin_device": info.st_dev, "stdin_inode": info.st_ino,
          "tty_open_errno": tty_error, "before_exec_ns": time.monotonic_ns()})
    os.execv(CANDIDATE, [CANDIDATE, "--noprofile", "--norc", "-c", "termpixel key-read --timeout 0"])


def observe(mode):
    read_fd, write_fd = os.pipe()
    proc = None
    cleaned = False
    try:
        input_bytes = b"a" if mode == "preloaded" else b""
        prepared_ns = time.monotonic_ns()
        if input_bytes and os.write(write_fd, input_bytes) != len(input_bytes):
            raise RuntimeError("incomplete pipe preload")
        prepared_ns = time.monotonic_ns()
        poller = select.poll()
        poller.register(read_fd, select.POLLIN)
        poll_started_ns = time.monotonic_ns()
        events = poller.poll(0)
        poll_finished_ns = time.monotonic_ns()
        readable = bool(events and events[0][1] & select.POLLIN)
        if readable != bool(input_bytes) or any(flags & (select.POLLERR | select.POLLHUP | select.POLLNVAL)
                                               for _, flags in events):
            raise RuntimeError("independent pipe readiness precondition failed")
        pipe_info = os.fstat(read_fd)
        launch_ns = time.monotonic_ns()
        # Keep the writer open without writing again until the consumer exits:
        # empty input means no readiness, not EOF, and no producer scheduling
        # or producer SIGPIPE can determine the result.
        with (HOME / "termpixel.out").open("wb") as out, (HOME / "termpixel.err").open("wb") as err:
            proc = subprocess.Popen(["/usr/bin/python3", str(Path(__file__).resolve()), "child"],
                                    stdin=read_fd, stdout=out, stderr=err, start_new_session=True)
            try:
                status = proc.wait(timeout=3)
                returned_ns = time.monotonic_ns()
            except subprocess.TimeoutExpired as error:
                raise RuntimeError("bounded pipe consumer timed out") from error
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=3)
                cleaned = True
        stdout = (HOME / "termpixel.out").read_bytes()
        stderr = (HOME / "termpixel.err").read_bytes()
        if len(stdout) > 4096 or len(stderr) > 4096:
            raise RuntimeError("consumer output exceeds control bound")
        identity = json.loads((HOME / "termpixel-child.json").read_text())
        if (identity["pid"] != proc.pid or identity["sid"] != proc.pid or
                identity["stdin_device"] != pipe_info.st_dev or identity["stdin_inode"] != pipe_info.st_ino or
                not (prepared_ns <= launch_ns <= identity["before_exec_ns"] <= returned_ns)):
            raise RuntimeError("owned child, pipe, or preload ordering differs")
        expected = b"a\n" if mode == "preloaded" else b"TIMEOUT\n"
        checks = {"status_zero": status == 0, "exact_stdout": stdout == expected, "stderr_empty": not stderr}
        write("termpixel-pipe-observation.json", {"mode": mode, "input_base64": base64.b64encode(input_bytes).decode(),
              "ready_before_launch": readable, "poll_events": events, "prepared_ns": prepared_ns,
              "readiness_poll_started_ns": poll_started_ns, "readiness_poll_finished_ns": poll_finished_ns,
              "readiness_poll_elapsed_ns": poll_finished_ns - poll_started_ns,
              "launch_ns": launch_ns, "returned_ns": returned_ns,
              "exec_to_observed_exit_ns": returned_ns - identity["before_exec_ns"],
              "child": identity, "writer_kept_open_until_exit": True,
              "status": status, "stdout_base64": base64.b64encode(stdout).decode(),
              "stderr_base64": base64.b64encode(stderr).decode(), "checks": checks})
        if not all(checks.values()):
            print("pipe result mismatch: " + json.dumps(checks, sort_keys=True), file=sys.stderr)
            return 1
        print(mode + ": ok")
        return 0
    finally:
        if proc is not None and not cleaned:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=3)
        os.close(read_fd)
        os.close(write_fd)


def main():
    require_guest()
    if sys.argv[1:] == ["child"]:
        child()
    elif len(sys.argv) == 2 and sys.argv[1] in ("preloaded", "empty"):
        return observe(sys.argv[1])
    else:
        raise ValueError("invalid control mode")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        try:
            write("termpixel-pipe-error.json", {"error": str(error)})
        except OSError:
            pass
        print("pipe observation error: " + str(error), file=sys.stderr)
        raise SystemExit(125)
