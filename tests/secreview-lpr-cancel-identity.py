#!/usr/bin/env python3
"""lpr cancel must write the control FIFO and must not signal a sidecar pid.

A live sleep process, identified with a pidfd taken before cancel, is
named in the job's .lpr.pid file. Cancel has to deliver one byte on the
FIFO when a reader holds it, and has to report a stale job without
signalling when no reader holds it. The sleep process must still be the
same process afterwards.
"""
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
if BINARY is None or not BINARY.is_file():
    sys.exit("usage: secreview-lpr-cancel-identity.py BASH")

JOB = "0123456789abcdef"
CASES = (
    ("default", ""),
    ("trapped", "trap 'printf unexpected-PIPE' PIPE; "),
    ("ignored", "trap '' PIPE; "),
)


def still_same(pid, pidfd, start):
    """The pidfd was opened on this pid before cancel. A recycled pid would
    show a different starttime, and a delivered fatal signal would make
    waitid report the exit."""
    try:
        waited = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
    except OSError as exc:
        return f"pidfd wait failed: {exc}"
    if waited is not None:
        return f"victim exited: {waited}"
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError as exc:
        return f"victim stat unreadable: {exc}"
    after = text[text.rfind(")") + 2 :].split()
    if len(after) < 20 or after[19] != start:
        shown = after[19] if len(after) >= 20 else after
        return f"starttime changed: {start!r} -> {shown!r}"
    return None


def starttime(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    after = text[text.rfind(")") + 2 :].split()
    return after[19]


def one(disposition, setup, live):
    victim = subprocess.Popen(
        ["/bin/sleep", "60"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pidfd = os.pidfd_open(victim.pid)
    started = starttime(victim.pid)
    reader = -1
    try:
        with tempfile.TemporaryDirectory(prefix="sr-lpr-id-") as temporary:
            spool = Path(temporary) / "spool"
            spool.mkdir(mode=0o700)
            (spool / f"{JOB}.lpr").write_bytes(b"owned fixture")
            (spool / f"{JOB}.lpr.pid").write_text(f"{victim.pid}\n")
            fifo = spool / f"{JOB}.ctl"
            os.mkfifo(fifo, 0o600)
            if live:
                reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            script = (
                "PATH=\n"
                + setup
                + 'before=$(trap -p PIPE); '
                + f"lpr cancel {JOB}; rc=$?; "
                + '[[ $(trap -p PIPE) == "$before" ]] || { printf "trap-changed\\n"; exit 91; }; '
                + 'printf "survived status=%s\\n" "$rc"'
            )
            proc = subprocess.Popen(
                [str(BINARY), "--noprofile", "--norc", "-c", script],
                env={"PATH": "/usr/bin:/bin", "BASHLPR_SPOOL": str(spool), "HOME": temporary},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                payload = b""
                if live:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and payload == b"":
                        ready, _, _ = select.select([reader], [], [], 0.2)
                        if ready:
                            payload = os.read(reader, 8)
                    os.close(reader)
                    reader = -1
                out, err = proc.communicate(timeout=8)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            label = f"lpr cancel {disposition} {'live' if live else 'stale'}"
            reason = still_same(victim.pid, pidfd, started)
            text = out + err
            problems = []
            if reason:
                problems.append(reason)
            if proc.returncode != 0:
                problems.append(f"rc={proc.returncode}")
            if b"unexpected-PIPE" in text or b"trap-changed" in out:
                problems.append("disposition changed")
            if b"survived status=" not in out:
                problems.append("shell did not return")
            if live:
                if payload != b"c":
                    problems.append(f"fifo byte {payload!r}")
                if b"handled" not in out:
                    problems.append("missing handled")
            else:
                if b"nothing signalled" not in out:
                    problems.append("missing nothing signalled")
            if problems:
                sys.exit(f"FAIL {label}: {'; '.join(problems)}\nout={out!r}\nerr={err!r}")
            print(f"PASS {label}; victim pid {victim.pid} still live")
    finally:
        if reader >= 0:
            os.close(reader)
        os.close(pidfd)
        if victim.poll() is None:
            victim.send_signal(signal.SIGTERM)
            try:
                victim.wait(timeout=2)
            except subprocess.TimeoutExpired:
                victim.kill()


def main():
    for disposition, setup in CASES:
        one(disposition, setup, live=True)
    one("default", "", live=False)


if __name__ == "__main__":
    main()
