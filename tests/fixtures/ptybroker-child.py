#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Raw PTY fixture used only by tests/ptybroker.py's private sessions."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import struct
import termios
import tty


def write_all(fd, data):
    while data:
        count = os.write(fd, data)
        data = data[count:]


def read_exact(count):
    result = bytearray()
    while len(result) < count:
        block = os.read(0, count - len(result))
        if not block:
            raise EOFError
        result.extend(block)
    return bytes(result)


def process_identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    return {"pid": pid, "starttime": int(fields[19])}


def atomic_json(path, value):
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value) + "\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def geometry():
    return list(struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))[:2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("mode", choices=("echo", "descendants"))
    args = parser.parse_args()
    tty.setraw(0)
    ready = args.state.with_suffix(".ready.json")
    events = args.state.with_suffix(".event.json")
    signal_file = args.state.with_suffix(".winch.json")
    state = {**process_identity(os.getpid()), "pgrp": os.getpgrp(),
             "sid": os.getsid(0), "geometry": geometry(), "fds": {}}
    for fd in Path("/proc/self/fd").iterdir():
        try:
            state["fds"][fd.name] = os.readlink(fd)
        except FileNotFoundError:
            pass
    signal.signal(signal.SIGWINCH,
                  lambda *_: atomic_json(signal_file, {"geometry": geometry()}))

    if args.mode == "descendants":
        read_fd, write_fd = os.pipe()
        descendant = os.fork()
        if descendant == 0:
            os.close(read_fd)
            os.setsid()
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            write_all(write_fd, json.dumps(process_identity(os.getpid())).encode())
            os.close(write_fd)
            while True:
                signal.pause()
        os.close(write_fd)
        data = bytearray()
        while block := os.read(read_fd, 4096):
            data.extend(block)
        os.close(read_fd)
        state["descendants"] = [json.loads(data)]
        atomic_json(ready, state)
        while True:
            signal.pause()

    atomic_json(ready, state)
    sequence = 0
    while True:
        try:
            command = read_exact(1)
            sequence += 1
            event = {"command": command.decode("ascii"), "sequence": sequence}
            if command == b"E":
                size = struct.unpack("!I", read_exact(4))[0]
                write_all(1, read_exact(size))
                event["bytes"] = size
            elif command == b"S":
                rows, columns = geometry()
                write_all(1, f"SIZE {rows} {columns}\n".encode())
                event["geometry"] = [rows, columns]
            elif command == b"Q":
                write_all(1, b"\x1b[6n")
            elif command == b"P":
                remaining = struct.unpack("!I", read_exact(4))[0]
                event["bytes"] = remaining
                block = bytes(range(256)) * 256
                while remaining:
                    part = block[:remaining]
                    write_all(1, part)
                    remaining -= len(part)
            elif command == b"X":
                code = read_exact(1)[0]
                atomic_json(events, {**event, "exit": code})
                os._exit(code)
            elif command == b"F":
                # Keep a descendant on the PTY after the original process has
                # exited, exposing stream-completion versus leader-exit bugs.
                signal.signal(signal.SIGHUP, signal.SIG_IGN)
                if os.fork() != 0:
                    os._exit(7)
                event.update(process_identity(os.getpid()))
            else:
                raise ValueError(f"unknown fixture command {command!r}")
            atomic_json(events, event)
        except (EOFError, OSError):
            return


if __name__ == "__main__":
    main()
