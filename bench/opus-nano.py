#!/usr/bin/env python3
"""Time whole nano editing sessions at several buffer sizes.

Each sample starts a bash-os shell on a private PTY (24x80, TERM=xterm,
LANG=C.UTF-8, empty PATH), runs one editor on a fresh copy of a fixed
fixture, feeds a fixed keystroke stream, and stops the clock when the
shell exits.  The saved file must hash to the value computed here
independently of either editor, on every warm-up and timed pass;
a sample whose file or exit status differs invalidates the case.

Workloads (W = fixture size):
  open-exit  open the file and quit                      (load + first frame)
  save       insert one byte at the top, ^S, quit        (load + one edit + atomic save)
  edit       go to the middle line (^_), type 400 bytes, delete 100 with
             Backspace, type 10 x (Enter + "line"), ^S, quit
             (550 edit keystrokes sent in bursts, coalesced frames, then a save)

Implementations: the nano builtin of each --binary, and optionally GNU nano
(--gnu PATH) started by the same shell with --ignorercfiles.  GNU nano is
a matched reference only in the sense that it receives identical keys and
must produce a byte-identical file; its drawing strategy differs.

Usage: bench/opus-nano.py --binary out/bash-x [--binary out/bash-y]
           [--gnu /usr/bin/nano] [--sizes 16384,1048576,8388608]
           [--runs 7] [--warmup 1] [--cpu N] --output report.json
"""
import argparse
import hashlib
import json
import os
import platform
import pty
import select
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import termios
import fcntl
import time
from pathlib import Path

LINE = "{:07d} lorem ipsum dolor sit amet consectetur adipiscing elit\n"
TYPED = "the quick brown fox " * 20          # 400 bytes
TAIL = "\rline" * 10                         # Enter + "line", ten times


def fixture(size):
    out, i, n = [], 0, 0
    while n < size:
        s = LINE.format(i)
        out.append(s)
        n += len(s)
        i += 1
    data = "".join(out).encode()[:size]
    if not data.endswith(b"\n"):
        data = data[:-1] + b"\n"
    return data


def workload(name, data):
    """Return (keys, expected bytes, work description)."""
    lines = data.split(b"\n")
    if name == "open-exit":
        return b"\x18", data, "load, one frame, exit"
    if name == "save":
        return b"Z\x13\x18", b"Z" + data, "load, 1 insert, atomic save, exit"
    if name == "edit":
        n_lines = data.count(b"\n")
        mid = n_lines // 2 + 1                                  # 1-based
        keys = (b"\x1f" + str(mid).encode() + b"\r" + TYPED.encode()
                + b"\x7f" * 100 + TAIL.encode() + b"\x13\x18")
        inserted = TYPED[:300].encode() + TAIL.replace("\r", "\n").encode()
        off = sum(len(l) + 1 for l in lines[:mid - 1])
        return keys, data[:off] + inserted + data[off:], \
            f"goto line {mid}, 400 typed + 100 backspace + 10 newline + 40 typed = 550 edit keys, save"
    raise ValueError(name)


def session(binary, script, cwd, keys, cpu):
    env = {"TERM": "xterm", "LANG": "C.UTF-8", "HOME": str(cwd), "PATH": ""}
    t0 = time.perf_counter()
    pid, fd = pty.fork()
    if pid == 0:
        try:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            if cpu is not None:
                os.sched_setaffinity(0, {cpu})
            os.chdir(cwd)
            os.execve(binary, [binary, "--norc", "--noprofile", "-c", script], env)
        finally:
            os._exit(127)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    sent, out_bytes, status = 0, 0, None
    deadline = time.monotonic() + 300
    # Wait for the first frame before typing so no editor sees keys early.
    started = False
    buf = b""
    while status is None:
        if time.monotonic() > deadline:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            os.close(fd)
            raise RuntimeError("session timed out")
        want_write = started and sent < len(keys)
        r, w, _ = select.select([fd], [fd] if want_write else [], [], 0.05)
        if r:
            try:
                data = os.read(fd, 1 << 16)
            except (BlockingIOError, InterruptedError):
                data = None
            except OSError:
                data = b""
            if data:
                out_bytes += len(data)
                if not started:
                    buf += data
                    if b"\x1b[" in buf and (b"\x1b[?25h" in buf or b"\x1b[?12l" in buf or len(buf) > 2000):
                        started = True
            elif data == b"":
                p, st = os.waitpid(pid, 0)
                status = os.waitstatus_to_exitcode(st)
                break
        if w:
            try:
                sent += os.write(fd, keys[sent:sent + 256])
            except BlockingIOError:
                pass
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            status = os.waitstatus_to_exitcode(st)
    elapsed = time.perf_counter() - t0
    os.close(fd)
    return elapsed, status, out_bytes, sent


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", action="append", required=True)
    ap.add_argument("--gnu")
    ap.add_argument("--sizes", default="16384,1048576,8388608")
    ap.add_argument("--workloads", default="open-exit,save,edit")
    ap.add_argument("--runs", type=int, default=7)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--cpu", type=int)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    if args.runs < 7:
        sys.exit("at least seven timed samples are required")

    impls = []
    for b in args.binary:
        b = str(Path(b).resolve())
        impls.append({"name": "bash-os nano " + Path(b).name, "kind": "builtin", "binary": b,
                      "binary_sha256": sha(Path(b).read_bytes()), "script": "nano f.txt"})
    if args.gnu:
        g = str(Path(args.gnu).resolve())
        ver = subprocess.run([g, "--version"], capture_output=True, text=True).stdout.split("\n")[0].strip()
        impls.append({"name": "GNU nano", "kind": "external", "binary": impls[0]["binary"],
                      "editor": g, "editor_version": ver, "editor_sha256": sha(Path(g).read_bytes()),
                      "script": f"{g} --ignorercfiles f.txt"})

    if args.cpu is not None:
        others = sorted(os.sched_getaffinity(0) - {args.cpu})
        if others:
            os.sched_setaffinity(0, {others[0]})

    report = {
        "harness": "bench/opus-nano.py",
        "host": {"kernel": platform.release(), "machine": platform.machine(),
                 "python": platform.python_version(),
                 "cpu_model": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                                    if l.startswith("model name")), None),
                 "editor_cpu": args.cpu, "driver_cpus": sorted(os.sched_getaffinity(0))},
        "method": {"runs": args.runs, "warmup": args.warmup, "pty": "24x80 TERM=xterm LANG=C.UTF-8 PATH=",
                   "clock": "perf_counter from pty.fork to shell exit",
                   "reset": "fixture rewritten from memory before every pass",
                   "validation": "saved file sha256 == independently computed expectation, exit 0, every pass"},
        "implementations": impls,
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="opus-nano-bench.") as tmp:
        d = Path(tmp)
        fs = subprocess.run(["stat", "-f", "-c", "%T", str(d)], capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin"}).stdout.strip()
        report["method"]["fixture_fs"] = fs
        for size in [int(x) for x in args.sizes.split(",")]:
            data = fixture(size)
            for wl in args.workloads.split(","):
                keys, expect, work = workload(wl, data)
                for impl in impls:
                    case = {"workload": wl, "size": size, "fixture_sha256": sha(data),
                            "fixture_lines": data.count(b"\n"), "keys": len(keys),
                            "expected_sha256": sha(expect), "work": work,
                            "implementation": impl["name"], "samples_s": [], "status": "ok",
                            "terminal_output_bytes": []}
                    for i in range(args.warmup + args.runs):
                        (d / "f.txt").write_bytes(data)
                        elapsed, status, out_bytes, sent = session(impl["binary"], impl["script"], d,
                                                                   keys, args.cpu)
                        got = (d / "f.txt").read_bytes()
                        if status != 0 or sent != len(keys) or sha(got) != case["expected_sha256"]:
                            case["status"] = "invalid"
                            case["failure"] = {"pass": i, "exit": status, "sent": sent,
                                               "got_sha256": sha(got), "got_len": len(got)}
                            break
                        if i >= args.warmup:
                            case["samples_s"].append(round(elapsed, 6))
                            case["terminal_output_bytes"].append(out_bytes)
                    if case["status"] == "ok":
                        s = case["samples_s"]
                        case.update(median_s=statistics.median(s), min_s=min(s), max_s=max(s),
                                    stdev_s=statistics.stdev(s))
                    else:
                        case["samples_s"] = []
                    report["cases"].append(case)
                    print(f"{wl:9s} {size:>9d} {impl['name']:32s} {case['status']:7s} "
                          f"{case.get('median_s', float('nan')) * 1000:9.1f} ms", flush=True)
    Path(args.output).write_text(json.dumps(report, indent=1) + "\n")
    bad = [c for c in report["cases"] if c["status"] != "ok"]
    print(f"{len(report['cases']) - len(bad)} valid cases, {len(bad)} invalid")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
