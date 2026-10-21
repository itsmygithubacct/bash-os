#!/usr/bin/env python3
"""Time nano editing and save sessions at several buffer sizes.

Each sample starts a bash-os shell on a private PTY (24x80, TERM=xterm,
LANG=C.UTF-8, empty PATH), opens a fresh copy of a fixed fixture, sends a
fixed key stream and stops the clock when the shell exits.  On every
warm-up and timed pass the saved file must hash to a value this script
computes without either editor, and the session must exit 0; one bad pass
marks the whole case failed.

Workloads (fixture of W bytes):
  open-exit   open and quit                                   (load + first frame)
  save        insert one byte at the top, ^S, quit            (one edit + atomic save)
  burst-edit  ^_ to the middle line, 400 typed, 100 Backspace, 10 x Enter+"line",
              ^S, quit; keys are written as fast as the PTY takes them, so
              frames are coalesced (the opus-nano "edit" workload)
  paced-edit  the same position, then 60 typed, 20 Backspace, 5 x Enter+"x"; each
              key is sent only after the previous key's frame has been drawn,
              so every key costs one edit and one full frame; per-key latency
              (write to end of frame) is recorded
  paced-sh    the same, shorter (12 typed, 4 Backspace, 2 Enter+x), on a .sh
              fixture, so every frame after an edit is syntax-coloured by the
              ts companion

Fixtures: .txt lines "NNNNNNN lorem ipsum ...", .sh lines of a small shell
pipeline; sizes default to 16 KiB, 1 MiB and 8 MiB.

GNU nano (--gnu) runs open-exit, save and burst-edit with the same keys and
must write the same bytes (with -L, its no-final-newline mode, which is this
builtin's model).  It draws differently, so it is a reference for the same
edit, not for the same work inside the editor.  Paced workloads have no GNU
column: GNU nano has no end-of-frame marker to pace on.

Usage: bench/sol-nano.py --binary A [--binary B] [--gnu /usr/bin/nano]
           [--sizes 16384,1048576,8388608] [--workloads ...] [--runs 7]
           [--warmup 1] [--cpu N] --output report.json
"""
import argparse
import fcntl
import hashlib
import json
import os
import platform
import pty
import select
import statistics
import struct
import subprocess
import tempfile
import termios
import time
from pathlib import Path

FRAME = b"\x1b[?25h"
TXT_LINE = "{:07d} lorem ipsum dolor sit amet consectetur adipiscing elit\n"
SH_LINE = 'echo "item {:07d}" | grep -q item && n=$((n + {}))  # count\n'


def fixture(kind, size):
    fmt = TXT_LINE if kind == "txt" else SH_LINE
    out, i, n = [], 0, 0
    while n < size:
        s = fmt.format(i, i % 10) if kind == "sh" else fmt.format(i)
        out.append(s)
        n += len(s)
        i += 1
    data = "".join(out).encode()[:size]
    return data[:-1] + b"\n" if not data.endswith(b"\n") else data


def middle(data):
    lines = data.split(b"\n")
    mid = data.count(b"\n") // 2 + 1
    off = sum(len(l) + 1 for l in lines[:mid - 1])
    return mid, off


def workload(name, data):
    """Return (key chunks, paced, expected bytes, description)."""
    if name == "open-exit":
        return [b"\x18"], False, data, "load, first frame, exit"
    if name == "save":
        return [b"Z\x13\x18"], False, b"Z" + data, "load, 1 insert, atomic save, exit"
    mid, off = middle(data)
    goto = [b"\x1f"] + [bytes([c]) for c in str(mid).encode()] + [b"\r"]
    if name == "burst-edit":
        typed = ("the quick brown fox " * 20).encode()
        tail = "\rline" * 10
        keys = [b"".join(goto) + typed + b"\x7f" * 100 + tail.encode() + b"\x13\x18"]
        ins = typed[:300] + tail.replace("\r", "\n").encode()
        return keys, False, data[:off] + ins + data[off:], \
            f"goto line {mid}; 400 typed, 100 Backspace, 10 Enter+line (550 edit keys) in bursts; save"
    if name in ("paced-edit", "paced-sh"):
        # paced-sh is shorter: before this change each of its keys reparsed
        # the whole highlighted buffer.
        n_typed, n_bs, n_nl = (60, 20, 5) if name == "paced-edit" else (12, 4, 2)
        typed = ("quick fox " * 6).encode()[:n_typed]
        edits = [bytes([c]) for c in typed] + [b"\x7f"] * n_bs
        for _ in range(n_nl):
            edits += [b"\r", b"x"]
        keys = goto + edits + [b"\x13", b"\x18"]
        ins = typed[:n_typed - n_bs] + b"\nx" * n_nl
        return keys, True, data[:off] + ins + data[off:], \
            (f"goto line {mid}; {n_typed} typed, {n_bs} Backspace, {n_nl} Enter+x "
             f"({n_typed + n_bs + 2 * n_nl} edit keys), one frame per key; save")
    raise ValueError(name)


def session(argv, cwd, chunks, paced, cpu, timeout=900):
    env = {"TERM": "xterm", "LANG": "C.UTF-8", "HOME": str(cwd), "PATH": ""}
    t0 = time.perf_counter()
    pid, fd = pty.fork()
    if pid == 0:
        try:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            if cpu is not None:
                os.sched_setaffinity(0, {cpu})
            os.chdir(cwd)
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    out = bytearray()
    frames_at = 0
    latencies = []
    deadline = time.monotonic() + timeout

    def pump(block):
        nonlocal out
        r, _, _ = select.select([fd], [], [], block)
        if not r:
            return True
        try:
            data = os.read(fd, 1 << 16)
        except OSError:
            return False
        if not data:
            return False
        out += data
        return True

    def wait_frames(n):
        while out.count(FRAME) < n:
            if time.monotonic() > deadline:
                raise RuntimeError("timed out waiting for a frame")
            if not pump(0.05):
                raise RuntimeError("session ended early")

    alive = True
    if paced:
        wait_frames(1)
        for i, chunk in enumerate(chunks):
            frames_at = out.count(FRAME)
            t = time.perf_counter()
            os.write(fd, chunk)
            if i == len(chunks) - 1:
                break
            wait_frames(frames_at + 1)
            latencies.append((time.perf_counter() - t) * 1000)
    else:
        # Wait for something on screen (GNU nano has no frame marker), then
        # write everything as fast as the PTY takes it.
        while not out and pump(0.05):
            if time.monotonic() > deadline:
                raise RuntimeError("no output")
        data = b"".join(chunks)
        sent = 0
        while sent < len(data):
            _, w, _ = select.select([], [fd], [], 0.05)
            if w:
                sent += os.write(fd, data[sent:sent + 256])
            pump(0)
    st = None
    while alive:
        if time.monotonic() > deadline:
            os.kill(pid, 9)
            break
        alive = pump(0.05)
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            st = status
            pump(0.01)
            break
    if st is None:
        _, st = os.waitpid(pid, 0)
    elapsed = (time.perf_counter() - t0) * 1000
    os.close(fd)
    return os.waitstatus_to_exitcode(st), elapsed, len(out), out.count(FRAME), latencies


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", action="append", required=True)
    ap.add_argument("--label", action="append")
    ap.add_argument("--gnu")
    ap.add_argument("--sizes", default="16384,1048576,8388608")
    ap.add_argument("--workloads", default="open-exit,save,burst-edit,paced-edit,paced-sh")
    ap.add_argument("--runs", type=int, default=7)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--cpu", type=int)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    labels = a.label or [Path(b).name for b in a.binary]
    impls = [(lab, str(Path(b).resolve()), False) for lab, b in zip(labels, a.binary)]
    if a.gnu:
        impls.append(("gnu", a.gnu, True))
    report = {
        "harness": "bench/sol-nano.py",
        "harness_sha256": sha(Path(__file__).read_bytes()),
        "host": {"machine": platform.machine(), "kernel": platform.release(),
                 "cpu_model": next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines()
                                    if l.startswith("model name")), None),
                 "loadavg_start": os.getloadavg()},
        "cpu_affinity": a.cpu, "runs": a.runs, "warmup": a.warmup,
        "implementations": [], "cases": [],
    }
    for lab, path, gnu in impls:
        info = {"label": lab, "path": path, "sha256": sha(Path(path).read_bytes())}
        if gnu:
            info["version"] = subprocess.run([path, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        report["implementations"].append(info)
    with tempfile.TemporaryDirectory(prefix="sol-nano-bench.") as tmp:
        root = Path(tmp)
        for size in [int(x) for x in a.sizes.split(",")]:
            for wl in a.workloads.split(","):
                kind = "sh" if wl == "paced-sh" else "txt"
                data = fixture(kind, size)
                chunks, paced, want, desc = workload(wl, data)
                name = f"f.{kind}"
                for lab, path, gnu in impls:
                    if gnu and paced:
                        continue
                    if gnu:
                        script = f"exec {path} --ignorercfiles -L {name}"
                    else:
                        script = f"nano {name}"
                    argv = [impls[0][1] if gnu else path, "--norc", "--noprofile", "-c", script]
                    case = {"workload": wl, "size": size, "lines": data.count(b"\n"), "impl": lab,
                            "fixture_sha256": sha(data), "expected_sha256": sha(want),
                            "work": desc, "keys": len(chunks) if paced else len(chunks[0]),
                            "samples_ms": [], "warmup_ms": [], "terminal_bytes": [], "frames": [],
                            "key_latency_ms": [], "status": "ok", "errors": []}
                    for i in range(a.warmup + a.runs):
                        work = root / f"{lab}-{wl}-{size}"
                        work.mkdir(exist_ok=True)
                        (work / name).write_bytes(data)
                        try:
                            rc, ms, nbytes, frames, lat = session(argv, work, chunks, paced, a.cpu)
                        except RuntimeError as e:
                            case["status"] = "failed"
                            case["errors"].append(f"pass {i}: {e}")
                            break
                        got = (work / name).read_bytes()
                        if rc != 0 or sha(got) != case["expected_sha256"]:
                            case["status"] = "failed"
                            case["errors"].append(f"pass {i}: exit {rc}, sha256 {sha(got)}")
                            break
                        if i < a.warmup:
                            case["warmup_ms"].append(round(ms, 3))
                            continue
                        case["samples_ms"].append(round(ms, 3))
                        case["terminal_bytes"].append(nbytes)
                        case["frames"].append(frames)
                        if lat:
                            case["key_latency_ms"].append([round(x, 3) for x in lat])
                    s = case["samples_ms"]
                    if s and case["status"] == "ok":
                        case["median_ms"] = round(statistics.median(s), 3)
                        case["min_ms"], case["max_ms"] = min(s), max(s)
                        if case["key_latency_ms"]:
                            flat = [x for run in case["key_latency_ms"] for x in run]
                            q = statistics.quantiles(flat, n=20)
                            case["key_latency_median_ms"] = round(statistics.median(flat), 3)
                            case["key_latency_p95_ms"] = round(q[18], 3)
                    report["cases"].append(case)
                    print(json.dumps({k: case.get(k) for k in ("workload", "size", "impl", "status",
                                     "median_ms", "key_latency_median_ms", "errors")}), flush=True)
    report["host"]["loadavg_end"] = os.getloadavg()
    Path(a.output).write_text(json.dumps(report, indent=1))
    bad = [c for c in report["cases"] if c["status"] != "ok"]
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
