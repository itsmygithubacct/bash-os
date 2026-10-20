#!/usr/bin/env python3
"""Validated FIFO API batches. Run through the campaign bench gate; never builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(case, batches):
    values = list(range(32))
    queue = list(range(-32, 0)) if case == "half-full" else []
    lines = ["PATH=", "export LC_ALL=C", "fifo clear || exit 90"]
    if case == "wraparound":
        # Empty ring at physical head=tail=60. Each 32-entry append starts at
        # 60 or 28 and every second append crosses the end of the ring.
        lines += ["fifo push " + " ".join(map(str, range(60))) + " || exit 91",
                  "for ((i=0;i<60;i++)); do fifo pull > /dev/null || exit 92; done"]
    if queue:
        lines += ["fifo push " + " ".join(map(str, queue)) + " || exit 93"]
    lines += [f"for ((batch=0;batch<{batches};batch++)); do",
              "fifo push " + " ".join(map(str, values)) + " || exit 94",
              "for ((i=0;i<32;i++)); do fifo peek || exit 95; done",
              "for ((i=0;i<32;i++)); do fifo pull || exit 96; done", "done",
              "fifo depth || exit 97"]
    expected = []
    for _ in range(batches):
        queue.extend(values)
        expected.extend(queue[:32])  # peek independent of consumption
        expected.extend(queue[:32])
        del queue[:32]
    expected += [len(queue), *queue]
    if queue:
        lines += [f"for ((i=0;i<{len(queue)};i++)); do fifo pull || exit 98; done"]
    lines += ["fifo depth || exit 99",
              "if fifo pull; then exit 100; else [[ $? == 1 ]] || exit 101; fi"]
    expected += [0]
    return ("\n".join(lines) + "\n").encode(), ("\n".join(map(str, expected)) + "\n").encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", type=Path, default=ROOT / "out/bash-sol-fifo")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--runs", type=int, default=9)
    ap.add_argument("--batches", type=int, default=128)
    ap.add_argument("--cpu", type=int)
    args = ap.parse_args()
    if args.runs < 7 or args.batches < 1:
        ap.error("at least seven samples and one batch required")
    binary = args.binary.resolve()
    allowed = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else max(allowed)
    if cpu not in allowed:
        ap.error(f"CPU {cpu} outside current allowed affinity {allowed}")
    os.sched_setaffinity(0, {cpu})
    env = dict(os.environ, PATH="", LC_ALL="C")
    for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "LD_PRELOAD"):
        env.pop(key, None)
    report = dict(kind="api", external_reference=None, external_ratio=None,
                  method="fresh shell wall time including startup, setup, loops, output capture and drain; no overhead subtraction",
                  reset="fresh shell plus fifo clear before every warm-up/sample",
                  events_per_batch=32, batches=args.batches, events_per_sample=args.batches * 32,
                  calls_per_batch=65, api_calls_per_event=65 / 32,
                  entry_operations_per_batch=96,
                  event="one enqueued/dequeued entry; each batch also peeks 32 entries",
                  warmups=1, samples_per_case=args.runs, cpu=cpu, affinity=sorted(os.sched_getaffinity(0)),
                  binary=str(binary), binary_sha256=sha(binary.read_bytes()),
                  bash_version=subprocess.check_output([str(binary), "--version"], env=env).decode(),
                  python=sys.version, platform=platform.platform(), uname=list(platform.uname()),
                  libc=platform.libc_ver(),
                  compiler_version=subprocess.check_output([os.environ.get("CC", "cc"), "--version"]).decode(),
                  environment=dict(PATH="", LC_ALL="C"),
                  cpu_model=next((x.split(":", 1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines()
                                  if x.startswith("model name")), "unknown"),
                  source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
                  source_status=subprocess.check_output(["git", "status", "--short"], cwd=ROOT).decode(),
                  source_sha256=sha((ROOT / "loadables/fifo.c").read_bytes()),
                  harness_sha256=sha(Path(__file__).read_bytes()),
                  manifest_sha256=sha(Path(str(binary) + ".manifest.json").read_bytes()),
                  build_manifest=json.loads(Path(str(binary) + ".manifest.json").read_text()),
                  build_options=Path(str(binary) + ".manifest.txt").read_text(),
                  cases={})
    fixture_dir = args.output.parent / (args.output.stem + "-fixtures")
    fixture_dir.mkdir(exist_ok=True)
    (fixture_dir / "fifo.c").write_bytes((ROOT / "loadables/fifo.c").read_bytes())
    fixtures = {}
    for name in ("empty", "half-full", "wraparound"):
        script, expected = fixtures[name] = fixture(name, args.batches)
        (fixture_dir / f"{name}.sh").write_bytes(script)
        (fixture_dir / f"{name}.expected").write_bytes(expected)
        report["cases"][name] = dict(status="pending", script_sha256=sha(script), expected_sha256=sha(expected),
            script=str(fixture_dir / f"{name}.sh"), expected=str(fixture_dir / f"{name}.expected"),
            expected_bytes=len(expected), samples=[],
            initial_depth=32 if name == "half-full" else 0,
            batch_depths=[32, 64, 32] if name == "half-full" else [0, 32, 0],
            setup_events=60 if name == "wraparound" else 32 if name == "half-full" else 0,
            trailing_drain_events=32 if name == "half-full" else 0)
    failed = False
    for round_no in range(-1, args.runs):
        names = list(fixtures)
        if round_no % 2:
            names.reverse()
        for name in names:
            script, expected = fixtures[name]
            start = time.perf_counter_ns()
            p = subprocess.run([str(binary), "--noprofile", "--norc", "-s"], input=script,
                               env=env, capture_output=True, timeout=120)
            elapsed = time.perf_counter_ns() - start
            valid = p.returncode == 0 and p.stdout == expected and p.stderr == b""
            entry = dict(exit_code=p.returncode, validated=valid, stdout_sha256=sha(p.stdout),
                         stderr=p.stderr.decode(errors="replace"))
            if valid:
                entry["elapsed_ns"] = elapsed
            else:
                failed = True
                (fixture_dir / f"{name}-{round_no}.stdout").write_bytes(p.stdout)
                (fixture_dir / f"{name}-{round_no}.stderr").write_bytes(p.stderr)
            case = report["cases"][name]
            if round_no == -1:
                case["warmup"] = entry
            else:
                case["samples"].append(entry)
    for name, case in report["cases"].items():
        valid = case["warmup"]["validated"] and all(x["validated"] for x in case["samples"])
        case["status"] = "pass" if valid else "fail"
        if valid:
            ns = [x["elapsed_ns"] for x in case["samples"]]
            case["batch_ms"] = [x / args.batches / 1e6 for x in ns]
            case["ns_per_event"] = [x / (args.batches * 32) for x in ns]
            case["median_batch_ms"] = statistics.median(case["batch_ms"])
            case["median_ns_per_event"] = statistics.median(case["ns_per_event"])
            case["min_ns_per_event"] = min(case["ns_per_event"])
            case["max_ns_per_event"] = max(case["ns_per_event"])
            print(f"{name}: PASS {args.batches} x 32 events; median {case['median_batch_ms']:.6f} ms/batch; "
                  f"{case['median_ns_per_event']:.1f} ns/event")
        else:
            # A failed case receives no aggregate timing, including prior valid passes.
            for entry in [case["warmup"], *case["samples"]]:
                entry.pop("elapsed_ns", None)
            print(f"{name}: FAIL (no timing published)")
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
