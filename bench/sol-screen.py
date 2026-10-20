#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure verified live screen relay workloads; run through the bench gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("streams", ROOT / "tests/sol-screen-streams.py")
streams = importlib.util.module_from_spec(spec)
spec.loader.exec_module(streams)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=7)
    args = parser.parse_args()
    if args.runs < 7:
        parser.error("at least seven samples are required")
    if len(os.sched_getaffinity(0)) != 1:
        parser.error("pin to one CPU (the campaign bench gate does this)")
    args.load_dir = None
    sources = ["loadables/screen.c", "loadables/ptybroker.c",
               "loadables/_ptybroker/client.c", "loadables/_ptybroker/server.c",
               "loadables/_ptybroker/transport.h", "loadables/_ptybroker/ptybroker.h",
               "tests/screen-broker.py", "tests/sol-screen-streams.py", "bench/sol-screen.py"]
    report = dict(
        schema=1, kind="api", external_reference=None,
        date=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_dirty=bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--", *sources], cwd=ROOT)),
        source_identity="source_sha256 describes the measured working tree; source_commit is its base",
        source_sha256={p: sha(ROOT / p) for p in sources},
        binary_sha256=sha(args.bash), binary_version=subprocess.check_output(
            [str(args.bash.resolve()), "--version"], text=True).splitlines()[0],
        python=platform.python_version(), kernel=platform.release(), machine=platform.machine(),
        compiler=subprocess.check_output(["cc", "--version"], text=True).splitlines()[0],
        cpu_model=next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                       if line.startswith("model name")),
        affinity=sorted(os.sched_getaffinity(0)), load_average_start=os.getloadavg(),
        fixture_sha256=hashlib.sha256(streams.PATTERN).hexdigest(),
        child_sha256=hashlib.sha256(streams.CHILD.encode()).hexdigest(),
        reset="fresh private directory, panes, broker, subscriptions per pass; identity-aware cleanup",
        method="one verified warm-up then seven or more verified samples; no external ratio; "
               "sustained time includes binary delivery, window barriers, concurrent layout mutations "
               "and per-window broker status/memory sampling, waits for every mutation, "
               "excludes setup and teardown; "
               "binary relay and round trips include driver pipes, prefix decoding and PTY echo",
        cases=[], passed=False)
    streams.subreaper()
    try:
        for case in ("sustained", "binary-relay", "roundtrip"):
            row = dict(case=case, warmup=streams.run_case(args, case), samples=[])
            report["cases"].append(row)
            for _ in range(args.runs):
                sample = streams.run_case(args, case, measured=True)
                row["samples"].append(sample)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
            values = ([s["seconds"] for s in row["samples"]] if case != "roundtrip" else
                      [v for s in row["samples"] for v in s["latency_seconds"]])
            row["distribution_seconds"] = dict(
                minimum=min(values), median=statistics.median(values), maximum=max(values),
                p95=sorted(values)[int((len(values)-1)*.95)])
            print(json.dumps({"case": case, **row["distribution_seconds"]}), flush=True)
        report["passed"] = True
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
