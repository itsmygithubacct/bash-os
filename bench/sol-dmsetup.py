#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed dmsetup syscall-shim workloads. Prebuild both artifacts; use the bench gate.

The three inherited work units are preserved for reproduction. A fourth checks
large table packing and readback. No external-tool or actual-device ratio.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dmbench", ROOT / "bench/opus-dmsetup.py")
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def artifact(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": digest(path.read_bytes())}


def final_state(text):
    """Independent expected state in the fixture's exit report, excluding counters."""
    lines, dev, targets = [], None, []
    def flush():
        if dev:
            name, uuid, minor, opened, suspended = dev
            lines.append(f"dev {name} {uuid} {minor} {opened} susp={suspended} ro=0 live={len(targets)} inactive=0")
            lines.extend("  live " + t for t in targets)
    for line in text.splitlines():
        if line.startswith("dev "):
            flush()
            dev, targets = line.split()[1:], []
        elif line.startswith("live "):
            targets.append(line[5:])
        elif line.startswith("bulk "):
            for i in range(int(line.split()[1])):
                # load_state's fixed bulk fixture: one linear target per device.
                lines.extend([f"dev bulk{i:05d} - {i} 0 susp=0 ro=0 live=1 inactive=0",
                              f"  live 0 2048 linear 7:{i % 8} 0"])
    flush()
    return lines


def workloads():
    cases = old.workloads()
    for c in cases:
        c["final_state"] = final_state(c["state"])
    rows = [(i * 8, 8, "linear", f"8:{i % 16} {i * 8}") for i in range(600)]
    table = "".join(f"{a} {b} {t} {p}\n" for a, b, t, p in rows)
    # Each cycle validates the just-loaded table through independent text output.
    cases.append(dict(name="table-pack-600", state="dev large - 0 0 0\n",
                      script='for i in {1..20}; do dmsetup load large --table "$TABLE" || exit 7; '
                             'dmsetup resume large || exit 7; dmsetup table large || exit 7; done',
                      env={"TABLE": table}, stdout=table * 20, calls=60, ioctls=100,
                      final_state=final_state("dev large - 0 0 0\n" +
                                              "".join("live " + row + "\n" for row in table.splitlines())),
                      work_unit="20 load/resume/table cycles, 600 targets each: 12000 input and output targets, "
                                "100 ioctls (each table query grows 16->32->64 KiB)"))
    return cases


def run_once(args, wl, tmp):
    state, stats = Path(tmp) / "state", Path(tmp) / "stats"
    state.write_text(wl["state"])
    stats.unlink(missing_ok=True)
    env = dict(PATH="", LC_ALL="C", LD_PRELOAD=str(Path(args.fixture).resolve()),
               DMSFIX_STATE=str(state), DMSFIX_STATS=str(stats), DMSFIX_EUID="0",
               BASHOS_DMSETUP_ALLOW_MUTATE="1", **wl.get("env", {}))
    start = time.perf_counter_ns()
    p = subprocess.run([str(Path(args.bash).resolve()), "--noprofile", "--norc", "-c", wl["script"]],
                       env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    seconds = (time.perf_counter_ns() - start) / 1e9
    raw_stats = stats.read_text() if stats.exists() else ""
    counts = {}
    state_lines = []
    for line in raw_stats.splitlines():
        if line.startswith(("dev ", "  live ")):
            state_lines.append(line)
        else:
            key, _, value = line.partition(" ")
            counts[key] = int(value)
    errors = []
    if p.returncode != 0:
        errors.append(f"exit {p.returncode}")
    if p.stderr:
        errors.append(f"stderr {p.stderr[:300]!r}")
    if p.stdout != wl["stdout"].encode():
        errors.append("stdout differs from independent oracle")
    if counts.get("ioctls") != wl["ioctls"]:
        errors.append(f"ioctl count {counts.get('ioctls')} != {wl['ioctls']}")
    if counts.get("opens") != wl["calls"] or counts.get("closes") != wl["calls"] or counts.get("open_now") != 0:
        errors.append(f"descriptor counts {counts}")
    if state_lines != wl["final_state"]:
        errors.append("final device/table state differs from independent oracle")
    return dict(seconds=seconds, status="fail" if errors else "pass", errors=errors,
                exit_code=p.returncode, stdout_sha256=digest(p.stdout), counts=counts,
                final_state_sha256=digest(("\n".join(state_lines) + "\n").encode()))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bash", required=True)
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--source", default=str(ROOT / "loadables/dmsetup.c"))
    ap.add_argument("--fixture-source", default=str(ROOT / "tests/opus-dmsetup-fixture.c"))
    ap.add_argument("--source-commit", required=True)
    ap.add_argument("--samples", type=int, default=9)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--cpu", type=int, required=True)
    ap.add_argument("--inherited-only", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.samples < 7 or args.warmup < 1:
        ap.error("require at least seven samples and one warm-up")
    os.sched_setaffinity(0, {args.cpu})
    report = dict(kind="syscall-shim", source_commit=args.source_commit,
                  binary=artifact(args.bash), fixture=artifact(args.fixture),
                  source=artifact(args.source), fixture_source=artifact(args.fixture_source),
                  harness=artifact(__file__), inherited_workloads=artifact(old.__file__),
                  platform=platform.platform(), python=platform.python_version(),
                  cpu_model=next((x.split(":", 1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines()
                                  if x.startswith("model name")), "unknown"),
                  affinity=sorted(os.sched_getaffinity(0)),
                  bash_version=subprocess.check_output([args.bash, "--version"], text=True).splitlines()[0],
                  compiler_version=subprocess.check_output(["cc", "--version"], text=True).splitlines()[0],
                  samples=args.samples, warmup=args.warmup,
                  reset="fresh Bash process and identical state file per pass; no request hex logging",
                  environment={"PATH": "", "LC_ALL": "C", "DMSFIX_EUID": "0", "BASHOS_DMSETUP_ALLOW_MUTATE": "1"},
                  limitations=["Injected device layer; no kernel mapper work or external ratio.",
                               "Whole process wall time includes fixture, shell, output capture and exit state report."],
                  workloads=[])
    with tempfile.TemporaryDirectory(prefix="sol-dmsetup-", dir=os.environ.get("BASHOS_TASK_DIR")) as tmp:
        for wl in workloads()[:3 if args.inherited_only else 4]:
            entry = dict(name=wl["name"], work_unit=wl["work_unit"], calls=wl["calls"],
                         expected_ioctls=wl["ioctls"], state_sha256=digest(wl["state"].encode()),
                         script_sha256=digest(wl["script"].encode()), environment=wl.get("env", {}),
                         expected_stdout_sha256=digest(wl["stdout"].encode()),
                         expected_final_state_sha256=digest(("\n".join(wl["final_state"]) + "\n").encode()),
                         passes=[])
            for i in range(args.warmup + args.samples):
                run = run_once(args, wl, tmp)
                run["warmup"] = i < args.warmup
                entry["passes"].append(run)
                if run["status"] != "pass":
                    break
            entry["status"] = "pass" if all(p["status"] == "pass" for p in entry["passes"]) else "fail"
            if entry["status"] == "pass":
                samples = [p["seconds"] for p in entry["passes"] if not p["warmup"]]
                entry.update(samples_s=samples, median_s=statistics.median(samples),
                             min_s=min(samples), max_s=max(samples), stdev_s=statistics.stdev(samples))
            report["workloads"].append(entry)
            print(wl["name"], entry["status"], entry.get("median_s", entry["passes"][-1]["errors"]), flush=True)
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    return int(any(w["status"] != "pass" for w in report["workloads"]))


if __name__ == "__main__":
    raise SystemExit(main())
