#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed dmsetup workloads over the injected DM-ioctl fixture (syscall-shim timings).

bench/opus-dmsetup.py --bash BASH --fixture SO [--base-bash BASH] [--samples N] [--cpu N] --out REPORT.json

Every timing is a whole `bash -c` process running a fixed loop of dmsetup calls
against tests/opus-dmsetup-fixture.c preloaded in place of /dev/mapper/control.
These are syscall-shim measurements: they time request construction, response
parsing and output in the builtin plus the fixture's in-memory model, never a
kernel device-mapper. Every pass (warm-up included) is validated against an
expected result computed here, independently of the builtin. Only the "table"
workload is valid on the pre-change builtin, so only it is paired.
"""

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def query_fixture():
    """64 devices, 4 linear targets each, and the exact `dmsetup table` output."""
    state, expect, names = [], {}, []
    for i in range(64):
        name = f"vol{i:02d}"
        names.append(name)
        state.append(f"dev {name} - {i} 0 0")
        rows = []
        for t in range(4):
            params = f"8:{(i + t) % 16} {i * 4096 + t * 1024}"
            state.append(f"live {t * 1024} 1024 linear {params}")
            rows.append(f"{t * 1024} 1024 linear {params}\n")
        expect[name] = "".join(rows)
    return "\n".join(state) + "\n", names, expect


def workloads():
    qstate, names, qexpect = query_fixture()
    rounds = 20
    table_script = (f"for r in {{1..{rounds}}}; do for d in {' '.join(names)}; do dmsetup table $d || exit 7; "
                    "done; done")
    table_out = "".join(qexpect[n] for n in names) * rounds

    cycles = 100
    tbl = "\\n".join(f"{t * 64} 64 linear 8:{t % 16} {t * 64}" for t in range(16))
    req_script = (f"t=$'{tbl}'; for i in {{1..{cycles}}}; do dmsetup create c$i --table \"$t\" || exit 7; "
                  "dmsetup reload c$i --table '0 1024 zero' || exit 7; dmsetup suspend c$i || exit 7; "
                  "dmsetup resume c$i || exit 7; dmsetup rename c$i d$i || exit 7; dmsetup remove d$i || exit 7; "
                  "done")
    # create, reload, resume, reload, suspend, resume, rename, remove per cycle
    req_ioctls = cycles * 8

    lsn, lsrounds = 3000, 20
    ls_script = f"for r in {{1..{lsrounds}}}; do dmsetup ls || exit 7; done"
    # the minor is the bulk index; names are bulk00000..
    ls_out = "".join(f"bulk{i:05d}\t(253:{i})\n" for i in range(lsn)) * lsrounds
    # 16 KiB -> 32 -> 64 -> 128 KiB: four DM_LIST_DEVICES requests per ls
    return [
        dict(name="table-query-64dev", state=qstate, script=table_script, stdout=table_out, ioctls=rounds * 64, calls=rounds * 64,
             paired=True, work_unit=f"{rounds * 64} `dmsetup table NAME` calls (64 devices x 4 targets, "
                                    f"{rounds} rounds) in one shell"),
        dict(name="request-lifecycle-100", state=qstate, script=req_script, stdout="", ioctls=req_ioctls, calls=cycles * 6,
             paired=False, work_unit=f"{cycles} create(16-target table)/reload/suspend/resume/rename/remove "
                                     f"cycles, {req_ioctls} DM ioctls, in one shell"),
        dict(name="ls-growth-3000dev", state=f"bulk {lsn}\n", script=ls_script, stdout=ls_out,
             ioctls=lsrounds * 4, calls=lsrounds, paired=False,
             work_unit=f"{lsrounds} `dmsetup ls` calls over {lsn} devices, each retried 16->128 KiB"),
    ]


def run_once(bash, so, wl, tmp, cpu):
    state = os.path.join(tmp, wl["name"] + ".state")
    stats = os.path.join(tmp, wl["name"] + ".stats")
    with open(state, "w") as f:
        f.write(wl["state"])
    if os.path.exists(stats):
        os.unlink(stats)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LD_PRELOAD": so, "DMSFIX_STATE": state,
           "DMSFIX_STATS": stats, "DMSFIX_EUID": "0", "BASHOS_DMSETUP_ALLOW_MUTATE": "1"}
    pre = (lambda: os.sched_setaffinity(0, {cpu})) if cpu is not None else None
    t0 = time.perf_counter()
    p = subprocess.run([bash, "-c", "PATH=; " + wl["script"]], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, preexec_fn=pre, timeout=600)
    dt = time.perf_counter() - t0
    got = {}
    if os.path.exists(stats):
        for line in open(stats):
            k, _, v = line.partition(" ")
            if k in ("ioctls", "opens", "closes", "open_now"):
                got[k] = int(v)
    problems = []
    if p.returncode != 0:
        problems.append(f"exit {p.returncode}: {p.stderr[:200]!r}")
    if p.stdout != wl["stdout"]:
        problems.append(f"stdout mismatch ({len(p.stdout)} vs {len(wl['stdout'])} bytes)")
    if p.stderr:
        problems.append(f"stderr {p.stderr[:200]!r}")
    if got.get("ioctls") != wl["ioctls"]:
        problems.append(f"ioctl count {got.get('ioctls')} != {wl['ioctls']}")
    if got.get("open_now") != 0 or got.get("opens") != got.get("closes"):
        problems.append(f"descriptor leak {got}")
    return dt, problems, hashlib.sha256(p.stdout.encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bash", required=True)
    ap.add_argument("--base-bash")
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--samples", type=int, default=9)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--cpu", type=int, default=2)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.samples < 7:
        ap.error("at least seven samples are required")
    cpu = a.cpu if hasattr(os, "sched_setaffinity") else None
    so = os.path.abspath(a.fixture)
    bins = {"new": os.path.abspath(a.bash)}
    if a.base_bash:
        bins["base"] = os.path.abspath(a.base_bash)

    report = dict(
        kind="syscall-shim",
        note="Times a bash process driving dmsetup against the LD_PRELOAD DM fixture; no kernel "
             "device-mapper is involved and no external dmsetup ratio is claimed.",
        host=dict(platform=platform.platform(), machine=platform.machine(), python=platform.python_version(),
                  cpus=os.cpu_count(), affinity_cpu=cpu),
        binaries={k: dict(path=v, sha256=sha256(v)) for k, v in bins.items()},
        fixture=dict(path=so, sha256=sha256(so),
                     source_sha256=sha256(os.path.join(ROOT, "tests", "opus-dmsetup-fixture.c"))),
        source_sha256=dict(dmsetup_c=sha256(os.path.join(ROOT, "loadables", "dmsetup.c")),
                           harness=sha256(os.path.abspath(__file__))),
        samples=a.samples, warmup=a.warmup, reset="fixture state file rewritten and a fresh bash process per pass",
        workloads=[])
    with tempfile.TemporaryDirectory(prefix="dmsbench.") as tmp:
        for wl in workloads():
            entry = dict(name=wl["name"], work_unit=wl["work_unit"], expected_ioctls=wl["ioctls"], calls=wl["calls"],
                         state_sha256=hashlib.sha256(wl["state"].encode()).hexdigest(),
                         script_sha256=hashlib.sha256(wl["script"].encode()).hexdigest(),
                         expected_stdout_sha256=hashlib.sha256(wl["stdout"].encode()).hexdigest(), runs={})
            for label, bash in bins.items():
                if label != "new" and not wl["paired"]:
                    continue
                times, status = [], "pass"
                for i in range(a.warmup + a.samples):
                    dt, problems, digest = run_once(bash, so, wl, tmp, cpu)
                    if problems:
                        status = "fail"
                        entry["runs"][label] = dict(status=status, pass_index=i, problems=problems)
                        break
                    if i >= a.warmup:
                        times.append(dt)
                if status == "pass":
                    entry["runs"][label] = dict(
                        status="pass", samples_s=times, median_s=statistics.median(times),
                        min_s=min(times), max_s=max(times), stdev_s=statistics.stdev(times),
                        per_call_us=statistics.median(times) / wl["calls"] * 1e6)
                print(f"{wl['name']:24s} {label:5s} {entry['runs'][label]['status']}"
                      + (f" median {entry['runs'][label]['median_s'] * 1e3:.1f} ms" if status == "pass" else
                         f" {entry['runs'][label]['problems']}"))
            if "base" in entry["runs"] and entry["runs"]["base"]["status"] == "pass" \
                    and entry["runs"]["new"]["status"] == "pass":
                entry["paired_new_over_base"] = entry["runs"]["new"]["median_s"] / entry["runs"]["base"]["median_s"]
            report["workloads"].append(entry)
    with open(a.out, "w") as f:
        json.dump(report, f, indent=2)
    bad = [w["name"] for w in report["workloads"] for r in w["runs"].values() if r["status"] != "pass"]
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
