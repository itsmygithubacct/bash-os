#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""uclampset query and controlled-setter timings.

bench/opus-uclampset.py BINARY SHIM.so OUTPUT.json [--calls N] [--samples N] [--cpu N]

Each sample is one shell loop of N calls, timed with $EPOCHREALTIME inside
the shell so startup is excluded. Every pass's output and statuses are
validated against values computed here (ctypes sched_getattr, the expected
fixture contents), and a sample whose validation fails is recorded as such
and gets no ratio. Workloads:

  query            uclampset -p PID of an owned child; builtin vs /usr/bin/uclampset
  pid-set-refused  -m 0 -M 512 -p PID on a kernel without CONFIG_UCLAMP_TASK:
                   both implementations do sched_getattr + a refused
                   sched_setattr and print the same error (verified)
  pid-set-shim     the same request accepted by tests/opus-uclampset-shim.c
                   emulation; builtin only (syscall-shim timing)
  system-set       -m V -s against a private BASHOS_PROC_ROOT fixture,
                   alternating V so every call writes; builtin only

Compile SHIM.so separately (through the build gate); this script does not
compile anything.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = "/usr/bin/uclampset"
GETATTR = {"x86_64": 315, "aarch64": 275, "riscv64": 275}.get(platform.machine())


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def oracle(pid):
    buf = (ctypes.c_uint32 * 14)()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    if libc.syscall(ctypes.c_long(GETATTR), ctypes.c_long(pid), buf,
                    ctypes.c_ulong(56), ctypes.c_ulong(0)) < 0:
        raise OSError(ctypes.get_errno(), "sched_getattr")
    return buf[12], buf[13]


def run_loop(binary, command, calls, env, cwd):
    """Run COMMAND CALLS times in one shell; return (seconds, stdout, stderr, failures)."""
    script = ('out=$1/out err=$1/err; shift; fails=0; : >"$out"; : >"$err"; '
              'start=$EPOCHREALTIME; for ((i=0;i<%d;i++)); do "$@" >>"$out" 2>>"$err" '
              '|| fails=$((fails+1)); done; end=$EPOCHREALTIME; '
              'printf "%%s %%s %%s\\n" "$start" "$end" "$fails"') % calls
    p = subprocess.run([binary, "--noprofile", "--norc", "-c", script, "bench", str(cwd), *command],
                       env=env, capture_output=True, timeout=600, cwd=cwd)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode())
    start, end, fails = p.stdout.decode().split()
    return (float(end) - float(start), (cwd / "out").read_bytes(), (cwd / "err").read_bytes(),
            int(fails))


def measure(name, impl, binary, command, calls, samples, env, cwd, check, reset=None):
    results, ok = [], True
    for i in range(samples + 1):  # sample 0 is the warm-up
        if reset:
            reset()
        secs, out, err, fails = run_loop(binary, command, calls, env, cwd)
        problem = check(out, err, fails)
        if problem:
            ok = False
        if i:
            results.append({"ms_per_call": secs * 1000 / calls, "valid": not problem,
                            "problem": problem})
        elif problem:
            results.append({"warmup_problem": problem})
    times = [r["ms_per_call"] for r in results if "ms_per_call" in r]
    return {"workload": name, "implementation": impl, "command": command, "calls": calls,
            "valid": ok, "samples_ms_per_call": times,
            "median_ms_per_call": statistics.median(times),
            "min_ms_per_call": min(times), "max_ms_per_call": max(times),
            "stdev_ms_per_call": statistics.stdev(times) if len(times) > 1 else 0.0,
            "records": results}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("shim")
    ap.add_argument("output")
    ap.add_argument("--calls", type=int, default=500)
    ap.add_argument("--samples", type=int, default=7)
    ap.add_argument("--cpu", type=int, default=2)
    args = ap.parse_args()
    binary = str(Path(args.binary).resolve())
    os.sched_setaffinity(0, {args.cpu})

    child = subprocess.Popen([sys.executable, "-c", "import time; print(1, flush=True); time.sleep(3600)"],
                             stdout=subprocess.PIPE)
    child.stdout.readline()
    pid = child.pid
    comm = Path(f"/proc/{pid}/comm").read_text().strip()
    lo, hi = oracle(pid)
    uclamp_kernel = Path("/proc/sys/kernel/sched_util_clamp_min").exists()
    rows = []
    try:
        with tempfile.TemporaryDirectory(prefix="bash-os-uclampset-bench-") as tmp:
            tmp = Path(tmp)
            base = {"PATH": "", "LC_ALL": "C"}
            query_line = f"{comm} ({pid}) util_clamp: min: {lo} max: {hi}\n".encode()

            def check_query(out, err, fails):
                if fails or err or out != query_line * args.calls:
                    return f"fails={fails} err={err[:80]!r} out_len={len(out)}"
                return None

            for impl, cmd in (("builtin", ["uclampset", "-p", str(pid)]),
                              ("external", [EXTERNAL, "-p", str(pid)])):
                rows.append(measure("query", impl, binary, cmd, args.calls, args.samples,
                                    base, tmp, check_query))

            if not uclamp_kernel:
                refused = f"uclampset: failed to set pid {pid}'s uclamp values: Operation not supported\n".encode()

                def check_refused(out, err, fails):
                    if fails != args.calls or out or err != refused * args.calls:
                        return f"fails={fails} err_head={err[:120]!r}"
                    return None

                for impl, cmd in (("builtin", ["uclampset", "-m", "0", "-M", "512", "-p", str(pid)]),
                                  ("external", [EXTERNAL, "-m", "0", "-M", "512", "-p", str(pid)])):
                    rows.append(measure("pid-set-refused", impl, binary, cmd, args.calls,
                                        args.samples, base, tmp, check_refused))

            state = tmp / "shim"
            state.mkdir()

            def reset_shim():
                for f in state.iterdir():
                    f.unlink()

            def check_shim(out, err, fails):
                log = (state / "log").read_text().splitlines()
                sets = [l for l in log if l.startswith("set ")]
                good = all(f"pid={pid} " in l and "flags=0x78 " in l and " min=0 max=512 " in l
                           and l.endswith("result=0") for l in sets)
                stored = (state / f"state-{pid}").read_text()
                if fails or out or err or len(sets) != args.calls or not good or stored != "0 512\n":
                    return f"fails={fails} sets={len(sets)} good={good} stored={stored!r}"
                return None

            shim_env = {**base, "LD_PRELOAD": str(Path(args.shim).resolve()),
                        "UCLAMP_SHIM_DIR": str(state), "UCLAMP_SHIM_SET": "emulate"}
            rows.append(measure("pid-set-shim", "builtin", binary,
                                ["uclampset", "-m", "0", "-M", "512", "-p", str(pid)],
                                args.calls, args.samples, shim_env, tmp, check_shim, reset_shim))

            proc = tmp / "proc"
            kernel = proc / "sys/kernel"
            kernel.mkdir(parents=True)

            def reset_sysctl():
                (kernel / "sched_util_clamp_min").write_text("0\n")
                (kernel / "sched_util_clamp_max").write_text("1024\n")

            # Alternate 100/200 so every call performs exactly one write; the
            # eval that picks the value is part of each timed call.
            final_min = "200\n" if args.calls % 2 == 0 else "100\n"

            def check_system(out, err, fails):
                got = ((kernel / "sched_util_clamp_min").read_text(),
                       (kernel / "sched_util_clamp_max").read_text())
                if fails or out or err or got != (final_min, "1024\n"):
                    return f"fails={fails} err={err[:80]!r} got={got}"
                return None

            sys_env = {**base, "BASHOS_PROC_ROOT": str(proc)}
            rows.append(measure("system-set", "builtin", binary,
                                ["eval", 'uclampset -m $(( i % 2 ? 200 : 100 )) -s'],
                                args.calls, args.samples, sys_env, tmp, check_system, reset_sysctl))
    finally:
        child.kill()
        child.wait()

    def ext_version():
        p = subprocess.run([EXTERNAL, "-V"], capture_output=True)
        return p.stdout.decode().strip()

    by = {(r["workload"], r["implementation"]): r for r in rows}
    ratios = {}
    for wl in ("query", "pid-set-refused"):
        b, e = by.get((wl, "builtin")), by.get((wl, "external"))
        if b and e and b["valid"] and e["valid"]:
            ratios[wl] = b["median_ms_per_call"] / e["median_ms_per_call"]
    report = {
        "binary": binary, "binary_sha256": sha256(binary),
        "source": "loadables/uclampset.c", "source_sha256": sha256(ROOT / "loadables/uclampset.c"),
        "shim_sha256": sha256(args.shim),
        "source_commit": subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                        capture_output=True, text=True).stdout.strip(),
        "worktree_dirty": bool(subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain",
                                               "loadables/uclampset.c"], capture_output=True,
                                              text=True).stdout.strip()),
        "external": EXTERNAL, "external_version": ext_version(),
        "external_sha256": sha256(EXTERNAL),
        "kernel": platform.release(), "uclamp_kernel": uclamp_kernel,
        "cpu_affinity": sorted(os.sched_getaffinity(0)), "nice": os.getpriority(os.PRIO_PROCESS, 0),
        "calls_per_sample": args.calls, "samples": args.samples, "warmup_passes": 1,
        "timer": "bash $EPOCHREALTIME around the loop; output redirected to private files",
        "ratios_builtin_over_external_median": ratios,
        "rows": rows,
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    for r in rows:
        print(f"{r['workload']:16} {r['implementation']:8} valid={r['valid']} "
              f"median={r['median_ms_per_call']:.4f} ms/call "
              f"[{r['min_ms_per_call']:.4f}..{r['max_ms_per_call']:.4f}]")
    print("ratios", ratios)
    return 0 if all(r["valid"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
