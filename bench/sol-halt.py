#!/usr/bin/env python3
"""Validated parser and intercepted-request timing only; no host shutdown.

Build separately through the build gate. Run this driver through the bench gate.
The shell loop, status assertions, boundary counters and startup are included.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shlex
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
helper = runpy.run_path(str(ROOT / 'tests/sol-halt-check.py'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--shim', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--passes', type=int, default=10000)
    p.add_argument('--runs', type=int, default=7)
    a = p.parse_args()
    if a.runs < 7 or a.passes < 1:
        p.error('at least seven samples and one pass required')
    affinity = sorted(os.sched_getaffinity(0))
    if len(affinity) != 1:
        p.error('run through the bench gate with fixed CPU affinity')
    binary, shim = a.binary.resolve(), a.shim.resolve()
    env = helper['environment'](shim)
    prefix = helper['setup'](shim)
    report = dict(kind='syscall-shim', scope='parser/intercepted requests; no real reboot, sync, accounting or runlevel change',
                  reference=None, ratio=None, binary=str(binary), binary_sha256=sha(binary),
                  boundary_sha256=sha(shim), fixture_sources={str(x.relative_to(ROOT)): sha(x) for x in [
                      ROOT/'loadables/halt.c', ROOT/'loadables/common/reboot-impl.h',
                      ROOT/'tests/sol-halt-shim.c', ROOT/'tests/sol-halt-check.py', Path(__file__).resolve()]},
                  environment=dict(uname=platform.uname()._asdict(), python=platform.python_version(),
                                   cpu_affinity=affinity, cpuinfo=Path('/proc/cpuinfo').read_text(),
                                   libc=platform.libc_ver(), compiler=(shim.parent/'compiler-version.txt').read_text(),
                                   binary_version=subprocess.check_output([str(binary), '--version'], text=True)),
                  method=dict(warmups=1, samples=a.runs, passes=a.passes, clock='perf_counter_ns',
                              reset='fresh shell and halt_fixture reset before every batch',
                              includes='shell startup, loop, per-request status assertions, shim counters and output validation',
                              units='milliseconds per batch'), cases=[])
    empty = 'sync=0 reboot=0 accounting=0 cmd=none order=\n'
    cases = [
        ('dry-run-parser', '-fn', 0, 0, f'halt: would halt (dry run)\n' * a.passes + empty, ''),
        ('force-request-success', '-f', 0, 0, f'sync=0 reboot={a.passes} accounting=0 cmd=RB_HALT_SYSTEM order=' + 'R'*min(15, a.passes) + '\n', ''),
        ('force-request-EPERM', '-f', 1, 1, f'sync=0 reboot={a.passes} accounting=0 cmd=RB_HALT_SYSTEM order=' + 'R'*min(15, a.passes) + '\n', '2>/dev/null'),
    ]
    for name, opts, err, status, expected, redir in cases:
        script = prefix + f'halt_fixture errno {err}\nfor ((i=0;i<{a.passes};i++)); do\n'
        script += f'halt {opts} {redir}; rc=$?; [[ $rc == {status} ]] || exit 80\ndone\nhalt_fixture report\n'
        cell = dict(name=name, kind='syscall-shim', work_unit=f'{a.passes} halt {opts} calls with status assertion on each call',
                    options=opts, injected_errno=err, script_sha256=hashlib.sha256(script.encode()).hexdigest(),
                    expected_sha256=hashlib.sha256(expected.encode()).hexdigest(), passes=a.passes,
                    warmup=[], samples=[], status='pending')
        valid = True
        for sample in range(a.runs + 1):
            start = time.perf_counter_ns()
            r = subprocess.run([str(binary), '--noprofile', '--norc', '-c', script], env=env,
                               capture_output=True, text=True, timeout=60)
            elapsed = (time.perf_counter_ns() - start) / 1e6
            ok = r.returncode == 0 and r.stdout == expected and not r.stderr
            entry = dict(valid=ok, exit_code=r.returncode, stdout_sha256=hashlib.sha256(r.stdout.encode()).hexdigest(),
                         stderr=r.stderr, milliseconds=elapsed if ok else None)
            (cell['warmup'] if sample == 0 else cell['samples']).append(entry)
            valid &= ok
        cell['status'] = 'pass' if valid else 'fail'
        if valid:
            times = [s['milliseconds'] for s in cell['samples']]
            cell.update(milliseconds=times, median_ms=statistics.median(times), min_ms=min(times), max_ms=max(times),
                        median_ns_per_request=statistics.median(times) * 1e6/a.passes)
        report['cases'].append(cell)
        print(name, cell['status'], cell.get('median_ms'))
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    return any(c['status'] != 'pass' for c in report['cases'])


if __name__ == '__main__':
    raise SystemExit(main())
