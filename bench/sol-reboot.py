#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Time validated reboot requests through the closed reboot boundary.

Compilation is separate. Run under the campaign bench gate with CPU affinity.
These are shell-loop/syscall-shim timings, never actual reboot latency.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
helper = runpy.run_path(str(ROOT / 'tests/sol-halt-check.py'))
guard = runpy.run_path(str(ROOT / 'tests/sol-reboot-check.py'))['preload_guard']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--passes', type=int, default=10000)
    parser.add_argument('--runs', type=int, default=7)
    args = parser.parse_args()
    affinity = sorted(os.sched_getaffinity(0))
    if args.runs < 7 or args.passes < 1 or len(affinity) != 1:
        parser.error('require >=7 samples, positive passes, and fixed single-CPU affinity')
    binary, shim = args.binary.resolve(), args.shim.resolve()
    env = helper['environment'](shim)
    sources = ['loadables/reboot.c', 'loadables/common/reboot-impl.h',
               'tests/sol-halt-shim.c', 'tests/sol-halt-check.py', 'tests/sol-reboot-check.py',
               'tests/sol-poweroff-build.sh', 'bench/sol-reboot.py']
    report = dict(
        kind='syscall-shim', reference=None, ratio=None,
        scope='Validated RB_AUTOBOOT request construction only; no actual reboot latency.',
        binary_sha256=sha(binary.read_bytes()), boundary_sha256=sha(shim.read_bytes()),
        sources={path: sha((ROOT / path).read_bytes()) for path in sources},
        environment=dict(
            uname=platform.uname()._asdict(), cpu_affinity=affinity,
            cpuinfo=Path('/proc/cpuinfo').read_text(), python=platform.python_version(),
            libc=platform.libc_ver(),
            compiler=(shim.parent / 'compiler-version.txt').read_text(),
            binary_version=subprocess.check_output([str(binary), '--version'], text=True)),
        method=dict(warmups=1, samples=args.runs, passes=args.passes,
                    clock='perf_counter_ns', units='milliseconds per batch',
                    reset='fresh shell per batch; preload verified before enable; reset interceptor before each request',
                    includes='startup, shell loop, shim reset, status assertion, per-call trace and capture',
                    oracle='every call: fixed expected status, output, sync count/order, RB_AUTOBOOT or no request, zero accounting'),
        cases=[])
    empty = 'sync=0 reboot=0 accounting=0 cmd=none order=\n'
    cases = [
        ('sync-success', '', 0, 0, '', 'sync=1 reboot=1 accounting=0 cmd=RB_AUTOBOOT order=SR\n'),
        ('force-success', '-f', 0, 0, '', 'sync=0 reboot=1 accounting=0 cmd=RB_AUTOBOOT order=R\n'),
        ('sync-EPERM', '', errno.EPERM, 1, '', 'sync=1 reboot=1 accounting=0 cmd=RB_AUTOBOOT order=SR\n'),
        ('force-EPERM', '-f', errno.EPERM, 1, '', 'sync=0 reboot=1 accounting=0 cmd=RB_AUTOBOOT order=R\n'),
        ('dry', '-n', 0, 0, 'reboot: would reboot (dry run)\n', empty),
        ('force-dry', '-fn', 0, 0, 'reboot: would reboot (dry run)\n', empty),
        ('invalid-action', '-n now', 0, 2, '', empty),
    ]
    for name, options, error, status, output, boundary in cases:
        expected = (output + boundary) * args.passes
        script = guard(shim) + helper['setup'](shim) + (
            f'for ((i=0;i<{args.passes};i++)); do\n'
            f'halt_fixture reset; halt_fixture errno {error}\n'
            f'reboot {options} {"2>/dev/null" if status else ""}; rc=$?\n'
            f'[[ $rc == {status} ]] || exit 80\nhalt_fixture report\ndone\n')
        case = dict(name=name, status='pending', options=options, injected_errno=error,
                    work_unit=f'{args.passes} reboot invocations, each checked for status, output and exact boundary trace',
                    script_sha256=sha(script.encode()), expected_sha256=sha(expected.encode()),
                    warmup=[], samples=[])
        for sample in range(args.runs + 1):
            start = time.perf_counter_ns()
            result = subprocess.run(
                [str(binary), '--noprofile', '--norc', '-c', script],
                env=env, capture_output=True, text=True, timeout=60)
            elapsed = (time.perf_counter_ns() - start) / 1e6
            valid = result.returncode == 0 and result.stdout == expected and not result.stderr
            entry = dict(valid=valid, exit_code=result.returncode,
                         stdout_sha256=sha(result.stdout.encode()), stderr=result.stderr,
                         milliseconds=elapsed if valid else None)
            (case['warmup'] if sample == 0 else case['samples']).append(entry)
        valid = all(e['valid'] for e in case['warmup'] + case['samples'])
        case['status'] = 'pass' if valid else 'fail'
        if valid:
            values = [e['milliseconds'] for e in case['samples']]
            case.update(milliseconds=values, median_ms=statistics.median(values),
                        min_ms=min(values), max_ms=max(values),
                        median_ns_per_request=statistics.median(values) * 1e6 / args.passes)
        report['cases'].append(case)
        print(name, case['status'], case.get('median_ms'), flush=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    return any(case['status'] != 'pass' for case in report['cases'])


if __name__ == '__main__':
    raise SystemExit(main())
