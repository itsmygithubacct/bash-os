#!/usr/bin/env python3
"""Time production fsfreeze with intercepted stat/open/ioctl/close calls.

No real filesystem operation and no external comparison. Build the module
separately with tests/sol-fsfreeze-build.sh through the build gate; run this
script only through the bench gate. All paths passed to fsfreeze are synthetic.
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
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fsfreeze_check', ROOT / 'tests/sol-fsfreeze-check.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--pairs', type=int, default=10000)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 7 or args.pairs < 1:
        parser.error('at least seven samples and one pair required')
    if args.output.exists():
        parser.error('output already exists; preserve each raw report separately')
    allowed = sorted(os.sched_getaffinity(0))
    cpu = args.cpu if args.cpu is not None else allowed[-1]
    if cpu not in allowed:
        parser.error(f'CPU {cpu} unavailable; allowed={allowed}')
    os.sched_setaffinity(0, {cpu})
    binary, module = args.binary.resolve(), args.module.resolve()
    workload = f'''ulimit -n 64 || exit 91
fsfreeze_fixture reset success quiet || exit 92
before=(/proc/$$/fd/*)
for ((i=0;i<{args.pairs};i++)); do
  fsfreeze -f /fixture/mount || exit 93
  fsfreeze -u /fixture/mount || exit 94
done
after=(/proc/$$/fd/*)
[[ ${{#before[@]}} == ${{#after[@]}} ]] || exit 95
fsfreeze_fixture dump
'''
    expected = contract.counts(2 * args.pairs, 2 * args.pairs, args.pairs,
                               args.pairs, 2 * args.pairs)
    report = {
        'schema': 1, 'workload': 'fsfreeze-freeze-thaw-syscall-shim',
        'kind': 'syscall-shim', 'status': 'pending',
        'real_device_operation': 'not performed', 'external_reference': None,
        'ratio': None, 'cpu_affinity': sorted(os.sched_getaffinity(0)),
        'environment': {'platform': platform.platform(), 'python': sys.version,
                        'cpu_model': next((line.split(':', 1)[1].strip() for line in
                                           Path('/proc/cpuinfo').read_text().splitlines()
                                           if line.startswith('model name')), 'unknown'),
                        'libc': platform.libc_ver(), 'PATH': '', 'LC_ALL': 'C'},
        'versions': {'bash': subprocess.check_output([str(binary), '--version'], text=True),
                     'compiler': (module.parent / 'compiler-version.txt').read_text()},
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
        'sha256': {str(p.relative_to(ROOT)): sha(p) for p in
                   [ROOT / 'loadables/fsfreeze.c', ROOT / 'tests/sol-fsfreeze-fixture.c',
                    ROOT / 'tests/sol-fsfreeze-check.py', ROOT / 'tests/sol-fsfreeze-build.sh',
                    Path(__file__).resolve()]},
        'binary_sha256': sha(binary), 'module_sha256': sha(module),
        'module_build_flags': '-O2 -g -fPIC -shared -Wl,-Bsymbolic -Wall -Wextra -DHAVE_CONFIG_H; worktree Bash include directories',
        'native_build_selection': json.loads(binary.with_name(binary.name + '.manifest.json').read_text()),
        'native_build_manifest': binary.with_name(binary.name + '.manifest.txt').read_text(),
        'fixture_sha256': hashlib.sha256((workload + expected).encode()).hexdigest(),
        'script': workload, 'expected_stdout': expected,
        'options': {'runs': args.runs, 'warmups': 1, 'pairs': args.pairs},
        'work_unit': {'pairs': args.pairs, 'builtin_calls': 2 * args.pairs,
                      'synthetic_stat_calls': 2 * args.pairs,
                      'real_dev_null_open_close_pairs': 2 * args.pairs,
                      'intercepted_FIFREEZE': args.pairs, 'intercepted_FITHAW': args.pairs},
        'request_order': 'strict FIFREEZE, FITHAW alternation checked on every intercepted request',
        'reset': 'fresh shell per batch; reset success quiet; fixed /fixture/mount; no persistent files',
        'method': 'wall clock including shell/module startup, loop, validation, and /dev/null open/close',
        'limitations': ['No real FIFREEZE/FITHAW reaches the kernel.',
                        'No filesystem writeback, freeze latency or thaw latency measured.',
                        'No util-linux or BusyBox equivalence/performance ratio claimed.'],
        'passes': [],
    }
    for i in range(args.runs + 1):
        start = time.perf_counter_ns()
        proc = contract.run_shell(binary, module, workload)
        elapsed = time.perf_counter_ns() - start
        valid = proc.returncode == 0 and proc.stdout == expected and not proc.stderr
        report['passes'].append({'phase': 'warmup' if i == 0 else 'sample',
                                 'index': i, 'elapsed_ns': elapsed, 'exit_code': proc.returncode,
                                 'stdout': proc.stdout, 'stderr': proc.stderr,
                                 'status': 'pass' if valid else 'fail'})
        if not valid:
            report['status'] = 'fail'
            break
    else:
        values = [p['elapsed_ns'] for p in report['passes'] if p['phase'] == 'sample']
        report.update(status='pass', samples_ns=values,
                      distribution_ns={'min': min(values), 'median': statistics.median(values),
                                       'max': max(values), 'mean': statistics.mean(values),
                                       'stdev': statistics.stdev(values)},
                      median_ns_per_builtin_call=statistics.median(values) / (2 * args.pairs))
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('workload', 'kind', 'status', 'real_device_operation')}))
    if report['status'] == 'pass':
        print(f"median {report['distribution_ns']['median'] / 1e6:.3f} ms per {2 * args.pairs} intercepted builtin calls")
    return report['status'] != 'pass'


if __name__ == '__main__':
    raise SystemExit(main())
