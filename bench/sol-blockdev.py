#!/usr/bin/env python3
"""Fixed, independently validated blockdev syscall-shim batches; no device I/O."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('blockdev_checks', ROOT / 'tests/sol-blockdev-check.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--passes', type=int, default=1000)
    p.add_argument('--runs', type=int, default=7)
    args = p.parse_args()
    if args.runs < 7 or args.passes < 1:
        p.error('require at least seven samples and one pass')
    binary, module = args.binary.resolve(), args.module.resolve()
    affinity = sorted(os.sched_getaffinity(0))
    if len(affinity) != 1:
        p.error('run through the bench gate on one fixed CPU')
    report = dict(kind='syscall-shim', external_ratio=None,
                  method='one warm-up then >=7 samples; shell startup + fixed builtin loop; all stdout/status/stats validated',
                  qualification='No real block devices opened. These are software boundary timings, not device latency.',
                  binary=str(binary), binary_sha256=digest(binary), module=str(module), module_sha256=digest(module),
                  source_sha256={str(f.relative_to(ROOT)): digest(f) for f in [ROOT/'loadables/blockdev.c',
                    ROOT/'tests/sol-blockdev-shim.c', ROOT/'tests/sol-blockdev-check.py', checks.FIXTURE, Path(__file__)]},
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                  environment=dict(cpu_affinity=affinity, platform=platform.platform(), python=sys.version,
                    shell_version=subprocess.check_output([str(binary), '--version'], text=True).splitlines()[0],
                    compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                    cpu_model=next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines()
                                    if x.startswith('model name')), 'unknown'), lc_all='C', path='empty inside shell'),
                  fixture_sha256=digest(checks.FIXTURE), reset='fresh shell and fixture metadata before every batch; tracing disabled; setters restore ro=0',
                  cases=[])
    cases = [('queries', checks.QUERIES),
             ('requests', ['--getro', '--setro', '--getro', '--setrw', '--getro', '--flushbufs', '--rereadpt'])]
    for name, actions in cases:
        n = args.passes
        command = shlex.join(['blockdev'] + actions + [d['name'] for d in checks.DEVICES])
        script = checks.setup(module) + 'blockdev_fixture quiet\n' + (
            f'for ((i=0;i<{n};i++)); do {command} || exit 97; done\nblockdev_fixture stats')
        expected = checks.values(actions, checks.DEVICES) * n
        states = [0, 7] if name == 'queries' else [0, 0]
        # On the request batch the initial nonzero RO value normalizes to 1,
        # and each subsequent pass starts at 0 after the preceding --setrw.
        if name == 'requests':
            reset_devices = [dict(d, ro=0) for d in checks.DEVICES]
            expected = checks.values(actions, checks.DEVICES) + checks.values(actions, reset_devices) * (n-1)
        expected += f'stats {n*2} {n*2} {n*2*len(actions)} 0 0\n'
        expected += ''.join(f'ro {d["name"]} {ro}\n' for d, ro in zip(checks.DEVICES, states))
        case = dict(name=name, status='pending', actions=actions, passes=n, samples_seconds=[],
                    work_unit=dict(invocations=n, devices_per_invocation=2, opens=2*n, closes=2*n,
                                   ioctls=2*n*len(actions), output_records=len(expected.splitlines())-3),
                    expected_stdout_sha256=hashlib.sha256(expected.encode()).hexdigest(),
                    expected_status=0, validation=[])
        report['cases'].append(case)
        for sample in range(args.runs + 1):
            started = time.perf_counter()
            r = checks.invoke(binary, script)
            elapsed = time.perf_counter() - started
            valid = r.returncode == 0 and r.stdout == expected and not r.stderr
            case['validation'].append(dict(sample='warmup' if sample == 0 else sample,
                valid=valid, exit_code=r.returncode, stdout_sha256=hashlib.sha256(r.stdout.encode()).hexdigest(),
                stderr=r.stderr))
            if not valid:
                case['status'] = 'failed'
                args.output.write_text(json.dumps(report, indent=2) + '\n')
                raise RuntimeError(f'{name}: sample {sample} failed independent output/status oracle')
            if sample:
                case['samples_seconds'].append(elapsed)
        samples = case['samples_seconds']
        case.update(status='passed', median_seconds=statistics.median(samples), min_seconds=min(samples),
                    max_seconds=max(samples), mean_seconds=statistics.mean(samples), stdev_seconds=statistics.stdev(samples))
        print(name, case['status'], 'median_seconds', case['median_seconds'], 'samples', samples, flush=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
