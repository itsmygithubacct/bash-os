#!/usr/bin/env python3
"""Validated production swapoff parsing/request batches; syscall-shim time only.

Run through the campaign bench gate. Build artifacts separately through its
build gate; this driver never compiles. No real swap syscall can be forwarded.
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
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('swapoff_contract', ROOT / 'tests/sol-swapoff-check.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixture-dir', type=Path,
                        default=Path(os.environ.get('BASHOS_TASK_DIR', Path.cwd())) / 'tmp')
    parser.add_argument('--passes', type=int, default=200)
    parser.add_argument('--runs', type=int, default=7)
    args = parser.parse_args()
    if args.runs < 7 or args.passes < 1:
        parser.error('at least seven samples and one pass required')
    args.binary = args.binary.resolve()
    args.shim = args.shim.resolve()
    affinity = sorted(os.sched_getaffinity(0))
    if len(affinity) != 1:
        parser.error('pin to one CPU through the bench gate')
    cases = [dict(name='named-64', argv=['/named/' + str(i) for i in range(64)],
                  data=contract.HEADER, expected=['/named/' + str(i) for i in range(64)], rows=0, opens=0),
             dict(name='all-empty', argv=['-a'], data=contract.HEADER, expected=[], rows=0, opens=1)]
    # 128 independently specified decoded names; 256 valid input rows include
    # duplicates and all four kernel escapes. Expected paths do not use the
    # production decoder or derive from its observed output.
    encoded = [f'/space\\040{i}\\011tab\\012line\\134end' for i in range(128)]
    decoded = [f'/space {i}\ttab\nline\\end' for i in range(128)]
    data = contract.HEADER + b''.join(contract.row(p) for p in encoded * 2)
    cases.append(dict(name='all-256-rows-128-requests', argv=['-a'], data=data, expected=decoded, rows=256, opens=1))
    report = dict(kind='syscall-shim', status='pass', external_ratio=None, warmups=1, runs=args.runs,
                  passes=args.passes, environment=dict(cpu_affinity=affinity, platform=platform.platform(),
                  python=sys.version, libc=platform.libc_ver(),
                  cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                                  if line.startswith('model name')), 'unknown'),
                  binary_version=subprocess.run([str(args.binary), '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0],
                  compiler=subprocess.run(['cc', '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]),
                  provenance=dict(binary=str(args.binary), binary_sha256=digest(args.binary), shim=str(args.shim),
                  shim_sha256=digest(args.shim), source_sha256=digest(ROOT / 'loadables/swapoff.c'),
                  driver_sha256=digest(__file__), fixture_driver_sha256=digest(ROOT / 'tests/sol-swapoff-check.py'),
                  shim_source_sha256=digest(ROOT / 'tests/sol-swapoff-shim.c'),
                  source_commit=subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip(),
                  source_diff_sha256=hashlib.sha256(subprocess.run(['git', 'diff', 'HEAD', '--', 'loadables/swapoff.c'], cwd=ROOT, capture_output=True, check=True).stdout).hexdigest()),
                  reset='immutable private fixture, expected sequence set once per process, request/open/close counters checked and reset after every invocation; fresh shell each sample',
                  timing_scope='wall time includes shell startup, fixture setup, shell loop and per-pass oracle; no real swapoff syscall',
                  limitations=['No matched external reference or speedup ratio.',
                               'No real-device disable latency, kernel reclamation, memory pressure or privilege qualification.'], cases=[])
    args.fixture_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sol-swapoff-bench-', dir=args.fixture_dir) as tmp:
        fixture = Path(tmp) / 'swaps'
        for case in cases:
            fixture.write_bytes(case['data'])
            q = contract.quote
            script = contract.shell_setup(args.shim)
            script += f'swapoff_fixture source {q(fixture)} || exit 93\n'
            script += 'swapoff_fixture expect ' + ' '.join(map(q, case['expected'])) + ' || exit 93\n'
            command = 'swapoff ' + ' '.join(map(q, case['argv']))
            script += f'for ((i=0; i<{args.passes}; i++)); do\n{command} || exit 81\n'
            script += f'swapoff_fixture check {len(case["expected"])} {case["opens"]} {case["opens"]} || exit 82\ndone\n'
            script += 'swapoff_fixture reset || exit 83\n'
            marker = f'validated {args.passes} passes {len(case["expected"]) * args.passes} requests\n'
            script += 'printf %s ' + q(marker) + '\n'
            case_report = dict(name=case['name'], status='pass', options=case['argv'], fixture_sha256=hashlib.sha256(case['data']).hexdigest(),
                               fixture_bytes=len(case['data']), rows_per_pass=case['rows'], requests_per_pass=len(case['expected']),
                               work_unit=f'{args.passes} builtin calls; {args.passes * case["rows"]} rows; {args.passes * len(case["expected"])} intercepted requests',
                               expected_sequence_sha256=hashlib.sha256(b'\x00'.join(p.encode() for p in case['expected'])).hexdigest(),
                               script_sha256=hashlib.sha256(script.encode()).hexdigest(), warmup=None, samples=[])
            for sample in range(args.runs + 1):
                started = time.perf_counter_ns()
                proc = subprocess.run([str(args.binary), '--noprofile', '--norc', '-c', script], env=contract.environment(args.shim), capture_output=True)
                elapsed = time.perf_counter_ns() - started
                valid = proc.returncode == 0 and proc.stdout == marker.encode() and proc.stderr == b''
                result = dict(elapsed_ns=elapsed, status='pass' if valid else 'fail', exit_code=proc.returncode,
                              stdout=proc.stdout.decode(errors='replace'), stderr=proc.stderr.decode(errors='replace'))
                if sample == 0:
                    case_report['warmup'] = result
                else:
                    case_report['samples'].append(result)
                if not valid:
                    case_report['status'] = report['status'] = 'fail'
                    break
            if case_report['status'] == 'pass':
                seconds = [s['elapsed_ns'] / 1e9 for s in case_report['samples']]
                med = statistics.median(seconds)
                case_report['summary'] = dict(samples_seconds=seconds, median_seconds=med, min_seconds=min(seconds), max_seconds=max(seconds),
                                              median_us_per_call=med * 1e6 / args.passes)
            report['cases'].append(case_report)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(dict(name=case_report['name'], status=case_report['status'], summary=case_report.get('summary')), indent=2), flush=True)
            if report['status'] != 'pass':
                break
    raise SystemExit(report['status'] != 'pass')


if __name__ == '__main__':
    main()
