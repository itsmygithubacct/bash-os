#!/usr/bin/env python3
"""Validated seed transactions and isolated random-source costs; never builds.
Run through the campaign bench gate. No external ratio or entropy claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--harness', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    binary = str(Path(a.harness).resolve())
    report = dict(schema=1, kind='syscall-shim', cpu_affinity=sorted(os.sched_getaffinity(0)),
                  environment=dict(kernel=platform.release(), machine=platform.machine(),
                                   python=platform.python_version(), libc=platform.libc_ver(),
                                   cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
                                   tmpdir=os.environ.get('TMPDIR', '/tmp'),
                                   filesystem_statvfs=list(os.statvfs(os.environ.get('TMPDIR', '/tmp')))),
                  build_options='cc -O2 -g -Wall -Wextra; production linked with syscall wrappers; see hashed build script',
                  binary_sha256=sha(binary),
                  baseline_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                  source_state='task worktree identified by the source SHA-256 map',
                  tracked_diff_sha256=hashlib.sha256(subprocess.check_output(['git', 'diff', '--binary'])).hexdigest(),
                  sources={f: sha(f) for f in ['loadables/rngseed.c', 'tests/sol-rngseed-host.c',
                                              'tests/sol-rngseed-build.sh', 'bench/sol-rngseed.py']},
                  compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                  fixture=dict(size=512, mode='0600', parent_mode='0700', umask='0000',
                               original_sha256=hashlib.sha256(bytes((i*7+3)&255 for i in range(512))).hexdigest(),
                               replacement_sha256=hashlib.sha256(bytes((0xa5+i)&255 for i in range(512))).hexdigest(),
                               reset='load: recreate original before each pass; save: replace prior generated seed',
                               credit='RNDADDENTROPY always intercepted; poolsize shim 256 bits'),
                  method='One untimed warm-up per case; 9 samples; CLOCK_MONOTONIC around each production call; '
                         'validation/reset excluded from operation_ns, included in batch_wall_ns; no builds',
                  limitations=['No live entropy credit, CRNG initialization, storage power-cut or board qualification.',
                               'random-system measures initialized host getrandom only, no entropy-quality oracle.',
                               'shim timings include deterministic fill, request interception and trace bookkeeping.',
                               'Filesystem sync times depend on host filesystem/cache; no external ratio.'], cases=[])
    assert len(report['cpu_affinity']) == 1, 'pin CPU using bench gate'
    for name, count in [('save-shim', 100), ('load-shim', 100),
                        ('random-shim', 100000), ('random-system', 100000)]:
        case = dict(name=name, status='pending', passes_per_sample=count,
                    work_unit='512 bytes per pass; '+('one durable seed transaction' if name.endswith('-shim') and name[:4] != 'rand'
                                                     else 'one complete 512-byte random fill'),
                    warmup=None, samples=[])
        report['cases'].append(case)
        for sample in range(-1, 9):
            started = time.perf_counter_ns()
            r = subprocess.run([binary, '--batch', name, str(count)], capture_output=True, text=True)
            wall = time.perf_counter_ns()-started
            item = dict(exit_code=r.returncode, stderr=r.stderr, stdout=r.stdout, batch_wall_ns=wall)
            try:
                data = json.loads(r.stdout)
                assert r.returncode == 0 and data['status'] == 'pass' and data['case'] == name
                assert data['passes'] == count and data['bytes_validated'] == 512*count
                assert data['operation_ns'] > 0
                item.update(data)
            except (ValueError, KeyError, AssertionError):
                case['status'] = 'failed'
                case['failure'] = item
                Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
                raise SystemExit(f'{name}: failed validation')
            if sample == -1:
                case['warmup'] = item
            else:
                case['samples'].append(item)
        values = [s['operation_ns']/count for s in case['samples']]
        case.update(status='pass', ns_per_pass=dict(min=min(values), median=statistics.median(values),
                                                  max=max(values), samples=values))
    Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({c['name']: c['ns_per_pass'] for c in report['cases']}, indent=2))


if __name__ == '__main__':
    main()
