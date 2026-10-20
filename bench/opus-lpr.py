#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Time lpr spool-and-deliver byte work against a fixture backend.

One sample is one bash-os process that submits the same fixture JOBS times.
Each job is copied into a private spool, handed to a fake backend that
hashes its stdin with sha256sum, and withdrawn from the spool. The reference
does the same byte work with cp, the same backend and rm in the same shell.
Every pass of every sample is validated against a SHA-256 computed here, not
against the backend's own output, before its time is kept.

This measures spool and local delivery overhead. It is not printer
throughput: no printer, network protocol or rendering is involved.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

BACKEND = '#!/bin/sh\nexec /usr/bin/sha256sum > "$LPR_BENCH_OUT/$1.sum"\n'

LPR = r'''PATH=
for ((i = 0; i < JOBS; i++)); do lpr submit "$1" || exit; done
'''

REFERENCE = r'''PATH=
for ((i = 0; i < JOBS; i++)); do
  id=$(printf '%016x' "$i")
  /usr/bin/cp -- "$1" "$BASHLPR_SPOOL/$id.lpr" || exit
  printf 'accepted %s\n' "$id"
  "$BASHLPR_BACKEND" "$id" "$2" job < "$BASHLPR_SPOOL/$id.lpr" || exit
  /usr/bin/rm -- "$BASHLPR_SPOOL/$id.lpr" || exit
done
'''


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def version(argv):
    try:
        return subprocess.run(argv, capture_output=True, text=True).stdout.splitlines()[0]
    except (OSError, IndexError):
        return None


def run_once(binary, script, args, env, cpu):
    out = Path(env['LPR_BENCH_OUT'])
    for f in out.iterdir():
        f.unlink()
    pre = (lambda: os.sched_setaffinity(0, {cpu})) if cpu is not None else None
    start = time.perf_counter()
    p = subprocess.run([binary, '-c', script, 'lpr-bench', *args], env=env,
                       capture_output=True, preexec_fn=pre)
    elapsed = (time.perf_counter() - start) * 1000
    return p, elapsed


def validate(p, env, jobs, size, digest, kind):
    if p.returncode != 0:
        return f'exit {p.returncode}: {p.stderr[-400:]!r}'
    accepted = [l for l in p.stdout.decode().splitlines() if 'accepted' in l]
    if len(accepted) != jobs:
        return f'{len(accepted)} accepted lines, want {jobs}'
    if kind == 'lpr' and any(not l.endswith(f'({size} bytes)') for l in accepted):
        return 'accepted line with wrong byte count'
    sums = sorted(Path(env['LPR_BENCH_OUT']).iterdir())
    if len(sums) != jobs:
        return f'{len(sums)} backend outputs, want {jobs}'
    for s in sums:
        if s.read_text() != f'{digest}  -\n':
            return f'backend {s.name} hashed {s.read_text()!r}, want {digest}'
    left = list(Path(env['BASHLPR_SPOOL']).iterdir())
    if left:
        return f'spool not empty: {left}'
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, default=ROOT / 'out/bash')
    ap.add_argument('--size', type=int, default=8 << 20, help='fixture bytes per job')
    ap.add_argument('--jobs', type=int, default=16, help='submissions per sample')
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--warmup', type=int, default=1)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    binary = str(a.binary.resolve())

    with tempfile.TemporaryDirectory(prefix='opus-lpr-bench-') as tmp:
        tmp = Path(tmp)
        fixture = tmp / 'job.bin'
        rng = random.Random(1179)
        fixture.write_bytes(rng.randbytes(a.size))
        digest = sha256_file(fixture)
        backend = tmp / 'backend'
        backend.write_text(BACKEND)
        backend.chmod(0o700)
        (tmp / 'out').mkdir()
        spool = tmp / 'spool'
        spool.mkdir(mode=0o700)
        env = {'LANG': 'C', 'LC_ALL': 'C', 'HOME': str(tmp),
               'BASHLPR_SPOOL': str(spool), 'BASHLPR_BACKEND': str(backend),
               'LPR_BENCH_OUT': str(tmp / 'out')}
        cases = {
            'lpr': (LPR.replace('JOBS', str(a.jobs)), [str(fixture)]),
            'reference': (REFERENCE.replace('JOBS', str(a.jobs)), [str(fixture), str(a.size)]),
        }
        results = {}
        for name, (script, args) in cases.items():
            samples, failures = [], []
            for i in range(a.warmup + a.runs):
                p, ms = run_once(binary, script, args, env, a.cpu)
                err = validate(p, env, a.jobs, a.size, digest, name)
                if err:
                    failures.append({'pass': i, 'error': err})
                elif i >= a.warmup:
                    samples.append(round(ms, 3))
            ok = not failures and len(samples) == a.runs
            results[name] = {
                'status': 'ok' if ok else 'failed', 'samples_ms': samples,
                'median_ms': statistics.median(samples) if ok else None,
                'min_ms': min(samples) if ok else None,
                'max_ms': max(samples) if ok else None,
                'stdev_ms': statistics.stdev(samples) if ok and len(samples) > 1 else None,
                'failures': failures,
            }
        both = all(r['status'] == 'ok' for r in results.values())
        report = {
            'workload': 'lpr-spool-deliver',
            'work_unit': (f'{a.jobs} jobs x {a.size} B: copy into private spool, '
                          'deliver on stdin to a sha256sum fixture backend, remove spool entry'),
            'bytes_per_sample': a.jobs * a.size,
            'fixture_sha256': digest,
            'fixture_seed': 1179,
            'jobs': a.jobs, 'size': a.size, 'runs': a.runs, 'warmup': a.warmup,
            'cpu_affinity': a.cpu,
            'binary': binary, 'binary_sha256': sha256_file(binary),
            'source_sha256': sha256_file(ROOT / 'loadables/lpr.c'),
            'source_commit': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                            capture_output=True, text=True).stdout.strip(),
            'host': {'machine': platform.machine(), 'kernel': platform.release(),
                     'python': sys.version.split()[0], 'cpus': os.cpu_count()},
            'tools': {'sha256sum': version(['/usr/bin/sha256sum', '--version']),
                      'cp': version(['/usr/bin/cp', '--version']),
                      'sh': os.path.realpath('/bin/sh')},
            'results': results,
            'lpr_over_reference': (round(results['lpr']['median_ms'] / results['reference']['median_ms'], 4)
                                   if both else None),
            'scope': 'spool + local fixture-backend byte delivery; not printer throughput',
        }
        for r in results.values():
            if r['median_ms']:
                r['mib_per_s'] = round(a.jobs * a.size / (1 << 20) / (r['median_ms'] / 1000), 1)
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: (v['status'], v['median_ms']) for k, v in results.items()}),
          report['lpr_over_reference'])
    return 0 if both else 1


if __name__ == '__main__':
    sys.exit(main())
