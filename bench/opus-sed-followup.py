#!/usr/bin/env python3
"""Paired sed builtin variants and GNU sed on the sol-sed workloads.

Usage: opus-sed-followup.py REPORT.json LABEL=BINARY[,SOURCE] [LABEL=...] [--cpu N]

Every variant and GNU sed run the same fixtures in one process, in rotating
order, after one warmup each. Every pass of every sample must produce the
exact expected bytes and status 0, or the run fails. Run under the campaign
bench gate. GNU sed runs in the first variant's shell.
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
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument('report', type=Path)
p.add_argument('variants', nargs='+')
p.add_argument('--cpu', type=int, default=11)
p.add_argument('--passes', type=int, default=8)
p.add_argument('--runs', type=int, default=7)
a = p.parse_args()
assert a.runs >= 7 and a.passes > 0
os.sched_setaffinity(0, {a.cpu})
sha = lambda b: hashlib.sha256(b).hexdigest()
variants = {}
for spec in a.variants:
    label, _, rest = spec.partition('=')
    binary, _, source = rest.partition(',')
    binary = Path(binary).resolve()
    variants[label] = dict(binary=str(binary), binary_sha256=sha(binary.read_bytes()),
                           source=source or None,
                           source_sha256=sha(Path(source).read_bytes()) if source else None,
                           version=subprocess.check_output([str(binary), '--version'], text=True).splitlines()[0])
first = next(iter(variants.values()))['binary']
env = dict(PATH='', LC_ALL='C', TZ='UTC')
report = dict(date_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), load_average_start=os.getloadavg(),
              affinity=sorted(os.sched_getaffinity(0)), environment=env, kernel=platform.release(),
              cpu=next(x for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
              driver_sha256=sha(Path(__file__).read_bytes()), passes=a.passes, runs=a.runs,
              gnu_version=subprocess.check_output(['/usr/bin/sed', '--version'], text=True).splitlines()[0],
              variants=variants, cases=[],
              method=('One process, fixed CPU, warm regular-file fixtures; each variant and GNU sed get one '
                      'validated warmup, then RUNS samples in rotating order. A sample is PASSES calls in one '
                      'shell loop, each writing a fresh regular file; every file and status is checked.'))
with tempfile.TemporaryDirectory(prefix='opus-sed-bench-') as directory:
    d = Path(directory)
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                   for _ in range(12000)).encode()[:423000]
    assert sha(text) == 'fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee'
    (d/'text').write_bytes(text)
    branch = b'alpha alpha beta\n' * 24000 + b'alpha'
    (d/'branch').write_bytes(branch)
    chunks = [b'first\n' + b'alpha beta\n'*8000, b'', b'alpha beta\n'*8000+b'last']
    for i, data in enumerate(chunks):
        (d/f'part{i}').write_bytes(data)
    (d/'empty').touch()
    # Expected bytes come from Python, independently of either sed.
    cases = [('historical-substitution', ['s/alpha/OMEGA/g'], 'text', text.replace(b'alpha', b'OMEGA')),
             ('branch', [':again;s/alpha/OMEGA/;t again'], 'branch', branch.replace(b'alpha', b'OMEGA')),
             ('multifile', ['-n', '1h;2,$H;$ {g;s/alpha/OMEGA/g;p;=;}', 'part0', 'part1', 'part2'],
              'empty', b''.join(chunks).replace(b'alpha', b'OMEGA') + b'\n16002\n')]
    program = ('input=$1; count=$2; shift 2; for ((i=0;i<count;i++)); do '
               '"$@" < "$input" > "pass-$i.out" || exit; done')

    def run(shell, argv, fixture, expected):
        for i in range(a.passes):
            (d/f'pass-{i}.out').unlink(missing_ok=True)
        start = time.perf_counter_ns()
        proc = subprocess.run([shell, '--noprofile', '--norc', '-c', program, '_', fixture, str(a.passes), *argv],
                              cwd=d, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300)
        elapsed = (time.perf_counter_ns() - start) / 1e6
        outputs = [(d/f'pass-{i}.out').read_bytes() if (d/f'pass-{i}.out').exists() else None
                   for i in range(a.passes)]
        valid = proc.returncode == 0 and all(o == expected for o in outputs)
        return elapsed, valid, proc.returncode, proc.stderr.decode(errors='replace')

    for name, args, fixture, expected in cases:
        row = dict(workload=name, args=args, fixture=fixture, fixture_sha256=sha((d/fixture).read_bytes()),
                   operand_sha256={f'part{i}': sha(c) for i, c in enumerate(chunks)} if name == 'multifile' else {},
                   input_bytes=sum(map(len, chunks)) if name == 'multifile' else len((d/fixture).read_bytes()),
                   expected_sha256=sha(expected), output_bytes=len(expected),
                   work_unit=f'{a.passes} calls per sample', results={})
        runners = {label: (v['binary'], ['sed', *args]) for label, v in variants.items()}
        runners['gnu'] = (first, ['/usr/bin/sed', *args])
        for label, (shell, argv) in runners.items():
            elapsed, valid, rc, err = run(shell, argv, fixture, expected)
            assert valid, (name, label, 'warmup', rc, err)
            row['results'][label] = dict(warmup_ms=elapsed, samples_ms=[], validated_passes=0)
        labels = list(runners)
        for n in range(a.runs):
            order = labels[n % len(labels):] + labels[:n % len(labels)]
            for label in order:
                shell, argv = runners[label]
                elapsed, valid, rc, err = run(shell, argv, fixture, expected)
                assert valid, (name, label, n, rc, err)
                row['results'][label]['samples_ms'].append(elapsed)
                row['results'][label]['validated_passes'] += a.passes
        for result in row['results'].values():
            values = result['samples_ms']
            result.update(median_ms=statistics.median(values), min_ms=min(values), max_ms=max(values))
        gnu = row['results']['gnu']['median_ms']
        row['over_gnu'] = {label: row['results'][label]['median_ms'] / gnu for label in variants}
        report['cases'].append(row)
        print(name, {label: round(r['median_ms'], 3) for label, r in row['results'].items()},
              {label: round(x, 3) for label, x in row['over_gnu'].items()}, flush=True)
report['load_average_end'] = os.getloadavg()
a.report.write_text(json.dumps(report, indent=2) + '\n')
