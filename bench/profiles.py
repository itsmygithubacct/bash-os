#!/usr/bin/env python3
"""Compare binary size, warm shell startup and idle resident memory on Linux."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binaries', nargs='+', type=Path)
parser.add_argument('--runs', type=int, default=100)
parser.add_argument('--cpu', type=int)
args = parser.parse_args()
if args.runs < 1:
    parser.error('--runs must be positive')
if args.cpu is not None:
    os.sched_setaffinity(0, {args.cpu})
binaries = [path.resolve() for path in args.binaries]
timings = {path: [] for path in binaries}
memory = {path: [] for path in binaries}
environment = dict(os.environ, PATH='', LC_ALL='C', BASH_ENV='', ENV='')

def launch(path):
    start = time.perf_counter_ns()
    subprocess.run([str(path), '--noprofile', '--norc', '-c', ':'],
                   env=environment, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=10)
    return (time.perf_counter_ns()-start)/1e6

for path in binaries:
    for _ in range(5):
        launch(path)
for iteration in range(args.runs):
    order = binaries if iteration % 2 == 0 else list(reversed(binaries))
    for path in order:
        timings[path].append(launch(path))
for iteration in range(5):
    for path in binaries:
        with subprocess.Popen([str(path), '--noprofile', '--norc', '-c',
                               'printf "ready\\n"; read -r line'], env=environment,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            assert proc.stdout.readline() == b'ready\n'
            fields = {}
            for line in Path(f'/proc/{proc.pid}/smaps_rollup').read_text().splitlines():
                parts = line.split()
                if parts[0] in ('Rss:', 'Pss:'):
                    fields[parts[0][:-1]] = int(parts[1])
            memory[path].append(fields)
            proc.communicate(b'exit\n', timeout=10)
            assert proc.returncode == 0

print(f'{args.runs} interleaved warm starts; median wall time includes process launch and wait.')
print('Idle RSS/PSS: median of five shells after startup; helpers have not been exercised.')
print('| binary | injected | bytes | start ms | RSS KiB | PSS KiB |')
print('|---|---:|---:|---:|---:|---:|')
for path in binaries:
    manifest = path.with_name(path.name+'.manifest.json')
    count = len(json.loads(manifest.read_text())['names']) if manifest.exists() else '—'
    rss = statistics.median(item['Rss'] for item in memory[path])
    pss = statistics.median(item['Pss'] for item in memory[path])
    print(f'| {path.name} | {count} | {path.stat().st_size} | '
          f'{statistics.median(timings[path]):.3f} | {rss:.0f} | {pss:.0f} |')
