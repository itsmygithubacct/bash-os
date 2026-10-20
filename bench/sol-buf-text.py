#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The catalog buf-text fixture, validating every timed output, including warmup."""
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

p = argparse.ArgumentParser()
p.add_argument('--before', type=Path, required=True)
p.add_argument('--after', type=Path, required=True)
p.add_argument('--before-source', type=Path, required=True)
p.add_argument('--rusage', type=Path, required=True)
p.add_argument('--cpu', type=int, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
os.sched_setaffinity(0, {a.cpu})
sha = lambda data: hashlib.sha256(data).hexdigest()
rng = random.Random(20260908)
words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
data = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
               for _ in range(12000)).encode()[:423000]
assert sha(data) == 'fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee'
report = dict(fixture_sha256=sha(data), input_bytes=len(data), operations=19,
              emitted_bytes=19*len(data), setup='new + load; same setup for cat; free after batch',
              affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
              method='one warmup and seven samples, alternating order; startup/setup included; exact entire output checked every batch; each of 19 commands must succeed',
              harness_sha256=sha(Path(__file__).read_bytes()),
              sources={'before': sha(a.before_source.read_bytes()), 'after': sha(Path('loadables/buf.c').read_bytes())},
              versions={'python': platform.python_version(), 'cat': subprocess.check_output(['/usr/bin/cat', '--version'], text=True).splitlines()[0]},
              results={})
commands = {'before': (a.before.resolve(), 'buf text "$b"'),
            'after': (a.after.resolve(), 'buf text "$b"'),
            'external': (a.after.resolve(), '/usr/bin/cat "$1"')}
for key, (binary, command) in commands.items():
    report['results'][key] = dict(binary_sha256=sha(binary.read_bytes()), samples_ms=[], peak_rss_kib=[], command=command, status='pending')
report['external_sha256'] = sha(Path('/usr/bin/cat').read_bytes())
with tempfile.TemporaryDirectory(prefix='sol-buf-text-') as td:
    d = Path(td)
    (d/'input').write_bytes(data)
    for sample in range(8):
        order = list(commands)
        if sample % 2: order.reverse()
        for key in order:
            binary, command = commands[key]
            script = f'PATH=; buf new -h b; buf load "$b" "$1"; for ((i=0;i<19;i++)); do {command} || exit; done; buf free "$b"'
            with (d/'output').open('wb') as out:
                start = time.perf_counter_ns()
                r = subprocess.run([str(a.rusage.resolve()), str(d/'rss'), str(binary), '-e', '-c', script, '_', str(d/'input')], env={'PATH':'','LC_ALL':'C','TZ':'UTC'}, stdout=out, stderr=subprocess.PIPE)
                ms = (time.perf_counter_ns()-start)/1e6
            assert r.returncode == 0 and r.stderr == b'', (key, r)
            assert (d/'output').read_bytes() == data*19, (key, sample)
            if sample:
                report['results'][key]['samples_ms'].append(ms)
                report['results'][key]['peak_rss_kib'].append(int((d/'rss').read_text()))
for result in report['results'].values():
    result.update(status='ok', median_ms=statistics.median(result['samples_ms']), validation='every byte, every operation, all eight batches')
report['after_over_external'] = report['results']['after']['median_ms']/report['results']['external']['median_ms']
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
