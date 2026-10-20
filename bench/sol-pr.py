#!/usr/bin/env python3
"""Validated fixed-work pr measurements. Run through the campaign bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source', type=Path)
p.add_argument('--passes', type=int, default=10)
a = p.parse_args()
assert a.passes > 0
binary = a.binary.resolve(strict=True)
root = Path(__file__).resolve().parents[1]
sha = lambda b: hashlib.sha256(b).hexdigest()
env = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
report = dict(binary=str(binary), binary_sha256=sha(binary.read_bytes()),
              source_sha256=sha((a.source or root/'loadables/pr.c').read_bytes()),
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
              affinity=sorted(os.sched_getaffinity(0)), kernel=platform.platform(),
              load_average_start=os.getloadavg(),
              compiler_version=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
              cpu=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
              environment=env, passes=a.passes, warmups=1, samples=7,
              reference_version=subprocess.check_output(['/usr/bin/pr', '--version'], text=True).splitlines()[0],
              shell_version=subprocess.check_output([str(binary), '--version'], text=True).splitlines()[0], cases=[])
script = '''file=$1; count=$2; shift 2
for ((i=0;i<count;i++)); do "$@" < "$file"; rc=$?; printf '\\036status=%d\\037' "$rc"; [[ $rc == 0 ]] || exit "$rc"; done'''
with tempfile.TemporaryDirectory(prefix='sol-pr-bench-') as d:
    fixture = Path(d)/'input'
    for name, options, data in [
        ('plain', ['-t'], b'plain record with words\n'*20000),
        ('columns-control', ['-t', '-3', '-n'], b'alpha\tbeta\0x\rY\bZ\n'*20000),
    ]:
        fixture.write_bytes(data)
        expected = subprocess.run(['/usr/bin/pr', *options], input=data, capture_output=True, env=env, check=True).stdout
        row = dict(name=name, options=options, fixture_sha256=sha(data), input_bytes=len(data), input_records=20000,
                   expected_bytes=len(expected), expected_sha256=sha(expected), results={})
        commands = {'builtin': ['pr', *options], 'gnu': ['/usr/bin/pr', *options]}
        for label in commands:
            row['results'][label] = dict(status='ok', samples_ms=[])
        for round_no in range(8):
            for label in (list(commands) if round_no % 2 == 0 else list(reversed(commands))):
                start = time.perf_counter_ns()
                got = subprocess.run([str(binary), '--noprofile', '--norc', '-c', script, '_', str(fixture), str(a.passes), *commands[label]], capture_output=True, env=env)
                elapsed = (time.perf_counter_ns()-start)/1e6
                result = row['results'][label]
                if got.returncode or got.stderr or got.stdout != (expected+b'\x1estatus=0\x1f')*a.passes:
                    result.update(status='failed', returncode=got.returncode, stderr=repr(got.stderr[:500]), actual_sha256=sha(got.stdout))
                elif round_no and result['status'] == 'ok':
                    result['samples_ms'].append(elapsed)
        for result in row['results'].values():
            if result['status'] == 'ok': result['median_ms'] = statistics.median(result['samples_ms'])
            else: result['samples_ms'] = []
        if all(r['status'] == 'ok' for r in row['results'].values()):
            row['builtin_over_gnu'] = row['results']['builtin']['median_ms']/row['results']['gnu']['median_ms']
        report['cases'].append(row)
        print(json.dumps(row), flush=True)
a.output.write_text(json.dumps(report, indent=2)+'\n')
raise SystemExit(any(r['status'] != 'ok' for c in report['cases'] for r in c['results'].values()))
