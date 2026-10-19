#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run through the campaign bench gate. Fixed, validated rot13 work units.

Writes every timed pass to a private regular file and validates bytes after
stopping the clock. Reports shell-internal batch time separately from launch
and driver/wait overhead; the latter is NOT subtracted to invent a transform
cost. Use sol-bsdgames-transform.c for a production transform-only measurement.
"""
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

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--before', type=Path, required=True)
    ap.add_argument('--after', type=Path)
    ap.add_argument('--before-source', type=Path, required=True)
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--transform', type=Path, help='separately built production transform microbenchmark')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.runs < 7:
        ap.error('at least seven samples are required')
    before = str(args.before.resolve(strict=True))
    implementations = {'before': (before, ['bsdgames', 'rot13']),
                       'external': (before, ['/usr/bin/tr', 'A-Za-z', 'N-ZA-Mn-za-m'])}
    if args.after:
        implementations['after'] = (str(args.after.resolve(strict=True)), ['bsdgames', 'rot13'])
    env = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
    report = {'schema': 1, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'affinity': sorted(os.sched_getaffinity(0)), 'kernel': platform.release(),
              'architecture': platform.machine(), 'environment': env,
              'load_start': os.getloadavg(), 'runs': args.runs, 'warmups': 1,
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_sha256': digest((ROOT/'loadables/bsdgames.c').read_bytes()),
              'source_dirty': bool(subprocess.check_output(['git', 'diff', '--', 'loadables/bsdgames.c'], cwd=ROOT)),
              'harness_sha256': digest(Path(__file__).read_bytes()),
              'before_source_sha256': digest(args.before_source.read_bytes()),
              'compiler_version': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
              'libc_version': subprocess.check_output(['/usr/bin/getconf', 'GNU_LIBC_VERSION'], text=True).strip(),
              'binaries': {label: {'path': binary, 'sha256': digest(Path(binary).read_bytes()),
                                   'version': subprocess.check_output([binary, '--version'], text=True).splitlines()[0]}
                           for label, (binary, _) in implementations.items()},
              'tr_sha256': digest(Path('/usr/bin/tr').read_bytes()),
              'tr_version': subprocess.check_output(['/usr/bin/tr', '--version'], text=True).splitlines()[0],
              'method': 'One warm-up then rotated/reversed seven samples. Same persistent Bash loop and stdin redirection per pass; every status checked; private output file reset each batch and exact bytes checked for every timed pass. Inner Bash TIMEFORMAT seconds excludes process launch; outer perf_counter includes launch/wait; empty command control reported separately. No derived pure-transform claim.',
              'cases': []}
    report['cpu_model'] = next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name'))
    with tempfile.TemporaryDirectory(prefix='sol-bsdgames-bench-') as tmp:
        root = Path(tmp)
        # Includes the exact historical fixture, long lines and arbitrary bytes.
        cases = [('historical-duplicates', ''.join(f'{i//3:08d} word\n' for i in range(120000)).encode(), 3)]
        for size in [0, 1, 64, 4096, 65536, 1048576, 8388608]:
            unit = bytes(range(65, 256)) + bytes(range(65))
            cases.append((f'binary-{size}', (unit * (size//256+1))[:size], 10 if size < 1048576 else 3))
        cases += [('long-line-8m', b'AzBy' * (2*1024*1024), 3),
                  ('dense-lines-1m', b'A\n' * (512*1024), 3)]
        table = bytes((c-65+13)%26+65 if 65<=c<=90 else (c-97+13)%26+97 if 97<=c<=122 else c for c in range(256))

        def run(binary, command, count, expected):
            script = '''input=$1; count=$2; shift 2
TIMEFORMAT=%R
time { for ((i=0;i<count;i++)); do "$@" < "$input" || exit; done; }'''
            with (root/'output').open('wb') as output:
                start = time.perf_counter_ns()
                p = subprocess.run([binary, '--noprofile', '--norc', '-c', script, '_', 'input', str(count), *command],
                                   cwd=root, env=env, stdout=output, stderr=subprocess.PIPE, timeout=60)
                outer = (time.perf_counter_ns() - start)/1e6
            assert p.returncode == 0, (command, p.returncode, p.stderr)
            assert (root/'output').read_bytes() == expected*count, (command, 'invalid timed output')
            inner = float(p.stderr.decode().strip())*1000
            return {'outer_ms': outer, 'inner_ms': inner, 'exit_code': p.returncode,
                    'validated_passes': count, 'output_sha256': digest(expected*count)}

        for identifier, data, count in cases:
            (root/'input').write_bytes(data)
            wanted = data.translate(table)
            reference = subprocess.run(['/usr/bin/tr', 'A-Za-z', 'N-ZA-Mn-za-m'], input=data, capture_output=True, env=env, check=True)
            assert reference.stdout == wanted
            commands = {**implementations, 'empty-loop': (before, [':'])}
            row = {'id': identifier, 'bytes_per_pass': len(data), 'passes': count,
                   'fixture_sha256': digest(data), 'expected_sha256': digest(wanted), 'warmup': {}, 'results': {}}
            values = {label: [] for label in commands}
            for iteration in range(-1, args.runs):
                order = list(commands)
                if iteration >= 0:
                    order = order[iteration % len(order):] + order[:iteration % len(order)]
                    if iteration % 2:
                        order.reverse()
                for label in order:
                    binary, command = commands[label]
                    value = run(binary, command, count, b'' if label == 'empty-loop' else wanted)
                    if iteration >= 0:
                        values[label].append(value)
                    else:
                        row['warmup'][label] = value
            for label, samples in values.items():
                row['results'][label] = {'status': 'ok', 'samples': samples,
                    **{f'{kind}_median_ms': statistics.median(s[f'{kind}_ms'] for s in samples) for kind in ['outer', 'inner']}}
            report['cases'].append(row)
            args.output.write_text(json.dumps(report, indent=2)+'\n')
            print(identifier + ': ' + ', '.join(f'{k}={v["outer_median_ms"]:.3f}ms' for k,v in row['results'].items()), flush=True)
    if args.transform:
        transform = args.transform.resolve(strict=True)
        result = subprocess.run([str(transform)], capture_output=True, text=True, check=True, env=env, timeout=60)
        report['transform_only'] = json.loads(result.stdout)
        report['transform_only'].update(binary_sha256=digest(transform.read_bytes()),
            source_sha256=report['source_sha256'], function='bsdg_caesar_transform',
            fixture_sha256=digest(bytes(range(256)) * (8*1024*1024//256)),
            kind='api', includes='in-memory lookup loop and per-call monotonic clock overhead',
            excludes='launch, allocation, map initialization, input/output, independent verification')
    report['load_end'] = os.getloadavg()
    args.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
