#!/usr/bin/env python3
"""Fixed head work units; validate every warm-up and timed batch byte for byte.

Invoke through the campaign bench gate, after building separately. Reports are
new artifacts; this does not publish or regenerate historical catalog data.
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--before', type=Path)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--only-first', action='store_true', help='reproduce the existing first-N case before implementing new options')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.runs >= 7
    os.sched_setaffinity(0, {max(os.sched_getaffinity(0))})
    binary = args.binary.resolve()
    before = args.before.resolve() if args.before else None
    environment = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                   for _ in range(12000)).encode()[:423000]
    # 524,288 binary records, exactly 64 bytes apiece; embedded NULs included.
    large = (b'0123456789abcdef' * 3 + b'\0binary record!\n') * 524288
    assert len(large) == 32*1024*1024
    first100 = b'\n'.join(text.split(b'\n')[:100]) + b'\n'
    cases = [
        ('first-100-lines', text, ['-n', '100'], first100, 78, False),
        ('first-65536-bytes', large, ['-c', '65536'], large[:65536], 8, False),
        ('exclude-262144-lines', large, ['-n', '-262144'], large[:16*1024*1024], 3, False),
        ('exclude-16777216-bytes', large, ['-c', '-16777216'], large[:16*1024*1024], 3, False),
        ('pipe-exclude-262144-lines', large, ['-n', '-262144'], large[:16*1024*1024], 1, True),
    ]
    if args.only_first: cases = cases[:1]
    source_paths = ['patches/head-stdin.patch', 'bench/sol-head.py', 'tests/sol-head-options.py']
    report = {
        'method': 'wall time of persistent-shell batch including startup, redirects, and output to a temporary file; every call checks status; every batch checks exact bytes',
        'runs': args.runs, 'warmups': 1,
        'environment': {'uname': platform.uname()._asdict(), 'affinity': sorted(os.sched_getaffinity(0)),
                        'load_start': os.getloadavg(), 'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC',
                        'cpu_model': next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), '')},
        'source_state': 'working tree identified by source_sha256; source_commit is the base revision',
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'source_sha256': {p: sha(Path(p).read_bytes()) for p in source_paths},
        'stock_archive_sha256': sha(Path('dl/bash-5.3.tar.gz').read_bytes()),
        'build_manifests': {str(b): Path(str(b)+'.manifest.txt').read_text() for b in (binary, before) if b and Path(str(b)+'.manifest.txt').exists()},
        'tools': {}, 'cases': [],
    }
    for label, path in [('builtin', binary), ('gnu', Path('/usr/bin/head')), ('producer', Path('/usr/bin/cat')), ('before', before)]:
        if path:
            report['tools'][label] = {'path': str(path), 'sha256': sha(path.read_bytes()),
                                     'version': subprocess.check_output([str(path), '--version'], env=dict(os.environ, LC_ALL='C'), text=True).splitlines()[0]}
    with tempfile.TemporaryDirectory(prefix='sol-head-bench-') as directory:
        root = Path(directory)
        for name, data, options, expected, passes, pipe in cases:
            fixture = root / name
            fixture.write_bytes(data)
            row = {'name': name, 'options': options, 'passes': passes,
                   'input_kind': 'pipe' if pipe else 'regular file stdin',
                   'fixture_bytes': len(data), 'fixture_sha256': sha(data),
                   'output_bytes_per_call': len(expected), 'output_sha256_per_call': sha(expected),
                   'reset': 'fresh read-only input redirection per invocation', 'results': {}}
            report['cases'].append(row)
            commands = {'builtin': (binary, ['head']), 'gnu': (binary, ['/usr/bin/head'])}
            if before and name == 'first-100-lines': commands['before'] = (before, ['head'])
            wanted = expected * passes

            def invoke(shell, command, count):
                step = '/usr/bin/cat "$input" | "$@"' if pipe else '"$@" < "$input"'
                script = f'input=$1; count=$2; shift 2; set -o pipefail; for ((i=0;i<count;i++)); do {step} || exit; done'
                with tempfile.TemporaryFile() as output:
                    start = time.perf_counter_ns()
                    p = subprocess.run([str(shell), '--noprofile', '--norc', '-c', script, '_', str(fixture), str(count), *command, *options],
                                       stdout=output, stderr=subprocess.PIPE, env=environment, timeout=90)
                    ms = (time.perf_counter_ns() - start) / 1e6
                    output.seek(0)
                    actual = output.read()
                assert p.returncode == 0 and not p.stderr, (name, command, p.returncode, p.stderr)
                assert actual == expected * count, (name, command, len(actual), sha(actual))
                return ms

            # Independent Python expected bytes, verified against GNU and each
            # builtin, precede timing. Full-batch warm-up then every sample is
            # validated again; no DEVNULL-only timed path.
            for label, (shell, command) in commands.items():
                invoke(shell, command, 1)
                invoke(shell, command, passes)
                row['results'][label] = {'status': 'ok', 'samples_ms': []}
            for sample in range(args.runs):
                order = list(commands)
                order = order[sample % len(order):] + order[:sample % len(order)]
                if sample % 2: order.reverse()
                for label in order:
                    shell, command = commands[label]
                    row['results'][label]['samples_ms'].append(invoke(shell, command, passes))
            for result in row['results'].values():
                samples = result['samples_ms']
                result.update(median_ms=statistics.median(samples), min_ms=min(samples), max_ms=max(samples),
                              validated_batches=2+args.runs, validated_timed_bytes=len(wanted)*args.runs)
            row['builtin_over_gnu'] = row['results']['builtin']['median_ms'] / row['results']['gnu']['median_ms']
            print(name, json.dumps({label: r['median_ms'] for label, r in row['results'].items()}), flush=True)
            args.output.write_text(json.dumps(report, indent=2)+'\n')
    report['environment']['load_end'] = os.getloadavg()
    args.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
