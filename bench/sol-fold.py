#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh fold measurements; invoke through the campaign bench gate.

Every warmup/timed batch checks exact output and every command's status.
Unicode column/character cases use an independent Python oracle, with no
external ratio. ASCII and Unicode byte mode also validate GNU equivalence.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fold_oracle', ROOT / 'tests/sol-fold-check.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--cpu', type=int, default=11)
    args = parser.parse_args()
    assert args.runs >= 7
    assert args.cpu in os.sched_getaffinity(0)
    os.sched_setaffinity(0, {args.cpu})
    binary = str(Path(args.binary).resolve())
    env = dict(os.environ, PATH='', LC_ALL='C.UTF-8', TZ='UTC')
    for key in ('BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'FOLD_MODULE', 'LD_PRELOAD'):
        env.pop(key, None)
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    ascii_data = ''.join(' '.join(rng.choice(words) for _ in range(10)) + '\n' for _ in range(12000)).encode()[:423000]
    unicode_data = ('é界e\u0301 😀 alpha beta gamma delta\n' * 150000).encode()
    report = {
        'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'method': 'one warmup then >=7 interleaved timed batches; exact output checked on EVERY pass; '
                  'fresh stdin redirect per invocation in one persistent Bash; output captured to private regular file; '
                  'time includes shell startup and, for GNU, fork/exec; validation outside timed interval',
        'environment': {'platform': platform.platform(), 'machine': platform.machine(),
                        'cpu_affinity': sorted(os.sched_getaffinity(0)), 'python': platform.python_version(),
                        'python_unicode_tables': module.unicodedata.unidata_version,
                        'load_start': os.getloadavg(), 'cpuinfo': Path('/proc/cpuinfo').read_text().split('model name')[1].split('\n')[0],
                        'locale': 'C.UTF-8', 'PATH': '', 'uname': list(platform.uname())},
        'versions': {'bash': subprocess.check_output([binary, '--version'], env=env, text=True),
                     'gnu_fold': subprocess.check_output(['/usr/bin/fold', '--version'], text=True),
                     'compiler': subprocess.check_output(['cc', '--version'], text=True)},
        'binary': binary, 'binary_sha256': sha(Path(binary).read_bytes()),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_fold_sha256': sha((ROOT / 'loadables/fold.c').read_bytes()),
        'source_fold_differs_from_commit': (ROOT / 'loadables/fold.c').read_bytes() != subprocess.check_output(
            ['git', 'show', 'HEAD:loadables/fold.c'], cwd=ROOT),
        'harness_sha256': sha(Path(__file__).read_bytes()),
        'oracle_sha256': sha((ROOT / 'tests/sol-fold-check.py').read_bytes()),
        'cases': [],
    }
    with tempfile.TemporaryDirectory(prefix='sol-fold-bench-') as directory:
        source, output = Path(directory) / 'input', Path(directory) / 'output'
        for size in [64, 4096, 423000, 4230000]:
            for kind, mode, flags in [('ascii', 'columns', []), ('unicode-byte', 'bytes', ['-b']),
                                      ('unicode-column', 'columns', []), ('unicode-character', 'characters', ['-c'])]:
                data = (ascii_data * 10)[:size] if kind == 'ascii' else unicode_data[:size]
                expected = module.oracle(data, 40, mode)
                passes = 128 if size == 64 else 32 if size == 4096 else 9 if size == 423000 else 3
                source.write_bytes(data)
                compared = kind in ['ascii', 'unicode-byte']
                if compared:
                    ref = subprocess.run(['/usr/bin/fold', *flags, '-w40'], input=data, capture_output=True, env=env)
                    assert ref.returncode == 0 and ref.stdout == expected and not ref.stderr, (kind, size, 'GNU oracle mismatch')
                case = {'name': f'{kind}-{size}', 'kind': 'compared' if compared else 'api',
                        'input_bytes': len(data), 'input_sha256': sha(data), 'options': [*flags, '-w40'],
                        'expected_bytes': len(expected), 'expected_sha256': sha(expected), 'passes': passes,
                        'work_unit': f'{passes} independent redirects of {len(data)} input bytes; {len(expected)} output bytes each',
                        'results': {}}
                report['cases'].append(case)
                implementations = ['builtin', 'GNU'] if compared else ['builtin']
                for name in implementations:
                    case['results'][name] = {'status': 'pending', 'samples_ms': [], 'validated_passes': 0}
                for iteration in range(args.runs + 1):
                    for name in implementations if iteration % 2 == 0 else implementations[::-1]:
                        command = 'fold' if name == 'builtin' else '/usr/bin/fold'
                        script = '[[ $(type -t fold) == builtin ]] || exit 99; '
                        script += f'for ((i=0;i<{passes};i++)); do {command} ' + ' '.join([*flags, '-w40']) + ' < "$1" || exit; done'
                        with output.open('wb') as stream:
                            start = time.perf_counter_ns()
                            proc = subprocess.run([binary, '--noprofile', '--norc', '-c', script, '_', str(source)],
                                                  stdout=stream, stderr=subprocess.PIPE, env=env, timeout=120)
                            elapsed = (time.perf_counter_ns() - start) / 1e6
                        result = case['results'][name]
                        actual = output.read_bytes()
                        valid = proc.returncode == 0 and not proc.stderr and actual == expected * passes
                        if not valid:
                            result.update(status='failed', exit_code=proc.returncode,
                                          stderr=proc.stderr.decode(errors='replace'), actual_sha256=sha(actual))
                            Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
                            raise AssertionError((case['name'], name, 'output/status mismatch'))
                        result['validated_passes'] += passes
                        if iteration:
                            result['samples_ms'].append(elapsed)
                        else:
                            result['warmup_ms'] = elapsed
                for result in case['results'].values():
                    values = result['samples_ms']
                    result.update(status='ok', median_ms=statistics.median(values), min_ms=min(values), max_ms=max(values))
                if compared:
                    case['builtin_over_GNU'] = case['results']['builtin']['median_ms'] / case['results']['GNU']['median_ms']
                print(case['name'], {k: round(v['median_ms'], 3) for k, v in case['results'].items()}, flush=True)
                Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
    report['environment']['load_end'] = os.getloadavg()
    report['ended_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    Path(args.output).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
