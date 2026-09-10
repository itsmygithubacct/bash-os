#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the zstd builtin with the host's zstd(1).

Compressed frames are not compared byte-for-byte: the builtin and zstd(1)
emit different frames at the same level. Validation is:

- compress: GNU zstd -d of the captured output must recover the fixture
- decompress: stdout must equal the original fixture

BusyBox has no zstd applet in the Debian builds this has been run against.
Every timed command is launched from the same bash-os shell.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time

import loadables


ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'
GNU_ZSTD = '/usr/bin/zstd'


def decode_frame(frame):
    p = subprocess.run([GNU_ZSTD, '-d', '-c', '-q', '-'],
                       input=frame, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=30)
    if p.returncode:
        return None, p.stderr[:512]
    return p.stdout, b''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'out/bash')
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--passes', type=int, help='Fixed invocations per batch')
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit')
    args = parser.parse_args()
    if args.runs < 1:
        parser.error('--runs must be positive')
    if args.passes is not None and args.passes < 1:
        parser.error('--passes must be positive')
    binary = str(args.binary.resolve(strict=True))
    if not Path(GNU_ZSTD).is_file():
        parser.error(f'{GNU_ZSTD} is required as the reference')
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})
    environment = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
    if args.source_commit:
        source_commit = args.source_commit
    else:
        source_commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    report = {
        'schema': 1,
        'command': 'zstd',
        'date': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source_commit': source_commit,
        'binary': Path(binary).name,
        'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        'kernel': platform.release(),
        'architecture': platform.machine(),
        'cpus': sorted(os.sched_getaffinity(0)),
        'load_average_start': os.getloadavg(),
        'runs': args.runs,
        'method': (
            'Same bash-os shell; builtin or absolute /usr/bin/zstd; '
            'median untraced batch wall time; stdout /dev/null; warm file cache. '
            'Compress validation is GNU zstd -d of the captured frame; '
            'decompress validation is byte identity with the original fixture. '
            'Frames themselves are not compared.'
        ),
    }
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name') or line.startswith('Hardware'):
            report['cpu_model'] = line.split(':', 1)[1].strip()
            if line.startswith('model name'):
                break
    if 'cpu_model' not in report:
        report['cpu_model'] = platform.processor() or platform.machine()
    report['versions'] = {}
    for name, cmd in [
        ('bash', [binary, '--version']),
        ('zstd', [GNU_ZSTD, '--version']),
        ('busybox', ['/usr/bin/busybox'] if Path('/usr/bin/busybox').is_file() else []),
    ]:
        if cmd:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            report['versions'][name] = (p.stdout or p.stderr).splitlines()[0]
    ldd = subprocess.run(['ldd', binary], capture_output=True, text=True, timeout=5)
    report['libzstd'] = next((line.strip() for line in ldd.stdout.splitlines()
                              if 'libzstd' in line), 'not dynamically linked')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report['cases'] = []

    def save():
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    with tempfile.TemporaryDirectory(prefix='bash-os-zstd-bench-') as directory:
        root = Path(directory)
        report['fixtures'] = loadables.fixtures(root)
        originals = {
            'text': (root/'text').read_bytes(),
            'blob': (root/'blob').read_bytes(),
        }
        frames = {}
        for name, data in originals.items():
            p = subprocess.run([GNU_ZSTD, '-c', '-q', '-'],
                               input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=30)
            if p.returncode:
                parser.error(f'GNU zstd failed to compress {name}: {p.stderr[:200]!r}')
            frames[name] = p.stdout
            (root/f'{name}.zst').write_bytes(p.stdout)
            recovered, err = decode_frame(p.stdout)
            if recovered != data:
                parser.error(f'GNU zstd frame for {name} does not round-trip: {err!r}')
            report['fixtures'][f'{name}.zst'] = {
                'bytes': len(p.stdout),
                'sha256': hashlib.sha256(p.stdout).hexdigest(),
                'producer': 'gnu-zstd -c -q -',
            }

        cases = [
            dict(id='compress-text', mode='compress', fixture='text',
                 original='text', args=['-c', '-'], maximum=80),
            dict(id='compress-blob', mode='compress', fixture='blob',
                 original='blob', args=['-c', '-'], maximum=80),
            dict(id='decompress-text', mode='decompress', fixture='text.zst',
                 original='text', args=['-d', '-c', '-'], maximum=80),
            dict(id='decompress-blob', mode='decompress', fixture='blob.zst',
                 original='blob', args=['-d', '-c', '-'], maximum=80),
        ]

        def run(command, fixture, count, *, capture=False):
            script = ('input=$1; count=$2; shift 2; '
                      'for ((i=0;i<count;i++)); do "$@" < "$input" || exit; done')
            argv = [binary, '--noprofile', '--norc', '-c', script, 'bench',
                    fixture, str(count), *command]
            with tempfile.TemporaryFile() as output:
                start = time.perf_counter_ns()
                try:
                    p = subprocess.run(
                        argv, cwd=root, env=environment,
                        stdout=output if capture else subprocess.DEVNULL,
                        stderr=subprocess.PIPE, timeout=120)
                except subprocess.TimeoutExpired:
                    return {'status': 'timeout'}
                elapsed = (time.perf_counter_ns() - start) / 1e6
                err = p.stderr[:2048].decode(errors='replace')
                if p.returncode:
                    return {'status': 'error', 'returncode': p.returncode,
                            'stderr': err, 'ms': elapsed}
                output.seek(0)
                return {'status': 'ok', 'ms': elapsed,
                        'data': output.read() if capture else b'', 'stderr': err}

        def accepted_output(mode, original, data):
            if mode == 'decompress':
                return data == original, {
                    'expected_sha256': hashlib.sha256(original).hexdigest(),
                    'actual_sha256': hashlib.sha256(data).hexdigest(),
                    'expected_bytes': len(original),
                    'actual_bytes': len(data),
                }
            recovered, err = decode_frame(data)
            if recovered is None:
                return False, {'status': 'decode-error',
                               'stderr': err.decode(errors='replace')}
            return recovered == original, {
                'frame_bytes': len(data),
                'frame_sha256': hashlib.sha256(data).hexdigest(),
                'expected_sha256': hashlib.sha256(original).hexdigest(),
                'recovered_sha256': hashlib.sha256(recovered).hexdigest(),
            }

        for case in cases:
            original = originals[case['original']]
            row = {
                'id': case['id'],
                'loadable': 'zstd',
                'mode': case['mode'],
                'args': list(case['args']),
                'fixture': case['fixture'],
                'results': {},
            }
            commands = {
                'bashos': ['zstd', *case['args']],
                'external': [GNU_ZSTD, *case['args']],
            }
            row['results']['busybox'] = {'status': 'unavailable'}
            initial = {}
            for label, command in commands.items():
                result = run(command, case['fixture'], 1, capture=True)
                initial[label] = result
            accepted = []
            for label, result in initial.items():
                if result['status'] != 'ok':
                    row['results'][label] = {k: v for k, v in result.items()
                                             if k not in ['data']}
                    continue
                ok, detail = accepted_output(case['mode'], original, result['data'])
                if not ok:
                    row['results'][label] = {'status': 'output-mismatch', **detail}
                else:
                    accepted.append(label)
                    if case['mode'] == 'compress':
                        row.setdefault('frames', {})[label] = {
                            'bytes': len(result['data']),
                            'sha256': hashlib.sha256(result['data']).hexdigest(),
                        }
            if 'bashos' not in accepted or 'external' not in accepted:
                report['cases'].append(row)
                save()
                print(case['id'] + ': ' + ', '.join(
                    label + '=' + str(row['results'].get(label, {}).get(
                        'status', 'ok' if label in accepted else 'missing'))
                    for label in ['bashos', 'external', 'busybox']), flush=True)
                continue
            probe = run(commands['bashos'], case['fixture'], 5)
            if probe['status'] != 'ok':
                row['results']['bashos'] = {k: v for k, v in probe.items()
                                            if k not in ['data']}
                report['cases'].append(row)
                save()
                continue
            passes = args.passes or max(3, min(case['maximum'],
                                              math.ceil(75 / (probe['ms'] / 5))))
            row['passes'] = passes
            validation_passes = max(3, passes)
            row['validation_passes'] = validation_passes
            for label in list(accepted):
                batch = run(commands[label], case['fixture'],
                            validation_passes, capture=True)
                if batch['status'] != 'ok':
                    accepted.remove(label)
                    row['results'][label] = {k: v for k, v in batch.items()
                                             if k not in ['data']}
                    continue
                if case['mode'] == 'decompress':
                    wanted = original * validation_passes
                    actual = batch['data']
                    ok = actual == wanted
                    detail = {
                        'expected_bytes': len(wanted),
                        'actual_bytes': len(actual),
                    }
                else:
                    # Concatenated zstd frames; GNU zstd -d reads the whole stream.
                    recovered, err = decode_frame(batch['data'])
                    ok = recovered == original * validation_passes
                    detail = {
                        'expected_bytes': len(original) * validation_passes,
                        'actual_bytes': 0 if recovered is None else len(recovered),
                    }
                    if recovered is None:
                        detail['stderr'] = err.decode(errors='replace')
                if not ok:
                    accepted.remove(label)
                    row['results'][label] = {'status': 'batch-mismatch', **detail}
            samples = {label: [] for label in accepted}
            for round_number in range(report['runs']):
                order = (accepted[round_number % len(accepted):]
                         + accepted[:round_number % len(accepted)])
                if round_number % 2:
                    order.reverse()
                for label in order:
                    timed = run(commands[label], case['fixture'], passes)
                    if timed['status'] != 'ok':
                        row['results'][label] = {k: v for k, v in timed.items()
                                                 if k not in ['data']}
                    else:
                        samples[label].append(timed['ms'])
            for label, values in samples.items():
                if len(values) == report['runs']:
                    row['results'][label] = {
                        'status': 'ok',
                        'median_ms': round(statistics.median(values), 3),
                        'min_ms': round(min(values), 3),
                        'max_ms': round(max(values), 3),
                        'runs_ms': [round(value, 3) for value in values],
                    }
            report['cases'].append(row)
            save()
            print(case['id'] + ': ' + ', '.join(
                label + '=' + str(result.get('median_ms', result['status']))
                for label, result in row['results'].items()), flush=True)
    report['load_average_end'] = os.getloadavg()
    save()


if __name__ == '__main__':
    main()
