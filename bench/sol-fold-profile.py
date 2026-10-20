#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Diagnostic syscall profiles of the validated large Unicode byte workload.

Run through the bench gate. Trace timings are instrumentation data, not
throughput measurements; use sol-fold.py for untraced timings.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('oracle', ROOT / 'tests/sol-fold-check.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cpu', type=int, default=11)
    args = parser.parse_args()
    os.sched_setaffinity(0, {args.cpu})
    destination = Path(args.output)
    directory = destination.parent / (destination.stem + '-raw')
    directory.mkdir()
    env = dict(os.environ, LC_ALL='C.UTF-8', PATH='', TZ='UTC')
    for key in ['BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS', 'FOLD_MODULE', 'LD_PRELOAD']:
        env.pop(key, None)
    data = (('é界e\u0301 😀 alpha beta gamma delta\n' * 150000).encode())[:4230000]
    expected = oracle.oracle(data, 40, 'bytes') * 3
    report = dict(cpu_affinity=sorted(os.sched_getaffinity(0)), input_sha256=sha(data),
                  work='3 fresh redirects of 4,230,000 bytes, fold -b -w40, same persistent shell',
                  expected_sha256=sha(expected), passes=3, runs=7, profiles={},
                  note='Untraced warmup plus seven validated strace samples. No traced throughput ratios.')
    with tempfile.TemporaryDirectory(prefix='sol-fold-profile-') as temp:
        source, output = Path(temp) / 'input', Path(temp) / 'output'
        source.write_bytes(data)
        for name, binary, command in [('before', args.before, 'fold'), ('after', args.after, 'fold'),
                                      ('GNU', args.after, '/usr/bin/fold')]:
            binary = str(Path(binary).resolve())
            argv = [binary, '--noprofile', '--norc', '-c',
                    'for ((i=0;i<3;i++)); do ' + command + ' -b -w40 < "$1" || exit; done',
                    '_', str(source)]
            result = dict(binary_sha256=sha(Path(binary).read_bytes()), command=argv,
                          status='pending', samples=[])
            if name == 'GNU':
                result['external_binary_sha256'] = sha(Path('/usr/bin/fold').read_bytes())
            report['profiles'][name] = result
            for run in range(-1, 7):
                trace = directory / f'{name}-{run}.strace'
                invocation = argv if run == -1 else ['/usr/bin/strace', '-qq', '-f', '-c', '-o', str(trace), *argv]
                with output.open('wb') as stream:
                    proc = subprocess.run(invocation, stdout=stream, stderr=subprocess.PIPE, env=env, timeout=60)
                valid = proc.returncode == 0 and not proc.stderr and output.read_bytes() == expected
                assert valid, (name, run, proc.returncode, proc.stderr)
                if run >= 0:
                    counts = {}
                    for line in trace.read_text().splitlines():
                        fields = line.split()
                        if len(fields) >= 5 and fields[-1] in ('read', 'write'):
                            counts[fields[-1]] = int(fields[3])
                    result['samples'].append(dict(trace=str(trace), counts=counts, status='ok'))
            result['status'] = 'ok'
        # Optional hardware counters: preserve a permission failure explicitly.
        counters = directory / 'perf-stat.txt'
        argv = [str(Path(args.after).resolve()), '-c', 'fold -b -w40 < "$1"', '_', str(source)]
        with output.open('wb') as stream:
            proc = subprocess.run(['/usr/bin/perf', 'stat', '-e', 'cycles,instructions',
                                   '-o', str(counters), '--', *argv],
                                  stdout=stream, stderr=subprocess.PIPE, env=env, timeout=60)
        report['hardware_counters'] = dict(status='ok' if proc.returncode == 0 else 'unavailable',
                                           exit_code=proc.returncode, log=str(counters),
                                           command=['/usr/bin/perf', 'stat', '-e', 'cycles,instructions', '-o', str(counters), '--', *argv],
                                           stderr=proc.stderr.decode(errors='replace'))
        if proc.returncode == 0:
            assert output.read_bytes() == expected[:len(expected) // 3]
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v['status'] for k, v in report['profiles'].items()}))


if __name__ == '__main__':
    main()
