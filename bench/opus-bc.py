#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Time bc programs through the builtin, an earlier builtin, and GNU bc.

Each workload is a fixed program with a fixed amount of work.  Its expected
output is GNU bc's output for the same bytes, computed once before timing.
Every timed run, warm-ups included, is checked against it: a run with the
wrong output or status marks that implementation INVALID for the workload
and no timing or ratio is published for it.

All implementations run from the same bash-os shell binary family with the
fixture redirected onto standard input, so the builtin pays no fork/exec and
the external program does.  Runs are interleaved per sample, pinned to one
CPU, and BC_LINE_LENGTH=0 is set for every one of them.

    python3 bench/opus-bc.py --after out/bash-opus-bc --before /path/bash-old \\
        --runs 7 --cpu 3 --output report.json
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time


def workloads():
    """(name, description, work unit, program bytes, runs in the old builtin)."""
    yield ('arithmetic', 'the historical loadables.py fixture, 80 invocations per sample',
           '80 x (scale=20; sqrt(2))', b'scale=20; sqrt(2)\n', True, 80)
    yield ('assign-lines', '200000 assignment statements, one per line, no output',
           '200000 statements', b'x=1\n' * 200000, True, 1)
    yield ('print-lines', '100000 lines each incrementing and printing a counter',
           '100000 statements, 100000 output lines',
           b'x=x+1;x\n' * 100000, True, 1)
    yield ('add-lines', '100000 six-digit additions, each printed',
           '100000 additions', b'123456+654321\n' * 100000, True, 1)
    yield ('big-output', 'one 9031-digit power printed 300 times',
           '2709300 output digits', b'x=2^30000\n' + b'x\n' * 300, True, 1)
    yield ('for-loop', 'a for loop summing 0..199999',
           '200000 iterations', b's=0\nfor (i = 0; i < 200000; i++) s += i\ns\n', False, 1)
    yield ('loop-print', 'a for loop printing 0..99999',
           '100000 iterations, 100000 output lines',
           b'for (i = 0; i < 100000; i++) i\n', False, 1)
    yield ('recursion', 'recursive fib(22): 57313 calls',
           '57313 user function calls',
           b'define f(n) { if (n < 2) return (n); return (f(n - 1) + f(n - 2)) }\nf(22)\n', False, 1)
    yield ('obase-output', '2^10000 printed in base 16, 10 times',
           '10 x 2501 hex digits', b'obase=16\nx=2^10000\n' + b'x\n' * 10, False, 1)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--after', required=True, help='bash-os binary with the builtin under test')
    ap.add_argument('--before', help='bash-os binary with an earlier builtin')
    ap.add_argument('--external', default='/usr/bin/bc')
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--warmup', type=int, default=1)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--only', help='comma-separated workload names')
    ap.add_argument('--alloc', help='LD_PRELOAD shim built from bench/opus-bc-alloc.c: count heap calls')
    ap.add_argument('--syscalls', action='store_true', help='count read/write system calls with strace')
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    if args.runs < 7:
        sys.exit('at least seven timed samples are required')
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})

    shells = {'after': str(Path(args.after).resolve())}
    if args.before:
        shells['before'] = str(Path(args.before).resolve())
    env = dict(os.environ, LC_ALL='C', BC_LINE_LENGTH='0')
    env.pop('BC_ENV_ARGS', None)
    only = set(args.only.split(',')) if args.only else None
    gnu_version = subprocess.run([args.external, '--version'], capture_output=True).stdout.split(b'\n')[0].decode()

    report = {
        'harness': 'bench/opus-bc.py', 'harness_sha256': sha256(__file__),
        'host': {'machine': platform.machine(), 'kernel': platform.release(),
                 'cpu_model': next((l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo')
                                    if l.startswith('model name')), None),
                 'cpus': os.cpu_count(), 'loadavg_start': os.getloadavg(),
                 'affinity': sorted(os.sched_getaffinity(0))},
        'binaries': {name: {'path': path, 'sha256': sha256(path)} for name, path in shells.items()},
        'external': {'path': args.external, 'sha256': sha256(args.external), 'version': gnu_version},
        'runs': args.runs, 'warmup': args.warmup, 'env': {'BC_LINE_LENGTH': '0', 'LC_ALL': 'C'},
        'workloads': [],
    }
    report['binaries']['external'] = report['external']

    with tempfile.TemporaryDirectory(prefix='opus-bc-bench-') as tmp:
        tmp = Path(tmp)
        for name, description, unit, program, old_ok, batch in workloads():
            if only and name not in only:
                continue
            fixture = tmp / f'{name}.bc'
            fixture.write_bytes(program)
            reference = subprocess.run([args.external], input=program, capture_output=True, env=env)
            assert reference.returncode == 0 and not reference.stderr, (name, reference.stderr[:200])
            expected = reference.stdout * batch
            # One shell per sample runs BATCH invocations, each with a fresh
            # redirection, and writes all output to one file.
            script = 'PATH=; for ((i = 0; i < $2; i++)); do %s < "$1" || exit; done > "$3"'
            impls = {'after': (shells['after'], script % 'bc')}
            if 'before' in shells:
                impls['before'] = (shells['before'], script % 'bc')
            impls['external'] = (shells['after'], script % args.external)
            entry = {'name': name, 'description': description, 'work_unit': unit,
                     'invocations_per_sample': batch,
                     'fixture_sha256': hashlib.sha256(program).hexdigest(), 'fixture_bytes': len(program),
                     'expected_sha256': hashlib.sha256(expected).hexdigest(), 'expected_bytes': len(expected),
                     'old_builtin_expected_to_run': old_ok, 'results': {}}
            samples = {k: [] for k in impls}
            valid = {k: True for k in impls}
            notes = {}
            out = tmp / 'out'
            for i in range(args.warmup + args.runs):
                for impl, (shell, text) in impls.items():
                    if not valid[impl]:
                        continue
                    start = time.perf_counter()
                    p = subprocess.run([shell, '--noprofile', '--norc', '-c', text, '_', str(fixture), str(batch), str(out)],
                                       stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, timeout=600)
                    elapsed = (time.perf_counter() - start) * 1000
                    got = out.read_bytes()
                    if p.returncode != 0 or got != expected or p.stderr:
                        valid[impl] = False
                        notes[impl] = {'pass': i, 'status': p.returncode, 'stderr': p.stderr[:300].decode(errors='replace'),
                                       'output_sha256': hashlib.sha256(got).hexdigest(), 'output_bytes': len(got)}
                        continue
                    if i >= args.warmup:
                        samples[impl].append(round(elapsed, 3))
            for impl in impls:
                if valid[impl]:
                    s = samples[impl]
                    entry['results'][impl] = {'result': 'ok', 'samples_ms': s, 'median_ms': round(statistics.median(s), 3),
                                              'min_ms': min(s), 'max_ms': max(s), 'validated_passes': args.warmup + args.runs}
                else:
                    entry['results'][impl] = {'result': 'INVALID', **notes[impl]}
            # Untimed, validated counting runs: heap calls and system calls
            # per implementation, minus the same shell loop running `:`.
            if args.alloc or args.syscalls:
                counts = {}
                for impl, (shell, text) in list(impls.items()) + [('empty-loop', (shells['after'], script % ':'))]:
                    if impl != 'empty-loop' and not valid[impl]:
                        continue
                    argv = [shell, '--noprofile', '--norc', '-c', text, '_', str(fixture), str(batch), str(out)]
                    c = {}
                    if args.alloc:
                        stats = tmp / 'alloc.json'
                        cenv = dict(env, LD_PRELOAD=str(Path(args.alloc).resolve()), OPUS_BC_ALLOC_OUT=str(stats))
                        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=cenv, timeout=600)
                        ok = p.returncode == 0 and (impl == 'empty-loop' or out.read_bytes() == expected)
                        c['heap'] = json.loads(stats.read_text()) if ok else 'INVALID'
                    if args.syscalls:
                        trace = tmp / 'strace.txt'
                        p = subprocess.run(['strace', '-f', '-c', '-e', 'trace=read,write', '-o', str(trace), *argv],
                                           stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=600)
                        ok = p.returncode == 0 and (impl == 'empty-loop' or out.read_bytes() == expected)
                        calls = {}
                        for line in trace.read_text().splitlines():
                            words = line.split()
                            if words and words[-1] in ('read', 'write') and words[-2].isdigit():
                                calls[words[-1]] = int(words[-2] if len(words) < 6 else words[3])
                        c['syscalls'] = calls if ok else 'INVALID'
                    counts[impl] = c
                base = counts.get('empty-loop', {})
                for impl, c in counts.items():
                    if impl == 'empty-loop':
                        continue
                    if isinstance(c.get('heap'), dict) and isinstance(base.get('heap'), dict):
                        c['heap_net'] = {k: c['heap'][k] - base['heap'][k] for k in c['heap']}
                    if isinstance(c.get('syscalls'), dict) and isinstance(base.get('syscalls'), dict):
                        c['syscalls_net'] = {k: c['syscalls'].get(k, 0) - base['syscalls'].get(k, 0)
                                             for k in ('read', 'write')}
                entry['counts'] = counts
            med = {k: v['median_ms'] for k, v in entry['results'].items() if v['result'] == 'ok'}
            if 'after' in med and 'external' in med:
                entry['after_over_external'] = round(med['after'] / med['external'], 4)
            if 'after' in med and 'before' in med:
                entry['after_over_before'] = round(med['after'] / med['before'], 4)
            report['workloads'].append(entry)
            print(name, {k: (v.get('median_ms') or v['result']) for k, v in entry['results'].items()}, flush=True)
    report['host']['loadavg_end'] = os.getloadavg()
    Path(args.output).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
