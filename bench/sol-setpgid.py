#!/usr/bin/env python3
"""Gated, independently validated owned-child API timing; no external ratio.
Build separately. Run through the campaign bench gate, which pins one CPU.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('setpgid_checks', ROOT/'tests/sol-setpgid-check.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sample_builtin(binary, operations):
    with checks.shell(binary) as s:
        pid = s.child()
        original = os.getpgid(s.p.pid)
        assert os.getpgid(pid) == original
        fd_before = len(list(Path(f'/proc/{s.p.pid}/fd').iterdir()))
        start = time.perf_counter_ns()
        for i in range(operations):
            group = pid if i % 2 == 0 else original
            rc, out, err = s.call(f'setpgid {pid} {0 if i % 2 == 0 else original}')
            assert (rc, out, err) == (0, [], ''), (i, rc, out, err)
            assert os.getpgid(pid) == group, (i, pid, group)
        elapsed = time.perf_counter_ns() - start
        assert os.getpgid(s.p.pid) == original
        assert len(list(Path(f'/proc/{s.p.pid}/fd').iterdir())) == fd_before
        s.release(pid)
    return elapsed


def sample_creation(binary, children):
    # Includes shell launch, builtin verification, pipe/coprocess creation,
    # ready PID exchange, independent group query, release, wait and shell exit.
    # There are zero setpgid calls in this separate workload.
    start = time.perf_counter_ns()
    for _ in range(children):
        with checks.shell(binary) as s:
            pid = s.child()
            assert os.getpgid(pid) == os.getpgid(s.p.pid)
            s.release(pid)
    return time.perf_counter_ns() - start


def sample_api(operations):
    # Different interpreter/control overhead: a diagnostic API timing only.
    read_fd, write_fd = os.pipe()
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        os.close(ready_read)
        os.write(ready_write, b'R')
        os.close(ready_write)
        os.read(read_fd, 1)
        os._exit(0)
    os.close(read_fd)
    os.close(ready_write)
    try:
        assert os.read(ready_read, 1) == b'R'
        os.close(ready_read)
        original = os.getpgid(pid)
        start = time.perf_counter_ns()
        for i in range(operations):
            expected = pid if i % 2 == 0 else original
            os.setpgid(pid, 0 if i % 2 == 0 else original)
            assert os.getpgid(pid) == expected
        elapsed = time.perf_counter_ns() - start
    finally:
        os.close(write_fd)
        assert os.waitpid(pid, 0) == (pid, 0)
    return elapsed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True)
    p.add_argument('--operations', type=int, default=4000)
    p.add_argument('--children', type=int, default=40)
    p.add_argument('--samples', type=int, default=7)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    assert args.operations > 0 and args.operations % 2 == 0
    assert args.children > 0 and args.samples >= 7
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'run under bench gate with fixed CPU affinity'
    binary = Path(args.binary).resolve()
    sources = ['bench/sol-setpgid.py', 'tests/sol-setpgid-check.py',
               'config/stock-patches.json', 'config/versions.sh', 'build.sh']
    if (ROOT/'patches/setpgid-ids.patch').exists():
        sources.append('patches/setpgid-ids.patch')
    fixtures = {name: digest(ROOT/name) for name in sources}
    fixture_id = hashlib.sha256(json.dumps(dict(hashes=fixtures, operations=args.operations,
        children=args.children, reset='new blocked owned child per sample; alternate own group and inherited group'),
        sort_keys=True).encode()).hexdigest()
    report = dict(kind='api', external_ratio=None, binary=str(binary),
                  binary_sha256=digest(binary), source_sha256=fixtures,
                  production_source_sha256=digest(ROOT/'build/bash-5.3/builtins/setpgid.c'),
                  fixture_sha256=fixture_id, options=vars(args) | {'output': str(args.output)},
                  affinity=affinity, environment=dict(kernel=platform.release(),
                      platform=platform.platform(), python=sys.version, executable=sys.executable,
                      cpu=next((line.split(':', 1)[1].strip() for line in
                          Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), None),
                      bash=subprocess.check_output([str(binary), '--version'], text=True).splitlines()[0],
                      compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                      clock='time.perf_counter_ns', path_during_shell_calls=''),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                  cases={})
    runners = {
        'builtin_owned_child_ipc': (lambda: sample_builtin(binary, args.operations), args.operations,
            'setpgid calls, alternating child-own group and inherited group; includes shell loop protocol, IPC and independent getpgid after every call; excludes creation and cleanup'),
        'python_owned_child_api': (lambda: sample_api(args.operations), args.operations,
            'os.setpgid calls with independent getpgid after every call; excludes fork and cleanup; different interpreter overhead, no builtin ratio'),
        'shell_and_child_lifecycle': (lambda: sample_creation(binary, args.children), args.children,
            'shell startups plus coprocess pipe/create/release/wait/exit; zero setpgid calls'),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for name, (_, work, description) in runners.items():
        report['cases'][name] = dict(status='pending', work_count=work, work_unit=description, samples_ns=[])
    try:
        for name, (run, _, _) in runners.items():
            report['cases'][name]['warmup_ns'] = run()
        for i in range(args.samples):
            order = list(runners) if i % 2 == 0 else list(reversed(runners))
            for name in order:
                report['cases'][name]['samples_ns'].append(runners[name][0]())
        for case in report['cases'].values():
            values = case['samples_ns']
            case.update(status='pass', validation='every operation status/output and exact independent group state checked; new owned child per pass',
                        min_ns=min(values), median_ns=statistics.median(values), max_ns=max(values),
                        median_ns_per_unit=statistics.median(values)/case['work_count'])
    except BaseException as e:
        report['error'] = repr(e)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    for name, case in report['cases'].items():
        print(name, case['status'], 'median ns/unit', round(case['median_ns_per_unit'], 2))


if __name__ == '__main__':
    main()
