#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated IPC creation/inspection/removal cycles, self timings only.

Build separately. Run this driver through the campaign bench gate.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ipcmk_tests', ROOT / 'tests/sol-ipcmk.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True); ap.add_argument('--oracle', required=True)
    ap.add_argument('--output', required=True); ap.add_argument('--passes', type=int, default=200)
    ap.add_argument('--samples', type=int, default=7)
    a = ap.parse_args()
    if a.samples < 7 or a.passes < 1: ap.error('at least seven samples and positive passes required')
    binary = str(Path(a.binary).resolve())
    affinity = sorted(os.sched_getaffinity(0))
    if len(affinity) != 1: ap.error('pin to one CPU (the campaign bench gate does this)')
    sources = ['loadables/ipcmk.c', 'tests/sol-ipcmk-kernel.c', 'tests/sol-ipcmk.py', 'bench/sol-ipcmk.py']
    policies = {}
    for path in ['/proc/sys/kernel/shmmax', '/proc/sys/kernel/shmall', '/proc/sys/kernel/shmmni', '/proc/sys/kernel/sem', '/proc/sys/kernel/msgmni', '/proc/sys/fs/mqueue/msg_default', '/proc/sys/fs/mqueue/msgsize_default', '/proc/sys/fs/mqueue/msg_max', '/proc/sys/fs/mqueue/queues_max']:
        try: policies[path] = Path(path).read_text().strip()
        except OSError as e: policies[path] = str(e)
    report = dict(kind='self', comparison_ratio=None,
                  method='whole shell batch: create, exact output/IPC_STAT or POSIX metadata validation, remove, verify absent on every pass; includes shell/file/oracle overhead',
                  cpu_affinity=affinity, kernel=platform.release(), machine=platform.machine(),
                  python=platform.python_version(), uid=os.getuid(), policies=policies,
                  rlimit_msgqueue=resource.getrlimit(resource.RLIMIT_MSGQUEUE),
                  rlimit_nofile=resource.getrlimit(resource.RLIMIT_NOFILE),
                  backing_mounts=[line for line in Path('/proc/mounts').read_text().splitlines() if ' /dev/shm ' in line or ' /dev/mqueue ' in line],
                  binary_sha256=sha(binary), oracle_sha256=sha(a.oracle),
                  source_sha256={p: sha(ROOT / p) for p in sources},
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  working_tree_diff_sha256=hashlib.sha256(subprocess.check_output(['git', 'diff', '--', 'loadables/ipcmk.c'], cwd=ROOT)).hexdigest(),
                  binary_version=subprocess.check_output([binary, '--version'], text=True).splitlines()[0],
                  compiler_version=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                  reference='none; self timings with independent kernel oracle, no external ratio', cases=[])
    failed = False
    with tempfile.TemporaryDirectory(prefix='sol-ipcmk-bench-', dir=Path(a.output).resolve().parent) as directory:
        out = Path(directory) / 'output'
        for kind in checks.KINDS:
            script = checks.setup(a.oracle) + f'for ((i=0;i<{a.passes};i++)); do\n' + checks.cycle(kind, out) + 'done\nfds=(/proc/$$/fd/*); [[ ${#fds[@]} == "$before" ]] || exit 16\n' + f'echo PASS:{a.passes}\n'
            case = dict(resource=kind, status='pending', passes=a.passes, warmups=1, samples_ns=[],
                        work_unit=f'{a.passes} private creations plus metadata/output checks and removal/absence checks',
                        fixture_sha256=hashlib.sha256(script.encode()).hexdigest(), options=checks.KINDS[kind][0] + ' -p600; umask 0', reset='each created object removed and verified absent before next iteration', runs=[])
            for sample in range(a.samples + 1):
                begin = time.perf_counter_ns()
                p = subprocess.run([binary, '--noprofile', '--norc', '-c', script], text=True, capture_output=True, env={**os.environ, 'LC_ALL': 'C'})
                elapsed = time.perf_counter_ns() - begin
                valid = p.returncode == 0 and p.stdout == f'PASS:{a.passes}\n' and p.stderr == ''
                case['runs'].append(dict(warmup=sample == 0, exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr, validated=valid))
                if not valid:
                    case['status'] = 'failed_or_kernel_restricted'
                    case['restriction'] = p.stderr
                    failed = True
                    break
                if sample: case['samples_ns'].append(elapsed)
            if case['status'] == 'pending':
                values = case['samples_ns']
                case.update(status='validated', min_ns=min(values), median_ns=statistics.median(values), max_ns=max(values), median_ns_per_cycle=statistics.median(values) / a.passes)
            else:
                case['samples_ns'] = []
            report['cases'].append(case)
            print(kind, case['status'], case.get('median_ns_per_cycle'))
    Path(a.output).write_text(json.dumps(report, indent=2) + '\n')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
