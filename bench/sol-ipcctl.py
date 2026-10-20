#!/usr/bin/env python3
"""Validated ipcctl syscall-shim timing; run through the campaign bench gate.

Does not compile. Includes process startup, module loading, Bash loop/status
checks, fixture reset/verification and three production IPC_RMID calls per cycle.
No external ratio and no claim about kernel IPC allocation/removal latency.
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
SPEC = importlib.util.spec_from_file_location('ipcctl_check', ROOT / 'tests/sol-ipcctl-check.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command_output(argv):
    r = subprocess.run(argv, capture_output=True, text=True, check=True)
    return r.stdout.strip()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--cycles', type=int, default=10000)
    p.add_argument('--samples', type=int, default=7)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.samples < 7 or args.cycles < 1:
        p.error('at least seven samples and one cycle required')
    affinity = sorted(os.sched_getaffinity(0))
    if len(affinity) != 1:
        p.error('pin to one CPU (the campaign bench gate does this)')
    binary, module = args.binary.resolve(), args.module.resolve()
    body = (f'export BASHOS_IPCRM_ALLOW_RMID=1\nn={args.cycles}\n'
            'for ((i=0;i<n;i++)); do\n'
            'ipcctl_fixture reset 17 231 4096 0 1 || exit 92\n'
            'ipcctl --rm shm 17 || exit 93\n'
            'ipcctl --rm msg 231 || exit 94\n'
            'ipcctl --rm sem 4096 || exit 95\n'
            'ipcctl_fixture verify || exit 96\ndone\n'
            'printf "validated cycles=%d removals=%d\\n" "$n" "$((3*n))"\n')
    expected = f'validated cycles={args.cycles} removals={3 * args.cycles}\n'
    source_paths = ['loadables/ipcctl.c', 'tests/sol-ipcctl-shim.c',
                    'tests/sol-ipcctl-check.py', 'tests/sol-ipcctl-build.sh',
                    'bench/sol-ipcctl.py', 'build.sh', 'config/versions.sh']
    report = dict(status='pending', kind='syscall-shim',
                  boundary='parent perf_counter_ns around shell process: startup, dlopen, Bash loop, '
                           'fixture reset, three production IPC_RMID requests with status checks, '
                           'fixture verification each cycle, output capture and process wait',
                  work_unit=dict(cycles=args.cycles, removals_per_cycle=3,
                                 intercepted_removals=3*args.cycles, kernel_sysv_calls=0),
                  reset='reset three active fixture objects to IDs shm=17,msg=231,sem=4096 before every cycle',
                  validation='every command status checked; fixture verifies exact IDs, IPC_RMID, '
                             'null shm/msg buffers, semnum zero, exactly three calls and all objects inactive each cycle; '
                             'exact stdout, empty stderr and process status checked each sample',
                  oracle_stdout=expected, fixture_body=body,
                  fixture_sha256=hashlib.sha256(body.encode()).hexdigest(),
                  binary=str(binary), binary_sha256=digest(binary),
                  module=str(module), module_sha256=digest(module),
                  sources={path: digest(ROOT/path) for path in source_paths},
                  build_manifest=binary.with_name(binary.name + '.manifest.txt').read_text(),
                  module_options='-std=gnu11 -g -O2 -fPIC -shared -Wl,-Bsymbolic -Wall -Wextra',
                  native_link_options='-Wl,--build-id=none -Wl,-z,relro -Wl,-z,now -no-pie',
                  git_head=command_output(['git', 'rev-parse', 'HEAD']),
                  git_dirty=bool(command_output(['git', 'status', '--porcelain'])),
                  environment=dict(cpu_affinity=affinity, platform=platform.platform(),
                                   kernel=platform.release(), machine=platform.machine(),
                                   python=sys.version, libc=platform.libc_ver(),
                                   compiler=command_output(['cc', '--version']),
                                   bash=command_output([str(binary), '--version']),
                                   cpu_model=next((line.split(':', 1)[1].strip() for line in
                                                  Path('/proc/cpuinfo').read_text().splitlines()
                                                  if line.startswith('model name')), 'unknown'),
                                   locale='C', path='empty inside child shell'),
                  limitations=['Closed syscall fixture, no kernel IPC lifecycle latency.',
                               'No matched external reference or speedup claim.',
                               'ASan/UBSan module is tested separately and never timed.'],
                  warmup=None, samples=[])
    for index in range(args.samples + 1):
        start = time.perf_counter_ns()
        r = CHECK.invoke(binary, body, module)
        elapsed = time.perf_counter_ns() - start
        good = r.returncode == 0 and r.stdout == expected and not r.stderr
        sample = dict(index=index, status='pass' if good else 'fail', elapsed_ns=elapsed,
                      exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr)
        if index == 0:
            report['warmup'] = sample
        else:
            report['samples'].append(sample)
        print('warmup' if index == 0 else f'sample {index}', sample['status'],
              f'{elapsed/1e6:.3f} ms', flush=True)
        if not good:
            report['status'] = 'fail'
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            return 1
    values = [s['elapsed_ns'] for s in report['samples']]
    report.update(status='pass', summary=dict(min_ns=min(values), median_ns=statistics.median(values),
                  max_ns=max(values), mean_ns=statistics.mean(values), stdev_ns=statistics.stdev(values),
                  median_ns_per_cycle=statistics.median(values)/args.cycles,
                  median_ns_per_intercepted_removal=statistics.median(values)/(args.cycles*3)))
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
