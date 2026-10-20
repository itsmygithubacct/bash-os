#!/usr/bin/env python3
"""Validated doas boundary timings. Run under the campaign bench gate; builds are separate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--before', type=Path)
p.add_argument('--before-source', type=Path)
p.add_argument('--profile', action='store_true')
p.add_argument('--output', type=Path, required=True)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--passes', type=int, default=16)
a = p.parse_args()
assert a.runs >= 7 and a.passes > 0
sha = lambda f: hashlib.sha256(Path(f).read_bytes()).hexdigest()
root = Path(__file__).resolve().parents[1]
source_files = ['loadables/doas.c', 'loadables/_bashauth/sudoedit.c', 'loadables/common/bashcred_privdrop.h', 'tests/sol-doas-fixture.c', 'loadables/_mbedtls/sha256.c']
report = dict(kind='syscall-shim', external_ratio=None, cpu_affinity=sorted(os.sched_getaffinity(0)),
              platform=platform.platform(), python=platform.python_version(),
              cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), platform.machine()),
              rlimit_nofile=list(resource.getrlimit(resource.RLIMIT_NOFILE)),
              compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              source_tree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'])),
              benchmark_driver_sha256=sha(Path(__file__)),
              sources={f: sha(root/f) for f in source_files},
              fixture='fixed in-memory account/group rows; fixed argv and caller environment; per-process private scratch directory',
              reset='fresh fixture process per sample; each pass resets decision/counters/auth latch; owned children reaped; scratch removed',
              warmups=1, passes=a.passes, runs=a.runs, cases=[], profiles=[],
              before_source_sha256=sha(a.before_source) if a.before_source else None,
              limitations=['Authority policy and verifier ioctls are injected, not live kernel authorization or password hashing.',
                           'Supplementary groups are intercepted; the child workload uses real setresuid/gid to its current owned identity, fork, signal/FD cleanup, exec and wait.',
                           'No sudo/doas external ratio; baseline comparison is the same production-source fixture on this host.',
                           'Batch wall time includes fixture process startup and assertion overhead; per-work values divide the full batch.'])
for label, binary in [('current', a.binary), ('baseline', a.before)]:
    if binary:
        metadata = json.loads((binary.parent/'build.json').read_text())
        assert metadata['binary_sha256'] == sha(binary)
        assert all(sha(path) == digest for path, digest in metadata['sources'].items()), 'source changed since fixture build'
        report[label+'_build'] = metadata
if a.profile:
    report['strace_version'] = subprocess.check_output(['strace', '--version'], text=True).splitlines()[0]
    for label, binary in [('baseline', a.before), ('current', a.binary)]:
        if not binary:
            continue
        path = a.output.with_name(a.output.stem+'-profile-'+label+'.txt')
        proc = subprocess.run(['strace', '-qq', '-f', '-c', '-e', 'trace=close,close_range,execve,clone,wait4,prctl',
                               '-o', str(path), str(binary.resolve()), '--work', '1'],
                              env={**os.environ, 'SOL_DOAS_WORK': 'child', 'LC_ALL': 'C'}, capture_output=True, timeout=120)
        assert proc.returncode == 0 and proc.stdout == b'validated child 1\n' and not proc.stderr, (proc.returncode, proc.stdout, proc.stderr)
        report['profiles'].append(dict(variant=label, command='strace -qq -f -c -e trace=close,close_range,execve,clone,wait4,prctl -o REPORT FIXTURE --work 1',
                                       report=str(path), validation='exact child count and status validated'))
for phase, unit in [('policy', 'parse one doas argv, build/digest one request, authorize and hand off through asserted ioctls'),
                    ('auth', 'fork one verifier child, assert EXEC_VERIFY request, wait for validated status'),
                    ('child', 'parse one argv, fork, request current groups/IDs (group syscall intercepted, real setresuid/gid to owned identity), scrub environment, close FDs, exec /bin/true, wait')]:
    variants = [('current', a.binary.resolve())]
    if a.before:
        variants.insert(0, ('baseline', a.before.resolve()))
    samples = {label: [] for label, _ in variants}
    def run(binary):
        env = {**os.environ, 'SOL_DOAS_WORK': phase, 'LC_ALL': 'C'}
        started = time.perf_counter_ns()
        proc = subprocess.run([str(binary), '--work', str(a.passes)], env=env, capture_output=True, timeout=120)
        elapsed = time.perf_counter_ns()-started
        assert proc.returncode == 0 and proc.stdout == f'validated {phase} {a.passes}\n'.encode() and not proc.stderr, (phase, binary, proc.returncode, proc.stdout, proc.stderr)
        return elapsed
    for _, binary in variants:
        run(binary)
    for n in range(a.runs):
        for label, binary in (variants if n%2==0 else variants[::-1]):
            samples[label].append(run(binary))
    case = dict(phase=phase, status='validated', work_unit=unit, passes=a.passes,
                binaries={label: dict(path=str(binary), sha256=sha(binary)) for label, binary in variants},
                samples_ns=samples,
                distributions={label: dict(min_ns=min(v), median_ns=statistics.median(v), max_ns=max(v),
                                           median_ns_per_work=statistics.median(v)/a.passes) for label, v in samples.items()})
    report['cases'].append(case)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print(phase, json.dumps(case['distributions']), flush=True)
