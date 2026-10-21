#!/usr/bin/env python3
"""Validated sudo boundary timings. Run under the campaign bench gate; builds are separate.

Each sample runs one fresh fixture process that performs PASSES work units and
validates every unit's status and recorded authority requests; a sample whose
output is not exactly 'validated PHASE PASSES' aborts the run. Timings are
syscall-shim timings of production code: no live kernel policy, password
hashing or external sudo is involved, so no external ratio is reported."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import tempfile
import time

PHASES = {
    'policy': 'parse one sudo argv with an assignment, build/digest one EXEC request, authorize, hand off, check the recorded request',
    'reset': 'sudo -k with a command: one RESET_TIMESTAMP request, then a fresh EXEC request and handoff',
    'verify': 'interactive route: fork, AUTHZ (auth required), verifier child and wait, second fork, AUTHZ, kernel exec stand-in, wait',
    'edit': 'sudoedit of two private files: AUTHZ, safe-open and temp copies, one real /bin/sh editor exec as the caller, re-AUTHZ, read-only fd vector, protected atomic copyback of both, content check',
    'child': 'root route: parse, fork, scrubbed environment, group vector, intercepted credential calls, no_new_privs, signal/FD cleanup, real exec of /bin/true, wait',
}

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--before', type=Path, help='historical-source fixture for phases it validates')
p.add_argument('--before-phases', default='verify,edit')
p.add_argument('--phases', default=','.join(PHASES))
p.add_argument('--output', type=Path, required=True)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--passes', type=int, default=16)
p.add_argument('--cpu', type=int)
a = p.parse_args()
assert a.runs >= 7 and a.passes > 0
sha = lambda f: hashlib.sha256(Path(f).read_bytes()).hexdigest()
root = Path(__file__).resolve().parents[1]
cpu = a.cpu if a.cpu is not None else max(os.sched_getaffinity(0))
sources = ['loadables/doas.c', 'loadables/sudo.c', 'loadables/_bashauth/sudoedit.c', 'loadables/common/bashcred_privdrop.h',
           'loadables/common/child-wait.h', 'tests/sol-sudo-fixture.c', 'loadables/_mbedtls/sha256.c']
report = dict(kind='syscall-shim', external_ratio=None, cpu_affinity=[cpu],
              platform=platform.platform(), python=platform.python_version(),
              cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                              if line.startswith('model name')), platform.machine()),
              loadavg_start=os.getloadavg(), rlimit_nofile=list(resource.getrlimit(resource.RLIMIT_NOFILE)),
              compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, cwd=root).strip(),
              source_tree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
              benchmark_driver_sha256=sha(Path(__file__)), sources={f: sha(root / f) for f in sources},
              fixture='private passwd/group rows, fixed argv, fixed caller exports, private originals rewritten per unit',
              reset='fresh fixture process per sample; per unit: shared request log, scripted replies and capture cleared; '
                    'sudoedit originals rewritten; temp copies removed and checked; scratch directory removed at exit',
              warmups=1, passes=a.passes, runs=a.runs, cases=[],
              limitations=['Authority ioctls are injected; no live kernel policy, timestamp, verifier binary or password hashing.',
                           'Root-route credential syscalls are intercepted; fork, no_new_privs, signal/FD cleanup, exec and wait are real.',
                           'sudoedit copyback runs the shared helper on private files as the caller, standing in for kernel mediation; '
                           'its fsync and rename are included.',
                           'No external sudo ratio: host sudo would need real policy and authentication.',
                           'Sample time includes fixture process startup and validation; per-unit values divide the whole sample.'])
variants = [('current', a.binary.resolve())]
if a.before:
    variants.append(('baseline', a.before.resolve()))
for label, binary in variants:
    metadata = json.loads((binary.parent / 'build.json').read_text())
    assert metadata['binary_sha256'] == sha(binary), 'binary changed since build'
    if label == 'current':
        assert all(sha(path) == digest for path, digest in metadata['sources'].items()), 'source changed since fixture build'
    report[label + '_build'] = metadata
before_phases = set(a.before_phases.split(',')) if a.before else set()


def sample(binary, phase, scratch):
    env = {**os.environ, 'SOL_SUDO_TMPDIR': scratch, 'LC_ALL': 'C'}
    started = time.perf_counter_ns()
    proc = subprocess.run([str(binary), phase, str(a.passes)], cwd=scratch, env=env, capture_output=True, timeout=300,
                          preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
    elapsed = time.perf_counter_ns() - started
    lines = proc.stdout.decode(errors='replace').splitlines()
    ok = proc.returncode == 0 and lines[-1:] == [f'validated {phase} {a.passes}'] and not os.listdir(scratch)
    return ok, elapsed, proc


for phase in a.phases.split(','):
    phase_variants = [(l, b) for l, b in variants if l == 'current' or phase in before_phases]
    samples = {label: [] for label, _ in phase_variants}
    with tempfile.TemporaryDirectory(prefix='sol-sudo-bench-') as scratch:
        scratch = os.path.realpath(scratch)
        for label, binary in phase_variants:
            ok, _, proc = sample(binary, phase, scratch)
            assert ok, (phase, label, 'warm-up failed validation', proc.returncode, proc.stdout[-500:], proc.stderr[-2000:])
        for n in range(a.runs):
            for label, binary in (phase_variants if n % 2 == 0 else phase_variants[::-1]):
                ok, elapsed, proc = sample(binary, phase, scratch)
                assert ok, (phase, label, n, proc.returncode, proc.stdout[-500:], proc.stderr[-2000:])
                samples[label].append(elapsed)
    case = dict(phase=phase, status='validated', work_unit=PHASES[phase], passes=a.passes,
                validated_units=a.passes * (a.runs + 1) * len(phase_variants),
                binaries={label: dict(path=str(binary), sha256=sha(binary)) for label, binary in phase_variants},
                samples_ns=samples,
                distributions={label: dict(min_ns=min(v), median_ns=statistics.median(v), max_ns=max(v),
                                           median_ms_per_unit=statistics.median(v) / a.passes / 1e6)
                               for label, v in samples.items()})
    if 'baseline' in samples:
        case['median_ratio_current_over_baseline'] = statistics.median(samples['current']) / statistics.median(samples['baseline'])
    report['cases'].append(case)
    report['loadavg_end'] = os.getloadavg()
    a.output.write_text(json.dumps(report, indent=2) + '\n')
    print(phase, json.dumps(case['distributions']), flush=True)
