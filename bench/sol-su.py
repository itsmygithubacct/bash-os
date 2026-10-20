#!/usr/bin/env python3
"""Separate validated su password and owned child boundaries; run through bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--passes', type=int, default=32)
a = p.parse_args()
assert a.runs >= 7 and a.passes > 0
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
binary = a.binary.resolve()
build = json.loads((binary.parent/'build.json').read_text())
assert sha(binary) == build['binary_sha256']
assert all(sha(p) == digest for p, digest in build['sources'].items()), 'source changed after build'
assert len(os.sched_getaffinity(0)) == 1, 'pin benchmark with taskset or campaign bench gate'
report = dict(kind='syscall-shim', external_ratio=None, build=build,
              source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
              source_tree_dirty=bool(subprocess.check_output(['git','status','--porcelain'])),
              driver_sha256=sha(__file__), platform=platform.platform(),
              affinity=sorted(os.sched_getaffinity(0)), python=platform.python_version(),
              libc=platform.libc_ver(),
              environment={'LC_ALL':'C','fixture_PATH':'','fixture_TERM':'fixture-term',
                           'LANG':os.environ.get('LANG'),'TZ':os.environ.get('TZ')},
              auth_options={'algorithm':'argon2id','version':19,'memory_kib':1024,
                            'passes':1,'lanes':1,'hash_bytes':32},
              compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
              shell_sha256=sha('/bin/sh'),
              cpu_model=next(l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),
              fixture_sha256=sha('tests/sol-su-fixture.c'), passes=a.passes, runs=a.runs, warmups=1,
              reset='fresh fixture process and private scratch directory per sample; event counters, password cursor and options reset every pass; owned children reaped',
              limitations=['No live kernel authority, external ratio or speedup claim.',
                           'Wall time includes fixture startup, assertions and private file setup.',
                           'Auth uses real Argon2id m=1024 KiB,t=1,p=1, fixed independent-oracle PHC, with injected tty bytes.',
                           'Child uses root route and asserted token/credential boundaries; real setresuid/gid keep the owned identity; supplementary-group syscall is injected.'], cases=[])
for phase, unit in [('auth','one secure password read, real PHC verification, password wipe, lock-success cleanup'),
                    ('child','one su parse/account lookup, fork, asserted mint/consume, credential transition, environment/FD/signal cleanup, real /bin/sh -c exit 37, wait')]:
    def run():
        start = time.perf_counter_ns()
        q = subprocess.run([str(binary),'--work',phase,str(a.passes)],capture_output=True,timeout=120,
                           env={**os.environ,'LC_ALL':'C'})
        elapsed = time.perf_counter_ns()-start
        assert q.returncode == 0 and q.stdout == f'validated {phase} {a.passes}\n'.encode() and not q.stderr, (phase,q.returncode,q.stdout,q.stderr)
        return elapsed
    run()
    samples = [run() for _ in range(a.runs)]
    report['cases'].append(dict(workload=phase,status='validated',work_unit=unit,samples_ns=samples,
                                min_ns=min(samples),median_ns=statistics.median(samples),max_ns=max(samples),
                                median_ns_per_work=statistics.median(samples)/a.passes))
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    print(phase, report['cases'][-1], flush=True)
