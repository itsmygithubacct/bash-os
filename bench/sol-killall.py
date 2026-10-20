#!/usr/bin/env python3
"""Fixed-work killall selection, interception, and owned signal syscall timings.

Run through the campaign bench gate; compile the shell and shim separately.
There is no equivalent external fixture interface, so no external ratios apply.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('killall_fixtures', ROOT / 'tests/sol-killall-check.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_sha(root):
    h = hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.is_file():
            h.update(str(p.relative_to(root)).encode() + b'\0' + p.read_bytes() + b'\0')
    return h.hexdigest()


def summary(values):
    return dict(samples=values, min=min(values), median=statistics.median(values), max=max(values),
                mean=statistics.mean(values), stdev=statistics.stdev(values))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True)
    ap.add_argument('--shim', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--samples', type=int, default=7)
    ap.add_argument('--passes', type=int, default=100)
    args = ap.parse_args()
    assert args.samples >= 7 and args.passes > 0
    binary, shim = Path(args.binary).resolve(), Path(args.shim).resolve()
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'run under bench gate with fixed CPU affinity'
    report = dict(method='one warm-up then >=7 samples; each batch runs in one shell with empty PATH; '
                         'every invocation status and every delivery validated; no external ratio',
                  units='milliseconds per batch', passes=args.passes, samples=args.samples,
                  cpu_affinity=affinity, platform=platform.platform(), python=sys.version,
                  cpu=Path('/proc/cpuinfo').read_text().split('model name',1)[-1].splitlines()[0],
                  binary_sha256=sha(binary), shim_sha256=sha(shim),
                  source_sha256={str(p.relative_to(ROOT)):sha(p) for p in [ROOT/'loadables/killall.c', ROOT/'loadables/pgrep.c',
                                  ROOT/'tests/sol-killall-shim.c', ROOT/'tests/sol-killall-check.py', Path(__file__).resolve()]},
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  source_tree_dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip()),
                  binary_version=subprocess.check_output([str(binary),'--version'],text=True).splitlines()[0],
                  compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0], cases=[])
    with tempfile.TemporaryDirectory(prefix='sol-killall-bench-') as tmp:
        directory = Path(tmp)
        for count in (64, 256):
            root = directory / f'proc-{count}'
            root.mkdir()
            for i in range(count):
                fixtures.entry(root, 10000 + i, 'selected' if i % 8 == 0 else 'other')
            runner = fixtures.Runner(binary, shim, root, directory/'calls')
            for kind, name, status, calls in [
                ('selection-only', 'absent', 1, []),
                ('selection-intercepted-delivery', 'selected', 0, [(10000+i,15,0) for i in range(count) if i%8 == 0])]:
                row = dict(name=f'{kind}-{count}', kind='syscall-shim', fixture_processes=count,
                           matches_per_pass=len(calls), fixture_sha256=tree_sha(root),
                           options=[name], reset='truncate interception log before each batch; fixture remains identical',
                           work_unit=f'{args.passes} scans x {count} comm files; {args.passes*len(calls)} intercepted kills',
                           validation='pending')
                times = []
                for sample in range(-1, args.samples):
                    Path(runner.log).write_text('')
                    script = f'for ((i=0;i<{args.passes};i++)); do killall {shlex.quote(name)}; printf "%d\\n" "$?"; done'
                    started = time.perf_counter_ns()
                    p = subprocess.run([str(binary),'--noprofile','--norc','-c',script], env=runner.env(),
                                       capture_output=True,text=True,timeout=60)
                    elapsed = (time.perf_counter_ns() - started)/1e6
                    actual = [tuple(map(int,line.split())) for line in Path(runner.log).read_text().splitlines()]
                    assert p.returncode == 0 and p.stdout == f'{status}\n' * args.passes and not p.stderr, (row,p)
                    assert sorted(actual) == sorted(calls * args.passes), (row, len(actual))
                    assert tree_sha(root) == row['fixture_sha256']
                    if sample >= 0: times.append(elapsed)
                row.update(validation='pass',wall_ms=summary(times))
                report['cases'].append(row)
                print(json.dumps(row),flush=True)
        # Exact child comm plus redirected single-entry proc tree. Ownership is
        # checked by the driver and again in the shim immediately before syscall.
        name = 'skb' + uuid.uuid4().hex[:9]
        child = subprocess.Popen([sys.executable,'-u','-c',fixtures.CHILD,name],stdout=subprocess.PIPE,text=True)
        try:
            assert child.stdout.readline().strip() == 'ready'
            root = directory / 'owned-proc'
            root.mkdir()
            fixtures.entry(root, child.pid, name)
            runner = fixtures.Runner(binary, shim, root, directory/'owned-calls')
            timing = directory / 'delivery-ns'
            env = {'SOL_KILLALL_OWNED_PID':str(child.pid), 'SOL_KILLALL_OWNED_COMM':name,
                   'SOL_KILLALL_PARENT':str(os.getpid()),'SOL_KILLALL_DELIVERY_NS':str(timing)}
            row = dict(name='controlled-delivery-one-owned-child',kind='syscall-shim',fixture_processes=1,
                       matches_per_pass=1,fixture_sha256=tree_sha(root),options=['-CONT',name],
                       reset='truncate logs; child stays running across batches',
                       work_unit=f'{args.passes} scans x 1 owned process; {args.passes} SIGCONT syscalls',
                       syscall_clock='CLOCK_MONOTONIC immediately around SYS_kill; excludes ownership checks, proc walk and log writes',
                       limitations=['includes two clock reads; child wakes and scheduling may affect syscall latency',
                                    'wall time includes fail-closed ownership verification and log writes'])
            walls, delivery = [], []
            for sample in range(-1,args.samples):
                assert child.poll() is None
                status = dict(x.split(':',1) for x in Path(f'/proc/{child.pid}/status').read_text().splitlines() if ':' in x)
                assert int(status['PPid']) == os.getpid() and int(status['Uid'].split()[0]) == os.getuid()
                assert Path(f'/proc/{child.pid}/comm').read_text().rstrip('\n') == name
                timing.write_text(''); Path(runner.log).write_text('')
                script = f'for ((i=0;i<{args.passes};i++)); do killall -CONT {name}; printf "%d\\n" "$?"; done'
                started = time.perf_counter_ns()
                p = subprocess.run([str(binary),'--noprofile','--norc','-c',script],env=runner.env(env),capture_output=True,text=True,timeout=60)
                elapsed = (time.perf_counter_ns()-started)/1e6
                assert p.returncode == 0 and p.stdout == '0\n' * args.passes and not p.stderr, p
                assert Path(runner.log).read_text().splitlines() == [f'{child.pid} {signal.SIGCONT} 0'] * args.passes
                ns = [int(x) for x in timing.read_text().splitlines()]
                assert len(ns) == args.passes and all(x > 0 for x in ns)
                assert child.poll() is None and tree_sha(root) == row['fixture_sha256']
                state = Path(f'/proc/{child.pid}/status').read_text().split('State:',1)[1].splitlines()[0].strip()
                assert state[0] in 'RS', state
                if sample >= 0:
                    walls.append(elapsed); delivery.append(sum(ns)/1e6)
            row.update(validation='pass',wall_ms=summary(walls),delivery_syscall_ms=summary(delivery))
            report['cases'].append(row)
            print(json.dumps(row),flush=True)
        finally:
            if child.poll() is None:
                status = dict(x.split(':',1) for x in Path(f'/proc/{child.pid}/status').read_text().splitlines() if ':' in x)
                assert int(status['PPid']) == os.getpid() and int(status['Uid'].split()[0]) == os.getuid()
                assert Path(f'/proc/{child.pid}/comm').read_text().rstrip('\n') == name
                child.kill(); child.wait(timeout=5)
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__':
    main()
