#!/usr/bin/env python3
"""Fixed proc snapshots and private-PTY refresh timings; invoke through bench gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('top_checks',ROOT/'tests/sol-top-check.py')
c=importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def distribution(samples):
    return dict(samples_ms=samples,min_ms=min(samples),median_ms=statistics.median(samples),
                max_ms=max(samples),mean_ms=statistics.mean(samples),stdev_ms=statistics.stdev(samples))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',required=True); ap.add_argument('--shim',required=True)
    ap.add_argument('--output',required=True); ap.add_argument('--runs',type=int,default=7)
    args=ap.parse_args(); assert args.runs>=7
    binary=Path(args.binary).resolve(); shim=Path(args.shim).resolve()
    allowed=sorted(os.sched_getaffinity(0)); cpu=allowed[-1]; os.sched_setaffinity(0,{cpu})
    report=dict(kind='syscall-shim',reference=None,ratio=None,cpu=cpu,affinity=sorted(os.sched_getaffinity(0)),
                system=platform.platform(),python=platform.python_version(),libc=platform.libc_ver(),
                cpu_model=next(line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
                bash=subprocess.check_output([str(binary),'--version'],text=True).splitlines()[0],
                compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                binary_sha256=sha(binary),shim_sha256=sha(shim),
                source_base=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                sources={str(p.relative_to(ROOT)):sha(p) for p in [ROOT/'loadables/top.c',
                    ROOT/'loadables/_bl_screen/screen.c',ROOT/'loadables/_bl_key/bl_key.c',
                    ROOT/'tests/sol-top-proc-shim.c',ROOT/'tests/sol-top-check.py',Path(__file__).resolve()]},
                warmups=1,runs=args.runs,cases=[],
                limits=['Injected proc files, real filesystem reads and private PTY; no live-counter or external-top ratio.',
                        'Batch includes shell startup and the production 200ms sampling delay.',
                        'Refresh includes input dispatch, proc sampling, formatting, terminal writes and parent cell decoding.',
                        'One pinned CPU; other host activity is not controlled.'])
    with tempfile.TemporaryDirectory(prefix='sol-top-bench-') as d:
        for count in [64,1024,4096]:
            root=Path(d)/str(count); c.fixture(root,count)
            r=c.Runner(binary,shim,root)
            want=c.expected('cpu',0,count); samples=[]; passes=[]
            for iteration in range(args.runs+1):
                start=time.perf_counter_ns()
                out=r.run('top --once -o cpu')
                elapsed=(time.perf_counter_ns()-start)/1e6
                assert out==want,(count,iteration,'independent output mismatch')
                passes.append(dict(iteration=iteration,warmup=iteration==0,exit_code=0,
                                   output_sha256=hashlib.sha256(out).hexdigest(),bytes=len(out)))
                if iteration: samples.append(elapsed)
            report['cases'].append(dict(name=f'batch-{count}',status='pass',work_unit=f'2 samples of {count} processes; {count} printed rows',
                                        fixture_sha256=c.digest(root),options='--once -o cpu',reset='fresh shell; pair frames 0,1',
                                        validation='Every byte equals independently formatted Python records on every pass.',
                                        passes=passes,**distribution(samples)))
        count=1024; root=Path(d)/str(count); r=c.Runner(binary,shim,root)
        c.switch(root,0)
        with c.Terminal(r,'top -d 3599 -o pid',rows=24,cols=100) as t:
            t.until(lambda:len(t.screen.pids())==20)
            assert t.screen.pids()==list(range(1000,1020))
            initial_bytes=len(t.raw); samples=[]; sizes=[]; passes=[]
            for iteration in range(args.runs+1):
                frame=(iteration+1)%2; c.switch(root,frame)
                cpu_percent=lambda i:(i%5)*100/max(200,count*5) if frame else 0.
                want_rows=[c.row(1000+i,cpu_percent(i),i%100+1,f'proc{i:05} --fixture') for i in range(20)]
                start_bytes=len(t.raw); start=time.perf_counter_ns(); t.send(b' ')
                deadline=time.monotonic()+10
                while True:
                    t.read(.1)
                    text=t.screen.text()
                    if f'load {frame+1}.00' in text and all(row in text for row in want_rows): break
                    assert time.monotonic()<deadline,('refresh timeout',text)
                elapsed=(time.perf_counter_ns()-start)/1e6
                assert t.screen.pids()==list(range(1000,1020))
                assert 'Mem: 100000 kB total, 60000 kB used, 40000 kB avail' in text
                assert 'Swap: 20000 kB total, 5000 kB used, 15000 kB free' in text
                size=len(t.raw)-start_bytes
                passes.append(dict(iteration=iteration,warmup=iteration==0,frame=frame,terminal_bytes=size,
                                   cells_sha256=hashlib.sha256(text.encode()).hexdigest(),validation='pass'))
                if iteration: samples.append(elapsed); sizes.append(size)
            t.finish(); assert t.proc.returncode==0
            report['cases'].append(dict(name='refresh-1024',status='pass',exit_code=0,
                work_unit='one refresh: 1024 processes sampled, 20 rows rendered at 24x100',
                fixture_sha256=c.digest(root),options='-d 3599 -o pid',reset='alternate immutable frames via atomic symlink, then send space',
                validation='All 20 rendered records, CPU deltas, header memory/load, PID order and final terminal restoration checked.',
                initial_terminal_bytes=initial_bytes,terminal_bytes=sizes,passes=passes,**distribution(samples)))
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
    for case in report['cases']:
        print(f"{case['name']}: {case['status']}, median {case['median_ms']:.3f} ms, samples {case['samples_ms']}")
    print(f'CPU {cpu}; report {args.output}')

if __name__=='__main__': main()
