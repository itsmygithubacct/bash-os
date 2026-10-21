#!/usr/bin/env python3
"""Validated API latency and terminal traffic; invoke through the bench gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tui_checks', ROOT/'tests/sol-tui-check.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
ROWS, COLS = 24, 80
POINTS = [(2,3),(2,70),(20,70)]


def cup(y,x):
    return f'\x1b[{y+1};{x+1}H'.encode()


def fixture(case, passes):
    seed = 'A'*(ROWS*COLS)
    script = f"seed={seed}; other={'B'*(ROWS*COLS)}; "
    script += 'for ((i=0;i<'+str(passes)+';i++)); do '
    if case == 'noop':
        script += 'tui move 0 0 && tui addstr "$seed" && '
    else:
        script += 'if ((i%2==0)); then ch=B; frame=$other; else ch=A; frame=$seed; fi; '
        if case == 'full': script += 'tui move 0 0 && tui addstr "$frame" && '
        else:
            for y,x in POINTS: script += f'tui move {y} {x} && tui addstr "$ch" && '
    script += 'tui move 0 0 && tui refresh || exit 90; done'
    return seed, script


def expected(case, passes):
    output = b''
    for i in range(passes):
        ch = b'B' if i%2==0 else b'A'
        if case == 'sparse':
            output += b''.join(cup(y,x)+ch for y,x in POINTS)+cup(0,0)
        elif case == 'full':
            output += ch*COLS+b''.join(cup(y,0)+ch*COLS for y in range(1,ROWS))+cup(0,0)
    return output


def run(binary, case, passes):
    t = checks.Terminal(binary, ROWS, COLS)
    seed, script = fixture(case, passes)
    try:
        t.command('tui init; tui move 0 0; tui addstr '+seed+'; tui move 0 0; tui refresh')
        assert t.decoder.lines() == ['A'*COLS]*ROWS
        printed = t.decoder.printed
        start = time.perf_counter_ns()
        output, traffic = t.command(script)
        elapsed = t.completion_ns-start
        assert output == b''
        want = expected(case,passes)
        assert traffic == want, (case,len(traffic),len(want),traffic[:100],want[:100])
        count = {'noop':0,'sparse':len(POINTS),'full':ROWS*COLS}[case]*passes
        assert t.decoder.printed-printed == count
        # Independently check every frame, not just a deterministic final hash.
        decoder = checks.Decoder(ROWS,COLS)
        decoder.cells = [[('A',0,None,None) for _ in range(COLS)] for _ in range(ROWS)]
        frame_bytes = len(want)//passes
        for i in range(passes):
            decoder.feed(traffic[i*frame_bytes:(i+1)*frame_bytes])
            grid = [['A']*COLS for _ in range(ROWS)]
            ch = 'B' if i%2==0 else 'A'
            if case == 'full': grid = [[ch]*COLS for _ in range(ROWS)]
            elif case == 'sparse':
                for y,x in POINTS: grid[y][x] = ch
            assert decoder.lines() == [''.join(row) for row in grid]
            assert all(c[1:] == (0,None,None) for row in decoder.cells for c in row)
        t.command('tui end')
        return {'elapsed_ns':elapsed, 'ns_per_refresh':elapsed/passes,
                'changed_cells':count, 'emitted_bytes':len(traffic), 'status':'pass'}
    finally:
        t.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--runs',type=int,default=7)
    ap.add_argument('--passes',type=int,default=200)
    args = ap.parse_args()
    assert args.runs >= 7 and args.passes > 0
    cpu = args.cpu if args.cpu is not None else min(os.sched_getaffinity(0))
    os.sched_setaffinity(0,{cpu})
    binary = Path(args.binary).resolve()
    sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    sources = ['loadables/tui.c','loadables/_bl_screen/screen.c','loadables/_bl_screen/screen.h',
               'loadables/_bl_key/bl_key.c','loadables/_bl_key/bl_key.h', 'bench/sol-tui.py','tests/sol-tui-check.py']
    source_receipt = binary.with_name(binary.name+'.sources.json')
    report = {'kind':'api','reference':None,'ratio':None, 'cpu_affinity':sorted(os.sched_getaffinity(0)),
              'environment':{'platform':platform.platform(),'python':platform.python_version(),
                             'TERM':'xterm-256color','COLORTERM':'truecolor','LC_ALL':'C.UTF-8','PATH':''},
              'binary':str(binary),'binary_sha256':sha(binary),
              'binary_version':subprocess.check_output([binary,'--version'],text=True).splitlines()[0],
              'compiler_version':subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
              'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'source_sha256':{p:sha(ROOT/p) for p in sources},
              'method':'One fresh private PTY per sample; initialize 24x80 A cells, park at (0,0), then 200 draw/refresh calls. Parent monotonic interval starts at command submission and ends after acknowledgement and PTY drain, before decoding; includes Bash loop, IPC and PTY consumer scheduling. One validated warm-up per case; no external ratio.',
              'passes':args.passes,'runs':args.runs,'dimensions':{'rows':ROWS,'cols':COLS},
              'cpu_model':next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),None),
              'working_tree_changes':subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).splitlines(),
              'results':[]}
    if source_receipt.exists():
        report['build_sources'] = json.loads(source_receipt.read_text())
    else:
        report['build_sources'] = {'source_sha256': {p:sha(ROOT/p) for p in sources if p.startswith('loadables/')}}
    for case in ('noop','sparse','full'):
        entry = {'case':case,'status':'running','fixture_sha256':hashlib.sha256(fixture(case,args.passes)[1].encode()).hexdigest(),
                 'work_unit':f'{args.passes} draw/refresh calls at {ROWS}x{COLS}', 'samples':[]}
        report['results'].append(entry)
        try:
            entry['warmup'] = run(binary,case,args.passes)
            for _ in range(args.runs): entry['samples'].append(run(binary,case,args.passes))
            values = [s['ns_per_refresh'] for s in entry['samples']]
            entry.update(status='pass', median_ns_per_refresh=statistics.median(values), min_ns_per_refresh=min(values),max_ns_per_refresh=max(values))
        except Exception as e:
            entry.update(status='fail',error=repr(e))
            raise
        finally:
            Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
        print(case, entry['median_ns_per_refresh'], 'ns/refresh',entry['samples'][0]['emitted_bytes'],'bytes/batch')


if __name__ == '__main__': main()
