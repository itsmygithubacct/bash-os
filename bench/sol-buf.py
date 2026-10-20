#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated persistent buf API batches; run under the campaign bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source', type=Path, default=Path('loadables/buf.c'))
p.add_argument('--cpu', type=int, required=True)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--rusage', type=Path, required=True)
a = p.parse_args()
assert a.runs >= 7
os.sched_setaffinity(0, {a.cpu})
binary = a.binary.resolve()
sha = lambda b: hashlib.sha256(b).hexdigest()
env = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC'}
report = dict(harness_sha256=sha(Path(__file__).read_bytes()), binary_sha256=sha(binary.read_bytes()), source_sha256=sha(a.source.read_bytes()),
              base_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
              launcher_sha256=sha(a.rusage.read_bytes()), launcher_source_sha256=sha(Path('tests/sol-buf-rusage.c').read_bytes()),
              versions={ 'bash': subprocess.check_output([str(binary), '--version'], text=True).splitlines()[0],
                         'python': platform.python_version(),
                         'cc': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]},
              method='one discarded warmup, seven samples; startup + load + batch; every output and status validated; peak RSS is shell process maximum via wait4 in a fresh small C launcher (avoids inherited Python RSS); output files reset each batch', cases=[])
with tempfile.TemporaryDirectory(prefix='sol-buf-bench-') as td:
    d = Path(td)
    for size in (423000, 4*1024*1024, 32*1024*1024):
        row = b'0123456789abcdef'*3 + b'\x00abcdef01234567\n'
        data = (row*((size+len(row)-1)//len(row)))[:size]
        src = d/'input'
        src.write_bytes(data)
        for op, passes in [('text', 19), ('edited-text', 19), ('load', 7), ('save', 2), ('edited-save', 2)]:
            script = ['PATH=', 'buf new -h b', 'buf load "$b" "$1"']
            if op in ('edited-text', 'edited-save'):
                script += ['buf insert-at "$b" 0 0 5a -X', 'buf delete-at "$b" 0 0 1']
            for i in range(passes):
                dest = d/f'output-{i}'
                if op == 'load':
                    script += ['buf load "$b" "$1"', f'buf text "$b" > "{dest}"']
                elif op in ('save', 'edited-save'):
                    script += [f'buf save "$b" "{dest}"']
                else:
                    script += [f'buf text "$b" > "{dest}"']
            script += ['buf free "$b"']
            samples, rss = [], []
            for run in range(a.runs+1):
                for f in d.glob('output-*'): f.unlink()
                with (d/'stdout').open('wb') as out, (d/'stderr').open('wb') as err:
                    t = time.perf_counter_ns()
                    child = subprocess.Popen([str(a.rusage.resolve()), str(d/'rss'), str(binary), '-e', '-c', '\n'.join(script), '_', str(src)], env=env, stdout=out, stderr=err)
                    _, status, usage = os.wait4(child.pid, 0)
                    child.returncode = os.waitstatus_to_exitcode(status)
                    elapsed = (time.perf_counter_ns()-t)/1e6
                assert child.returncode == 0, (op, size, (d/'stderr').read_bytes())
                assert (d/'stdout').read_bytes() == b''
                assert (d/'stderr').read_bytes() == b''
                for i in range(passes):
                    assert (d/f'output-{i}').read_bytes() == data, (op, size, run, i)
                if run: samples.append(elapsed); rss.append(int((d/'rss').read_text()))
            case = dict(operation=op, input_bytes=size, fixture_sha256=sha(data), operations=passes,
                        setup_loads=1, setup_edits=2 if op in ('edited-text', 'edited-save') else 0,
                        api_calls=3+passes*(2 if op == 'load' else 1)+(2 if op in ('edited-text', 'edited-save') else 0),
                        loaded_input_bytes=size*(1+(passes if op == 'load' else 0)),
                        validation_text_operations=passes if op == 'load' else 0,
                        output_bytes=passes*size, validation='exact Python bytes equality for every operation, warmup and sample',
                        samples_ms=samples, median_ms=statistics.median(samples), peak_rss_kib=rss, max_peak_rss_kib=max(rss), kind='api')
            report['cases'].append(case)
            a.output.write_text(json.dumps(report, indent=2)+'\n')
            print(f'{op} {size} bytes x {passes}: {case["median_ms"]:.3f} ms, RSS {max(rss)} KiB', flush=True)
