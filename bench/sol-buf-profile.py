#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Count allocation/copy/write costs in the actual buf source under local wrappers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--module', type=Path, required=True)
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
report = {'kind': 'syscall-shim', 'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'counter_scope': 'source-local malloc/calloc/realloc requests (not live heap); explicit memcpy bytes including paths (excludes libc realloc and memmove copying); raw write calls; no timings from instrumentation', 'binary_sha256': hashlib.sha256(a.binary.read_bytes()).hexdigest(),
          'module_sha256': hashlib.sha256(a.module.read_bytes()).hexdigest(),
          'source_sha256': hashlib.sha256(a.source.read_bytes()).hexdigest(),
          'affinity': sorted(os.sched_getaffinity(0)), 'cases': []}
with tempfile.TemporaryDirectory(prefix='sol-buf-profile-') as td:
    d = Path(td)
    for shape in ('short-lines', 'single-line'):
        data = (b'0123456789abcde\n' if shape == 'short-lines' else b'0123456789abcdef')*(4*1024*1024//16)
        (d/'input').write_bytes(data)
        for op in ('load', 'text', 'save', 'edit', 'edited-text', 'edited-save'):
            command = {'load': 'buf load "$b" "$1/input"',
                       'text': 'buf text "$b" > "$1/output"',
                       'save': 'buf save "$b" "$1/output"',
                       'edited-text': 'buf text "$b" > "$1/output"',
                       'edited-save': 'buf save "$b" "$1/output"',
                       'edit': 'buf insert-at "$b" 0 0 Z'}[op]
            setup = 'buf insert-at "$b" 0 0 Z; buf delete-at "$b" 0 0 1' if op.startswith('edited-') else ':'
            script = f'''enable -f "$2" buf; enable -f "$2" bufprobe
PATH=; buf new -h b; buf load "$b" "$1/input"
{setup}
bufprobe reset
{command}
bufprobe stats
bufprobe reset
buf text "$b" > "$1/check"
buf free "$b"
'''
            r = subprocess.run([str(a.binary.resolve()), '-e', '-c', script, '_', td, str(a.module.resolve())], capture_output=True)
            assert r.returncode == 0 and r.stderr == b'', r
            expected = b'Z'+data if op == 'edit' else data
            assert (d/'check').read_bytes() == expected
            if op in ('text', 'save', 'edited-text', 'edited-save'): assert (d/'output').read_bytes() == data
            report['cases'].append(dict(shape=shape, operation=op, operations=1, input_bytes=len(data), fixture_sha256=hashlib.sha256(data).hexdigest(), validation='exact independent Python bytes', **json.loads(r.stdout)))
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report['cases'], indent=2))
