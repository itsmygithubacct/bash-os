#!/usr/bin/env python3
"""Test benchmark scheduling with mocked work; no timing measurement."""
import ast
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1]/'bench'/'sol-index.py'
tree = ast.parse(source.read_text())
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'batch_script']
namespace = {}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
with tempfile.TemporaryDirectory(prefix='index-bench-check-') as d:
    body = '{ if ((i % 2)); then printf B; else printf A; fi; } >> trace'
    script = namespace['batch_script'](body, 5, 7, 'i=0').replace('$EPOCHREALTIME', '0000000')
    r = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', script], cwd=d, capture_output=True)
    assert r.returncode == 0, r.stderr
    trace = (Path(d)/'trace').read_text()
    assert len(trace) == 40, trace
    assert trace == 'AB'*20, 'each warm-up and timed pass must alternate: '+trace
    # A failed work invocation must invalidate the entire report.
    bad = namespace['batch_script']('false', 5, 7).replace('$EPOCHREALTIME', '0000000')
    r = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', bad], cwd=d, capture_output=True)
    assert r.returncode != 0
print('PASS: 40 alternating invocations, including all warm-up and batch boundaries; failures propagate')
