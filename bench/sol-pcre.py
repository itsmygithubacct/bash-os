#!/usr/bin/env python3
"""Gated, output-validated PCRE catalog and API batches. Does not build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shlex
import statistics
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--reference', required=True)
p.add_argument('--profiler', required=True)
p.add_argument('--output', required=True)
p.add_argument('--runs', type=int, default=7)
a = p.parse_args()
assert a.runs >= 7
binary, reference, profiler = [str(Path(x).resolve()) for x in (a.binary, a.reference, a.profiler)]
env = {**os.environ, 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'PATH': ''}
env.pop('LD_PRELOAD', None)
for key in ('BASHPCRE_MATCH_LIMIT', 'BASHPCRE_DEPTH_LIMIT', 'BASH_ENV'): env.pop(key, None)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def run(script, cwd, profile=False):
    e = dict(env)
    if profile: e['LD_PRELOAD'] = profiler
    start = time.perf_counter_ns()
    r = subprocess.run([binary, '-e', '-c', 'PATH=; ' + script], cwd=cwd, env=e,
                       capture_output=True, timeout=120)
    elapsed = (time.perf_counter_ns() - start)/1e6
    assert r.returncode == 0, (script, r.returncode, r.stderr[:1000])
    return r, elapsed
rng = random.Random(20260908)
words = ['alpha','beta','gamma','delta','epsilon','the','and','of']
text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n' for _ in range(12000)).encode()[:423000]
wanted = b''.join(x if x.endswith(b'\n') else x+b'\n' for x in text.splitlines(keepends=True) if b'alpha' in x)
q = shlex.quote
cases = {
    'catalog': (14, {'builtin': 'pcre grep alpha text', 'pcre2': q(reference)+' alpha text',
                     'gnu': '/usr/bin/grep -P alpha text'}, wanted, '423000 B catalog text; select alpha lines'),
    'retained-text-captures': (5000, {'builtin': "pcre match '(a)(b)' ab; [[ ${BPCRE_MATCH[0]} == ab && ${BPCRE_MATCH[1]} == a && ${BPCRE_MATCH[2]} == b ]]"}, b'', '5000 cache-hit matches and capture bindings'),
    'retained-hex-captures': (5000, {'builtin': "pcre match 286129280029 6100 -X; [[ ${BPCRE_MATCH[0]} == 6100 && ${BPCRE_MATCH[1]} == 61 && ${BPCRE_MATCH[2]} == 00 ]]"}, b'', '5000 hex decodes, cached binary-pattern matches and capture encodes'),
    'compile-per-call': (5000, {'builtin': 'pcre match "(a)(b)(?#$i)" ab; [[ ${BPCRE_MATCH[2]} == b ]]'}, b'', '5000 unique patterns; compile/match/capture bind'),
    'retained-replace': (5000, {'builtin': "pcre subst '(a)(b)' '$2$1' ab"}, b'ba\n', '5000 cached-pattern replacements'),
}
report = dict(binary=binary, binary_sha256=sha(binary), reference_sha256=sha(reference),
              source_sha256=sha('loadables/pcre.c'), harness_sha256=sha(__file__),
              reference_source_sha256=sha('tests/sol-pcre-reference.c'),
              commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
              affinity=sorted(os.sched_getaffinity(0)), platform=platform.uname()._asdict(),
              cpu=next((l.strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')), ''),
              environment={k:env[k] for k in ('PATH','LC_ALL','TZ')},
              fixture=dict(bytes=len(text), sha256=hashlib.sha256(text).hexdigest(), selected_bytes=len(wanted)),
              versions={}, cases={})
for name, cmd in {'bash':[binary,'--version'], 'grep':['/usr/bin/grep','--version'], 'pcre2':['pkg-config','--modversion','libpcre2-8'], 'linkage':['ldd',binary]}.items():
    r = subprocess.run(cmd,capture_output=True,text=True)
    report['versions'][name] = dict(exit=r.returncode, stdout=r.stdout, stderr=r.stderr)
with tempfile.TemporaryDirectory() as d:
    Path(d,'text').write_bytes(text)
    for name, (passes, variants, expected, work) in cases.items():
        row = dict(kind='compared' if name == 'catalog' else 'api', passes=passes, work=work,
                   warmups=1, samples={}, profiles={}, commands=variants, validation='exact stdout and exit 0 on every pass, warmup and sample')
        scripts = {k: 'for ((i=0;i<'+str(passes)+';i++)); do '+v+'; done' for k,v in variants.items()}
        for k,s in scripts.items():
            r,_ = run(s,d)
            assert r.stdout == expected*passes, (name,k,len(r.stdout))
            row['samples'][k] = []
        for sample in range(a.runs):
            order = list(scripts)
            if sample % 2: order.reverse()
            for k in order:
                r,ms = run(scripts[k],d)
                assert r.stdout == expected*passes, (name,k,sample,len(r.stdout))
                row['samples'][k].append(ms)
        r,_ = run(scripts['builtin'],d,True)
        assert r.stdout == expected*passes
        row['profiles']['builtin'] = r.stderr.decode()
        row['medians_ms'] = {k:statistics.median(v) for k,v in row['samples'].items()}
        if name == 'catalog': row['builtin_over_reference'] = {k:row['medians_ms']['builtin']/row['medians_ms'][k] for k in ('pcre2','gnu')}
        report['cases'][name] = row
        print(name, row['medians_ms'], row.get('builtin_over_reference',''), flush=True)
Path(a.output).write_text(json.dumps(report,indent=2)+'\n')
