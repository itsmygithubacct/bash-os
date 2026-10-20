#!/usr/bin/env python3
"""Validated grep batches. Run through the campaign bench gate; never builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shlex
import statistics
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--source', default='loadables/grep.c')
    p.add_argument('--pcre', action='store_true')
    a = p.parse_args()
    binary = str(Path(a.binary).resolve())
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                   for _ in range(12000)).encode()[:423000]
    lines = text.splitlines(keepends=True)
    ordinary = b''.join(x if x.endswith(b'\n') else x+b'\n'
                        for x in lines if b'alpha' in x)
    regex = rb'(alpha|beta)[a-z ]*(gamma|delta)'
    regex_count = sum(bool(re.search(regex, x)) for x in lines)
    cases = [('grep-count', ['-c', 'alpha'], text,
              str(sum(b'alpha' in x for x in lines)).encode()+b'\n', 0, 57),
             ('grep-lines', ['alpha'], text, ordinary, 0, 57)]
    for dialect, pat in [('-E', regex.decode()),
                         ('-G', r'\(alpha\|beta\)[a-z ]*\(gamma\|delta\)')]:
        cases += [(dialect+'-scan', [dialect, '-c', pat], text,
                   str(regex_count).encode()+b'\n', 0, 15),
                  (dialect+'-compile-empty', [dialect, '-c', pat], b'', b'0\n', 1, 200)]
    if a.pcre:
        # Python's independent oracle for lookahead; no regex engine is used
        # to derive the expected result for the ordinary cases.
        pat = r'alpha(?=[a-z ]*gamma)'
        count = sum(bool(re.search(pat.encode(), x)) for x in lines)
        cases += [('PCRE-scan', ['-P', '-c', pat], text, str(count).encode()+b'\n', 0, 15),
                  ('PCRE-compile-empty', ['-P', '-c', pat], b'', b'0\n', 1, 200)]
    env = dict(os.environ, LC_ALL='C', PATH='')
    report = dict(binary=binary, binary_sha256=sha(binary),
                  source_sha256=sha(a.source),
                  source_file=str(Path(a.source).resolve()),
                  working_tree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'])),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
                  environment=dict(platform=platform.platform(), cpu=platform.processor(),
                                   cpu_model=next((x.split(':', 1)[1].strip() for x in
                                                   Path('/proc/cpuinfo').read_text().splitlines()
                                                   if x.startswith('model name')), 'unknown'),
                                   affinity=sorted(os.sched_getaffinity(0)), locale='C',
                                   shell=subprocess.check_output([binary, '--version']).decode().splitlines()[0],
                                   reference=subprocess.check_output(['/usr/bin/grep', '--version']).decode().splitlines()[0],
                                   compiler=subprocess.check_output(['cc', '--version']).decode().splitlines()[0],
                                   pcre2=subprocess.check_output(['pkg-config', '--modversion', 'libpcre2-8']).decode().strip()),
                  method='One warmup and seven interleaved samples; same shell, fresh stdin redirection per pass; '
                         'stdout and status validated for every pass including warmup. Empty input measures '
                         'call/compile cost; scan includes compilation, IO and output. No subtraction or pure-engine claim.',
                  cases=[])
    with tempfile.TemporaryDirectory(prefix='sol-grep-bench-') as td:
        for name, args, data, expected, status, passes in cases:
            fixture = Path(td)/'input'
            fixture.write_bytes(data)
            row = dict(name=name, args=args, passes=passes, bytes_per_pass=len(data),
                       records_per_pass=len(data.splitlines()), fixture_sha256=sha(fixture),
                       expected_sha256=hashlib.sha256(expected).hexdigest(), expected_status=status,
                       validation='pending', samples_ms={'builtin': [], 'GNU': []})
            report['cases'].append(row)
            frame = expected + b'\x1e' + str(status).encode() + b'\x1f'
            for iteration in range(8):
                order = ['builtin', 'GNU'] if iteration % 2 == 0 else ['GNU', 'builtin']
                for implementation in order:
                    cmd = shlex.join((['grep'] if implementation == 'builtin' else ['/usr/bin/grep']) + args)
                    script = (f'for ((i=0;i<{passes};i++)); do {cmd} < {shlex.quote(str(fixture))}; '
                              'printf "\\036%d\\037" "$?"; done')
                    started = time.perf_counter_ns()
                    r = subprocess.run([binary, '-c', script], env=env, capture_output=True)
                    elapsed = (time.perf_counter_ns()-started)/1e6
                    if r.returncode or r.stderr or r.stdout != frame*passes:
                        row['validation'] = 'FAILED'
                        row['failure'] = dict(implementation=implementation, iteration=iteration,
                                              exit=r.returncode, stderr=r.stderr.decode(errors='replace'),
                                              output_sha256=hashlib.sha256(r.stdout).hexdigest())
                        Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
                        raise SystemExit(f'{name}: validation failed: {row["failure"]}')
                    if iteration:
                        row['samples_ms'][implementation].append(elapsed)
            row['validation'] = 'ok: every pass matched independent stdout/status oracle'
            row['median_ms'] = {k: statistics.median(v) for k, v in row['samples_ms'].items()}
            row['builtin_over_GNU'] = row['median_ms']['builtin']/row['median_ms']['GNU']
            print(name, row['median_ms'], flush=True)
    Path(a.output).write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
