#!/usr/bin/env python3
"""Fixed join workloads; validate each invocation, including every timed pass.

Run only through the campaign bench gate. Builds are separate. Instrumented
modules optionally collect function call counts in untimed profile passes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixtures(root):
    rows = []
    def add(name, left, right, expected, passes, work):
        d = root/name
        d.mkdir()
        for label, data in [('left', left), ('right', right), ('expected', expected)]:
            (d/label).write_bytes(data)
        rows.append(dict(name=name, passes=passes, work=work,
                         hashes={n: sha(d/n) for n in ('left', 'right', 'expected')},
                         bytes={n: (d/n).stat().st_size for n in ('left', 'right', 'expected')}))
    add('historical', b''.join(f'{i:06d} left\n'.encode() for i in range(10000)),
        b''.join(f'{i:06d} right\n'.encode() for i in range(0,10000,2)),
        b''.join(f'{i:06d} left right\n'.encode() for i in range(0,10000,2)), 18,
        '10000 left + 5000 right rows; 5000 joined rows per invocation')
    left, right, out = [], [], []
    for k in range(120):
        key = f'{k:06d}'.encode()
        ls = [f'L{i:03d}'.encode() for i in range(40)]
        rs = [f'R{i:03d}'.encode() for i in range(35)]
        left += [key+b' '+v+b'\n' for v in ls]
        right += [key+b' '+v+b'\n' for v in rs]
        out += [key+b' '+l+b' '+r+b'\n' for l in ls for r in rs]
    add('duplicates', b''.join(left), b''.join(right), b''.join(out), 3,
        '120 keys x 40 left x 35 right; 9000 input rows, 168000 output rows per invocation')
    left = b''.join(b'a '+f'{i:06d}'.encode()+b'x'*8192+b'\n' for i in range(4000))
    right = b'a R\n'
    out = b''.join(line+b' R\n' for line in left.splitlines())
    add('large-group', left, right, out, 2,
        'one key, 4000 left rows with 8198-byte fields x one right row; 4000 output rows')
    left, right, out = [], [], []
    for i in range(2000):
        key = f'{i:06d}'.encode()
        left.append(key+b' '+b'x'*8192+b'\n')
        right.append(key+b' R\n')
        out.append(key+b' '+b'x'*8192+b' R\n')
    add('large-unique', b''.join(left), b''.join(right), b''.join(out), 3,
        '2000 unique keys, 8192-byte left fields; 4000 input and 2000 output rows')
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=Path('loadables/join.c'))
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--rusage-launcher', type=Path, required=True)
    p.add_argument('--profile-module', type=Path)
    p.add_argument('--runs', type=int, default=7)
    a = p.parse_args()
    assert a.runs >= 7
    binary = a.binary.resolve()
    env = dict(PATH='', LC_ALL='C', TZ='UTC', TERM='dumb')
    report = dict(binary=str(binary), binary_sha256=sha(binary),
                  source_sha256=sha(a.source), source_path=str(a.source), driver_sha256=sha(__file__),
                  external_sha256=sha('/usr/bin/join'), python=platform.python_version(),
                  rusage_launcher_sha256=sha(a.rusage_launcher),
                  source_dirty=(a.source.resolve() == Path('loadables/join.c').resolve() and
                                subprocess.run(['git','diff','--quiet','--','loadables/join.c']).returncode != 0),
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
                  affinity=sorted(os.sched_getaffinity(0)), environment=env,
                  platform=platform.platform(), cpu=next((l.strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')), ''),
                  versions={n: subprocess.check_output([exe,'--version'], text=True).splitlines()[0]
                            for n,exe in [('bash',str(binary)),('GNU','/usr/bin/join'),('compiler','gcc')]},
                  method='One warmup plus >=7 alternating sample rounds; same Bash shell for both commands; per-pass separate regular output files; wall includes shell startup and output writes; small native fork/wait4 launcher maxRSS includes waited children, excludes Python pre-exec high water mark; every status and byte validated outside timer', cases=[])
    historical = a.output.with_name(a.output.stem+'-historical.json')
    assert not historical.exists(), historical
    subprocess.run(['python3', 'bench/loadables.py', '--binary', str(binary),
                    '--only', 'join', '--passes', '18', '--runs', str(a.runs),
                    '--cpu', str(max(os.sched_getaffinity(0))), '--output', str(historical)],
                   check=True)
    historical_data = json.loads(historical.read_text())
    for case in historical_data['cases']:
        for label in ('bashos', 'external'):
            assert case['results'][label]['status'] == 'ok', (label, case)
    report['shared_historical_report'] = str(historical)
    with tempfile.TemporaryDirectory(prefix='sol-join-') as tmp:
        root = Path(tmp)
        for row in fixtures(root):
            d = root/row['name']
            expected = (d/'expected').read_bytes()
            row['results'] = {}
            for label in ('builtin','GNU'):
                row['results'][label] = dict(status='ok', samples_ms=[], peak_rss_kib=[], validated_passes=0)
            for sample in range(-1,a.runs):
                order = ['builtin','GNU'] if sample % 2 else ['GNU','builtin']
                for label in order:
                    command = 'join' if label == 'builtin' else '/usr/bin/join'
                    script = f'for ((i=0;i<{row["passes"]};i++)); do {command} left right >"pass$i" || exit; done'
                    start = time.perf_counter_ns()
                    got = subprocess.run([str(a.rusage_launcher.resolve()), str(d/'rss'), str(binary),
                                          '--noprofile', '--norc', '-c', script],
                                         cwd=d, env=env, capture_output=True)
                    ms = (time.perf_counter_ns()-start)/1e6
                    assert got.returncode == 0 and not got.stderr and not got.stdout, (row['name'],label,got)
                    result = row['results'][label]
                    for i in range(row['passes']):
                        actual = (d/f'pass{i}').read_bytes()
                        assert actual == expected, (row['name'],label,sample,i,hashlib.sha256(actual).hexdigest())
                        result['validated_passes'] += 1
                    if sample >= 0:
                        result['samples_ms'].append(ms)
                        result['peak_rss_kib'].append(int((d/'rss').read_text()))
            for result in row['results'].values():
                result['median_ms'] = statistics.median(result['samples_ms'])
                result['max_rss_kib'] = max(result['peak_rss_kib'])
            row['builtin_over_GNU'] = row['results']['builtin']['median_ms']/row['results']['GNU']['median_ms']
            if a.profile_module:
                row['profile_module_sha256'] = sha(a.profile_module)
                row['instrumented_profiles'] = []
                script = 'enable -f '+shlex.quote(str(a.profile_module.resolve()))+' join; join left right'
                for profile_sample in range(-1, a.runs):
                    with (d/'profile-output').open('wb') as out:
                        got = subprocess.run([str(binary),'-c',script], cwd=d, env=env,
                                             stdout=out, stderr=subprocess.PIPE)
                    assert got.returncode == 0 and (d/'profile-output').read_bytes() == expected, got.stderr
                    assert got.stderr.startswith(b'PROFILE '), got.stderr
                    if profile_sample >= 0:
                        row['instrumented_profiles'].append(got.stderr.decode())
            report['cases'].append(row)
            a.output.write_text(json.dumps(report,indent=2)+'\n')
            print(row['name'], json.dumps(row['results']), 'ratio',row['builtin_over_GNU'],flush=True)

if __name__ == '__main__':
    main()
