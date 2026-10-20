#!/usr/bin/env python3
"""Validated sed batches; run through the campaign bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('binary', type=Path)
p.add_argument('report', type=Path)
p.add_argument('--passes', type=int, default=8)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--source', type=Path, default=ROOT/'loadables/sed.c')
p.add_argument('--profile', type=Path, help='Collect a gprofng CPU profile instead of timings')
a = p.parse_args()
assert a.runs >= 7 and a.passes > 0
binary = a.binary.resolve()
env = dict(PATH='', LC_ALL='C', TZ='UTC')
sha = lambda b: hashlib.sha256(b).hexdigest()
report = dict(date_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()), load_average_start=os.getloadavg(), binary_sha256=sha(binary.read_bytes()), source_sha256=sha(a.source.read_bytes()),
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              affinity=sorted(os.sched_getaffinity(0)), environment=env, kernel=platform.release(),
              cpu=next(x for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
              versions={}, passes=a.passes, runs=a.runs, cases=[],
              method='Same shell, warm regular files, rotating order, one warmup and >=7 samples; each pass output captured to a fresh temporary regular file and every pass compared byte for byte; shell exits on each failed invocation')
for label, command in [('bash', [str(binary), '--version']), ('sed', ['/usr/bin/sed', '--version']), ('cc', ['cc', '--version'])]:
    report['versions'][label] = subprocess.check_output(command, text=True).splitlines()[0]
manifest = Path(str(binary)+'.manifest.txt')
report['build_manifest'] = manifest.read_text() if manifest.exists() else None
report['driver_sha256'] = sha(Path(__file__).read_bytes())
report['source_is_git_head'] = a.source.read_bytes() == subprocess.check_output(['git', 'show', 'HEAD:loadables/sed.c'], cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='sol-sed-bench-') as directory:
    d = Path(directory)
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    text = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                   for _ in range(12000)).encode()[:423000]
    assert sha(text) == 'fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee'
    (d/'text').write_bytes(text)
    report['fixtures'] = {'text': dict(bytes=len(text), sha256=sha(text))}
    branch = b'alpha alpha beta\n' * 24000 + b'alpha'
    (d/'branch').write_bytes(branch)
    chunks = [b'first\n' + b'alpha beta\n'*8000, b'', b'alpha beta\n'*8000+b'last']
    for i, data in enumerate(chunks):
        (d/f'part{i}').write_bytes(data)
    cases = [('historical-substitution', ['s/alpha/OMEGA/g'], 'text', text.replace(b'alpha', b'OMEGA')),
             ('branch', [':again;s/alpha/OMEGA/;t again'], 'branch', branch.replace(b'alpha', b'OMEGA')),
             ('multifile', ['-n', '1h;2,$H;$ {g;s/alpha/OMEGA/g;p;=;}', 'part0', 'part1', 'part2'],
              'empty', b''.join(chunks).replace(b'alpha', b'OMEGA') + b'\n16002\n')]
    (d/'empty').touch()
    if a.profile:
        fixture = d/'text'
        expected = cases[0][3]
        count = 400
        program = 'for ((i=0;i<400;i++)); do sed s/alpha/OMEGA/g < "$1" || exit; done > "$2"'
        output = d/'profile-output'
        proc = subprocess.run(['/usr/bin/gprofng', 'collect', 'app', '-F', 'off', '-p', 'hi',
                               '-o', str(a.profile.resolve()), str(binary), '-c', program, '_',
                               str(fixture), str(output)], env=env, capture_output=True)
        got = output.read_bytes() if output.exists() else b''
        report['profile'] = dict(exit_code=proc.returncode, validated=proc.returncode==0 and got==expected*count,
                                 calls=count, expected_bytes=len(expected)*count, actual_bytes=len(got),
                                 collector_stdout=proc.stdout.decode(errors='replace'),
                                 stderr=proc.stderr.decode(errors='replace'))
        a.report.write_text(json.dumps(report,indent=2)+'\n')
        assert report['profile']['validated'], report['profile']
        raise SystemExit(0)
    for name, args, fixture, expected in cases:
        row = dict(workload=name, args=args, fixture=fixture, fixture_sha256=sha((d/fixture).read_bytes()),
                   operand_hashes={f'part{i}': sha(data) for i, data in enumerate(chunks)} if name == 'multifile' else {},
                   input_bytes=sum(map(len, chunks)) if name == 'multifile' else len((d/fixture).read_bytes()),
                   expected_sha256=sha(expected), output_bytes=len(expected), results={})
        accepted = []
        commands = {'builtin':['sed', *args], 'gnu':['/usr/bin/sed', *args]}
        def run(label, count):
            program = ('input=$1; count=$2; shift 2; for ((i=0;i<count;i++)); do '
                       '"$@" < "$input" > "pass-$i.out" || exit; done')
            for i in range(count):
                (d/f'pass-{i}.out').unlink(missing_ok=True)
            start = time.perf_counter_ns()
            proc = subprocess.run([str(binary), '--noprofile', '--norc', '-c', program, '_', fixture,
                                   str(count), *commands[label]], cwd=d, env=env, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, timeout=120)
            elapsed = (time.perf_counter_ns()-start)/1e6
            outputs = [(d/f'pass-{i}.out').read_bytes() if (d/f'pass-{i}.out').exists() else None
                       for i in range(count)]
            valid = proc.returncode == 0 and all(got == expected for got in outputs)
            hashes = [sha(got) if got is not None else None for got in outputs]
            return elapsed, valid, proc.returncode, hashes, proc.stderr.decode(errors='replace')
        for label in commands:
            warm = run(label, a.passes)
            if warm[1]:
                accepted.append(label)
                row['results'][label] = dict(status='ok', warmup=dict(exit_code=warm[2], output_sha256=warm[3]), samples_ms=[], validated_samples=[])
            else:
                row['results'][label] = dict(status='invalid', exit_code=warm[2], actual_sha256_per_pass=warm[3], stderr=warm[4])
        for n in range(a.runs):
            for label in (accepted if n%2 == 0 else accepted[::-1]):
                elapsed, valid, rc, digest, err = run(label, a.passes)
                assert valid, (name, label, rc, digest, err)
                row['results'][label]['samples_ms'].append(elapsed)
                row['results'][label]['validated_samples'].append(dict(exit_code=rc, output_sha256=digest))
        for result in row['results'].values():
            if result['status'] == 'ok':
                values = result['samples_ms']
                result.update(median_ms=statistics.median(values), min_ms=min(values), max_ms=max(values))
        if all(row['results'][x]['status']=='ok' for x in commands):
            row['builtin_over_gnu'] = row['results']['builtin']['median_ms']/row['results']['gnu']['median_ms']
        report['cases'].append(row)
        report['load_average_end'] = os.getloadavg()
        a.report.write_text(json.dumps(report, indent=2)+'\n')
        print(name, {label: {k: result[k] for k in ('status','median_ms','min_ms','max_ms') if k in result}
                     for label,result in row['results'].items()}, flush=True)
