#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated unexpand -a workloads. Run via the campaign bench gate.

Every warmup/sample validates each pass's exact bytes, stderr and exit status
outside the timer. Output-failure checks are also outside timing. No builds.
"""
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

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--previous', type=Path, help='Also interleave the candidate before the measured conversion optimization')
p.add_argument('--before', type=Path, help='Interleave a retained baseline builtin with the current build and GNU')
p.add_argument('--source', type=Path, default=ROOT / 'loadables/unexpand.c')
p.add_argument('--output', type=Path, required=True)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--profile', type=Path)
a = p.parse_args()
assert a.runs >= 7
binary = a.binary.resolve()
sha = lambda b: hashlib.sha256(b).hexdigest()
env = dict(os.environ, LC_ALL='C', PATH='')
report = dict(harness_sha256=sha(Path(__file__).read_bytes()), binary=str(binary), binary_sha256=sha(binary.read_bytes()),
              external_sha256=sha(Path('/usr/bin/unexpand').read_bytes()),
              source_sha256=sha(a.source.read_bytes()),
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              source_path=str(a.source.resolve()),
              worktree_source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain', '--', 'loadables/unexpand.c'], cwd=ROOT)),
              cpu_affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
              cpu=next((s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines()
                        if s.startswith('model name')), ''),
              versions={name: subprocess.check_output([exe, '--version'], text=True).splitlines()[0]
                        for name, exe in [('bash', str(binary)), ('gnu', '/usr/bin/unexpand'), ('cc', '/usr/bin/cc')]},
              environment={'LC_ALL':'C', 'PATH':'', 'reset':'reopen fixture and truncate one output per pass'},
              method='one warmup then >=7 samples; alternate order; shell startup and output-file creation included; validate every pass outside timing',
              cases=[])
if a.before:
    a.before = a.before.resolve()
    report['before_binary'] = str(a.before)
    report['before_sha256'] = sha(a.before.read_bytes())
if a.previous:
    a.previous = a.previous.resolve()
    report['previous_binary'] = str(a.previous)
    report['previous_sha256'] = sha(a.previous.read_bytes())
a.output.parent.mkdir(parents=True, exist_ok=True)
try:
    with tempfile.TemporaryDirectory(prefix='sol-unexpand-bench-') as d:
        d = Path(d)
        cases = [('tiny', b'alpha   beta    gamma\n', 300),
                 ('historical-spaces', b'alpha   beta    gamma\n' * 20000, 9),
                 ('large-spaces', b'alpha   beta    gamma\n' * 200000, 3),
                 ('long-blanks', b' ' * 1000000 + b'X\n', 3),
                 ('binary-controls', (bytes(range(256)) + b'        \b   \t\0\n') * 2000, 3)]
        for name, data, passes in cases:
            fixture = d / name
            fixture.write_bytes(data)
            oracle = subprocess.run(['/usr/bin/unexpand', '-a', str(fixture)], capture_output=True,
                                    env=env, timeout=30)
            assert oracle.returncode == 0 and not oracle.stderr
            expected = oracle.stdout
            if 'spaces' in name or name == 'tiny':
                assert len(data) % len(b'alpha   beta    gamma\n') == 0
                assert expected == b'alpha\tbeta\tgamma\n' * (len(data) // len(b'alpha   beta    gamma\n'))
            row = dict(name=name, fixture_sha256=sha(data), bytes=len(data), passes=passes,
                       work_bytes=len(data) * passes, output_bytes=len(expected), output_sha256=sha(expected),
                       options=['-a'], results={})
            report['cases'].append(row)
            commands = {'builtin':(binary, 'unexpand -a'), 'gnu':(binary, '/usr/bin/unexpand -a')}
            if a.before:
                commands['before'] = (a.before, 'unexpand -a')
            if a.previous:
                commands['previous'] = (a.previous, 'unexpand -a')
            for impl, (shell_binary, command) in commands.items():
                with open('/dev/full', 'wb') as full:
                    failed = subprocess.run([str(shell_binary), '-c', command + ' < "$1"', '_', str(fixture)],
                                            stdout=full, stderr=subprocess.PIPE, env=env, timeout=30)
                assert failed.returncode == 1 and b'write error' in failed.stderr, (impl, failed)
                row['results'][impl] = dict(output_failure_exit=failed.returncode, samples_ms=[], validations=[])
            if a.profile:
                if name != 'historical-spaces':
                    continue
                outdir = d / 'profile-output'; outdir.mkdir()
                script = 'for ((i=0;i<400;i++)); do unexpand -a < "$1" > "$2/$i" || exit; done'
                proc = subprocess.run(['gprofng', 'collect', 'app', '-F', 'off', '-p', 'hi',
                                       '-o', str(a.profile.resolve()), str(binary), '-c', script, '_',
                                       str(fixture), str(outdir)], capture_output=True, env={**env, 'PATH':'/usr/bin:/bin'}, timeout=120)
                assert proc.returncode == 0, proc.stderr
                assert all((outdir / str(i)).read_bytes() == expected for i in range(400))
                report['profile'] = dict(validated=True, passes=400, experiment=str(a.profile), stderr=proc.stderr.decode())
                break
            for sample in range(-1, a.runs):
                order = list(commands) if sample % 2 else list(reversed(commands))
                for impl in order:
                    outdir = d / f'{name}-{impl}-{sample}'; outdir.mkdir()
                    shell_binary, command = commands[impl]
                    script = ('for ((i=0;i<$3;i++)); do ' + command +
                              ' < "$1" > "$2/$i"; rc=$?; printf "%s\\n" "$rc" >&3; '
                              '[[ $rc == 0 ]] || exit "$rc"; done')
                    with tempfile.TemporaryFile() as statuses:
                        start = time.perf_counter_ns()
                        proc = subprocess.run([str(shell_binary), '-c', script + ' 3>&1', '_', str(fixture), str(outdir), str(passes)],
                                              stdout=statuses, stderr=subprocess.PIPE, env=env, timeout=120)
                        elapsed = (time.perf_counter_ns() - start) / 1e6
                        statuses.seek(0); status = statuses.read()
                    valid = proc.returncode == 0 and status == b'0\n' * passes and not proc.stderr
                    valid = valid and all((outdir / str(i)).read_bytes() == expected for i in range(passes))
                    entry = dict(sample=sample, valid=valid, shell_exit=proc.returncode,
                                 statuses=status.decode(errors='replace'), stderr=proc.stderr.decode(errors='replace'))
                    row['results'][impl]['validations'].append(entry)
                    assert valid, (name, impl, entry)
                    if sample >= 0:
                        row['results'][impl]['samples_ms'].append(elapsed)
                    else:
                        row['results'][impl]['warmup_ms'] = elapsed
                    for path in outdir.iterdir(): path.unlink()
                    outdir.rmdir()
            if not a.profile:
                for result in row['results'].values():
                    result['median_ms'] = statistics.median(result['samples_ms'])
                    result['min_ms'] = min(result['samples_ms'])
                    result['max_ms'] = max(result['samples_ms'])
                row['builtin_over_gnu'] = row['results']['builtin']['median_ms'] / row['results']['gnu']['median_ms']
                if a.before:
                    row['before_over_builtin'] = row['results']['before']['median_ms'] / row['results']['builtin']['median_ms']
                if a.previous:
                    row['previous_over_builtin'] = row['results']['previous']['median_ms'] / row['results']['builtin']['median_ms']
                print(name, 'validated', row['builtin_over_gnu'], flush=True)
finally:
    a.output.write_text(json.dumps(report, indent=2) + '\n')
