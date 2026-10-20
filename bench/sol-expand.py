#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated size sweep: every warm-up/timed pass has exact bytes and status.

Run through the campaign bench gate. No build is performed. Timings include
writing to a private regular file; output validation occurs after the timer.
The catalog fixture/options match bench/loadables.py, with stronger timed-pass
validation. External commands run in the same selected Bash executable.
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

import loadables

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', action='append', required=True, help='LABEL=PATH')
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source-for', action='append', default=[], help='LABEL=SOURCE snapshot for provenance')
p.add_argument('--runs', type=int, default=7)
a = p.parse_args()
assert a.runs >= 7
binaries = {label: str(Path(path).resolve()) for label, path in
            (x.split('=', 1) for x in a.binary)}
sha = lambda b: hashlib.sha256(b).hexdigest()
sources = {label: dict(path=path, sha256=sha(Path(path).read_bytes()))
           for label, path in (x.split('=', 1) for x in a.source_for)}
report = dict(cpu_model=next((line.split(':', 1)[1].strip() for line in
              Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
              compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
              libc=platform.libc_ver(), method='exact output and status on every pass; private regular-file output; '
              'one full-batch warm-up; rotating order; warm cache; no reset beyond fresh stdin per invocation',
              affinity=sorted(os.sched_getaffinity(0)), kernel=platform.release(),
              machine=platform.machine(), environment=dict(PATH='', LC_ALL='C', TZ='UTC'),
              load_start=os.getloadavg(), runs=a.runs, cases=[],
              worktree_source_sha256=sha(Path('loadables/expand.c').read_bytes()), source_snapshots=sources,
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              worktree_source_diff=subprocess.check_output(['git','diff','--','loadables/expand.c'], text=True),
              binaries={k: dict(path=v, sha256=sha(Path(v).read_bytes()),
                        source_sha256=sources.get(k, {}).get('sha256'),
                        version=subprocess.check_output([v, '--version'], text=True).splitlines()[0])
                        for k, v in binaries.items()},
              gnu=dict(sha256=sha(Path('/usr/bin/expand').read_bytes()),
                       version=subprocess.check_output(['/usr/bin/expand','--version'],text=True).splitlines()[0]))
# Run GNU under the last supplied shell, so only command implementation differs.
commands = {k: (v, 'expand') for k, v in binaries.items()}
commands['gnu'] = (list(binaries.values())[-1], '/usr/bin/expand')
env = report['environment']
catalog_case = next(case for case in loadables.cases() if case['id'] == 'expand')
assert catalog_case['args'] == ['-t', '8'] and catalog_case['fixture'] == 'tabs'
report['catalog_case'] = catalog_case
with tempfile.TemporaryDirectory(prefix='sol-expand-bench-') as directory:
    root = Path(directory)
    fixture = root / 'tabs'
    # Read the authoritative catalog fixture through its unchanged generator.
    catalog_metadata = loadables.fixtures(root, {'tabs'})['tabs']
    assert fixture.read_bytes() == b'alpha\tbeta\tgamma\n' * 20000
    report['catalog_fixture'] = catalog_metadata
    for lines, passes in [(20, 38), (2000, 10), (20000, 38), (200000, 10)]:
        data = b'alpha\tbeta\tgamma\n' * lines
        fixture.write_bytes(data)
        expected = b'alpha   beta    gamma\n' * lines
        row = dict(id='expand' if lines == 20000 else f'expand-{lines}-lines',
                   lines=lines, passes=passes, input_bytes=len(data),
                   input_sha256=sha(data), output_bytes=len(expected), output_sha256=sha(expected),
                   options=['-t', '8'], results={})
        samples = {k: [] for k in commands}
        def run(label):
            shell, command = commands[label]
            script = ('[[ $(type -t expand) == builtin ]] || exit 99; '
                      'for ((i=0;i<$2;i++)); do "$3" -t 8 < "$1" || exit; done')
            with tempfile.TemporaryFile() as output:
                start = time.perf_counter_ns()
                got = subprocess.run([shell, '--noprofile', '--norc', '-c', script,
                                      '_', str(fixture), str(passes), command],
                                     env=env, stdout=output, stderr=subprocess.PIPE, timeout=120)
                elapsed = (time.perf_counter_ns() - start) / 1e6
                assert got.returncode == 0 and not got.stderr, (label, got)
                output.seek(0)
                # Check every pass separately, then require EOF: detect dropped,
                # stale, partial or extra data even on later timed invocations.
                for n in range(passes):
                    actual = output.read(len(expected))
                    assert actual == expected, (label, lines, n, len(actual), sha(actual))
                assert not output.read(1), (label, 'extra output')
            return elapsed
        for label in commands:
            run(label)
        for n in range(a.runs):
            order = list(commands)
            order = order[n % len(order):] + order[:n % len(order)]
            if n % 2:
                order.reverse()
            for label in order:
                samples[label].append(run(label))
        for label, values in samples.items():
            row['results'][label] = dict(status='ok', runs_ms=values,
                    median_ms=statistics.median(values), min_ms=min(values), max_ms=max(values),
                    validated_passes=passes * (a.runs + 1))
        report['cases'].append(row)
        a.output.write_text(json.dumps(report, indent=2) + '\n')
        print(lines, {k: round(v['median_ms'], 3) for k, v in row['results'].items()}, flush=True)
report['load_end'] = os.getloadavg()
a.output.write_text(json.dumps(report, indent=2) + '\n')
