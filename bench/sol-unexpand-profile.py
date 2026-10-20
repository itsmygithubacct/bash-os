#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trace production unexpand I/O separately from timings; run via bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture', choices=['spaces', 'long-blanks'], default='spaces')
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--source', type=Path, default=Path('loadables/unexpand.c'))
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
binary = a.binary.resolve()
env = dict(os.environ, LC_ALL='C', PATH='')
line = b'alpha   beta    gamma\n'
data = line * 20000
expected = b'alpha\tbeta\tgamma\n' * 20000
if a.fixture == 'long-blanks':
    data = b' ' * 1000000 + b'X\n'
    expected = b'\t' * 125000 + b'X\n'
report = dict(fixture=a.fixture, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
              source_sha256=hashlib.sha256(a.source.read_bytes()).hexdigest(),
              cpu_affinity=sorted(os.sched_getaffinity(0)), fixture_sha256=hashlib.sha256(data).hexdigest(),
              work_bytes=9 * len(data), passes=9, options=['-a'],
              strace_version=subprocess.check_output(['/usr/bin/strace', '--version'], text=True).splitlines()[0],
              method='separate strace -f -c runs; output bytes and each invocation status validated; no wall-time ratios', results={})
a.output.parent.mkdir(parents=True, exist_ok=True)
try:
    with tempfile.TemporaryDirectory(prefix='sol-unexpand-profile-') as d:
        root = Path(d)
        fixture = root / 'spaces'; fixture.write_bytes(data)
        for name, command in [('builtin', 'unexpand -a'), ('gnu', '/usr/bin/unexpand -a')]:
            out = root / name; out.mkdir()
            trace = a.output.with_name(a.output.stem + '-' + name + '.txt')
            script = ('for ((i=0;i<9;i++)); do ' + command + ' < "$1" > "$2/$i"; '
                      'rc=$?; printf "%s\\n" "$rc"; [[ $rc == 0 ]] || exit "$rc"; done')
            proc = subprocess.run(['/usr/bin/strace', '-f', '-qq', '-c', '-o', str(trace), str(binary),
                                   '-c', script, '_', str(fixture), str(out)], env=env, capture_output=True, timeout=120)
            valid = proc.returncode == 0 and proc.stdout == b'0\n' * 9 and not proc.stderr
            valid = valid and all((out / str(i)).read_bytes() == expected for i in range(9))
            report['results'][name] = dict(valid=valid, exit_code=proc.returncode,
                                            statuses=proc.stdout.decode(), stderr=proc.stderr.decode(), trace=str(trace))
            assert valid, report['results'][name]
finally:
    a.output.write_text(json.dumps(report, indent=2) + '\n')
