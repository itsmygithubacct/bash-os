#!/usr/bin/env python3
"""Repeated nl work with independent byte oracles and per-pass validation.

Run through the campaign bench gate. Does not compile. Source/binary hashes,
CPU affinity, fixtures, statuses, sample distributions and versions go to JSON.
"""
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
p.add_argument('--output', required=True)
p.add_argument('--module')
p.add_argument('--passes', type=int, default=48)
p.add_argument('--runs', type=int, default=7)
p.add_argument('--source', default='loadables/nl.c')
a = p.parse_args()
assert a.passes >= 3 and a.runs >= 7
binary = str(Path(a.binary).resolve())
module = str(Path(a.module).resolve()) if a.module else None
env = dict(os.environ, LC_ALL='C', PATH='')
sha = lambda data: hashlib.sha256(data).hexdigest()
rng = random.Random(20260908)
words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
text = ''.join(' '.join(rng.choice(words) for _ in range(10)) + '\n' for _ in range(12000)).encode()[:423000]
regex = b''.join(f'item-{n:06d} '.encode() + (b'alpha:12345:alpha' if n % 3 == 0 else b'beta:00000:gamma') + b' tail\n' for n in range(16000))
# These oracles do not invoke nl or reuse its implementation.
def numbered(data, predicate):
    out = bytearray()
    count = 0
    for line in data.splitlines(keepends=True):
        content = line.rstrip(b'\n')
        if predicate(content):
            count += 1
            out.extend(f'{count:6d}\t'.encode())
        else:
            out.extend(b' ' * 7)
        out.extend(content + b'\n')
    return bytes(out)

workloads = [('all', ['-ba'], text, numbered(text, lambda _: True), 0, ''),
             ('regex', [r'-bp^item-[0-9]\{6\} \([a-z]*\):[0-9]\{5\}:\1 tail$'], regex,
              numbered(regex, lambda line: b'alpha:12345:alpha' in line), 0, ''),
             ('invalid-regex', ['-bp['], b'x\n', b'', 1, ''),
             ('write-error', ['-ba'], text, b'', 1, ' > /dev/full')]
report = dict(method='one warm-up plus alternating order; every pass output/status checked outside measured interval',
              passes=a.passes, runs=a.runs, affinity=sorted(os.sched_getaffinity(0)),
              environment={k: env[k] for k in ('LC_ALL', 'PATH')},
              platform=platform.platform(), cpu=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), ''),
              source_sha256=sha(Path(a.source).read_bytes()),
              harness_sha256=sha(Path(__file__).read_bytes()),
              binary_sha256=sha(Path(binary).read_bytes()),
              module_sha256=sha(Path(module).read_bytes()) if module else None,
              fallback_source_sha256=sha(Path('loadables/common/nl-regex.h').read_bytes()),
              libc=platform.libc_ver(), load_average=os.getloadavg(),
              reference_sha256=sha(Path('/usr/bin/nl').read_bytes()),
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              binary_version=subprocess.check_output([binary, '--version'], env=env).decode().splitlines()[0],
              reference_version=subprocess.check_output(['/usr/bin/nl', '--version'], env=env).decode().splitlines()[0], cases=[])
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for name, opts, data, expected, status, redirect in workloads:
        fixture = root / 'input'
        fixture.write_bytes(data)
        case = dict(name=name, kind='compared' if status == 0 else 'self', options=opts,
                    work_unit=f'{a.passes} fresh redirected invocations per sample', fixture_sha256=sha(data), input_bytes=len(data),
                    input_records=data.count(b'\n'), expected_sha256=sha(expected),
                    expected_bytes=len(expected), expected_status=status,
                    reset='fresh stdin redirect and separate stdout/stderr/status files on every invocation', results={})
        values = {key: [] for key in ('builtin','gnu')}
        for round_number in range(-1, a.runs):
            for key in (('builtin','gnu') if round_number % 2 else ('gnu','builtin')):
                command = 'nl' if key == 'builtin' else '/usr/bin/nl'
                invocation = shlex.join([command, *opts])
                script = ('[[ $(type -t nl) == builtin ]] || exit 97\n' if key == 'builtin' else '')
                if key == 'builtin' and module:
                    script = shlex.join(['enable', '-f', module, 'nl']) + ' || exit 96\n' + script
                script += f'for ((i=0;i<{a.passes};i++)); do\n'
                script += f'{invocation} < "$1/input" > "$1/out.$i" 2> "$1/err.$i"{redirect}\n'
                script += 'rc=$?; printf "%s\\n" "$rc" > "$1/rc.$i"\ndone\n'
                started = time.perf_counter_ns()
                result = subprocess.run([binary, '--noprofile','--norc','-c',script,'_',str(root)],
                                        capture_output=True, env=env, timeout=120)
                elapsed = (time.perf_counter_ns()-started)/1e6
                assert result.returncode == 0 and not result.stdout and not result.stderr, result
                for i in range(a.passes):
                    got_status = int((root/f'rc.{i}').read_text())
                    got = (root/f'out.{i}').read_bytes()
                    error = (root/f'err.{i}').read_bytes()
                    assert (got_status, got) == (status, expected), (name,key,i,got_status,sha(got))
                    assert bool(error) == bool(status), (name,key,i,error)
                    for stem in ('rc','out','err'):
                        (root/f'{stem}.{i}').unlink()
                if round_number >= 0:
                    values[key].append(elapsed)
        for key, samples in values.items():
            case['results'][key] = dict(status='ok', validated_passes=a.passes*(a.runs+1),
                                        samples_ms=samples, median_ms=statistics.median(samples),
                                        min_ms=min(samples), max_ms=max(samples))
        case['builtin_over_gnu'] = (statistics.median(values['builtin']) / statistics.median(values['gnu'])
                                    if status == 0 else None)
        if status:
            case['limits'] = ['Failure paths stop at implementation-dependent positions; timings are individual self measurements, with no external ratio.']
        report['cases'].append(case)
        print(name, json.dumps(case['results']), flush=True)
Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
