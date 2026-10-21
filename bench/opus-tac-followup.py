#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tac before/after/GNU: literal and regex size scaling and per-process
peak RSS, with exact GNU bytes and status checked on every sample."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import tempfile
import time

GNU = '/usr/bin/tac'


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def fixtures(size):
    unit = b'alpha 0123456789\nbeta 9876543210\n'
    text = (unit * (size // len(unit) + 1))[:size]
    huge = b'A' * (size // 2) + b'\n' + b'B' * (size - size // 2 - 1)
    unit = b'alpha,beta::gamma,tail\n'
    fields = (unit * (size // len(unit) + 1))[:size]
    return text, huge, fields


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--before', type=Path, required=True, help='Earlier build of the same selection')
    p.add_argument('--after', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True, help='tac.c of the after build')
    p.add_argument('--before-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--runs', type=int, default=7)
    p.add_argument('--sizes', default='1,4,16', help='MiB')
    p.add_argument('--rusage-tool', type=Path, required=True,
                   help='bench/sol-tac-rusage.c, built separately through the build gate')
    a = p.parse_args()
    assert a.runs >= 7
    assert len(os.sched_getaffinity(0)) == 1, 'Use the campaign bench gate'
    builds = {'before': str(a.before.resolve()), 'after': str(a.after.resolve())}
    monitor = str(a.rusage_tool.resolve())
    env = dict(PATH='', LC_ALL='C', TZ='UTC', TERM='dumb')
    manifests = {k: json.loads(Path(v + '.manifest.json').read_text()) for k, v in builds.items()}
    for key in ['names', 'target', 'static', 'stripped', 'helpers', 'libraries']:
        assert manifests['before'][key] == manifests['after'][key], ('unmatched builds', key)
    report = dict(
        date_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        binaries={k: dict(path=v, sha256=digest(v), manifest=manifests[k],
                          shell_version=subprocess.check_output([v, '--version'], text=True).splitlines()[0])
                  for k, v in builds.items()},
        source_sha256=dict(after=digest(a.source), before=digest(a.before_source)),
        driver_sha256=digest(__file__), rusage_tool_sha256=digest(monitor),
        cpu_affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
        libc=platform.libc_ver(), python=platform.python_version(),
        cpu_model=next(l.split(':', 1)[1].strip() for l in
                       Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),
        gnu_version=subprocess.check_output([GNU, '--version'], text=True).splitlines()[0],
        gnu_sha256=digest(GNU), load_start=os.getloadavg(), env=env, samples=a.runs, cases=[],
        method=('One warm-up, then seven samples per implementation, interleaved with the order '
                'rotated each round. Fresh shell per sample; warm page cache; output to an owned '
                'file whose size and SHA-256 must equal GNU\'s output for the same pass count. '
                'Peak RSS is the largest single process in the waited-for tree (wait4), not a sum. '
                'Wall time includes the wait4 launcher, shell startup, the producer for pipe cases '
                'and output file writes; hashing is outside the timed interval.'))
    cases = []
    for mib in [int(x) for x in a.sizes.split(',')]:
        text, huge, fields = fixtures(mib * 1024 * 1024)
        report.setdefault('fixtures', {})[f'{mib}M'] = {
            'text': hashlib.sha256(text).hexdigest(), 'huge': hashlib.sha256(huge).hexdigest(),
            'fields': hashlib.sha256(fields).hexdigest()}
        cases += [(f'{name}-{mib}M', mib, kind, options, shape) for name, kind, options, shape in [
            ('literal', 'text', [], 'file'),
            ('huge-record-file', 'huge', [], 'file'),
            ('huge-record-pipe', 'huge', [], 'pipe'),
            ('regex-atom', 'fields', ['-r', '-s', '[,:]+'], 'file'),
            ('regex-general-nomatch-file', 'huge', ['-r', '-s', 'BEGIN.*END'], 'file'),
            ('regex-general-nomatch-pipe', 'huge', ['-r', '-s', 'BEGIN.*END'], 'pipe'),
            ('regex-alternation-dense', 'fields', ['-r', '-s', ',\\|::'], 'file'),
            ('regex-anchored', 'text', ['-r', '-s', '^beta'], 'file'),
            ('regex-plain', 'fields', ['-r', '-s', '::'], 'file'),
            ('regex-backref-dense', 'fields', ['-r', '-s', '\\(:\\)\\1'], 'file'),
            ('regex-backref-nomatch', 'huge', ['-r', '-s', '\\(B\\)\\1Q'], 'file')]]
    with tempfile.TemporaryDirectory(prefix='opus-tac-bench-') as d:
        root = Path(d)
        fixture, expected, output, rss = [root / n for n in ['input', 'expected', 'output', 'rss']]
        for name, mib, kind, options, shape in cases:
            data = fixtures(mib * 1024 * 1024)[['text', 'huge', 'fields'].index(kind)]
            fixture.write_bytes(data)
            with expected.open('wb') as f:
                subprocess.run([GNU, *options, str(fixture)], env=env, stdout=f, check=True)
            expected_hash, expected_size = digest(expected), expected.stat().st_size
            row = dict(id=name, bytes=len(data), fixture=kind, options=options, input_kind=shape,
                       passes=1, fixture_sha256=hashlib.sha256(data).hexdigest(),
                       expected_sha256=expected_hash, results={})
            if shape == 'file':
                script = 'input=$1; shift; "$@" "$input"'
            else:
                # One owned /bin/cat producer for every implementation.
                script = 'set -o pipefail; input=$1; shift; /bin/cat "$input" | "$@"'
            tools = {'before': (builds['before'], ['tac', *options]),
                     'after': (builds['after'], ['tac', *options]),
                     # GNU runs from the after shell, as an external command.
                     'gnu': (builds['after'], [GNU, *options])}

            def sample(label):
                shell, command = tools[label]
                rss.unlink(missing_ok=True)
                with output.open('wb') as out:
                    start = time.perf_counter_ns()
                    proc = subprocess.Popen([monitor, str(rss), shell, '--noprofile', '--norc', '-c',
                                             script, '_', str(fixture), *command],
                                            env=env, stdout=out, stderr=subprocess.PIPE, process_group=0)
                    timed_out = False
                    try:
                        _, stderr = proc.communicate(timeout=180)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        _, stderr = proc.communicate()
                        timed_out = True
                    ms = (time.perf_counter_ns() - start) / 1e6
                counters = json.loads(rss.read_text()) if rss.exists() else {'peak_rss_kib': 0}
                valid = (not timed_out and proc.returncode == 0
                         and output.stat().st_size == expected_size and digest(output) == expected_hash)
                return dict(valid=valid, exit_code=124 if timed_out else proc.returncode, ms=ms,
                            **counters, stdout_sha256=digest(output),
                            stderr=stderr.decode(errors='replace')[:400])

            accepted = []
            for label in tools:
                warmup = sample(label)
                row['results'][label] = dict(status='ok' if warmup['valid'] else 'invalid',
                                             warmup=warmup, samples=[])
                if warmup['valid']:
                    accepted.append(label)
            for i in range(a.runs):
                order = accepted[i % len(accepted):] + accepted[:i % len(accepted)] if accepted else []
                if i % 2:
                    order.reverse()
                for label in order:
                    s = sample(label)
                    row['results'][label]['samples'].append(s)
                    if not s['valid']:
                        row['results'][label]['status'] = 'invalid'
            for r in row['results'].values():
                if r['samples']:
                    times = [s['ms'] for s in r['samples']]
                    r.update(median_ms=statistics.median(times), min_ms=min(times), max_ms=max(times),
                             max_rss_kib=max(s['peak_rss_kib'] for s in r['samples']),
                             median_user_ms=statistics.median(s['user_ms'] for s in r['samples']))
            report['cases'].append(row)
            report['load_end'] = os.getloadavg()
            a.output.write_text(json.dumps(report, indent=2) + '\n')
            print(name, {k: (v['status'], round(v.get('median_ms', 0), 2), v.get('max_rss_kib'))
                         for k, v in row['results'].items()}, flush=True)
    assert all(row['results']['gnu']['status'] == 'ok' for row in report['cases'])


if __name__ == '__main__':
    main()
