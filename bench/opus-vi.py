#!/usr/bin/env python3
"""Time vi's G + dd deletion workload and its full save, validating every pass.

Same method as bench/loadables.py (one bash-os shell per batch, the builtin
called `passes` times in a loop, median batch wall time, warm file cache,
empty PATH, fixed CPU), with two differences that make every timed pass
checkable: each pass writes its own output file (`out.N`), and every one of
those files is compared with an expected value computed here in Python, not
taken from either implementation. A binary or reference whose output does
not match is reported as `output-mismatch` and is not timed, so a no-op
cannot be measured as a fast edit.

Cases
  vi-gdd        1,000-line / 45,000-byte file: G, then 250 dd (each deleting
                the current last line), then :w of the remaining 750 lines.
  vi-gdd-large  The 1.68 MB / 120,000-line `duplicates` file: G, 250 dd,
                then :w of the remaining 119,750 lines.
  vi-write      `duplicates` loaded and saved unchanged (the historical
                vi-write work unit: piece-table load + full 1.68 MB save).

usage: bench/opus-vi.py --binary out/bash-X [--binary ...] --output R.json
       [--cpu N] [--runs 7] [--passes N] [--no-reference]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = '/usr/local/bin:/usr/bin:/bin'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixtures(root):
    small = [b'line %04d %s\n' % (i, sha(b'%d' % i)[:32].encode()) for i in range(1000)]
    (root / 'small').write_bytes(b''.join(small))
    dup = [f'{i//3:08d} word\n'.encode() for i in range(120000)]
    (root / 'duplicates').write_bytes(b''.join(dup))
    return {
        'vi-gdd': ('small', b'G' + b'dd' * 250, b''.join(small[:750]), 250),
        'vi-gdd-large': ('duplicates', b'G' + b'dd' * 250, b''.join(dup[:-250]), 250),
        'vi-write': ('duplicates', None, b''.join(dup), 0),
    }


def commands(kind, case, fixture, keys):
    """Shell loop body for one pass; `$i` is the pass index."""
    if kind == 'bashos':
        if keys is None:
            return f'vi -c "w out.$i" -c "q!" {fixture}'
        return f'vi --keys keys.$i {fixture}'
    # nvim: same keystrokes from a script file, or the same ex commands.
    base = ('"$NVIM" --headless -u NONE -i NONE -n -c "set nofixeol sol"')
    if keys is None:
        return f'{base} -c "w! out.$i" -c "q!" {fixture}'
    return f'{base} -s nkeys.$i {fixture}'


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', type=Path, action='append', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--passes', type=int)
    ap.add_argument('--only')
    ap.add_argument('--no-reference', action='store_true')
    args = ap.parse_args()
    if args.runs < 7:
        ap.error('--runs must be at least 7')
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})
    nvim = None if args.no_reference else shutil.which('nvim', path=HOST_PATH)
    binaries = [b.resolve(strict=True) for b in args.binary]
    report = {
        'schema': 1, 'harness': 'bench/opus-vi.py',
        'date': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                 cwd=ROOT, text=True).strip(),
        'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'],
                                                     cwd=ROOT, text=True).strip()),
        'vi_c_sha256': sha((ROOT / 'loadables/vi.c').read_bytes()),
        'kernel': platform.release(), 'architecture': platform.machine(),
        'cpus': sorted(os.sched_getaffinity(0)), 'load_average_start': os.getloadavg(),
        'runs': args.runs,
        'method': 'One bash-os shell per batch, `passes` invocations in a loop; '
                  'median batch wall time; stdout/stderr discarded; warm file cache; '
                  'every pass writes out.N and every out.N is checked against a '
                  'Python-computed expected value after every batch',
        'implementations': {}, 'cases': [],
    }
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name'):
            report['cpu_model'] = line.split(':', 1)[1].strip()
            break
    impls = {}
    for b in binaries:
        label = b.name
        impls[label] = ('bashos', b)
        report['implementations'][label] = {
            'path': str(b), 'sha256': sha(b.read_bytes()),
            'version': subprocess.run([str(b), '--version'], capture_output=True,
                                      text=True).stdout.splitlines()[0]}
    if nvim:
        impls['nvim'] = ('nvim', Path(nvim))
        report['implementations']['nvim'] = {
            'path': nvim, 'sha256': sha(Path(nvim).read_bytes()),
            'version': subprocess.run([nvim, '--version'], capture_output=True,
                                      text=True).stdout.splitlines()[0],
            'options': '-u NONE -i NONE -n --headless, set nofixeol sol'}
    else:
        report['implementations']['nvim'] = {'status': 'unavailable'}

    with tempfile.TemporaryDirectory(prefix='opus-vi-bench-') as tmp:
        root = Path(tmp)
        cases = fixtures(root)
        report['fixtures'] = {name: {'sha256': sha((root / name).read_bytes()),
                                     'bytes': (root / name).stat().st_size}
                              for name in ['small', 'duplicates']}
        selected = args.only.split(',') if args.only else list(cases)
        shell = binaries[0]

        def prepare(case, keys, passes):
            for f in root.glob('out.*'):
                f.unlink()
            if keys is None:
                return
            for i in range(passes):
                (root / f'keys.{i}').write_bytes(keys + b':w out.%d\r:q!\r' % i)
                (root / f'nkeys.{i}').write_bytes(keys + b':w! out.%d\r:q!\r' % i)

        def batch(kind, binary, case, fixture, keys, passes):
            body = commands(kind, case, fixture, keys)
            script = f'for ((i=0;i<{passes};i++)); do {body} || exit; done'
            runner = binary if kind == 'bashos' else shell
            env = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb', 'HOME': tmp}
            if kind == 'nvim':
                env['NVIM'] = str(binary)
            argv = [str(runner), '--noprofile', '--norc', '-c', script]
            start = time.perf_counter_ns()
            p = subprocess.run(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               timeout=600)
            ms = (time.perf_counter_ns() - start) / 1e6
            return p.returncode, ms, p.stderr[-1000:].decode(errors='replace')

        def validate(want, passes):
            bad = []
            for i in range(passes):
                f = root / f'out.{i}'
                got = f.read_bytes() if f.exists() else None
                if got != want:
                    bad.append({'pass': i, 'bytes': None if got is None else len(got),
                                'sha256': None if got is None else sha(got)})
            return bad

        for name in selected:
            fixture, keys, want, deletes = cases[name]
            row = {'id': name, 'fixture': fixture,
                   'fixture_sha256': report['fixtures'][fixture]['sha256'],
                   'keys_sha256': sha(keys) if keys else None,
                   'actual_deletes_per_pass': deletes,
                   'expected_bytes': len(want), 'expected_sha256': sha(want),
                   'expected_lines': want.count(b'\n'), 'results': {}}
            for label, (kind, binary) in impls.items():
                # Probe for calibration (one pass) and correctness.
                prepare(name, keys, 1)
                rc, ms, err = batch(kind, binary, name, fixture, keys, 1)
                bad = validate(want, 1)
                if rc or bad:
                    row['results'][label] = {'status': 'error' if rc else 'output-mismatch',
                                             'returncode': rc, 'stderr': err, 'mismatches': bad}
                    continue
                passes = args.passes or max(3, min(50, int(150 / max(ms, 0.1))))
                prepare(name, keys, passes)
                # Warm-up batch, validated like every timed batch.
                rc, _, err = batch(kind, binary, name, fixture, keys, passes)
                bad = validate(want, passes)
                if rc or bad:
                    row['results'][label] = {'status': 'batch-mismatch', 'returncode': rc,
                                             'stderr': err, 'mismatches': bad[:5]}
                    continue
                samples = []
                failure = None
                for _ in range(args.runs):
                    prepare(name, keys, passes)
                    rc, ms, err = batch(kind, binary, name, fixture, keys, passes)
                    bad = validate(want, passes)
                    if rc or bad:
                        failure = {'status': 'timed-batch-mismatch', 'returncode': rc,
                                   'stderr': err, 'mismatches': bad[:5]}
                        break
                    samples.append(round(ms, 3))
                if failure:
                    row['results'][label] = failure
                    continue
                med = statistics.median(samples)
                row['results'][label] = {
                    'status': 'ok', 'passes': passes, 'validated_passes': passes * (args.runs + 1),
                    'median_ms': round(med, 3), 'min_ms': min(samples), 'max_ms': max(samples),
                    'per_pass_median_ms': round(med / passes, 4), 'runs_ms': samples}
            report['cases'].append(row)
            print(name + ': ' + ', '.join(
                f"{k}={v.get('per_pass_median_ms', v['status'])}"
                for k, v in row['results'].items()), flush=True)
    report['load_average_end'] = os.getloadavg()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
