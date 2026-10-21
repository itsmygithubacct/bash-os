#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""clip workloads at several region sizes, every pass byte-validated.

    bench/sol-clip.py --binary before=PATH --binary after=PATH --cpu 11 \
        --runs 7 --output REPORT.json

Each sample is one fresh shell running one batch: untimed setup, then the
timed loop measured with $EPOCHREALTIME inside the shell (process start and
setup excluded), then untimed validation. Batches for the given binaries are
interleaved, one discarded warmup each. Every pass must succeed, and its
output (or its effect on the buffer) is compared byte for byte with an oracle
built here from the fixture, for the warmup and every sample.

The `text` fixture is generated exactly as bench/loadables.py generates its
catalog `text` fixture (423,000 bytes, 8,062 lines, no final newline); its
SHA-256 is recorded. `head -n K` from the same shell is the matched reference
for text output: identical output bytes, but a fork/exec and file read per
pass. All other workloads are self timings with no external ratio."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def catalog_text():
    rng = random.Random(20260908)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
    return ''.join(' '.join(rng.choice(words) for _ in range(10)) + '\n'
                   for _ in range(12000)).encode()[:423000]


def large_text():
    rng = random.Random(20261020)
    words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of', 'été', '\U0001f600']
    return '\n'.join(' '.join(rng.choice(words) for _ in range(rng.randrange(1, 14)))
                     for _ in range(65536)).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', action='append', required=True, help='LABEL=PATH; repeatable')
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--only', help='comma-separated case-name prefixes')
    ap.add_argument('--exclude', help='comma-separated case-name prefixes to skip')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.runs < 7:
        sys.exit('at least seven samples are required')
    binaries = {}
    for spec in args.binary:
        label, _, path = spec.partition('=')
        binaries[label] = Path(path).resolve()
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})     # inherited by every shell
    head = shutil.which('head', path='/usr/bin:/bin')

    with tempfile.TemporaryDirectory(prefix='sol-clip-bench-') as td:
        d = Path(td)
        fx = {'text': catalog_text(), 'large': large_text(), 'oneline': b'Z' * (4 << 20)}
        for name, data in fx.items():
            (d / name).write_bytes(data)
        lines = {name: data.split(b'\n') for name, data in fx.items()}
        out = d / 'out'

        def entry_bytes(name, k):
            return b''.join(x + b'\n' for x in lines[name][:k])

        cases = []
        # (fixture, region lines, passes): region sizes from one line to the whole file.
        sizes = [('text', 1, 64), ('text', 100, 64), ('text', 4000, 19), ('text', 8062, 19),
                 ('large', 65536, 7), ('oneline', 1, 7)]
        for name, k, r in sizes:
            nbytes = len(entry_bytes(name, k))
            tag = f'{name}-{k}'
            load = f'buf new -h B; buf load "$B" {name}\n'
            realize = f'buf insert-line "$B" 0 x; buf delete-line "$B" 0; buf clean "$B"\n'
            cases.append(dict(
                name=f'text-{tag}', kind='compared', reference='head',
                work=f'{r} x clip text of a {k}-line / {nbytes}-byte entry to a file',
                setup=load + realize + f'clip new -h C; clip copy-range "$C" "$B" 0 {k}\nexec 3>out\n',
                loop=f'clip text "$C" -F 3 || exit 7',
                ref_loop=f'{head} -n {k} {name} >&3 || exit 7',
                passes=r, expect=lambda name=name, k=k, r=r: entry_bytes(name, k) * r,
                check='exec 3>&-\n'))
            for state, pre in (('paged', ''), ('realized', realize)):
                rr = 16    # each pass's entry is still in the 16-slot ring for validation
                cases.append(dict(
                    name=f'copy-{state}-{tag}', kind='self',
                    work=f'{rr} x clip copy-range of {k} lines / {nbytes} bytes from a {state} buffer',
                    setup=load + pre + 'clip new -h C\n',
                    loop=f'clip copy-range "$C" "$B" 0 {k} || exit 7',
                    passes=rr, expect=lambda name=name, k=k: entry_bytes(name, k) * 16,
                    check='exec 3>out; for s in {0..15}; do clip text "$C" -N $s -F 3 || exit 8; done; exec 3>&-\n'))
            n = len(lines[name])
            rr = 7
            cases.append(dict(
                name=f'paste-append-{tag}', kind='self',
                work=f'{rr} x clip paste of {k} lines / {nbytes} bytes appended to a realized buffer',
                setup=load + realize + f'clip new -h C; clip copy-range "$C" "$B" 0 {k}; n={n}\n',
                loop=f'clip paste "$C" "$B" $n || exit 7; ((n += {k}))',
                passes=rr,
                expect=lambda name=name, k=k: b'\n'.join(lines[name] + lines[name][:k] * 7),
                check='buf text "$B" -F 3 3>out || exit 8\n'))
            mid = min(n - 1, k // 2)
            col = len(lines[name][mid]) // 2
            def col_expect(name=name, k=k, mid=mid, col=col):
                L = list(lines[name])
                e = L[:k]
                for _ in range(7):
                    pre, tail = L[mid][:col], L[mid][col:]
                    new = [pre + e[0] + tail] if len(e) == 1 else [pre + e[0]] + e[1:-1] + [e[-1] + tail]
                    L[mid:mid + 1] = new
                return b'\n'.join(L)
            cases.append(dict(
                name=f'paste-col-{tag}', kind='self',
                work=f'{rr} x clip paste of {k} lines / {nbytes} bytes at byte {col} of line {mid}',
                setup=load + realize + f'clip new -h C; clip copy-range "$C" "$B" 0 {k}\n',
                loop=f'clip paste "$C" "$B" {mid} {col} || exit 7',
                passes=rr, expect=col_expect,
                check='buf text "$B" -F 3 3>out || exit 8\n'))
            cases.append(dict(
                name=f'cut-paste-{tag}', kind='self',
                work=f'{rr} x (clip cut-range of {k} lines from line 0, clip paste back at 0)',
                setup=load + realize + 'clip new -h C\n',
                loop=f'clip cut-range "$C" "$B" 0 {k} || exit 7; clip paste "$C" "$B" 0 || exit 7',
                passes=rr, expect=lambda name=name: fx[name],
                check='buf text "$B" -F 3 3>out || exit 8\n'))
        if args.only:
            prefixes = args.only.split(',')
            cases = [c for c in cases if any(c['name'].startswith(p) for p in prefixes)]
        if args.exclude:
            prefixes = args.exclude.split(',')
            cases = [c for c in cases if not any(c['name'].startswith(p) for p in prefixes)]

        def batch(binary, case, loop):
            script = ('PATH=\nset -e\n' + case['setup'] + 'set +e\n'
                      f't0=$EPOCHREALTIME\nfor ((i = 0; i < {case["passes"]}; i++)); do {loop}; done\n'
                      't1=$EPOCHREALTIME\nset -e\n' + case['check'] +
                      'echo "${t0/./} ${t1/./}"\n')
            if out.exists():
                out.unlink()
            p = subprocess.run([str(binary), '-c', script], cwd=d, capture_output=True, timeout=600)
            data = out.read_bytes() if out.exists() else b''
            want = case['expect']()
            ok = p.returncode == 0 and data == want
            ms = None
            if ok:
                t0, t1 = map(int, p.stdout.split())
                ms = (t1 - t0) / 1000
            return dict(ok=ok, ms=ms, exit=p.returncode, bytes=len(data), stderr=p.stderr[-400:].decode('replace'))

        report = dict(
            method='in-shell $EPOCHREALTIME around the timed loop; setup and validation untimed; '
                   'one discarded warmup per case and binary; batches interleaved across binaries',
            runs=args.runs, cpu=args.cpu, kernel=platform.release(), machine=platform.machine(),
            python=platform.python_version(),
            head=subprocess.run([head, '--version'], capture_output=True, text=True).stdout.splitlines()[0],
            binaries={k: dict(path=str(v), sha256=sha(v.read_bytes())) for k, v in binaries.items()},
            fixtures={k: dict(bytes=len(v), lines=len(lines[k]), sha256=sha(v)) for k, v in fx.items()},
            cases=[])
        for case in cases:
            row = dict(name=case['name'], kind=case['kind'], work=case['work'], passes=case['passes'],
                       validated_bytes_per_batch=len(case['expect']()), results={})
            columns = {label: (path, case['loop']) for label, path in binaries.items()}
            if case.get('reference'):
                first = next(iter(binaries.values()))
                columns['head'] = (first, case['ref_loop'])
            for label, (path, loop) in columns.items():
                row['results'][label] = dict(warmup=batch(path, case, loop), samples=[])
            for _ in range(args.runs):
                for label, (path, loop) in columns.items():
                    row['results'][label]['samples'].append(batch(path, case, loop))
            for label, res in row['results'].items():
                good = res['warmup']['ok'] and all(s['ok'] for s in res['samples'])
                ms = [s['ms'] for s in res['samples'] if s['ok']]
                res['status'] = 'ok' if good else 'invalid'
                res['samples_ms'] = ms
                if good:
                    res.update(median_ms=statistics.median(ms), min_ms=min(ms), max_ms=max(ms))
                else:
                    bad = [s for s in [res['warmup']] + res['samples'] if not s['ok']][0]
                    res['first_failure'] = bad
                del res['samples']
            line = f"{case['name']:28}"
            for label, res in row['results'].items():
                line += f"  {label}={res.get('median_ms', float('nan')):9.3f}ms[{res['status']}]"
            print(line, flush=True)
            report['cases'].append(row)
        args.output.write_text(json.dumps(report, indent=1) + '\n')
        bad = [c['name'] for c in report['cases'] for r in c['results'].values() if r['status'] != 'ok']
        print(f'sol-clip bench: {len(report["cases"])} cases; invalid={bad}')
        return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
