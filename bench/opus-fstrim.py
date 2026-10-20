#!/usr/bin/env python3
"""fstrim -n -I: the bash-os builtin against util-linux fstrim on one fixture.

Both implementations run from the same bash-os shell, inside one private user
and mount namespace, over the same list file. Every pass of every batch is
checked against util-linux's own output and exit status for that fixture,
which is the independent oracle; a mismatch on any pass voids the case.
Only --dry-run is used, so FITRIM is never issued.

Workloads
  historical-left  the bench/loadables.py `fstrim` fixture: 10,000 two-field
                   lines ("000000 left"). Neither implementation accepts a
                   line without a filesystem type, so both print nothing and
                   exit 255. Kept to show what the historical case costs now.
  mounted-list     10,000 fstab lines: 64 name freshly mounted tmpfs
                   instances, the rest name unmounted directories, regular
                   files and missing paths, every target and source distinct.
                   Both print the same 64 lines.

    python3 bench/opus-fstrim.py --binary out/bash-opus-fstrim --cpu 3 \\
        --runs 7 --passes 20 --output report.json
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
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MOUNTS = 64
LINES = 10000


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_fixtures(base):
    """Inside the namespace: mount the tmpfs targets and write both lists."""
    (base / 'left').write_text(''.join(f'{i:06d} left\n' for i in range(10000)))
    root = base / 'root'
    root.mkdir()
    lines = []
    for i in range(LINES):
        kind = 'mounted' if i < MOUNTS else ('dir', 'file', 'missing')[i % 3]
        t = root / f'{kind}{i:05d}'
        if kind in ('mounted', 'dir'):
            t.mkdir()
        if kind == 'mounted':
            subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=64k', 'fixture', str(t)], check=True)
        elif kind == 'file':
            t.write_text('')
        lines.append(f'/dev/fx{i:05d} {t} ext4 defaults 0 2\n')
    # interleave so the mounted entries are spread through the table
    lines = lines[MOUNTS:][:LINES // 2] + lines[:MOUNTS] + lines[MOUNTS:][LINES // 2:]
    (base / 'mounted-list').write_text(''.join(lines))


def batch(binary, command, passes, outdir, cwd):
    """One timed batch; per-pass stdout files and statuses are kept for checking."""
    script = f'''
PATH=
cd {cwd}
s=$EPOCHREALTIME
for ((i = 0; i < {passes}; i++)); do
  {command} > {outdir}/out.$i 2> {outdir}/err.$i
  st[i]=$?
done
e=$EPOCHREALTIME
printf '%s %s\\n' "$s" "$e"
printf '%s\\n' "${{st[@]}}"
'''
    p = subprocess.run([str(binary), '--noprofile', '--norc', '-c', script],
                       capture_output=True, text=True, env={'LC_ALL': 'C'})
    if p.returncode != 0:
        raise SystemExit(f'batch shell failed: {p.stderr}')
    lines = p.stdout.split('\n')
    s, e = (float(x.replace(',', '.')) for x in lines[0].split())
    statuses = [int(x) for x in lines[1:1 + passes]]
    return (e - s) * 1000.0, statuses


def validate(outdir, passes, statuses, want_out, want_err, want_status):
    bad = []
    for i in range(passes):
        out = (outdir / f'out.{i}').read_bytes()
        err = (outdir / f'err.{i}').read_bytes()
        if out != want_out or err != want_err or statuses[i] != want_status:
            bad.append(i)
    return bad


def inner(args):
    base = Path(args.inner)
    os.sched_setaffinity(0, {args.cpu})
    build_fixtures(base)
    ul = args.util_linux
    report = {'cases': []}
    for name in ('historical-left', 'mounted-list'):
        listfile = base / name if name != 'historical-left' else base / 'left'
        rel = listfile.name
        # independent oracle: util-linux run once, outside any timed batch
        ref = subprocess.run([ul, '-n', '-I', rel], cwd=base, capture_output=True)
        want_out, want_err, want_status = ref.stdout, ref.stderr, ref.returncode
        impls = {'builtin': f'fstrim -n -I {rel}', 'util-linux': f'{ul} -n -I {rel}'}
        case = {'workload': name, 'fixture': str(listfile.name), 'fixture_sha256': sha256(listfile),
                'oracle': {'stdout_sha256': hashlib.sha256(want_out).hexdigest(),
                           'stdout_lines': want_out.count(b'\n'), 'stderr': want_err.decode(),
                           'status': want_status},
                'passes': args.passes, 'runs': args.runs, 'samples_ms': {}, 'valid': True,
                'invalid_passes': {}}
        outdir = base / f'out-{name}'
        outdir.mkdir()
        for impl, cmd in impls.items():           # warm-up batch, validated, untimed
            _, st = batch(args.binary, cmd, args.passes, outdir, base)
            if validate(outdir, args.passes, st, want_out, want_err, want_status):
                case['valid'] = False
                case['invalid_passes'][f'{impl}-warmup'] = True
        order = list(impls)
        for r in range(args.runs):
            for impl in (order if r % 2 == 0 else order[::-1]):
                ms, st = batch(args.binary, impls[impl], args.passes, outdir, base)
                bad = validate(outdir, args.passes, st, want_out, want_err, want_status)
                if bad:
                    case['valid'] = False
                    case['invalid_passes'].setdefault(impl, []).append(bad)
                case['samples_ms'].setdefault(impl, []).append(round(ms, 3))
        for impl, xs in case['samples_ms'].items():
            case.setdefault('median_ms', {})[impl] = round(statistics.median(xs), 3)
            case.setdefault('per_call_ms', {})[impl] = round(statistics.median(xs) / args.passes, 4)
        if case['valid']:
            m = case['median_ms']
            case['ratio_builtin_over_util_linux'] = round(m['builtin'] / m['util-linux'], 4)
        report['cases'].append(case)
    print(json.dumps(report))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--util-linux', default=shutil.which('fstrim', path='/usr/sbin:/sbin'))
    ap.add_argument('--cpu', type=int, required=True)
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--passes', type=int, default=20)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--inner', help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.binary = args.binary.resolve()
    if args.inner:
        return inner(args)
    if args.runs < 7:
        raise SystemExit('at least seven samples are required')
    if not args.util_linux:
        raise SystemExit('util-linux fstrim not found')
    base = Path(tempfile.mkdtemp(prefix='opus-fstrim-bench.'))
    try:
        p = subprocess.run(['unshare', '-rm', sys.executable, '-I', str(Path(__file__).resolve()),
                            '--binary', str(args.binary), '--util-linux', args.util_linux,
                            '--cpu', str(args.cpu), '--runs', str(args.runs),
                            '--passes', str(args.passes), '--inner', str(base)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise SystemExit(f'namespace run failed ({p.returncode}): {p.stderr}')
        report = json.loads(p.stdout)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    ver = subprocess.run([args.util_linux, '--version'], capture_output=True, text=True).stdout.strip()
    report['environment'] = {
        'binary': str(args.binary), 'binary_sha256': sha256(args.binary),
        'source_sha256': sha256(ROOT / 'loadables/fstrim.c'),
        'source_commit': subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                        capture_output=True, text=True).stdout.strip(),
        'source_dirty': bool(subprocess.run(['git', '-C', str(ROOT), 'status', '--porcelain',
                                             'loadables/fstrim.c'], capture_output=True,
                                            text=True).stdout.strip()),
        'util_linux': args.util_linux, 'util_linux_version': ver,
        'util_linux_sha256': sha256(args.util_linux),
        'kernel': platform.release(), 'machine': platform.machine(), 'cpu': args.cpu,
        'python': platform.python_version(), 'method': 'one bash-os shell per batch; '
        'EPOCHREALTIME around the pass loop; alternating implementation order per run; '
        'one validated warm-up batch per implementation',
        'work': {'historical-left': '10,000 two-field lines read and rejected; no output; status 255',
                 'mounted-list': f'{LINES:,} fstab lines parsed; each entry statfs, access, stat '
                 f'and parent stat checked; {MOUNTS} mounted entries pass and are opened and '
                 f'printed in reverse order ({MOUNTS} lines)'},
    }
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text)
    return 0 if all(c['valid'] for c in report['cases']) else 1


if __name__ == '__main__':
    sys.exit(main())
