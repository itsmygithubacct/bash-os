#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Time `index read` and `index --index-info` against host git, on indexes git wrote.

Every fixture is written by the host git itself (`git update-index
--index-info`, version 2), so the comparison runs on exact git indexes:

  small    100 entries
  large    20000 entries, the paths and ids of bench/loadables.py's
           index-read fixture. That harness writes them in the order it
           generates them, which is not path order (dir000/file-00256
           follows dir255/file-00255), and the index format requires path
           order; the builtin refuses that file, and git, which does not
           check order on a read, lists it. The file here is checked to be
           byte-identical to the same entries sorted, which is what git
           writes. The unsorted file's refusal is recorded, untimed.
  xlarge   110000 entries, past the 8 MiB checksum snapshot, so every read
           verifies the trailer

`index read` is timed warm (the same file every pass, so after the first
the trailer check is a comparison with the verified snapshot) and cold
(alternating between two files of the same size that differ in one id, so
every pass computes the SHA-1). The reference is `git ls-files --stage`,
which does not verify the trailer at all. `index --index-info` is timed on
the large fixture's 20000 records against `git update-index --index-info`,
both writing a new index each pass; the two files must be byte-identical.

Each case first runs a validation batch whose every pass is checked
against the git oracle (output bytes, or the written index) and exit
status, then a discarded warm-up batch, then RUNS timed batches of PASSES
invocations in one bash-os shell pinned to one CPU. Every warm-up and timed
pass retains its output or index for exact oracle validation; any bad status
or output invalidates the report. Times include capture to owned regular
files and are batch wall times from $EPOCHREALTIME. Validation is outside
the timed interval. Cold alternation continues across batch boundaries.

usage: bench/sol-index.py --binary out/bash --output report.json
       [--cpu N] [--runs 7] [--passes 5]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument('--binary', default='out/bash')
parser.add_argument('--output', required=True)
parser.add_argument('--cpu', type=int, default=None)
parser.add_argument('--runs', type=int, default=7)
parser.add_argument('--passes', type=int, default=5)
parser.add_argument('--only', default='', help='comma-separated case ids')
args = parser.parse_args()
assert args.runs >= 7, 'at least seven timed samples'
BINARY = Path(args.binary).resolve()
GIT = shutil.which('git')
TASKSET = shutil.which('taskset')
assert GIT, 'host git is required'
q = shlex.quote


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(root, *argv, data=None, index=None):
    env = {**os.environ, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    if index is not None:
        env['GIT_INDEX_FILE'] = str(index)
    r = subprocess.run([GIT, '-C', str(root), '-c', 'index.version=2', *argv], input=data,
                       capture_output=True, env=env, check=True)
    return r.stdout


def historical(count=20000, ordered=False):
    """bench/loadables.py's build_indexrepo, in its order or in path order."""
    entries = []
    for i in range(count):
        path = ('dir%03d/file-%05d.txt' % (i % 256, i)).encode()
        sha = hashlib.sha1(b'entry %d' % i).digest()
        entry = struct.pack('>10I', 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 0)
        entry += sha+struct.pack('>H', len(path))+path+b'\0'
        while len(entry) % 8:
            entry += b'\0'
        entries.append((path, entry))
    if ordered:
        entries.sort()
    body = b'DIRC'+struct.pack('>II', 2, count)+b''.join(e for _, e in entries)
    return body+hashlib.sha1(body).digest()


def records(count, salt=b''):
    out = []
    for i in range(count):
        path = b'dir%03d/file-%05d.txt' % (i % 256, i) if count == 20000 else b'd%03d/f-%06d.txt' % (i % 251, i)
        sha = hashlib.sha1(b'entry %d' % i if count == 20000 else b'e%d' % i).hexdigest().encode()
        if salt and i == count // 2:
            sha = hashlib.sha1(salt).hexdigest().encode()
        out.append(b'100644 '+sha+b'\t'+path+b'\n')
    return b''.join(out)


def oracle_listing(root, index):
    out = git(root, 'ls-files', '--stage', '-z', index=index)
    lines = []
    for rec in out.split(b'\0')[:-1]:
        meta, path = rec.split(b'\t', 1)
        lines.append(meta+b' '+path+b'\n')
    return b''.join(lines)


def run_shell(script, cwd):
    cmd = [str(BINARY), '--noprofile', '--norc', '-c', script]
    if args.cpu is not None and TASKSET:
        cmd = [TASKSET, '-c', str(args.cpu)]+cmd
    env = {k: v for k, v in os.environ.items() if k != 'GIT_INDEX_FILE'}
    env.update(LC_ALL='C', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, env=env, timeout=3600)
    if r.returncode != 0:
        raise SystemExit(f'shell failed ({r.returncode}): {r.stderr.decode(errors="replace")[:2000]}')
    return r.stdout.decode()


def batch_script(body, passes, runs, setup=''):
    """Warm-up batch, then RUNS timed batches of PASSES; prints ms per batch."""
    return (f'{setup}\nPATH=\nfail=0\ni=0\n'
            f'for ((w=0; w<{passes}; w++, i++)); do {body} || fail=1; done\n'
            f'for ((r=0; r<{runs}; r++)); do\n'
            f'  t0=$EPOCHREALTIME\n'
            f'  for ((j=0; j<{passes}; j++, i++)); do {body} || fail=1; done\n'
            f'  t1=$EPOCHREALTIME\n'
            f'  echo "ms $(( (${{t1/./}} - ${{t0/./}}) ))"\n'
            f'done\n'
            f'[ "$fail" = 0 ] || exit 3\n')


def samples(text):
    return [int(line.split()[1])/1000.0 for line in text.splitlines() if line.startswith('ms ')]


def stats(values):
    return {'median_ms': round(statistics.median(values), 3), 'min_ms': round(min(values), 3),
            'max_ms': round(max(values), 3), 'samples_ms': [round(v, 3) for v in values]}


load_start = os.getloadavg()
work = Path(tempfile.mkdtemp(prefix='sol-index-bench.'))
repo = work/'repo'
subprocess.run([GIT, 'init', '-q', str(repo)], check=True, capture_output=True)
fixtures = {}
for name, count in (('small', 100), ('large', 20000), ('xlarge', 110000)):
    a, b = work/f'{name}-a.index', work/f'{name}-b.index'
    git(repo, 'update-index', '--index-info', data=records(count), index=a)
    git(repo, 'update-index', '--index-info', data=records(count, b'other'), index=b)
    assert a.stat().st_size == b.stat().st_size and a.read_bytes() != b.read_bytes()
    listing = oracle_listing(repo, a)
    listing_b = oracle_listing(repo, b)
    fixtures[name] = dict(entries=count, a=a, b=b, listing=listing, listing_b=listing_b,
                          bytes=a.stat().st_size, sha256_a=sha256(a), sha256_b=sha256(b),
                          output_bytes=len(listing))
large_matches_historical = fixtures['large']['a'].read_bytes() == historical(ordered=True)
assert large_matches_historical, 'git-written large fixture differs from the historical entries in path order'
unsorted = work/'historical-unsorted.index'
unsorted.write_bytes(historical())
r = subprocess.run([str(BINARY), '--noprofile', '--norc', '-c', f'PATH=; index read {q(str(unsorted))}'],
                   capture_output=True)
g = subprocess.run([GIT, '-C', str(repo), 'ls-files', '--stage'], capture_output=True,
                   env={**os.environ, 'GIT_INDEX_FILE': str(unsorted)})
historical_unsorted = {'bytes': unsorted.stat().st_size, 'sha256': sha256(unsorted),
                       'builtin_status': r.returncode, 'builtin_stdout_bytes': len(r.stdout),
                       'builtin_stderr': r.stderr.decode(errors='replace').strip()[-200:],
                       'git_ls_files_status': g.returncode, 'git_ls_files_lines': g.stdout.count(b'\n')}
print(f'historical unsorted fixture: builtin {r.returncode}, git ls-files {g.returncode}', flush=True)

cases = []
wanted = set(filter(None, args.only.split(',')))


def validate_read(fx, alternate):
    """Every pass's stdout and status, in one shell, against the oracle."""
    script = 'PATH=\n'
    for i in range(args.passes):
        src = fx['b'] if alternate and i % 2 else fx['a']
        script += f'index read {q(str(src))} > {q(str(work/f"v{i}"))} || exit 4\n'
    run_shell(script, work)
    for i in range(args.passes):
        want = fx['listing_b'] if alternate and i % 2 else fx['listing']
        assert (work/f'v{i}').read_bytes() == want, f'pass {i} output differs from git'
    return args.passes


def validate_git(fx):
    script = f'PATH=\nexport GIT_INDEX_FILE={q(str(fx["a"]))}\n'
    for i in range(args.passes):
        script += f'{q(GIT)} -C {q(str(repo))} ls-files --stage > {q(str(work/f"g{i}"))} || exit 4\n'
    run_shell(script, work)
    want = git(repo, 'ls-files', '--stage', index=fx['a'])
    for i in range(args.passes):
        assert (work/f'g{i}').read_bytes() == want, f'git pass {i} differs'
    return args.passes


for name, fx in fixtures.items():
    a, b = q(str(fx['a'])), q(str(fx['b']))
    work_unit = (f"{fx['bytes']}-byte git index v2 with {fx['entries']} entries parsed and trailer-checked; "
                 f"{fx['entries']} '<mode> <sha> <stage> <path>' lines / {fx['output_bytes']} bytes emitted")
    for variant in ('warm', 'cold'):
        cid = f'index-read-{name}-{variant}'
        if wanted and cid not in wanted:
            continue
        validated = validate_read(fx, variant == 'cold')
        alternate = variant == 'cold'
        select = f'if ((i % 2)); then src={b}; else src={a}; fi;' if alternate else f'src={a};'
        body = select + ' index read "$src" > capture-builtin-$i'
        builtin = samples(run_shell(batch_script(body, args.passes, args.runs), work))
        total = (args.runs + 1) * args.passes
        for i in range(total):
            output = work/f'capture-builtin-{i}'
            expected = fx['listing_b'] if alternate and i % 2 else fx['listing']
            assert output.read_bytes() == expected, f'{cid} builtin pass {i} differs from git'
            output.unlink()
        validated_git = validate_git(fx)
        body = select + f' GIT_INDEX_FILE="$src" {q(GIT)} -C {q(str(repo))} ls-files --stage > capture-git-$i'
        external = samples(run_shell(batch_script(body, args.passes, args.runs), work))
        expected_a = git(repo, 'ls-files', '--stage', index=fx['a'])
        expected_b = git(repo, 'ls-files', '--stage', index=fx['b'])
        for i in range(total):
            output = work/f'capture-git-{i}'
            assert output.read_bytes() == (expected_b if alternate and i % 2 else expected_a), f'{cid} git pass {i}'
            output.unlink()
        cases.append(dict(id=cid, fixture=name, kind='compared', passes=args.passes, runs=args.runs,
                          builtin_command=(f'index read {name}-a.index' if variant == 'warm'
                                           else f'index read {name}-a.index / {name}-b.index alternately'),
                          external_command=f'GIT_INDEX_FILE={name}-a/b.index git ls-files --stage' if alternate else f'GIT_INDEX_FILE={name}-a.index git ls-files --stage',
                          work_unit=work_unit, validation_passes=validated, external_validation_passes=validated_git,
                          captured_passes_per_implementation=total,
                          checksum_misses=(total if alternate or fx['bytes'] > 8*1024*1024 else 1),
                          validation='exact output and zero status on every warm-up and timed pass',
                          cold_sequence=('A/B continuously, including warm-up' if alternate else None),
                          bashos=stats(builtin), external=stats(external),
                          bashos_over_external=round(statistics.median(builtin)/statistics.median(external), 4),
                          equivalence=('same entries and fields; git does not verify the trailer, the builtin '
                                       + ('compares with its verified snapshot' if variant == 'warm'
                                          else 'computes the SHA-1 on every pass'))))
        print(f'{cid}: bashos {cases[-1]["bashos"]["median_ms"]} ms, git {cases[-1]["external"]["median_ms"]} ms '
              f'({cases[-1]["bashos_over_external"]}x) per {args.passes} passes', flush=True)

cid = 'index-info-import-large'
if not wanted or cid in wanted:
    feed = work/'feed'
    feed.write_bytes(records(20000))
    expected = fixtures['large']['a'].read_bytes()
    script = 'PATH=\n'
    for i in range(args.passes):
        script += f'index --index-info {q(str(work/f"i{i}.index"))} < {q(str(feed))} || exit 4\n'
    run_shell(script, work)
    for i in range(args.passes):
        assert (work/f'i{i}.index').read_bytes() == expected, f'import pass {i} differs from git'
    builtin = samples(run_shell(batch_script(
        f'{{ ((++n)); index --index-info {q(str(work))}/o$n.index < {q(str(feed))}; }}',
        args.passes, args.runs, 'n=0'), work))
    script = f'PATH=\n'
    for i in range(args.passes):
        script += (f'GIT_INDEX_FILE={q(str(work/f"j{i}.index"))} {q(GIT)} -C {q(str(repo))} -c index.version=2 '
                   f'update-index --index-info < {q(str(feed))} || exit 4\n')
    run_shell(script, work)
    for i in range(args.passes):
        assert (work/f'j{i}.index').read_bytes() == expected
    external = samples(run_shell(batch_script(
        f'{{ ((++n)); GIT_INDEX_FILE={q(str(work))}/x$n.index {q(GIT)} -C {q(str(repo))} -c index.version=2 '
        f'update-index --index-info < {q(str(feed))}; }}', args.passes, args.runs, 'n=0'), work))
    total = (args.runs + 1) * args.passes
    for prefix in ('o', 'x'):
        for i in range(1, total + 1):
            output = work/f'{prefix}{i}.index'
            assert output.read_bytes() == expected, f'import {prefix} pass {i} differs from git'
            output.unlink()
    cases.append(dict(id=cid, fixture='large', kind='compared', passes=args.passes, runs=args.runs,
                      builtin_command='index --index-info new.index < 20000 records',
                      external_command='GIT_INDEX_FILE=new.index git update-index --index-info < 20000 records',
                      work_unit=f"20000 '100644 <sha> TAB <path>' records ({feed.stat().st_size} bytes) applied to "
                                f"an absent index; {len(expected)}-byte index written and renamed into place",
                      reset='every pass, of both, writes a new index at a path not used before',
                      validation_passes=args.passes, external_validation_passes=args.passes,
                      captured_passes_per_implementation=total,
                      bashos=stats(builtin), external=stats(external),
                      bashos_over_external=round(statistics.median(builtin)/statistics.median(external), 4),
                      equivalence='byte-identical index files and zero status from both on every warm-up, timed and validation pass'))
    print(f'{cid}: bashos {cases[-1]["bashos"]["median_ms"]} ms, git {cases[-1]["external"]["median_ms"]} ms '
          f'({cases[-1]["bashos_over_external"]}x) per {args.passes} passes', flush=True)

report = {
    'schema': 1,
    'date': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'binary': str(BINARY.name), 'binary_sha256': sha256(BINARY),
    'source_commit': subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True,
                                    cwd=Path(__file__).resolve().parent).stdout.strip(),
    'git_version': subprocess.run([GIT, '--version'], capture_output=True, text=True).stdout.strip(),
    'kernel': platform.release(), 'architecture': platform.machine(),
    'cpu_affinity': args.cpu if TASKSET else None,
    'cpu_model': next((l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo') if l.startswith('model name')), ''),
    'load_average_start': load_start, 'method': ('batch wall time from $EPOCHREALTIME in one bash-os shell; '
                                           'stdout captured to owned regular files and every pass checked; warm page cache; warm-up times discarded'),
    'large_fixture_matches_bench_loadables_sorted': large_matches_historical,
    'bench_loadables_unsorted_fixture': historical_unsorted,
    'fixtures': {n: {k: fx[k] for k in ('entries', 'bytes', 'sha256_a', 'sha256_b', 'output_bytes')}
                 for n, fx in fixtures.items()},
    'cases': cases,
}
report['load_average_end'] = os.getloadavg()
Path(args.output).write_text(json.dumps(report, indent=1)+'\n')
shutil.rmtree(work, ignore_errors=True)
