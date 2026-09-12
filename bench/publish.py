#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Turn a raw bench/loadables.py report into the published measurement JSON.

The raw report records everything the harness saw, including failed validation
and the wall times of runs that were later rejected. The published file is the
subset the catalog is allowed to describe, plus the host inventory the catalog
needs. This step is deliberately separate and deliberately in the repository:
the rule that a speed ratio is never published for incorrect output is enforced
here, once, rather than in each refresh by hand.

    python3 bench/publish.py RAW.json docs/data/loadable-benchmarks-current.json
    python3 bench/publish.py RAW.json OUT.json --merge          # same binary only
    python3 bench/publish.py RAW.json OUT.json --omit free --omit-reason \
        'live meminfo counters move between invocations'

Merging keeps cases measured earlier on the *same* binary and replaces the ones
present in the raw report. It refuses a different binary, because a table whose
rows describe two different executables cannot be compared row to row.
"""
import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'
def _performance():
    """The curated P2 set, read from catalog.py so the two cannot drift.

    Two copies of this list is exactly the failure the publication checklist
    warns about: the catalog would assert on a `confirmed` flag this file had
    stopped setting, or worse, stop asserting on one it still set.
    """
    spec = importlib.util.spec_from_file_location('bashos_catalog', ROOT/'bench/catalog.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return set(module.PERFORMANCE)
# Fields copied from a raw case. Anything else in the raw report (stderr text,
# per-run samples, captured output) stays out of the published file.
CASE_FIELDS = ['id', 'loadable', 'args', 'fixture', 'host', 'applet',
               'host_args', 'normalizer', 'output', 'reference', 'self_timed',
               'mode', 'reset', 'env', 'work', 'passes', 'validation_passes']


def inventory(raw, previous):
    """Which comparison tools this host actually has."""
    busybox = shutil.which('busybox', path=HOST_PATH)
    applets = subprocess.check_output([busybox, '--list'], text=True).split() if busybox else []
    # Keep programs named by earlier runs: the catalog reports availability for
    # every reviewed comparator, not only the ones in this report.
    programs = {case['host'] for case in raw['cases'] if case.get('host')}
    programs |= set((previous.get('tool_inventory') or {}).get('external_available') or {})
    available = {}
    for program in sorted(programs):
        # A comparator recorded as an adapter ('git hash-object / cat-file') is
        # a description, not a command; never hand it to which().
        if program and all(c.isalnum() or c in '_+.-' for c in program):
            available[program] = bool(shutil.which(program, path=HOST_PATH))
    return {'busybox_applets': applets, 'external_available': available}


def clean(result):
    """Drop every timing from a result that did not pass output validation."""
    if result.get('status') == 'ok':
        return {'status': 'ok', 'median_ms': result['median_ms'],
                'min_ms': result['min_ms'], 'max_ms': result['max_ms']}
    kept = {k: v for k, v in result.items() if 'ms' not in k and k != 'data'}
    kept.setdefault('status', 'error')
    return kept


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('raw', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--merge', action='store_true',
                        help='keep existing cases measured on the same binary')
    parser.add_argument('--base', type=Path,
                        default=ROOT/'docs/data/loadable-benchmarks-current.json',
                        help='published file to merge onto and to read the tool inventory from')
    parser.add_argument('--omit', action='append', default=[], metavar='CASE',
                        help='drop this case id; repeatable')
    parser.add_argument('--omit-reason', default='',
                        help='why the omitted cases are not publishable')
    args = parser.parse_args()

    raw = json.loads(args.raw.read_text())
    if raw.get('schema') != 1 or not raw.get('cases'):
        parser.error(f'{args.raw} is not a complete schema-1 report')
    if args.omit and not args.omit_reason:
        parser.error('--omit requires --omit-reason: an undocumented gap reads as an oversight')
    previous = json.loads(args.base.read_text()) if args.base.is_file() else {}
    performance = _performance()

    published = {
        'schema': 1,
        'date': raw['date'],
        'source_commit': raw['source_commit'],
        'binary_sha256': raw['binary_sha256'],
        'kernel': raw['kernel'],
        'architecture': raw['architecture'],
        'cpus': raw['cpus'],
        'load_average_start': raw['load_average_start'],
        'load_average_end': raw.get('load_average_end', raw['load_average_start']),
        'method': raw['method'],
        'cpu_model': raw['cpu_model'],
        'versions': raw['versions'],
        'fixtures': raw['fixtures'],
        'catalog_sha256': hashlib.sha256((ROOT/'config/bash-loadables.list').read_bytes()).hexdigest(),
        'tool_inventory': inventory(raw, previous),
        'cases': [],
    }
    if args.omit:
        published['omitted'] = {'cases': sorted(args.omit), 'reason': args.omit_reason}

    kept, omitted, invalid = [], [], []
    for case in raw['cases']:
        if case['id'] in args.omit:
            omitted.append(case['id'])
            continue
        results = case.get('results', {})
        if results.get('bashos', {}).get('status') != 'ok':
            invalid.append(f"{case['id']}={results.get('bashos', {}).get('status')}")
        row = {field: case.get(field) for field in CASE_FIELDS}
        # A report written before self_timed existed still identifies the case:
        # only a self-referenced one resolves its expected output to 'bashos'.
        if row['self_timed'] is None:
            row['self_timed'] = case.get('reference') == 'bashos'
        row['date'] = raw['date']
        row['runs'] = raw['runs']
        row['confirmed'] = (case['id'] in performance
                            and results.get('bashos', {}).get('status') == 'ok')
        row['results'] = {label: clean(result) for label, result in results.items()}
        kept.append(row)

    if args.merge:
        if not previous:
            parser.error(f'--merge needs an existing {args.base}')
        if previous['binary_sha256'] != raw['binary_sha256']:
            parser.error('--merge refused: the raw report measured a different binary than '
                         f"{args.base.name} ({raw['binary_sha256'][:12]} vs "
                         f"{previous['binary_sha256'][:12]}). Remeasure the full set instead; "
                         'rows from two binaries are not comparable.')
        # The published source_commit describes the measured implementation. A
        # docs-only or harness-only HEAD must not relabel it.
        published['source_commit'] = previous['source_commit']
        published['fixtures'] = {**previous.get('fixtures', {}), **raw['fixtures']}
        merged = {case['id']: case for case in previous['cases']}
        merged.update({case['id']: case for case in kept})
        published['cases'] = [merged[key] for key in sorted(merged)]
    else:
        published['cases'] = sorted(kept, key=lambda case: case['id'])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(published, indent=2)+'\n')
    selftimed = sum(1 for case in published['cases'] if case.get('self_timed'))
    print(f'{args.output}: {len(published["cases"])} cases '
          f'({len({case["loadable"] for case in published["cases"]})} loadables, '
          f'{selftimed} self-timed), catalog {published["catalog_sha256"][:12]}')
    if omitted:
        print(f'  omitted: {", ".join(omitted)} — {args.omit_reason}')
    if invalid:
        print(f'  published WITHOUT a builtin timing (validation failed): {", ".join(invalid)}')
        print('  register each of these in docs/loadables-review.json before running catalog.py')


if __name__ == '__main__':
    main()
