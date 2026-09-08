#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate the documented loadable inventory from reviewed evidence.

No benchmarks or loadables are executed here. --check verifies that the
Markdown and CSV match the catalog, profiles and recorded measurements.
"""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT/'docs/loadables-status.md'
CSV = ROOT/'docs/loadables-status.csv'
RANK = {'Build/help': 0, 'Negative checks': 1, 'Smoke': 2, 'Contract': 3,
        'Query parity': 4, 'Parity': 5}
PROFILE_CODES = {'pure': 'P', 'core': 'C', 'device': 'D', 'server': 'S',
                 'desktop': 'T', 'full': 'F'}
# Candidates confirmed in the baseline and checked again in the current run.
PERFORMANCE = ['comm', 'sort-text']


def cell(value):
    return str(value).replace('|', '&#124;').replace('\n', ' ')


def link(path, label):
    return f'[{label}](../{path})'


def value(case, implementation):
    result = case['results'][implementation]
    return result.get('median_ms') if result['status'] == 'ok' else None


def timing(case, implementation):
    result = case['results'][implementation]
    if result['status'] == 'ok':
        return f"{result['median_ms']:.3f}"
    if result['status'] == 'unavailable':
        return '—'
    return 'INVALID' if 'mismatch' in result['status'] else result['status'].upper()


def ratio(case):
    ours, external = value(case, 'bashos'), value(case, 'external')
    return ours/external if ours is not None and external else None


def table(headers, rows):
    return '\n'.join(['| '+' | '.join(headers)+' |',
                      '| '+' | '.join('---' for _ in headers)+' |',
                      *['| '+' | '.join(cell(x) for x in row)+' |' for row in rows]])


def replace_section(document, name, content):
    start, end = f'<!-- BEGIN {name} -->', f'<!-- END {name} -->'
    if document.count(start) != 1 or document.count(end) != 1:
        raise ValueError(f'Expected one marker pair for {name}')
    before, rest = document.split(start)
    _, after = rest.split(end)
    return before+start+'\n'+content+'\n'+end+after


def generate():
    spec = importlib.util.spec_from_file_location('loadable_config', ROOT/'config/loadables.py')
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    if os.environ.get('EXTRA_LOADABLES'):
        raise ValueError('Unset EXTRA_LOADABLES when generating the repository catalog')
    catalog = config.parse_list(ROOT/'config/bash-loadables.list')
    review = json.loads((ROOT/'docs/loadables-review.json').read_text())
    data = json.loads((ROOT/review.get('measurement_file', 'docs/data/loadable-benchmarks.json')).read_text())
    assert review['source_commit'] == data['source_commit']
    assert data['catalog_sha256'] == hashlib.sha256((ROOT/'config/bash-loadables.list').read_bytes()).hexdigest(), 'Refresh the reviewed snapshot after changing the catalog'
    profiles = {}
    for name in json.loads((ROOT/'config/profiles.json').read_text()):
        args = argparse.Namespace(profile=name, level=None, list=None, include=[],
                                  include_list=[], exclude=[], name=None,
                                  list_profiles=False, list_loadables=False)
        profiles[name] = set(config.selection(ROOT, args)['names'])
    assert profiles['full'] == catalog.keys()
    coverage = {name: [] for name in catalog}
    sanitized = {name: [] for name in catalog}
    for groups, destination in [(review['coverage_groups'], coverage),
                                (review['sanitizer_groups'], sanitized)]:
        for group in groups:
            assert set(group['names']) <= catalog.keys(), group['names']
            assert (ROOT/group['evidence']).is_file(), group['evidence']
            for name in group['names']:
                destination[name].append(group)
    for key in ['fuzz', 'comparators', 'notes']:
        assert review[key].keys() <= catalog.keys(), key
    for path in review['fuzz'].values():
        assert (ROOT/path).is_file(), path
    for note in review['notes'].values():
        if 'evidence' in note:
            assert (ROOT/note['evidence']).is_file(), note['evidence']
    assert set(review['repeat_input_findings']) <= catalog.keys()
    assert set(review['limitations']) <= catalog.keys()
    assert review.get('assignments', {}).keys() <= catalog.keys()
    benchmarks = {name: [] for name in catalog}
    ids = set()
    for case in data['cases']:
        assert case['id'] not in ids, case['id']
        ids.add(case['id'])
        assert case['loadable'] in catalog and case['fixture'] in data['fixtures']
        assert case['passes'] > 0 and case['validation_passes'] >= 3
        for result in case['results'].values():
            if result['status'] == 'ok':
                assert 0 < result['min_ms'] <= result['median_ms'] <= result['max_ms']
            else:
                assert 'median_ms' not in result, 'Never publish invalid timings'
        benchmarks[case['loadable']].append(case)
    assert {c['loadable'] for c in data['cases'] if c['results']['bashos']['status'] != 'ok'} == set(review['repeat_input_findings']), 'Review new validation findings before publishing'
    local = {p.stem for p in (ROOT/'loadables').glob('*.c')}
    assert local <= catalog.keys(), 'Source missing from full catalog'
    inventory = data['tool_inventory']
    applets = set(inventory['busybox_applets'])
    helpers = json.loads((ROOT/'config/helpers.json').read_text())['commands']
    entries, rows = [], []
    for name in sorted(catalog):
        groups = sorted(coverage[name], key=lambda g: RANK[g['status']], reverse=True)
        note = review['notes'].get(name, {})
        cases = benchmarks[name]
        failures = [case for case in cases if case['results']['bashos']['status'] != 'ok']
        selected = (failures or sorted(cases, key=lambda c: ratio(c) or 0, reverse=True) or [None])[0]
        base_status = groups[0]['status'] if groups else 'Build/help'
        status = base_status
        if failures:
            status = 'Repeat-input bug'
        elif cases and not groups:
            status = 'Bench checked'
        status_text = status
        if groups:
            status_text = link(groups[0]['evidence'], status)
        if failures:
            status_text = '[Repeat-input bug](#repeated-input-findings)'
        elif cases and not groups:
            status_text = f'[Bench checked](#case-{selected["id"]})'
        if name in review['limitations']:
            status_text += '; [limited](#scope-notes)'
        if sanitized[name]:
            status_text += '; '+link(sanitized[name][0]['evidence'], 'S')
        if name in review['fuzz']:
            status_text += '; '+link(review['fuzz'][name], 'Fz')
        comparison = review['comparators'].get(name, {'program':name, 'applet':name if name in applets else None})
        program, applet = comparison['program'], comparison['applet']
        external_state = ('adapter' if program and not re.fullmatch(r'[a-z0-9_+.-]+', program)
                          else 'available' if inventory['external_available'].get(program)
                          else 'missing' if program else 'n/a')
        applet_state = 'available' if applet in applets else 'missing' if applet else 'n/a'
        program_text = program or 'API fixture'
        if external_state == 'missing':
            program_text += ' (missing)'
        applet_text = applet or '—'
        if applet_state == 'missing':
            applet_text += ' (not in build)'
        priorities = [c for c in cases if c['id'] in PERFORMANCE]
        if failures:
            priority = 'P1'
            action = note['next']
        elif priorities:
            priority = 'P2'
            action = note.get('next') or f"Profile {priorities[0]['id']}: {ratio(priorities[0]):.2f}× external time."
        elif note.get('next'):
            priority, action = 'P3', note['next']
        elif selected and ratio(selected) is not None and ratio(selected) > 1.25:
            priority = 'P3'
            action = f"Confirm {selected['id']} ({ratio(selected):.2f}× external time), then profile."
        elif name in review['limitations']:
            priority, action = 'P3', 'Decide required option scope; see limitations.'
        elif not cases:
            priority = 'P3'
            action = ('Add behavioral fixtures, then timing.' if base_status in ['Build/help', 'Smoke', 'Negative checks']
                      else 'Add a matched workload and timing.')
            if not program and not applet:
                action = 'Define an API workload and metric, then measure.'
        else:
            priority, action = 'P4', 'Extend sizes/options; no selected-case performance priority.'
        if name in review.get('assignments', {}):
            action += f" Assigned to {review['assignments'][name]}."
        members = [p for p in PROFILE_CODES if name in profiles[p]]
        source = f'loadables/{name}.c' if name in local else f'Bash examples/loadables/{name}.c'
        name_text = link(source, f'`{name}`') if name in local else f'`{name}`*'
        bench_text = 'N/M'
        if name == 'gpu':
            bench_text = '[Transport data](#graphics-metrics); no applet ratio'
        if selected:
            bench_text = ' / '.join(timing(selected, label) for label in ['bashos','busybox','external'])
            bench_text += f'; [{selected["id"]}](#case-{selected["id"]}), {selected["passes"]} passes'
            if len(cases) > 1:
                bench_text += f'; {len(cases)} cases total'
        rows.append([name_text, ' '.join(PROFILE_CODES[p] for p in members), status_text,
                     applet_text+'; '+program_text, bench_text, priority, action])
        entry = dict(loadable=name, snapshot_date=data['date'][:10], source_commit=data['source_commit'],
                     profiles=';'.join(members), source=source,
                     status=status, baseline_coverage=base_status, limited=name in review['limitations'],
                     evidence=';'.join(dict.fromkeys(g['evidence'] for g in groups)),
                     coverage_scope='; '.join(dict.fromkeys(g['scope'] for g in groups)),
                     sanitizer_evidence=';'.join(g['evidence'] for g in sanitized[name]),
                     fuzz_evidence=review['fuzz'].get(name,''),
                     companion_loadables=';'.join(helpers.get(name,{}).get('requires',[])),
                     busybox_applet=applet or '', busybox_availability=applet_state,
                     external_program=program or '', external_availability=external_state,
                     comparison_scope=comparison.get('scope','Same-name candidate; only measured arguments are compared.'),
                     benchmark_cases=';'.join(c['id'] for c in cases),
                     selected_case=selected['id'] if selected else '',
                     fixture=selected['fixture'] if selected else '',
                     builtin_command=shlex.join([name,*selected['args']]) if selected else '',
                     external_command=shlex.join([selected['host'],*selected['host_args']]) if selected else '',
                     passes=selected['passes'] if selected else '',
                     timed_samples=selected['runs'] if selected else '',
                     bashos_result=selected['results']['bashos']['status'] if selected else 'unmeasured',
                     bashos_ms=value(selected,'bashos') if selected else '',
                     busybox_ms=value(selected,'busybox') if selected else '',
                     external_ms=value(selected,'external') if selected else '',
                     bashos_over_external=round(ratio(selected),4) if selected and ratio(selected) is not None else '',
                     priority=priority, next_work=action,
                     notes=' '.join(note.get(k,'') for k in ['finding','note']).strip())
        entries.append(entry)
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(entries[0]), lineterminator='\n')
    writer.writeheader(); writer.writerows(entries)
    document = DOC.read_text()
    measured = sum(bool(cases) for cases in benchmarks.values())
    valid = sum(bool(cases) and all(c['results']['bashos']['status']=='ok' for c in cases) for cases in benchmarks.values())
    summary = (f"Catalog: **{len(catalog)} loadables** ({len(local)} local sources, {len(catalog)-len(local)} stock Bash sources). "
               f"Command benchmark: **{len(data['cases'])} cases covering {measured} loadables**; {valid} loadables passed the selected output checks, "
               f"{measured-valid} have confirmed correctness findings. The other {len(catalog)-measured} have no individual command timings here; "
               "GPU transport measurements are reported separately.\n\n")
    summary += table(['Profile','Included loadables'], [[p,len(names)] for p,names in profiles.items()])
    summary += f"\n\nCommand measurement source: `{data['source_commit']}`. "
    validation = review['validation']
    assert validation['source_commit'] == data['source_commit']
    summary += validation['summary'] + '\n\n'
    baseline = review['baseline']
    summary += f"Historical baseline: `{baseline['source_commit']}`; [CI]({baseline['ci']}) passed all nine jobs "
    summary += '(including 48 native test groups). Those older suites did not detect the repeated-input findings. '
    summary += 'Coverage labels describe the mapped fixtures, not a guarantee that every option works.'
    document = replace_section(document,'SUMMARY',summary)
    queue = []
    for name in sorted(review['repeat_input_findings']):
        action = review['notes'][name]['next']
        if name in review.get('assignments', {}):
            action += f" Assigned to {review['assignments'][name]}."
        queue.append(['P1', name, 'Repeated redirected input fails output validation.', action])
    for identifier in PERFORMANCE:
        case = next(c for c in data['cases'] if c['id']==identifier)
        assert case['confirmed'] and case['runs'] == 7
        bb = value(case,'busybox')
        detail = f"{ratio(case):.2f}× external time"
        if bb:
            detail += f"; {value(case,'bashos')/bb:.2f}× BusyBox time"
        action = review['notes'].get(case['loadable'], {}).get('next') or 'Profile input/output and allocation costs on this fixture, then measure the proposed change.'
        if case['loadable'] in review.get('assignments', {}):
            action += f" Assigned to {review['assignments'][case['loadable']]}."
        queue.append(['P2',f'[{identifier}](#case-{identifier})',detail+'; output checks pass, seven samples.', action])
    queue += [['P3','unexpand, wc -m, diff, join, crypto sha256','Candidates from the baseline; current case timings appear below.',
               'Check the current ratio and several input sizes before optimizing; crypto covers SHA-256 only.'],
              ['P3','Unmeasured commands and APIs','No per-command timing is available; many only have small fixtures.',
               'Choose by target profile and application use, establish equivalent outputs, then time.']]
    document = replace_section(document,'PRIORITIES',table(['Priority','Loadable / case','Evidence','Next step'],queue))
    document = replace_section(document,'CATALOG',table(['Loadable','Profiles','Status / evidence','Targets: BB; external','Batch ms: BOS / BB / external','Work','Next work'],rows))
    notes = []
    for name,note in sorted(review['notes'].items()):
        if note.get('note'):
            evidence = ' '+link(note['evidence'],'source') if note.get('evidence') else ''
            notes.append([f'`{name}`',note['note']+evidence])
    document = replace_section(document,'NOTES',table(['Loadable','Scope / limitation'],notes))
    case_rows = []
    for case in data['cases']:
        command = shlex.join([case['loadable'],*case['args']])
        external = shlex.join([case['host'],*case['host_args']])
        fixture = case['fixture']
        fixture_text = f"{fixture} ({data['fixtures'][fixture]['bytes']:,} stdin bytes)"
        if fixture=='empty':
            fixture_text = 'No stdin; named fixtures / arguments'
        case_rows.append([f'<a id="case-{case["id"]}"></a>{case["id"]}',f'`{command}`',f'`{external}`',fixture_text,
                          case['passes'],timing(case,'bashos'),timing(case,'busybox'),timing(case,'external'),
                          f'{ratio(case):.2f}×' if ratio(case) is not None else '—',case['runs']])
    document = replace_section(document,'CASES',table(['Case','Builtin command','External command','Input','Passes','BOS ms','BB ms','External ms','BOS / external','Samples'],case_rows))
    method = f"The command measurements use the native dynamic full `out/bash` at the source above, SHA-256 `{data['binary_sha256']}`. "
    method += f"Host: {data['cpu_model']}, {data['architecture']} Linux {data['kernel']}; pinned CPUs: {', '.join(map(str, data['cpus']))}. "
    method += 'Reference versions and fixture hashes are recorded in the measurement JSON. '
    method += 'These are host measurements; no per-command RISC-V or appliance performance is claimed.\n\n'
    method += f"Every case uses {', '.join(map(str, sorted({c['runs'] for c in data['cases']})))} timed samples after output validation and warm-up. "
    method += f"The one-minute host load was {data['load_average_start'][0]:.1f} at the start and {data['load_average_end'][0]:.1f} at the end. "
    method += 'A shared lock serialized participating benchmarks; builds and other host activity could still contend. '
    method += 'Use the recorded ranges for prioritization and repeat on the intended device before claiming small performance differences.'
    document = replace_section(document,'METHOD',method)
    graphics_data = json.loads((ROOT/review['graphics_measurement_file']).read_text())
    gpu = graphics_data['gpu']
    assert gpu['binary_sha256'] == graphics_data['binary_sha256'] and gpu['source_commit'] == graphics_data['source_commit']
    for result in gpu['cases']:
        assert result['tty_bytes_min'] <= result['tty_bytes'] <= result['tty_bytes_max']
        assert result['bytes_per_update'] == result['tty_bytes']/gpu['updates']
        assert 0 < result['min_seconds'] <= result['median_seconds'] <= result['max_seconds']
    graphics = f"Historical graphics measurement source: `{gpu['source_commit']}`; binary SHA-256 `{gpu['binary_sha256']}`. These transport timings were not rerun with the current command measurements.\n\n"
    graphics += table(['Transport / change','Median TTY bytes / 30 updates','Median TTY bytes / update','Median seconds','Min–max seconds'],
                     [[r['transport']+' / '+r['mode'],f"{r['tty_bytes']:,}",f"{r['bytes_per_update']:,.0f}",
                       f"{r['median_seconds']:.3f}",f"{r['min_seconds']:.3f}–{r['max_seconds']:.3f}"] for r in gpu['cases']])
    document = replace_section(document,'GPU',graphics)
    return document, stream.getvalue(), len(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    document, csv_data, count = generate()
    for path, expected in [(DOC,document),(CSV,csv_data)]:
        if args.check:
            if not path.is_file() or path.read_text() != expected:
                parser.exit(1, f'{path.name} is stale; run python3 bench/catalog.py\n')
        else:
            path.write_text(expected)
    print(f'loadable catalog: {count} unique rows; evidence, profiles and measurements checked')


if __name__ == '__main__':
    main()
