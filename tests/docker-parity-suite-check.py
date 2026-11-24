#!/usr/bin/env python3
"""Integration checks for scripts/docker-parity-suite.py against the real images.

A planted suite holds a matching case, a failing case, known differences that
still differ, that now match, that differ in an undeclared way or that break
the reference, sidecar files, a replay case and a stale known entry. The driver
must classify every one correctly and set its exit status accordingly.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / 'scripts/docker-parity-suite.py'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace', required=True, type=Path)
    p.add_argument('--reference', default='bash-os:parity-debian')
    p.add_argument('--candidate', default='bash-os:parity-bash-os')
    args = p.parse_args()
    workspace = args.workspace.resolve()
    work = workspace / 'results' / ('suite-validation-' + uuid.uuid4().hex[:8])
    suite = work / 'suite'
    cases = {
        'plant/match.sh': "printf 'same\\n'\n",
        'plant/fails.sh': 'type -t cat\n',
        'plant/known-still-differs.sh': 'type -t cat\n',
        'plant/known-now-passes.sh': "printf 'same\\n'\n",
        'plant/known-undeclared-stream.sh': 'type -t cat >&2\n',
        'plant/known-reference-fails.sh': 'type -t cat; exit 3\n',
        'plant/sidecars.sh': 'IFS= read -r line; printf \'<%s> <%s>\\n\' "$line" "$1"; exit 4\n',
        'other/second-area.sh': 'printf "%s\\n" b a | sort\n',
    }
    for name, text in cases.items():
        path = suite / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (suite / 'plant/sidecars.stdin').write_bytes(b'from stdin\n')
    (suite / 'plant/sidecars.args').write_text('two words\n')
    (suite / 'plant/sidecars.status').write_text('4\n')
    (suite / 'plant/sidecars.timeout').write_text('20\n')
    (suite / 'replay').mkdir()
    (suite / 'replay/prompt.replay.json').write_text(json.dumps([
        {'expect': 'parity> '}, {'send': "printf 'ok=%s\\n' $((6*7))\n"}, {'expect': 'ok=42\r\n'},
        {'expect': 'parity> '}, {'send': 'exit 0\n'}]))
    entry = {'category': 'by-design', 'reason': 'planted for the driver check'}
    known = {
        '_comment': 'keys starting with an underscore are ignored',
        'plant/known-still-differs': dict(entry, differences=['stdout']),
        'plant/known-now-passes': dict(entry),
        'plant/known-undeclared-stream': dict(entry, differences=['stdout']),
        'plant/known-reference-fails': dict(entry),
        'plant/no-such-case': dict(entry),
    }
    (suite / 'known-differences.json').write_text(json.dumps(known, indent=2))
    common = [sys.executable, str(DRIVER), '--workspace', str(workspace), '--suite', str(suite),
              '--reference', args.reference, '--candidate', args.candidate, '--jobs', '4']
    records = []

    def run(name, extra, expected_exit):
        output = work / name
        result = subprocess.run(common + ['--output', str(output)] + extra,
                                capture_output=True, text=True, timeout=600)
        assert result.returncode == expected_exit, (name, result.returncode, result.stdout, result.stderr)
        summary = json.loads((output / 'summary.json').read_text())
        assert (output / 'summary.md').exists(), name
        for image in summary['images']:
            assert image['id'].startswith('sha256:') and image['id'] in result.stdout, (name, image)
        records.append({'name': name, 'passed': True, 'summary': str(output / 'summary.json')})
        print('PASS', name, flush=True)
        return summary, result.stdout, (output / 'summary.md').read_text()

    listing = subprocess.run(common[:-2] + ['--list'], capture_output=True, text=True, timeout=60, check=True)
    assert len(listing.stdout.splitlines()) == 9, listing.stdout
    assert 'plant/known-now-passes  [known: by-design]' in listing.stdout, listing.stdout
    records.append({'name': 'list', 'passed': True})

    summary, stdout, report = run('full-run', [], 1)
    results = {c['id']: c['result'] for c in summary['cases']}
    assert results == {
        'plant/match': 'pass', 'plant/fails': 'fail', 'plant/known-still-differs': 'xfail',
        'plant/known-now-passes': 'xpass', 'plant/known-undeclared-stream': 'fail',
        'plant/known-reference-fails': 'fail', 'plant/sidecars': 'pass',
        'other/second-area': 'pass', 'replay/prompt': 'pass'}, results
    assert summary['stale_known'] == ['plant/no-such-case'], summary['stale_known']
    assert summary['totals'] == {'pass': 4, 'xfail': 1, 'fail': 3, 'xpass': 1}, summary['totals']
    assert summary['areas']['plant'] == {'pass': 2, 'xfail': 1, 'fail': 3, 'xpass': 1}, summary['areas']
    assert not summary['ok']
    sidecar = work / 'full-run/cases/plant/sidecars/reference/stdout'
    assert sidecar.read_bytes() == b'<from stdin> <two words>\n', sidecar.read_bytes()
    assert 'XPASS: plant/known-now-passes: prune known-differences entry' in stdout, stdout
    assert 'FAIL: plant/fails: stdout bytes' in stdout, stdout
    assert 'STALE: known-differences entry plant/no-such-case has no case' in stdout, stdout
    assert '## Failures' in report and '### `plant/fails`' in report, report
    assert '+builtin' in report and '-file' in report, report  # the short diff of the planted failure
    assert '## Unexpected passes' in report and '### `plant/known-now-passes`' in report, report
    assert '| plant | 7 | 2 | 1 | 3 | 1 |' in report, report
    failing = {c['id']: c for c in summary['cases']}
    assert any('reference exit 3' in d for d in failing['plant/known-reference-fails']['differences'])
    assert failing['plant/known-undeclared-stream']['differences'] == [
        d for d in failing['plant/known-undeclared-stream']['differences'] if d.startswith('stderr')]

    # A subset never reports stale entries; a pass plus an xfail is a success.
    summary, _, _ = run('subset-ok', ['--case', 'plant/match', 'plant/known-still-*'], 0)
    assert summary['totals'] == {'pass': 1, 'xfail': 1, 'fail': 0, 'xpass': 0}, summary['totals']
    assert summary['stale_known'] == [] and summary['ok']
    summary, _, _ = run('area-only', ['--area', 'replay', '--area', 'other'], 0)
    assert sorted(c['id'] for c in summary['cases']) == ['other/second-area', 'replay/prompt']
    # A rerun compared with the first run reports no changed results.
    summary, stdout, _ = run('compare', ['--compare', str(work / 'full-run/summary.json')], 1)
    assert summary['changed'] == [], summary['changed']
    assert 'CHANGED' not in stdout

    # Every container the runner created for these cases was removed.
    remaining = set(subprocess.check_output(['docker', 'ps', '-a', '--format', '{{.Names}}'],
                                            text=True).splitlines())
    names = [json.loads(path.read_text())['name'] for path in work.rglob('container.json')]
    assert names and not remaining.intersection(names), remaining.intersection(names)
    records.append({'name': 'containers-removed', 'passed': True})
    (work / 'validation.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'{len(records)} suite driver checks passed; evidence: {work}', flush=True)


if __name__ == '__main__':
    main()
