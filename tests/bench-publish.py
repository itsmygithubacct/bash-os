#!/usr/bin/env python3
"""Published merges preserve omissions and never relabel incompatible measurements."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bench_publish', ROOT / 'bench/publish.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)

base = {
    'schema': 1, 'date': '2026-10-17', 'source_commit': 'measured-source',
    'binary_sha256': 'a' * 64, 'kernel': 'fixture-kernel', 'architecture': 'x86_64',
    'cpus': [1], 'load_average_start': [0, 0, 0], 'method': 'validated batches',
    'cpu_model': 'fixture-cpu', 'versions': {'bash': 'fixture'}, 'runs': 3,
    'fixtures': {'text': {'bytes': 1, 'sha256': 'b' * 64}},
    'cases': [{'id': name, 'loadable': name, 'results': {'bashos': {
        'status': 'ok', 'median_ms': 1, 'min_ms': 0.9, 'max_ms': 1.1}}}
        for name in ('keep', 'omit')],
}

with tempfile.TemporaryDirectory(prefix='bench-publish-test-') as directory:
    root = Path(directory)
    previous, raw, output = (root / name for name in ('base.json', 'raw.json', 'output.json'))
    previous.write_text(json.dumps(base))

    def run(report, *args, ok=True):
        raw.write_text(json.dumps(report))
        before = output.read_bytes() if output.exists() else None
        argv = ['publish.py', str(raw), str(output), '--base', str(previous), *args]
        with patch.object(sys, 'argv', argv), patch.object(publisher, 'inventory', return_value={}), \
                patch.object(publisher, '_performance', return_value={'keep', 'omit'}), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                publisher.main()
            except SystemExit as error:
                assert not ok and error.code == 2, error
                assert (output.read_bytes() if output.exists() else None) == before
                return
        assert ok, 'invalid report was published'
        return json.loads(output.read_text())

    report = copy.deepcopy(base)
    report['cases'] = report['cases'][:1]
    report['source_commit'] = 'later-harness-only-commit'
    result = run(report, '--merge', '--omit', 'omit', '--omit-reason', 'invalid old case')
    assert [case['id'] for case in result['cases']] == ['keep']
    assert result['source_commit'] == base['source_commit']
    assert result['omitted']['cases'] == ['omit']
    run(report, '--merge', '--omit', 'typo', '--omit-reason', 'mistyped', ok=False)
    for field, value in [('binary_sha256', 'c' * 64), ('kernel', 'other-kernel'),
                         ('architecture', 'aarch64'), ('cpu_model', 'other-cpu'),
                         ('cpus', [2]), ('method', 'different method'),
                         ('versions', {'bash': 'other'}),
                         ('fixtures', {'text': {'bytes': 2, 'sha256': 'd' * 64}})]:
        changed = copy.deepcopy(report)
        changed[field] = value
        run(changed, '--merge', ok=False)
    duplicate = copy.deepcopy(report)
    duplicate['cases'] *= 2
    run(duplicate, ok=False)
    report['cases'][0]['results']['bashos']['status'] = 'batch-mismatch'
    result = run(report)
    assert result['cases'][0]['results']['bashos'] == {'status': 'batch-mismatch'}
    assert not result['cases'][0]['confirmed']
print('bench-publish: omissions, provenance, duplicate ids, and failed timing removal verified')
