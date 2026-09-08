#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise benchmark validation with a producer that corrupts later records."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
digest = hashlib.sha256(bytes(range(256)) * 4096).hexdigest()
record = f"printf '%s\\n' {digest}"
variants = {
    'valid': record,
    'missing': ':',
    'changed': "printf '%064d\\n' 0",
    'extra': f'{record}; {record}',
    'blank': f"printf '\\n'; {record}",
    'whitespace': "printf ' \\t\\n'",
}

with tempfile.TemporaryDirectory(prefix='loadable-bench-test-') as directory:
    scratch = Path(directory)
    for name, second_record in variants.items():
        # The first call always succeeds. Only the second call in the same
        # shell changes, so single-call validation cannot detect the defect.
        prefix = ('crypto_test_calls=0\ncrypto() { '
                  'crypto_test_calls=$((crypto_test_calls + 1)); '
                  f'if [[ $crypto_test_calls -eq 2 ]]; then {second_record}; '
                  f'else {record}; fi; return 0; }}\n')
        binary = scratch / f'shell-{name}'
        binary.write_text('#!/usr/bin/python3\nimport os, sys\n'
                          'args = sys.argv[1:]\n'
                          'if "-c" in args:\n'
                          '    index = args.index("-c") + 1\n'
                          f'    args[index] = {prefix!r} + args[index]\n'
                          'os.execv("/bin/bash", ["/bin/bash", *args])\n')
        binary.chmod(0o700)
        report = scratch / f'{name}.json'
        result = subprocess.run(
            ['python3', str(ROOT / 'bench/loadables.py'), '--binary', str(binary),
             '--busybox', '', '--only', 'crypto', '--quick', '--output', str(report)],
            capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, (name, result.stdout, result.stderr)
        case, = json.loads(report.read_text())['cases']
        assert case['validation_passes'] >= 3
        assert case['results']['external']['status'] == 'ok', case
        actual = case['results']['bashos']
        if name == 'valid':
            assert actual['status'] == 'ok' and actual['median_ms'] > 0, actual
        else:
            assert actual['status'] == 'batch-mismatch', (name, actual)
            assert 'median_ms' not in actual, (name, actual)
        print(f'PASS {name}: {actual["status"]}')
print(f'bench-loadables: {len(variants)} producer scenarios passed')
