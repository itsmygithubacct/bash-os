#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sweep every production diff allocation and verify recovery in the same shell."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = {**os.environ, 'PATH': '', 'LC_ALL': 'C'}
env.pop('BASH_ENV', None)
with tempfile.TemporaryDirectory(prefix='sol-diff-alloc-') as tmp:
    root = Path(tmp)
    records = [f'line {i}\n'.encode() for i in range(600)]
    cases = [(b'old\n' * 12, b'new\n' * 12),
             (b'', b'new\n' * 20), (b'old\n' * 20, b''),
             (b''.join(records), b'insert\n' + b''.join(records)),
             (b'x' * 20000 + b'a\n', b'x' * 20000 + b'b\n'),
             (b'old\0\n', b'new\0\n'), (b'same\n', b'same\n')]
    checks = 0
    for a, b in cases:
        (root / 'a').write_bytes(a)
        (root / 'b').write_bytes(b)
        for mode in ('', '-u', '-q', '-i'):
            p = subprocess.run([binary, '-c', f'export BASHOS_DIFF_REPORT=1; diff {mode} a b'],
                               cwd=tmp, env=env, capture_output=True, timeout=30)
            assert p.returncode == (0 if a == b else 1), p
            assert p.stderr.startswith(b'allocations='), p.stderr
            count = int(p.stderr.split(b'=')[1])
            # Every successful allocation is failed once, then a success beyond
            # the last allocation confirms that the sweep reached the endpoint.
            for fail_at in range(1, count + 2):
                script = (f'export BASHOS_DIFF_FAIL={fail_at}; diff {mode} a b >/dev/null; '
                          'r=$?; unset BASHOS_DIFF_FAIL; diff a a || exit 90; '
                          'printf "status=%s\\n" "$r"')
                p = subprocess.run([binary, '-c', script], cwd=tmp, env=env,
                                   capture_output=True, timeout=30)
                expected = 2 if fail_at <= count else (0 if a == b else 1)
                assert (p.returncode, p.stdout) == (0, f'status={expected}\n'.encode()), p
                if fail_at <= count:
                    assert b'out of memory' in p.stderr, p.stderr
                else:
                    assert not p.stderr, p.stderr
                assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
                checks += 1
    print(f'PASS {checks} allocation failure/recovery cases; no live production allocations')
