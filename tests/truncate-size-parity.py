#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check signed size-unit boundaries against GNU without creating large files."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, LC_ALL='C', PATH='')
prefix = 'if [[ -n ${TRUNCATE_MODULE:-} ]]; then enable -f "$TRUNCATE_MODULE" truncate || exit; fi; '
if env.get('TRUNCATE_PRELOAD'):
    env.update(LD_PRELOAD=env['TRUNCATE_PRELOAD'],
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
minimum, maximum = -(1 << 63), (1 << 63) - 1
units = {'': 1, 'K': 1024, 'KiB': 1024, 'KB': 1000, 'kB': 1000}
for power, letter in enumerate('M G T P'.split(), 2):
    units[letter] = units[letter+'iB'] = 1024**power
    units[letter+'B'] = 1000**power
checks = 0
with tempfile.TemporaryDirectory(prefix='truncate-size-') as directory:
    root = Path(directory)
    original = b'keep\0these bytes\n'
    for suffix, multiplier in units.items():
        lower = -((-minimum)//multiplier)
        upper = maximum//multiplier
        values = {minimum, lower-1, lower, lower+1, upper, upper+1, maximum}
        for value in sorted(values):
            size = str(value)+suffix
            # Positive boundary values are parsed with -c and a missing file;
            # negative values shrink only small files, or must leave them alone.
            for existing in ([False, True] if value < 0 else [False]):
                results = []
                for candidate in [False, True]:
                    file = root/'file'
                    file.unlink(missing_ok=True)
                    if existing:
                        file.write_bytes(original)
                    argv = ['-s', size, 'file'] if existing else ['-c', '-s', size, 'file']
                    command = ([binary, '-c', prefix+'truncate "$@"', '_', *argv] if candidate
                               else ['/usr/bin/truncate', *argv])
                    p = subprocess.run(command, cwd=root, env=env if candidate else {'LC_ALL': 'C'},
                                       capture_output=True, timeout=10)
                    assert b'runtime error:' not in p.stderr and b'AddressSanitizer' not in p.stderr, p.stderr
                    assert not file.exists() or file.stat().st_size <= len(original), size
                    data = file.read_bytes() if file.exists() else None
                    results.append((p.returncode, p.stdout, bool(p.stderr), data))
                assert results[0] == results[1], (size, existing, results)
                checks += 1
    file = root/'file'
    file.write_bytes(original)
    p = subprocess.run([binary, '-c', prefix+
                        'truncate -s -9223372036854775808K file 2>/dev/null; rc=$?; '
                        'truncate -s 4 file || exit; [[ $rc == 1 ]]'],
                       cwd=root, capture_output=True, env=env, timeout=10)
    assert p.returncode == 0 and not p.stderr and file.read_bytes() == b'keep', p
    checks += 1
print(f'truncate-size: {checks} GNU boundary and recovery checks passed')
