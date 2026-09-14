#!/usr/bin/env python3
"""Compare reusable join groups with GNU join over changing group sizes."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = dict(os.environ, LC_ALL='C')
checks = 0
with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    left, right = [], []
    for key in range(60):
        for i in range((key * 3 + 1) % 8):
            left.append(f'{key:03d} L{i} ' + 'a' * (1 + key % 13) + '\n')
        for i in range((key * 5 + 2) % 7):
            right.append(f'{key:03d} R{i} ' + 'b' * (1 + key % 17) + '\n')
    options = [[], ['-a1'], ['-a2'], ['-a1', '-a2'], ['-v1'], ['-v2'],
               ['-o', '0,1.2,2.2,1.3,2.3', '-e', '_', '-a1', '-a2'],
               ['-o', 'auto', '-a1', '-a2'], ['--header']]
    for separator in (' ', ':'):
        Path('left').write_text(''.join(left).replace(' ', separator))
        Path('right').write_text(''.join(right).replace(' ', separator))
        for opts in options:
            args = (['-t:'] if separator == ':' else []) + opts + ['left', 'right']
            reference = subprocess.run(['/usr/bin/join', *args], capture_output=True, env=env)
            actual = subprocess.run([binary, '-c', 'join "$@"', 'check', *args],
                                    capture_output=True, env=env)
            assert (actual.returncode, actual.stdout) == (reference.returncode, reference.stdout), (
                args, actual.returncode, actual.stderr, actual.stdout[:160], reference.stdout[:160])
            checks += 1
print(f'join-reuse: {checks} checks passed')
