#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare version prereleases, numeric ties, and key options against GNU."""
import os
from pathlib import Path
import random
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, LC_ALL='C', PATH='')
prefix = 'if [[ -n ${SORT_MODULE:-} ]]; then enable -f "$SORT_MODULE" sort || exit; fi; '
if env.get('SORT_PRELOAD'):
    env.update(LD_PRELOAD=env['SORT_PRELOAD'], ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
               UBSAN_OPTIONS='halt_on_error=1')
versions = [f'v{n}{suffix}' for n in ['0', '00', '1', '01', '001', '2', '10', '9'*80]
            for suffix in ['', '~', '~~', '~rc1', '~rc02', '~rc2', '.0', '.00', '.2', '.10', 'a', '+1']]
versions += ['v1.0~rc1', 'v1.0', 'v1.02', 'v1.2', 'v1.10', '', '~', '.', '..', '.a', '.a~']
versions += [v+ext for v in ['v1', 'v01', 'v1a', 'v1~rc', '.v1', '.v2', 'v2']
             for ext in ['', '.gz', '.tar.gz', '.zip', '.1.gz', '.~1~']]
names_rng = random.Random(71)
versions += [''.join(names_rng.choice('abAB012.~+-_') for _ in range(names_rng.randrange(20)))
             for _ in range(2000)]
rng = random.Random(20)
checks = 0
for trial in range(4):
    rng.shuffle(versions)
    for delimiter in [b'\n', b'\0']:
        for args in [['-V'], ['-Vr'], ['-Vs'], ['-Vu'], ['-Vrs'], ['-Vru'], ['-k2,2V', '-s']]:
            rows = [f'{i} {v} tail'.encode() if '-k2,2V' in args else v.encode()
                    for i, v in enumerate(versions)]
            data = delimiter.join(rows) + delimiter
            opts = args + (['-z'] if delimiter == b'\0' else [])
            want = subprocess.run(['/usr/bin/sort', *opts], input=data, capture_output=True,
                                  env={'LC_ALL': 'C'}, timeout=20)
            got = subprocess.run([binary, '-c', prefix+'PATH=; sort "$@"', '_', *opts],
                                 input=data, capture_output=True, env=env, timeout=20)
            assert (got.returncode, got.stdout, got.stderr) == (want.returncode, want.stdout, want.stderr), (trial, opts, got, want)
            checks += 1
print(f'sort-version: {checks} GNU comparisons passed')
