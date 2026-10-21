#!/usr/bin/env python3
"""v compares an extra component even when it is zero.

GNU sed 4.9 rejects v 4.9.0. The reviewed sed treated the missing component
as zero and accepted it. Trailing junk and a shorter older prefix stay put.
"""
import os
from pathlib import Path
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
GNU = '/usr/bin/sed'
env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C')
checks = failures = 0


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:300], 'expected', repr(expected)[:300], flush=True)


def run(script):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', 'sed "$1"', '_', script],
                       input=b'a\nb\n', capture_output=True, env=env, timeout=10)
    return p.returncode, p.stdout, p.stderr


def gnu(script):
    p = subprocess.run([GNU, script], input=b'a\nb\n', capture_output=True, env=env, timeout=10)
    return p.returncode, p.stdout


for script in (
    'v 4.9.0', 'v 4.9.00', 'v 4.9.0.0', 'v 4.9.0.1', 'v 4.9.1',
    'v 4.9.', 'v 4.9x', 'v x', 'v 5', 'v 4.10',
    'v', 'v 4', 'v 4.9', 'v 4.8', 'v 4.8.99', 'v 3.9.0', 'v 4.09', 'v 04.9',
    'v4.2.2', '1{v\n}',
):
    rc, out, err = run(script)
    grc, gout = gnu(script)
    check(script, (rc, out), (grc, gout))
    if b'AddressSanitizer' in err or b'runtime error:' in err:
        failures += 1
        print('FAIL sanitizer', script)

print(f'{checks - failures}/{checks} passed')
sys.exit(1 if failures else 0)
