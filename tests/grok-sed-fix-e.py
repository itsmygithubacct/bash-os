#!/usr/bin/env python3
"""e COMMAND consumes a backslash-newline continuation.

Addressed and unaddressed forms are checked against GNU sed 4.9. The shell
command is printf only. Fails on the reviewed sed, which ends the command at
the escaped newline.
"""
import os
from pathlib import Path
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
GNU = '/usr/bin/sed'
env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C', BASHSED_ALLOW_EXEC='1')
checks = failures = 0
DATA = b'x\ny\n'


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:400], 'expected', repr(expected)[:400], flush=True)


def run(script, data=DATA):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', 'sed "$1"', '_', script],
                       input=data, capture_output=True, env=env, timeout=10)
    return p.returncode, p.stdout, p.stderr


def gnu(script, data=DATA):
    p = subprocess.run([GNU, script], input=data, capture_output=True, env=env, timeout=10)
    return p.returncode, p.stdout


scripts = [
    '1e printf A\\\nprintf B',
    'e printf A\\\nprintf B',
    'e printf A\\\n printf B',
    'e printf A\\\n;printf B',
    'e printf A\\\\\nprintf B',
    'e printf A\\\nprintf B;p',
    '1e printf A\\\nprintf B\np',
    'e printf A\\',
    'e',
    'e ',
    '1e\np',
    'e\\\nprintf B',
]
for script in scripts:
    rc, out, err = run(script)
    grc, gout = gnu(script)
    check(script.replace('\n', '\\n'), (rc, out), (grc, gout))
    if b'AddressSanitizer' in err or b'runtime error:' in err:
        failures += 1
        print('FAIL sanitizer', err[:200])

# Still gated when the variable is unset.
blocked = dict(env)
del blocked['BASHSED_ALLOW_EXEC']
p = subprocess.run([binary, '--noprofile', '--norc', '-c', 'sed "$1"', '_',
                    'e printf A\\\nprintf B'],
                   input=DATA, capture_output=True, env=blocked, timeout=10)
check('gated', (p.returncode, p.stdout), (1, b''))

print(f'{checks - failures}/{checks} passed')
sys.exit(1 if failures else 0)
