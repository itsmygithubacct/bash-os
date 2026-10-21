#!/usr/bin/env python3
"""Bracket-aware regex delimiters in addresses and s///.

A delimiter inside [] is part of the expression, including negated classes
and [:.= names. Fails on the reviewed sed, which stops at the first delimiter.
"""
import os
from pathlib import Path
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
GNU = '/usr/bin/sed'
env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C')
checks = failures = 0
DATA = b'a\n,\n|\n#\nb\nx\n'


def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:300], 'expected', repr(expected)[:300], flush=True)


def run(args, data):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', 'sed "$@"', '_', *args],
                       input=data, capture_output=True, env=env, timeout=10)
    return p.returncode, p.stdout, p.stderr


def gnu(args, data):
    p = subprocess.run([GNU, *args], input=data, capture_output=True, env=env, timeout=10)
    return p.returncode, p.stdout


# The nine review cases, plus nested names and the s/// regex half.
scripts = [
    ['-n', r'\,[a,b],p'],
    ['-n', r'\,[^,],p'],
    ['-n', r'\,[[:alpha:],],p'],
    ['-n', r'\|[a|b]|p'],
    ['-n', r'\|[^|]|p'],
    ['-n', r'\|[[:alpha:]|]|p'],
    ['-n', r'\#[a#b]#p'],
    ['-n', r'\#[^#]#p'],
    ['-n', r'\#[[:alpha:]#]#p'],
    ['-n', r'\,[[.a.],],p'],
    ['-n', r'\,[[=a=],],p'],
    ['-n', r'\,[]a,],p'],
    ['-n', r'\,[^],],p'],
    ['-n', r'\,[[:],],p'],
    ['-n', r'\,[]],],p'],
    ['-n', r'\,[[],],p'],
    ['-n', r'\,[a\],b],p'],
    ['-n', r'\,[a\\],],p'],
    [r's,[a,],X,'],
    ['-n', r's,[a,],X,'],
    [r's,[^,],X,'],
    ['-E', r's,[a|b,],Y,'],
]
for args in scripts:
    rc, out, err = run(args, DATA)
    grc, gout = gnu(args, DATA)
    check(args, (rc, out), (grc, gout))
    if b'AddressSanitizer' in err or b'runtime error:' in err:
        failures += 1
        print('FAIL sanitizer', args, err[:200])

print(f'{checks - failures}/{checks} passed')
sys.exit(1 if failures else 0)
