#!/usr/bin/env python3
"""Empty backreferences must not share loop guards across search branches."""
import itertools
import os
from pathlib import Path
import random
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C')
prefix = 'if [[ -n ${NL_MODULE:-} ]]; then enable -f "$NL_MODULE" nl || exit; fi; '
checks = 0


def run(pattern, data):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c',
                        prefix + 'nl -w1 -s: "$1"', '_', '-bp' + pattern],
                       input=data, capture_output=True, env=env, timeout=20)
    assert not p.stderr and p.returncode == 0, p
    return p.stdout


for pattern, data, expected in [
    (r'^\(a*\)b*\1$', b'b\n', b'1:b\n'),
    (r'^\(.*\)[^b]*\1$', b'a\n\0\n', b'1:a\n2:\0\n'),
    (r'^\(a*\)\1*$', b'\na\n', b'1:\n2:a\n'),
    (r'^\(a*\)b\1$', b'b\naba\n', b'1:b\n2:aba\n'),
]:
    assert run(pattern, data) == expected, pattern
    checks += 1

subjects = [bytes(t) for n in range(6) for t in itertools.product(b'ab\0', repeat=n)]
data = b'\n'.join(subjects) + b'\n'
rng = random.Random(10202026)
atoms = ['a', 'b', '.', '[^a]', '[ab]', '[^b]', '[[:alnum:]]']
patterns = {r'^\(a*\)\1*$', r'^\(a*\)\(b*\)\1*\2*$',
            r'^\(a*\)b*\1$', r'^\(.*\)[^b]*\1$'}
for _ in range(700):
    group = ''.join(rng.choice(atoms) + rng.choice(['', '*', r'\{0,2\}', r'\?'])
                    for _ in range(rng.randrange(1, 3)))
    pattern = r'\(' + group + r'\)' + rng.choice(atoms) + rng.choice(['', '*']) + r'\1'
    patterns.add(rng.choice(['', '^']) + pattern + rng.choice(['', '$', r'\b', r'\B']))
for loc in ('C', 'C.UTF-8'):
    env['LC_ALL'] = loc
    # Keep binary records, and add non-ASCII characters to exercise byte offsets.
    blob = data if loc == 'C' else data + 'é\néé\néaé\né\0é\n'.encode()
    for pattern in sorted(patterns):
        reference = subprocess.run(['/usr/bin/nl', '-w1', '-s:', '-bp' + pattern],
                                   input=blob, capture_output=True, env=env, timeout=20)
        assert reference.returncode == 0 and not reference.stderr, (pattern, reference)
        assert run(pattern, blob) == reference.stdout, (loc, pattern)
        checks += 1
print(f'nl-backrefs: {checks} explicit/GNU comparisons; {len(subjects)} binary subjects per pattern')
