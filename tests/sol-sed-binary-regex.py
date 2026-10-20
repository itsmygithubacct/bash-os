#!/usr/bin/env python3
"""Deterministic GNU oracles for length-aware BRE/ERE and binary captures."""
import os
from pathlib import Path
import random
import subprocess
import sys

binary=str(Path(sys.argv[1]).resolve())
rng=random.Random(20261020)
subjects=[b'',b'\0',b'\0\0\0\n',b'a\0b\0ab\n',b'a\0a\0\n',bytes(range(256)),
          'é\0あ é\n'.encode(),b'\xff\0\x80a\n',b'a\nb\0c\n']
subjects += [bytes(rng.choice([0,1,65,97,98,99,95,32,255]) for _ in range(25))+b'\n' for _ in range(3)]
patterns=[r'\x00',r'\x00+',r'[\x00ab]',r'[^\x00a]',r'.*',r'.\{0,2\}',r'\b',r'\B',
          r'^',r'$',r'[[:alpha:]]+',r'\w',r'\W',r'a\|\x00',r'\(a*\)\x00\1',
          r'(a*)\x00\1',r'\(.\)\1',r'(.)\1',r'[\x00-\x02]',r'\`',r"\'"]
checks=failures=0
for locale in ('C','C.UTF-8'):
    env=dict(os.environ,PATH='',LC_ALL=locale)
    for extended in (False,True):
        opts=['-E'] if extended else []
        for pattern in patterns:
            script='s/'+pattern+'/[&]/g'
            for subject in subjects:
                args=[*opts,script]
                got=subprocess.run([binary,'-c','sed "$@"','_',*args],input=subject,capture_output=True,env=env,timeout=10)
                ref=subprocess.run(['/usr/bin/sed',*args],input=subject,capture_output=True,env=env,timeout=10)
                checks+=1
                if (got.returncode,got.stdout)!=(ref.returncode,ref.stdout):
                    failures+=1
                    print('FAIL',locale,args,subject.hex(),(got.returncode,got.stdout.hex()),(ref.returncode,ref.stdout.hex()),got.stderr[:200],flush=True)
                assert b'AddressSanitizer' not in got.stderr and b'runtime error:' not in got.stderr,got.stderr
print(f'sol-sed-binary-regex: {checks} comparisons, {failures} failures',flush=True)
raise SystemExit(bool(failures))
