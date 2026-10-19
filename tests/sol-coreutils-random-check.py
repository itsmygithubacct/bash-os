#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact entropy-read fixtures for the production sanitizer module.

Run via sol-coreutils-sanitize.sh; native, unwrapped entropy is separately
covered by sol-coreutils-check.py's invariants.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = {**os.environ, 'PATH':'', 'LC_ALL':'C',
       'BASH_ENV':os.environ['COREUTILS_TEST_LOAD'],
       'LD_PRELOAD':os.environ['COREUTILS_TEST_ASAN']}
checks = 0
with tempfile.TemporaryDirectory(prefix='sol-coreutils-entropy-') as tmp:
    d=Path(tmp); target=d/'target'; seed=d/'entropy'
    data=bytes(range(256))*1024
    env['SOL_COREUTILS_RANDOM_FIXTURE']=str(seed)
    def run(args, success=True):
        global checks
        p=subprocess.run([binary,'-c','coreutils "$@"','_',*map(str,args)],env=env,
                         capture_output=True,timeout=20)
        assert (p.returncode==0)==success,(args,p.returncode,p.stderr)
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr,p.stderr
        if not success: assert p.stderr
        checks+=1
        return p
    for size in [1,8191,8192,8193,65537]:
        for passes in [1,2]:
            seed.write_bytes(data); target.write_bytes(b'x'*size)
            run(['shred','-n',passes,target])
            assert target.read_bytes()==data[size*(passes-1):size*passes]
    # Exhausting or failing the entropy source must retain the target, even
    # with -u: the real overwrite request must not turn into an unlink.
    for payload in [b'',b'short']:
        seed.write_bytes(payload); target.write_bytes(b'x'*8193)
        run(['shred','-n','1','-u',target],success=False)
        assert target.exists()
    seed.unlink(); target.write_bytes(b'x'*8193)
    run(['shred','-n','1','-u',target],success=False)
    assert target.read_bytes()==b'x'*8193
    seed.write_bytes(bytes(range(1,9)))
    p=run(['shuf','-i','1-10'])
    assert p.stdout==b'10\n8\n2\n5\n9\n6\n4\n7\n3\n1\n'
print(f'sol-coreutils-random: {checks} production entropy fixture checks passed')
