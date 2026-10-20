#!/usr/bin/env python3
"""Noncompiling sanitizer driver for the harness built by sol-pgrep-tools-build.sh."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

spec=importlib.util.spec_from_file_location('pgrep_bench',Path(__file__).resolve().parents[1]/'bench/sol-pgrep.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
binary=str(Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory(prefix='sol-pgrep-asan-') as tmp:
    root=Path(tmp)
    module.fixture(root)
    special=root/'900512'
    special.mkdir()
    (special/'comm').write_text('multiline\n')
    (special/'cmdline').write_bytes(b'multiline\0line1\nline2\0')
    env=dict(os.environ,BASHOS_PROC_ROOT=tmp,SOL_PGREP_REPEAT='100',
             ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    cases=[('pgrep',['-fx','multiline line1 line2'],'900512\n',0),
           ('pgrep',['-c','worker[0-9]{3}'],'511\n',0),
           ('pgrep',['-c','-x','worker000|kthreadd'],'2\n',0),
           ('pgrep',['-c','-u2001','-G3001','-P77','-s99','^worker(0[0-9][0-9]|1[0-9][0-9])$'],'34\n',0),
           ('pgrep',['-f','-c','--','--task [0-9]+$'],'512\n',0),
           ('pgrep',['-nc','worker'],'1\n',0),
           ('pgrep',['-o','worker'],'900000\n',0),
           ('pgrep',['['],'',2),('pgrep',['-x','['],'',2),
           ('pgrep',['-P','-1'],'',2),('pgrep',['-u','999999999999999999999999999999'],'',2),
           ('pgrep',['-s','1,'],'',2),('pgrep',['-no','a'],'',2),
           ('pkill',['['],'',2),('pkill',['-USR1','worker'],'',3),
           ('pkill',['-URG','worker'],'',3),('pkill',['-PIPE','worker'],'',3),
           ('pkill',['-PWR','worker'],'',3),
           ('killall',['['],'',3),('killall5',['-TERM'],'',3)]
    for cmd,args,expected,status in cases:
        p=subprocess.run([binary,cmd,*args],env=env,text=True,capture_output=True,timeout=60)
        assert (p.returncode,p.stdout)==(status,expected*100),(cmd,args,p.returncode,p.stdout[:100],p.stderr[-1000:])
        assert 'AddressSanitizer' not in p.stderr and 'runtime error:' not in p.stderr,p.stderr
    with open('/dev/full','w') as full:
        p=subprocess.run([binary,'pgrep','-c','worker'],env=env,stdout=full,stderr=subprocess.PIPE,text=True,timeout=60)
        assert p.returncode==3 and 'AddressSanitizer' not in p.stderr and 'runtime error:' not in p.stderr,p
print(f'PASS: {len(cases)+1} ASan/UBSan cases, each repeated 100 times with leak detection')
