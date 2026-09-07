#!/usr/bin/env python3
"""Independent proc ABI fixtures for the MIT snapshot implementation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary=str(Path(sys.argv[1] if len(sys.argv)>1 else 'out/bash').resolve())
checks=0
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp); (root/'42').mkdir()
    env={**os.environ,'LC_ALL':'C','BASHOS_PROC_ROOT':tmp}
    if os.environ.get('PROCSTAT_LOAD_ENV'):
        env.update(BASH_ENV=os.environ['PROCSTAT_LOAD_ENV'],LD_PRELOAD=os.environ['PROCSTAT_ASAN_LIB'],
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    def run(*args,rc=0):
        global checks
        p=subprocess.run([binary,'-c','PATH=; procstat "$@"','_',*args],capture_output=True,env=env,timeout=5)
        assert p.returncode==rc,(args,p.returncode,p.stderr)
        assert b'runtime error:' not in p.stderr and b'AddressSanitizer' not in p.stderr,p.stderr
        checks+=1;return p.stdout.decode()
    (root/'uptime').write_text('100.0 25.0\n')
    (root/'stat').write_text('cpu 40 10 20 20 5 2 2 1 5 2\ncpu0 40 10 20 20 5 2 2 1 5 2\nintr 42\n')
    (root/'diskstats').write_text('8 0 sda 10 0 200 1 20 0 400 2 0 3 4\n')
    cpu=run('mpstat').splitlines()
    assert cpu[1].split()==['all','35.00','8.00','20.00','5.00','2.00','2.00','1.00','5.00','2.00','20.00']
    assert len(run('mpstat','-P','ALL').splitlines())==3
    assert run('sar','-u')=='\n'.join(cpu)+'\n'
    assert run('iostat','-d').splitlines()[1].split()==['sda','0.30','1.00','2.00','100.0','200.0']
    hz=os.sysconf('SC_CLK_TCK');pagesize=os.sysconf('SC_PAGESIZE')
    fields=['0']*21
    for field,value in {4:1,14:2*hz,15:hz,20:3,22:50*hz,23:65536,24:4}.items():fields[field-4]=str(value)
    raw='42 (fixture ) with spaces) S '+' '.join(fields)+'\n';(root/'42/stat').write_text(raw)
    report=run('prtstat','42')
    for fragment in ['fixture ) with spaces','Parent: 1','Threads: 3','User seconds: 2.00',f'Resident KiB: {4*pagesize//1024}']:
        assert fragment in report,report
    assert run('prtstat','-r','42')==raw
    assert run('pidstat','-p','42').splitlines()[1].split()[:5]==['42','4.00','2.00','6.00',str(4*pagesize//1024)]
    assert run('pidstat')==run('pidstat','-p','42')
    (root/'42/maps').write_text('1000-2000 r-xp 00000000 08:01 1 /lib/fixture.so.1\n'
                              '2000-3000 r--p 00001000 08:01 1 /lib/fixture.so.1\n'
                              '4000-6000 rw-p 00000000 00:00 0 [heap]\n')
    assert run('pmap','42').endswith('total 16K\n')
    assert '0000000000001000 /lib/fixture.so.1' in run('pmap','-x','42')
    assert run('pldd','42')=='42:\n/lib/fixture.so.1\n'
    for args in [('prtstat','../42'),('pidstat','-p','0'),('pmap','-x'),('mpstat','2'),('unknown',)]:run(*args,rc=2)
    run('prtstat','43',rc=1)
    (root/'42/stat').write_text('42 (bad) S 1\n');run('prtstat','42',rc=1)
    (root/'42/maps').write_text('broken\n');run('pmap','42',rc=1)
    (root/'diskstats').write_text('broken\n');run('iostat',rc=1)
    (root/'stat').write_text('cpu bad\n');run('mpstat',rc=1)
print(f'procstat-smoke: {checks} checks passed')
