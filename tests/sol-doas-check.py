#!/usr/bin/env python3
"""Noncompiling fixture checks, plus optional native shell entry-point checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile

p=argparse.ArgumentParser()
p.add_argument('--fixture',type=Path)
p.add_argument('--shell',type=Path)
a=p.parse_args()
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
assert a.fixture or a.shell, 'select --fixture and/or --shell'
if a.fixture:
    fixture=a.fixture.resolve()
    for case in ['root','authority','edit','copyback']:
        with tempfile.TemporaryDirectory(prefix='sol-doas-check-') as scratch:
            proc=subprocess.run([str(fixture),case],env={**os.environ,'SOL_DOAS_TMPDIR':scratch},capture_output=True,timeout=60)
        print(case, 'exit', proc.returncode, proc.stdout.decode(), proc.stderr.decode(),flush=True)
        assert proc.returncode==0
    # Independent request-digest oracle: little-endian integers + counted strings +
    # literal NUL-packed argv/environment, as specified by the production wire format.
    av=b'/bin/true\0'
    env=b'BASHOS_CALLER_SAFE=caller\0BASHOS_CALLER_LD_PRELOAD=caller\0BASHOS_CALLER_BASH_ENV=caller\0'
    # mode EXEC=1, non-interactive=1, fixture target uid/gid=4242/4343.
    values=[1,0,1,os.getuid(),os.getgid(),4242,4343,1,3,len(av),len(env)]
    # The existing v1 wire format hashes exactly 16 domain bytes (also auth.c).
    blob=b'bashos-privcmd-v'+struct.pack('<11I',*values)
    for text in [str(os.getuid()).encode(),b'fixture',os.getcwd().encode()]:
        blob+=struct.pack('<I',len(text))+text
    expected=hashlib.sha256(blob+av+env).hexdigest()
    proc=subprocess.run([str(fixture),'--digest'],capture_output=True,check=True,text=True)
    assert proc.stdout.strip()==expected,(proc.stdout,expected)
    print('independent request SHA-256 oracle passed',flush=True)
if a.shell:
    assert os.geteuid()!=0 and not Path('/dev/bashos-auth').exists(), 'native fallback checks require a non-root host without the authority; run mandatory fixtures separately'
    shell=a.shell.resolve()
    with tempfile.TemporaryDirectory(prefix='sol-doas-native-') as tmp:
        tmp=Path(tmp)
        delegate=tmp/'delegate'
        delegate.write_text('''#!/usr/bin/python3
import json, os, sys
if os.environ.get('FIXTURE_DENY') == '1': sys.exit(1)
fds=[]
for fd in range(3,512):
 try: os.fstat(fd); fds.append(fd)
 except OSError: pass
print(json.dumps({'argv':sys.argv[1:], 'uid':os.getuid(), 'gid':os.getgid(), 'fds':fds}))
''')
        delegate.chmod(0o700)
        def shell_run(script,rc=0,extra=None):
            env={**os.environ,'BASHDOAS_EXTERNAL':str(delegate),'LC_ALL':'C',**(extra or {})}
            proc=subprocess.run([str(shell),'--noprofile','--norc','-c','PATH=; '+script],env=env,capture_output=True,timeout=30)
            assert proc.returncode==rc,(script,proc.returncode,proc.stdout,proc.stderr)
            return proc.stdout
        for command in ['doas','sudo','su']:
            shell_run(f'{command} --invalid-fixture-option',2)
        for command in ['doas','sudo']:
            assert shell_run(f'{command} --version')==f'{command} 0.1\n'.encode()
            shell_run(f'{command} --version >/dev/full',1)
            shell_run(f'{command} --help >/dev/full',1)
            assert shell_run(f'{command} --version >/dev/full; {command} --version')==f'{command} 0.1\n'.encode()
            # Real fallback, with owned external delegate: no setuid or accounts.
            rows=shell_run(f'exec 200</dev/null; {command} -n -- /bin/echo "literal ; $(printf no)" ""; {command} -n -- /bin/echo again; [[ -r /proc/$$/fd/200 ]]').splitlines()
            decoded=[json.loads(row) for row in rows]
            assert decoded[0]==dict(argv=['-n','--','/bin/echo','literal ; no',''],uid=os.getuid(),gid=os.getgid(),fds=[]),decoded
            assert decoded[1]['argv']==['-n','--','/bin/echo','again'] and not decoded[1]['fds']
            shell_run(f'{command} -n -- /bin/true',1,{'FIXTURE_DENY':'1'})
        print('native doas/sudo/su entries, repeated calls, empty PATH, output failures and owned fallback passed')
print('sol-doas checks passed; live authority qualification is unavailable on this host')
