#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Compare man-db query meaning on a private page set, retaining raw output."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker))!=marker.lower(): raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('wrong uid')
        if Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home': raise ValueError('wrong scratch directory')
    except (OSError,ValueError,UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: '+str(exc))


require_guest()
HOME=Path('/tmp/parity-home')
GUARD=r'''[[ $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r v </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r u </etc/bashos-parity-vm || exit 125
[[ $v == QEMU && $u =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
'''
QUERIES={'regex-dot':(['--','al.ha'],['first apple']), 'regex-anchor':(['--','^alp'],['first apple']),
         'or':(['--','alpha','beta'],['first apple','second berry']),
         'alias':(['-w','--','aleph'],['first apple']), 'glob':(['-w','--','alp*'],['first apple']),
         'dash':(['--','-x'],['option -x feature'])}


def descriptions(data):
    text=data.decode('utf8','strict');out=[]
    for line in text.splitlines():
        m=re.fullmatch(r'.*\(1\)\s+-\s+(.+)',line)
        if not m: raise ValueError('unrecognized query result: '+repr(line))
        out.append(m.group(1))
    return sorted(set(out))


def write(name,data):
    (HOME/name).write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')


def control():
    sample=b'alpha, aleph (1) - first apple\nbeta (1) - second berry\n'
    got=descriptions(sample)
    bad=descriptions(sample.replace(b'second berry',b'altered'))
    checks={'known_records':got==['first apple','second berry'],
            'mutated_record_detected':bad!=got}
    write('apropos-parser-control.json',{'input_base64':base64.b64encode(sample).decode(),'decoded':got,'mutated':bad,'checks':checks})
    if not all(checks.values()): raise AssertionError('parser control failed')
    print('query parser controls ok')


def query(side,shell,mode):
    args,expected=QUERIES[mode]
    if side=='reference': command=['/usr/bin/apropos','-M',str(HOME/'man')]+args
    else: command=[shell,'--noprofile','--norc','-c',GUARD+'export MANPATH="$PWD/man" BASHMAN_STALE_QUIET=1\napropos "$@"\n','apropos-fixture']+args
    p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if len(p.stdout)>65536 or len(p.stderr)>65536: raise RuntimeError('query output exceeded bound')
    parsed=None;error=None
    try: parsed=descriptions(p.stdout)
    except (UnicodeError,ValueError) as exc: error=str(exc)
    checks={'status_zero':p.returncode==0,'stderr_empty':p.stderr==b'','expected_descriptions':parsed==expected,'parse_complete':error is None}
    write('apropos-query.json',{'mode':mode,'side':side,'command':command,'status':p.returncode,
          'stdout_base64':base64.b64encode(p.stdout).decode(),'stderr_base64':base64.b64encode(p.stderr).decode(),
          'descriptions':parsed,'parse_error':error,'expected':expected,'checks':checks})
    if not all(checks.values()): raise AssertionError('query mismatch: '+repr(checks))
    print(mode+': ok')


if sys.argv[1:]==['--control']: control()
elif len(sys.argv)==4 and sys.argv[1] in ('candidate','reference') and sys.argv[3] in QUERIES:
    side,shell,mode=sys.argv[1:]
    if side=='candidate' and shell!='/opt/bashos-parity/candidate': raise SystemExit('candidate path refused')
    if side=='reference' and shell!='/opt/bash-5.3.15/bin/bash': raise SystemExit('reference path refused')
    query(side,shell,mode)
else: raise SystemExit('invalid invocation')
