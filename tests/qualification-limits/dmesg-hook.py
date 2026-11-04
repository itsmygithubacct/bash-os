#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Proposed hook oracle: the fixture read-clear path must not call syslog."""
import argparse
import os
from pathlib import Path
import signal
import tempfile
from guest import clean_env, digest, entrypoint, guard, require_bash_5320, run, save

FILTER_SHA256='16e931bf4c2933b468c6d9484a6b0c9258135901fe084d5a229a83f677757aac'


def main():
    p=argparse.ArgumentParser();p.add_argument('shell');p.add_argument('seccomp_helper')
    p.add_argument('reference_dmesg');p.add_argument('output');p.add_argument('--module')
    a=p.parse_args();guard()
    bash_version = require_bash_5320(a.shell)
    fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if os.geteuid()==0 or int(fields['CapEff'].strip(),16):
        raise RuntimeError('run this hook control as the unprivileged fixture user without capabilities')
    if digest(a.seccomp_helper)!=FILTER_SHA256:raise RuntimeError('review required: seccomp helper changed')
    prefix=['/usr/bin/python3',a.seccomp_helper,'--kill','syslog','--']
    control=run(prefix+[a.reference_dmesg,'-C'])
    setup=('[[ $(type -t dmesg || :) != builtin ]] || exit 125\nenable -f "$1" dmesg || exit 125\n') if a.module else (
           '[[ $(type -t dmesg || :) == builtin ]] || exit 125\n')
    with tempfile.TemporaryDirectory(prefix='qual-kmsg-hook-') as td:
        source=Path(td)/'record';source.write_bytes(b'14,1,1000000,-;hook record\n')
        env=clean_env();env['BASHDMESG_DEV_KMSG_FILE']=str(source)
        candidate=run(prefix+[a.shell,'--noprofile','--norc','-c',setup+'builtin dmesg -c -t',
                              'qualification',a.module or ''],env=env)
        unchanged=source.read_bytes()==b'14,1,1000000,-;hook record\n'
    controls=control['status']==128+signal.SIGSYS and not control['stdout_hex']
    matches=candidate['status']==0 and candidate['stdout_hex']==b'hook record\n'.hex() and not candidate['stderr_hex'] and unchanged
    result='ERROR' if not controls or candidate['status'] in (125,126,127) else ('PASS' if matches else 'FAIL')
    save(a.output,dict(scope='proposed 0.1.4 candidate-only fixture hook invariant; no live ring access',result=result,
                       bash_version=bash_version,
                       shell_sha256=digest(a.shell),module_sha256=digest(a.module) if a.module else None,
                       reference_sha256=digest(a.reference_dmesg),filter_sha256=FILTER_SHA256,
                       negative_control=control,candidate=candidate,input_unchanged=unchanged))
    return {'PASS':0,'FAIL':1,'ERROR':125}[result]


if __name__=='__main__':entrypoint(main)
