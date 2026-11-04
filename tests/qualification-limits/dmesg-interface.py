#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""0.1.4 decoder/option contracts on fixture input, separate from live records."""
import argparse
from pathlib import Path
import tempfile
from guest import clean_env, digest, entrypoint, guard, require_bash_5320, run, save


def main():
    p=argparse.ArgumentParser();p.add_argument('shell');p.add_argument('output');p.add_argument('--module')
    a=p.parse_args();guard()
    bash_version = require_bash_5320(a.shell)
    setup=('[[ $(type -t dmesg || :) != builtin ]] || exit 125\nenable -f "$1" dmesg || exit 125\nshift\n') if a.module else (
           '[[ $(type -t dmesg || :) == builtin ]] || exit 125\nshift\n')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='qual-dmesg-') as td:
        source=Path(td)/'records'
        source.write_bytes(b'14,1,1000000,-;first\n11,2,2000000,-;second\n6,3,3000000,-;kernel\n134,4,4000000,-;local\n')
        large=Path(td)/'large-record'
        large.write_bytes(b'14,1,1000000,-;'+b'A'*70000+b'\n')
        env=clean_env();env['BASHDMESG_DEV_KMSG_FILE']=str(source)
        cases=[('plain',['-t'],0,b'first\nsecond\nkernel\nlocal\n',b''),
               ('decode',['-f','user','-x','-t'],0,b'user  :info  : first\nuser  :err   : second\n',b''),
               ('decode-level',['-x','-t','-l','err'],0,b'user  :err   : second\n',b''),
               ('local-facility',['-x','-t','-f','local0'],0,b'local0:info  : local\n',b''),
               ('raw',['-r','-f','user'],0,b'<14>[    1.000000] first\n<11>[    2.000000] second\n',b''),
               ('raw-notime',['-r','-t'],1,b'',b'dmesg: mutually exclusive arguments: --raw --notime\n'),
               ('notime-raw',['-t','-r'],1,b'',b'dmesg: mutually exclusive arguments: --raw --notime\n'),
               ('raw-decode',['-r','-x'],1,b'',b'dmesg: mutually exclusive arguments: --raw --decode\n'),
               ('stream-boundary',['-t'],0,b'A'*70000+b'\n',b'')]
        for name,args,status,want,error in cases:
            env['BASHDMESG_DEV_KMSG_FILE']=str(large if name=='stream-boundary' else source)
            r=run([a.shell,'--noprofile','--norc','-c',setup+'builtin dmesg "$@"','qualification',a.module or '']+args,env=env)
            # The builtin may include the shell's source-location prefix.
            observed_error=bytes.fromhex(r['stderr_hex'])
            if error and b'dmesg: ' in observed_error:
                observed_error=b'dmesg: '+observed_error.split(b'dmesg: ',1)[1]
            r.update(case=name,expected_hex=want.hex(),matches=r['status']==status and r['stdout_hex']==want.hex() and observed_error==error)
            rows.append(r)
        input_hash=digest(source)
        large_hash=digest(large)
    result='PASS' if all(r['matches'] for r in rows) else 'FAIL'
    if any(r['status'] in (125,126,127) for r in rows):result='ERROR'
    save(a.output,dict(scope='0.1.4 fixture decoder/flags; no live-ring or kernel-size claim',result=result,
                       bash_version=bash_version,
                       shell_sha256=digest(a.shell),module_sha256=digest(a.module) if a.module else None,
                       input_sha256=input_hash,large_stream_sha256=large_hash,observations=rows))
    return {'PASS':0,'FAIL':1,'ERROR':125}[result]


if __name__=='__main__':entrypoint(main)
