#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Public key-definition API controls; temporal contracts use wgetch-runtime."""
import argparse
from guest import digest, entrypoint, guard, require_bash_5320, run, save


def main():
    p=argparse.ArgumentParser();p.add_argument('shell');p.add_argument('output');p.add_argument('--module')
    a=p.parse_args();guard()
    bash_version = require_bash_5320(a.shell)
    setup = ('[[ $(type -t wgetch || :) != builtin ]] || exit 125\n'
             'enable -f "$1" wgetch || exit 125\n') if a.module else (
             '[[ $(type -t wgetch || :) == builtin ]] || exit 125\n')
    definitions = "wgetch define-key custom_short 1792 $'\\e[9'\nwgetch define-key custom_long 1793 $'\\e[9~'\n"
    cases=[('long',definitions+'wgetch read 0\n',b'\x1b[9~',b'custom_long 1793\n'),
           ('short',definitions+'wgetch read 0\n',b'\x1b[9',b'custom_short 1792\n'),
           ('default', 'wgetch read 0\n',b'\x1b[A',b'key_up 257\n'),
           ('absent_pair','wgetch read 0\n',b'\x1b[9~',b'esc 27\n'),
           ('removed',definitions+'wgetch undefine-key custom_long\nwgetch undefine-key custom_short\nwgetch read 0\n',b'\x1b[9~',b'esc 27\n')]
    # Failure is checked before proceeding; no accepted definition is overwritten.
    contract = definitions + r'''
bad() { "$@" 2>/dev/null; test "$?" = 2; }
bad wgetch define-key duplicate 1800 $'\e[9'
bad wgetch define-key custom_short 1800 $'\e[8'
bad wgetch define-key duplicate 1792 $'\e[8'
bad wgetch define-key duplicate 1800 $'\e[A'
bad wgetch define-key char 1800 $'\e[8'
bad wgetch define-key invalid 12 $'\e[8'
bad wgetch define-key invalid 65536 $'\e[8'
bad wgetch define-key 'bad name' 1800 $'\e[8'
bad wgetch define-key invalid 1800 plain
bad wgetch define-key invalid 1800 $'\e'
bad wgetch define-key invalid 1800 $'\e[8' extra
wgetch read 0
'''
    # Deliberately omit errexit inside the bad() function so status 2 is visible.
    contract=contract.replace('bad() { "$@" 2>/dev/null; test "$?" = 2; }',
                              'bad() { local rc=0; "$@" 2>/dev/null || rc=$?; test "$rc" = 2; }')
    cases.append(('validation',contract,b'\x1b[9~',b'custom_long 1793\n'))
    full=''
    for i in range(32): full+=f"wgetch define-key custom_{i} {2048+i} $'\\eZ{i:02d}'\n"
    full+="rc=0; wgetch define-key overflow 3000 $'\\eZ32' 2>/dev/null || rc=$?\n[[ $rc == 1 ]]\n"
    full+="wgetch undefine-key custom_0\nwgetch define-key replacement 3000 $'\\eZ32'\nwgetch read 0\n"
    cases.append(('capacity',full,b'\x1bZ32',b'replacement 3000\n'))
    rows=[]
    for name,script,data,want in cases:
        r=run([a.shell,'--noprofile','--norc','-c','set -eu\n'+setup+script,'qualification',a.module or ''],data)
        r.update(case=name,expected_hex=want.hex(),matches=r['status']==0 and not r['stderr_hex'] and r['stdout_hex']==want.hex())
        rows.append(r)
    result='PASS' if all(r['matches'] for r in rows) else 'FAIL'
    if any(r['status'] in (125,126,127) for r in rows):result='ERROR'
    save(a.output,dict(scope='0.1.4 public key-definition interface; no timing/physical claim',result=result,
                       bash_version=bash_version,
                       shell_sha256=digest(a.shell),module_sha256=digest(a.module) if a.module else None,observations=rows))
    return {'PASS':0,'FAIL':1,'ERROR':125}[result]


if __name__=='__main__':entrypoint(main)
