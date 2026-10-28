#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guarded guest-only independent Argon2 CLI oracle for synthetic fixtures."""
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case')


def guard():
    if not __debug__:raise SystemExit(125)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.geteuid()!=2000 or Path.cwd()!=CASE:raise SystemExit(125)


def derive(password,salt,t,m,p,n,record):
    guard()
    if not isinstance(password,bytes) or not isinstance(salt,bytes) or not all(type(x) is int and x>0 for x in (t,m,p,n)):
        raise ValueError('invalid Argon2 oracle inputs')
    if b'\0' in salt:
        record('argon2-oracle-unavailable',reason='CLI cannot represent a NUL byte in argv salt',salt_base64=base64.b64encode(salt).decode(),t=t,m=m,p=p,n=n)
        raise RuntimeError('independent Argon2 CLI cannot represent a NUL-containing salt')
    argv=[b'/usr/bin/argon2',salt,b'-id',b'-t',str(t).encode(),b'-k',str(m).encode(),b'-p',str(p).encode(),b'-l',str(n).encode()]
    runs=[]
    for mode in (b'-r',b'-e'):
        try:
            result=subprocess.run(argv+[mode],input=password,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        except (OSError,subprocess.TimeoutExpired) as error:
            record('argon2-oracle-error',mode=mode.decode(),error=repr(error),salt_base64=base64.b64encode(salt).decode(),t=t,m=m,p=p,n=n)
            raise RuntimeError('independent Argon2 CLI failed to run') from error
        runs.append(result)
    raw,encoded=runs
    record('argon2-cli',password_base64=base64.b64encode(password).decode(),salt_base64=base64.b64encode(salt).decode(),
           t=t,m=m,p=p,n=n,raw_status=raw.returncode,raw_stdout_base64=base64.b64encode(raw.stdout).decode(),
           raw_stderr_base64=base64.b64encode(raw.stderr).decode(),encoded_status=encoded.returncode,
           encoded_stdout_base64=base64.b64encode(encoded.stdout).decode(),encoded_stderr_base64=base64.b64encode(encoded.stderr).decode())
    if raw.returncode!=0 or encoded.returncode!=0 or raw.stderr or encoded.stderr:
        raise RuntimeError('independent Argon2 CLI returned an error')
    if not re.fullmatch(rb'[0-9a-f]{%d}\n'%(2*n),raw.stdout):
        raise RuntimeError('independent Argon2 CLI returned malformed raw output')
    digest=bytes.fromhex(raw.stdout[:-1].decode('ascii'))
    expected=(b'$argon2id$v=19$m='+str(m).encode()+b',t='+str(t).encode()+b',p='+str(p).encode()+b'$'+
              base64.b64encode(salt).rstrip(b'=')+b'$'+base64.b64encode(digest).rstrip(b'=')+b'\n')
    if encoded.stdout!=expected:
        raise RuntimeError('independent Argon2 CLI raw and standard-PHC outputs disagree')
    return digest


if __name__=='__main__':
    guard()
    sys.exit(125)
