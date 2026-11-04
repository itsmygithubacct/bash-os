#!/usr/bin/env python3
"""Parse canonical Argon2id PHC and compare to independent OpenSSL KDF."""
import base64, pathlib, subprocess, sys

def guest_guard():
    assert pathlib.Path.cwd() == pathlib.Path('/tmp/parity-case')
    assert pathlib.Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert pathlib.Path('/etc/bashos-parity-vm').is_file()

def derive(password, salt, memory, time, lanes, n):
    command=['/usr/bin/openssl','kdf','-keylen',str(n),'-binary','-kdfopt','hexpass:'+password.hex(),'-kdfopt','hexsalt:'+salt.hex(),'-kdfopt','iter:'+str(time),'-kdfopt','memcost:'+str(memory),'-kdfopt','lanes:'+str(lanes),'-kdfopt','threads:'+str(lanes),'ARGON2ID']
    return subprocess.run(command,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20).stdout

def decode(value):
    raw=base64.b64decode(value+'='*((-len(value))%4),validate=True)
    assert base64.b64encode(raw).decode().rstrip('=')==value
    return raw

def verify(path, user, password):
    rows=[line.split(':') for line in pathlib.Path(path).read_text().splitlines() if line.split(':',1)[0]==user]
    assert len(rows)==1 and len(rows[0])==9
    x=rows[0][1].split('$'); assert len(x)==6 and x[:3]==['','argon2id','v=19']
    assert x[3]=='m=1024,t=1,p=1'
    salt,expected=decode(x[4]),decode(x[5]); assert len(salt)==16 and len(expected)==32
    assert derive(password,salt,1024,1,1,32)==expected

def main():
    guest_guard()
    kat=derive(b'password',b'somesalt',65536,2,1,32).hex()
    assert kat=='09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7'
    verify(sys.argv[1],sys.argv[2],pathlib.Path(sys.argv[3]).read_bytes().rstrip(b'\r\n'))
    print('canonical-base64-kdf=match')
if __name__=='__main__': main()
