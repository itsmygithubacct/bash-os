#!/usr/bin/python3
"""VM-only signed file:// repository and independently encoded delta data."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import uuid


HOME=Path('/tmp/parity-home')
FIX=HOME/'pkg-fixture'
REPO=HOME/'repository'
KEYID=bytes.fromhex('1032547698badcfe')


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        case=Path('/tmp/parity-case')
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(HOME)
                or Path.cwd().resolve() != case or case.stat().st_uid != 2000
                or HOME.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sign(path):
    raw=HOME/(path.name+'.independent-signature')
    subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-rawin','-inkey',str(FIX/'publisher.key'),'-in',str(path),'-out',str(raw)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    verified=subprocess.run(['/usr/bin/openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(FIX/'publisher.der'),'-keyform','DER','-in',str(path),'-sigfile',str(raw)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    signature=raw.read_bytes()
    Path(str(path)+'.sig').write_text('untrusted comment: repository fixture\n'+base64.b64encode(b'Ed'+KEYID+signature).decode()+'\n')
    event={'file':str(path.relative_to(REPO)), 'message_sha256':sha(path.read_bytes()),
           'keyid_hex':KEYID.hex(), 'public_der_base64':base64.b64encode((FIX/'publisher.der').read_bytes()).decode(),
           'signature_base64':base64.b64encode(signature).decode(), 'verify_status':verified.returncode,
           'verify_stdout':verified.stdout.decode(errors='replace'), 'verify_stderr':verified.stderr.decode(errors='replace')}
    with (HOME/'repository-control.jsonl').open('a',encoding='utf-8') as stream:
        stream.write(json.dumps(event,sort_keys=True)+'\n')


def capture(phase):
    if phase not in ('before','after'):
        raise ValueError('unexpected repository capture phase')
    public={}
    for path in sorted(REPO.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        content=path.read_bytes()
        public[str(path.relative_to(REPO))]={'size':len(content),'sha256':sha(content),
                                            'bytes_base64':base64.b64encode(content).decode()}
    evidence=json.dumps(public,sort_keys=True).encode()+b'\n'
    if len(evidence)>950*1024:
        raise ValueError('repository public evidence exceeds diagnostic capture budget')
    (HOME/('repository-evidence-'+phase+'.json')).write_bytes(evidence)


def main():
    arch=platform.machine(); directory=REPO/arch; directory.mkdir(parents=True)
    old=(FIX/'valid.pkg').read_bytes(); new=(FIX/'v2.pkg').read_bytes()
    package='fixtureprobe-2.pkg'; delta=package+'.delta'
    (directory/package).write_bytes(new)
    shutil.copyfile(FIX/'v2.pkg.sig',directory/(package+'.sig'))
    prefix=0
    while prefix<min(len(old),len(new)) and old[prefix]==new[prefix]: prefix+=1
    suffix=0
    while suffix<min(len(old)-prefix,len(new)-prefix) and old[-1-suffix]==new[-1-suffix]: suffix+=1
    insertion=new[prefix:len(new)-suffix if suffix else len(new)]
    delta_data=('BPKGDELTA1\n'+sha(old)+'\n'+sha(new)+'\n'+str(len(old))+'\n'+str(len(new))+'\n'+str(prefix)+'\n'+str(suffix)+'\n'+str(len(insertion))+'\n').encode()+insertion
    assert old[:prefix]+insertion+(old[len(old)-suffix:] if suffix else b'')==new
    patch=directory/delta; patch.write_bytes(delta_data); sign(patch)
    text=(f'pkg-loadable-v1 name=fixtureprobe version=2 builtin=fixtureprobe abi=bash-5.3 arch={arch} '
          f'package={package} sha256={sha(new)} sig={package}.sig deps=- '
          f'delta={delta} delta_sig={delta}.sig delta_from={sha(old)} delta_to={sha(new)}\n')
    index=directory/'INDEX'; index.write_text(text); sign(index)
    (HOME/'sources.list').write_text('file://'+str(REPO)+'\n')
    capture('before')
    print('repository control: signed per-architecture index, signed delta and independent old-to-new reconstruction')


if __name__=='__main__':
    require_guest()
    if len(sys.argv)==1:
        main()
    elif len(sys.argv)==3 and sys.argv[1]=='resign':
        target=Path(sys.argv[2]).resolve()
        if REPO.resolve() not in target.parents or not target.is_file():
            raise ValueError('refuse non-fixture signature target')
        sign(target)
    elif len(sys.argv)==2 and sys.argv[1]=='capture-after':
        capture('after')
    else:
        raise SystemExit('unexpected repository helper arguments')
