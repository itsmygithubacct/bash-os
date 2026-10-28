#!/usr/bin/python3
"""VM-only independent package, Ed25519-signature and ABI fixture builder."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import uuid


BASE = Path('/tmp/parity-home/pkg-fixture')
KEYID = bytes.fromhex('1032547698badcfe')
FOREIGN_ID = bytes.fromhex('efcdab8967452301')
PREFIX = bytes.fromhex('302a300506032b6570032100')
PUBLIC_AUDIT = {'keys': {}, 'archive_controls': [], 'signature_controls': []}


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        case, home = Path('/tmp/parity-case'), Path('/tmp/parity-home')
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(home)
                or Path.cwd().resolve() != case or case.stat().st_uid != 2000
                or home.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)


def key(name, keyid):
    private, public = BASE/(name+'.key'), BASE/(name+'.der')
    command('/usr/bin/openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(private))
    command('/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout', '-outform', 'DER', '-out', str(public))
    der = public.read_bytes()
    assert len(der) == 44 and der[:12] == PREFIX
    PUBLIC_AUDIT['keys'][name] = {'keyid_hex': keyid.hex(), 'public_der_base64': base64.b64encode(der).decode()}
    return private, public, keyid, der[12:]


def archive(path, entries):
    with tarfile.open(path, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in entries:
            ti = tarfile.TarInfo(name)
            ti.mode, ti.size, ti.mtime = mode, len(data), 1
            tar.addfile(ti, io.BytesIO(data))
    with tarfile.open(path, 'r:') as tar:
        observed = [(m.name, tar.extractfile(m).read(), m.mode) for m in tar]
        assert observed == entries
    PUBLIC_AUDIT['archive_controls'].append({
        'package': path.name, 'result': 'equal',
        'members': [{'name': name, 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                     'mode': mode} for name, body, mode in observed]})


def sign(path, identity):
    private, public, keyid, _ = identity
    sig = BASE/(path.name+'.raw-signature')
    command('/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(private), '-in', str(path), '-out', str(sig))
    raw = sig.read_bytes()
    assert len(raw) == 64
    verified = command('/usr/bin/openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(public), '-keyform', 'DER', '-in', str(path), '-sigfile', str(sig))
    signature = 'untrusted comment: disposable fixture\n'+base64.b64encode(b'Ed'+keyid+raw).decode()+'\n'
    Path(str(path)+'.sig').write_text(signature)
    PUBLIC_AUDIT['signature_controls'].append({
        'package': path.name, 'message_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'keyid_hex': keyid.hex(), 'signature_base64': base64.b64encode(raw).decode(),
        'verify_status': verified.returncode, 'verify_stdout': verified.stdout.decode(errors='replace'),
        'verify_stderr': verified.stderr.decode(errors='replace')})


def digest(b):
    return hashlib.sha256(b).hexdigest()


def manifest(elf, version='1', missing=None, abi='bash-5.3', arch=None, checksum=None, data=None, builtin='fixtureprobe'):
    values = {'type':'loadable','name':'fixtureprobe','version':version,'builtin':builtin,
              'abi':abi,'arch':arch or platform.machine(),'sha256':checksum or digest(elf)}
    fields = ''.join(f'{k}: {v}\n' for k,v in values.items() if k != missing)
    if data:
        for name, body in data.items():
            fields += f'data: {name} 0644 {digest(body)}\n'
    return fields.encode()


def main():
    assert os.getuid() != 0 and Path.cwd() == Path('/tmp/parity-case')
    BASE.mkdir(mode=0o700, parents=True, exist_ok=False)
    (BASE/'trusted').mkdir()
    pub = key('publisher', KEYID)
    foreign = key('foreign', FOREIGN_ID)
    (BASE/'trusted/publisher.pub').write_text('untrusted comment: fixture public key\n'+base64.b64encode(b'Ed'+KEYID+pub[3]).decode()+'\n')
    (BASE/'revoked').write_text(KEYID.hex()+'\n')
    source = BASE/'probe.c'
    source.write_text('''typedef struct word_list WORD_LIST;
struct builtin { char *name; int (*function)(WORD_LIST *); int flags; char **doc; char *usage; void *handle; };
static int probe(WORD_LIST *w) { (void)w; return 0; }
static char *doc[] = { "fixture probe", 0 };
struct builtin fixtureprobe_struct = { "fixtureprobe", probe, 1, doc, "fixtureprobe", 0 };
''')
    elfpath = BASE/'probe.so'
    command('/usr/bin/gcc', '-fPIC', '-shared', '-nostdlib', str(source), '-o', str(elfpath))
    elf = elfpath.read_bytes()
    assert elf[:6] == b'\x7fELF\x02\x01' and int.from_bytes(elf[18:20], 'little') == 62
    syms = command('/usr/bin/readelf', '-sW', str(elfpath)).stdout
    assert b'fixtureprobe_struct' in syms
    PUBLIC_AUDIT['elf_control'] = {'sha256': digest(elf), 'class': elf[4], 'machine': int.from_bytes(elf[18:20], 'little'),
                                   'readelf_symbols': syms.decode(errors='replace')}
    d1 = {'share/fixtureprobe/config':'version-one\n'.encode(), 'libexec/fixtureprobe/data':'data-one\n'.encode()}
    d2 = {'share/fixtureprobe/config':'version-two\n'.encode()}

    def make(name, body=elf, meta=None, data=None, signer=pub):
        mf = meta or manifest(body, data=data)
        entries = [('MANIFEST', mf, 0o644), ('loadable/fixtureprobe.so', body, 0o755)]
        if data:
            entries += [(n, b, 0o644) for n,b in data.items()]
        target=BASE/(name+'.pkg')
        archive(target, entries)
        sign(target, signer)
        return target

    valid=make('valid', data=d1)
    (BASE/'installed.manifest').write_bytes(manifest(elf, data=d1))
    (BASE/'static.manifest').write_bytes(manifest(elf, builtin='echo'))
    make('v2', meta=manifest(elf, version='2', data=d2), data=d2)
    broken_data={'share/fixtureprobe/config':b'not-the-signed-data\n'}
    make('bad-data', meta=manifest(elf, version='2', data=d2), data=broken_data)
    make('foreign', data=d1, signer=foreign)
    shutil.copyfile(valid, BASE/'unsigned.pkg')
    tampered=BASE/'tampered.pkg'
    b=bytearray(valid.read_bytes()); b[-1] ^= 1; tampered.write_bytes(b)
    shutil.copyfile(Path(str(valid)+'.sig'), Path(str(tampered)+'.sig'))
    truncated=BASE/'truncated.pkg'; truncated.write_bytes(valid.read_bytes()[:517]); sign(truncated,pub)
    for field in ('name','version','builtin','abi','arch','sha256'):
        make('missing-'+field, meta=manifest(elf, missing=field))
    make('bad-sha',meta=manifest(elf,checksum='0'*64))
    make('bad-abi',meta=manifest(elf,abi='bash-4.4'))
    make('bad-arch',meta=manifest(elf,arch='not-this-architecture'))
    wrong=bytearray(elf); wrong[18:20]=(183).to_bytes(2,'little'); make('bad-machine',body=bytes(wrong))
    wrong=bytearray(elf); wrong[4]=1; make('bad-class',body=bytes(wrong))
    simple=BASE/'unsigned-info.pkg'
    archive(simple,[('MANIFEST', b'name: info-fixture\ntype: payload\nversion: 1\ndescription: independent\n',0o644)])

    def hook(stage, fail=False):
        s = ("printf '%s|%s|%s|%s|%s\\n' '"+stage+"' \"$BASHPKG_NAME\" \"$BASHPKG_VERSION\" \"$BASHPKG_PREFIX\" \"$BASHPKG_ROOT\" >> \"$BASHPKG_PREFIX/hook.log\"\n")
        return (s+('exit 7\n' if fail else 'exit 0\n')).encode()
    legacy_manifest=b'name: legacyprobe\nversion: 1\n'
    def legacy(name, fail=False):
        entries=[('MANIFEST',legacy_manifest,0o644),('files/etc/fixture.conf',b'legacy-data\n',0o644)]
        entries += [('hooks/'+h,hook(h,fail and h=='pre-install'),0o700)
                    for h in ('pre-install','post-install','pre-remove','post-remove')]
        p=BASE/(name+'.pkg'); archive(p,entries); sign(p,pub)
    legacy('legacy'); legacy('legacy-fail',True)
    PUBLIC_AUDIT['trusted_pub_text'] = (BASE/'trusted/publisher.pub').read_text()
    PUBLIC_AUDIT['revoked_key_ids'] = (BASE/'revoked').read_text()
    PUBLIC_AUDIT['packages'] = {}
    for package in sorted(BASE.glob('*.pkg')):
        body = package.read_bytes()
        signature = Path(str(package)+'.sig')
        PUBLIC_AUDIT['packages'][package.name] = {
            'size': len(body), 'sha256': digest(body), 'bytes_base64': base64.b64encode(body).decode(),
            'signature_text': signature.read_text() if signature.is_file() else None}
    evidence = json.dumps(PUBLIC_AUDIT, sort_keys=True).encode() + b'\n'
    if len(evidence) > 950 * 1024:
        raise ValueError('public package evidence exceeds diagnostic capture budget')
    (BASE/'public-evidence.json').write_bytes(evidence)
    print('fixture control: independent ustar round trips; OpenSSL verifies each Ed25519 signature; ELF class, machine and exported builtin symbol checked')


if __name__ == '__main__':
    require_guest()
    main()
