#!/usr/bin/python3
"""VM-only signed claude stand-in packages and an /etc overlay holding the trusted key.

Builds, under /tmp/parity-home/claude-fixture, a gcc-built claude.so stand-in
(builtin "claude" printing "claude-fixture 2", whose constructor appends one
line to /tmp/parity-home/load-marks recording pid, ppid and whether the
installed state and the installed .so already existed when it was loaded),
and bashclaude_*.pkg variants signed with an independent OpenSSL Ed25519 key:
valid, old (version 1), tampered, unsigned, foreign signer, wrong ABI, wrong
architecture, wrong digest and one whose .so lacks the claude_struct symbol.
Every signature and every manifest field is cross-checked with OpenSSL, the
tarfile module and readelf before the candidate sees anything.
"""
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

HOME = Path('/tmp/parity-home')
BASE = HOME / 'claude-fixture'
KEYID = bytes.fromhex('2143658709badcfe')
FOREIGN_ID = bytes.fromhex('fedcba9876543210')
PREFIX = bytes.fromhex('302a300506032b6570032100')
AUDIT = {'keys': {}, 'packages': {}, 'controls': []}


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        case = Path('/tmp/parity-case')
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(HOME)
                or Path.cwd().resolve() != case or case.stat().st_uid != 2000
                or HOME.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def run(*args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def key(name, keyid):
    private, public = BASE / (name + '.key'), BASE / (name + '.der')
    run('/usr/bin/openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(private))
    run('/usr/bin/openssl', 'pkey', '-in', str(private), '-pubout', '-outform', 'DER', '-out', str(public))
    der = public.read_bytes()
    assert len(der) == 44 and der[:12] == PREFIX
    AUDIT['keys'][name] = {'keyid_hex': keyid.hex(), 'public_der_base64': base64.b64encode(der).decode()}
    return private, public, keyid, der[12:]


SOURCE = r'''
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
typedef struct word_list WORD_LIST;
struct builtin { char *name; int (*function)(WORD_LIST *); int flags; char **doc; char *usage; void *handle; };
static int fixture_claude(WORD_LIST *w) { (void)w; puts("claude-fixture 2"); return 0; }
static char *doc[] = { "claude stand-in fixture", 0 };
%(symbol)s
__attribute__((constructor)) static void mark(void) {
  char line[256];
  int state = access("/var/lib/pkg/installed/claude/sha256", R_OK) == 0;
  int so = access("/usr/lib/bash-os/loadables/claude.so", R_OK) == 0;
  int n = snprintf(line, sizeof line, "load pid=%%d ppid=%%d state=%%d so=%%d\n", (int)getpid(), (int)getppid(), state, so);
  int fd = open("/tmp/parity-home/load-marks", O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd >= 0) { if (write(fd, line, (size_t)n) < 0) { } close(fd); }
}
'''


def build_so(name, symbol):
    src = BASE / (name + '.c')
    src.write_text(SOURCE % {'symbol': symbol})
    out = BASE / (name + '.so')
    run('/usr/bin/gcc', '-fPIC', '-shared', str(src), '-o', str(out))
    elf = out.read_bytes()
    assert elf[:6] == b'\x7fELF\x02\x01' and int.from_bytes(elf[18:20], 'little') == 62
    syms = run('/usr/bin/readelf', '-sW', str(out)).stdout
    return elf, (b'claude_struct' in syms)


def manifest(elf, version='2', abi='bash-5.3', arch=None, checksum=None):
    values = {'type': 'loadable', 'name': 'claude', 'version': version, 'builtin': 'claude', 'abi': abi,
              'arch': arch or platform.machine(), 'sha256': checksum or digest(elf)}
    return ''.join(f'{k}: {v}\n' for k, v in values.items()).encode()


def archive(path, mf, elf):
    entries = [('MANIFEST', mf, 0o644), ('loadable/claude.so', elf, 0o755)]
    with tarfile.open(path, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in entries:
            ti = tarfile.TarInfo(name)
            ti.mode, ti.size, ti.mtime = mode, len(data), 1
            tar.addfile(ti, io.BytesIO(data))
    with tarfile.open(path, 'r:') as tar:
        observed = [(m.name, tar.extractfile(m).read(), m.mode) for m in tar]
    assert observed == entries
    fields = dict(line.split(': ', 1) for line in mf.decode().splitlines())
    AUDIT['packages'][path.name] = {'size': path.stat().st_size, 'sha256': digest(path.read_bytes()),
                                    'manifest': fields, 'so_sha256': digest(elf)}


def sign(path, ident):
    private, public, keyid, _ = ident
    raw = BASE / (path.name + '.raw')
    run('/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(private), '-in', str(path), '-out', str(raw))
    sig = raw.read_bytes()
    assert len(sig) == 64
    verified = run('/usr/bin/openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(public),
                   '-keyform', 'DER', '-in', str(path), '-sigfile', str(raw))
    Path(str(path) + '.sig').write_text('untrusted comment: claude fixture\n' + base64.b64encode(b'Ed' + keyid + sig).decode() + '\n')
    AUDIT['controls'].append({'package': path.name, 'signed_by': keyid.hex(), 'openssl_verify_rc': verified.returncode})


def make(name, so, mf, signer):
    target = BASE / ('bashclaude_' + name + '.pkg')
    archive(target, mf, so)
    sign(target, signer)
    return target


def main():
    BASE.mkdir(mode=0o700, parents=True, exist_ok=False)
    pub = key('publisher', KEYID)
    foreign = key('foreign', FOREIGN_ID)
    upper = BASE / 'etc-upper' / 'bashsignify' / 'trusted'
    upper.mkdir(parents=True)
    (upper / 'publisher.pub').write_text('untrusted comment: fixture public key\n' + base64.b64encode(b'Ed' + KEYID + pub[3]).decode() + '\n')
    elf, has = build_so('claude', 'struct builtin claude_struct = { "claude", fixture_claude, 1, doc, "claude", 0 };')
    assert has
    (BASE / 'valid.so.sha256').write_text(digest(elf) + '\n')
    noload, has2 = build_so('noload', 'int not_the_builtin_symbol;')
    assert not has2
    valid = make('valid', elf, manifest(elf), pub)
    make('old', elf, manifest(elf, version='1'), pub)
    shutil.copyfile(valid, BASE / 'bashclaude_unsigned.pkg')
    tampered = BASE / 'bashclaude_tampered.pkg'
    data = bytearray(valid.read_bytes())
    data[-1] ^= 1
    tampered.write_bytes(bytes(data))
    shutil.copyfile(str(valid) + '.sig', str(tampered) + '.sig')
    make('foreign', elf, manifest(elf), foreign)
    make('bad-abi', elf, manifest(elf, abi='bash-4.4'), pub)
    make('bad-arch', elf, manifest(elf, arch='not-this-architecture'), pub)
    make('bad-sha', elf, manifest(elf, checksum='0' * 64), pub)
    make('noload', noload, manifest(noload), pub)
    # independent controls on what the candidate will be asked to reject
    pk = BASE / 'bashclaude_tampered.pkg'
    bad = run('/usr/bin/openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(pub[1]), '-keyform', 'DER',
              '-in', str(pk), '-sigfile', str(BASE / 'bashclaude_valid.pkg.raw'), check=False)
    assert bad.returncode != 0
    AUDIT['controls'].append({'package': 'bashclaude_tampered.pkg', 'openssl_verify_rc_with_valid_signature': bad.returncode})
    assert not (BASE / 'bashclaude_unsigned.pkg.sig').exists()
    AUDIT['pubkey_in_overlay'] = (upper / 'publisher.pub').read_text()
    (BASE / 'public-evidence.json').write_text(json.dumps(AUDIT, sort_keys=True, indent=1) + '\n')
    print('claude fixture control: OpenSSL verifies every signature, tampering breaks the valid signature, ELF exports claude_struct')


if __name__ == '__main__':
    require_guest()
    main()
