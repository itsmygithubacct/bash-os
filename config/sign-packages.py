#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a pkg publisher key, or sign built packages into a release directory.

  keygen DIR NAME                              write DIR/NAME.pub and DIR/NAME.sec
  release --key NAME.sec --out DIR PKGDIR...   sign packages from build-packages.sh

Keys use the signify format that pkg verifies. The secret key has no
passphrase and is written with mode 0600, so keep it on the signing machine
only, never in a repository or a CI secret. A release directory holds every
package with its signature, one INDEX covering all architectures with its
INDEX.sig, and SHA256SUMS. Nothing is nested, so the directory can be uploaded
as the assets of one GitHub release.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RECORD = 'pkg-loadable-v1'
REQUIRED = ('name', 'version', 'builtin', 'abi', 'arch', 'package', 'sha256', 'sig', 'deps')
RAW = serialization.Encoding.Raw


def die(message):
    raise SystemExit(f'sign-packages: {message}')


def signify_text(comment, blob):
    return f'untrusted comment: {comment}\n{base64.b64encode(blob).decode()}\n'


def signify_blob(path, size):
    lines = Path(path).read_text().split('\n')
    if len(lines) < 2 or not lines[0].startswith('untrusted comment: '):
        die(f'{path} is not in signify format')
    try:
        blob = base64.b64decode(lines[1], validate=True)
    except ValueError:
        die(f'{path} is not in signify format')
    if len(blob) != size or blob[:2] != b'Ed':
        die(f'{path} is not an Ed25519 signify key')
    return blob


def keygen(directory, name):
    pub, sec = directory/f'{name}.pub', directory/f'{name}.sec'
    for path in (pub, sec):
        if path.exists():
            die(f'{path} exists; refusing to replace a key')
    directory.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = private.public_key().public_bytes(RAW, serialization.PublicFormat.Raw)
    keynum = os.urandom(8)
    secret = seed + public
    # signify's layout for a key without a passphrase: the "BK" KDF with zero
    # rounds leaves the key unmasked, behind a SHA-512 checksum prefix.
    blob = (b'EdBK' + (0).to_bytes(4, 'big') + os.urandom(16)
            + hashlib.sha512(secret).digest()[:8] + keynum + secret)
    with os.fdopen(os.open(sec, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
        handle.write(signify_text(f'{name} secret key', blob))
    pub.write_text(signify_text(f'{name} public key', b'Ed' + keynum + public))
    print(f'keygen: wrote {pub} and {sec} (key number {keynum.hex()})')


class Signer:
    def __init__(self, path):
        blob = signify_blob(path, 104)
        if blob[2:4] != b'BK':
            die(f'{path} is not a signify secret key')
        if int.from_bytes(blob[4:8], 'big') != 0:
            die(f'{path} is protected by a passphrase, which this tool does not read')
        checksum, self.keynum, secret = blob[24:32], blob[32:40], blob[40:]
        if hashlib.sha512(secret).digest()[:8] != checksum:
            die(f'{path} fails its checksum')
        self.private = Ed25519PrivateKey.from_private_bytes(secret[:32])
        self.public = self.private.public_key()
        if self.public.public_bytes(RAW, serialization.PublicFormat.Raw) != secret[32:]:
            die(f'{path} holds a mismatched key pair')
        self.name = Path(path).stem

    def sign(self, target):
        data = Path(target).read_bytes()
        signature = self.private.sign(data)
        self.public.verify(signature, data)
        Path(f'{target}.sig').write_text(
            signify_text(f'verify with {self.name}.pub', b'Ed' + self.keynum + signature))


def parse_record(line, origin):
    words = line.split()
    if not words or words[0] != RECORD:
        die(f'{origin}: not a {RECORD} record')
    fields = {}
    for word in words[1:]:
        key, separator, value = word.partition('=')
        if not separator or not value or key in fields:
            die(f'{origin}: malformed field {word!r}')
        fields[key] = value
    missing = [key for key in REQUIRED if key not in fields]
    if missing:
        die(f'{origin}: record lacks {", ".join(missing)}')
    return fields


def release(key, out, sources):
    signer = Signer(key)
    if out.exists() and any(out.iterdir()):
        die(f'{out} is not empty')
    out.mkdir(parents=True, exist_ok=True)
    records = {}
    for source in sources:
        index = source/'INDEX'
        if not index.is_file():
            die(f'{source} has no INDEX')
        for number, line in enumerate(index.read_text().splitlines(), 1):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            origin = f'{index}:{number}'
            fields = parse_record(line, origin)
            package = fields['package']
            if not re.fullmatch(r'[A-Za-z0-9_.+-]+\.pkg', package):
                die(f'{origin}: package {package!r} is not a plain .pkg file name')
            if fields['sig'] != package + '.sig':
                die(f'{origin}: sig must name {package}.sig')
            slot = (fields['arch'], fields['name'])
            if slot in records:
                die(f'{origin}: a second {fields["name"]} package for {fields["arch"]}')
            data = (source/package).read_bytes()
            if hashlib.sha256(data).hexdigest() != fields['sha256']:
                die(f'{source/package} does not match the sha256 in {origin}')
            (out/package).write_bytes(data)
            signer.sign(out/package)
            records[slot] = ' '.join(line.split())
    if not records:
        die('no packages to sign')
    (out/'INDEX').write_text(''.join(records[slot] + '\n' for slot in sorted(records)))
    signer.sign(out/'INDEX')
    (out/'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n'
        for path in sorted(out.iterdir()) if path.name != 'SHA256SUMS'))
    print(f'release: signed {len(records)} packages and INDEX in {out} '
          f'(key number {signer.keynum.hex()})')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('keygen', help='create a publisher key pair')
    create.add_argument('directory', type=Path)
    create.add_argument('name')
    publish = commands.add_parser('release', help='sign packages into a release directory')
    publish.add_argument('--key', type=Path, required=True)
    publish.add_argument('--out', type=Path, required=True)
    publish.add_argument('sources', type=Path, nargs='+')
    args = parser.parse_args()
    if args.command == 'keygen':
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', args.name):
            die(f'invalid key name {args.name!r}')
        keygen(args.directory, args.name)
    else:
        release(args.key, args.out, args.sources)


if __name__ == '__main__':
    main()
