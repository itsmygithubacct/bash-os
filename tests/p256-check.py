#!/usr/bin/env python3
"""P-256 interoperability fixtures; accepts a Bash executable or QEMU wrapper.

All keys and certificates are disposable test data. --report preserves results
including failed outputs, so a broken target can be compared independently.
P256_LOAD_ENV optionally loads shared crypto/acme modules via BASH_ENV;
P256_ASAN_LIB preloads the sanitizer runtime in the tested Bash only.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

ORDER = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
SCALARS = [1, 2, ORDER - 1] + [
    int.from_bytes(hashlib.sha256(f'p256 fixture {i}'.encode()).digest(), 'big') % (ORDER - 1) + 1
    for i in range(3)
]
MESSAGE = b'P-256 independent interoperability fixture\x00' + bytes(range(256))


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint)


def raw(der):
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def verifies(key, sig, message):
    if len(sig) != 64:
        return False
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big'))
    try:
        key.public_key().verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    runner = shlex.split(os.environ.get('BASH_OS_RUNNER', ''))
    env = dict(os.environ, LC_ALL='C')
    if env.get('P256_LOAD_ENV'):
        env['BASH_ENV'] = env['P256_LOAD_ENV']
    if env.get('P256_ASAN_LIB'):
        env.update(LD_PRELOAD=env['P256_ASAN_LIB'], ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    records = []

    def run(*words, data=None):
        p = subprocess.run([*runner, binary, '--noprofile', '--norc', '-c', 'PATH=; "$@"', 'fixture', *words],
                           input=data, capture_output=True, timeout=60, env=env)
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        return p

    def check(name, passed, **details):
        records.append(dict(name=name, passed=bool(passed), **details))
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)

    for scalar in SCALARS:
        sk = f'{scalar:064x}'
        key = ec.derive_private_key(scalar, ec.SECP256R1())
        pk = public(key)
        p = run('crypto', 'ecdsa-p256-pub', '-k', sk, '-x')
        observed = p.stdout.strip().decode()
        check(f'public {sk}', p.returncode == 0 and observed == pk.hex(),
              rc=p.returncode, expected=pk.hex(), observed=observed)
        p = run('crypto', 'ecdsa-p256-sign', '-k', sk, data=MESSAGE)
        sig = p.stdout
        check(f'sign interop {sk}', p.returncode == 0 and verifies(key, sig, MESSAGE),
              rc=p.returncode, signature=sig.hex(), independent_accepts=verifies(key, sig, MESSAGE))
        # Test both an independently produced signature and the target's output.
        reference = raw(key.sign(MESSAGE, ec.ECDSA(hashes.SHA256())))
        for label, signature, message, expected in [
            ('independent', reference, MESSAGE, 0),
            ('own signature correct public key', sig, MESSAGE, 0),
            ('changed message', reference, MESSAGE + b'!', 1),
            ('zero signature', bytes(64), MESSAGE, 1),
            ('changed signature', reference[:-1] + bytes([reference[-1] ^ 1]), MESSAGE, 1),
        ]:
            p = run('crypto', 'ecdsa-p256-verify', '-k', pk.hex(), '-s', signature.hex(), data=message)
            check(f'verify {label} {sk}', p.returncode == expected,
                  rc=p.returncode, signature=signature.hex(), message=message.hex(),
                  independent_accepts=verifies(key, signature, message), target_accepts=p.returncode == 0)
        if len(observed) == 130:
            p = run('crypto', 'ecdsa-p256-verify', '-k', observed, '-s', sig.hex(), data=MESSAGE)
            check(f'own signature own public key {sk}', p.returncode == 0, rc=p.returncode)
        jwk = {'kty': 'EC', 'crv': 'P-256', 'x': b64(pk[1:33]), 'y': b64(pk[33:])}
        p = run('acme', 'jwk-public', '-k', sk)
        check(f'acme JWK {sk}', p.returncode == 0 and json.loads(p.stdout) == jwk,
              rc=p.returncode, observed=p.stdout.decode().strip())
        thumb = b64(hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode()).digest())
        p = run('acme', 'jwk-thumbprint', '-k', sk)
        check(f'acme thumbprint {sk}', p.returncode == 0 and p.stdout.strip().decode() == thumb)
        p = run('acme', 'key-authorization', 'fixture', '-k', sk)
        check(f'acme key authorization {sk}', p.returncode == 0 and p.stdout.strip().decode() == 'fixture.' + thumb)
        for mode in ['--jwk', '--kid']:
            extra = [mode] if mode == '--jwk' else [mode, 'https://example.invalid/account/1']
            p = run('acme', 'jws-sign', '-k', sk, '--url', 'https://example.invalid/acme',
                    '--nonce', 'fixture', *extra, '-d', '{"ok":true}')
            jws = json.loads(p.stdout)
            signed = (jws['protected'] + '.' + jws['payload']).encode()
            signature = base64.urlsafe_b64decode(jws['signature'] + '==')
            header = json.loads(base64.urlsafe_b64decode(jws['protected'] + '=='))
            expected_header = dict(alg='ES256', nonce='fixture', url='https://example.invalid/acme')
            expected_header.update(jwk=jwk) if mode == '--jwk' else expected_header.update(kid='https://example.invalid/account/1')
            check(f'acme JWS {mode} {sk}', p.returncode == 0 and header == expected_header
                  and jws['payload'] == b64(b'{"ok":true}') and verifies(key, signature, signed),
                  rc=p.returncode, jws=jws, independent_accepts=verifies(key, signature, signed))

    with tempfile.TemporaryDirectory(prefix='p256-chain-') as directory:
        d = Path(directory)
        root_key, leaf_key = [ec.derive_private_key(s, ec.SECP256R1()) for s in SCALARS[:2]]
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'P256 fixture root')])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'P256 fixture leaf')])
        def cert(name, key, serial, ca):
            return (x509.CertificateBuilder().subject_name(name).issuer_name(root_name)
                    .public_key(key.public_key()).serial_number(serial)
                    .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
                    .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
                    .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                    .sign(root_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        root = cert(root_name, root_key, 1, True)
        leaf = cert(leaf_name, leaf_key, 2, False)
        (d/'root.der').write_bytes(root)
        (d/'leaf.der').write_bytes(leaf)
        (d/'bad.der').write_bytes(leaf[:-1] + bytes([leaf[-1] ^ 1]))
        for name, expected in [('leaf', 0), ('bad', 1)]:
            p = run('crypto', 'x509-chain-verify-mbedtls', '-c', str(d/(name + '.der')),
                    '-t', str(d/'root.der'), '--time', '1767225600')
            check(f'x509 chain {name}', p.returncode == expected, rc=p.returncode,
                  output=p.stdout.decode().strip(), stderr=p.stderr.decode().strip())
    if args.report:
        args.report.write_text(json.dumps(dict(binary=binary, message=MESSAGE.hex(), checks=records), indent=2) + '\n')
    failed = sum(not r['passed'] for r in records)
    print(f'p256-check: {len(records) - failed} passed, {failed} failed')
    return bool(failed)


if __name__ == '__main__':
    raise SystemExit(main())
