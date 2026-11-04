#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only ACME response mutation controls. Never contacts a public CA."""
import base64
import datetime
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PEER = Path('/opt/bashos-parity/harness/helpers/acme-cert-peer-r13.py')
spec = importlib.util.spec_from_file_location('acme_cert_peer_r13', PEER)
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
PORT = 15810
ACCOUNT = '00' * 31 + '01'
NAME = 'fixture.test'


def root_cert(key, name):
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(8301)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2040, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))


def signed_leaf(ca, pub, names, *, expired=False):
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)]))
               .issuer_name(ca.ca_cert.subject).public_key(pub).serial_number(8302)
               .not_valid_before(datetime.datetime(2020, 1, 1))
               .not_valid_after(datetime.datetime(2021 if expired else 2040, 1, 1)))
    if names is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return builder.sign(ca.ca_key, hashes.SHA256())


def pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def pem_der(der):
    return b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(der) + b'-----END CERTIFICATE-----\n'


def expect_bad_signature(cert, public_key):
    try:
        public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    except InvalidSignature:
        return
    raise AssertionError('independent cryptography control unexpectedly verified tampered signature')


def exercise(shell, mode, case_dir):
    case_dir.mkdir(mode=0o700)
    os.environ.pop('ACME_FIXTURE_BAD_NONCE_ONCE', None)
    ca = peer.CA(PORT)
    root = pem_cert(ca.ca_cert)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue = root_cert(rogue_key, ca.ca_cert.subject)
    alternate_key = ec.generate_private_key(ec.SECP256R1())
    alternate = root_cert(alternate_key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Alternate fixture root')]))
    if mode == 'untrusted':
        trust = pem_cert(rogue)
    elif mode == 'cross-signed':
        trust = pem_cert(alternate)
    else:
        trust = root
    (case_dir / 'anchor.pem').write_bytes(trust)
    seen = []
    cross_signed = []
    base = ca.make_handler()

    class Handler(base):
        def send(self, code, body=b'', ctype='application/json', extra=()):
            if self.path == '/acme/cert/1' and code == 200:
                original = body
                leaf = x509.load_pem_x509_certificate(original)
                if mode == 'malformed':
                    body = b'-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n'
                elif mode == 'junk':
                    body = original + b'junk-after-chain\n'
                elif mode == 'wrong-name':
                    body = pem_cert(signed_leaf(ca, leaf.public_key(), ['wrong.test'])) + root
                elif mode == 'extra-name':
                    body = pem_cert(signed_leaf(ca, leaf.public_key(), [NAME, 'other.test'])) + root
                elif mode == 'no-san':
                    body = pem_cert(signed_leaf(ca, leaf.public_key(), None)) + root
                elif mode == 'expired':
                    body = pem_cert(signed_leaf(ca, leaf.public_key(), [NAME], expired=True)) + root
                elif mode == 'wrong-key':
                    other = ec.generate_private_key(ec.SECP256R1())
                    body = pem_cert(signed_leaf(ca, other.public_key(), [NAME])) + root
                    assert other.public_key().public_numbers() != leaf.public_key().public_numbers()
                elif mode == 'bad-signature':
                    der = bytearray(leaf.public_bytes(serialization.Encoding.DER))
                    der[-1] ^= 1
                    corrupted = x509.load_der_x509_certificate(bytes(der))
                    expect_bad_signature(corrupted, ca.ca_key.public_key())
                    body = pem_der(bytes(der)) + root
                elif mode == 'bad-chain':
                    expect_bad_signature(leaf, rogue_key.public_key())
                    body = pem_cert(leaf) + pem_cert(rogue)
                elif mode == 'bad-root-signature':
                    root_der = bytearray(ca.ca_cert.public_bytes(serialization.Encoding.DER))
                    root_der[-1] ^= 1
                    corrupted_root = x509.load_der_x509_certificate(bytes(root_der))
                    expect_bad_signature(corrupted_root, ca.ca_key.public_key())
                    body = pem_cert(leaf) + pem_der(bytes(root_der))
                elif mode == 'extra-cert':
                    body = original + pem_cert(rogue)
                elif mode == 'untrusted':
                    expect_bad_signature(leaf, rogue_key.public_key())
                elif mode == 'cross-signed':
                    cross = (x509.CertificateBuilder().subject_name(ca.ca_cert.subject).issuer_name(alternate.subject)
                             .public_key(ca.ca_key.public_key()).serial_number(8303)
                             .not_valid_before(datetime.datetime(2020, 1, 1))
                             .not_valid_after(datetime.datetime(2040, 1, 1))
                             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                             .sign(alternate_key, hashes.SHA256()))
                    alternate_key.public_key().verify(cross.signature, cross.tbs_certificate_bytes, ec.ECDSA(cross.signature_hash_algorithm))
                    cross_signed.append(cross)
                    body = pem_cert(leaf) + pem_cert(cross)
                elif mode != 'valid':
                    raise AssertionError('unknown mode ' + mode)
                assert mode in ('valid', 'untrusted') or body != original
                if mode not in ('malformed', 'junk', 'bad-signature'):
                    observed = x509.load_pem_x509_certificate(body)
                    ca.ca_key.public_key().verify(observed.signature, observed.tbs_certificate_bytes,
                                                  ec.ECDSA(observed.signature_hash_algorithm))
                    if mode == 'wrong-name':
                        assert observed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ['wrong.test']
                    if mode == 'extra-name':
                        assert observed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [NAME, 'other.test']
                    if mode == 'no-san':
                        try:
                            observed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        except x509.ExtensionNotFound:
                            pass
                        else:
                            raise AssertionError('missing-SAN fixture contains SAN')
                    if mode == 'wrong-key':
                        assert observed.public_key().public_numbers() != leaf.public_key().public_numbers()
                seen.append(body)
            return super().send(code, body, ctype, extra)

    server = peer.ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = ['issue', '--allow-http', '--http-listen', '127.0.0.1:%d' % (PORT + 2),
               '--directory', 'http://127.0.0.1:%d/directory' % PORT, '-k', ACCOUNT,
               '--domain', NAME, '--out', 'issued', '--cert-ca', str((case_dir / 'anchor.pem').resolve())]
    if mode == 'account-url':
        command = ['account', '--allow-http', '--directory',
                   'http://127.0.0.1:%d/directory' % PORT, '-k', ACCOUNT]
    proc = None
    try:
        proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c', 'acme "$@"', 'acme-control'] + command,
                                cwd=case_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise AssertionError('candidate deadline expired')
        if mode == 'account-url':
            assert proc.returncode == 0 and stdout == (ca.base + '/acme/acct/1\n').encode(), (proc.returncode, stdout, stderr)
            posts = [e for e in ca.log if e.get('method') == 'POST' and e.get('path') == '/acme/new-acct']
            assert len(posts) == 1 and posts[0].get('problems') == [] and posts[0].get('protected', {}).get('jwk'), posts
            assert any(e.get('method') == 'HEAD' and e.get('path') == '/acme/new-nonce' for e in ca.log), ca.log
        else:
            assert len(seen) == 1, ('candidate did not reach certificate response', mode, proc.returncode, stderr[-500:])
            assert ca.order.get('status') == 'valid', ('fixture order was not valid', mode)
            assert any(e.get('csr_ok') is True for e in ca.log), ('fixture CSR control did not pass', mode)
            issued = case_dir / 'issued'
            if mode in ('valid', 'cross-signed'):
                assert proc.returncode == 0, ('valid signed chain rejected', proc.returncode, stderr[-1000:])
                chain = (issued / 'fullchain.pem').read_bytes()
                assert chain == seen[0], 'stored bytes differ from issued chain'
                if mode == 'valid':
                    assert chain == ca.cert_pem.encode(), 'stored bytes differ from original issued chain'
                else:
                    assert len(cross_signed) == 1
                    alternate_key.public_key().verify(cross_signed[0].signature, cross_signed[0].tbs_certificate_bytes, ec.ECDSA(cross_signed[0].signature_hash_algorithm))
                leaf = x509.load_pem_x509_certificate(chain)
                ca.ca_key.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
                ca.ca_key.public_key().verify(ca.ca_cert.signature, ca.ca_cert.tbs_certificate_bytes, ec.ECDSA(ca.ca_cert.signature_hash_algorithm))
                assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [NAME]
                key = serialization.load_pem_private_key((issued / 'privkey.pem').read_bytes(), password=None)
                assert key.public_key().public_numbers() == leaf.public_key().public_numbers(), 'stored private key differs from certificate'
            else:
                assert proc.returncode != 0, ('invalid certificate accepted', mode, stdout, stderr)
                assert b'issued certificate validation failed' in stderr, ('failure not attributed to certificate validation', mode, stderr[-1000:])
                assert not (issued / 'fullchain.pem').exists() and not (issued / 'privkey.pem').exists(), ('invalid response created output', mode)
        with socket.socket() as probe:
            probe.settimeout(0.5)
            assert probe.connect_ex(('127.0.0.1', PORT + 2)) != 0, 'HTTP-01 responder leaked after exit'
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive(), 'fixture CA thread did not stop'


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: helper SHELL MODE')
    shell, mode = sys.argv[1:]
    exercise(shell, 'valid', Path('positive'))
    if mode != 'valid':
        exercise(shell, mode, Path('negative'))
    print('acme-certificate-%s=PASS' % mode)


if __name__ == '__main__':
    main()
