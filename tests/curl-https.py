#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the curl builtin's HTTPS transfers and redirect handling.

Usage: python3 tests/curl-https.py [BINARY]
Serves HTTPS on 127.0.0.1 with a throwaway certificate authority and runs curl
with an empty PATH. On a build host /bin/bash is not bash-os, so the transfers
succeed only if the TLS exchange runs in curl's own child. Release downloads
redirect to storage URLs longer than a kilobyte, so the redirects here carry
3000-byte queries, and a target past the limit must be refused, not cut short.
"""

import datetime
import http.server
import ipaddress
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
LONG = 'x' * 3000
TOO_LONG = 'y' * 9000
checks = 0


def pem(path, value):
    path.write_bytes(value)
    return path


def authority(tmp):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'curl-https test authority')])

    def builder(subject, key):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=2)))

    ca = (builder(ca_name, ca_key)
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')]), leaf_key)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    encoding = serialization.Encoding.PEM
    return (pem(tmp / 'ca.pem', ca.public_bytes(encoding)),
            pem(tmp / 'leaf.pem', leaf.public_bytes(encoding)),
            pem(tmp / 'leaf.key', leaf_key.private_bytes(encoding, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=b'', location=None):
        self.send_response(status)
        if location:
            self.send_header('Location', location)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == '/absolute':
            self.reply(302, location=f'https://127.0.0.1:{port}/asset?sig={LONG}')
        elif self.path == '/relative':
            self.reply(302, location=f'asset?sig={LONG}')
        elif self.path == '/too-long':
            self.reply(302, location=f'/asset?sig={TOO_LONG}')
        elif self.path.startswith('/asset?sig='):
            self.reply(200, f'payload {len(self.path) - len("/asset?sig=")}\n'.encode())
        else:
            self.reply(404)


def curl(*args, status=0, stdout=None, stderr=None):
    global checks
    result = subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; curl "$@"', '_', *map(str, args)],
                            capture_output=True, text=True, timeout=60, env={'LC_ALL': 'C'})
    assert result.returncode == status, (args[-1][:80], result.returncode, result.stdout, result.stderr)
    if stdout is not None:
        assert result.stdout == stdout, (args[-1][:80], result.stdout, result.stderr)
    if stderr is not None:
        assert stderr in result.stderr, (args[-1][:80], result.stderr)
    checks += 1


with tempfile.TemporaryDirectory(prefix='curl-https-') as directory:
    ca, leaf, key = authority(Path(directory))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(leaf, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'https://127.0.0.1:{server.server_address[1]}'
    try:
        curl('-fsS', '--cacert', ca, f'{base}/asset?sig=abc', stdout='payload 3\n')
        curl('-fsSL', '--cacert', ca, f'{base}/absolute', stdout=f'payload {len(LONG)}\n')
        curl('-fsSL', '--cacert', ca, f'{base}/relative', stdout=f'payload {len(LONG)}\n')
        curl('-fsSL', '--cacert', ca, f'{base}/too-long', status=1,
             stderr='redirect target is longer than 8191 bytes')
        curl('-fsS', '--cacert', ca, f'{base}/too-long', stdout='')
        curl('-fsS', '--cacert', ca, f'{base}/missing', status=22)
        curl('-fsS', '-k', f'{base}/asset?sig=k', stdout='payload 1\n')
        curl('-fsS', f'{base}/asset?sig=untrusted', status=1, stdout='')
        curl('-fsS', '--cacert', ca, f'{base}/asset?sig={TOO_LONG}', status=2, stderr='URL is longer than')
    finally:
        server.shutdown()

print(f'curl-https: {checks} checks passed')
