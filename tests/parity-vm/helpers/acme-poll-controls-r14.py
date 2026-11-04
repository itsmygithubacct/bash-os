#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only polling controls against a separately pinned local ACME CA."""
import datetime
import email.utils
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

peer_path = '/opt/bashos-parity/harness/helpers/acme-cert-peer-r13.py'
spec = importlib.util.spec_from_file_location('poll_peer', peer_path)
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
PORT = 15810
ACCOUNT = '00' * 31 + '01'


def exercise(shell, mode):
    ca = peer.CA(PORT)
    Path('anchor.pem').write_bytes(ca.ca_cert.public_bytes(serialization.Encoding.PEM))
    base = ca.make_handler()
    observations = []
    notified = threading.Event()
    counts = {'auth': 0, 'order': 0}

    class Handler(base):
        def do_HEAD(self):
            if mode in ('expiry', 'request-expiry'):
                time.sleep(12 if mode == 'request-expiry' else 2)
            return super().do_HEAD()

        def send(self, code, body=b'', ctype='application/json', extra=()):
            extra = list(extra)
            path = self.path
            if code == 200 and path == '/acme/chall/1':
                if mode == 'auth-terminal':
                    body = b'{"status":"invalid"}'
                elif mode in ('slow', 'interrupt'):
                    extra.append(('Retry-After', '1' if mode == 'slow' else '20'))
                if mode == 'interrupt':
                    notified.set()
            if code == 200 and path == '/acme/authz/1' and ca.order.get('authz') == 'valid':
                counts['auth'] += 1
                if mode == 'slow' and counts['auth'] == 1:
                    body = b'{"status":"processing"}'
                    extra.append(('Retry-After', '1'))
            if code == 200 and path == '/acme/finalize/1' and mode in ('slow', 'date', 'date-rfc850', 'date-asctime', 'terminal', 'expiry', 'bad-retry', 'duplicate-retry'):
                body = b'{"status":"processing"}'
                val = ('bad-date' if mode == 'bad-retry' else '20' if mode == 'expiry' else
                       email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2), usegmt=True)
                       if mode in ('date', 'date-rfc850', 'date-asctime') else '1')
                if mode == 'date-rfc850':
                    val = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)).strftime('%A, %d-%b-%y %H:%M:%S GMT')
                elif mode == 'date-asctime':
                    val = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)).strftime('%a %b %e %H:%M:%S %Y')
                extra.append(('Retry-After', val))
                if mode == 'duplicate-retry':
                    extra.append(('Retry-After', '1'))
            if code == 200 and path == '/acme/order/1':
                counts['order'] += 1
                if mode == 'terminal':
                    body = b'{"status":"invalid"}'
                elif mode == 'slow' and counts['order'] <= 11:
                    body = b'{"status":"processing"}'
                    extra.append(('Retry-After', '1'))
                elif mode == 'date' and counts['order'] == 1:
                    body = b'{"status":"processing"}'
                    extra.append(('Retry-After', email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2), usegmt=True)))
            if code == 200 and path in ('/acme/chall/1', '/acme/authz/1', '/acme/finalize/1', '/acme/order/1'):
                observations.append((path, time.monotonic(), time.time(), list(extra), body.decode()))
            return super().send(code, body, ctype, extra)

    server = peer.ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    limit = 7 if mode == 'expiry' else 3 if mode == 'request-expiry' else 45
    command = [shell, '--noprofile', '--norc', '-c', 'acme "$@"', 'poll-control',
               'issue', '--allow-http', '--http-listen', '127.0.0.1:%d' % (PORT+2),
               '--directory', 'http://127.0.0.1:%d/directory' % PORT, '-k', ACCOUNT,
               '--domain', 'fixture.test', '--out', 'issued', '--cert-ca', str(Path('anchor.pem').resolve()),
               '--timeout', str(limit)]
    proc = None
    started = time.monotonic()
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        if mode == 'interrupt':
            assert notified.wait(15), 'challenge processing response never reached'
            os.kill(proc.pid, signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=50 if mode == 'slow' else 20)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise AssertionError('candidate did not terminate within control bound')
        elapsed = time.monotonic() - started
        issued = Path('issued')
        if mode in ('slow', 'date', 'date-rfc850', 'date-asctime'):
            assert proc.returncode == 0, (mode, proc.returncode, stdout, stderr, observations)
            chain = (issued/'fullchain.pem').read_bytes()
            assert chain == ca.cert_pem.encode()
            leaf = x509.load_pem_x509_certificate(chain)
            ca.ca_key.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
            key = serialization.load_pem_private_key((issued/'privkey.pem').read_bytes(), password=None)
            assert key.public_key().public_numbers() == leaf.public_key().public_numbers()
            assert any(e.get('csr_ok') is True for e in ca.log), 'CSR was not accepted'
            if mode == 'slow':
                assert counts['auth'] >= 2 and counts['order'] >= 12 and elapsed >= 13, (counts, elapsed)
        else:
            assert proc.returncode != 0, (mode, stdout, stderr)
            assert not (issued/'fullchain.pem').exists() and not (issued/'privkey.pem').exists(), 'failure published output'
            if mode == 'terminal':
                assert counts['order'] == 1, (counts, observations)
            elif mode == 'auth-terminal':
                assert not any(x[0] == '/acme/finalize/1' for x in observations)
                assert counts['auth'] == 0, observations
            elif mode == 'expiry':
                assert any(x[0] == '/acme/finalize/1' for x in observations), observations
                assert counts['order'] == 0 and 6 <= elapsed < 11, (counts, elapsed)
            elif mode in ('bad-retry', 'duplicate-retry'):
                assert any(x[0] == '/acme/finalize/1' for x in observations) and counts['order'] == 0, observations
            elif mode == 'request-expiry':
                assert 2.5 <= elapsed < 6 and not any(x[0] == '/acme/finalize/1' for x in observations), (elapsed, observations)
            elif mode == 'interrupt':
                assert elapsed < 15, elapsed
                assert not any(x[0] == '/acme/finalize/1' for x in observations)
        if mode in ('slow', 'date', 'date-rfc850', 'date-asctime'):
            # Every pending response with Retry-After must precede the next
            # corresponding POST-as-GET by at least the advertised interval.
            for index, event in enumerate(observations):
                path, monotonic, wall, headers, body = event
                retry = next((v for k, v in headers if k.lower() == 'retry-after'), None)
                if retry is None:
                    continue
                target = '/acme/authz/1' if path in ('/acme/chall/1', '/acme/authz/1') else '/acme/order/1'
                later = next((x for x in observations[index+1:] if x[0] == target), None)
                assert later is not None, (event, observations)
                parsed = email.utils.parsedate_to_datetime(retry) if not retry.isdigit() else None
                if parsed is not None and parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=datetime.timezone.utc)
                seconds = float(retry) if retry.isdigit() else max(0, parsed.timestamp() - wall)
                assert later[1] - monotonic >= max(0, seconds - 0.12), (event, later, seconds)
        with socket.socket() as probe:
            probe.settimeout(0.5)
            assert probe.connect_ex(('127.0.0.1', PORT+2)) != 0, 'HTTP-01 responder leaked'
    finally:
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: helper SHELL MODE')
    exercise(*sys.argv[1:])
    print('acme-poll-%s=PASS' % sys.argv[2])
