#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only local ACME (RFC 8555) mock peer, positive-control client and assertions for the w2 acme fixtures.

    mig-w2-acme.py serve CONTROL_PORT CANDIDATE_PORT READY   # two independent mock CAs on loopback
    mig-w2-acme.py control PORT                              # independent Python ACME client (positive control)
    mig-w2-acme.py verify CHECK PORT [args]                  # assertions on the candidate-side request log

Each mock CA validates every JWS it receives (ES256 signature, protected header, nonce, url, Content-Type,
kid/jwk exclusivity, POST-as-GET empty payload). Fixture-only keys and certificates; no other network target.
"""
import base64
import datetime
import hashlib
import json
import os
import signal
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

SK_HEX = '00' * 31 + '01'          # fixture scalar: P-256 private key d = 1
FIXTURE_ID = 'fixture.test'
TOKEN = 'w2tokenABCDEFGH'


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def account_key():
    return ec.derive_private_key(int(SK_HEX, 16), ec.SECP256R1())


def jwk_of(key):
    n = key.public_key().public_numbers()
    return {'crv': 'P-256', 'kty': 'EC', 'x': b64u(n.x.to_bytes(32, 'big')), 'y': b64u(n.y.to_bytes(32, 'big'))}


def thumbprint(jwk):
    canon = json.dumps({k: jwk[k] for k in ('crv', 'kty', 'x', 'y')}, separators=(',', ':'), sort_keys=True)
    return b64u(hashlib.sha256(canon.encode()).digest())


class CA:
    def __init__(self, port):
        self.port = port
        self.base = 'http://127.0.0.1:%d' % port
        self.log = []
        self.nonces = set()
        self.counter = 0
        self.jwk = None
        self.inject_bad_nonce = os.environ.get('ACME_FIXTURE_BAD_NONCE_ONCE') == '1'
        self.inject_bad_cert = False
        self.inject_challenge_fault = False
        self.order = {'status': 'pending'}
        self.cert_pem = None
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture CA')])
        self.ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                        .public_key(self.ca_key.public_key()).serial_number(1)
                        .not_valid_before(datetime.datetime(2020, 1, 1))
                        .not_valid_after(datetime.datetime(2040, 1, 1))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                        .sign(self.ca_key, hashes.SHA256()))
        self.lock = threading.Lock()

    def nonce(self):
        with self.lock:
            self.counter += 1
            n = 'nonce-%04d' % self.counter
            self.nonces.add(n)
            return n

    def validate_jws(self, body, url, headers):
        problems = []
        if headers.get('Content-Type') != 'application/jose+json':
            problems.append('content-type')
        try:
            jws = json.loads(body)
            if not isinstance(jws, dict) or set(jws) != {'protected', 'payload', 'signature'}:
                raise ValueError('not a flattened JWS')
            prot = json.loads(unb64u(jws['protected']))
            if not isinstance(prot, dict):
                raise ValueError('protected header is not an object')
        except Exception:
            return None, None, ['malformed-jws']
        if prot.get('alg') != 'ES256':
            problems.append('alg')
        if prot.get('url') != url:
            problems.append('url')
        with self.lock:
            if not isinstance(prot.get('nonce'), str) or prot['nonce'] not in self.nonces:
                problems.append('nonce')
            else:
                self.nonces.discard(prot['nonce'])
        has_jwk, has_kid = 'jwk' in prot, 'kid' in prot
        if has_jwk == has_kid:
            problems.append('jwk-xor-kid')
        if url.endswith('/acme/new-acct'):
            if not has_jwk or has_kid or prot.get('jwk') != jwk_of(account_key()):
                problems.append('account-jwk')
        elif not has_kid or has_jwk or prot.get('kid') != self.base + '/acme/acct/1' or self.jwk is None:
            problems.append('account-kid')
        jwk = prot.get('jwk') or self.jwk
        try:
            nums = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(jwk['x']), 'big'), int.from_bytes(unb64u(jwk['y']), 'big'), ec.SECP256R1())
            sig = unb64u(jws['signature'])
            if len(sig) != 64 or jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
                raise ValueError('not an ES256 signature and P-256 JWK')
            nums.public_key().verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')),
                                     (jws['protected'] + '.' + jws['payload']).encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:
            problems.append('signature')
        try:
            payload = unb64u(jws['payload'])
        except Exception:
            payload = b''
            problems.append('malformed-payload')
        if url.rsplit('/', 2)[-2] in ('authz', 'order', 'cert') and payload != b'':
            problems.append('post-as-get')
        return prot, payload, problems

    def make_handler(ca):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, body=b'', ctype='application/json', extra=()):
                self.send_response(code)
                self.send_header('Content-Type', ctype)
                nonce = ca.nonce()
                self.send_header('Replay-Nonce', nonce)
                for k, v in extra:
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.record(method='RESPONSE', status=code, response_nonce=nonce,
                            response_body=body.decode('utf-8', errors='replace'),
                            response_sha256=hashlib.sha256(body).hexdigest())
                if self.command != 'HEAD':
                    self.wfile.write(body)

            def record(self, **kw):
                entry = {'method': self.command, 'path': self.path, 'client': self.client_address[0], 't': time.time()}
                entry.update(kw)
                ca.log.append(entry)
                json.dump(ca.log, open('acme-%d.json' % ca.port, 'w'))

            def do_HEAD(self):
                self.record()
                self.send(200 if self.path == '/acme/new-nonce' else 404)

            def do_GET(self):
                self.record()
                if self.path == '/directory':
                    d = {'newNonce': ca.base + '/acme/new-nonce', 'newAccount': ca.base + '/acme/new-acct',
                         'newOrder': ca.base + '/acme/new-order', 'revokeCert': ca.base + '/acme/revoke',
                         'keyChange': ca.base + '/acme/key-change'}
                    self.send(200, json.dumps(d).encode())
                elif self.path.startswith('/.well-known/acme-challenge/'):
                    self.send(200, b'', 'text/plain')
                else:
                    self.send(404)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                url = ca.base + self.path
                prot, payload, problems = ca.validate_jws(body, url, self.headers)
                entry = {'url': url, 'problems': problems, 'protected': prot,
                         'payload_len': None if payload is None else len(payload),
                         'payload': (payload or b'').decode(errors='replace')[:2000]}
                self.record(**entry)
                if problems:
                    kind = 'badNonce' if 'nonce' in problems else 'malformed'
                    return self.send(400, json.dumps({'type': 'urn:ietf:params:acme:error:' + kind, 'detail': ','.join(problems)}).encode(), 'application/problem+json')
                p = self.path
                if p == '/acme/new-order' and ca.inject_bad_nonce:
                    ca.inject_bad_nonce = False
                    self.record(method='EVENT', injected_bad_nonce=True)
                    return self.send(400, b'{"type":"urn:ietf:params:acme:error:badNonce"}', 'application/problem+json')
                if p == '/acme/new-acct':
                    ca.jwk = prot['jwk']
                    self.send(201, b'{"status":"valid"}', extra=[('Location', ca.base + '/acme/acct/1')])
                elif p == '/acme/new-order':
                    try:
                        if json.loads(payload).get('identifiers') != [{'type': 'dns', 'value': FIXTURE_ID}]:
                            raise ValueError('wrong identifiers')
                    except Exception:
                        return self.send(400, b'{"type":"urn:ietf:params:acme:error:rejectedIdentifier"}', 'application/problem+json')
                    ca.order = {'status': 'pending', 'identifiers': [{'type': 'dns', 'value': FIXTURE_ID}],
                                'authorizations': [ca.base + '/acme/authz/1'], 'finalize': ca.base + '/acme/finalize/1'}
                    self.send(201, json.dumps(ca.order).encode(), extra=[('Location', ca.base + '/acme/order/1')])
                elif p == '/acme/authz/1':
                    status = ca.order.get('authz', 'pending')
                    self.send(200, json.dumps({'status': status, 'identifier': {'type': 'dns', 'value': FIXTURE_ID},
                                               'challenges': [{'type': 'http-01', 'url': ca.base + '/acme/chall/1', 'token': TOKEN, 'status': status}]}).encode())
                elif p == '/acme/chall/1':
                    if ca.inject_challenge_fault:
                        self.record(method='EVENT', injected_challenge_fault=True)
                        return self.send(503, b'{"type":"urn:ietf:params:acme:error:serverInternal"}', 'application/problem+json')
                    fetched = None
                    try:
                        fetched = urllib.request.urlopen('http://127.0.0.1:%d/.well-known/acme-challenge/%s' % (ca.port + 2, TOKEN), timeout=2).read().decode()
                    except Exception:
                        pass
                    self.record(method='EVENT', fetched=fetched)
                    expected = TOKEN + '.' + thumbprint(ca.jwk)
                    if fetched != expected:
                        ca.order['authz'] = 'invalid'
                        return self.send(400, b'{"type":"urn:ietf:params:acme:error:unauthorized"}', 'application/problem+json')
                    ca.order['authz'] = 'valid'
                    ca.order['status'] = 'ready'
                    self.send(200, json.dumps({'type': 'http-01', 'url': url, 'token': TOKEN, 'status': 'processing'}).encode())
                elif p == '/acme/finalize/1':
                    if ca.order.get('authz') != 'valid':
                        return self.send(403, b'{"type":"urn:ietf:params:acme:error:orderNotReady"}', 'application/problem+json')
                    ok = False
                    try:
                        csr = json.loads(payload).get('csr', '')
                        req = x509.load_der_x509_csr(unb64u(csr))
                        san = req.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                        ok = req.is_signature_valid and san == [FIXTURE_ID]
                    except Exception:
                        pass
                    self.record(method='EVENT', csr_ok=ok, csr_der_b64=csr if ok else '')
                    if not ok:
                        return self.send(400, b'{"type":"urn:ietf:params:acme:error:badCSR"}', 'application/problem+json')
                    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture CA')])
                    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FIXTURE_ID)]))
                            .issuer_name(name).public_key(req.public_key()).serial_number(7)
                            .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2027, 1, 1))
                            .add_extension(x509.SubjectAlternativeName([x509.DNSName(FIXTURE_ID)]), critical=False)
                            .sign(ca.ca_key, hashes.SHA256()))
                    ca.cert_pem = (cert.public_bytes(serialization.Encoding.PEM) + ca.ca_cert.public_bytes(serialization.Encoding.PEM)).decode()
                    ca.order.update(status='valid', certificate=ca.base + '/acme/cert/1')
                    self.send(200, json.dumps(ca.order).encode(), extra=[('Location', ca.base + '/acme/order/1')])
                elif p == '/acme/order/1':
                    self.send(200, json.dumps(ca.order).encode())
                elif p == '/acme/cert/1':
                    if ca.inject_bad_cert:
                        self.record(method='EVENT', injected_bad_cert=True)
                        return self.send(200, b'-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n', 'application/pem-certificate-chain')
                    self.send(200, (ca.cert_pem or '').encode(), 'application/pem-certificate-chain')
                else:
                    self.send(404)
        return H


def serve(cport, kport, ready):
    servers = []
    for port in (cport, kport):
        ca = CA(port)
        ca.inject_bad_cert = (port == kport and os.environ.get('ACME_FIXTURE_BAD_CERT') == '1')
        ca.inject_challenge_fault = (port == kport and os.environ.get('ACME_FIXTURE_CHALLENGE_FAULT') == '1')
        srv = ThreadingHTTPServer(('127.0.0.1', port), ca.make_handler())
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    open(ready, 'w').write('ready\n')
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        time.sleep(1)


# ---- positive control: an independent client that performs the whole lifecycle ----------------
def control(port, invalid_challenge=False, invalid_csr=None):
    base = 'http://127.0.0.1:%d' % port
    key = account_key()
    jwk = jwk_of(key)
    state = {'nonce': None}

    def req(method, url, data=None, ctype=None):
        r = urllib.request.Request(url, data=data, method=method, headers={'Content-Type': ctype} if ctype else {})
        try:
            resp = urllib.request.urlopen(r, timeout=5)
        except urllib.error.HTTPError as exc:
            state['nonce'] = exc.headers.get('Replay-Nonce')
            raise
        state['nonce'] = resp.headers.get('Replay-Nonce')
        return resp

    def post(url, payload, kid=None):
        for attempt in range(2):
            prot = {'alg': 'ES256', 'nonce': state['nonce'], 'url': url}
            prot.update({'kid': kid} if kid else {'jwk': jwk})
            p64 = b64u(json.dumps(prot).encode())
            pl = '' if payload is None else b64u(json.dumps(payload).encode())
            r, s = utils.decode_dss_signature(key.sign((p64 + '.' + pl).encode(), ec.ECDSA(hashes.SHA256())))
            body = json.dumps({'protected': p64, 'payload': pl, 'signature': b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}).encode()
            try:
                return req('POST', url, body, 'application/jose+json')
            except urllib.error.HTTPError as exc:
                try:
                    retryable = exc.code == 400 and json.loads(exc.read()).get('type') == 'urn:ietf:params:acme:error:badNonce'
                except Exception:
                    retryable = False
                if not retryable or not state['nonce'] or attempt:
                    raise

    want = 'invalid-authorization' if invalid_challenge else TOKEN + '.' + thumbprint(jwk)

    class Responder(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = want.encode() if self.path == '/.well-known/acme-challenge/' + TOKEN else b''
            self.send_response(200 if body else 404)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    responder = ThreadingHTTPServer(('127.0.0.1', port + 2), Responder)
    threading.Thread(target=responder.serve_forever, daemon=True).start()
    d = json.load(req('GET', base + '/directory'))
    req('HEAD', d['newNonce'])
    acct = post(d['newAccount'], {'termsOfServiceAgreed': True}).headers['Location']
    order = post(d['newOrder'], {'identifiers': [{'type': 'dns', 'value': FIXTURE_ID}]}, acct)
    ourl, o = order.headers['Location'], json.load(order)
    az = json.load(post(o['authorizations'][0], None, acct))
    try:
        post(az['challenges'][0]['url'], {}, acct)
    except urllib.error.HTTPError as exc:
        if not invalid_challenge or exc.code != 400:
            raise
        responder.shutdown()
        responder.server_close()
        print('invalid-challenge-rejected')
        return
    if invalid_challenge:
        raise AssertionError('mock CA accepted invalid challenge authorization')
    csr_key = ec.generate_private_key(ec.SECP256R1())
    identifier = 'wrong.invalid' if invalid_csr == 'identifier' else FIXTURE_ID
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identifier)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(identifier)]), False).sign(csr_key, hashes.SHA256()))
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    if invalid_csr == 'signature':
        csr_der = csr_der[:-1] + bytes([csr_der[-1] ^ 1])
    elif invalid_csr == 'malformed':
        csr_der = b'not-a-der-csr'
    try:
        fin = json.load(post(o['finalize'], {'csr': b64u(csr_der)}, acct))
    except urllib.error.HTTPError as exc:
        if not invalid_csr or exc.code != 400:
            raise
        responder.shutdown()
        responder.server_close()
        print('invalid-csr-rejected')
        return
    if invalid_csr:
        raise AssertionError('mock CA accepted invalid CSR')
    polled = json.load(post(ourl, None, acct))
    assert fin['status'] == 'valid' and polled['status'] == 'valid'
    pem = post(fin['certificate'], None, acct).read().decode()
    check_chain(pem, b64u(csr.public_bytes(serialization.Encoding.DER)))
    assert post(o['authorizations'][0], None, acct).status == 200
    responder.shutdown()
    responder.server_close()
    print('control-ok')


def check_chain(pem, csr_der_b64):
    """Reject malformed, substituted or unrelated certificate chains."""
    marker = '-----END CERTIFICATE-----'
    parts = pem.split(marker)
    if len(parts) != 3 or parts[-1].strip():
        raise ValueError('expected leaf and CA certificates')
    leaf, ca = [x509.load_pem_x509_certificate((part + marker + '\n').encode()) for part in parts[:2]]
    req = x509.load_der_x509_csr(unb64u(csr_der_b64))
    if not req.is_signature_valid:
        raise ValueError('CSR signature invalid')
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub(leaf.public_key()) != pub(req.public_key()):
        raise ValueError('certificate public key differs from CSR')
    if leaf.issuer != ca.subject or ca.issuer != ca.subject:
        raise ValueError('certificate issuer mismatch')
    if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('issuer is not a CA')
    if leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) != [FIXTURE_ID]:
        raise ValueError('certificate identifier mismatch')
    ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, ec.ECDSA(ca.signature_hash_algorithm))


def check_private_key(chain_pem, key_pem):
    leaf = x509.load_pem_x509_certificate(chain_pem.split('-----END CERTIFICATE-----')[0].encode() + b'-----END CERTIFICATE-----\n')
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, fmt) != leaf.public_key().public_bytes(serialization.Encoding.DER, fmt):
        raise ValueError('issued key does not match certificate')


def oracle_selftest():
    """Guest-only negative controls for the protocol gate, not a product test."""
    ca = CA(5810)
    key = account_key()
    jwk = jwk_of(key)
    headers = {'Content-Type': 'application/jose+json'}
    def signed(url, nonce, payload=b'{}', kid=None, corrupt=False):
        protected = {'alg': 'ES256', 'url': url, 'nonce': nonce}
        protected.update({'kid': kid} if kid else {'jwk': jwk})
        p64, pl64 = b64u(json.dumps(protected).encode()), b64u(payload)
        r, s = utils.decode_dss_signature(key.sign((p64 + '.' + pl64).encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        if corrupt:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        return json.dumps({'protected': p64, 'payload': pl64, 'signature': b64u(sig)}).encode()
    acct = ca.base + '/acme/new-acct'
    nonce = ca.nonce()
    body = signed(acct, nonce)
    assert ca.validate_jws(body, acct, headers)[2] == []
    assert 'nonce' in ca.validate_jws(body, acct, headers)[2]
    assert 'signature' in ca.validate_jws(signed(acct, ca.nonce(), corrupt=True), acct, headers)[2]
    assert 'url' in ca.validate_jws(signed(acct, ca.nonce()), acct + '/other', headers)[2]
    ca.jwk = jwk
    url = ca.base + '/acme/authz/1'
    assert 'account-kid' in ca.validate_jws(signed(url, ca.nonce(), kid=ca.base + '/wrong'), url, headers)[2]
    assert 'post-as-get' in ca.validate_jws(signed(url, ca.nonce(), kid=ca.base + '/acme/acct/1'), url, headers)[2]
    assert ca.validate_jws(signed(url, ca.nonce(), payload=b'', kid=ca.base + '/acme/acct/1'), url, headers)[2] == []
    assert 'malformed-jws' in ca.validate_jws(b'{}', acct, headers)[2]
    assert 'content-type' in ca.validate_jws(signed(acct, ca.nonce()), acct, {})[2]
    csr_key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FIXTURE_ID)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(FIXTURE_ID)]), False).sign(csr_key, hashes.SHA256()))
    csr64 = b64u(csr.public_bytes(serialization.Encoding.DER))
    def chain(public_key, identifier=FIXTURE_ID, signing_key=None):
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identifier)]))
                .issuer_name(ca.ca_cert.subject).public_key(public_key).serial_number(42)
                .not_valid_before(datetime.datetime(2020, 1, 1)).not_valid_after(datetime.datetime(2040, 1, 1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(identifier)]), False)
                .sign(signing_key or ca.ca_key, hashes.SHA256()))
        return (leaf.public_bytes(serialization.Encoding.PEM) + ca.ca_cert.public_bytes(serialization.Encoding.PEM)).decode()
    good_chain = chain(csr_key.public_key())
    check_chain(good_chain, csr64)
    key_pem = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    check_private_key(good_chain, key_pem(csr_key))
    try:
        check_private_key(good_chain, key_pem(ec.generate_private_key(ec.SECP256R1())))
    except ValueError:
        pass
    else:
        raise AssertionError('mismatched issued key accepted')
    for bad in (chain(ec.generate_private_key(ec.SECP256R1()).public_key()),
                chain(csr_key.public_key(), identifier='wrong.invalid'),
                chain(csr_key.public_key(), signing_key=ec.generate_private_key(ec.SECP256R1())),
                '-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n'):
        try:
            check_chain(bad, csr64)
        except Exception:
            continue
        raise AssertionError('invalid certificate chain accepted')
    print('oracle-negative-controls-ok')


# ---- assertions on the candidate-side log --------------------------------------------------------
def verify(check, port):
    log = json.load(open('acme-%d.json' % port)) if os.path.exists('acme-%d.json' % port) else []
    fails = []
    posts = [e for e in log if e['method'] == 'POST']
    base = 'http://127.0.0.1:%d' % port
    def need(name, cond, detail=''):
        if not cond:
            fails.append('%s FAIL %s' % (name, detail))
    if check == 'r1':
        need('directory-fetched', any(e['method'] == 'GET' and e['path'] == '/directory' for e in log), len(log))
        need('advertised-newNonce-url-used', any(e['path'] == '/acme/new-nonce' for e in log), [e['path'] for e in log])
        need('advertised-newAccount-url-used', any(e['path'] == '/acme/new-acct' for e in posts), [e['path'] for e in posts])
        need('advertised-newOrder-url-used', any(e['path'] == '/acme/new-order' for e in posts), [e['path'] for e in posts])
    elif check == 'r2':
        need('head-newNonce-used', any(e['method'] == 'HEAD' and e['path'] == '/acme/new-nonce' for e in log), [e['method'] for e in log])
        need('two-or-more-posts', len(posts) >= 2, len(posts))
        need('every-post-nonce-was-server-supplied', posts and all('nonce' not in e['problems'] for e in posts), [e['problems'] for e in posts])
        need('nonces-not-reused', len({e['protected']['nonce'] for e in posts if e['protected']}) == len(posts), '')
        last_nonce = None
        for e in log:
            if e['method'] == 'RESPONSE':
                last_nonce = e.get('response_nonce')
            elif e['method'] == 'POST':
                need('nonce-from-previous-response', e.get('protected') is not None and e['protected'].get('nonce') == last_nonce, e['path'])
    elif check == 'r3':
        acct = [e for e in posts if e['path'] == '/acme/new-acct']
        need('newAccount-posted', len(acct) == 1, len(acct))
        if acct:
            e = acct[0]
            need('newAccount-jws-valid-es256-jwk-url-nonce-content-type', e['problems'] == [] and 'jwk' in e['protected'], e['problems'])
            need('newAccount-jwk-is-fixture-key', e['protected'].get('jwk') == jwk_of(account_key()), e['protected'].get('jwk'))
    elif check == 'r4':
        need('newOrder-with-kid', any(e['path'] == '/acme/new-order' and e['protected'] and e['protected'].get('kid') == base + '/acme/acct/1' and not e['problems'] for e in posts), [e['path'] for e in posts])
        for path in ('/acme/authz/1', '/acme/order/1'):
            need('post-as-get-' + path, any(e['path'] == path and e['payload_len'] == 0 and not e['problems'] and e['protected'].get('kid') for e in posts), [e['path'] for e in posts])
    elif check == 'r5':
        ch = [e for e in posts if e['path'] == '/acme/chall/1']
        need('challenge-posted-with-kid', len(ch) == 1 and not ch[0]['problems'] and ch[0]['protected'].get('kid'), len(ch))
        got = [e.get('fetched') for e in log if 'fetched' in e]
        need('ca-fetched-token-dot-thumbprint-for-http-01', got == [TOKEN + '.' + thumbprint(jwk_of(account_key()))], got)
    elif check == 'r6':
        fin = [e for e in log if e.get('path') == '/acme/finalize/1' and 'csr_ok' in e]
        need('finalize-csr-for-fixture-identifier', len(fin) == 1 and fin[0]['csr_ok'], fin)
        polled = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/order/1' and e.get('status') == 200]
        try:
            valid = any(json.loads(e['response_body']).get('status') == 'valid' for e in polled)
        except (ValueError, TypeError):
            valid = False
        need('order-polled-until-valid', valid, polled)
    elif check == 'r7':
        need('certificate-downloaded', any(e['path'] == '/acme/cert/1' and e['payload_len'] == 0 for e in posts), [e['path'] for e in posts])
        try:
            text = open('issued/fullchain.pem').read()
        except OSError:
            text = ''
        responses = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/cert/1' and e.get('status') == 200]
        csrs = [e.get('csr_der_b64') for e in log if e.get('csr_ok')]
        need('exact-issued-chain-stored', len(responses) == 1 and text == responses[0].get('response_body'), len(text))
        try:
            if len(csrs) != 1:
                raise ValueError('expected exactly one accepted CSR')
            check_chain(text, csrs[0])
            chain_valid = True
        except Exception:
            chain_valid = False
        need('issued-chain-and-csr-cryptographically-valid', chain_valid)
        try:
            with open('issued/privkey.pem') as f:
                check_private_key(text, f.read())
            key_valid = True
        except Exception:
            key_valid = False
        need('stored-private-key-matches-issued-certificate', key_valid)
    elif check == 'r8':
        # Incoming peer addresses cannot prove absence of other outbound traffic.
        # A trusted external network observer is an explicit qualification gate.
        need('independent-outbound-observer-required', False, 'see runtime request')
        stages = ['/directory', '/acme/new-acct', '/acme/new-order', '/acme/chall/1', '/acme/finalize/1', '/acme/cert/1']
        need('complete-lifecycle-against-the-private-peer', all(any(e['path'] == s for e in log) for s in stages), [e['path'] for e in log])
    elif check == 'retry':
        events = [e for e in log if e.get('injected_bad_nonce')]
        orders = [e for e in posts if e['path'] == '/acme/new-order']
        responses = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/new-order']
        need('one-injected-bad-nonce', len(events) == 1, len(events))
        need('one-bounded-retry', len(orders) == 2 and len(responses) == 2 and responses[0].get('status') == 400 and responses[1].get('status') == 201, len(orders))
        if len(orders) == 2 and len(responses) == 2:
            need('fresh-response-nonce-used', orders[1].get('protected') is not None and orders[1]['protected'].get('nonce') == responses[0].get('response_nonce') and orders[0]['protected'].get('nonce') != orders[1]['protected'].get('nonce') and not orders[1]['problems'])
    elif check == 'invalid-challenge':
        events = [e for e in log if e.get('fetched') == 'invalid-authorization']
        errors = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/chall/1' and e.get('status') == 400]
        need('invalid-key-authorization-rejected', len(events) == 1 and len(errors) == 1, len(events))
        need('no-finalize-or-certificate-after-rejection', not any(e['path'] in ('/acme/finalize/1', '/acme/cert/1') for e in posts))
    elif check == 'invalid-csr':
        events = [e for e in log if e.get('csr_ok') is False]
        errors = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/finalize/1' and e.get('status') == 400]
        need('invalid-csr-rejected', len(events) == 1 and len(errors) == 1, len(events))
        need('no-certificate-after-rejection', not any(e['path'] == '/acme/cert/1' for e in posts))
    elif check == 'bad-certificate':
        events = [e for e in log if e.get('injected_bad_cert')]
        responses = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/cert/1' and e.get('status') == 200]
        need('malformed-certificate-served', len(events) == 1 and len(responses) == 1 and 'not-a-certificate' in responses[0].get('response_body',''))
        need('no-issued-key-or-certificate', not os.path.lexists('issued/privkey.pem') and not os.path.lexists('issued/fullchain.pem'))
    elif check == 'challenge-server-fault':
        events = [e for e in log if e.get('injected_challenge_fault')]
        responses = [e for e in log if e['method'] == 'RESPONSE' and e['path'] == '/acme/chall/1' and e.get('status') == 503]
        need('challenge-server-fault-reached', len(events) == 1 and len(responses) == 1)
        need('no-finalize-or-certificate-after-fault', not any(e['path'] in ('/acme/finalize/1','/acme/cert/1') for e in posts))
        need('no-issued-key-or-certificate', not os.path.lexists('issued/privkey.pem') and not os.path.lexists('issued/fullchain.pem'))
    else:
        need('known-verifier-check', False, check)
    for f in fails:
        print(f)
    print('verified %s failed=%d' % (check, len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == 'serve-bad-nonce':
        os.environ['ACME_FIXTURE_BAD_NONCE_ONCE'] = '1'
        serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == 'serve-bad-cert':
        os.environ['ACME_FIXTURE_BAD_CERT'] = '1'
        serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == 'serve-challenge-fault':
        os.environ['ACME_FIXTURE_CHALLENGE_FAULT'] = '1'
        serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == 'control':
        control(int(sys.argv[2]))
    elif sys.argv[1] == 'control-invalid-challenge':
        control(int(sys.argv[2]), invalid_challenge=True)
    elif sys.argv[1] == 'control-invalid-csr':
        if sys.argv[3] not in ('identifier', 'signature', 'malformed'):
            raise SystemExit('unknown CSR fault')
        control(int(sys.argv[2]), invalid_csr=sys.argv[3])
    elif sys.argv[1] == 'oracle-selftest':
        oracle_selftest()
    else:
        sys.exit(verify(sys.argv[2], int(sys.argv[3])))
