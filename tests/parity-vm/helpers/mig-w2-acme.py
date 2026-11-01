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
        self.order = {'status': 'pending'}
        self.cert_pem = None
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
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
            prot = json.loads(unb64u(jws['protected']))
        except Exception:
            return None, None, ['malformed-jws']
        if prot.get('alg') != 'ES256':
            problems.append('alg')
        if prot.get('url') != url:
            problems.append('url')
        if prot.get('nonce') not in self.nonces:
            problems.append('nonce')
        else:
            self.nonces.discard(prot['nonce'])
        has_jwk, has_kid = 'jwk' in prot, 'kid' in prot
        if has_jwk == has_kid:
            problems.append('jwk-xor-kid')
        jwk = prot.get('jwk') or self.jwk
        try:
            nums = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64u(jwk['x']), 'big'), int.from_bytes(unb64u(jwk['y']), 'big'), ec.SECP256R1())
            sig = unb64u(jws['signature'])
            nums.public_key().verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')),
                                     (jws['protected'] + '.' + jws['payload']).encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:
            problems.append('signature')
        payload = unb64u(jws.get('payload', ''))
        return prot, payload, problems

    def make_handler(ca):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, body=b'', ctype='application/json', extra=()):
                self.send_response(code)
                self.send_header('Content-Type', ctype)
                self.send_header('Replay-Nonce', ca.nonce())
                for k, v in extra:
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
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
                    return self.send(400, json.dumps({'type': 'urn:ietf:params:acme:error:malformed', 'detail': ','.join(problems)}).encode(), 'application/problem+json')
                p = self.path
                if p == '/acme/new-acct':
                    ca.jwk = prot['jwk']
                    self.send(201, b'{"status":"valid"}', extra=[('Location', ca.base + '/acme/acct/1')])
                elif p == '/acme/new-order':
                    ca.order = {'status': 'pending', 'identifiers': [{'type': 'dns', 'value': FIXTURE_ID}],
                                'authorizations': [ca.base + '/acme/authz/1'], 'finalize': ca.base + '/acme/finalize/1'}
                    self.send(201, json.dumps(ca.order).encode(), extra=[('Location', ca.base + '/acme/order/1')])
                elif p == '/acme/authz/1':
                    status = ca.order.get('authz', 'pending')
                    self.send(200, json.dumps({'status': status, 'identifier': {'type': 'dns', 'value': FIXTURE_ID},
                                               'challenges': [{'type': 'http-01', 'url': ca.base + '/acme/chall/1', 'token': TOKEN, 'status': status}]}).encode())
                elif p == '/acme/chall/1':
                    fetched = None
                    try:
                        fetched = urllib.request.urlopen('http://127.0.0.1:%d/.well-known/acme-challenge/%s' % (ca.port + 2, TOKEN), timeout=2).read().decode()
                    except Exception:
                        pass
                    self.record(fetched=fetched)
                    ca.order['authz'] = 'valid'
                    ca.order['status'] = 'ready'
                    self.send(200, json.dumps({'type': 'http-01', 'url': url, 'token': TOKEN, 'status': 'processing'}).encode())
                elif p == '/acme/finalize/1':
                    csr = json.loads(payload).get('csr', '')
                    ok = False
                    try:
                        req = x509.load_der_x509_csr(unb64u(csr))
                        san = req.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                        ok = req.is_signature_valid and FIXTURE_ID in san
                    except Exception:
                        pass
                    self.record(csr_ok=ok)
                    if not ok:
                        return self.send(400, b'{"type":"urn:ietf:params:acme:error:badCSR"}', 'application/problem+json')
                    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture CA')])
                    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FIXTURE_ID)]))
                            .issuer_name(name).public_key(req.public_key()).serial_number(7)
                            .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2027, 1, 1))
                            .sign(ca.ca_key, hashes.SHA256()))
                    ca.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
                    ca.order.update(status='valid', certificate=ca.base + '/acme/cert/1')
                    self.send(200, json.dumps(ca.order).encode(), extra=[('Location', ca.base + '/acme/order/1')])
                elif p == '/acme/order/1':
                    self.send(200, json.dumps(ca.order).encode())
                elif p == '/acme/cert/1':
                    self.send(200, (ca.cert_pem or '').encode(), 'application/pem-certificate-chain')
                else:
                    self.send(404)
        return H


def serve(cport, kport, ready):
    servers = []
    for port in (cport, kport):
        ca = CA(port)
        srv = ThreadingHTTPServer(('127.0.0.1', port), ca.make_handler())
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    open(ready, 'w').write('ready\n')
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        time.sleep(1)


# ---- positive control: an independent client that performs the whole lifecycle ----------------
def control(port):
    base = 'http://127.0.0.1:%d' % port
    key = account_key()
    jwk = jwk_of(key)
    state = {'nonce': None}

    def req(method, url, data=None, ctype=None):
        r = urllib.request.Request(url, data=data, method=method, headers={'Content-Type': ctype} if ctype else {})
        try:
            resp = urllib.request.urlopen(r, timeout=5)
        except urllib.error.HTTPError as exc:
            raise SystemExit('control: %s %s -> %s %s' % (method, url, exc.code, exc.read()[:200]))
        state['nonce'] = resp.headers.get('Replay-Nonce')
        return resp

    def post(url, payload, kid=None):
        prot = {'alg': 'ES256', 'nonce': state['nonce'], 'url': url}
        prot.update({'kid': kid} if kid else {'jwk': jwk})
        p64 = b64u(json.dumps(prot).encode())
        pl = '' if payload is None else b64u(json.dumps(payload).encode())
        r, s = utils.decode_dss_signature(key.sign((p64 + '.' + pl).encode(), ec.ECDSA(hashes.SHA256())))
        body = json.dumps({'protected': p64, 'payload': pl, 'signature': b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}).encode()
        return req('POST', url, body, 'application/jose+json')

    want = TOKEN + '.' + thumbprint(jwk)

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
    post(az['challenges'][0]['url'], {}, acct)
    csr_key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, FIXTURE_ID)]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(FIXTURE_ID)]), False).sign(csr_key, hashes.SHA256()))
    fin = json.load(post(o['finalize'], {'csr': b64u(csr.public_bytes(serialization.Encoding.DER))}, acct))
    pem = post(fin['certificate'], None, acct).read().decode()
    assert pem.startswith('-----BEGIN CERTIFICATE-----')
    print('control-ok')


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
        need('order-polled-until-valid', any(e['path'] == '/acme/order/1' for e in posts), [e['path'] for e in posts])
    elif check == 'r7':
        need('certificate-downloaded', any(e['path'] == '/acme/cert/1' and e['payload_len'] == 0 for e in posts), [e['path'] for e in posts])
        try:
            text = open('issued/fullchain.pem').read()
        except OSError:
            text = ''
        need('certificate-chain-stored', text.startswith('-----BEGIN CERTIFICATE-----'), text[:40])
    elif check == 'r8':
        need('only-loopback-peer-contacted', log and all(e['client'] == '127.0.0.1' for e in log), len(log))
        stages = ['/directory', '/acme/new-acct', '/acme/new-order', '/acme/chall/1', '/acme/finalize/1', '/acme/cert/1']
        need('complete-lifecycle-against-the-private-peer', all(any(e['path'] == s for e in log) for s in stages), [e['path'] for e in log])
    for f in fails:
        print(f)
    print('verified %s failed=%d' % (check, len(fails)))


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        serve(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    elif sys.argv[1] == 'control':
        control(int(sys.argv[2]))
    else:
        verify(sys.argv[2], int(sys.argv[3]))
