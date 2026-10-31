#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Loopback HTTPS mock of the Claude messages API for disposable parity-VM fixtures.

  certs                         create a synthetic PKI under $HOME/pki and prove it with Python's ssl
  serve PORT CERT KEY SCRIPT OUT [DEADLINE]
                                serve scripted responses (one per connection; the last repeats),
                                append one JSON record per connection to OUT
  check-request OUT KEY BODYFILE   print the exact-request assertions for the first recorded request
  check-body OUT DUMPFILE          compare the first wire body with a --dump-request file and the
                                   independently built expected object
  check-secret KEY FILE...         the key must not appear in any FILE
  count OUT                        number of recorded requests
  gap OUT                          seconds between the first two recorded requests
"""
import base64
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import uuid

HOME = Path(os.environ.get('HOME', '/tmp/parity-home'))
PKI = HOME / 'pki'
OPENSSL = '/usr/bin/openssl'
KEY = 'sk-ant-synthetic-fixture-key-0123456789abcdef'
EXPECTED_HEADERS = ['accept', 'anthropic-version', 'connection', 'content-length', 'content-type', 'host', 'x-api-key']


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)


def make_ca(name):
    run(OPENSSL, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(PKI / (name + '.key')),
        '-out', str(PKI / (name + '.pem')), '-subj', '/CN=' + name, '-days', '2',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')


def make_leaf(name, ca, san):
    run(OPENSSL, 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(PKI / (name + '.key')),
        '-out', str(PKI / (name + '.csr')), '-subj', '/CN=' + name)
    (PKI / (name + '.ext')).write_text('subjectAltName=' + san + '\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n')
    run(OPENSSL, 'x509', '-req', '-in', str(PKI / (name + '.csr')), '-CA', str(PKI / (ca + '.pem')), '-CAkey', str(PKI / (ca + '.key')),
        '-CAcreateserial', '-out', str(PKI / (name + '.pem')), '-days', '2', '-extfile', str(PKI / (name + '.ext')))


def certs():
    PKI.mkdir(mode=0o700, parents=True, exist_ok=False)
    make_ca('ca'); make_ca('rogue-ca')
    make_leaf('server', 'ca', 'IP:127.0.0.1,DNS:claude-mock.test')
    make_leaf('wrong', 'ca', 'DNS:other.test')
    make_leaf('rogue', 'rogue-ca', 'IP:127.0.0.1')
    (HOME / 'key.txt').write_text(KEY + '\n')
    for leaf, ca in (('server', 'ca'), ('wrong', 'ca'), ('rogue', 'rogue-ca')):
        run(OPENSSL, 'verify', '-CAfile', str(PKI / (ca + '.pem')), str(PKI / (leaf + '.pem')))
    # Independent TLS stack control: Python's ssl against each (cert, CA, name) combination.
    results = {}
    for leaf, ca, host, expect in (('server', 'ca', '127.0.0.1', True), ('wrong', 'ca', '127.0.0.1', False), ('rogue', 'ca', '127.0.0.1', False), ('rogue', 'rogue-ca', '127.0.0.1', True)):
        results['%s/%s/%s' % (leaf, ca, host)] = (probe(leaf, ca, host) == expect)
    print(json.dumps(results, sort_keys=True))
    if not all(results.values()):
        raise SystemExit('PKI control failed')


def probe(leaf, ca, host):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(PKI / (leaf + '.pem')), str(PKI / (leaf + '.key')))
    srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1)
    port = srv.getsockname()[1]
    import threading
    def accept():
        try:
            c, _ = srv.accept(); c.settimeout(3)
            with sctx.wrap_socket(c, server_side=True) as t:
                t.recv(1)
        except (OSError, ssl.SSLError):
            pass
    th = threading.Thread(target=accept); th.start()
    cctx = ssl.create_default_context(cafile=str(PKI / (ca + '.pem')))
    cctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    ok = False
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
            with cctx.wrap_socket(s, server_hostname=host) as t:
                t.sendall(b'x'); ok = True
    except (OSError, ssl.SSLError):
        ok = False
    th.join(); srv.close()
    return ok


def read_request(conn):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 1 << 20:
            return None
    head, _, rest = data.partition(b'\r\n\r\n')
    lines = head.decode('latin1').split('\r\n')
    headers = [l.split(':', 1) for l in lines[1:]]
    headers = [(k, v.lstrip()) for k, v in headers]
    length = int(dict((k.lower(), v) for k, v in headers).get('content-length', '0'))
    while len(rest) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        rest += chunk
    return lines[0], headers, rest, head


def respond(conn, step):
    reason = step.get('reason', 'OK')
    head = 'HTTP/1.1 %d %s\r\n' % (step.get('status', 200), reason)
    chunks = [base64.b64decode(c) for c in step.get('chunks', [])]
    chunked = step.get('chunked', True)
    headers = [tuple(h) for h in step.get('headers', [])]
    if chunked:
        headers.append(('Transfer-Encoding', 'chunked'))
    else:
        headers.append(('Content-Length', str(sum(len(c) for c in chunks))))
    headers.append(('Connection', 'close'))
    conn.sendall((head + ''.join('%s: %s\r\n' % h for h in headers) + '\r\n').encode('latin1'))
    for c in chunks:
        conn.sendall(b'%x\r\n' % len(c) + c + b'\r\n' if chunked else c)
        time.sleep(step.get('delay_ms', 10) / 1000)
    if chunked and not step.get('truncate'):
        conn.sendall(b'0\r\n\r\n')


def serve(port, cert, key, script, out, deadline=25):
    steps = json.loads(Path(script).read_text())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port)); srv.listen(8)
    Path(out + '.ready').write_text('ready\n')
    start = time.monotonic(); n = 0
    while time.monotonic() - start < float(deadline):
        srv.settimeout(0.2)
        try:
            raw, _ = srv.accept()
        except socket.timeout:
            continue
        raw.settimeout(5)
        rec = {'n': n, 't_ms': round((time.monotonic() - start) * 1000)}
        try:
            with ctx.wrap_socket(raw, server_side=True) as conn:
                req = read_request(conn)
                if req is None:
                    rec['handshake'] = 'ok'; rec['error'] = 'no request'
                else:
                    line, headers, body, head = req
                    rec.update({'handshake': 'ok', 'request_line': line, 'headers': headers, 'body_b64': base64.b64encode(body).decode(),
                                'raw_head_b64': base64.b64encode(head).decode()})
                    with open(out, 'a') as f:
                        f.write(json.dumps(rec) + '\n')
                    respond(conn, steps[min(n, len(steps) - 1)])
                    rec = None
        except (OSError, ssl.SSLError) as exc:
            if rec is not None:
                rec.update({'handshake': 'failed', 'error': type(exc).__name__})
        if rec is not None:
            with open(out, 'a') as f:
                f.write(json.dumps(rec) + '\n')
        n += 1
    srv.close()


def records(out):
    try:
        return [json.loads(l) for l in Path(out).read_text().splitlines()]
    except OSError:
        return []


def ok(cond, label, detail=''):
    print(label + ('=ok' if cond else '=BAD ' + detail))


def check_request(out, key, bodyfile):
    reqs = [r for r in records(out) if r.get('handshake') == 'ok' and 'headers' in r]
    if not reqs:
        print('request=none'); return
    r = reqs[0]; h = {k.lower(): v for k, v in r['headers']}
    body = base64.b64decode(r['body_b64']); raw = base64.b64decode(r['raw_head_b64']) + b'\r\n\r\n' + body
    ok(r['request_line'] == 'POST /v1/messages HTTP/1.1', 'request-line', r['request_line'])
    ok(sorted(k.lower() for k, _ in r['headers']) == EXPECTED_HEADERS, 'header-set', str(sorted(k.lower() for k, _ in r['headers'])))
    expected = {'host': '127.0.0.1', 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json',
                'accept': 'text/event-stream', 'connection': 'close'}
    for k, v in expected.items():
        ok(h.get(k) == v, 'header-' + k, repr(h.get(k)))
    ok(h.get('content-length') == str(len(body)) and len(body) > 0, 'content-length-exact', '%s vs %d' % (h.get('content-length'), len(body)))
    ok(raw.count(key.encode()) == 1, 'key-only-in-x-api-key', str(raw.count(key.encode())))
    ok(Path(bodyfile).read_bytes() == body if bodyfile != '-' else True, 'body-matches-file')


def expected_body():
    return {"model": "claude-test-model", "max_tokens": 77, "stream": True, "thinking": {"type": "adaptive"},
            "system": 'sys "quoted"\n\ttext \\ end',
            "tools": [{"name": "t", "description": "d", "input_schema": {"type": "object"}}],
            "messages": [{"role": "user", "content": 'user line with "quotes", a \\ backslash and é'}]}


def check_body(out, dump):
    reqs = [r for r in records(out) if 'body_b64' in r]
    if not reqs:
        print('body=none'); return
    body = base64.b64decode(reqs[0]['body_b64'])
    d = Path(dump).read_bytes()
    ok(d == body + b'\n', 'wire-body-equals-dump-request', 'dump %d wire %d' % (len(d), len(body)))
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    ok(parsed == expected_body(), 'wire-body-equals-independent-object', repr(parsed)[:200])
    ok(list(parsed or {}) == ['model', 'max_tokens', 'stream', 'thinking', 'system', 'tools', 'messages'], 'field-order', str(list(parsed or {})))


def check_secret(key, *files):
    for f in files:
        data = Path(f).read_bytes() if Path(f).exists() else b''
        ok(key.encode() not in data, 'secret-absent-' + Path(f).name)


if __name__ == '__main__':
    require_guest()
    a = sys.argv[1:]
    cmd = a[0]
    if cmd == 'certs': certs()
    elif cmd == 'serve': serve(int(a[1]), a[2], a[3], a[4], a[5], *(a[6:7]))
    elif cmd == 'check-request': check_request(a[1], a[2], a[3])
    elif cmd == 'check-body': check_body(a[1], a[2])
    elif cmd == 'check-secret': check_secret(a[1], *a[2:])
    elif cmd == 'count': print(len([r for r in records(a[1]) if 'headers' in r]))
    elif cmd == 'gap':
        r = [x for x in records(a[1]) if 'headers' in x]
        print('%.2f' % ((r[1]['t_ms'] - r[0]['t_ms']) / 1000) if len(r) > 1 else 'none')
    else: raise SystemExit('unknown command')
