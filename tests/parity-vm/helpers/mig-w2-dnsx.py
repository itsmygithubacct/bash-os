#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only DNS transport peer, independent DoT/DoH client probes and assertions for the w2 DNS fixtures.

    mig-w2-dnsx.py mock UDP_PORT DOT_PORT DOH_PORT READY   # one zone served over UDP, DoT and DoH (HTTP/1.1)
    mig-w2-dnsx.py probe DOT_PORT DOH_PORT                 # independent DoT and DoH client probes of a server
    mig-w2-dnsx.py waitport PORT...                        # wait until loopback TCP ports accept
    mig-w2-dnsx.py verify-r4                               # compare candidate query output across transports

Wire format per RFC 1035, RFC 7858 (two-byte length framing inside TLS) and RFC 8484 (application/dns-message,
POST body or GET ?dns=base64url). Expected answers are the zone data below, fixed by the fixture.
"""
import base64
import http.client
import os
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOME = os.environ.get('HOME', '/tmp/parity-home')
CERT, KEY = HOME + '/tls.crt', HOME + '/tls.key'
ZONE = {
    ('www.x.test.', 1): [socket.inet_aton('192.0.2.10'), socket.inet_aton('192.0.2.11')],
    ('x.test.', 15): [struct.pack('!H', 10) + b'\x04mail\x01x\x04test\x00'],
    ('txt.x.test.', 16): [b'\x05alpha', b'\x04beta'],
}
NAMES = {n for n, _ in ZONE} | {'ns1.x.test.'}
SERVFAIL_NAME = 'fail.x.test.'
SOA = (b'\x03ns1\x01x\x04test\x00\x0ahostmaster\x01x\x04test\x00' + struct.pack('!IIIII', 1, 3600, 600, 86400, 300))


def qname_wire(name):
    return b''.join(bytes([len(l)]) + l.encode() for l in name.rstrip('.').split('.')) + b'\0'


def build_query(name, qtype, qid=0x4242):
    return struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0) + qname_wire(name) + struct.pack('!HH', qtype, 1)


def read_name(data, off):
    labels, jumped, end = [], False, None
    while True:
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        labels.append(data[off + 1:off + 1 + n].decode())
        off += 1 + n
    return '.'.join(labels).lower() + '.', (end if jumped else off)


def parse_response(data):
    qid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = read_name(data, off)
        typ, cls, ttl, rdlen = struct.unpack('!HHIH', data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        if typ == 1:
            text = socket.inet_ntoa(rd)
        elif typ == 15:
            text = '%d %s' % (struct.unpack('!H', rd[:2])[0], read_name(data, off + 2)[0])
        elif typ == 16:
            text, p = [], 0
            while p < len(rd):
                text.append(rd[p + 1:p + 1 + rd[p]].decode())
                p += 1 + rd[p]
            text = ''.join(text)
        else:
            text = rd.hex()
        answers.append((typ, text))
        off += rdlen
    return {'id': qid, 'rcode': flags & 15, 'aa': bool(flags & 0x400), 'answers': answers}


def answer(query):
    qid = query[:2]
    end = 12
    while query[end]:
        end += query[end] + 1
    name = read_name(query, 12)[0]
    qtype = struct.unpack('!H', query[end + 1:end + 3])[0]
    question = query[12:end + 5]
    if name == SERVFAIL_NAME:
        return qid + struct.pack('!HHHHH', 0x8402, 1, 0, 0, 0) + question
    rrs = ZONE.get((name, qtype), [])
    if rrs:
        body = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 300, len(r)) + r for r in rrs)
        return qid + struct.pack('!HHHHH', 0x8400, 1, len(rrs), 0, 0) + question + body
    rcode = 0 if name in NAMES else 3
    soa = b'\xc0\x0c' + struct.pack('!HHIH', 6, 1, 300, len(SOA)) + SOA
    return qid + struct.pack('!HHHHH', 0x8400 | rcode, 1, 0, 1, 0) + question + soa


def mock(up, dp, hp, ready):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', up))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(['http/1.1'])
    dot = socket.socket()
    dot.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dot.bind(('127.0.0.1', dp))
    dot.listen(8)

    def serve_dot():
        while True:
            conn, _ = dot.accept()
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                while True:
                    hdr = tls.recv(2)
                    if len(hdr) < 2:
                        break
                    n = struct.unpack('!H', hdr)[0]
                    q = b''
                    while len(q) < n:
                        q += tls.recv(n - len(q))
                    a = answer(q)
                    tls.sendall(struct.pack('!H', len(a)) + a)
                    break
                tls.close()
            except Exception:
                conn.close()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, q):
            a = answer(q)
            self.send_response(200)
            self.send_header('Content-Type', 'application/dns-message')
            self.send_header('Content-Length', str(len(a)))
            self.end_headers()
            self.wfile.write(a)

        def do_POST(self):
            self.reply(self.rfile.read(int(self.headers.get('Content-Length', 0))))

        def do_GET(self):
            qs = parse_qs(urlparse(self.path).query)
            self.reply(base64.urlsafe_b64decode(qs['dns'][0] + '==='))
    doh = ThreadingHTTPServer(('127.0.0.1', hp), H)
    doh.socket = ctx.wrap_socket(doh.socket, server_side=True)
    threading.Thread(target=serve_dot, daemon=True).start()
    threading.Thread(target=doh.serve_forever, daemon=True).start()
    Path(ready).write_text('ready\n')
    while True:
        data, src = udp.recvfrom(2048)
        udp.sendto(answer(data), src)


def probe(dot_port, doh_port):
    fails = []

    def need(name, cond, detail=''):
        if not cond:
            fails.append('%s FAIL %s' % (name, detail))
    ctx = ssl.create_default_context(cafile=CERT)
    want = [(1, '192.0.2.10'), (1, '192.0.2.11')]
    q = build_query('www.x.test.', 1)
    try:
        c = ssl.create_default_context(cafile=CERT)
        with socket.create_connection(('127.0.0.1', dot_port), timeout=5) as raw:
            with c.wrap_socket(raw, server_hostname='127.0.0.1') as tls:
                tls.sendall(struct.pack('!H', len(q)) + q)
                n = struct.unpack('!H', tls.recv(2))[0]
                data = b''
                while len(data) < n:
                    data += tls.recv(n - len(data))
        r = parse_response(data)
        need('dot-answer-rrset', sorted(r['answers']) == want and r['rcode'] == 0, r)
    except Exception as exc:
        need('dot-answer-rrset', False, repr(exc))
    for label, method in (('doh-http1-post', 'POST'), ('doh-http1-get', 'GET')):
        try:
            c = ssl.create_default_context(cafile=CERT)
            c.set_alpn_protocols(['http/1.1'])
            conn = http.client.HTTPSConnection('127.0.0.1', doh_port, context=c, timeout=5)
            if method == 'POST':
                conn.request('POST', '/dns-query', q, {'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'})
            else:
                conn.request('GET', '/dns-query?dns=' + base64.urlsafe_b64encode(q).rstrip(b'=').decode(), headers={'Accept': 'application/dns-message'})
            resp = conn.getresponse()
            body = resp.read()
            need(label + '-status-200-dns-message', resp.status == 200 and resp.getheader('Content-Type') == 'application/dns-message', (resp.status, resp.getheader('Content-Type')))
            r = parse_response(body)
            need(label + '-answer-rrset', sorted(r['answers']) == want and r['rcode'] == 0, r)
        except Exception as exc:
            need(label + '-answer-rrset', False, repr(exc))
    try:
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection(('127.0.0.1', doh_port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname='127.0.0.1') as tls:
                need('doh-tls-handshake-and-alpn-selected', tls.selected_alpn_protocol() in ('h2', 'http/1.1'), tls.selected_alpn_protocol())
    except Exception as exc:
        need('doh-tls-handshake-and-alpn-selected', False, repr(exc))
    for f in fails:
        print(f)
    print('verified probe failed=%d' % len(fails))


QUERIES = [('www.x.test', 'A'), ('x.test', 'MX'), ('txt.x.test', 'TXT'), ('nx.x.test', 'A'), ('fail.x.test', 'A'), ('www.x.test', 'TXT')]
EXPECT = {('www.x.test', 'A'): ['192.0.2.10', '192.0.2.11'], ('x.test', 'MX'): ['10 mail.x.test'],
          ('txt.x.test', 'TXT'): ['alpha', 'beta'], ('nx.x.test', 'A'): [], ('fail.x.test', 'A'): [], ('www.x.test', 'TXT'): []}
RCODE_WORD = {('nx.x.test', 'A'): 'NXDOMAIN', ('fail.x.test', 'A'): 'SERVFAIL'}


def read(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return None


def norm(text):
    return sorted(l.strip().strip('"').rstrip('.').lower() for l in (text or '').splitlines() if l.strip())


def verify_r4():
    fails = []
    for name, typ in QUERIES:
        base = {}
        for tag in ('u', 'd', 'h'):
            stem = '%s-%s-%s' % (tag, name, typ)
            out, err, rc = read(stem + '.out'), read(stem + '.err'), (read(stem + '.rc') or 'missing').strip()
            base[tag] = (rc, norm(out), err)
            want = EXPECT[(name, typ)]
            if (name, typ) in RCODE_WORD:
                ok = rc not in ('0', 'missing') and RCODE_WORD[(name, typ)] in (err or '') and not norm(out)
            elif want:
                ok = rc == '0' and norm(out) == sorted(w.lower() for w in want)
            else:
                ok = not norm(out)
            if not ok:
                fails.append('%s-%s-%s-matches-zone FAIL rc=%s out=%r err=%r' % (tag, name, typ, rc, norm(out), (err or '')[:100]))
        for tag in ('d', 'h'):
            same_rc = (base[tag][0] == '0') == (base['u'][0] == '0')
            if not (same_rc and base[tag][1] == base['u'][1]):
                fails.append('%s-%s-%s-equals-udp FAIL %r vs %r' % (tag, name, typ, base[tag][:2], base['u'][:2]))
    for f in fails:
        print(f)
    print('verified r4 failed=%d' % len(fails))


if __name__ == '__main__':
    if sys.argv[1] == 'mock':
        mock(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    elif sys.argv[1] == 'waitport':
        end = time.monotonic() + 10
        for port in sys.argv[2:]:
            want = '0100007F:%04X' % int(port)
            while True:
                rows = Path('/proc/net/tcp').read_text().splitlines()[1:]
                if any(r.split()[1] == want and r.split()[3] == '0A' for r in rows):
                    break
                if time.monotonic() > end:
                    print('port-%s-not-listening' % port)
                    sys.exit(1)
                time.sleep(0.05)
    elif sys.argv[1] == 'probe':
        probe(int(sys.argv[2]), int(sys.argv[3]))
    else:
        verify_r4()
