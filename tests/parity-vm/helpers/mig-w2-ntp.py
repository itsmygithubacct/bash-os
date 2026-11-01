#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only NTS-KE + NTS-authenticated NTP peer and assertions for the w2 ntp query fixtures.

    mig-w2-ntp.py serve MODE READY   # TLS 1.3 NTS-KE on 127.0.0.1:4460 and NTP/UDP on 127.0.0.1:1234
    mig-w2-ntp.py verify CHECK       # assertions on the peer capture and the candidate output files

MODE is good | ke-error | no-cookie | bad-auth | wrong-uid. The TLS side reuses the independent OpenSSL
(ctypes) NTS-KE peer class from the trace helper, whose reference client already matched its exporter keys;
NTP packets follow RFC 5905 and RFC 8915 s5 (Unique Identifier 0x0104, NTS Cookie 0x0204, Placeholder 0x0304,
Authenticator 0x0404, AES-SIV-CMAC-256 over [packet prefix, nonce]) and are checked with python-cryptography.
"""
import json
import os
import re
import signal
import socket
import struct
import sys
import time
from pathlib import Path

_src = (Path(__file__).with_name('trace-vm-nts-r1.py')).read_text()
_ns = {'__name__': 'trace_nts_peer'}
exec(compile(_src[:_src.index('def parse_stdout')], 'trace-vm-nts-r1.py', 'exec'), _ns)
OpenSSL, response, records, rec, COOKIE0, COOKIE1, REQUEST = (
    _ns[n] for n in ('OpenSSL', 'response', 'records', 'rec', 'COOKIE0', 'COOKIE1', 'REQUEST'))

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

LOG = 'ntp-peer.json'
KE_PORT, NTP_PORT = 4460, 1234
EF_UID, EF_COOKIE, EF_PLACEHOLDER, EF_AUTH = 0x0104, 0x0204, 0x0304, 0x0404
NTP_EPOCH = 2208988800


def ntp_now():
    t = time.time()
    return struct.pack('!II', int(t) + NTP_EPOCH, int((t % 1) * 2**32))


def fields(pkt):
    out, off = [], 48
    while off + 4 <= len(pkt):
        typ, flen = struct.unpack('!HH', pkt[off:off + 4])
        out.append((typ, pkt[off + 4:off + flen], off))
        off += flen
    return out


def pad4(n):
    return (n + 3) & ~3


def serve(mode, ready):
    log = {'mode': mode, 'ke': {}, 'ntp': []}
    ke = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ke.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ke.bind(('127.0.0.1', KE_PORT))
    ke.listen(4)
    ke.settimeout(0.2)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', NTP_PORT))
    udp.settimeout(0.2)
    keys = {}

    def save():
        Path(LOG).write_text(json.dumps(log))

    def stop(*_):
        save()
        os._exit(0)
    signal.signal(signal.SIGTERM, stop)
    Path(ready).write_text('ready\n')
    cookies = [COOKIE0.hex(), COOKIE1.hex()]
    while True:
        try:
            conn, _ = ke.accept()
        except socket.timeout:
            conn = None
        if conn:
            tls = None
            trace = {}
            try:
                conn.setblocking(True)
                tls = OpenSSL(True, trace)
                tls.handshake(conn)
                request = tls.read_message()
                keys['c2s'], keys['s2c'] = tls.exporter(0), tls.exporter(1)
                body = response({'ke-error': 'error', 'no-cookie': 'nocookie'}.get(mode, 'good')) if mode != 'no-cookie' else (
                    rec(0x8001, struct.pack('!H', 0)) + rec(0x8004, struct.pack('!H', 15)) + rec(6, b'127.0.0.1') +
                    rec(7, struct.pack('!H', NTP_PORT)) + rec(0x8000, b''))
                if mode == 'good' or mode in ('bad-auth', 'wrong-uid'):
                    body = (rec(0x8001, struct.pack('!H', 0)) + rec(0x8004, struct.pack('!H', 15)) + rec(5, COOKIE0) +
                            rec(5, COOKIE1) + rec(6, b'127.0.0.1') + rec(7, struct.pack('!H', NTP_PORT)) + rec(0x8000, b''))
                tls.write(body)
                log['ke'] = {'alpn_offered': trace.get('alpn_offered_hex'), 'alpn_selected': trace.get('alpn_selected'),
                             'tls_version': trace.get('tls_version'), 'request_hex': request.hex(),
                             'c2s': keys['c2s'].hex(), 's2c': keys['s2c'].hex()}
            except Exception as exc:
                log['ke']['error'] = repr(exc)
            finally:
                if tls:
                    tls.close()
                conn.close()
            save()
        try:
            data, src = udp.recvfrom(2048)
        except socket.timeout:
            continue
        entry = {'len': len(data), 'src': src[0]}
        fl = fields(data)
        entry['types'] = [hex(t) for t, _, _ in fl]
        entry['mode'] = data[0] & 7
        uid = next((b for t, b, _ in fl if t == EF_UID), None)
        cookie = next((b for t, b, _ in fl if t == EF_COOKIE), None)
        ph = next((b for t, b, _ in fl if t == EF_PLACEHOLDER), None)
        auth = next(((b, o) for t, b, o in fl if t == EF_AUTH), None)
        entry.update(uid_len=None if uid is None else len(uid), cookie=None if cookie is None else cookie.hex(),
                     placeholder_len=None if ph is None else len(ph), auth_ok=False)
        if auth and keys:
            body, off = auth
            nl, cl = struct.unpack('!HH', body[:4])
            nonce, ct = body[4:4 + nl], body[4 + pad4(nl):4 + pad4(nl) + cl]
            try:
                AESSIV(keys['c2s']).decrypt(ct, [data[:off], nonce])
                entry['auth_ok'] = True
            except Exception:
                pass
        log['ntp'].append(entry)
        if entry['auth_ok'] and uid is not None:
            hdr = bytearray(48)
            hdr[0], hdr[1], hdr[2], hdr[3] = 0x24, 2, 10, 0xEC
            hdr[12:16] = b'LOCL'
            hdr[24:32] = data[40:48]
            hdr[32:40] = ntp_now()
            hdr[40:48] = ntp_now()
            out = bytes(hdr)
            echo_uid = bytes(32) if mode == 'wrong-uid' else uid
            out += struct.pack('!HH', EF_UID, 4 + len(echo_uid)) + echo_uid
            nonce = os.urandom(16)
            newcookie = bytes.fromhex('c1c2c3c4c5c6c7c8')
            plain = struct.pack('!HH', EF_COOKIE, 4 + len(newcookie)) + newcookie
            key = bytes(32) if mode == 'bad-auth' else keys['s2c']
            ct = AESSIV(key).encrypt(plain, [out, nonce])
            body = struct.pack('!HH', 16, len(ct)) + nonce + ct + bytes(pad4(len(ct)) - len(ct))
            out += struct.pack('!HH', EF_AUTH, 4 + len(body)) + body
            udp.sendto(out, src)
        save()


def read(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return ''


def verify(check):
    fails = []

    def need(name, cond, detail=''):
        if not cond:
            fails.append('%s FAIL %s' % (name, detail))
    log = json.loads(read(LOG) or '{"ke":{},"ntp":[]}')
    ke = log.get('ke', {})
    if check == 'r1':
        need('tls13-handshake', ke.get('tls_version') == '0x304', ke.get('tls_version'))
        need('alpn-ntske-1-offered', (ke.get('alpn_offered') or '').find('6e74736b652f31') >= 0, ke.get('alpn_offered'))
        need('ke-request-next-protocol-aead-end', ke.get('request_hex') == REQUEST.hex(), ke.get('request_hex'))
        need('trust-from-fixture-bundle-no-error', 'error' not in ke, ke.get('error'))
    elif check == 'r2':
        n = log.get('ntp', [])
        need('ntp-request-received', len(n) == 1, len(n))
        if n:
            e = n[0]
            need('unique-identifier-32-bytes', e['uid_len'] == 32, e['uid_len'])
            need('first-cookie-consumed', e['cookie'] == COOKIE0.hex(), e['cookie'])
            need('cookie-placeholder-present-same-size', e['placeholder_len'] == len(COOKIE0), e['placeholder_len'])
            need('authenticator-seals-with-exported-c2s-key', e['auth_ok'], e['types'])
            need('client-mode', e['mode'] == 3, e['mode'])
    elif check == 'r3':
        out = read('query-out.txt').strip()
        m = re.fullmatch(r'offset=(-?\d+\.\d+) delay=(\d+\.\d+) stratum=2 server=127\.0\.0\.1', out)
        need('result-line-offset-delay-stratum-server', bool(m), out)
        if m:
            need('offset-small-for-same-host-peer', abs(float(m.group(1))) < 5, m.group(1))
    elif check == 'r4':
        want = {'ke-error': 'nts-ke failed', 'no-cookie': 'returned no NTP cookie', 'bad-auth': 'NTS authenticator verification failed',
                'wrong-uid': 'NTS authenticator verification failed'}
        for mode, needle in want.items():
            rc = read('rc-%s.txt' % mode).strip()
            err = read('err-%s.txt' % mode)
            need(mode + '-nonzero-status', rc not in ('', '0'), rc)
            need(mode + '-diagnostic', needle in err, err.strip()[:160])
            need(mode + '-no-result-line', 'offset=' not in read('out-%s.txt' % mode), read('out-%s.txt' % mode))
    for f in fails:
        print(f)
    print('verified %s failed=%d' % (check, len(fails)))


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        serve(sys.argv[2], sys.argv[3])
    else:
        verify(sys.argv[2])
