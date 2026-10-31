#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only DHCPv4 peers and independent RFC 2131 codec for the w2 migration fixtures.

The module is imported (by file path) by sibling helpers and also runs as a script:

    mig-w2-dhcp4.py peer MODE SYNC_FIFO     # peer in its own network namespace on veth1
    mig-w2-dhcp4.py verify CHECK [args]     # assertions on the peer capture, one line each

The wire layouts below come from RFC 2131/2132 and are written without reference to
the candidate's loadable sources.
"""
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time

HOME = os.environ.get('HOME', '/tmp/parity-home')
LOG = os.path.join(HOME, 'w2-peer.json')
IP = '/usr/bin/ip'
CLIENT_MAC = '02:00:00:00:0a:01'
PEER_MAC = '02:00:00:00:0a:02'
PEER_IP = '192.0.2.1'
CLIENT_IP = '192.0.2.10'
COOKIE = bytes.fromhex('63825363')
MSG = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}


def mac_bytes(text):
    return bytes(int(x, 16) for x in text.split(':'))


def ip_bytes(text):
    return socket.inet_aton(text)


def d4_parse(b):
    """Parse a BOOTP/DHCP payload; options keep wire order as (code, bytes) pairs."""
    if len(b) < 240 or b[236:240] != COOKIE:
        return None
    op, htype, hlen, hops = b[0], b[1], b[2], b[3]
    xid, secs, flags = struct.unpack('!IHH', b[4:12])
    opts = []
    p = 240
    while p < len(b):
        c = b[p]
        p += 1
        if c == 0:
            continue
        if c == 255:
            break
        n = b[p]
        p += 1
        opts.append((c, bytes(b[p:p + n])))
        p += n
    return {'op': op, 'htype': htype, 'hlen': hlen, 'hops': hops, 'xid': xid, 'secs': secs, 'flags': flags,
            'ciaddr': b[12:16], 'yiaddr': b[16:20], 'siaddr': b[20:24], 'giaddr': b[24:28],
            'chaddr': b[28:44], 'sname': b[44:108], 'file': b[108:236], 'opts': opts}


def opt(msg, code):
    for c, v in msg['opts']:
        if c == code:
            return v
    return None


def d4_build(op, xid, mac, options, yiaddr='0.0.0.0', ciaddr='0.0.0.0', siaddr='0.0.0.0',
             giaddr='0.0.0.0', flags=0x8000):
    b = bytearray(236)
    b[0], b[1], b[2], b[3] = op, 1, 6, 0
    b[4:12] = struct.pack('!IHH', xid, 0, flags)
    b[12:16] = ip_bytes(ciaddr)
    b[16:20] = ip_bytes(yiaddr)
    b[20:24] = ip_bytes(siaddr)
    b[24:28] = ip_bytes(giaddr)
    b[28:28 + len(mac)] = mac
    b += COOKIE
    for c, v in options:
        b += bytes([c, len(v)]) + v
    b += b'\xff'
    while len(b) < 300:
        b += b'\0'
    return bytes(b)


def lease_options(msgtype, server=PEER_IP, lease=3600, t1=1800, t2=3150):
    """The option set the fixture server hands out (all values chosen here, not by the candidate)."""
    return [(53, bytes([msgtype])), (54, ip_bytes(server)), (51, struct.pack('!I', lease)),
            (58, struct.pack('!I', t1)), (59, struct.pack('!I', t2)), (1, ip_bytes('255.255.255.0')),
            (3, ip_bytes('192.0.2.254')), (6, ip_bytes('192.0.2.53') + ip_bytes('192.0.2.54')),
            (15, b'lab.test'), (42, ip_bytes('192.0.2.123'))]


def frame_parse(f):
    """Ethernet II / IPv4 / UDP frame -> dict, or None."""
    if len(f) < 42 or f[12:14] != b'\x08\x00' or f[14] >> 4 != 4:
        return None
    ihl = (f[14] & 15) * 4
    if f[14 + 9] != 17:
        return None
    udp = f[14 + ihl:]
    sport, dport, ulen = struct.unpack('!HHH', udp[:6])
    return {'eth_dst': f[0:6].hex(), 'eth_src': f[6:12].hex(), 'ip_src': socket.inet_ntoa(f[26:30]),
            'ip_dst': socket.inet_ntoa(f[30:34]), 'sport': sport, 'dport': dport, 'payload': bytes(udp[8:ulen])}


def sh(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def save(entries):
    tmp = LOG + '.tmp'
    with open(tmp, 'w') as handle:
        json.dump(entries, handle)
    os.replace(tmp, LOG)


def join_namespace_and_configure(sync):
    """Move into a fresh netns, announce the pid, wait for veth1, address it, announce readiness."""
    os.unshare(os.CLONE_NEWNET)
    fd = os.open(sync, os.O_WRONLY)
    os.write(fd, ('pid=%d\n' % os.getpid()).encode())
    deadline = time.monotonic() + 15
    while True:
        try:
            socket.if_nametoindex('veth1')
            break
        except OSError:
            if time.monotonic() > deadline:
                raise RuntimeError('veth1 never arrived')
            time.sleep(0.02)
    sh(IP, 'link', 'set', 'lo', 'up')
    sh(IP, 'addr', 'add', PEER_IP + '/24', 'dev', 'veth1')
    sh(IP, 'link', 'set', 'veth1', 'up')
    return fd


class Peer:
    def __init__(self, mode):
        self.mode = mode
        self.log = []
        self.counts = {}
        self.sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sniff.bind(('veth1', 0))
        self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.out.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.out.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'veth1')
        self.out.bind((PEER_IP, 67))
        self.offered = None

    def send(self, payload, dst):
        self.out.sendto(payload, dst)
        self.log.append({'t': time.monotonic(), 'dir': 'out', 'to': list(dst), 'payload': payload.hex()})

    def reply(self, kind, req, yiaddr, wrong_xid=False, port=68, **fields):
        xid = (req['xid'] ^ 0x00010000) if wrong_xid else req['xid']
        mac = req['chaddr'][:6]
        msg = d4_build(2, xid, mac, lease_options(kind), yiaddr=yiaddr, **fields)
        ci = socket.inet_ntoa(req['ciaddr'])
        dst = (ci, port) if ci != '0.0.0.0' else ('255.255.255.255', port)
        self.send(msg, dst)

    def handle(self, info, msg):
        mt = opt(msg, 53)
        kind = MSG.get(mt[0]) if mt else None
        self.counts[kind] = self.counts.get(kind, 0) + 1
        n = self.counts[kind]
        mode = self.mode
        if mode == 'silent' or kind is None:
            return
        if kind == 'DISCOVER':
            if mode == 'offer-only' or mode == 'full':
                self.reply(2, msg, '192.0.2.50')
            elif mode == 'noise':
                if n == 1:
                    self.reply(2, msg, '192.0.2.66', wrong_xid=True)
                elif n == 2:
                    self.reply(5, msg, '192.0.2.67')          # right xid, ACK where OFFER is wanted
                else:
                    self.reply(2, msg, '192.0.2.50')
        elif kind == 'REQUEST':
            if mode == 'offer-only':
                return
            ciaddr = socket.inet_ntoa(msg['ciaddr'])
            if ciaddr != '0.0.0.0':                           # RENEWING: ACK the client's own address
                self.reply(5, msg, ciaddr)
            elif mode == 'full':
                self.reply(5, msg, '192.0.2.50')
            elif mode == 'noise':
                if n == 1:
                    self.reply(5, msg, '192.0.2.66', wrong_xid=True)
                elif n == 2:
                    self.reply(2, msg, '192.0.2.67')          # right xid, OFFER where ACK is wanted
                else:
                    self.reply(5, msg, '192.0.2.50')
        elif kind == 'INFORM':
            if mode == 'full':                                # RFC 2131 s4.1: answer to the client port 68
                self.reply(5, msg, '0.0.0.0', ciaddr=socket.inet_ntoa(msg['ciaddr']))
            elif mode == 'full-source-port':                  # lenient server: answer to the INFORM's source port
                self.reply(5, msg, '0.0.0.0', port=info['sport'], ciaddr=socket.inet_ntoa(msg['ciaddr']))

    def run(self):
        def terminate(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, terminate)
        try:
            while True:
                data, meta = self.sniff.recvfrom(4096)
                if meta[2] == socket.PACKET_OUTGOING:
                    continue
                info = frame_parse(data)
                if not info or info['dport'] != 67:
                    continue
                msg = d4_parse(info['payload'])
                entry = {'t': time.monotonic(), 'dir': 'in', 'eth_dst': info['eth_dst'], 'eth_src': info['eth_src'],
                         'ip_src': info['ip_src'], 'ip_dst': info['ip_dst'], 'sport': info['sport'],
                         'dport': info['dport'], 'payload': info['payload'].hex()}
                self.log.append(entry)
                if msg:
                    self.handle(info, msg)
                save(self.log)
        except KeyboardInterrupt:
            pass
        save(self.log)


def peer_main(mode, sync):
    fd = join_namespace_and_configure(sync)
    peer = Peer(mode)
    os.write(fd, b'ready\n')
    os.close(fd)
    peer.run()


# ---------------------------------------------------------------- verification

class Report:
    def __init__(self):
        self.lines = []

    def check(self, name, cond, detail=''):
        self.lines.append(name + (' ok' if cond else ' FAIL ' + str(detail)))

    def emit(self, name):
        failed = [line for line in self.lines if ' FAIL ' in line]
        for line in failed:
            print(line)
        print('verified %s failed=%d' % (name, len(failed)))


def load_log():
    with open(LOG) as handle:
        data = json.load(handle)
    for e in data:
        e['payload_b'] = bytes.fromhex(e['payload'])
        if e['dir'] == 'in':
            e['msg'] = d4_parse(e['payload_b'])
    return data


def inbound(log, kind):
    out = []
    for e in log:
        if e['dir'] == 'in' and e.get('msg'):
            mt = opt(e['msg'], 53)
            if mt and MSG.get(mt[0]) == kind:
                out.append(e)
    return out


def verify_discover(report, e, mac=CLIENT_MAC, tag='discover'):
    m = e['msg']
    report.check(tag + '-bootp-header', (m['op'], m['htype'], m['hlen'], m['hops']) == (1, 1, 6, 0),
                 (m['op'], m['htype'], m['hlen'], m['hops']))
    report.check(tag + '-broadcast-flag', m['flags'] & 0x8000 == 0x8000, hex(m['flags']))
    report.check(tag + '-chaddr', m['chaddr'][:6] == mac_bytes(mac) and m['chaddr'][6:] == bytes(10), m['chaddr'].hex())
    report.check(tag + '-addresses-zero', m['ciaddr'] == m['yiaddr'] == m['siaddr'] == m['giaddr'] == bytes(4), '')
    report.check(tag + '-opt53', opt(m, 53) == b'\x01', opt(m, 53))
    report.check(tag + '-opt61-clientid', opt(m, 61) == b'\x01' + mac_bytes(mac), opt(m, 61))
    host = opt(m, 12)
    report.check(tag + '-opt12-hostname', bool(host), host)
    prl = opt(m, 55)
    report.check(tag + '-opt55-prl', bool(prl) and 1 in prl and 3 in prl and 6 in prl, prl)
    report.check(tag + '-frame-broadcast', e['eth_dst'] == 'ff' * 6 and e['ip_dst'] == '255.255.255.255'
                 and (e['sport'], e['dport']) == (68, 67) and e['ip_src'] == '0.0.0.0',
                 (e['eth_dst'], e['ip_dst'], e['sport'], e['dport'], e['ip_src']))


def main(argv):
    if argv[1] == 'peer':
        peer_main(argv[2], argv[3])
        return 0
    report = Report()
    log = load_log()
    check = argv[2]
    if check == 'discover':
        disc = inbound(log, 'DISCOVER')
        report.check('discover-count', len(disc) == 1, len(disc))
        if disc:
            verify_discover(report, disc[0])
    elif check == 'request':
        disc = inbound(log, 'DISCOVER')
        reqs = inbound(log, 'REQUEST')
        report.check('discover-count', len(disc) == 1, len(disc))
        report.check('request-count', len(reqs) == 1, len(reqs))
        if disc and reqs:
            d, r = disc[0]['msg'], reqs[0]['msg']
            report.check('request-same-xid', r['xid'] == d['xid'], (hex(r['xid']), hex(d['xid'])))
            report.check('request-opt53', opt(r, 53) == b'\x03', opt(r, 53))
            report.check('request-opt50-offered-yiaddr', opt(r, 50) == ip_bytes('192.0.2.50'), opt(r, 50))
            report.check('request-opt54-offer-server', opt(r, 54) == ip_bytes(PEER_IP), opt(r, 54))
            report.check('request-chaddr', r['chaddr'][:6] == mac_bytes(CLIENT_MAC), r['chaddr'].hex())
    elif check == 'noise':
        disc = inbound(log, 'DISCOVER')
        reqs = inbound(log, 'REQUEST')
        report.check('discover-retransmitted-after-each-ignored-reply', len(disc) == 3, len(disc))
        report.check('request-retransmitted-after-each-ignored-reply', len(reqs) == 3, len(reqs))
        report.check('one-xid-throughout', len({e['msg']['xid'] for e in disc + reqs}) == 1, '')
        report.check('request-names-genuine-offer', bool(reqs) and all(
            opt(e['msg'], 50) == ip_bytes('192.0.2.50') and opt(e['msg'], 54) == ip_bytes(PEER_IP) for e in reqs),
            [opt(e['msg'], 50) for e in reqs])
    elif check == 'silent-timing':
        stage = argv[3]                       # DISCOVER (no offer) or REQUEST (offer but no ack)
        base = float(argv[4])                 # the -t value in seconds
        sent = inbound(log, stage)
        report.check(stage.lower() + '-attempts', len(sent) == 3, len(sent))
        if len(sent) == 3:
            gaps = [sent[1]['t'] - sent[0]['t'], sent[2]['t'] - sent[1]['t']]
            report.check('first-wait-about-t', base * 0.9 <= gaps[0] <= base * 1.9, gaps[0])
            report.check('second-wait-about-2t', base * 1.8 <= gaps[1] <= base * 3.5, gaps[1])
            report.check('timeout-doubles', 1.5 <= gaps[1] / gaps[0] <= 2.8, gaps[1] / gaps[0])
        if stage == 'REQUEST':
            report.check('request-follows-offer', len(inbound(log, 'DISCOVER')) == 1, len(inbound(log, 'DISCOVER')))
    elif check == 'inform':
        inf = inbound(log, 'INFORM')
        report.check('inform-count', len(inf) == 1, len(inf))
        if inf:
            e = inf[0]
            m = e['msg']
            report.check('inform-bootp-header', (m['op'], m['htype'], m['hlen']) == (1, 1, 6), '')
            report.check('inform-opt53', opt(m, 53) == b'\x08', opt(m, 53))
            report.check('inform-ciaddr', m['ciaddr'] == ip_bytes(CLIENT_IP), m['ciaddr'].hex())
            report.check('inform-yiaddr-zero', m['yiaddr'] == bytes(4), '')
            report.check('inform-chaddr', m['chaddr'][:6] == mac_bytes(CLIENT_MAC), m['chaddr'].hex())
            report.check('inform-opt61-clientid', opt(m, 61) == b'\x01' + mac_bytes(CLIENT_MAC), opt(m, 61))
            report.check('inform-opt12-hostname', bool(opt(m, 12)), '')
            prl = opt(m, 55)
            report.check('inform-opt55-prl', bool(prl) and 1 in prl and 3 in prl, prl)
            report.check('inform-no-opt50', opt(m, 50) is None, opt(m, 50))
            report.check('inform-no-opt54', opt(m, 54) is None, opt(m, 54))
    elif check == 'inform-destination':
        inf = inbound(log, 'INFORM')
        report.check('inform-count', len(inf) == 1, len(inf))
        if inf:
            e = inf[0]
            report.check('inform-to-limited-broadcast-port-67', e['ip_dst'] == '255.255.255.255' and e['dport'] == 67,
                         (e['ip_dst'], e['dport']))
            report.check('inform-link-layer-broadcast', e['eth_dst'] == 'ff' * 6, e['eth_dst'])
            report.check('inform-from-selected-interface', e['eth_src'] == CLIENT_MAC.replace(':', ''), e['eth_src'])
            report.check('inform-source-address', e['ip_src'] == CLIENT_IP, e['ip_src'])
    elif check == 'release':
        rel = inbound(log, 'RELEASE')
        everything = [e for e in log if e['dir'] == 'in']
        report.check('exactly-one-datagram', len(everything) == 1 and len(rel) == 1, len(everything))
        if rel:
            e = rel[0]
            m = e['msg']
            report.check('release-unicast-to-server', e['ip_dst'] == PEER_IP and e['eth_dst'] == PEER_MAC.replace(':', '')
                         and e['dport'] == 67, (e['ip_dst'], e['eth_dst'], e['dport']))
            report.check('release-opt53', opt(m, 53) == b'\x07', opt(m, 53))
            report.check('release-ciaddr-is-lease-ip', m['ciaddr'] == ip_bytes('192.0.2.50'), m['ciaddr'].hex())
            report.check('release-opt54-server-id', opt(m, 54) == ip_bytes(PEER_IP), opt(m, 54))
            report.check('release-chaddr', m['chaddr'][:6] == mac_bytes(CLIENT_MAC), m['chaddr'].hex())
            report.check('release-no-prl', opt(m, 55) is None, opt(m, 55))
    elif check == 'nothing-sent':
        report.check('no-datagram-reached-peer', not [e for e in log if e['dir'] == 'in'],
                     len([e for e in log if e['dir'] == 'in']))
    elif check == 'renew':
        req = inbound(log, 'REQUEST')
        report.check('renew-count', len(req) == 1, len(req))
        if req:
            e = req[0]
            m = e['msg']
            report.check('renew-unicast-to-server', e['ip_dst'] == PEER_IP and e['eth_dst'] == PEER_MAC.replace(':', '')
                         and e['dport'] == 67 and e['ip_src'] == CLIENT_IP, (e['ip_dst'], e['eth_dst'], e['ip_src']))
            report.check('renew-opt53', opt(m, 53) == b'\x03', opt(m, 53))
            report.check('renew-ciaddr-is-lease-ip', m['ciaddr'] == ip_bytes(CLIENT_IP), m['ciaddr'].hex())
            report.check('renew-chaddr', m['chaddr'][:6] == mac_bytes(CLIENT_MAC), m['chaddr'].hex())
            report.check('renew-no-opt50', opt(m, 50) is None, opt(m, 50))
    elif check == 'renew-no-server-id':
        req = inbound(log, 'REQUEST')
        report.check('renew-count', len(req) == 1, len(req))
        if req:
            report.check('renewing-request-has-no-opt54', opt(req[0]['msg'], 54) is None, opt(req[0]['msg'], 54))
    elif check == 'stderr-contains':
        path, needle = argv[3], argv[4]
        with open(path, errors='replace') as handle:
            text = handle.read()
        report.check('diagnostic-' + needle.replace(' ', '-'), needle in text, text.strip()[:120])
    else:
        raise SystemExit('unknown check ' + check)
    report.emit(check)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
