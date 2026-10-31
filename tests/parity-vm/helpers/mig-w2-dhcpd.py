#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only DHCPv4 client/relay peers and assertions for the w2 dhcpd (server) fixtures.

    mig-w2-dhcpd.py peer SCENARIO SYNC_FIFO GO_FIFO [ARG]   # scripted client/relay in its own netns on veth1
    mig-w2-dhcpd.py verify CHECK [args]                     # one line per failing assertion, then a summary

The peer sniffs every frame the server puts on veth1 (so destination addresses, ports and link-layer
destinations are observed on the wire) and sends from ordinary UDP sockets. DHCP layouts follow RFC 2131
and the PXE/relay options RFC 4578 / RFC 3046; they are written without reference to the loadable sources.
"""
import importlib.util
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('mig_w2_dhcp4', os.path.join(_here, 'mig-w2-dhcp4.py'))
d4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d4)

HOME = os.environ.get('HOME', '/tmp/parity-home')
LOG = os.path.join(HOME, 'w2-peer-dhcpd.json')
SERVER = '192.0.2.1'
MAC = {'A': bytes.fromhex('02000000 0b01'.replace(' ', '')), 'B': bytes.fromhex('020000000b02'),
       'C': bytes.fromhex('020000000b03')}


def mac_s(mac):
    return ':'.join('%02x' % b for b in mac)


def message(mtype, mac, xid, host=b'host-a', ciaddr='0.0.0.0', giaddr='0.0.0.0', extra=(), flags=0x8000):
    opts = [(53, bytes([mtype])), (61, b'\x01' + mac), (12, host), (55, bytes([1, 3, 6, 15]))] + list(extra)
    return d4.d4_build(1, xid, mac, opts, ciaddr=ciaddr, giaddr=giaddr, flags=flags)


class Client:
    def __init__(self, ip=None, relay_port=None):
        self.log = []
        self.sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.sniff.bind(('veth1', 0))
        self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.out.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.out.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'veth1')
        self.out.bind((ip or '0.0.0.0', relay_port or 68))
        self.default_dst = (SERVER, 67) if ip else ('255.255.255.255', 67)
        self.frames = []

    def drain(self, wait):
        ready, _, _ = select.select([self.sniff], [], [], wait)
        if not ready:
            return False
        data, meta = self.sniff.recvfrom(4096)
        if meta[2] == socket.PACKET_OUTGOING:
            return True
        info = d4.frame_parse(data)
        if info:
            msg = d4.d4_parse(info['payload'])
            if msg and msg['op'] == 2:
                info['payload'] = info['payload'].hex()
                info['t'] = time.monotonic()
                self.frames.append(info)
        return True

    def send(self, label, payload, dst=None):
        self.frames = []
        self.out.sendto(payload, dst or self.default_dst)
        return label

    def wait_reply(self, timeout=2.0, want_type=None):
        end = time.monotonic() + timeout
        seen = 0
        while True:
            for info in self.frames[seen:]:
                msg = d4.d4_parse(bytes.fromhex(info['payload']))
                if want_type is None or d4.opt(msg, 53) == bytes([want_type]):
                    return info
            seen = len(self.frames)
            left = end - time.monotonic()
            if left <= 0:
                return None
            self.drain(left)

    def exchange(self, label, payload, dst=None, timeout=2.0, want_type=None, **extra):
        self.send(label, payload, dst)
        reply = self.wait_reply(timeout, want_type)
        entry = {'label': label, 'sent': payload.hex(), 'reply': reply, 'wall': time.time()}
        entry.update(extra)
        self.log.append(entry)
        save(self.log)
        return reply


def save(log):
    tmp = LOG + '.tmp'
    with open(tmp, 'w') as handle:
        json.dump(log, handle)
    os.replace(tmp, LOG)


def sh(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_text(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def msg_of(reply):
    return d4.d4_parse(bytes.fromhex(reply['payload'])) if reply else None


def peer_main(scenario, sync, go, arg):
    ip = None
    relay_port = None
    if scenario == 'relay':
        ip, relay_port = '192.0.2.5', int(arg or '67')
    elif scenario == 'proxy':
        ip = '192.0.2.77'
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
    sh('/usr/bin/ip', 'link', 'set', 'lo', 'up')
    with open('/proc/sys/net/ipv4/conf/all/rp_filter', 'w') as handle:
        handle.write('0')
    with open('/proc/sys/net/ipv4/conf/veth1/rp_filter', 'w') as handle:
        handle.write('0')
    if ip:
        sh('/usr/bin/ip', 'addr', 'add', ip + '/24', 'dev', 'veth1')
    sh('/usr/bin/ip', 'link', 'set', 'veth1', 'up')
    client = Client(ip, relay_port)
    os.write(fd, b'ready\n')
    gofd = os.open(go, os.O_RDONLY)
    os.read(gofd, 8)
    state = {'leases': os.environ.get('W2_LEASES', 'leases')}
    A, B, C = MAC['A'], MAC['B'], MAC['C']
    try:
        if scenario == 'discover':
            client.exchange('discover-a', message(1, A, 0x1001), want_type=2)
        elif scenario in ('exchange', 'decline-lease', 'release-lease'):
            offer = client.exchange('discover-a', message(1, A, 0x1001), want_type=2)
            yi = socket.inet_ntoa(msg_of(offer)['yiaddr']) if offer else None
            ack = None
            if offer:
                req = message(3, A, 0x1001, extra=[(50, socket.inet_aton(yi)), (54, socket.inet_aton(SERVER))])
                ack = client.exchange('request-a', req, want_type=5)
            time.sleep(0.3)
            client.log.append({'label': 'leases-after-ack', 'text': read_text(state['leases']), 'wall': time.time()})
            if ack and scenario == 'decline-lease':
                dec = message(4, A, 0x1002, extra=[(50, socket.inet_aton(yi)), (54, socket.inet_aton(SERVER))])
                client.send('decline-a', dec)
                time.sleep(0.5)
                client.log.append({'label': 'leases-after-decline', 'text': read_text(state['leases']), 'wall': time.time()})
            if ack and scenario == 'release-lease':
                sh('/usr/bin/ip', 'addr', 'add', yi + '/24', 'dev', 'veth1')
                client.out.close()
                client.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                client.out.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'veth1')
                client.out.bind((yi, 68))
                rel = message(7, A, 0x1003, ciaddr=yi, extra=[(54, socket.inet_aton(SERVER))])
                client.send('release-a', rel, (SERVER, 67))
                time.sleep(0.5)
                client.log.append({'label': 'leases-after-release', 'text': read_text(state['leases']), 'wall': time.time()})
        elif scenario == 'pool':
            for name, mac, xid in (('a', A, 0x2001), ('b', B, 0x2002)):
                offer = client.exchange('discover-' + name, message(1, mac, xid), want_type=2)
                if offer:
                    yi = socket.inet_aton(socket.inet_ntoa(msg_of(offer)['yiaddr']))
                    client.exchange('request-' + name, message(3, mac, xid, extra=[(50, yi), (54, socket.inet_aton(SERVER))]),
                                    want_type=5)
            client.exchange('discover-a-again', message(1, A, 0x2003), want_type=2)
            client.exchange('discover-c-exhausted', message(1, C, 0x2004), timeout=1.5, want_type=2)
        elif scenario == 'decline-quarantine':
            offer = client.exchange('discover-a', message(1, A, 0x3001), want_type=2)
            yi = msg_of(offer)['yiaddr'] if offer else None
            if offer:
                client.send('decline-a', message(4, A, 0x3002, extra=[(50, yi), (54, socket.inet_aton(SERVER))]))
                time.sleep(0.5)
                client.exchange('discover-b-during-quarantine', message(1, B, 0x3003), want_type=2)
                time.sleep(3.0)
                client.exchange('discover-c-after-expiry', message(1, C, 0x3004), want_type=2)
        elif scenario == 'once':
            client.exchange('first-discover', message(1, A, 0x4001), want_type=2)
            time.sleep(1.5)
            client.exchange('second-discover', message(1, B, 0x4002), timeout=1.5, want_type=2)
        elif scenario == 'idle':
            time.sleep(0.3)
        elif scenario == 'relay':
            opt82 = bytes([1, 3]) + b'eth' + bytes([2, 4]) + b'rem1'
            client.exchange('relayed-discover', message(1, A, 0x5001, giaddr='192.0.2.5', extra=[(82, opt82)]),
                            want_type=2, timeout=2.0, relay_port=relay_port)
        elif scenario == 'proxy':
            vendor = b'PXEClient:Arch:00000:UNDI:002001'
            client.exchange('proxy-discover', message(1, A, 0x6001, extra=[(60, vendor)]), dst=(SERVER, 4011),
                            want_type=2, timeout=2.0)
            client.exchange('proxy-request', message(3, A, 0x6002, extra=[(60, vendor)]), dst=(SERVER, 4011),
                            want_type=5, timeout=2.0)
        else:
            raise SystemExit('unknown scenario ' + scenario)
    finally:
        save(client.log)
    os.write(fd, b'done\n')
    os.close(fd)


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


def entry(log, label):
    for e in log:
        if e.get('label') == label:
            return e
    return None


def ip_of(msg, field='yiaddr'):
    return socket.inet_ntoa(msg[field])


def parse_leases(text):
    rows = []
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) >= 3:
            rows.append({'mac': f[0], 'ip': f[1], 'expiry': int(f[2]), 'host': f[3] if len(f) > 3 else ''})
    return rows


def verify_pxe_gating(report):
    nxt = socket.inet_aton('192.0.2.99')
    for name in ('none', 'msft', 'pxe'):
        text = read_text('reply-%s.hex' % name)
        report.check('reply-' + name + '-produced', bool(text and text.strip()), text)
        if not (text and text.strip()):
            continue
        m = d4.d4_parse(bytes.fromhex(text.strip()))
        if name != 'pxe':
            report.check(name + '-siaddr-not-next-server', m['siaddr'] != nxt, ip_of(m, 'siaddr'))
            report.check(name + '-no-option-66-67-43', all(d4.opt(m, c) is None for c in (66, 67, 43)),
                         [c for c, _ in m['opts'] if c in (66, 67, 43)])
            report.check(name + '-bootp-file-empty', m['file'] == bytes(128), m['file'][:16])
        else:
            report.check('pxe-siaddr-next-server', m['siaddr'] == nxt, ip_of(m, 'siaddr'))
            report.check('pxe-option-66', d4.opt(m, 66) == b'tftp.lab.test', d4.opt(m, 66))
            report.check('pxe-option-67', d4.opt(m, 67) == b'pxelinux.0', d4.opt(m, 67))
            report.check('pxe-bootp-file', m['file'].rstrip(b'\0') == b'pxelinux.0', m['file'][:16])



def main(argv):
    if argv[1] == 'peer':
        peer_main(argv[2], argv[3], argv[4], argv[5] if len(argv) > 5 else None)
        return 0
    if argv[1] == 'mkreq':
        for name, vendor in (('none', None), ('msft', b'MSFT 5.0'), ('pxe', b'PXEClient:Arch:00000:UNDI:002001')):
            extra = [(60, vendor)] if vendor else []
            with open('req-%s.hex' % name, 'w') as handle:
                handle.write(message(1, MAC['A'], 0x7001, extra=extra).hex() + '\n')
        return 0
    report = Report()
    check = argv[2]
    if check == 'file-contains':
        text = read_text(argv[3]) or ''
        report.check('file-' + argv[3] + '-has-' + argv[4].replace(' ', '_'), argv[4] in text, text.strip()[:200])
        report.emit(check)
        return 0
    if check == 'pxe-gating':
        verify_pxe_gating(report)
        report.emit(check)
        return 0
    with open(LOG) as handle:
        log = json.load(handle)
    if check == 'offer':
        e = entry(log, 'discover-a')
        r = e and e['reply']
        report.check('offer-received', bool(r), r)
        if r:
            m = msg_of(r)
            report.check('offer-type', d4.opt(m, 53) == b'\x02', d4.opt(m, 53))
            report.check('offer-xid-echoed', m['xid'] == 0x1001, hex(m['xid']))
            report.check('offer-yiaddr-first-pool-address', ip_of(m) == '192.0.2.100', ip_of(m))
            report.check('offer-server-id', d4.opt(m, 54) == socket.inet_aton(SERVER), d4.opt(m, 54))
            report.check('offer-netmask', d4.opt(m, 1) == socket.inet_aton('255.255.255.0'), d4.opt(m, 1))
            report.check('offer-router', d4.opt(m, 3) == socket.inet_aton('192.0.2.254'), d4.opt(m, 3))
            report.check('offer-dns', d4.opt(m, 6) == socket.inet_aton('192.0.2.53'), d4.opt(m, 6))
            report.check('offer-domain', d4.opt(m, 15) == b'lab.test', d4.opt(m, 15))
            report.check('offer-lease-time', d4.opt(m, 51) == struct.pack('!I', 3600), d4.opt(m, 51))
            report.check('offer-chaddr', m['chaddr'][:6] == MAC['A'], m['chaddr'].hex())
    elif check == 'broadcast':
        e = entry(log, 'discover-a')
        r = e and e['reply']
        report.check('reply-received', bool(r), r)
        if r:
            report.check('reply-to-limited-broadcast-port-68', r['ip_dst'] == '255.255.255.255' and r['dport'] == 68,
                         (r['ip_dst'], r['dport']))
            report.check('reply-link-layer-broadcast', r['eth_dst'] == 'ff' * 6, r['eth_dst'])
            report.check('reply-from-server-port-67', r['ip_src'] == SERVER and r['sport'] == 67, (r['ip_src'], r['sport']))
    elif check == 'ack-persist':
        e = entry(log, 'request-a')
        r = e and e['reply']
        report.check('ack-received', bool(r), r)
        if r:
            m = msg_of(r)
            report.check('ack-type', d4.opt(m, 53) == b'\x05', d4.opt(m, 53))
            report.check('ack-yiaddr', ip_of(m) == '192.0.2.100', ip_of(m))
            report.check('ack-xid-echoed', m['xid'] == 0x1001, hex(m['xid']))
        snap = entry(log, 'leases-after-ack')
        rows = parse_leases(snap and snap['text'])
        report.check('one-lease-persisted', len(rows) == 1, rows)
        if rows:
            row = rows[0]
            report.check('lease-mac-ip-host', (row['mac'], row['ip'], row['host']) == ('02:00:00:00:0b:01', '192.0.2.100', 'host-a'), row)
            report.check('lease-expiry-is-now-plus-lease', abs(row['expiry'] - (snap['wall'] + 3600)) <= 10,
                         (row['expiry'], snap['wall']))
    elif check == 'pool':
        want = {'discover-a': '192.0.2.100', 'request-a': '192.0.2.100', 'discover-b': '192.0.2.101',
                'request-b': '192.0.2.101', 'discover-a-again': '192.0.2.100'}
        for label, ip in want.items():
            e = entry(log, label)
            r = e and e['reply']
            report.check(label + '-answered', bool(r), r)
            if r:
                report.check(label + '-yiaddr', ip_of(msg_of(r)) == ip, ip_of(msg_of(r)))
        e = entry(log, 'discover-c-exhausted')
        report.check('exhausted-pool-sends-nothing', e is not None and e['reply'] is None, e and e['reply'])
    elif check == 'quarantine':
        a = entry(log, 'discover-a')
        b = entry(log, 'discover-b-during-quarantine')
        c = entry(log, 'discover-c-after-expiry')
        ips = [ip_of(msg_of(x['reply'])) if x and x['reply'] else None for x in (a, b, c)]
        report.check('first-offer', ips[0] == '192.0.2.100', ips)
        report.check('declined-address-withheld-during-quarantine', ips[1] is not None and ips[1] != ips[0], ips)
        report.check('declined-address-offered-again-after-expiry', ips[2] == ips[0], ips)
    elif check == 'decline-removes-lease':
        rows = parse_leases(entry(log, 'leases-after-ack')['text'])
        after = entry(log, 'leases-after-decline')
        report.check('lease-existed-before-decline', [r['mac'] for r in rows] == ['02:00:00:00:0b:01'], rows)
        report.check('lease-gone-after-decline', after is not None and parse_leases(after['text']) == [], after)
    elif check == 'release-removes-lease':
        rows = parse_leases(entry(log, 'leases-after-ack')['text'])
        after = entry(log, 'leases-after-release')
        report.check('lease-existed-before-release', [r['mac'] for r in rows] == ['02:00:00:00:0b:01'], rows)
        report.check('lease-gone-after-release', after is not None and parse_leases(after['text']) == [], after)
    elif check == 'hook-lines':
        lines = (read_text(argv[3]) or '').splitlines()
        report.check('hook-ran-commit-then-release', lines == ['commit 02:00:00:00:0b:01 192.0.2.100',
                                                              'release 02:00:00:00:0b:01 192.0.2.100'], lines)
    elif check == 'once-messages':
        first = entry(log, 'first-discover')
        second = entry(log, 'second-discover')
        report.check('first-message-answered', bool(first and first['reply']), first and first['reply'])
        report.check('second-message-not-answered-after-return', second is not None and second['reply'] is None,
                     second and second['reply'])
    elif check == 'run-serves':
        e = entry(log, 'discover-a')
        report.check('run-answers-discover', bool(e and e['reply']), e and e['reply'])
    elif check == 'relay-reply':
        port = int(argv[3])
        e = entry(log, 'relayed-discover')
        r = e and e['reply']
        report.check('reply-received-by-relay', bool(r), r)
        if r:
            m = msg_of(r)
            report.check('reply-unicast-to-giaddr-relay-port', r['ip_dst'] == '192.0.2.5' and r['dport'] == port,
                         (r['ip_dst'], r['dport']))
            report.check('reply-from-server-port-67', r['ip_src'] == SERVER and r['sport'] == 67, (r['ip_src'], r['sport']))
            report.check('reply-giaddr-echoed', ip_of(m, 'giaddr') == '192.0.2.5', ip_of(m, 'giaddr'))
            report.check('reply-is-offer', d4.opt(m, 53) == b'\x02', d4.opt(m, 53))
    elif check == 'proxy':
        for label, want in (('proxy-discover', 2), ('proxy-request', 5)):
            e = entry(log, label)
            r = e and e['reply']
            report.check(label + '-answered', bool(r), r)
            if r:
                m = msg_of(r)
                report.check(label + '-sent-to-source', r['ip_dst'] == '192.0.2.77' and r['dport'] == 68, (r['ip_dst'], r['dport']))
                report.check(label + '-from-proxy-port-4011', r['sport'] == 4011, r['sport'])
                report.check(label + '-offer-only-no-address', ip_of(m) == '0.0.0.0', ip_of(m))
                report.check(label + '-type', d4.opt(m, 53) == bytes([want]), d4.opt(m, 53))
                report.check(label + '-pxe-vendor-echo', (d4.opt(m, 60) or b'').startswith(b'PXEClient'), d4.opt(m, 60))
                report.check(label + '-boot-file-option', d4.opt(m, 67) == b'pxelinux.0', d4.opt(m, 67))
        report.check('no-lease-assigned', not parse_leases(read_text('leases')), read_text('leases'))
    else:
        raise SystemExit('unknown check ' + check)
    report.emit(check)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
