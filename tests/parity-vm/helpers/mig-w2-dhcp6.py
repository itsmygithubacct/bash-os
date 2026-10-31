#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only DHCPv6 server peer and assertions for the w2 client-side fixtures (dhcp6 inforequest/solicit).

    mig-w2-dhcp6.py server MODE SYNC_FIFO   # DHCPv6 server peer in its own netns on veth1
    mig-w2-dhcp6.py verify CHECK [args]     # one line per failing assertion, then a summary line
"""
import importlib.util
import os
import signal
import socket
import struct
import sys
import time

_spec = importlib.util.spec_from_file_location(
    'mig_w2_d6lib', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mig-w2-d6lib.py'))
lib = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lib)
from_lib = ['CLIENT_DUID', 'SERVER_DUID', 'OTHER_DUID', 'MCAST', 'CLIENT_LL', 'PEER_LL', 'T', 'NAME', 'v6', 'parse', 'get',
            'build', 'build_ia_na', 'opt_raw', 'encode_domains', 'ia_na', 'iaaddr', 'save', 'netns_peer_setup',
            'Report', 'parse_kv', 'inbound', 'oro_codes', 'all_codes']
globals().update({name: getattr(lib, name) for name in from_lib})

# ------------------------------------------------------------------ server peer (client-side topics)

class ServerPeer:
    ADDR = '2001:db8::50'
    DNS = ['2001:db8::53', '2001:db8::54']
    DOMAINS = ['lab.test', 'example.org']

    def __init__(self, mode):
        self.mode = mode
        self.log = []
        self.counts = {}
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'veth1')
        port = int(os.environ.get('W2_SERVER_PORT', '547'))
        self.sock.bind(('::', port))
        ifindex = socket.if_nametoindex('veth1')
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, v6(MCAST) + struct.pack('@I', ifindex))
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        self.ifindex = ifindex

    def send(self, msg, dst):
        self.sock.sendto(msg, dst)
        self.log.append({'t': time.monotonic(), 'dir': 'out', 'to': [dst[0], dst[1]], 'payload': msg.hex()})

    def reply(self, kind, req, src, wrong_xid=False, lifetimes=(3600, 7200), with_ia=True, dns=None, domains=True,
              server_duid=SERVER_DUID, addr=None, rapid=False):
        xid = req['xid'] ^ 0x010000 if wrong_xid else req['xid']
        opts = [(1, get(req, 1)), (2, server_duid)]
        ia = get(req, 3)
        if with_ia and ia:
            iaid = struct.unpack('!I', ia[:4])[0]
            opts.append((3, build_ia_na(iaid, 1800, 2880, addr or self.ADDR, *lifetimes)[4:]))
        if rapid:
            opts.append((14, b''))
        opts.append((23, b''.join(v6(a) for a in (dns or self.DNS))))
        if domains:
            opts.append((24, encode_domains(self.DOMAINS)))
        kind_no = NAME[kind]
        self.send(build(kind_no, xid, opts), (src[0], src[1], 0, src[3]))

    def handle(self, msg, src):
        m = parse(msg)
        kind = T.get(m['type'])
        self.counts[kind] = self.counts.get(kind, 0) + 1
        n = self.counts[kind]
        mode = self.mode
        if mode == 'silent':
            return
        if kind == 'INFORMATION-REQUEST':
            if mode == 'info':
                self.reply('REPLY', m, src, with_ia=False)
            elif mode == 'info-noise':
                self.reply('REPLY', m, src, with_ia=False, wrong_xid=True, dns=['2001:db8::bad'])
                self.reply('REPLY', m, src, with_ia=False)
        elif kind == 'SOLICIT':
            if mode == 'advertise-only' or mode == 'full':
                self.reply('ADVERTISE', m, src)
            elif mode == 'noise':
                self.reply('ADVERTISE', m, src, wrong_xid=True, server_duid=OTHER_DUID, addr='2001:db8::66')
                self.reply('ADVERTISE', m, src)
            elif mode == 'rapid':
                if get(m, 14) is not None:
                    self.reply('REPLY', m, src, rapid=True)
        elif kind == 'REQUEST':
            if mode in ('full', 'noise'):
                self.reply('REPLY', m, src)

    def run(self):
        def terminate(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, terminate)
        try:
            while True:
                data, anc, flags, src = self.sock.recvmsg(4096, 256)
                dst = None
                for level, typ, cdata in anc:
                    if level == socket.IPPROTO_IPV6 and typ == socket.IPV6_PKTINFO:
                        dst = socket.inet_ntop(socket.AF_INET6, cdata[:16])
                self.log.append({'t': time.monotonic(), 'dir': 'in', 'src': [src[0].split('%')[0], src[1]], 'dst': dst,
                                 'payload': data.hex(), 'ifindex': self.ifindex})
                self.handle(data, src)
                save(self.log)
        except KeyboardInterrupt:
            pass
        save(self.log)


def server_main(mode, sync):
    fd = netns_peer_setup(sync)
    peer = ServerPeer(mode)
    os.write(fd, b'ready\n')
    os.close(fd)
    peer.run()


def check_client_common(report, m, tag):
    report.check(tag + '-clientid', get(m, 1) == CLIENT_DUID, get(m, 1))
    report.check(tag + '-elapsed-time', get(m, 8) is not None and len(get(m, 8)) == 2, get(m, 8))


def main(argv):
    if argv[1] == 'server':
        server_main(argv[2], argv[3])
        return 0
    report = Report()
    check = argv[2]
    if check == 'stderr-contains':
        with open(argv[3], errors='replace') as handle:
            text = handle.read()
        report.check('diagnostic-' + argv[4].replace(' ', '-'), argv[4] in text, text.strip()[:120])
        report.emit(check)
        return 0
    log = lib.load_log()
    if check == 'inforequest-fields':
        reqs = inbound(log, 'INFORMATION-REQUEST')
        report.check('inforequest-count', len(reqs) == 1, len(reqs))
        if reqs:
            m = reqs[0]['msg']
            check_client_common(report, m, 'inforequest')
            report.check('inforequest-oro-dns-and-domain', oro_codes(m) == [23, 24], oro_codes(m))
            report.check('inforequest-no-ia', 3 not in all_codes(m) and 25 not in all_codes(m), all_codes(m))
    elif check == 'inforequest-oro-override':
        reqs = inbound(log, 'INFORMATION-REQUEST')
        report.check('inforequest-count', len(reqs) == 1, len(reqs))
        if reqs:
            report.check('inforequest-oro-as-requested', oro_codes(reqs[0]['msg']) == [23], oro_codes(reqs[0]['msg']))
    elif check == 'inforequest-default-transport':
        reqs = inbound(log, 'INFORMATION-REQUEST')
        report.check('inforequest-count', len(reqs) == 1, len(reqs))
        if reqs:
            e = reqs[0]
            report.check('inforequest-to-all-servers-multicast', e['dst'] == MCAST, e['dst'])
            report.check('inforequest-from-client-port-546', e['src'][1] == 546, e['src'])
            report.check('inforequest-from-link-local', e['src'][0] == CLIENT_LL, e['src'][0])
    elif check == 'inforequest-override-transport':
        reqs = inbound(log, 'INFORMATION-REQUEST')
        report.check('inforequest-count', len(reqs) == 1, len(reqs))
        if reqs:
            e = reqs[0]
            report.check('inforequest-unicast-to-server', e['dst'] == PEER_LL, e['dst'])
            report.check('inforequest-from-overridden-client-port', e['src'][1] == 54600, e['src'])
    elif check == 'inforequest-dns':
        out = parse_kv(argv[3])
        reps = [parse(bytes.fromhex(e['payload'])) for e in log if e['dir'] == 'out']
        good = [r for r in reps if r['xid'] == inbound(log, 'INFORMATION-REQUEST')[0]['msg']['xid']][0]
        want = [socket.inet_ntop(socket.AF_INET6, get(good, 23)[i:i + 16]) for i in range(0, len(get(good, 23)), 16)]
        values = ' '.join(out.values())
        report.check('reply-dns-servers-printed', all(a in values for a in want), out)
        report.check('wrong-xid-reply-ignored', '2001:db8::bad' not in values, out)
    elif check == 'inforequest-domains':
        out = parse_kv(argv[3])
        values = ' '.join(out.values())
        report.check('reply-domain-list-printed', all(d in values for d in ServerPeer.DOMAINS), out)
    elif check == 'retransmit':
        kind = argv[3]
        sent = inbound(log, kind)
        report.check(kind.lower() + '-attempts', len(sent) == 3, len(sent))
        if len(sent) == 3:
            gaps = [sent[1]['t'] - sent[0]['t'], sent[2]['t'] - sent[1]['t']]
            wait = float(argv[4])
            report.check('retransmit-interval', all(wait * 0.9 <= g <= wait * 2.0 for g in gaps), gaps)
            report.check('same-xid', len({e['msg']['xid'] for e in sent}) == 1, '')
    elif check == 'solicit-fields':
        sol = inbound(log, 'SOLICIT')
        report.check('solicit-count', len(sol) == 1, len(sol))
        if sol:
            m = sol[0]['msg']
            check_client_common(report, m, 'solicit')
            ia = get(m, 3)
            report.check('solicit-ia-na-iaid', ia is not None and ia_na(ia)['iaid'] == 7, ia)
            report.check('solicit-oro-default-dns', oro_codes(m) == [23], oro_codes(m))
            report.check('solicit-no-rapid-commit', get(m, 14) is None, '')
            report.check('solicit-no-ia-pd', get(m, 25) is None, '')
    elif check == 'solicit-rapid-pd':
        sol = inbound(log, 'SOLICIT')
        report.check('solicit-count', len(sol) >= 1, len(sol))
        if sol:
            m = sol[0]['msg']
            if argv[3] == 'rapid':
                report.check('solicit-rapid-commit-option', get(m, 14) == b'', get(m, 14))
            else:
                pd = get(m, 25)
                report.check('solicit-ia-pd-iaid', pd is not None and struct.unpack('!I', pd[:4])[0] == 9, pd)
    elif check == 'request-follows':
        sol = inbound(log, 'SOLICIT')
        req = inbound(log, 'REQUEST')
        report.check('solicit-count', len(sol) == 1, len(sol))
        report.check('request-count', len(req) == 1, len(req))
        if req:
            m = req[0]['msg']
            report.check('request-server-id-is-genuine-advertiser', get(m, 2) == SERVER_DUID, get(m, 2))
            ia = ia_na(get(m, 3))
            addrs = [iaaddr(v)['addr'] for c, v in ia['subs'] if c == 5]
            report.check('request-iaaddr-is-genuine-offer', addrs == [ServerPeer.ADDR], addrs)
            report.check('request-iaid-kept', ia['iaid'] == 7, ia['iaid'])
            check_client_common(report, m, 'request')
    elif check == 'solicit-output':
        out = parse_kv(argv[3])
        sent = [parse(bytes.fromhex(e['payload'])) for e in log if e['dir'] == 'out']
        final = sent[-1]
        want = {'msg_type': 'REPLY', 'xid': '0x%06x' % final['xid'], 'client_id': CLIENT_DUID.hex(),
                'server_id': SERVER_DUID.hex(), 'iaid': '7', 't1': '1800', 't2': '2880',
                'address': ServerPeer.ADDR, 'preferred': '3600', 'valid': '7200', 'dns': ','.join(ServerPeer.DNS)}
        for k, v in want.items():
            report.check('reply-' + k, out.get(k) == v, out.get(k))
    elif check == 'rapid-direct':
        sol = inbound(log, 'SOLICIT')
        report.check('solicit-count', len(sol) == 1, len(sol))
        report.check('no-request-after-direct-reply', not inbound(log, 'REQUEST'), len(inbound(log, 'REQUEST')))
    elif check == 'rapid-output':
        out = parse_kv(argv[3])
        sent = [parse(bytes.fromhex(e['payload'])) for e in log if e['dir'] == 'out']
        report.check('direct-reply-decoded-type', out.get('msg_type') == 'REPLY', out.get('msg_type'))
        report.check('direct-reply-address', out.get('address') == ServerPeer.ADDR, out.get('address'))
        report.check('direct-reply-xid', out.get('xid') == '0x%06x' % sent[-1]['xid'], out.get('xid'))
        report.check('direct-reply-server-id', out.get('server_id') == SERVER_DUID.hex(), out.get('server_id'))
    else:
        raise SystemExit('unknown check ' + check)
    report.emit(check)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
