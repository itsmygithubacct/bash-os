#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only DHCPv6 client peer, leasequery inputs and assertions for the w2 dhcpd6 fixtures.

    mig-w2-dhcpd6.py peer SCENARIO SYNC_FIFO GO_FIFO SERVER_PORT CLIENT_PORT   # scripted client in its own netns
    mig-w2-dhcpd6.py lqprep                                                     # seed leases + LEASEQUERY hex files
    mig-w2-dhcpd6.py verify CHECK [args]                                        # failing assertions, then a summary

Layouts follow RFC 8415 and RFC 5007 (OPTION_LQ_QUERY 44, OPTION_CLIENT_DATA 45, OPTION_CLT_TIME 46,
QUERY_BY_ADDRESS 1, QUERY_BY_CLIENTID 2) and are written without reference to the loadable sources.
"""
import importlib.util
import json
import os
import select
import socket
import struct
import sys
import time

_spec = importlib.util.spec_from_file_location(
    'mig_w2_d6lib', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mig-w2-d6lib.py'))
lib = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lib)
for _name in ('CLIENT_DUID', 'SERVER_DUID', 'PEER_LL', 'T', 'NAME', 'v6', 'parse', 'get', 'build', 'build_ia_na',
              'opt_raw', 'ia_na', 'iaaddr', 'netns_peer_setup', 'Report'):
    globals()[_name] = getattr(lib, _name)

HOME = os.environ.get('HOME', '/tmp/parity-home')
LOG = os.path.join(HOME, 'w2-peer-dhcpd6.json')
SERVER_LL = 'fe80::a01'
POOL_START = '2001:db8::100'
DUID_B = bytes.fromhex('00030001' + '020000000b02')
DUID_C = bytes.fromhex('00030001' + '020000000b03')
DUID_D = bytes.fromhex('00030001' + '020000000b04')


def save(log):
    tmp = LOG + '.tmp'
    with open(tmp, 'w') as handle:
        json.dump(log, handle)
    os.replace(tmp, LOG)


def read_text(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return None


def parse_leases(text):
    rows = []
    for line in (text or '').splitlines():
        f = line.split()
        if len(f) >= 4:
            rows.append({'duid': f[0], 'iaid': int(f[1]), 'addr': f[2], 'expiry': int(f[3])})
    return rows


def peer_main(scenario, sync, go, server_port, client_port):
    fd = netns_peer_setup(sync)
    ifindex = socket.if_nametoindex('veth1')
    listen = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'veth1')
    listen.bind(('::', client_port))
    other = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    other.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'veth1')
    other.bind(('::', 0))
    socks = {'listen': listen, 'other': other}
    dst = (SERVER_LL, server_port, 0, ifindex)
    log = []
    os.write(fd, b'ready\n')
    gofd = os.open(go, os.O_RDONLY)
    os.read(gofd, 8)
    xid = [0x100000]

    def exchange(label, mtype, options, via='listen', wait=1.5, expect_reply=True):
        xid[0] += 1
        msg = build(NAME[mtype], xid[0], options)
        socks[via].sendto(msg, dst)
        entry = {'label': label, 'sent': msg.hex(), 'via': via, 'sport': socks[via].getsockname()[1], 'replies': []}
        end = time.monotonic() + wait
        while True:
            left = end - time.monotonic()
            if left <= 0:
                break
            ready, _, _ = select.select([listen, other], [], [], left)
            for s in ready:
                data, src = s.recvfrom(4096)
                entry['replies'].append({'on': 'listen' if s is listen else 'other', 'port': s.getsockname()[1],
                                         'from': [src[0].split('%')[0], src[1]], 'payload': data.hex()})
            if entry['replies'] and expect_reply:
                break
        log.append(entry)
        save(log)
        return entry

    def solicit(duid=CLIENT_DUID, iaid=1):
        return [(1, duid), (8, b'\0\0'), (3, build_ia_na(iaid, 0, 0)[4:])]

    def echo_ia(entry, duid=CLIENT_DUID, iaid=1):
        rep = parse(bytes.fromhex(entry['replies'][0]['payload']))
        ia = ia_na(get(rep, 3))
        addr = [v for c, v in ia['subs'] if c == 5][0]
        return rep, [(1, duid), (2, get(rep, 2)), (8, b'\0\0'),
                     (3, struct.pack('!III', iaid, 0, 0) + opt_raw(5, addr))]

    try:
        if scenario == 'ports':
            exchange('solicit-from-other-port', 'SOLICIT', solicit(), via='other', wait=2.0)
        elif scenario in ('exchange', 'lease-lifecycle'):
            a = exchange('solicit', 'SOLICIT', solicit())
            if a['replies']:
                _, opts = echo_ia(a)
                r = exchange('request', 'REQUEST', opts)
                time.sleep(0.3)
                log.append({'label': 'leases-after-reply', 'text': read_text('leases'), 'wall': time.time()})
                if scenario == 'lease-lifecycle' and r['replies']:
                    _, ropts = echo_ia(r)
                    exchange('release', 'RELEASE', ropts)
                    time.sleep(0.5)
                    log.append({'label': 'leases-after-release', 'text': read_text('leases'), 'wall': time.time()})
        elif scenario == 'once':
            exchange('first', 'SOLICIT', solicit())
            time.sleep(1.5)
            exchange('second', 'SOLICIT', solicit(DUID_B), wait=1.5, expect_reply=False)
        else:
            raise SystemExit('unknown scenario ' + scenario)
    finally:
        save(log)
    os.write(fd, b'done\n')
    os.close(fd)


# ------------------------------------------------------------------ leasequery inputs

CFG_VALID, CFG_PREF = 7200, 3600


def lq_query(qtype, xid, key_opts):
    """RFC 5007 s4.1.2.1: CLIENTID (requestor), then OPTION_LQ_QUERY = type + link-address(::) + options."""
    body = bytes([qtype]) + bytes(16) + b''.join(opt_raw(c, v) for c, v in key_opts)
    return build(14, xid, [(1, DUID_D), (44, body)])


def lqprep():
    now = int(time.time())
    rows = [(CLIENT_DUID, 1, '2001:db8::100', now + 5000), (CLIENT_DUID, 2, '2001:db8::101', now + 1000),
            (DUID_B, 1, '2001:db8::102', now - 100), (DUID_C, 1, '2001:db8::103', now + 7000)]
    with open('leases', 'w') as handle:
        for duid, iaid, addr, exp in rows:
            handle.write('%s %d %s %d\n' % (duid.hex(), iaid, v6(addr).hex(), exp))
    open('prep-time.txt', 'w').write('%d\n' % now)
    queries = {'addr-100': lq_query(1, 0xA001, [(5, v6('2001:db8::100') + bytes(8))]),
               'addr-103': lq_query(1, 0xA002, [(5, v6('2001:db8::103') + bytes(8))]),
               'client-a': lq_query(2, 0xA003, [(1, CLIENT_DUID)]),
               'client-c': lq_query(2, 0xA004, [(1, DUID_C)]),
               'addr-unknown': lq_query(1, 0xA005, [(5, v6('2001:db8::777') + bytes(8))]),
               'client-unknown': lq_query(2, 0xA006, [(1, bytes.fromhex('00030001' + '0200000000ff'))]),
               'addr-expired': lq_query(1, 0xA007, [(5, v6('2001:db8::102') + bytes(8))]),
               'client-expired': lq_query(2, 0xA008, [(1, DUID_B)])}
    for name, msg in queries.items():
        open('q-%s.hex' % name, 'w').write(msg.hex() + '\n')


def lq_reply(name):
    text = read_text('r-%s.hex' % name)
    if not text or not text.strip():
        return None
    return parse(bytes.fromhex(text.strip()))


def client_data(m):
    cd = get(m, 45)
    if cd is None:
        return None
    subs, p = [], 0
    while p + 4 <= len(cd):
        code, n = struct.unpack('!HH', cd[p:p + 4])
        subs.append((code, cd[p + 4:p + 4 + n]))
        p += 4 + n
    return subs


def status_of(m):
    st = get(m, 13)
    return struct.unpack('!H', st[:2])[0] if st else None


# ------------------------------------------------------------------ verification

def entry(log, label):
    for e in log:
        if e.get('label') == label:
            return e
    return None


def reply_msg(e, i=0):
    return parse(bytes.fromhex(e['replies'][i]['payload'])) if e and e['replies'] else None


def main(argv):
    if argv[1] == 'peer':
        peer_main(argv[2], argv[3], argv[4], int(argv[5]), int(argv[6]))
        return 0
    if argv[1] == 'lqprep':
        lqprep()
        return 0
    report = Report()
    check = argv[2]
    if check.startswith('lq-'):
        prep = int(read_text('prep-time.txt'))
        if check == 'lq-address':
            for name, addr, iaid_unused in (('addr-100', '2001:db8::100', 0xA001), ('addr-103', '2001:db8::103', 0xA002)):
                m = lq_reply(name)
                report.check(name + '-reply', m is not None and m['type'] == 15, m and m['type'])
                if m is None:
                    continue
                report.check(name + '-xid', m['xid'] == iaid_unused, hex(m['xid']))
                report.check(name + '-server-id', get(m, 2) == SERVER_DUID, get(m, 2))
                cd = client_data(m)
                report.check(name + '-has-client-data', cd is not None, [c for c, _ in m['opts']])
                if cd:
                    codes = [c for c, _ in cd]
                    want = CLIENT_DUID if name == 'addr-100' else DUID_C
                    report.check(name + '-clientid-in-client-data', dict(cd).get(1) == want, dict(cd).get(1))
                    addrs = [iaaddr(v)['addr'] for c, v in cd if c == 5]
                    report.check(name + '-iaaddr', addrs == [addr], addrs)
                    report.check(name + '-clt-time-present', 46 in codes and len(dict(cd)[46]) == 4, codes)
        elif check == 'lq-clientid':
            m = lq_reply('client-a')
            report.check('client-a-reply', m is not None and m['type'] == 15, m and m['type'])
            if m:
                cd = client_data(m) or []
                addrs = sorted(iaaddr(v)['addr'] for c, v in cd if c == 5)
                report.check('client-a-all-active-addresses', addrs == ['2001:db8::100', '2001:db8::101'], addrs)
                report.check('client-a-clientid', dict(cd).get(1) == CLIENT_DUID, dict(cd).get(1))
            m = lq_reply('client-c')
            cd = (client_data(m) or []) if m else []
            report.check('client-c-single-address', [iaaddr(v)['addr'] for c, v in cd if c == 5] == ['2001:db8::103'], cd)
        elif check == 'lq-miss-no-client-data':
            for name in ('addr-unknown', 'client-unknown', 'addr-expired', 'client-expired'):
                m = lq_reply(name)
                report.check(name + '-reply', m is not None and m['type'] == 15, m and m['type'])
                if m:
                    report.check(name + '-no-client-data', get(m, 45) is None, [c for c, _ in m['opts']])
                    report.check(name + '-no-iaaddr', get(m, 5) is None, '')
        elif check == 'lq-miss-status':
            for name in ('addr-unknown', 'client-unknown', 'addr-expired', 'client-expired'):
                m = lq_reply(name)
                report.check(name + '-reply', m is not None, m)
                if m:
                    report.check(name + '-failure-status-code', status_of(m) not in (None, 0), status_of(m))
        elif check == 'lq-lifetimes':
            for name in ('addr-100', 'client-a', 'addr-103'):
                m = lq_reply(name)
                cd = (client_data(m) or []) if m else []
                report.check(name + '-has-data', bool(cd), cd)
            m = lq_reply('addr-100')
            cd = client_data(m) or []
            ia = [iaaddr(v) for c, v in cd if c == 5]
            clt = [struct.unpack('!I', v)[0] for c, v in cd if c == 46]
            rem = 5000
            now_window = (0, 15)
            if ia:
                report.check('valid-equals-remaining', rem - now_window[1] <= ia[0]['valid'] <= rem, ia[0])
                report.check('preferred-is-configured-preferred-when-lower', ia[0]['pref'] == CFG_PREF, ia[0])
                report.check('clt-time-is-valid-minus-remaining', bool(clt) and CFG_VALID - rem <= clt[0] <= CFG_VALID - rem + 15, clt)
            m = lq_reply('client-a')
            cd = client_data(m) or []
            by_addr = {}
            for c, v in cd:
                if c == 5:
                    last = iaaddr(v)
                    by_addr[last['addr']] = last
            short = by_addr.get('2001:db8::101')
            report.check('preferred-is-min-of-configured-and-remaining', short is not None and
                         1000 - 15 <= short['pref'] <= 1000 and short['pref'] == short['valid'], short)
            m = lq_reply('addr-103')
            cd = client_data(m) or []
            ia = [iaaddr(v) for c, v in cd if c == 5]
            clt = [struct.unpack('!I', v)[0] for c, v in cd if c == 46]
            if ia:
                report.check('long-lease-valid-equals-remaining', 7000 - 15 <= ia[0]['valid'] <= 7000, ia[0])
                report.check('long-lease-clt-time', bool(clt) and CFG_VALID - 7000 <= clt[0] <= CFG_VALID - 7000 + 15, clt)
        else:
            raise SystemExit('unknown check')
        report.emit(check)
        return 0
    if check == 'file-contains':
        text = read_text(argv[3]) or ''
        report.check('file-has-' + argv[4].replace(' ', '_'), argv[4] in text, text.strip()[:200])
        report.emit(check)
        return 0
    with open(LOG) as handle:
        log = json.load(handle)
    sp, cp = int(argv[3]) if len(argv) > 3 else 547, int(argv[4]) if len(argv) > 4 else 546
    if check == 'ports':
        e = entry(log, 'solicit-from-other-port')
        report.check('reply-arrived', bool(e and e['replies']), e and e['replies'])
        if e and e['replies']:
            r = e['replies'][0]
            report.check('reply-to-configured-client-port', r['on'] == 'listen' and r['port'] == cp, (r['on'], r['port']))
            report.check('reply-from-server-address-and-port', r['from'] == [SERVER_LL, sp], r['from'])
            report.check('nothing-sent-to-request-source-port', all(x['on'] != 'other' for x in e['replies']), e['replies'])
            m = parse(bytes.fromhex(r['payload']))
            report.check('reply-is-advertise', T.get(m['type']) == 'ADVERTISE', m['type'])
    elif check == 'exchange':
        a, r = entry(log, 'solicit'), entry(log, 'request')
        adv, rep = reply_msg(a), reply_msg(r)
        report.check('advertise-received', adv is not None and T.get(adv['type']) == 'ADVERTISE', adv and adv['type'])
        report.check('reply-received', rep is not None and T.get(rep['type']) == 'REPLY', rep and rep['type'])
        for name, m in (('advertise', adv), ('reply', rep)):
            if not m:
                continue
            report.check(name + '-server-id', get(m, 2) == SERVER_DUID, get(m, 2))
            report.check(name + '-client-id-echoed', get(m, 1) == CLIENT_DUID, get(m, 1))
            ia = ia_na(get(m, 3))
            addrs = [iaaddr(v) for c, v in ia['subs'] if c == 5]
            report.check(name + '-pool-address', [x['addr'] for x in addrs] == [POOL_START], addrs)
            report.check(name + '-lifetimes', addrs and (addrs[0]['pref'], addrs[0]['valid']) == (CFG_PREF, CFG_VALID), addrs)
            report.check(name + '-iaid', ia['iaid'] == 1, ia['iaid'])
        if a and r and adv and rep:
            report.check('xids-echoed', adv['xid'] == 0x100001 and rep['xid'] == 0x100002, (hex(adv['xid']), hex(rep['xid'])))
    elif check == 'lease-persist':
        snap = entry(log, 'leases-after-reply')
        rows = parse_leases(snap and snap['text'])
        report.check('one-lease-written-on-reply', len(rows) == 1, rows)
        if rows:
            row = rows[0]
            report.check('lease-duid-iaid-address', (row['duid'], row['iaid'], row['addr']) ==
                         (CLIENT_DUID.hex(), 1, v6(POOL_START).hex()), row)
            report.check('lease-expiry-is-now-plus-valid', abs(row['expiry'] - (snap['wall'] + CFG_VALID)) <= 10, row)
        after = entry(log, 'leases-after-release')
        rel = reply_msg(entry(log, 'release'))
        report.check('release-answered-with-reply', rel is not None and T.get(rel['type']) == 'REPLY', rel and rel['type'])
        report.check('lease-removed-by-release', after is not None and parse_leases(after['text']) == [], after)
    elif check == 'once-messages':
        first, second = entry(log, 'first'), entry(log, 'second')
        report.check('first-message-answered', bool(first and first['replies']), first and first['replies'])
        report.check('second-message-not-answered', second is not None and not second['replies'], second and second['replies'])
    else:
        raise SystemExit('unknown check ' + check)
    report.emit(check)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
