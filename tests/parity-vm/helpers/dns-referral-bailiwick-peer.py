#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only root/TLD/authoritative referral chain and assertions for the w2 iterative-resolution fixture.

    mig-w2-recurse.py serve READY        # three UDP servers on 127.0.0.2/3/4 port 5330 (root, tld, auth)
    mig-w2-recurse.py waitudp PORT       # wait until a loopback UDP port is bound
    mig-w2-recurse.py verify             # check the resolver's client answer and the queries each tier saw

Referral layout per RFC 1034 s4.3.2: the root delegates test. to ns.tld. (glue 127.0.0.3), the TLD server
delegates x.test. to ns.x.test. (glue 127.0.0.4) and the authority answers www.x.test. A 192.0.2.10.
"""
import importlib.util
import json
import os
import re
import select
import signal
import socket
import struct
import sys
import time
from pathlib import Path

_spec = importlib.util.spec_from_file_location('mig_w2_dnsx', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mig-w2-dnsx.py'))
dx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dx)

PORT = 5330
TIERS = {'root': '127.0.0.2', 'tld': '127.0.0.3', 'auth': '127.0.0.4', 'poison': '127.0.0.5'}
DELEGATION = {'root': ('test.', 'ns.test.', '127.0.0.3'), 'tld': ('x.test.', 'ns.x.test.', '127.0.0.4')}


def referral(query, zone, ns, glue):
    end = 12
    while query[end]:
        end += query[end] + 1
    question = query[12:end + 5]
    nsrd = dx.qname_wire(ns)
    auth = dx.qname_wire(zone) + struct.pack('!HHIH', 2, 1, 300, len(nsrd)) + nsrd
    add = dx.qname_wire(ns) + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton(glue)
    # Unrelated in-zone address appears first, but is not an NS target.
    if zone == 'test.':
        badname = dx.qname_wire('not-a-nameserver.test.')
        bad = badname + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton('127.0.0.5')
        return query[:2] + struct.pack('!HHHHH', 0x8000, 1, 0, 1, 2) + question + auth + bad + add
    return query[:2] + struct.pack('!HHHHH', 0x8000, 1, 0, 1, 1) + question + auth + add


def respond(role, query):
    name = dx.read_name(query, 12)[0]
    if role in DELEGATION:
        zone, ns, glue = DELEGATION[role]
        if name == zone or name.endswith('.' + zone):
            return referral(query, zone, ns, glue)
        return query[:2] + struct.pack('!HHHHH', 0x8403, 1, 0, 0, 0) + query[12:12 + len(dx.qname_wire(name)) + 4]
    end = 12
    while query[end]:
        end += query[end] + 1
    qtype = struct.unpack('!H', query[end + 1:end + 3])[0]
    question = query[12:end + 5]
    if name == 'www.x.test.' and qtype == 1:
        rr = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton('192.0.2.66' if role == 'poison' else '192.0.2.10')
        return query[:2] + struct.pack('!HHHHH', 0x8400, 1, 1, 0, 0) + question + rr
    soa = b'\xc0\x0c' + struct.pack('!HHIH', 6, 1, 300, len(dx.SOA)) + dx.SOA
    rcode = 0 if name.endswith('x.test.') and name in ('www.x.test.', 'x.test.') else 3
    return query[:2] + struct.pack('!HHHHH', 0x8400 | rcode, 1, 0, 1, 0) + question + soa


def serve(ready):
    socks = {}
    for role, ip in TIERS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, PORT))
        socks[s] = role
    log = []

    def stop(*_):
        Path('recurse-queries.json').write_text(json.dumps(log))
        os._exit(0)
    signal.signal(signal.SIGTERM, stop)
    Path(ready).write_text('ready\n')
    while True:
        ready_socks, _, _ = select.select(list(socks), [], [])
        for s in ready_socks:
            data, src = s.recvfrom(2048)
            end = 12
            while data[end]:
                end += data[end] + 1
            log.append({'role': socks[s], 'name': dx.read_name(data, 12)[0], 'qtype': struct.unpack('!H', data[end + 1:end + 3])[0]})
            s.sendto(respond(socks[s], data), src)
            Path('recurse-queries.json').write_text(json.dumps(log))


def waitudp(port):
    want = '0100007F:%04X' % int(port)
    end = time.monotonic() + 10
    while True:
        rows = Path('/proc/net/udp').read_text().splitlines()[1:]
        if any(r.split()[1] == want for r in rows):
            return
        if time.monotonic() > end:
            print('udp-%s-not-bound' % port)
            sys.exit(1)
        time.sleep(0.05)


def verify():
    fails = []

    def need(name, cond, detail=''):
        if not cond:
            fails.append('%s FAIL %s' % (name, detail))
    text = Path('dig.out').read_text(errors='replace') if Path('dig.out').exists() else ''
    log = json.loads(Path('recurse-queries.json').read_text()) if Path('recurse-queries.json').exists() else []
    need('client-answer-noerror', 'status: NOERROR' in text, text[:200])
    need('client-answer-www-a-record', re.search(r'^www\.x\.test\.\s+\d+\s+IN\s+A\s+192\.0\.2\.10$', text, re.M) is not None, text[-300:])
    need('client-sees-recursion-available', re.search(r';; flags:[^;]*\bra\b', text) is not None, text[:300])
    roles = [e['role'] for e in log]
    collapsed = [r for i, r in enumerate(roles) if i == 0 or r != roles[i - 1]]
    need('all-correct-tiers', all(x in roles for x in ('root', 'tld', 'auth')), roles)
    need('poison-not-contacted', 'poison' not in roles, roles)
    root_text = Path('reference-root.out').read_text(errors='replace')
    auth_text = Path('reference-auth.out').read_text(errors='replace')
    need('reference-referral-and-decoy', all(x in root_text for x in ('ns.test.', 'not-a-nameserver.test.', '127.0.0.5')), root_text)
    need('reference-authoritative-answer', '192.0.2.10' in auth_text, auth_text)
    first = {r: next((e for e in log if e['role'] == r), None) for r in TIERS}
    need('authority-asked-for-the-name', first['auth'] is not None and first['auth']['name'].endswith('www.x.test.') or
         (first['auth'] is not None and first['auth']['name'] == 'www.x.test.'), first['auth'])
    need('answering-query-was-type-A-at-authority', any(e['role'] == 'auth' and e['name'] == 'www.x.test.' and e['qtype'] == 1 for e in log), log)
    for f in fails:
        print(f)
    print('verified recurse failed=%d' % len(fails))


if __name__ == '__main__':
    if sys.argv[1] == 'serve':
        serve(sys.argv[2])
    elif sys.argv[1] == 'waitudp':
        waitudp(sys.argv[2])
    else:
        verify()
