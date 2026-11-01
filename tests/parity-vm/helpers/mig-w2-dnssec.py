#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only independently signed DNS hierarchy, BIND delv control and assertions for the w2 DNSSEC fixtures.

    mig-w2-dnssec.py prep                      # write trust anchors (candidate DS file, delv conf, wrong-digest variants)
    mig-w2-dnssec.py serve IP PORT READY       # UDP server for ".", "test.", "x.test." and "bad.test." (one process)
    mig-w2-dnssec.py waitudp IP PORT           # wait until a UDP port is bound
    mig-w2-dnssec.py control IP PORT GROUP...  # BIND delv validates the zone: good names secure, bogus names fail
    mig-w2-dnssec.py verify-secure|verify-below|verify-bogus|verify-skew|verify-anchor   # assertions on candidate query outputs
    mig-w2-dnssec.py verify-resolver-ad|verify-resolver-bogus               # assertions on dig answers from a resolver

The zones are signed here with ECDSAP256SHA256 (RFC 6605) from fixed key seeds: a KSK (flags 257) signs each DNSKEY
RRset, a ZSK (256) signs the rest, DS digests are SHA-256 (RFC 4509), NSEC chains follow RFC 4034 s4 and the denial
proofs follow RFC 4035 s3.1.3. Signature windows are computed from the guest clock when the server starts, so the
validation time is fixed relative to the fixture: valid names carry [now-1h, now+30d], the skew names carry a window
that ended (or starts) 120 s from now, and the expired or future names are an hour outside it. Expected outcomes are
fixed by those choices and never read from the candidate. Written without the loadable sources.
"""
import base64
import hashlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ALG = 13
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
T_A, T_NS, T_SOA, T_TXT, T_DS, T_RRSIG, T_NSEC, T_DNSKEY, T_OPT = 1, 2, 6, 16, 43, 46, 47, 48, 41
TTL = 300
PORT = 5340
GOOD = ['www.x.test', 'mail.x.test', 'txt.x.test']


def labels_of(name):
    return [p for p in name.rstrip('.').split('.') if p]


def wire(name):
    out = b''
    for part in labels_of(name):
        out += bytes([len(part)]) + part.lower().encode()
    return out + b'\0'


def canon_key(name):
    return tuple(p.lower().encode() for p in reversed(labels_of(name)))


def keytag(rd):
    acc = 0
    for i, b in enumerate(rd):
        acc += b << 8 if i % 2 == 0 else b
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


class Key:
    def __init__(self, label, flags):
        scalar = int.from_bytes(hashlib.sha256(b'w2-dnssec-' + label.encode()).digest(), 'big') % (ORDER - 1) + 1
        self.priv = ec.derive_private_key(scalar, ec.SECP256R1())
        nums = self.priv.public_key().public_numbers()
        self.rdata = struct.pack('!HBB', flags, 3, ALG) + nums.x.to_bytes(32, 'big') + nums.y.to_bytes(32, 'big')
        self.tag = keytag(self.rdata)

    def sign(self, data):
        r, s = decode_dss_signature(self.priv.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def ds_rdata(owner, key, wrong=False):
    digest = hashlib.sha256(wire(owner) + key.rdata).digest()
    if wrong:
        digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
    return struct.pack('!HBB', key.tag, ALG, 2) + digest


def rrset_canonical(owner, rtype, rdatas):
    return b''.join(wire(owner) + struct.pack('!HHIH', rtype, 1, TTL, len(rd)) + rd for rd in sorted(rdatas))


def rrsig(key, signer, owner, rtype, rdatas, inc, exp):
    head = struct.pack('!HBBIIIH', rtype, ALG, len(labels_of(owner)), TTL, exp, inc, key.tag) + wire(signer)
    return head + key.sign(head + rrset_canonical(owner, rtype, rdatas))


def bitmap(types):
    windows = {}
    for t in types:
        windows.setdefault(t >> 8, bytearray(32))[(t & 255) // 8] |= 0x80 >> (t & 7)
    out = b''
    for w in sorted(windows):
        bits = windows[w]
        n = max(i for i, v in enumerate(bits) if v) + 1
        out += bytes([w, n]) + bytes(bits[:n])
    return out


# deeper names in x.test.: all correctly signed (the chain walker needs a DS lookup at every label below a zone apex)
LEAVES = {
    'www.x.test.': [T_A, '192.0.2.10'],
    'mail.x.test.': [T_A, '192.0.2.25'],
    'txt.x.test.': [T_TXT, b'\x05hello', b'\x05world'],
}
# one-name zones whose apex A RRset carries the defect named by the zone label (the apex needs no DS lookup below it)
APEX = {
    'ok.test.': ('good', '192.0.2.60'),
    'badsig.test.': ('badsig', '192.0.2.61'),
    'tamper.test.': ('tamper', '192.0.2.62'),
    'nosig.test.': ('nosig', '192.0.2.63'),
    'expired.test.': ('expired', '192.0.2.64'),
    'future.test.': ('future', '192.0.2.65'),
    'unknownkey.test.': ('unknownkey', '192.0.2.66'),
    'edge-exp.test.': ('edge-exp', '192.0.2.67'),
    'edge-inc.test.': ('edge-inc', '192.0.2.68'),
    'badds.test.': ('good', '192.0.2.69'),       # DS in test. has a flipped digest
    'badnsec.test.': ('good', '192.0.2.70'),     # the apex NSEC (NODATA proof) carries a flipped signature
}


def windows(now):
    return {
        'good': (now - 3600, now + 30 * 86400),
        'expired': (now - 7200, now - 3600),
        'future': (now + 3600, now + 7200),
        'edge-exp': (now - 3600, now - 120),
        'edge-inc': (now + 120, now + 86400),
    }


def flip(sig):
    return sig[:-1] + bytes([sig[-1] ^ 0x01])


class Zone:
    def __init__(self, origin, ksk, zsk):
        self.origin, self.ksk, self.zsk = origin, ksk, zsk
        self.names = {}          # owner -> {type: [rdata]}
        self.sigs = {}           # (owner, type) -> [rrsig rdata]

    def add(self, owner, rtype, rdatas):
        self.names.setdefault(owner, {})[rtype] = list(rdatas)


def soa(zone):
    mname = wire('ns.' + zone) if zone != '.' else wire('ns.')
    return mname + wire('hostmaster.' + zone if zone != '.' else 'hostmaster.') + struct.pack('!IIIII', 1, 3600, 600, 86400, TTL)


def build(now):
    win = windows(now)
    names = ('.', 'test.', 'x.test.') + tuple(APEX)
    keys = {z: (Key(z + 'ksk', 257), Key(z + 'zsk', 256)) for z in names}
    rogue = Key('rogue', 256)
    zones = {z: Zone(z, *keys[z]) for z in keys}
    for z in zones:
        zones[z].add(z, T_SOA, [soa(z)])
        zones[z].add(z, T_NS, [wire('ns.' + z if z != '.' else 'ns.')])
        zones[z].add(z, T_DNSKEY, [k.rdata for k in keys[z]])
    delegations = [('.', 'test.', False), ('test.', 'x.test.', False)] + [('test.', z, z == 'badds.test.') for z in APEX]
    for parent, child, wrong in delegations:
        zones[parent].add(child, T_NS, [wire('ns.' + child)])
        zones[parent].add(child, T_DS, [ds_rdata(child, keys[child][0], wrong)])
    leaf = zones['x.test.']
    for owner, spec in LEAVES.items():
        leaf.add(owner, spec[0], [socket.inet_aton(spec[1])] if spec[0] == T_A else spec[1:])
    for z, (mode, ip) in APEX.items():
        zones[z].add(z, T_A, [socket.inet_aton(ip)])
        zones[z].add(z, T_TXT, [b'\x05hello', b'\x05world'])
    # NSEC chain per zone (RFC 4034 s4): canonical order, last wraps to the apex
    for z, zone in zones.items():
        owners = sorted(zone.names, key=canon_key)
        for i, owner in enumerate(owners):
            nxt = owners[(i + 1) % len(owners)]
            zone.names[owner][T_NSEC] = [wire(nxt) + bitmap(set(zone.names[owner]) | {T_RRSIG, T_NSEC})]
    for z, zone in zones.items():
        for owner, rrsets in zone.names.items():
            for rtype, rdatas in rrsets.items():
                if rtype == T_NS and owner != z:
                    continue                      # delegation NS is unsigned (RFC 4035 s2.2)
                mode = 'good'
                signkey = zone.ksk if rtype == T_DNSKEY else zone.zsk
                signed_rdatas = rdatas
                if z in APEX and owner == z and rtype == T_A:
                    mode = APEX[z][0]
                if z == 'badnsec.test.' and rtype == T_NSEC:
                    mode = 'badsig'
                if mode == 'nosig':
                    continue
                inc, exp = win.get(mode, win['good'])
                if mode == 'unknownkey':
                    signkey = rogue
                if mode == 'tamper':
                    signed_rdatas = [socket.inet_aton('192.0.2.77')]
                sig = rrsig(signkey, z, owner, rtype, signed_rdatas, inc, exp)
                if mode == 'badsig':
                    sig = flip(sig)
                zone.sigs[(owner, rtype)] = [sig]
    return zones


def anchors(directory='.'):
    ksk = Key('.ksk', 257)
    good = '. IN DS %d %d 2 %s\n' % (ksk.tag, ALG, ds_rdata('.', ksk)[4:].hex())
    wrong = '. IN DS %d %d 2 %s\n' % (ksk.tag, ALG, ds_rdata('.', ksk, wrong=True)[4:].hex())
    Path(directory, 'anchor.ds').write_text(good)
    Path(directory, 'anchor.wrong.ds').write_text(wrong)
    for name, text in (('anchor.delv.conf', good), ('anchor.wrong.delv.conf', wrong)):
        f = text.split()
        Path(directory, name).write_text('trust-anchors { "." static-ds %s %s %s "%s"; };\n' % (f[3], f[4], f[5], f[6]))


# ---- server ----------------------------------------------------------------

def parse_query(data):
    end = 12
    while data[end]:
        end += data[end] + 1
    qname_raw = data[12:end + 1]
    qtype = struct.unpack('!H', data[end + 1:end + 3])[0]
    off = end + 5
    udp, do, edns = 512, False, False
    for _ in range(struct.unpack('!H', data[10:12])[0]):
        if data[off] != 0:
            break
        rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[off + 1:off + 11])
        if rtype == T_OPT:
            edns, udp, do = True, max(rclass, 512), bool(ttl & 0x8000)
        off += 11 + rdlen
    return qname_raw, qtype, data[12:end + 5], udp, do, edns


def decode_name(raw):
    out, i = [], 0
    while raw[i]:
        out.append(raw[i + 1:i + 1 + raw[i]].decode())
        i += 1 + raw[i]
    return '.'.join(out) + '.' if out else '.'


def pick_zone(zones, name, qtype):
    best = None
    for z in zones:
        if z == '.' or name == z or name.endswith('.' + z):
            if qtype == T_DS and name == z and z != '.':
                continue
            if best is None or len(z) > len(best):
                best = z
    return best


def respond(zones, data):
    qraw, qtype, question, udp, do, edns = parse_query(data)
    qcase = decode_name(qraw)
    name = qcase.lower()
    zone = zones[pick_zone(zones, name, qtype)]
    rd = struct.unpack('!H', data[2:4])[0] & 0x0100

    def owner_bytes(owner):
        return qraw if owner == name else wire(owner)

    def rr(owner, rtype, rdata):
        return owner_bytes(owner) + struct.pack('!HHIH', rtype, 1, TTL, len(rdata)) + rdata

    def rrset_with_sigs(owner, rtype, out):
        for rdata in zone.names[owner][rtype]:
            out.append(rr(owner, rtype, rdata))
        if do:
            for sig in zone.sigs.get((owner, rtype), []):
                out.append(rr(owner, T_RRSIG, sig))

    def covering(target):
        owners = sorted(zone.names, key=canon_key)
        for i, owner in enumerate(owners):
            nxt = owners[(i + 1) % len(owners)]
            if canon_key(owner) <= canon_key(target) < canon_key(nxt) or (i == len(owners) - 1 and canon_key(target) > canon_key(owner)):
                return owner
        return owners[-1]
    answer, authority, rcode = [], [], 0
    rrsets = zone.names.get(name)
    if rrsets is not None and qtype in rrsets and not (qtype == T_NS and name != zone.origin):
        rrset_with_sigs(name, qtype, answer)
    elif rrsets is not None:
        rrset_with_sigs(zone.origin, T_SOA, authority)
        if do:
            rrset_with_sigs(name, T_NSEC, authority)
    else:
        rcode = 3
        rrset_with_sigs(zone.origin, T_SOA, authority)
        if do:
            seen = []
            wildcard = '*.' + zone.origin if zone.origin != '.' else '*.'
            for target in (name, wildcard):
                owner = covering(target)
                if owner not in seen:
                    seen.append(owner)
                    rrset_with_sigs(owner, T_NSEC, authority)
    additional = []
    if edns:
        additional.append(b'\0' + struct.pack('!HHIH', T_OPT, 1232, 0x8000 if do else 0, 0))
    flags = 0x8400 | rd | rcode
    body = question + b''.join(answer) + b''.join(authority) + b''.join(additional)
    msg = data[:2] + struct.pack('!HHHHH', flags, 1, len(answer), len(authority), len(additional)) + body
    if len(msg) > udp:
        msg = data[:2] + struct.pack('!HHHHH', flags | 0x0200, 1, 0, 0, 0) + question
    return msg, (name, qtype, do)


def serve(ip, port, ready):
    zones = build(int(time.time()))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, int(port)))
    log = []

    def stop(*_):
        Path('dnssec-queries.json').write_text(json.dumps(log))
        os._exit(0)
    signal.signal(signal.SIGTERM, stop)
    Path(ready).write_text('ready\n')
    while True:
        data, src = sock.recvfrom(4096)
        msg, info = respond(zones, data)
        log.append({'name': info[0], 'type': info[1], 'do': info[2], 'tc': bool(msg[2] & 2), 'bytes': len(msg)})
        sock.sendto(msg, src)
        Path('dnssec-queries.json').write_text(json.dumps(log))


def waitudp(ip, port):
    parts = ip.split('.')
    want = '%02X%02X%02X%02X:%04X' % (int(parts[3]), int(parts[2]), int(parts[1]), int(parts[0]), int(port))
    end = time.monotonic() + 10
    while True:
        rows = Path('/proc/net/udp').read_text().splitlines()[1:]
        if any(r.split()[1] == want for r in rows):
            return
        if time.monotonic() > end:
            print('udp-%s-not-bound' % port)
            sys.exit(1)
        time.sleep(0.05)


# ---- delv control (independent validator) ------------------------------------

def delv(ip, port, name, qtype, conf='anchor.delv.conf'):
    proc = subprocess.run(['/usr/bin/delv', '-a', conf, '-p', str(port), '@' + ip, '-t', qtype, name], capture_output=True, text=True, timeout=30)
    return proc.stdout + proc.stderr


def secure(text):
    return 'fully validated' in text and 'resolution failed' not in text


def control(ip, port, groups):
    fails = []
    jobs = []        # (label, name, type, conf, predicate)

    def add(label, name, typ, pred, conf='anchor.delv.conf'):
        jobs.append((label, name, typ, conf, pred))
    bogus = lambda t: 'resolution failed' in t and 'fully validated' not in t
    neg = lambda t: 'negative response, fully validated' in t
    if 'ok' in groups or 'secure' in groups:
        add('secure-ok-A', 'ok.test', 'A', secure)
    if 'secure' in groups:
        add('secure-ok-TXT', 'ok.test', 'TXT', secure)
        add('secure-ok-DNSKEY', 'ok.test', 'DNSKEY', secure)
        add('secure-nodata-ok-AAAA', 'ok.test', 'AAAA', neg)
        add('secure-nxdomain-below-ok', 'nx.ok.test', 'A', lambda t: neg(t) and 'ncache nxdomain' in t)
        for name, typ in (('www.x.test', 'A'), ('mail.x.test', 'A'), ('txt.x.test', 'TXT')):
            add('secure-%s-%s' % (name, typ), name, typ, secure)
        add('secure-nxdomain-nx-x-test', 'nx.x.test', 'A', lambda t: neg(t) and 'ncache nxdomain' in t)
        add('secure-nodata-www-aaaa', 'www.x.test', 'AAAA', neg)
    if 'bogus' in groups:
        for z in ('badsig', 'tamper', 'nosig', 'expired', 'future', 'unknownkey', 'edge-exp', 'edge-inc', 'badds'):
            add('bogus-' + z, z + '.test', 'A', bogus)
        add('bogus-nodata-bad-nsec-signature', 'badnsec.test', 'AAAA', bogus)
    if 'anchor' in groups:
        add('bogus-wrong-trust-anchor', 'ok.test', 'A', lambda t: 'fully validated' not in t, 'anchor.wrong.delv.conf')
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as pool:
        texts = list(pool.map(lambda j: delv(ip, port, j[1], j[2], j[3]), jobs))
    for (label, _, _, _, pred), text in zip(jobs, texts):
        if not pred(text):
            fails.append('control-%s FAIL %s' % (label, text[:300].replace('\n', ' | ')))
    for f in fails:
        print(f)
    print('control-ok' if not fails else 'control-failed=%d' % len(fails))


# ---- assertions -------------------------------------------------------------

def read(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return None


def run_status(stem):
    rc = (read(stem + '.rc') or 'missing').strip()
    out = [l.strip() for l in (read(stem + '.out') or '').splitlines() if l.strip()]
    return rc, out, read(stem + '.err') or ''


def finish(label, fails):
    for f in fails:
        print(f)
    print('verified %s failed=%d' % (label, len(fails)))


def expect_answer(fails, label, stem, answers):
    rc, out, err = run_status(stem)
    if not (rc == '0' and sorted(l.strip('"') for l in out) == sorted(answers)):
        fails.append('%s FAIL rc=%s out=%r err=%r' % (label, rc, out, err[:120]))


def expect_denial(fails, label, stem):
    rc, out, err = run_status(stem)
    if not (rc == '0' and not out):
        fails.append('%s FAIL rc=%s out=%r err=%r' % (label, rc, out, err[:120]))


def expect_rejected(fails, label, stem):
    rc, out, err = run_status(stem)
    if rc in ('0', 'missing') or out:
        fails.append('%s FAIL rc=%s out=%r' % (label, rc, out))


def verify_secure():
    fails = []
    expect_answer(fails, 'secure-ok-A', 's-ok.test-A', ['192.0.2.60'])
    expect_answer(fails, 'secure-ok-TXT', 's-ok.test-TXT', ['hello', 'world'])
    expect_denial(fails, 'secure-nodata-ok-AAAA', 's-ok.test-AAAA')
    expect_denial(fails, 'secure-nodata-ok-MX', 's-ok.test-MX')
    finish('secure', fails)


def verify_below():
    fails = []
    expect_answer(fails, 'below-apex-www-A', 'w-www.x.test-A', ['192.0.2.10'])
    expect_answer(fails, 'below-apex-mail-A', 'w-mail.x.test-A', ['192.0.2.25'])
    expect_answer(fails, 'below-apex-txt-TXT', 'w-txt.x.test-TXT', ['hello', 'world'])
    expect_denial(fails, 'below-apex-nxdomain-nx', 'w-nx.x.test-A')
    expect_denial(fails, 'below-apex-nxdomain-nx-ok', 'w-nx.ok.test-A')
    expect_denial(fails, 'below-apex-nodata-www-AAAA', 'w-www.x.test-AAAA')
    finish('below-apex', fails)


def verify_bogus():
    fails = []
    expect_answer(fails, 'positive-control-ok-A', 'b-ok.test-A', ['192.0.2.60'])
    for z in ('badsig', 'tamper', 'nosig', 'expired', 'future', 'unknownkey', 'badds'):
        expect_rejected(fails, 'bogus-%s' % z, 'b-%s.test-A' % z)
    expect_rejected(fails, 'bogus-nodata-bad-nsec-signature', 'b-badnsec.test-AAAA')
    finish('bogus', fails)


def verify_skew():
    fails = []
    expect_answer(fails, 'valid-window-accepted-with-skew-0', 'k0-ok.test-A', ['192.0.2.60'])
    for z, ip in (('edge-exp', '192.0.2.67'), ('edge-inc', '192.0.2.68')):
        expect_rejected(fails, '%s-rejected-with-skew-0' % z, 'k0-%s.test-A' % z)
        expect_answer(fails, '%s-accepted-within-skew-300' % z, 'k300-%s.test-A' % z, [ip])
    for z, ip in (('expired', '192.0.2.64'), ('future', '192.0.2.65')):
        expect_rejected(fails, '%s-rejected-with-skew-300' % z, 'k300-%s.test-A' % z)
        expect_answer(fails, '%s-accepted-within-skew-7200' % z, 'k7200-%s.test-A' % z, [ip])
    finish('skew', fails)


def verify_anchor():
    fails = []
    expect_answer(fails, 'matching-anchor-validates', 'a-good', ['192.0.2.60'])
    expect_rejected(fails, 'wrong-digest-anchor-rejected', 'a-wrong')
    expect_rejected(fails, 'missing-anchor-file-rejected', 'a-none')
    finish('anchor', fails)


def dig_fields(text):
    status = re.search(r'status: (\w+)', text)
    flags = re.search(r';; flags: ([a-z ]+);', text)
    answers = re.findall(r'^\S+\s+\d+\s+IN\s+A\s+(\S+)$', text, re.M)
    return (status.group(1) if status else None), set((flags.group(1) if flags else '').split()), answers


def verify_resolver_ad():
    fails = []
    status, flags, answers = dig_fields(read('dig-valid.out') or '')
    if status != 'NOERROR' or answers != ['192.0.2.60']:
        fails.append('valid-answer-delivered FAIL status=%s answers=%r' % (status, answers))
    if 'ad' not in flags:
        fails.append('valid-answer-has-ad-flag FAIL flags=%s' % sorted(flags))
    status, flags, answers = dig_fields(read('dig-nodata.out') or '')
    if 'ad' not in flags or status != 'NOERROR' or answers:
        fails.append('valid-nodata-has-ad-flag FAIL status=%s flags=%s' % (status, sorted(flags)))
    status, flags, answers = dig_fields(read('dig-nx.out') or '')
    if 'ad' not in flags or status != 'NXDOMAIN':
        fails.append('valid-nxdomain-has-ad-flag FAIL status=%s flags=%s' % (status, sorted(flags)))
    status, flags, answers = dig_fields(read('dig-noad.out') or '')
    if answers != ['192.0.2.60'] or 'ad' in flags:
        fails.append('query-without-do-or-ad-request-carries-no-ad FAIL status=%s flags=%s answers=%r' % (status, sorted(flags), answers))
    finish('resolver-ad', fails)


def verify_resolver_bogus():
    fails = []
    for name in ('badsig', 'tamper', 'nosig', 'expired', 'unknownkey', 'badds'):
        status, flags, answers = dig_fields(read('dig-%s.out' % name) or '')
        if status != 'SERVFAIL' or answers or 'ad' in flags:
            fails.append('bogus-%s-servfail FAIL status=%s flags=%s answers=%r' % (name, status, sorted(flags), answers))
    status, flags, answers = dig_fields(read('dig-cd.out') or '')
    if status != 'NOERROR' or answers != ['192.0.2.61'] or 'ad' in flags:
        fails.append('checking-disabled-returns-bogus-data-without-ad FAIL status=%s flags=%s answers=%r' % (status, sorted(flags), answers))
    finish('resolver-bogus', fails)


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'prep':
        anchors()
    elif cmd == 'serve':
        serve(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'waitudp':
        waitudp(sys.argv[2], sys.argv[3])
    elif cmd == 'control':
        control(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        {'verify-secure': verify_secure, 'verify-below': verify_below, 'verify-bogus': verify_bogus, 'verify-skew': verify_skew,
         'verify-anchor': verify_anchor, 'verify-resolver-ad': verify_resolver_ad,
         'verify-resolver-bogus': verify_resolver_bogus}[cmd]()
