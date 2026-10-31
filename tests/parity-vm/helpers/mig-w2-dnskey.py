#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only DNSKEY primary and assertions for the w2 rfc5011-poll fixture.

    mig-w2-dnskey.py prep            # write anchors/root.anchor (key K1) and key material
    mig-w2-dnskey.py serve PORT READY  # UDP responder returning the apex DNSKEY RRset {K1, K2}
    mig-w2-dnskey.py verify          # assertions on the poll outputs and anchor files

Key tags are computed from RFC 4034 Appendix B; state transitions follow RFC 5011 s2.4.1 with a
single hold-down of 100 s and injected times 1000/1050/1100. Written without the loadable sources.
"""
import base64
import hashlib
import json
import os
import signal
import socket
import struct
import sys

ZONE = 'rollover.test.'
K1 = hashlib.sha256(b'w2-ksk-1').digest() + hashlib.sha256(b'w2-ksk-1b').digest()
K2 = hashlib.sha256(b'w2-ksk-2').digest() + hashlib.sha256(b'w2-ksk-2b').digest()


def rdata(key, flags=257):
    return struct.pack('!HBB', flags, 3, 13) + key


def keytag(rd):
    acc = 0
    for i, b in enumerate(rd):
        acc += b << 8 if i % 2 == 0 else b
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def name_wire(name):
    return b''.join(bytes([len(l)]) + l.encode() for l in name.rstrip('.').split('.')) + b'\0'


def serve(port, ready):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', port))
    log = []

    def stop(*_):
        with open('dnskey-queries.json', 'w') as handle:
            json.dump(log, handle)
        os._exit(0)
    signal.signal(signal.SIGTERM, stop)
    open(ready, 'w').write('ready\n')
    while True:
        data, src = sock.recvfrom(4096)
        qid = data[:2]
        end = 12
        while data[end]:
            end += data[end] + 1
        qname = data[12:end + 1]
        qtype = struct.unpack('!H', data[end + 1:end + 3])[0]
        log.append({'qtype': qtype, 'qname': qname.hex()})
        question = data[12:end + 5]
        answers = b''
        for key in (K1, K2):
            rd = rdata(key)
            answers += b'\xc0\x0c' + struct.pack('!HHIH', 48, 1, 300, len(rd)) + rd
        flags = 0x8400
        if qtype != 48 or qname.lower() != name_wire(ZONE):
            answers, flags = b'', 0x8403
        count = 2 if answers else 0
        sock.sendto(qid + struct.pack('!HHHHH', flags, 1, count, 0, 0) + question + answers, src)


def prep():
    os.makedirs('anchors', exist_ok=True)
    with open('anchors/root.anchor', 'w') as handle:
        handle.write('%s IN DNSKEY 257 3 13 %s\n' % (ZONE, base64.b64encode(K1).decode()))


def keys_in(path):
    found = []
    try:
        text = open(path).read()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(';') or not line.strip():
            continue
        tok = line.split()
        if 'DNSKEY' in tok:
            found.append(base64.b64decode(''.join(tok[tok.index('DNSKEY') + 4:])))
    return found


def verify():
    fails = []
    t1, t2 = keytag(rdata(K1)), keytag(rdata(K2))
    out = {t: open('out-%d.txt' % t).read() for t in (1000, 1050, 1100)}
    rcs = open('rcs.txt').read().split()
    if rcs != ['0', '0', '0']:
        fails.append('poll-status %s' % rcs)
    if 'keytag=%d' % t2 not in out[1000] or 'added' not in out[1000] or 'pending' not in out[1000]:
        fails.append('step1-new-key-added-pending: %r' % out[1000])
    if 'keytag=%d' % t1 in out[1000]:
        fails.append('step1-active-key-untouched: %r' % out[1000])
    if 'keytag=%d' % t2 not in out[1050] or 'pending' not in out[1050] or 'promoted' in out[1050]:
        fails.append('step2-still-pending: %r' % out[1050])
    if 'keytag=%d' % t2 not in out[1100] or 'promoted' not in out[1100]:
        fails.append('step3-promoted-at-hold-down: %r' % out[1100])
    active = keys_in('anchors/root.anchor')
    previous = keys_in('anchors/root.anchor.previous')
    cand = keys_in('anchors/root.anchor.candidate')
    if active is None or sorted(active) != sorted([K1, K2]):
        fails.append('active-set-has-both-keys: %s' % (active and [keytag(rdata(k)) for k in active]))
    if previous != [K1]:
        fails.append('previous-retains-prior-active-set: %s' % previous)
    if cand:
        fails.append('candidate-emptied-after-promotion: %s' % cand)
    q = json.load(open('dnskey-queries.json'))
    if [x['qtype'] for x in q] != [48, 48, 48] or any(bytes.fromhex(x['qname']).lower() != name_wire(ZONE) for x in q):
        fails.append('server-saw-three-DNSKEY-queries-for-the-zone: %s' % q)
    for f in fails:
        print(f + ' FAIL')
    print('verified rfc5011-poll failed=%d' % len(fails))


if __name__ == '__main__':
    if sys.argv[1] == 'prep':
        prep()
    elif sys.argv[1] == 'serve':
        serve(int(sys.argv[2]), sys.argv[3])
    else:
        verify()
