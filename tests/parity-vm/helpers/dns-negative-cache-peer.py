"""Independent UDP authority/client for CNAME NODATA cache lifetime checks."""
import socket
import struct
import sys
import time

def wire(name):
    return b''.join(bytes([len(x)]) + x.encode('ascii') for x in name.split('.')) + b'\0'

def rr(owner, typ, ttl, data):
    return wire(owner) + struct.pack('!HHIH', typ, 1, ttl, len(data)) + data

def query():
    return struct.pack('!HHHHHH', 0x7421, 0x100, 1, 0, 0, 0) + wire('alias.test') + struct.pack('!HH', 28, 1)

def question_end(msg):
    i = 12
    while msg[i]:
        i += 1 + msg[i]
    return i + 5

def authority(log):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.2', 5342))
    with open(log, 'w', buffering=1) as f:
        f.write('ready\n')
        while True:
            q, peer = s.recvfrom(4096)
            f.write('upstream-query\n')
            qe = question_end(q)
            soa = wire('ns.test') + wire('hostmaster.test') + struct.pack('!IIIII', 1, 60, 60, 600, 4)
            ans = rr('alias.test', 5, 10, wire('missing.test'))
            auth = rr('test', 6, 9, soa)
            s.sendto(q[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 1, 0) + q[12:qe] + ans + auth, peer)

def lookup():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(query(), ('127.0.0.1', 5343))
    data, _ = s.recvfrom(4096)
    s.close()
    if data[:2] != b'\x74\x21' or struct.unpack('!HH', data[6:10]) != (1, 1):
        raise ValueError('invalid response header')
    off = question_end(data)
    def skip(p):
        while True:
            n = data[p]
            if n & 0xc0 == 0xc0: return p + 2
            p += 1
            if not n: return p
            p += n
    off = skip(off)
    typ, _, _, length = struct.unpack('!HHIH', data[off:off + 10])
    if typ != 5: raise ValueError('missing CNAME')
    off += 10 + length
    off = skip(off)
    typ, _, ttl, _ = struct.unpack('!HHIH', data[off:off + 10])
    if typ != 6: raise ValueError('missing SOA')
    return ttl

def client(log):
    first = lookup()
    time.sleep(1.1)
    second = lookup()
    before = open(log).read().count('upstream-query')
    time.sleep(3.1)
    third = lookup()
    after = open(log).read().count('upstream-query')
    print('first-soa-capped=' + ('yes' if first == 4 else 'no'))
    print('cached-soa-aged=' + ('yes' if 0 <= second < first else 'no'))
    print('second-from-cache=' + ('yes' if before == 1 else 'no'))
    print('expired-refetched=' + ('yes' if after == 2 and third == 4 else 'no'))

if sys.argv[1] == 'authority': authority(sys.argv[2])
elif sys.argv[1] == 'client': client(sys.argv[2])
else: raise SystemExit('unknown mode')
