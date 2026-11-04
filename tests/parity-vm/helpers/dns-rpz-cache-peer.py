"""Source-bound RPZ/cache check with an independent UDP upstream."""
import socket
import struct
import sys

mode, path = sys.argv[1:]
name = b'\x03www\x07example\x04test\0'
def question(ident):
    return struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', 1, 1)
def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.2', 5347))
    with open(path, 'w', buffering=1) as log:
        log.write('ready\n')
        while True:
            q, peer = s.recvfrom(2048)
            log.write('query\n')
            if len(q) < 12 + len(name) + 4: continue
            question_bytes = q[12:12 + len(name) + 4]
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + b'\xc0\x00\x02\x0a'
            s.sendto(q[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question_bytes + answer, peer)
def ask(source, ident):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((source, 0)); s.settimeout(5)
    try:
        s.sendto(question(ident), ('127.0.0.1', 5348)); data, _ = s.recvfrom(2048)
    finally: s.close()
    if len(data) < 12 or data[:2] != struct.pack('!H', ident): raise ValueError('bad response')
    rcode = data[3] & 15
    has_address = b'\xc0\x00\x02\x0a' in data
    return rcode, has_address
def client():
    a = ask('127.0.0.1', 0x1101)
    b = ask('127.0.0.2', 0x2202)
    c = ask('127.0.0.1', 0x3303)
    count = open(path).read().count('query\n')
    print('allowed-first=' + ('correct' if a == (0, True) else 'incorrect'))
    print('blocked-after-cache=' + ('correct' if b == (3, False) else 'incorrect'))
    print('allowed-cached=' + ('correct' if c == (0, True) and count == 1 else 'incorrect'))
if mode == 'serve': serve()
elif mode == 'client': client()
else: raise SystemExit('bad mode')
