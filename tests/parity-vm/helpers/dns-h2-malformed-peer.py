"""Independent malformed HTTP/2 requests and post-rejection health control."""
import socket
import struct
import sys

port = int(sys.argv[1])
preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
query = struct.pack('!HHHHHH', 0x4545, 0, 1, 0, 0, 0) + b'\x03www\x07example\x04test\0' + struct.pack('!HH', 1, 1)
def frame(kind, flags, sid, data=b''):
    return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + struct.pack('!I', sid) + data
def lit(text):
    b = text.encode('ascii')
    return bytes((len(b),)) + b
def headers(length):
    return b'\x83\x86\x84\x5f' + lit('application/dns-message') + b'\x0f\x0d' + lit(str(length))
def exact(s, n):
    out = b''
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk: raise EOFError()
        out += chunk
    return out
def getframe(s):
    h = exact(s, 9)
    return h[3], h[4], int.from_bytes(h[5:9], 'big') & 0x7fffffff, exact(s, int.from_bytes(h[:3], 'big'))
def run_bad(label, request):
    s = socket.create_connection(('127.0.0.1', port), timeout=3); s.settimeout(3)
    try:
        s.sendall(preface + frame(4, 0, 0) + request)
        rejected = False
        try:
            for _ in range(30):
                kind, flags, sid, payload = getframe(s)
                if kind in (3, 7): rejected = True; break
                if kind == 1 and sid == 1:
                    if payload.startswith(b'\x88'): raise ValueError('malformed request accepted')
                    if payload.startswith(b'\x08\x03400') and flags & 1: rejected = True; break
                if kind == 0 and sid == 1: raise ValueError('malformed request returned data')
        except (EOFError, ConnectionResetError, BrokenPipeError): rejected = True
        if not rejected: raise ValueError('request was not rejected promptly')
        print(label + '=rejected')
    finally: s.close()

run_bad('duplicate-pseudo', frame(1, 5, 1, b'\x83\x83\x86\x84'))
run_bad('unknown-dynamic', frame(1, 5, 1, b'\xbe'))
run_bad('interleaved-continuation', frame(1, 0, 1, b'\x83') + frame(6, 0, 0, b'12345678'))
run_bad('wrong-content-length', frame(1, 4, 1, headers(1)) + frame(0, 1, 1, query))
s = socket.create_connection(('127.0.0.1', port), timeout=3); s.settimeout(3)
try:
    s.sendall(preface + frame(4, 0, 0) + frame(1, 4, 1, headers(len(query))) + frame(0, 1, 1, query))
    header, body, ended = False, b'', False
    for _ in range(30):
        kind, flags, sid, payload = getframe(s)
        if sid == 1 and kind == 1: header = payload.startswith(b'\x88')
        if sid == 1 and kind == 0:
            body += payload
            if flags & 1: ended = True; break
    if not header or not ended or body[:2] != b'\x45\x45' or b'\xc0\x00\x02\x0a' not in body:
        raise ValueError('post-rejection valid response failed')
    print('post-rejection-health=ok')
finally: s.close()
