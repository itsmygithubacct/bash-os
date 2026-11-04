"""Independent bounded HTTP/2 client: multiplexing, HPACK state and windows."""
import socket
import struct
import sys

port = int(sys.argv[1])
def frame(kind, flags, sid, data=b''):
    return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + struct.pack('!I', sid) + data
def lit(text):
    b = text.encode('ascii')
    if len(b) >= 127: raise ValueError('fixture literal too long')
    return bytes((len(b),)) + b
def query(ident):
    return struct.pack('!HHHHHH', ident, 0, 1, 0, 0, 0) + b'\x03www\x07example\x04test\0' + struct.pack('!HH', 1, 1)
def block(qlen, insert):
    # Static :method POST, :scheme http, :path /. Stream 1 inserts a dynamic
    # content-type entry; later streams refer to index 62 on the same connection.
    out = b'\x83\x86\x84'
    out += (b'\x5f' + lit('application/dns-message')) if insert else b'\xbe'
    return out + b'\x0f\x0d' + lit(str(qlen))  # content-length, no indexing
def exact(sock, n):
    data = b''
    while len(data) < n:
        b = sock.recv(n - len(data))
        if not b: raise ValueError('unexpected EOF')
        data += b
    return data
def read_frame(sock):
    h = exact(sock, 9)
    n = int.from_bytes(h[:3], 'big')
    if n > 65535: raise ValueError('oversize frame')
    return h[3], h[4], int.from_bytes(h[5:9], 'big') & 0x7fffffff, exact(sock, n)
def valid_dns(data, ident):
    if len(data) < 12 or struct.unpack('!H', data[:2])[0] != ident or (data[3] & 15): return False
    def skip(i):
        while True:
            n = data[i]
            if n & 0xc0 == 0xc0: return i + 2
            i += 1
            if not n: return i
            i += n
    try:
        off = 12
        for _ in range(struct.unpack('!H', data[4:6])[0]): off = skip(off) + 4
        for _ in range(struct.unpack('!H', data[6:8])[0]):
            off = skip(off)
            typ, cls, _, n = struct.unpack('!HHIH', data[off:off+10]); off += 10
            if typ == 1 and cls == 1 and n == 4 and data[off:off+4] == b'\xc0\x00\x02\x0a': return True
            off += n
    except (IndexError, struct.error): return False
    return False

sock = socket.create_connection(('127.0.0.1', port), timeout=4)
sock.settimeout(4)
try:
    q1, q3, q5 = query(0x1111), query(0x3333), query(0x5555)
    # Initially block server DATA on every stream. Requests 1 and 3 are
    # interleaved before either body is sent.
    initial_window_zero = struct.pack('!HI', 4, 0)
    sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0, initial_window_zero) +
                 frame(1, 4, 1, block(len(q1), True)) + frame(1, 4, 3, block(len(q3), False)) +
                 frame(0, 1, 1, q1) + frame(0, 1, 3, q3))
    got_headers = set()
    for _ in range(40):
        kind, flags, sid, payload = read_frame(sock)
        if kind == 0: raise ValueError('DATA sent before stream window credit')
        if kind == 1 and sid in (1, 3):
            if not payload or payload[0] != 0x88: raise ValueError('unexpected status')
            got_headers.add(sid)
            if len(got_headers) == 2: break
    if got_headers != {1, 3}: raise ValueError('missing response headers')
    print('zero-window-blocks-data=yes')
    sock.sendall(frame(8, 0, 1, struct.pack('!I', 4096)) + frame(8, 0, 3, struct.pack('!I', 4096)))
    bodies, ended = {1: b'', 3: b''}, set()
    for _ in range(40):
        kind, flags, sid, payload = read_frame(sock)
        if kind == 0 and sid in bodies:
            bodies[sid] += payload
            if flags & 1: ended.add(sid)
            if len(ended) == 2: break
    if ended != {1, 3} or not valid_dns(bodies[1], 0x1111) or not valid_dns(bodies[3], 0x3333):
        raise ValueError('multiplexed DNS answers invalid')
    print('streams-1-and-3=validated')
    sock.sendall(frame(1, 4, 5, block(len(q5), False)) + frame(0, 1, 5, q5) +
                 frame(8, 0, 5, struct.pack('!I', 4096)))
    header, body, ended5 = False, b'', False
    for _ in range(40):
        kind, flags, sid, payload = read_frame(sock)
        if sid == 5 and kind == 1: header = bool(payload and payload[0] == 0x88)
        if sid == 5 and kind == 0:
            body += payload
            if flags & 1: ended5 = True; break
    if not header or not ended5 or not valid_dns(body, 0x5555): raise ValueError('third stream invalid')
    print('stream-5-dynamic=validated')
finally:
    sock.close()
