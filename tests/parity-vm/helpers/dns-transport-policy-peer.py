"""Independent DNS clients bound to two local source addresses, VM only."""
import socket
import ssl
import struct
import sys

transport, source, port, cert = sys.argv[1:]
port = int(port)
name = b'\x03www\x07example\x04test\x00'
query = struct.pack('!HHHHHH', 0x1234, 0, 1, 0, 0, 0) + name + struct.pack('!HH', 1, 1)

def exact(s, n):
    out = b''
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk: raise OSError('short read')
        out += chunk
    return out

def skip_name(data, pos):
    while True:
        n = data[pos]
        if n & 0xc0 == 0xc0: return pos + 2
        pos += 1
        if not n: return pos
        pos += n

def parse(data):
    if len(data) < 12 or data[:2] != b'\x12\x34' or not (data[2] & 0x80):
        raise ValueError('bad DNS response')
    if data[3] & 15: return 'rcode-%d' % (data[3] & 15)
    pos = 12
    for _ in range(struct.unpack('!H', data[4:6])[0]): pos = skip_name(data, pos) + 4
    addresses = []
    for _ in range(struct.unpack('!H', data[6:8])[0]):
        pos = skip_name(data, pos)
        typ, cls, _, n = struct.unpack('!HHIH', data[pos:pos + 10])
        pos += 10
        if typ == 1 and cls == 1 and n == 4: addresses.append(socket.inet_ntoa(data[pos:pos + n]))
        pos += n
    return ','.join(addresses) or 'no-A'

try:
    kind = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, kind)
    sock.settimeout(2)
    sock.bind((source, 0))
    sock.connect(('127.0.0.1', port))
    if transport in ('dot', 'doh-tls'):
        ctx = ssl.create_default_context(cafile=cert)
        sock = ctx.wrap_socket(sock, server_hostname='127.0.0.1')
    if transport == 'udp':
        sock.sendall(query)
        response = sock.recv(4096)
    elif transport in ('doh', 'doh-tls'):
        header = (b'POST /dns-query HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                  b'Content-Type: application/dns-message\r\nContent-Length: ' + str(len(query)).encode() + b'\r\n\r\n')
        sock.sendall(header + query)
        data = b''
        while b'\r\n\r\n' not in data:
            data += exact(sock, 1)
            if len(data) > 16384: raise ValueError('HTTP header too long')
        head, response = data.split(b'\r\n\r\n', 1)
        if not head.startswith(b'HTTP/1.1 200 '): raise ValueError('HTTP status')
        lengths = [int(x.split(b':', 1)[1].strip()) for x in head.split(b'\r\n')[1:] if x.lower().startswith(b'content-length:')]
        if len(lengths) != 1 or lengths[0] > 4096: raise ValueError('HTTP length')
        response += exact(sock, lengths[0] - len(response))
    else:
        sock.sendall(struct.pack('!H', len(query)) + query)
        response = exact(sock, struct.unpack('!H', exact(sock, 2))[0])
    print(transport + ' ' + source + ' ' + parse(response))
except (OSError, ValueError, IndexError, struct.error) as exc:
    print(transport + ' ' + source + ' denied-or-error')
