"""Check DNS question case and IDs across fresh and cached UDP answers."""
import socket
import struct
import sys

port = int(sys.argv[1])
name = b'\x02Ok\x04TeSt\0'
def query(ident, dnssec):
    header = struct.pack('!HHHHHH', ident, 0x0120, 1, 0, 0, int(dnssec))
    question = name + struct.pack('!HH', 1, 1)
    opt = b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000, 0) if dnssec else b''
    return header + question + opt
def run(ident, dnssec):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(10)
    try:
        s.sendto(query(ident, dnssec), ('127.0.0.1', port)); data, _ = s.recvfrom(4096)
    finally: s.close()
    if len(data) < 12 or data[:2] != struct.pack('!H', ident) or data[3] & 15 or not data[3] & 0x20:
        raise ValueError('invalid authenticated response')
    if data[12:12 + len(name)] != name:
        raise ValueError('question case changed')
    if b'\xc0\x00\x02\x3c' not in data:
        raise ValueError('expected A address absent')
for enabled in (False, True):
    run(0x1010 + enabled * 2, enabled)
    run(0x1011 + enabled * 2, enabled)
    print(('do' if enabled else 'no-do') + '-fresh-and-cached=correct')
