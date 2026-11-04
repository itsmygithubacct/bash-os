"""Force UDP truncation then close the TCP fallback with an immediate reset."""
import socket
import struct
import sys

log_path = sys.argv[1]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp.bind(('127.0.0.2', 5349)); tcp.bind(('127.0.0.2', 5349)); tcp.listen(2)
udp.settimeout(10); tcp.settimeout(10)
with open(log_path, 'w', buffering=1) as log:
    log.write('ready\n')
    q, peer = udp.recvfrom(4096)
    log.write('udp-query\n')
    end = 12
    while q[end]: end += 1 + q[end]
    question = q[12:end + 5]
    flags = 0x8200 | (struct.unpack('!H', q[2:4])[0] & 0x0100)
    udp.sendto(q[:2] + struct.pack('!HHHHH', flags, 1, 0, 0, 0) + question, peer)
    conn, _ = tcp.accept()
    log.write('tcp-accepted\n')
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    conn.close()
udp.close(); tcp.close()
