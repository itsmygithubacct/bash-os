#!/usr/bin/python3
"""Fixture-only loopback evidence; never run on the host."""
import fcntl
import json
import os
from pathlib import Path
import socket
import struct

if os.getuid() != 2000 or os.geteuid() != 2000 or os.getcwd() != '/tmp/parity-case' or os.environ.get('HOME') != '/tmp/parity-home':
    raise RuntimeError('unexpected fixture identity')
marker = Path('/etc/bashos-parity-vm').read_text().strip().lower()
product = Path('/run/bashos-parity-vm-identity').read_text().strip().lower()
if marker != product or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
    raise RuntimeError('unexpected guest identity')
interfaces = sorted(os.listdir('/sys/class/net'))
if interfaces != ['lo']:
    raise RuntimeError('unexpected network interface')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    flags = struct.unpack('H', fcntl.ioctl(receiver.fileno(), 0x8913, struct.pack('16sH14x', b'lo', 0))[16:18])[0]
    if not flags & 1:
        raise RuntimeError('loopback is down')
    receiver.settimeout(2); sender.settimeout(2)
    receiver.bind(('127.0.0.1', 0)); sender.bind(('127.0.0.1', 0))
    sender.sendto(b'bashos-udp-control', receiver.getsockname())
    data, peer = receiver.recvfrom(256)
    if data != b'bashos-udp-control' or peer != sender.getsockname():
        raise RuntimeError('loopback UDP exchange mismatch')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    listener.settimeout(2); client.settimeout(2)
    listener.bind(('127.0.0.1', 0)); listener.listen(1)
    client.connect(listener.getsockname())
    with listener.accept()[0] as server:
        server.settimeout(2); client.sendall(b'bashos-tcp-control')
        if server.recv(256) != b'bashos-tcp-control' or server.getpeername() != client.getsockname():
            raise RuntimeError('loopback TCP exchange mismatch')
        server.sendall(b'ok')
        if client.recv(2) != b'ok':
            raise RuntimeError('loopback TCP reply mismatch')
proof = {'schema':'bashos-dns-loopback-control-v1','vm_uuid':marker,'uid':os.geteuid(),
         'netns':os.readlink('/proc/self/ns/net'),'interfaces':interfaces,'lo_up':True,
         'udp_exchange':True,'tcp_exchange':True,'address':'127.0.0.1'}
Path('/tmp/parity-home/dns-loopback-control.json').write_text(json.dumps(proof,sort_keys=True)+'\n')
