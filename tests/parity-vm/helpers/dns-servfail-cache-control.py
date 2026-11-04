#!/usr/bin/python3
"""VM-only control: transient failure with an SOA must not be cached."""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
up.bind(('127.0.0.1', 0))
up.settimeout(0.2)
up_port = up.getsockname()[1]
reserve = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
reserve.bind(('127.0.0.1', 0))
resolver_port = reserve.getsockname()[1]
reserve.close()
seen = []
stop = threading.Event()
name = b'\x06failed\x04test\0'
question = name + struct.pack('!HH', 1, 1)
soa = b'\0\0' + struct.pack('!IIIII', 1, 30, 30, 30, 30)
authority = b'\xc0\x0c' + struct.pack('!HHIH', 6, 1, 30, len(soa)) + soa

def peer():
    while not stop.is_set():
        try:
            request, addr = up.recvfrom(4096)
        except socket.timeout:
            continue
        seen.append(request)
        header = request[:2] + struct.pack('!HHHHH', 0x8182, 1, 0, 1, 0)
        up.sendto(header + question + authority, addr)

thread = threading.Thread(target=peer, daemon=True)
thread.start()
env = dict(os.environ, BASHDNS_SERVER_PORT=str(up_port), BASHDNS_0X20='0')
command = 'dns resolver-serve --listen 127.0.0.1 --port %d --upstream 127.0.0.1 --max-queries 2 --timeout 1500' % resolver_port
with tempfile.TemporaryFile() as err:
    proc = subprocess.Popen([sys.argv[1], '--noprofile', '--norc', '-c', command],
                            env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=err)
    try:
        deadline = time.monotonic() + 5
        while True:
            expected = '0100007F:%04X' % resolver_port
            with open('/proc/net/udp', encoding='ascii') as status:
                ready = any(len(fields) > 3 and fields[1] == expected and fields[3] == '07'
                            for fields in (line.split() for line in status))
            if ready:
                break
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('resolver failed to start')
            time.sleep(0.05)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3)
        try:
            for qid in (0x1234, 0x1235):
                query = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0) + question
                client.sendto(query, ('127.0.0.1', resolver_port))
                reply, _ = client.recvfrom(4096)
                if len(reply) < 12 or reply[:2] != query[:2] or reply[3] & 15 != 2:
                    raise RuntimeError('bad SERVFAIL response')
        finally:
            client.close()
        if proc.wait(timeout=4) != 0:
            raise RuntimeError('resolver failed')
        if len(seen) != 2:
            raise RuntimeError('expected two upstream queries; got %d' % len(seen))
        print('servfail-upstream-queries=2')
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=4)
        stop.set()
        thread.join(timeout=2)
        up.close()
