#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Single-connection loopback TCP recorder for disposable parity-VM fixtures.

Usage: mig-w3-tcp-record.py LISTEN_PORT UPSTREAM_PORT OUTPUT

Listens on 127.0.0.1:LISTEN_PORT, relays exactly one client connection to
127.0.0.1:UPSTREAM_PORT, records the first 4096 bytes of each direction as
base64 in OUTPUT (JSON) and exits. It uses select() on plain sockets, makes no
other connection and gives up after 10 seconds.
"""
import base64
import json
import os
from pathlib import Path
import select
import socket
import sys
import time
import uuid


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def main(listen_port, upstream_port, output):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', listen_port))
    server.listen(1)
    Path(output + '.ready').write_text('ready\n')
    deadline = time.monotonic() + 10
    record = {'client_to_server': b'', 'server_to_client': b'', 'error': None}
    client = None
    upstream = None
    try:
        while client is None:
            ready, _, _ = select.select([server], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                raise TimeoutError('no client connection')
            client, _ = server.accept()
        upstream = socket.create_connection(('127.0.0.1', upstream_port), timeout=5)
        pair = {client: upstream, upstream: client}
        names = {client: 'client_to_server', upstream: 'server_to_client'}
        open_ends = set(pair)
        while open_ends and time.monotonic() < deadline:
            ready, _, _ = select.select(list(open_ends), [], [], 0.1)
            for sock in ready:
                data = sock.recv(65536)
                if not data:
                    open_ends.discard(sock)
                    try:
                        pair[sock].shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                if len(record[names[sock]]) < 4096:
                    record[names[sock]] += data[:4096 - len(record[names[sock]])]
                pair[sock].sendall(data)
    except (OSError, TimeoutError) as exc:
        record['error'] = repr(exc)
    finally:
        for sock in (client, upstream, server):
            if sock is not None:
                sock.close()
        out = {k: (base64.b64encode(v).decode() if isinstance(v, bytes) else v) for k, v in record.items()}
        Path(output).write_text(json.dumps(out) + '\n')
    return 0


if __name__ == '__main__':
    require_guest()
    sys.exit(main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]))
