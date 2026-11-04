#!/usr/bin/env python3
"""VM-only regression: one bounded server replies to v3 and v4 clients."""
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    cmd = (f'ntp serve -S 127.0.0.1:{port} --stratum 3 '
           '--refid TEST --leap 2 --max 2')
    proc = subprocess.Popen([sys.argv[1], '--noprofile', '--norc', '-c', cmd],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 4
        address = '0100007F:%04X' % port
        while True:
            if proc.poll() is not None:
                raise AssertionError('server exited before binding')
            inodes = set()
            for fd in Path(f'/proc/{proc.pid}/fd').iterdir():
                try:
                    match = re.fullmatch(r'socket:\[(\d+)\]', os.readlink(fd))
                    if match:
                        inodes.add(match.group(1))
                except FileNotFoundError:
                    pass
            rows = Path(f'/proc/{proc.pid}/net/udp').read_text().splitlines()[1:]
            if any(len(fields) > 9 and fields[1] == address and fields[9] in inodes
                   for fields in map(str.split, rows)):
                break
            if time.monotonic() >= deadline:
                raise AssertionError('server did not bind')
            time.sleep(.02)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0))
            peer.settimeout(3)
            for version, stamp in ((3, bytes.fromhex('e123456789abcdef')),
                                   (4, bytes.fromhex('e123456789abcdee'))):
                req = bytearray(48)
                # Request LI=3 verifies that response LI comes from the config.
                req[0] = 0xc0 | (version << 3) | 3
                req[2] = 6
                req[40:48] = stamp
                peer.sendto(req, ('127.0.0.1', port))
                reply, source = peer.recvfrom(4096)
                assert len(reply) == 48 and source == ('127.0.0.1', port)
                assert reply[0] == (2 << 6) | (version << 3) | 4
                assert reply[1] == 3 and reply[2] == 6 and reply[12:16] == b'TEST'
                assert reply[24:32] == stamp
                assert reply[32:40] != bytes(8) and reply[40:48] != bytes(8)
                assert reply[32:40] <= reply[40:48]
                if version == 3:
                    assert proc.poll() is None, 'server exited before second reply'
        out, err = proc.communicate(timeout=3)
        assert proc.returncode == 0, (proc.returncode, out, err)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    print('ntp-serve-mixed-versions=ok')


if __name__ == '__main__':
    main()
