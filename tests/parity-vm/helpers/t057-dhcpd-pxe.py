#!/usr/bin/python3
"""Guest-only verifier for the PXE vendor gate and structured option 43."""
from pathlib import Path
import sys


def options(data):
    result = {}
    i = 0
    while i < len(data):
        code = data[i]
        i += 1
        if code == 0:
            continue
        if code == 255:
            return result
        if i >= len(data):
            raise ValueError('missing option length')
        n = data[i]
        i += 1
        if i + n > len(data) or code in result:
            raise ValueError('truncated or duplicate option')
        result[code] = data[i:i+n]
        i += n
    raise ValueError('missing option terminator')


def check(mode, vendor):
    packet = bytes.fromhex(Path('reply-%s-%s.hex' % (mode, vendor)).read_text().strip())
    if len(packet) != 548 or packet[:3] != b'\x02\x01\x06' or packet[236:240] != bytes.fromhex('63825363'):
        raise ValueError('bad BOOTP reply')
    opts = options(packet[240:])
    if opts.get(53) != b'\x02' or opts.get(54) != bytes.fromhex('c0000201'):
        raise ValueError('bad DHCP identity')
    enabled = mode == 'off' or vendor == 'pxe'
    if packet[20:24] != bytes.fromhex('c0000263' if enabled else 'c0000201'):
        raise ValueError('incorrect siaddr')
    if enabled:
        if opts.get(66) != b'tftp.lab.test' or opts.get(67) != b'pxelinux.0':
            raise ValueError('bad boot options')
        if packet[108:236].split(b'\0', 1)[0] != b'pxelinux.0':
            raise ValueError('bad BOOTP file')
        expected = {6: b'\x08', 8: bytes.fromhex('000701c0000208'),
                    9: bytes.fromhex('000709') + b'Boot Menu', 10: b'\x03Select'}
        if options(opts.get(43, b'')) != expected:
            raise ValueError('bad structured PXE suboptions')
    elif any(code in opts for code in (43, 66, 67)) or any(packet[108:236]):
        raise ValueError('PXE fields leaked through vendor gate')


if __name__ == '__main__':
    for mode in ('on', 'off'):
        for vendor in ('none', 'msft', 'pxe'):
            check(mode, vendor)
    print('t057-pxe-gating-and-menu-verified')
