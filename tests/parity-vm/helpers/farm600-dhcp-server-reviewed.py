#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only offline DHCP response observations for the farm600 contract."""
import binascii
import json
import os
from pathlib import Path
import re
import subprocess
import sys

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
HELPER = '/opt/bashos-parity/harness/helpers/farm600-dhcp-server-reviewed.py'
IDENTITY = '/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py'
PREFIX = 'farm600-dhcp-server-'
MAC = bytes.fromhex('020000000011')
XID = bytes.fromhex('183a5b7c')
COOKIE = bytes.fromhex('63825363')


def guard():
    subprocess.run(['/usr/bin/python3', IDENTITY], check=True, timeout=5)
    if os.getuid() != 2000 or os.geteuid() != 2000 or Path.cwd() != CASE or os.environ.get('HOME') != str(HOME):
        raise RuntimeError('guest scratch identity failed')


def write(name, data):
    (HOME / (PREFIX + name)).write_bytes(data)


def option(code, data):
    if not (0 < code < 255 and len(data) < 256):
        raise ValueError('invalid option')
    return bytes((code, len(data))) + data


def request(giaddr, vendor=None, kind=1):
    p = bytearray(240)
    p[0:4] = bytes((1, 1, 6, 0))
    p[4:8] = XID
    p[24:28] = giaddr
    p[28:34] = MAC
    p[236:240] = COOKIE
    p += option(53, bytes((kind,))) + option(12, b'fixture-host')
    if vendor is not None:
        p += option(60, vendor)
    if giaddr != bytes(4):
        p += option(82, bytes.fromhex('01047261632d020400ff1020'))
    return bytes(p + b'\xff')


def options(raw):
    found = {}
    i = 0
    while i < len(raw):
        code = raw[i]
        i += 1
        if code == 0:
            continue
        if code == 255:
            if any(raw[i:]):
                raise ValueError('nonzero bytes after option terminator')
            return found
        if i == len(raw):
            raise ValueError('truncated option length')
        n = raw[i]
        i += 1
        if i + n > len(raw) or code in found:
            raise ValueError('truncated or duplicate option')
        found[code] = raw[i:i+n]
        i += n
    raise ValueError('missing option terminator')


def config(mode):
    if mode in ('relay-a', 'relay-b'):
        return ('server_id 192.0.2.1\nlease 3600\n'
                'subnet 192.0.2.0 255.255.255.0 {\npool 192.0.2.100 192.0.2.101\ngateway 192.0.2.254\n}\n'
                'subnet 198.51.100.0 255.255.255.0 {\npool 198.51.100.50 198.51.100.51\ngateway 198.51.100.254\n}\n')
    base = ('pool 192.0.2.100 192.0.2.100\nnetmask 255.255.255.0\n'
            'server_id 192.0.2.1\nlease 3600\n')
    if mode.startswith('pxe-'):
        return (base + 'next-server 192.0.2.7\ntftp-server boot.example\nbootfile image.efi\n'
                'pxe-vendor-match on\npxe-discovery-control 8\n'
                'pxe-boot-server 7 192.0.2.8\npxe-menu-item 7 Boot\npxe-menu-prompt 3 Select\n')
    if mode == 'hook-commit':
        return base + 'lease-exec /usr/bin/python3 ' + HELPER + ' hook ok\n'
    if mode == 'hook-failure':
        return base + 'lease-exec /usr/bin/python3 ' + HELPER + ' hook fail\n'
    if mode == 'hook-missing':
        return base + 'lease-exec /tmp/parity-case/farm600-absent-hook\n'
    raise ValueError('unknown mode')


def save_hook():
    guard()
    keys = ('ACTION', 'MAC', 'IP', 'HOSTNAME', 'LEASE_TIME')
    row = {k: os.environ.get('BASHDHCPD_' + k) for k in keys}
    write('hook.json', (json.dumps(row, sort_keys=True) + '\n').encode())


def setup(mode):
    guard()
    if mode not in ('relay-a', 'relay-b', 'pxe-match', 'pxe-other',
                    'hook-commit', 'hook-failure', 'hook-missing'):
        raise RuntimeError('invalid mode')
    if (CASE / 'leases').exists() or (CASE / 'leases.tmp').exists():
        raise RuntimeError('lease database is not fresh')
    if options(b'\x35\x01\x02\xff\x00') != {53: b'\x02'}:
        raise RuntimeError('option parser positive control failed')
    for bad in (b'', b'\x35', b'\x35\x02\x01', b'\x35\x01\x02\x35\x01\x02\xff', b'\xff\x01'):
        try:
            options(bad)
        except ValueError:
            continue
        raise RuntimeError('option parser negative control failed')
    giaddr = {'relay-a': bytes.fromhex('c0000209'),
              'relay-b': bytes.fromhex('c6336409')}.get(mode, bytes(4))
    vendor = {'pxe-match': b'PXEClient:Arch:00000', 'pxe-other': b'OtherClient'}.get(mode)
    kind = 3 if mode.startswith('hook-') else 1
    pkt = request(giaddr, vendor, kind)
    decoded = options(pkt[240:])
    if (len(pkt) > 1500 or pkt[:4] != b'\x01\x01\x06\x00' or pkt[4:8] != XID or
        pkt[24:28] != giaddr or pkt[28:34] != MAC or pkt[236:240] != COOKIE or
        decoded.get(53) != bytes((kind,)) or decoded.get(12) != b'fixture-host' or
        (vendor is not None and decoded.get(60) != vendor) or
        (giaddr != bytes(4) and decoded.get(82) != bytes.fromhex('01047261632d020400ff1020'))):
        raise RuntimeError('request preflight failed')
    (CASE / 'request.hex').write_text(pkt.hex() + '\n', encoding='ascii')
    (CASE / 'server.conf').write_text(config(mode), encoding='ascii')
    if mode.startswith('hook-'):
        expected = {'ACTION': 'control', 'MAC': 'control', 'IP': 'control',
                    'HOSTNAME': 'control', 'LEASE_TIME': 'control'}
        env = dict(os.environ, **{'BASHDHCPD_' + k: v for k, v in expected.items()})
        missing = CASE / 'farm600-absent-hook'
        if mode == 'hook-missing' and (missing.exists() or missing.is_symlink()):
            raise RuntimeError('missing hook control path exists')
        shellcmd = str(missing) if mode == 'hook-missing' else '/usr/bin/python3 ' + HELPER + ' hook ' + ('fail' if mode == 'hook-failure' else 'ok')
        proc = subprocess.run(['/bin/sh', '-c', shellcmd], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        expected_rc = 127 if mode == 'hook-missing' else 23 if mode == 'hook-failure' else 0
        hook = HOME / (PREFIX + 'hook.json')
        control_hook = json.loads(hook.read_text()) if hook.is_file() else None
        if proc.returncode != expected_rc or (mode != 'hook-missing' and control_hook != expected):
            raise RuntimeError('hook control failed')
        if hook.exists():
            hook.unlink()
        write('hook-control.json', (json.dumps({'command': shellcmd, 'status': proc.returncode,
              'hook_environment': control_hook,
              'stdout_hex': proc.stdout.hex(), 'stderr_hex': proc.stderr.hex()}) + '\n').encode())
    control = {'mode': mode, 'request_hex': pkt.hex(), 'config': config(mode),
               'expected_giaddr_hex': giaddr.hex(), 'kind': kind, 'parser_control': 'ok'}
    write('control.json', (json.dumps(control, sort_keys=True) + '\n').encode())


def verify(mode, status):
    guard()
    control = json.loads((HOME / (PREFIX + 'control.json')).read_text())
    if control['mode'] != mode or control['config'] != config(mode) or control['parser_control'] != 'ok':
        raise RuntimeError('control mismatch')
    out = (HOME / (PREFIX + 'reply.out')).read_bytes()
    err = (HOME / (PREFIX + 'reply.err')).read_bytes()
    write('candidate-status.json', (json.dumps({'status': int(status), 'out_bytes': len(out),
          'err_bytes': len(err)}) + '\n').encode())
    if int(status) != 0 or len(out) > 4096 or len(err) > 4096:
        raise ValueError('candidate status or capture length')
    if mode != 'hook-missing' and err:
        raise ValueError('unexpected candidate stderr')
    if not re.fullmatch(rb'[0-9A-Fa-f]+\n', out):
        raise ValueError('candidate did not emit a complete hexadecimal packet')
    try:
        packet = binascii.unhexlify(out[:-1])
    except binascii.Error as exc:
        raise ValueError('bad hexadecimal packet') from exc
    if len(packet) < 241 or len(packet) > 1500 or packet[:3] != b'\x02\x01\x06' or packet[4:8] != XID or packet[28:34] != MAC or packet[236:240] != COOKIE:
        raise ValueError('invalid BOOTP reply identity')
    opts = options(packet[240:])
    expected_type = b'\x05' if mode.startswith('hook-') else b'\x02'
    if opts.get(53) != expected_type or opts.get(54) != bytes.fromhex('c0000201'):
        raise ValueError('wrong message or server ID')
    if mode.startswith('relay-'):
        expected = {'relay-a': (bytes.fromhex('c0000264'), bytes.fromhex('c00002fe')),
                    'relay-b': (bytes.fromhex('c6336432'), bytes.fromhex('c63364fe'))}[mode]
        if (packet[16:20] != expected[0] or packet[24:28].hex() != control['expected_giaddr_hex'] or
            opts.get(1) != bytes.fromhex('ffffff00') or opts.get(3) != expected[1] or
            opts.get(82) != bytes.fromhex('01047261632d020400ff1020')):
            raise ValueError('relay subnet, gateway, mask or option 82 differs')
    elif mode.startswith('pxe-'):
        if packet[16:20] != bytes.fromhex('c0000264'):
            raise ValueError('unexpected pool address')
        if mode == 'pxe-match':
            if (packet[20:24] != bytes.fromhex('c0000207') or opts.get(66) != b'boot.example' or
                opts.get(67) != b'image.efi' or packet[108:236].split(b'\0', 1)[0] != b'image.efi'):
                raise ValueError('PXE server or bootfile differs')
            subs = options(opts.get(43, b''))
            # PXE boot-menu entries carry type, label length, then label.
            expected = {6: b'\x08', 8: bytes.fromhex('000701c0000208'),
                        9: bytes.fromhex('000704') + b'Boot', 10: b'\x03Select'}
            if subs != expected:
                raise ValueError('PXE option 43 suboptions differ')
        elif any(k in opts for k in (43, 66, 67)) or any(packet[108:236]):
            raise ValueError('PXE options emitted for nonmatching vendor')
    else:
        if packet[16:20] != bytes.fromhex('c0000264'):
            raise ValueError('wrong ACK address')
        if mode != 'hook-missing':
            data = json.loads((HOME / (PREFIX + 'hook.json')).read_text())
            expected = {'ACTION': 'commit', 'MAC': '02:00:00:00:00:11', 'IP': '192.0.2.100',
                        'HOSTNAME': 'fixture-host', 'LEASE_TIME': '3600'}
            if data != expected:
                raise ValueError('hook environment differs')
        elif (HOME / (PREFIX + 'hook.json')).exists():
            raise ValueError('unexpected hook artifact')
    print('farm600-dhcp-server-' + mode + '-verified')


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == 'setup':
            setup(sys.argv[2])
        elif len(sys.argv) == 4 and sys.argv[1] == 'verify':
            verify(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 3 and sys.argv[1] == 'hook' and sys.argv[2] in ('ok', 'fail'):
            save_hook()
            sys.exit(23 if sys.argv[2] == 'fail' else 0)
        else:
            raise RuntimeError('invalid invocation')
    except Exception as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        sys.exit(1)
