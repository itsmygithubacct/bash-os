#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Independent RFC 8415 / RFC 5007 codec, report helper and namespace setup shared by the w2 DHCPv6 fixtures."""
import json
import os
import socket
import struct
import subprocess
import time

HOME = os.environ.get('HOME', '/tmp/parity-home')
LOG = os.path.join(HOME, 'w2-peer6.json')
IP = '/usr/bin/ip'
CLIENT_MAC = '02:00:00:00:0a:01'
PEER_MAC = '02:00:00:00:0a:02'
CLIENT_LL = 'fe80::a01'
PEER_LL = 'fe80::a02'
MCAST = 'ff02::1:2'
CLIENT_DUID = bytes.fromhex('00030001' + CLIENT_MAC.replace(':', ''))
SERVER_DUID = bytes.fromhex('00030001' + 'aabbccddeeff')
OTHER_DUID = bytes.fromhex('00030001' + '112233445566')
T = {1: 'SOLICIT', 2: 'ADVERTISE', 3: 'REQUEST', 4: 'CONFIRM', 5: 'RENEW', 6: 'REBIND', 7: 'REPLY', 8: 'RELEASE',
     9: 'DECLINE', 11: 'INFORMATION-REQUEST'}
NAME = {v: k for k, v in T.items()}


def v6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def opt_raw(code, data):
    return struct.pack('!HH', code, len(data)) + data


def encode_domains(names):
    out = b''
    for name in names:
        for label in name.split('.'):
            out += bytes([len(label)]) + label.encode()
        out += b'\0'
    return out


def decode_domains(data):
    names, p, cur = [], 0, []
    while p < len(data):
        n = data[p]
        p += 1
        if n == 0:
            names.append('.'.join(cur))
            cur = []
        else:
            cur.append(data[p:p + n].decode())
            p += n
    return names


def parse(msg):
    """Top-level message -> {'type', 'xid', 'opts': [(code, bytes)]}; IA_NA/IAADDR/IA_PD helpers below."""
    if len(msg) < 4:
        return None
    opts, p = [], 4
    while p + 4 <= len(msg):
        code, n = struct.unpack('!HH', msg[p:p + 4])
        opts.append((code, bytes(msg[p + 4:p + 4 + n])))
        p += 4 + n
    return {'type': msg[0], 'xid': int.from_bytes(msg[1:4], 'big'), 'opts': opts}


def get(m, code):
    for c, v in m['opts']:
        if c == code:
            return v
    return None


def all_codes(m):
    return [c for c, _ in m['opts']]


def ia_na(data):
    iaid, t1, t2 = struct.unpack('!III', data[:12])
    subs, p = [], 12
    while p + 4 <= len(data):
        code, n = struct.unpack('!HH', data[p:p + 4])
        subs.append((code, data[p + 4:p + 4 + n]))
        p += 4 + n
    return {'iaid': iaid, 't1': t1, 't2': t2, 'subs': subs}


def iaaddr(data):
    return {'addr': socket.inet_ntop(socket.AF_INET6, data[:16]), 'pref': struct.unpack('!I', data[16:20])[0],
            'valid': struct.unpack('!I', data[20:24])[0]}


def build(mtype, xid, options):
    return bytes([mtype]) + xid.to_bytes(3, 'big') + b''.join(opt_raw(c, v) for c, v in options)


def build_ia_na(iaid, t1, t2, addr=None, pref=0, valid=0):
    body = struct.pack('!III', iaid, t1, t2)
    if addr:
        body += opt_raw(5, v6(addr) + struct.pack('!II', pref, valid))
    return opt_raw(3, body)


def save(entries):
    tmp = LOG + '.tmp'
    with open(tmp, 'w') as handle:
        json.dump(entries, handle)
    os.replace(tmp, LOG)


def sh(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def netns_peer_setup(sync):
    """Fresh netns, announce pid, wait for veth1, give it a link-local address, return the sync fd."""
    os.unshare(os.CLONE_NEWNET)
    fd = os.open(sync, os.O_WRONLY)
    os.write(fd, ('pid=%d\n' % os.getpid()).encode())
    deadline = time.monotonic() + 15
    while True:
        try:
            socket.if_nametoindex('veth1')
            break
        except OSError:
            if time.monotonic() > deadline:
                raise RuntimeError('veth1 never arrived')
            time.sleep(0.02)
    sh(IP, 'link', 'set', 'lo', 'up')
    sh(IP, 'link', 'set', 'veth1', 'addrgenmode', 'none')
    sh(IP, 'addr', 'add', PEER_LL + '/64', 'dev', 'veth1', 'nodad')
    sh(IP, 'link', 'set', 'veth1', 'up')
    return fd



class Report:
    def __init__(self):
        self.lines = []

    def check(self, name, cond, detail=''):
        self.lines.append(name + (' ok' if cond else ' FAIL ' + str(detail)))

    def emit(self, name):
        failed = [line for line in self.lines if ' FAIL ' in line]
        for line in failed:
            print(line)
        print('verified %s failed=%d' % (name, len(failed)))


def load_log():
    with open(LOG) as handle:
        return json.load(handle)


def parse_kv(path):
    kv = {}
    with open(path) as handle:
        for line in handle:
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                kv[k] = v
    return kv


def inbound(log, kind):
    out = []
    for e in log:
        if e.get('dir') == 'in':
            m = parse(bytes.fromhex(e['payload']))
            if m and T.get(m['type']) == kind:
                e = dict(e)
                e['msg'] = m
                out.append(e)
    return out


def oro_codes(m):
    v = get(m, 6) or b''
    return [struct.unpack('!H', v[i:i + 2])[0] for i in range(0, len(v), 2)]
