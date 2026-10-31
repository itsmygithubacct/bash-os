#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated loopback referral observation; execute only in the parity guest."""
import base64
import json
import os
from pathlib import Path
import select
import signal
import stat
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

HOME = Path('/tmp/parity-home')
HERE = '/opt/bashos-parity/harness/helpers/farm600-dns-service-reviewed-recursion.py'
CANDIDATE = '/opt/bashos-parity/candidate'
DIG = '/usr/bin/dig'
NAME = 'www.deleg.test.'
NS = 'ns.deleg.test.'
ROOT = '127.0.0.2'
AUTH = '127.0.0.3'
ANSWER = '192.0.2.73'
SO_TIMESTAMPNS = getattr(socket, 'SO_TIMESTAMPNS', 35)


def clock_pair():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return {'monotonic_before_ns': before, 'realtime_ns': realtime, 'monotonic_after_ns': after}


def save(name, data):
    (HOME / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def identity(stage, outer_proof=None):
    if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME):
        raise RuntimeError('guest scratch mismatch')
    def bounded_proc(path):
        with open(path, 'rb') as stream:
            raw = stream.read(513)
        if not raw or len(raw) > 512: raise RuntimeError('identity map or overflow value missing or too long')
        return raw.decode('ascii')
    uid_map_raw = bounded_proc('/proc/self/uid_map')
    gid_map_raw = bounded_proc('/proc/self/gid_map')
    overflow_uid_raw = bounded_proc('/proc/sys/kernel/overflowuid')
    overflow_gid_raw = bounded_proc('/proc/sys/kernel/overflowgid')
    if stage == 'outer':
        if (os.getuid() != 2000 or os.geteuid() != 2000 or
                os.getgid() != 2000 or os.getegid() != 2000):
            raise RuntimeError('outer uid/gid mismatch')
        expected_uid = expected_gid = 0
    elif stage == 'inner':
        if (os.getuid() != 0 or os.geteuid() != 0 or os.getgid() != 0 or os.getegid() != 0 or
                uid_map_raw.split() != ['0', '2000', '1'] or
                gid_map_raw.split() != ['0', '2000', '1']):
            raise RuntimeError('mapped uid/gid mismatch')
        expected_uid = int(overflow_uid_raw.strip())
        expected_gid = int(overflow_gid_raw.strip())
        if not isinstance(outer_proof, dict):
            raise RuntimeError('missing outer identity proof')
    else:
        raise RuntimeError('unknown identity stage')
    entries = {}
    for directory, filename in (('/etc', 'bashos-parity-vm'), ('/run', 'bashos-parity-vm-identity')):
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            di = os.fstat(dfd)
            if (not stat.S_ISDIR(di.st_mode) or di.st_uid != expected_uid or di.st_gid != expected_gid
                    or stat.S_IMODE(di.st_mode) & 0o022):
                raise RuntimeError('identity directory not protected')
            fd = os.open(filename, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or before.st_gid != expected_gid
                        or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o444 or before.st_size != 37):
                    raise RuntimeError('identity file not protected')
                raw = os.read(fd, 38)
                after = os.fstat(fd)
                entry = os.stat(filename, dir_fd=dfd, follow_symlinks=False)
                def fingerprint(info):
                    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                            info.st_size, info.st_mtime_ns, info.st_ctime_ns]
                if fingerprint(before) != fingerprint(after) or fingerprint(after) != fingerprint(entry):
                    raise RuntimeError('identity file changed during read')
            finally:
                os.close(fd)
            if len(raw) != 37 or raw[-1:] != b'\n': raise RuntimeError('invalid identity bytes')
            value = raw[:-1].decode('ascii')
            if str(uuid.UUID(value)) != value: raise RuntimeError('noncanonical UUID')
            entries[directory] = {'uuid': value, 'directory': [di.st_dev, di.st_ino, di.st_mode],
                                  'file': fingerprint(after), 'directory_uid': di.st_uid, 'directory_gid': di.st_gid,
                                  'owner_uid': after.st_uid, 'owner_gid': after.st_gid}
        finally:
            os.close(dfd)
    if entries['/etc']['uuid'] != entries['/run']['uuid']:
        raise RuntimeError('marker and controller attestation mismatch')
    proof = {'stage': stage, 'uid': os.getuid(), 'euid': os.geteuid(),
             'gid': os.getgid(), 'egid': os.getegid(), 'uid_map_raw': uid_map_raw,
             'gid_map_raw': gid_map_raw, 'overflowuid_raw': overflow_uid_raw,
             'overflowgid_raw': overflow_gid_raw, 'entries': entries}
    if stage == 'inner':
        for path in ('/etc', '/run'):
            for key in ('uuid', 'directory', 'file'):
                if entries[path][key] != outer_proof['entries'][path][key]:
                    raise RuntimeError('mapped identity differs from outer proof')
    return proof


def wire(name):
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.rstrip('.').split('.')) + b'\0'


def rr(name, typ, rdata):
    return wire(name) + struct.pack('!HHIH', typ, 1, 60, len(rdata)) + rdata


def question_name(packet, start):
    """Decode a bounded DNS name, retaining label bytes and compression semantics."""
    labels = []; pos = start; end = None; seen = set(); expanded = 1
    while True:
        if pos in seen or pos >= len(packet): raise ValueError('invalid DNS name')
        seen.add(pos); size = packet[pos]
        if size & 0xc0 == 0xc0:
            if pos + 1 >= len(packet): raise ValueError('truncated DNS pointer')
            if end is None: end = pos + 2
            pos = ((size & 0x3f) << 8) | packet[pos + 1]
            continue
        if size & 0xc0 or size > 63: raise ValueError('invalid DNS label')
        pos += 1
        if size == 0: return labels, end if end is not None else pos
        if pos + size > len(packet): raise ValueError('truncated DNS label')
        expanded += size + 1
        if expanded > 255: raise ValueError('DNS name exceeds wire limit')
        labels.append(packet[pos:pos + size]); pos += size


def classify_question(packet):
    """Separate supported questions, valid auxiliaries and uncertain DNS forms."""
    if len(packet) < 12 or len(packet) > 4096:
        return {'kind': 'malformed', 'reason': 'DNS header or length'}
    _, flags, qd, an, ns, ar = struct.unpack_from('!HHHHHH', packet)
    # Other opcodes or question counts are outside this peer's semantics, not product failures.
    if flags & 0x8000 or flags & 0x7800 or qd != 1 or an + ns + ar > 64:
        return {'kind': 'unsupported', 'reason': 'DNS operation or question count'}
    try:
        labels, pos = question_name(packet, 12)
        if pos + 4 > len(packet): raise ValueError('truncated question type/class')
        typ, cls = struct.unpack_from('!HH', packet, pos); pos += 4
        for _ in range(an + ns + ar):
            _, pos = question_name(packet, pos)
            if pos + 10 > len(packet): raise ValueError('truncated resource record')
            size = struct.unpack_from('!H', packet, pos + 8)[0]; pos += 10
            if pos + size > len(packet): raise ValueError('truncated resource data')
            pos += size
        if pos != len(packet):
            return {'kind': 'unsupported', 'reason': 'uninterpreted trailing DNS bytes'}
        raw_name = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
        normalized = raw_name + struct.pack('!HH', typ, cls)
        expected = [part.encode('ascii') for part in NAME.rstrip('.').split('.')]
        kind = 'fixture' if [x.lower() for x in labels] == expected and (typ, cls) == (1, 1) else 'auxiliary'
        return {'kind': kind, 'question_b64': base64.b64encode(normalized).decode(),
                'qtype': typ, 'qclass': cls, 'flags': flags}
    except (ValueError, IndexError, struct.error) as exc:
        return {'kind': 'malformed', 'reason': str(exc)}


def response(packet, role):
    question = classify_question(packet)
    if question['kind'] not in ('fixture', 'auxiliary'):
        return question, None
    question_wire = base64.b64decode(question['question_b64'], validate=True)
    if question['kind'] == 'auxiliary':
        # Explicitly refuse unsupported auxiliary lookup; never manufacture a DNS answer.
        header = packet[:2] + struct.pack('!HHHHH', 0x8005 | (question['flags'] & 0x0100), 1, 0, 0, 0)
        return question, header + question_wire
    if role == 'root':
        records = rr('deleg.test.', 2, wire(NS)) + rr(NS, 1, socket.inet_aton(AUTH))
        counts = (0, 1, 1); flags = 0x8000
    else:
        records = rr(NAME, 1, socket.inet_aton(ANSWER))
        counts = (1, 0, 0); flags = 0x8400
    header = packet[:2] + struct.pack('!HHHHH', flags, 1, *counts)
    return question, header + question_wire + records



def decode_name(packet, start):
    labels = []; pos = start; end = None; seen = set()
    while True:
        if pos in seen or pos >= len(packet): raise ValueError('invalid compression')
        seen.add(pos); n = packet[pos]
        if n & 0xc0 == 0xc0:
            if pos + 1 >= len(packet): raise ValueError('truncated pointer')
            if end is None: end = pos + 2
            pos = ((n & 0x3f) << 8) | packet[pos + 1]; continue
        if n & 0xc0 or n > 63: raise ValueError('invalid label')
        pos += 1
        if n == 0: return '.'.join(labels).lower() + '.', end if end is not None else pos
        if pos + n > len(packet): raise ValueError('truncated label')
        labels.append(packet[pos:pos+n].decode('ascii')); pos += n


def parse_answer(packet, query_id):
    if len(packet) < 12: raise ValueError('short DNS response')
    ident, flags, qd, an, ns, ar = struct.unpack_from('!HHHHHH', packet)
    if ident != query_id or not flags & 0x8000 or flags & 0x000f or qd != 1:
        raise ValueError('response header')
    name, pos = decode_name(packet, 12)
    if pos + 4 > len(packet) or name != NAME or struct.unpack_from('!HH', packet, pos) != (1, 1):
        raise ValueError('response question')
    pos += 4; answers = []
    for i in range(an + ns + ar):
        owner, pos = decode_name(packet, pos)
        if pos + 10 > len(packet): raise ValueError('short RR')
        typ, cls, ttl, size = struct.unpack_from('!HHIH', packet, pos); pos += 10
        if pos + size > len(packet): raise ValueError('short rdata')
        if i < an and typ == 1 and cls == 1 and size == 4:
            answers.append([owner, ttl, socket.inet_ntoa(packet[pos:pos+size])])
        pos += size
    if pos != len(packet): raise ValueError('trailing bytes')
    return answers


def client_query(port):
    ident = 0x5142
    query = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + wire(NAME) + struct.pack('!HH', 1, 1)
    result = {'query_b64': base64.b64encode(query).decode(), 'status': 'pending'}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        result['send_begin_clock'] = clock_pair()
        result['send_begin_monotonic_ns'] = time.monotonic_ns()
        result['destination'] = ['127.0.0.1', port]
        result['sent_bytes'] = sock.sendto(query, tuple(result['destination']))
        result['send_end_monotonic_ns'] = time.monotonic_ns()
        result['send_end_clock'] = clock_pair()
        if result['sent_bytes'] != len(query):
            raise RuntimeError('incomplete client send')
        result['local'] = list(sock.getsockname())
        result['fd'] = sock.fileno()
        result['fd_link'] = os.readlink('/proc/self/fd/%d' % sock.fileno())
        with open('/proc/self/net/udp', 'rb') as stream:
            table = stream.read(262145)
        if not table or len(table) > 262144: raise RuntimeError('client UDP evidence limit')
        result['udp_table_raw'] = table.decode('ascii')
        result['udp_table_bytes'] = len(table)
        matches = [line for line in result['udp_table_raw'].splitlines()[1:]
                   if len(line.split()) >= 10 and
                   int(line.split()[1].split(':')[1], 16) == result['local'][1] and
                   result['fd_link'] == 'socket:[%s]' % line.split()[9]]
        if len(matches) != 1: raise RuntimeError('client UDP ownership ambiguous')
        result['udp_row'] = matches[0]
        result['socket_observed_monotonic_ns'] = time.monotonic_ns()
        try:
            raw, _, flags, peer = sock.recvmsg(4096)
            result['receive_monotonic_ns'] = time.monotonic_ns()
        except socket.timeout:
            result['timeout_monotonic_ns'] = time.monotonic_ns()
            result['status'] = 'timeout'; return result
    result.update({'status': 'response', 'source': list(peer), 'response_b64': base64.b64encode(raw).decode(),
                   'msg_flags': flags, 'truncated': bool(flags & socket.MSG_TRUNC), 'received_bytes': len(raw)})
    if result['truncated']:
        result['status'] = 'truncated'; return result
    try: result['answers'] = parse_answer(raw, ident)
    except (ValueError, UnicodeError, struct.error) as exc: result['parse_error'] = repr(exc)
    return result


def referral_flow(events):
    """Identify the fixture path without treating auxiliary questions as failures."""
    root_seen = False
    followed = False
    for event in events:
        role = event.get('role')
        if role not in ('root', 'authoritative') or event.get('truncated') is not False:
            return False
        if event.get('question_kind') != 'fixture':
            continue
        if 'query_error' in event or 'response_b64' not in event:
            return False
        if role == 'root':
            root_seen = True
        elif root_seen:
            followed = True
    return followed


def referral_assessment(events, client_ok):
    """Describe observed peer ordering only; never infer candidate causality."""
    if referral_flow(events) and client_ok:
        return 'ordered_observation_only'
    if any(e.get('question_kind') in ('auxiliary', 'unsupported', 'malformed') for e in events):
        return 'inconclusive'
    return 'not_observed'


def event_phase(kernel_ns, offset_min, offset_max, ready_ns, send_begin_ns, send_end_ns):
    """Classify the bounded kernel ingress interval on the monotonic timeline."""
    if not all(type(x) is int for x in (kernel_ns, offset_min, offset_max, ready_ns, send_begin_ns, send_end_ns)):
        return 'ambiguous'
    if kernel_ns <= 0 or offset_min > offset_max or not ready_ns < send_begin_ns < send_end_ns:
        return 'ambiguous'
    lower, upper = kernel_ns - offset_max, kernel_ns - offset_min
    if upper < ready_ns: return 'pre_readiness'
    if ready_ns < lower and upper < send_begin_ns: return 'pre_query'
    if lower > send_end_ns: return 'post_query'
    return 'ambiguous'


def upstream_witness(pid, source):
    """Capture a later ownership snapshot; this does not attribute a datagram."""
    root = Path('/proc/%d' % pid)
    def read(path, limit):
        with open(path, 'rb') as stream: data = stream.read(limit + 1)
        if not data or len(data) > limit: raise RuntimeError('upstream proc evidence limit')
        return data.decode('ascii')
    def start(raw):
        end = raw.rfind(')'); fields = raw[end + 1:].split()
        if end < 0 or int(raw[:raw.find(' ')]) != pid or len(fields) < 20 or fields[0] in ('Z', 'X', 'x'):
            raise RuntimeError('upstream process not live')
        return fields[19]
    begin = time.monotonic_ns()
    first = read(root / 'stat', 4096); ticks = start(first)
    namespaces = {k: os.readlink(root / 'ns' / k) for k in ('net', 'user', 'pid')}
    fds = list((root / 'fd').iterdir())
    if len(fds) > 1024: raise RuntimeError('upstream descriptor limit')
    links = sorted(({'fd': int(p.name), 'link': os.readlink(p)} for p in fds), key=lambda x: x['fd'])
    if any(len(x['link']) > 4096 for x in links) or sum(len(x['link']) for x in links) > 65536:
        raise RuntimeError('upstream descriptor data limit')
    table = read(root / 'net' / 'udp', 262144)
    matches = []
    for row in table.splitlines()[1:]:
        fields = row.split()
        if len(fields) < 10: raise RuntimeError('invalid upstream UDP table')
        address, port = fields[1].split(':')
        local = socket.inet_ntoa(bytes.fromhex(address)[::-1])
        if int(port, 16) == source[1] and local in ('0.0.0.0', source[0]):
            for link in links:
                if link['link'] == 'socket:[%s]' % fields[9]:
                    matches.append({'fd': link['fd'], 'inode': fields[9], 'udp_row': row})
    last = read(root / 'stat', 4096)
    if start(last) != ticks or namespaces != {k: os.readlink(root / 'ns' / k) for k in namespaces}:
        raise RuntimeError('upstream process changed')
    if len(matches) != 1: raise RuntimeError('upstream socket ownership ambiguous')
    return {'pid': pid, 'start_ticks': ticks, 'stat_before_raw': first, 'stat_after_raw': last,
            'namespaces': namespaces, 'fd_links': links, 'fd_count': len(links), 'udp_table_raw': table,
            'udp_table_bytes': len(table.encode('ascii')), 'match': matches[0], 'source': list(source),
            'begin_monotonic_ns': begin, 'end_monotonic_ns': time.monotonic_ns()}


def peer_loop(sockets, events, errors, stop, context):
    try:
        while not stop.is_set():
            ready, _, _ = select.select(list(sockets), [], [], .1)
            for sock in ready:
                receive_begin = time.monotonic_ns()
                data, ancillary, flags, peer = sock.recvmsg(4096, socket.CMSG_SPACE(struct.calcsize('@ll')))
                receive_clock = clock_pair()
                if len(events) >= 32: raise RuntimeError('peer event limit')
                role = sockets[sock]
                event = {'role': role, 'source': list(peer), 'received_bytes': len(data),
                         'msg_flags': flags, 'truncated': bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)),
                         'query_b64': base64.b64encode(data).decode(), 'receive_begin_monotonic_ns': receive_begin,
                         'receive_clock': receive_clock, 'ancillary': [{'level': level, 'type': typ,
                             'data_b64': base64.b64encode(value).decode()} for level, typ, value in ancillary],
                         'send_status': 'not_sent'}
                timestamps = [value for level, typ, value in ancillary if level == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS]
                if len(timestamps) != 1 or len(timestamps[0]) != struct.calcsize('@ll'):
                    events.append(event); errors.append('missing or ambiguous kernel receive timestamp'); continue
                seconds, nanos = struct.unpack('@ll', timestamps[0])
                if seconds <= 0 or not 0 <= nanos < 1000000000:
                    events.append(event); errors.append('invalid kernel receive timestamp'); continue
                event['kernel_receive_realtime_ns'] = seconds * 1000000000 + nanos
                if context.get('candidate_phase'):
                    try: event['upstream_witness'] = upstream_witness(context['pid'], peer)
                    except Exception as exc: event['upstream_witness_error'] = repr(exc)
                if event['truncated']:
                    events.append(event); errors.append('peer datagram truncated'); continue
                question, reply = response(data, role)
                event['question_kind'] = question['kind']
                event['question'] = question
                if reply is None:
                    event['query_error'] = question['reason']
                    events.append(event); continue
                if question['kind'] == 'auxiliary':
                    event['auxiliary_handling'] = 'refused_unsupported'
                event['response_b64'] = base64.b64encode(reply).decode()
                events.append(event)
                event['send_begin_monotonic_ns'] = time.monotonic_ns()
                try:
                    event['sent_bytes'] = sock.sendto(reply, peer)
                    event['send_end_monotonic_ns'] = time.monotonic_ns()
                    event['send_status'] = 'sent' if event['sent_bytes'] == len(reply) else 'short'
                    if event['send_status'] != 'sent': raise RuntimeError('short peer send')
                except Exception as exc:
                    event['send_end_monotonic_ns'] = time.monotonic_ns()
                    event['send_status'] = 'error'; event['send_error'] = repr(exc)
                    raise
    except Exception as exc:
        errors.append(repr(exc))


def dig(addr, port, option, recurse=False):
    argv = [DIG, '@' + addr, '-p', str(port), '+time=2', '+tries=1', '+recurse' if recurse else '+norecurse',
            '+noedns', '+noall', *option, NAME, 'A']
    try:
        p = subprocess.run(argv, capture_output=True, timeout=5)
        status, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as exc:
        status, out, err = None, exc.stdout or b'', exc.stderr or b''
    if len(out) > 65536 or len(err) > 65536: raise RuntimeError('dig output limit')
    return {'argv': argv, 'status': status, 'stdout_b64': base64.b64encode(out).decode(),
            'stderr_b64': base64.b64encode(err).decode()}


def rows(result):
    data = base64.b64decode(result['stdout_b64'], validate=True).decode('ascii')
    return [line.split() for line in data.splitlines() if line.strip() and not line.startswith(';')]


def listening_witness(pid, port):
    """Retain bounded proc evidence for this process and its bound UDP socket."""
    def read_bounded(path, limit):
        with open(path, 'rb') as stream:
            data = stream.read(limit + 1)
        if not data or len(data) > limit:
            raise RuntimeError('missing or oversized readiness evidence: ' + str(path))
        return data

    def start_identity(raw):
        text = raw.decode('ascii')
        close = text.rfind(')')
        if close < 0 or int(text[:text.find(' ')]) != pid:
            raise RuntimeError('invalid candidate stat')
        fields = text[close + 1:].split()
        if len(fields) < 20 or fields[0] in ('Z', 'X', 'x'):
            raise RuntimeError('candidate is not live')
        return fields[19]

    try:
        started = time.monotonic_ns()
        root = Path('/proc/%d' % pid)
        stat_before = read_bounded(root / 'stat', 4096).decode('ascii')
        start = start_identity(stat_before.encode('ascii'))
        namespaces_before = {kind: os.readlink(root / 'ns' / kind) for kind in ('net', 'user', 'pid')}
        observer_namespaces = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ('net', 'user', 'pid')}
        if namespaces_before != observer_namespaces:
            raise RuntimeError('candidate namespace mismatch')
        exe_link = os.readlink(root / 'exe')
        exe_stat = os.stat(root / 'exe')
        expected_stat = os.stat(CANDIDATE)
        if (exe_stat.st_dev, exe_stat.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
            raise RuntimeError('candidate executable mismatch')
        cmdline = read_bounded(root / 'cmdline', 16384)
        paths = list((root / 'fd').iterdir())
        if len(paths) > 1024:
            raise RuntimeError('candidate descriptor limit')
        links = [{'fd': int(p.name), 'link': os.readlink(p)} for p in paths]
        if (any(len(item['link']) > 4096 for item in links) or
                sum(len(item['link']) for item in links) > 65536):
            raise RuntimeError('candidate descriptor link limit')
        links.sort(key=lambda item: item['fd'])
        table = read_bounded(root / 'net' / 'udp', 262144).decode('ascii')
        matches = []
        for line in table.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise RuntimeError('malformed UDP table')
            if fields[1] == '0100007F:%04X' % port:
                for item in links:
                    if item['link'] == 'socket:[%s]' % fields[9]:
                        matches.append({'fd': item['fd'], 'inode': fields[9], 'udp_row': line})
        stat_after = read_bounded(root / 'stat', 4096).decode('ascii')
        namespaces_after = {kind: os.readlink(root / 'ns' / kind) for kind in ('net', 'user', 'pid')}
        if start_identity(stat_after.encode('ascii')) != start or namespaces_after != namespaces_before:
            raise RuntimeError('candidate identity changed during readiness')
        if len(matches) > 1:
            raise RuntimeError('ambiguous candidate UDP ownership')
        if matches:
            return {'pid': pid, 'start_ticks': start, 'stat_before_raw': stat_before,
                    'stat_after_raw': stat_after, 'namespaces_before': namespaces_before,
                    'namespaces_after': namespaces_after, 'observer_namespaces': observer_namespaces,
                    'exe_link': exe_link, 'exe_dev': exe_stat.st_dev, 'exe_inode': exe_stat.st_ino,
                    'expected_exe_dev': expected_stat.st_dev, 'expected_exe_inode': expected_stat.st_ino,
                    'cmdline_b64': base64.b64encode(cmdline).decode(), 'cmdline_bytes': len(cmdline),
                    'fd_links': links, 'fd_count': len(links), 'udp_table_raw': table,
                    'udp_table_bytes': len(table.encode('ascii')), 'match': matches[0],
                    'expected_address': '127.0.0.1', 'expected_port': port,
                    'begin_monotonic_ns': started, 'end_monotonic_ns': time.monotonic_ns()}
    except (FileNotFoundError, ProcessLookupError):
        pass
    return None


def run_inner(mode, outer_net, outer_user, inner_identity):
    if mode != 'setup':
        raise RuntimeError('candidate observer requires reviewed attribution and containment witnesses')
    report = {'mode': mode, 'state': 'setup', 'controls': {}, 'peer_events': [], 'peer_errors': [],
              'identity_inner': inner_identity}
    name = 'recursion-' + mode + '.json'
    sockets = {}
    events, errors = report['peer_events'], report['peer_errors']
    stop = threading.Event(); thread = None; proc = None
    context = {'candidate_phase': False, 'pid': None}
    try:
        uid_map = Path('/proc/self/uid_map').read_text().split()
        net, user = os.readlink('/proc/self/ns/net'), os.readlink('/proc/self/ns/user')
        if os.getuid() != 0 or uid_map != ['0', '2000', '1'] or net == outer_net or user == outer_user:
            raise RuntimeError('namespace isolation precondition')
        report['namespace'] = {'net': net, 'user': user, 'outer_net': outer_net,
                               'outer_user': outer_user, 'uid_map': uid_map}
        link = subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], capture_output=True, timeout=5)
        report['loopback'] = {'status': link.returncode, 'stdout_b64': base64.b64encode(link.stdout).decode(),
                              'stderr_b64': base64.b64encode(link.stderr).decode()}
        if link.returncode: raise RuntimeError('loopback setup failed')
        if struct.calcsize('@ll') != 16: raise RuntimeError('unsupported kernel timestamp ABI')
        root = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sockets[root] = 'root'
        root.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        root.bind((ROOT, 0)); port = root.getsockname()[1]
        auth = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sockets[auth] = 'authoritative'
        auth.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        auth.bind((AUTH, port))
        report['timestamping'] = {'level': socket.SOL_SOCKET, 'option': SO_TIMESTAMPNS, 'timespec_size': 16,
                                  'enabled_roles': ['root', 'authoritative']}
        thread = threading.Thread(target=peer_loop, args=(sockets, events, errors, stop, context), daemon=True); thread.start()
        test_query = struct.pack('!HHHHHH', 0x5142, 0x0100, 1, 0, 0, 0) + wire(NAME) + struct.pack('!HH', 1, 1)
        test_kind, test_reply = response(test_query, 'authoritative')
        if test_kind['kind'] != 'fixture': raise RuntimeError('fixture question parser control failed')
        if parse_answer(test_reply, 0x5142) != [[NAME, 60, ANSWER]]:
            raise RuntimeError('answer parser positive control failed')
        for invalid in (test_reply[:-1], test_reply[:2] + b'\x00\x00' + test_reply[4:]):
            try: parse_answer(invalid, 0x5142)
            except (ValueError, UnicodeError, struct.error): continue
            raise RuntimeError('answer parser accepted negative control')
        negative_queries = (test_query[:-1], test_query[:12] + wire('wrong.deleg.test.') + struct.pack('!HH', 1, 1),
                            test_query[:-4] + struct.pack('!HH', 28, 1),
                            test_query[:-4] + struct.pack('!HH', 1, 3))
        if [classify_question(q)['kind'] for q in negative_queries] != ['malformed', 'auxiliary', 'auxiliary', 'auxiliary']:
            raise RuntimeError('request classifier control failed')
        def sample(role):
            return {'role': role, 'truncated': False, 'question_kind': 'fixture', 'response_b64': 'AA=='}
        flow_valid = [[sample('root'), sample('root'), sample('authoritative')],
                      [sample('root'), sample('authoritative'), sample('authoritative')]]
        flow_invalid = [[sample('root')], [sample('authoritative')],
                        [sample('root'), {'role': 'authoritative', 'truncated': False, 'question_kind': 'fixture', 'query_error': 'bad'}],
                        [sample('root'), {'role': 'authoritative', 'truncated': True, 'response_b64': 'AA=='}]]
        if not all(referral_flow(events) for events in flow_valid) or any(referral_flow(events) for events in flow_invalid):
            raise RuntimeError('referral-flow classifier control failed')
        aux_query = negative_queries[2]
        aux_kind, aux_reply = response(aux_query, 'root')
        if (aux_kind['kind'] != 'auxiliary' or aux_reply is None or
                struct.unpack_from('!H', aux_reply, 2)[0] & 15 != 5):
            raise RuntimeError('auxiliary refusal control failed')
        unsupported_query = test_query[:2] + b'\x09\x00' + test_query[4:]
        unsupported_kind, unsupported_reply = response(unsupported_query, 'root')
        if unsupported_kind['kind'] != 'unsupported' or unsupported_reply is not None:
            raise RuntimeError('unsupported query control failed')
        aux_event = {'role': 'root', 'truncated': False, 'question_kind': 'auxiliary',
                     'query_b64': base64.b64encode(aux_query).decode(),
                     'response_b64': base64.b64encode(aux_reply).decode(), 'send_status': 'sent',
                     'sent_bytes': len(aux_reply), 'auxiliary_handling': 'refused_unsupported'}
        unknown_event = {'role': 'root', 'truncated': False, 'question_kind': 'unsupported',
                         'query_b64': base64.b64encode(unsupported_query).decode(),
                         'send_status': 'not_sent', 'query_error': 'unsupported'}
        def raw_sample(role):
            kind, data = response(test_query, role)
            if kind['kind'] != 'fixture' or data is None: raise RuntimeError('fixture wire control failed')
            return {'role': role, 'truncated': False, 'question_kind': kind['kind'],
                    'query_b64': base64.b64encode(test_query).decode(),
                    'response_b64': base64.b64encode(data).decode(), 'send_status': 'sent', 'sent_bytes': len(data)}
        path_with_aux = [aux_event, raw_sample('root'), raw_sample('authoritative')]
        blocked_aux = [aux_event]
        blocked_unknown = [unknown_event]
        if (referral_assessment(path_with_aux, True) != 'ordered_observation_only' or
                referral_assessment(blocked_aux, False) != 'inconclusive' or
                referral_assessment(blocked_unknown, False) != 'inconclusive'):
            raise RuntimeError('auxiliary flow classification control failed')
        report['auxiliary_controls'] = [
            {'events': path_with_aux, 'client_ok': True, 'expected': 'ordered_observation_only',
             'client_query_b64': base64.b64encode(test_query).decode(),
             'client_response_b64': base64.b64encode(test_reply).decode(),
             'actual': referral_assessment(path_with_aux, True)},
            {'events': blocked_aux, 'client_ok': False, 'expected': 'inconclusive',
             'client_query_b64': base64.b64encode(test_query).decode(), 'client_status': 'timeout',
             'actual': referral_assessment(blocked_aux, False)},
            {'events': blocked_unknown, 'client_ok': False, 'expected': 'inconclusive',
             'client_query_b64': base64.b64encode(test_query).decode(), 'client_status': 'timeout',
             'actual': referral_assessment(blocked_unknown, False)}]
        ordering_controls = [(50, 0, 0, 100, 200, 300, 'pre_readiness'),
                             (150, 0, 0, 100, 200, 300, 'pre_query'),
                             (350, 0, 0, 100, 200, 300, 'post_query'),
                             (200, 0, 0, 100, 200, 300, 'ambiguous'),
                             (305, 0, 10, 100, 200, 300, 'ambiguous'),
                             (350, 10, 0, 100, 200, 300, 'ambiguous')]
        if any(event_phase(*row[:-1]) != row[-1] for row in ordering_controls):
            raise RuntimeError('event timing classifier controls failed')
        report['parser_controls'] = {'answer_positive': 1, 'answer_negative': 2,
                                     'request_positive': 1, 'request_negative': 4,
                                     'flow_positive': 2, 'flow_negative': 4,
                                     'auxiliary_path_positive': 1, 'auxiliary_blocked_inconclusive': 1,
                                     'unsupported_blocked_inconclusive': 1,
                                     'ordering_pre_readiness': 1, 'ordering_pre_query': 1,
                                     'ordering_post_query': 1, 'ordering_ambiguous': 3}
        r = dig(ROOT, port, ['+authority', '+additional']); a = dig(AUTH, port, ['+answer'])
        report['controls'] = {'root': r, 'authority': a, 'root_port': port}
        want_root = [['deleg.test.', '60', 'IN', 'NS', NS], [NS, '60', 'IN', 'A', AUTH]]
        want_auth = [[NAME, '60', 'IN', 'A', ANSWER]]
        if (r['status'] != 0 or a['status'] != 0 or rows(r) != want_root or rows(a) != want_auth
                or errors or [e['role'] for e in events] != ['root', 'authoritative']):
            raise RuntimeError('independent dig peer controls failed')
        report['control_events'] = list(events); events.clear()
        if mode == 'setup':
            report['state'] = 'controls-complete'; return
        temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp.bind(('127.0.0.1', 0)); listen_port = temp.getsockname()[1]; temp.close()
        env = dict(os.environ, BASHDNS_SERVER_PORT=str(port), BASHDNS_0X20='0')
        env.pop('BASHDNS_FIXTURE_DIR', None)
        cmd = 'builtin dns resolver-serve --listen 127.0.0.1 --port %d --recurse --root-hints %s --timeout 1000 --max-queries 1' % (listen_port, ROOT)
        argv = [CANDIDATE, '--noprofile', '--norc', '-c', cmd]
        report['candidate'] = {'argv': argv, 'upstream_port': port, 'listen_port': listen_port}
        with (HOME / 'recursion-server.out').open('wb') as out, (HOME / 'recursion-server.err').open('wb') as err:
            report['candidate']['launch_clock'] = clock_pair()
            context['candidate_phase'] = True
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    env=env, start_new_session=True)
            context['pid'] = proc.pid
            report['candidate']['pid'] = proc.pid
            deadline = time.monotonic() + 5
            witness = None
            while proc.poll() is None and time.monotonic() < deadline:
                witness = listening_witness(proc.pid, listen_port)
                if witness is not None:
                    break
                time.sleep(.05)
            report['candidate']['readiness'] = witness
            report['candidate']['readiness_clock'] = clock_pair()
            report['candidate']['alive_before_query'] = proc.poll() is None
            report['candidate']['alive_check_monotonic_ns'] = time.monotonic_ns()
            ready = witness is not None and report['candidate']['alive_before_query']
            report['candidate']['ready'] = ready
            if not ready:
                raise RuntimeError('candidate readiness unproven')
            report['client'] = client_query(listen_port)
            try: report['candidate']['exit'] = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                report['candidate']['exit'] = None
                report['candidate']['timeout'] = True
    except Exception as exc:
        report['state'] = 'error'; report['error'] = repr(exc)
    finally:
        if proc is not None and proc.poll() is None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=5)
        if proc is not None:
            report['candidate']['final_exit'] = proc.returncode
            for suffix in ('out', 'err'):
                f = HOME / ('recursion-server.' + suffix)
                data = f.read_bytes() if f.exists() else b''
                report['candidate'][suffix + '_bytes'] = len(data)
                report['candidate'][suffix + '_b64'] = base64.b64encode(data[:65536]).decode()
        stop.set()
        if thread is not None: thread.join(timeout=2)
        report['peer_stopped'] = thread is None or not thread.is_alive()
        for sock in sockets: sock.close()
        if errors or not report['peer_stopped']:
            report['state'] = 'error'; report['error'] = 'peer failed or did not stop'
        if report.get('client', {}).get('status') == 'truncated':
            report['state'] = 'error'; report['error'] = 'client response datagram truncated'
        if mode == 'candidate' and report['state'] == 'setup':
            candidate = report.get('candidate', {}); client = report.get('client', {})
            clocks = [candidate.get('launch_clock'), candidate.get('readiness_clock'),
                      client.get('send_begin_clock'), client.get('send_end_clock')]
            clocks += [event.get('receive_clock') for event in events]
            try:
                if any(not isinstance(c, dict) or not c['monotonic_before_ns'] <= c['monotonic_after_ns'] for c in clocks):
                    raise RuntimeError('missing clock samples')
                low = min(c['realtime_ns'] - c['monotonic_after_ns'] for c in clocks)
                high = max(c['realtime_ns'] - c['monotonic_before_ns'] for c in clocks)
                report['clock_offset_bounds_ns'] = [low, high]
                for event in events:
                    event['phase'] = event_phase(event.get('kernel_receive_realtime_ns'), low, high,
                        candidate['readiness_clock']['monotonic_after_ns'], client['send_begin_monotonic_ns'],
                        client['send_end_monotonic_ns'])
                if any(event['phase'] != 'post_query' or 'upstream_witness_error' in event for event in events):
                    raise RuntimeError('peer event provenance or timing inconclusive')
                client_end = client.get('receive_monotonic_ns', client.get('timeout_monotonic_ns'))
                if type(client_end) is not int or any(
                        event['kernel_receive_realtime_ns'] - low >= client_end for event in events):
                    raise RuntimeError('peer event is outside client observation interval')
                root_send = None
                for event in events:
                    if event.get('question_kind') != 'fixture':
                        continue
                    if event['role'] == 'root' and event.get('send_status') == 'sent':
                        root_send = event['send_end_monotonic_ns']
                    elif event['role'] == 'authoritative' and root_send is not None:
                        if event['kernel_receive_realtime_ns'] - high <= root_send:
                            raise RuntimeError('referral response and authority timing ambiguous')
            except (KeyError, TypeError, RuntimeError) as exc:
                report['state'] = 'error'; report['error'] = repr(exc)
        if mode == 'candidate' and report['state'] == 'setup': report['state'] = 'complete'
        save(name, report)


def outer(mode):
    if os.getuid() != 2000 or os.geteuid() != 2000: raise RuntimeError('outer uid mismatch')
    outer_identity = identity('outer')
    if mode == 'candidate':
        # The existing namespace observer cannot prove referral delivery, the
        # attribution of sends to the service, or writer/sender quiescence.
        # Under the suite runner the candidate driver shell has already started
        # to invoke this helper; the helper does not observe or attest it.  It
        # must not launch a DNS service without a reviewed evidence boundary.
        # No environment flag can bypass this guard.
        common = {'mode': mode, 'state': 'inconclusive',
                  'observer_launched_dns_service': False,
                  'driver_shell_observation': 'not-recorded-by-helper',
                  'identity_outer': outer_identity,
                  'missing_capabilities': ['referral-causality',
                                           'service-sender-attribution',
                                           'owned-writer-containment'],
                  'reason': 'candidate DNS service held pending reviewed witnesses'}
        blocked = {**common, 'peer_events': []}
        save('recursion-candidate.json', blocked)
        save('recursion-candidate-outer.json', common)
        print('recursive referral inconclusive: required witnesses unavailable', file=sys.stderr)
        return 125
    net, user = os.readlink('/proc/self/ns/net'), os.readlink('/proc/self/ns/user')
    argv = ['/usr/bin/unshare', '--user', '--map-root-user', '--net', '/usr/bin/python3', HERE, 'inner', mode, net, user,
            json.dumps(outer_identity, sort_keys=True, separators=(',', ':'))]
    p = subprocess.run(argv, capture_output=True, timeout=30)
    save('recursion-' + mode + '-outer.json', {'argv': argv, 'identity_outer': outer_identity, 'status': p.returncode,
         'stdout_b64': base64.b64encode(p.stdout[:65536]).decode(), 'stderr_b64': base64.b64encode(p.stderr[:65536]).decode(),
         'stdout_bytes': len(p.stdout), 'stderr_bytes': len(p.stderr)})
    path = HOME / ('recursion-' + mode + '.json')
    if p.returncode or not path.exists(): raise RuntimeError('namespace or observer failed')
    data = json.loads(path.read_text())
    if data['state'] == 'error': raise RuntimeError('fixture control failed')
    if identity('outer') != outer_identity: raise RuntimeError('outer identity changed')
    data['identity_outer'] = outer_identity
    save('recursion-' + mode + '.json', data)
    if mode == 'setup':
        if data['state'] != 'controls-complete': raise RuntimeError('controls incomplete')
        print('referral controls ready'); return 0
    raise RuntimeError('unexpected mode after setup observer')


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ('setup', 'candidate'): return outer(sys.argv[1])
    if len(sys.argv) == 6 and sys.argv[1] == 'inner' and sys.argv[2] in ('setup', 'candidate'):
        inner_identity = identity('inner', json.loads(sys.argv[5]))
        run_inner(sys.argv[2], sys.argv[3], sys.argv[4], inner_identity); return 0
    raise ValueError('invalid invocation')


if __name__ == '__main__':
    raise SystemExit(main())
