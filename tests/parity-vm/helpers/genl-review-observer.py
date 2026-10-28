#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only raw NETLINK_GENERIC oracle and observer for the genl controller reader.

Modes (always inside the disposable parity VM, as uid 2000, in the case scratch directory):
  setup SCENARIO    independent controls; a failed control is invalid evidence (exit 97)
  SHELL SCENARIO    run the candidate "genl" builtin and print one summary line per vector
  child-dump        internal: raw dump with recvmsg(2), used to calibrate the syscall observer

Expected values never come from the candidate. Kernel facts (family IDs, versions, header
sizes, operations, capability flags, multicast groups, errno values) come from this file's own
NETLINK_GENERIC client: its own message builder, attribute parser (including the nested
operation and group arrays), multi-message and multi-buffer handling, NLMSG_DONE/ERROR/ACK
handling and sequence/port matching. That parser is first calibrated against hand-encoded
vectors and then against the real kernel (by name, by id, dump, interleaved requests, ACK and
error replies). The text layout is the documented print contract of loadables/genl.c. The guest
iproute2 genl is a cross-check of the family table and the reference only for the "fails like
iproute2" term. Every summary key is evaluated for every vector; a failed control prints
CONTROL-INVALID and exits 97 instead of a candidate result.
"""
import base64
import errno
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid


ROOT = Path('/opt/bashos-parity/harness/helpers')
SELF = ROOT / 'genl-review-observer.py'
SEQUENCE = ROOT / 'system-sequence.py'
PYTHON = '/usr/bin/python3'
REFERENCE_BASH = '/opt/bash-5.3.15/bin/bash'
IPROUTE2 = '/usr/sbin/genl'

# Linux UAPI (linux/netlink.h, linux/genetlink.h).
AF_NETLINK = 16
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
GENL_MIN_ID, GENL_MAX_ID = 0x10, 1023
NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE = 1, 2, 3
NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_DUMP_INTR, NLM_F_DUMP = 0x01, 0x02, 0x04, 0x10, 0x300
CTRL_CMD_NEWFAMILY, CTRL_CMD_GETFAMILY = 1, 3
CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_VERSION = 1, 2, 3
CTRL_ATTR_HDRSIZE, CTRL_ATTR_MAXATTR, CTRL_ATTR_OPS, CTRL_ATTR_MCAST_GROUPS = 4, 5, 6, 7
CTRL_ATTR_OP_ID, CTRL_ATTR_OP_FLAGS = 1, 2
CTRL_ATTR_MCAST_GRP_NAME, CTRL_ATTR_MCAST_GRP_ID = 1, 2
NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLA_TYPE_MASK = 0x8000, 0x4000, 0x3fff
GENL_ADMIN_PERM, GENL_CMD_CAP_DO, GENL_CMD_CAP_DUMP, GENL_CMD_CAP_HASPOL = 0x01, 0x02, 0x04, 0x08

NLMSG = struct.Struct('=IHHII')
GENL = struct.Struct('=BBH')
NLA = struct.Struct('=HH')
U16 = struct.Struct('=H')
U32 = struct.Struct('=I')
S32 = struct.Struct('=i')
SEQ_BASE = 0x6f726163
RECV_SIZE = 65536
CONTROL_MARKER = b'GENL-BEGIN:0\n'
PLAIN_SCRIPT = 'genl "$@"'
TRACED_SCRIPT = 'printf "GENL-BEGIN:%s\\n" "$BASHPID"; genl "$@"'
# (bit, phrase in the candidate's flag text, summary-key suffix)
WORDS = ((GENL_ADMIN_PERM, 'requires admin permission', 'admin'), (GENL_CMD_CAP_DO, 'can doit', 'doit'),
         (GENL_CMD_CAP_DUMP, 'can dumpit', 'dumpit'), (GENL_CMD_CAP_HASPOL, 'has policy', 'haspol'))

# One entry per case. "needs" selects the independent controls; every line is one candidate
# invocation whose summary line is exactly "<label> <keys>" on success. The suite generator reads
# this literal with ast.literal_eval, so the expected stdout and the printed lines cannot drift.
SCENARIOS = {
    'get-id-record': {
        'needs': ['oracle', 'crosscheck'],
        'lines': [
            {'label': 'name-nlctrl', 'kind': 'record', 'family': 'ctrl',
             'args': ['ctrl', 'get', 'name', 'nlctrl'], 'reference': True,
             'keys': 'status=0 stderr=empty semantic=yes'},
            {'label': 'id-hex-0x10', 'kind': 'record', 'family': 'ctrl', 'baseline': 'name-nlctrl',
             'args': ['ctrl', 'get', 'id', '0x10'], 'reference': True,
             'keys': 'status=0 stderr=empty semantic=yes same-as-name=yes'},
            {'label': 'id-decimal-16', 'kind': 'record', 'family': 'ctrl', 'baseline': 'name-nlctrl',
             'args': ['ctrl', 'get', 'id', '16'], 'reference': True,
             'keys': 'status=0 stderr=empty semantic=yes same-as-name=yes'},
            {'label': 'id-octal-020', 'kind': 'record', 'family': 'ctrl', 'baseline': 'name-nlctrl',
             'args': ['ctrl', 'get', 'id', '020'], 'reference': True,
             'keys': 'status=0 stderr=empty semantic=yes same-as-name=yes'},
        ]},
    'get-id-unknown': {
        'needs': ['oracle', 'errors', 'iproute2'],
        'lines': [
            {'label': 'id-0x3ff', 'kind': 'kernel-error', 'lookup': ['id', '0x3ff'],
             'args': ['ctrl', 'get', 'id', '0x3ff'],
             'keys': 'failed=yes stdout-empty=yes stderr-exact=yes iproute2-stderr-same=yes'},
            {'label': 'id-65535', 'kind': 'kernel-error', 'lookup': ['id', '65535'],
             'args': ['ctrl', 'get', 'id', '65535'],
             'keys': 'failed=yes stdout-empty=yes stderr-exact=yes iproute2-stderr-same=yes'},
            {'label': 'id-0', 'kind': 'kernel-error', 'lookup': ['id', '0'],
             'args': ['ctrl', 'get', 'id', '0'],
             'keys': 'failed=yes stdout-empty=yes stderr-exact=yes iproute2-stderr-same=yes'},
        ]},
    'get-id-unknown-status': {
        'needs': ['oracle', 'errors', 'iproute2'],
        'lines': [
            {'label': 'id-0x3ff', 'kind': 'kernel-error', 'lookup': ['id', '0x3ff'],
             'args': ['ctrl', 'get', 'id', '0x3ff'], 'keys': 'failed=yes iproute2-status-same=yes'},
            {'label': 'id-65535', 'kind': 'kernel-error', 'lookup': ['id', '65535'],
             'args': ['ctrl', 'get', 'id', '65535'], 'keys': 'failed=yes iproute2-status-same=yes'},
            {'label': 'id-0', 'kind': 'kernel-error', 'lookup': ['id', '0'],
             'args': ['ctrl', 'get', 'id', '0'], 'keys': 'failed=yes iproute2-status-same=yes'},
        ]},
    'get-id-invalid': {
        'needs': ['errors', 'usage', 'observer'],
        'lines': [
            {'label': 'control-valid-16', 'kind': 'traced-control', 'args': ['ctrl', 'get', 'id', '16'],
             'keys': 'sockets=1'},
            {'label': 'control-boundary-0xffff', 'kind': 'traced-control', 'lookup': ['id', '0xffff'],
             'args': ['ctrl', 'get', 'id', '0xffff'], 'keys': 'sockets=1 no-invalid-diag=yes'},
            {'label': 'nonnumeric-abc', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', 'abc'],
             'message': 'invalid family id: abc', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'nonnumeric-empty', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', ''],
             'message': 'invalid family id: ', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'nonnumeric-name', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', 'nlctrl'],
             'message': 'invalid family id: nlctrl', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'range-0x10000', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '0x10000'],
             'message': 'invalid family id: 0x10000', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'range-65536', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '65536'],
             'message': 'invalid family id: 65536', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'range-4294967296', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '4294967296'],
             'message': 'invalid family id: 4294967296',
             'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'range-negative', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '-1'],
             'message': 'invalid family id: -1', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'range-overflow', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '99999999999999999999'],
             'message': 'invalid family id: 99999999999999999999',
             'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'junk-16x', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '16x'],
             'message': 'invalid family id: 16x', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'junk-0x10g', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '0x10g'],
             'message': 'invalid family id: 0x10g', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'junk-trailing-space', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '16 '],
             'message': 'invalid family id: 16 ', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'junk-dot', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '1.6'],
             'message': 'invalid family id: 1.6', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
            {'label': 'junk-bare-0x', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '0x'],
             'message': 'invalid family id: 0x', 'keys': 'status=2 stdout-empty=yes diag-exact=yes sockets=0'},
        ]},
    'get-name-record': {
        'needs': ['oracle', 'crosscheck'],
        'lines': [
            {'label': 'name-nlctrl', 'kind': 'record', 'family': 'ctrl',
             'args': ['ctrl', 'get', 'name', 'nlctrl'], 'reference': True,
             'keys': 'status=0 stderr=empty exact=yes semantic=yes one-record=yes id-0x10=yes groups-notify=yes'},
        ]},
    'get-name-unknown': {
        'needs': ['oracle', 'errors', 'iproute2'],
        'lines': [
            {'label': 'name-bashos_nofam', 'kind': 'kernel-error', 'lookup': ['name', 'bashos_nofam'],
             'args': ['ctrl', 'get', 'name', 'bashos_nofam'],
             'keys': 'failed=yes stdout-empty=yes stderr-exact=yes'},
            {'label': 'name-NLCTRL', 'kind': 'kernel-error', 'lookup': ['name', 'NLCTRL'],
             'args': ['ctrl', 'get', 'name', 'NLCTRL'],
             'keys': 'failed=yes stdout-empty=yes stderr-exact=yes'},
        ]},
    'get-name-malformed': {
        'needs': ['usage'],
        'lines': [
            {'label': 'missing-kind-and-value', 'kind': 'usage', 'args': ['ctrl', 'get'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'missing-value-name', 'kind': 'usage', 'args': ['ctrl', 'get', 'name'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'missing-value-id', 'kind': 'usage', 'args': ['ctrl', 'get', 'id'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'extra-after-name', 'kind': 'usage', 'args': ['ctrl', 'get', 'name', 'nlctrl', 'extra'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'extra-after-id', 'kind': 'usage', 'args': ['ctrl', 'get', 'id', '16', 'extra'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'unknown-kind', 'kind': 'usage', 'args': ['ctrl', 'get', 'bogus', 'nlctrl'],
             'message': 'unsupported ctrl command: get', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'unknown-kind-case', 'kind': 'usage', 'args': ['ctrl', 'get', 'NAME', 'nlctrl'],
             'message': 'unsupported ctrl command: get', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
        ]},
    'list-records': {
        'needs': ['oracle', 'crosscheck'],
        'lines': [
            {'label': 'list', 'kind': 'listing', 'args': ['ctrl', 'list'], 'reference': True,
             'keys': 'status=0 stderr=empty families-complete=yes records=yes'},
        ]},
    'list-capabilities': {
        'needs': ['oracle', 'crosscheck', 'caps'],
        'lines': [
            {'label': 'list', 'kind': 'listing', 'args': ['ctrl', 'list'], 'reference': True,
             'keys': ('status=0 stderr=empty commands=yes caps-hex=yes word-admin=yes word-doit=yes '
                      'word-dumpit=yes word-haspol=yes')},
        ]},
    'list-groups': {
        'needs': ['oracle', 'crosscheck'],
        'lines': [
            {'label': 'list', 'kind': 'listing', 'args': ['ctrl', 'list'], 'reference': True,
             'keys': 'status=0 stderr=empty families-complete=yes groups=yes'},
        ]},
    'list-multipart': {
        'needs': ['oracle', 'span', 'observer'],
        'lines': [
            {'label': 'list-traced', 'kind': 'listing', 'args': ['ctrl', 'list'],
             'keys': 'status=0 stderr=empty families-complete=yes recv-buffers-ge2=yes sockets=1'},
        ]},
    'list-extra-argument': {
        'needs': ['usage'],
        'lines': [
            {'label': 'extra-word', 'kind': 'usage', 'args': ['ctrl', 'list', 'extra'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'extra-empty', 'kind': 'usage', 'args': ['ctrl', 'list', ''],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
            {'label': 'extra-two', 'kind': 'usage', 'args': ['ctrl', 'list', 'a', 'b'],
             'message': 'wrong controller params', 'keys': 'status=2 stdout-empty=yes diag-exact=yes'},
        ]},
    'list-exact': {
        'needs': ['oracle', 'crosscheck'],
        'lines': [
            {'label': 'list', 'kind': 'listing', 'args': ['ctrl', 'list'], 'reference': True,
             'keys': 'status=0 stderr=empty exact=yes semantic=yes'},
        ]},
    'get-dynamic-family': {
        'needs': ['oracle', 'crosscheck', 'dynamic'],
        'lines': [
            {'label': 'name-dynamic', 'kind': 'record', 'family': 'dynamic',
             'args': ['ctrl', 'get', 'name', '{dyn_name}'], 'reference': True,
             'keys': 'status=0 stderr=empty exact=yes semantic=yes'},
            {'label': 'id-dynamic-hex', 'kind': 'record', 'family': 'dynamic', 'baseline': 'name-dynamic',
             'args': ['ctrl', 'get', 'id', '{dyn_id_hex}'], 'reference': True,
             'keys': 'status=0 stderr=empty exact=yes semantic=yes same-as-name=yes'},
            {'label': 'id-dynamic-decimal', 'kind': 'record', 'family': 'dynamic', 'baseline': 'name-dynamic',
             'args': ['ctrl', 'get', 'id', '{dyn_id_dec}'], 'reference': True,
             'keys': 'status=0 stderr=empty exact=yes semantic=yes same-as-name=yes'},
        ]},
}


class ControlFailure(Exception):
    """An independent control failed: the evidence is invalid, not the candidate."""


class ProtocolError(Exception):
    """The oracle parser rejected a netlink byte string."""


def refuse(reason):
    sys.stderr.write('genl-review-observer: refusing: %s\n' % reason)
    sys.exit(99)


def require_guest():
    # The root evaluator separately verifies the marker against the DMI UUID.
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
    except (OSError, ValueError):
        refuse('not inside the disposable parity VM')
    if vendor != 'QEMU':
        refuse('not a QEMU guest')
    if os.geteuid() != 2000:
        refuse('not uid 2000')
    if Path.cwd() != Path('/tmp/parity-case'):
        refuse('not in the case scratch directory')


def yes(flag):
    return 'yes' if flag else 'no'


def align4(length):
    return (length + 3) & ~3


# ---------------------------------------------------------------------------
# Raw NETLINK_GENERIC client: message builder, parsers, conversation state.
# ---------------------------------------------------------------------------

def attribute(kind, payload):
    length = NLA.size + len(payload)
    return NLA.pack(length, kind) + payload + b'\0' * (align4(length) - length)


def message(mtype, flags, seq, pid, payload):
    return NLMSG.pack(NLMSG.size + len(payload), mtype, flags, seq, pid) + payload


def controller_request(cmd, flags, seq, attrs=b''):
    return message(GENL_ID_CTRL, flags, seq, 0, GENL.pack(cmd, 1, 0) + attrs)


def parse_attributes(data):
    """Return [(type, flag bits, payload)] for a run of netlink attributes."""
    found, offset = [], 0
    while offset < len(data):
        if len(data) - offset < NLA.size:
            raise ProtocolError('attribute header is truncated')
        length, kind = NLA.unpack_from(data, offset)
        if length < NLA.size or offset + length > len(data):
            raise ProtocolError('attribute length %d does not fit its container' % length)
        found.append((kind & NLA_TYPE_MASK, kind & (NLA_F_NESTED | NLA_F_NET_BYTEORDER),
                      data[offset + NLA.size:offset + length]))
        offset += align4(length)
    return found


def unique(attrs):
    table = {}
    for kind, flags, payload in attrs:
        if kind in table:
            raise ProtocolError('attribute %d appears twice' % kind)
        table[kind] = payload
    return table


def need(table, kind, what):
    if kind not in table:
        raise ProtocolError('missing attribute: ' + what)
    return table[kind]


def as_u16(payload, what):
    if len(payload) != U16.size:
        raise ProtocolError('%s is not a u16' % what)
    return U16.unpack(payload)[0]


def as_u32(payload, what):
    if len(payload) != U32.size:
        raise ProtocolError('%s is not a u32' % what)
    return U32.unpack(payload)[0]


def as_string(payload, what):
    if not payload.endswith(b'\0') or b'\0' in payload[:-1]:
        raise ProtocolError('%s is not one NUL-terminated string' % what)
    return payload[:-1].decode('utf-8', 'surrogateescape')


def parse_family(payload):
    """One CTRL_CMD_NEWFAMILY body (generic header plus attributes) as a dict."""
    if len(payload) < GENL.size:
        raise ProtocolError('generic netlink header is truncated')
    cmd = GENL.unpack_from(payload, 0)[0]
    table = unique(parse_attributes(payload[GENL.size:]))
    family = {'cmd': cmd,
              'name': as_string(need(table, CTRL_ATTR_FAMILY_NAME, 'family name'), 'family name'),
              'id': as_u16(need(table, CTRL_ATTR_FAMILY_ID, 'family id'), 'family id'),
              'version': as_u32(need(table, CTRL_ATTR_VERSION, 'version'), 'version'),
              'hdrsize': as_u32(need(table, CTRL_ATTR_HDRSIZE, 'header size'), 'header size'),
              'maxattr': as_u32(need(table, CTRL_ATTR_MAXATTR, 'maximum attribute'), 'maximum attribute'),
              'ops': None, 'groups': None}
    if CTRL_ATTR_OPS in table:
        family['ops'] = []
        for index, _flags, body in parse_attributes(table[CTRL_ATTR_OPS]):
            inner = unique(parse_attributes(body))
            family['ops'].append({
                'index': index,
                'id': as_u32(need(inner, CTRL_ATTR_OP_ID, 'operation id'), 'operation id'),
                'flags': as_u32(need(inner, CTRL_ATTR_OP_FLAGS, 'operation flags'), 'operation flags')})
    if CTRL_ATTR_MCAST_GROUPS in table:
        family['groups'] = []
        for index, _flags, body in parse_attributes(table[CTRL_ATTR_MCAST_GROUPS]):
            inner = unique(parse_attributes(body))
            family['groups'].append({
                'index': index,
                'id': as_u32(need(inner, CTRL_ATTR_MCAST_GRP_ID, 'group id'), 'group id'),
                'name': as_string(need(inner, CTRL_ATTR_MCAST_GRP_NAME, 'group name'), 'group name')})
    return family


class Conversation:
    """Replies to one request: sequence/port matching, several messages per buffer, DONE/ERROR/ACK."""

    def __init__(self, seq, portid, dump, expect_ack=False):
        self.seq, self.portid, self.dump, self.expect_ack = seq, portid, dump, expect_ack
        self.messages = []        # data messages: {'flags': int, 'payload': bytes}
        self.foreign = []         # messages for another sequence or port, ignored
        self.error = 0            # positive errno from NLMSG_ERROR, else 0
        self.acked = False
        self.done = False
        self.interrupted = False
        self.buffers = 0          # received buffers fed to this conversation
        self.data_buffers = 0     # of those, buffers that carried at least one record
        self.bytes = 0            # bytes of record messages
        self.complete = False

    def feed(self, data):
        self.buffers += 1
        carried = False
        offset = 0
        while offset < len(data):
            if len(data) - offset < NLMSG.size:
                raise ProtocolError('netlink header is truncated')
            length, mtype, flags, seq, pid = NLMSG.unpack_from(data, offset)
            if length < NLMSG.size or offset + length > len(data):
                raise ProtocolError('netlink message length %d does not fit its buffer' % length)
            payload = data[offset + NLMSG.size:offset + length]
            offset += align4(length)
            if seq != self.seq or pid != self.portid:
                self.foreign.append({'seq': seq, 'pid': pid, 'type': mtype})
                continue
            if self.complete:
                raise ProtocolError('message type %d after the conversation completed' % mtype)
            carried = self.accept(mtype, flags, payload, length) or carried
            self.refresh()
        if carried:
            self.data_buffers += 1

    def accept(self, mtype, flags, payload, length):
        if mtype == NLMSG_ERROR:
            if len(payload) < S32.size:
                raise ProtocolError('NLMSG_ERROR lacks an error code')
            code = S32.unpack_from(payload)[0]
            if code == 0:
                if not self.expect_ack:
                    raise ProtocolError('acknowledgement that was not requested')
                self.acked = True
            elif code > 0:
                raise ProtocolError('positive error code %d' % code)
            else:
                self.error = -code
            return False
        if mtype == NLMSG_DONE:
            if not self.dump:
                raise ProtocolError('NLMSG_DONE answered a request that was not a dump')
            self.done = True
            return False
        if mtype == NLMSG_NOOP:
            return False
        if mtype != GENL_ID_CTRL:
            raise ProtocolError('unexpected message type %d' % mtype)
        if not self.dump and self.messages:
            raise ProtocolError('more than one record answered a single-family request')
        if flags & NLM_F_DUMP_INTR:
            self.interrupted = True
        self.messages.append({'flags': flags, 'payload': payload})
        self.bytes += length
        return True

    def refresh(self):
        if self.error:
            self.complete = True
        elif self.dump:
            self.complete = self.done
        else:
            self.complete = bool(self.messages) and (self.acked or not self.expect_ack)

    @property
    def multi(self):
        return all(m['flags'] & NLM_F_MULTI for m in self.messages)


def name_attribute(name):
    return attribute(CTRL_ATTR_FAMILY_NAME, name.encode() + b'\0')


def id_attribute(family_id):
    return attribute(CTRL_ATTR_FAMILY_ID, U16.pack(family_id))


class Netlink:
    """One raw NETLINK_GENERIC socket; every byte sent and received is saved in a transcript."""

    def __init__(self, transcript):
        self.transcript = Path(transcript)
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.portid = self.sock.getsockname()[0]
        self.seq = SEQ_BASE

    def close(self):
        self.sock.close()

    def record(self, label, direction, seq, data):
        row = {'label': label, 'direction': direction, 'seq': seq, 'length': len(data),
               'base64': base64.b64encode(data).decode()}
        with self.transcript.open('a') as stream:
            stream.write(json.dumps(row, sort_keys=True) + '\n')

    def start(self, label, cmd, flags, attrs=b'', dump=False, ack=False):
        self.seq += 1
        seq = self.seq
        request = controller_request(cmd, flags | (NLM_F_ACK if ack else 0), seq, attrs)
        self.record(label, 'send', seq, request)
        self.sock.sendto(request, (0, 0))
        return Conversation(seq, self.portid, dump, ack)

    def wait(self, label, conversations, limit=10.0):
        deadline = time.monotonic() + limit
        try:
            while not all(c.complete for c in conversations):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([self.sock], [], [], remaining)[0]:
                    raise ControlFailure('%s: no complete netlink answer within %d s' % (label, limit))
                data, _ancillary, flags, _address = self.sock.recvmsg(RECV_SIZE)
                if flags & socket.MSG_TRUNC:
                    raise ControlFailure('%s: a receive truncated a netlink message' % label)
                self.record(label, 'recv', None, data)
                for conversation in conversations:
                    conversation.feed(data)
        except ProtocolError as exc:
            raise ControlFailure('%s: kernel reply rejected by the oracle parser: %s' % (label, exc))

    def get_family(self, label, name=None, family_id=None, ack=False):
        attrs = name_attribute(name) if name is not None else id_attribute(family_id)
        conversation = self.start(label, CTRL_CMD_GETFAMILY, NLM_F_REQUEST, attrs, ack=ack)
        self.wait(label, [conversation])
        return conversation

    def dump(self, label):
        conversation = self.start(label, CTRL_CMD_GETFAMILY, NLM_F_REQUEST | NLM_F_DUMP, dump=True)
        self.wait(label, [conversation])
        return conversation


def families_of(conversation, label):
    try:
        return [parse_family(m['payload']) for m in conversation.messages]
    except ProtocolError as exc:
        raise ControlFailure('%s: family record rejected by the oracle parser: %s' % (label, exc))


def snapshot(nl, tag):
    conversation = nl.dump(tag + '-dump')
    if conversation.interrupted or not conversation.multi or not conversation.done:
        raise ControlFailure('%s: the dump was inconsistent, not multipart or not terminated' % tag)
    return {'families': families_of(conversation, tag + '-dump'), 'buffers': conversation.buffers,
            'data_buffers': conversation.data_buffers, 'bytes': conversation.bytes,
            'foreign': len(conversation.foreign)}


def nlctrl_of(families):
    found = [f for f in families if f['name'] == 'nlctrl']
    if len(found) != 1 or found[0]['id'] != GENL_ID_CTRL:
        raise ControlFailure('the controller family nlctrl with id 0x10 is not listed exactly once')
    return found[0]


def choose_dynamic(families):
    """A family other than nlctrl, preferring one with operations and groups and the most operations."""
    others = [f for f in families if f['id'] != GENL_ID_CTRL]
    if not others:
        raise ControlFailure('no family other than nlctrl is visible; the dynamic-id vectors cannot run')
    return sorted(others, key=lambda f: (0 if f['ops'] and f['groups'] else 1,
                                         -len(f['ops'] or []), f['id']))[0]


# ---------------------------------------------------------------------------
# Text: the documented print contract of loadables/genl.c, and a tolerant reader.
# ---------------------------------------------------------------------------

def words(flags):
    text = ''
    if flags & GENL_ADMIN_PERM:
        text += 'requires admin permission; '
    if flags & GENL_CMD_CAP_DO:
        text += 'can doit; '
    if flags & GENL_CMD_CAP_DUMP:
        text += 'can dumpit; '
    if flags & GENL_CMD_CAP_HASPOL:
        text += 'has policy'
    return text or 'none'


def render(family):
    out = ['\n', 'Name: %s\n' % family['name'],
           '\tID: 0x%x  Version: 0x%x  header size: %u  max attribs: %u \n'
           % (family['id'], family['version'], family['hdrsize'], family['maxattr'])]
    if family['ops']:
        out.append('\tcommands supported: \n')
        for number, op in enumerate(family['ops'], 1):
            out.append('\t\t#%u:  ID-0x%x \n' % (number, op['id']))
            out.append('\t\tCapabilities (0x%x):\n' % op['flags'])
            out.append(' \t\t  ' + words(op['flags']) + '\n')
            out.append('\n')
        out.append('\n')
    if family['groups']:
        out.append('\tmulticast groups:\n')
        for number, group in enumerate(family['groups'], 1):
            out.append('\t\t#%u:  ID-0x%x  name: %s \n' % (number, group['id'], group['name']))
        out.append('\n')
    return ''.join(out)


def render_all(families):
    return ''.join(render(f) for f in families).encode('utf-8', 'surrogateescape')


ID_LINE = re.compile(r'ID: 0x([0-9a-f]+)\s+Version: 0x([0-9a-f]+)\s+header size: ([0-9]+)\s+max attribs: ([0-9]+)')
OP_LINE = re.compile(r'#([0-9]+):\s+ID-0x([0-9a-f]+)')
CAP_LINE = re.compile(r'Capabilities \(0x([0-9a-f]+)\):')
GROUP_LINE = re.compile(r'#([0-9]+):\s+ID-0x([0-9a-f]+)\s+name:\s*(.*?)\s*')


def parse_listing(text):
    """Tolerant reader shared by candidate and iproute2 output: {'families': [...], 'junk': [...]}."""
    families, junk = [], []
    family = section = awaiting = None
    for raw in text.split('\n'):
        line = raw.strip()
        if not line:
            continue
        if raw.startswith('Name: '):
            family = {'name': raw[len('Name: '):].strip(), 'id': None, 'version': None, 'hdrsize': None,
                      'maxattr': None, 'ops': [], 'groups': []}
            families.append(family)
            section = awaiting = None
            continue
        if family is None:
            junk.append(line)
            continue
        match = ID_LINE.fullmatch(line)
        if match:
            family['id'], family['version'] = int(match.group(1), 16), int(match.group(2), 16)
            family['hdrsize'], family['maxattr'] = int(match.group(3)), int(match.group(4))
            section = awaiting = None
            continue
        if line.startswith('commands supported:'):
            section, awaiting = 'ops', None
            continue
        if line.startswith('multicast groups:'):
            section, awaiting = 'groups', None
            continue
        if section == 'ops':
            match = OP_LINE.fullmatch(line)
            if match:
                family['ops'].append({'idx': int(match.group(1)), 'id': int(match.group(2), 16),
                                      'flags': None, 'words': None})
                awaiting = None
                continue
            match = CAP_LINE.fullmatch(line)
            if match and family['ops']:
                awaiting = family['ops'][-1]
                awaiting['flags'] = int(match.group(1), 16)
                continue
            if awaiting is not None and awaiting['words'] is None:
                awaiting['words'] = line
                continue
        elif section == 'groups':
            match = GROUP_LINE.fullmatch(line)
            if match:
                family['groups'].append({'idx': int(match.group(1)), 'id': int(match.group(2), 16),
                                         'name': match.group(3)})
                continue
        junk.append(line)
    return {'families': families, 'junk': junk}


def core_of(f):
    return (f['name'], f['id'], f['version'], f['hdrsize'], f['maxattr'])


def wanted_ops(f):
    return [(n, o['id'], o['flags']) for n, o in enumerate(f['ops'] or [], 1)]


def wanted_groups(f):
    return [(n, g['id'], g['name']) for n, g in enumerate(f['groups'] or [], 1)]


def shown_ops(p):
    return [(o['idx'], o['id'], o['flags']) for o in p['ops']]


def shown_groups(p):
    return [(g['idx'], g['id'], g['name']) for g in p['groups']]


def same_table(parsed, families):
    """Structure of a parsed listing equals the oracle's families (words and byte layout ignored)."""
    shown = parsed['families']
    return (len(shown) == len(families)
            and all(core_of(p) == core_of(f) and shown_ops(p) == wanted_ops(f)
                    and shown_groups(p) == wanted_groups(f) for p, f in zip(shown, families)))


# ---------------------------------------------------------------------------
# Child processes and the syscall observer.
# ---------------------------------------------------------------------------

class Ran:
    """One finished child process with its raw output."""

    def __init__(self, argv, status, out, err, timed_out):
        self.argv, self.status, self.out, self.err, self.timed_out = argv, status, out, err, timed_out
        self.raw_out = out


def spawn(argv, timeout=10, env=None):
    proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    return Ran(argv, proc.returncode, out, err, timed_out)


def status_text(ran):
    return 'timeout' if ran.timed_out else str(ran.status)


def tracing(log):
    return [PYTHON, str(SEQUENCE), '--notify', 'socket', '--reply', 'socket=continue',
            '--log-args', 'socket=0,1,2', '--notify', 'recvmsg', '--reply', 'recvmsg=continue',
            '--log-args', 'recvmsg=0', '--notify', 'write:0=1', '--reply', 'write=continue',
            '--log-args', 'write=0,2', '--log-mem', 'write=1:64', '--log', str(log), '--']


def split_marker(out):
    head, separator, rest = out.partition(b'\n')
    if not separator or not re.fullmatch(rb'GENL-BEGIN:[0-9]+', head):
        return None, out
    return head + separator, rest


def trace_counts(log, marker):
    """Socket and recvmsg notifications after the captured pre-builtin stdout marker."""
    rows = [json.loads(line) for line in Path(log).read_text().splitlines()] if Path(log).exists() else []
    counts = {'rows': len(rows), 'markers': 0, 'before_sockets': 0, 'sockets': 0, 'netlink_sockets': 0,
              'recvmsg': 0}
    for row in rows:
        name = row['syscall']
        if name == 'write':
            data = bytes.fromhex(row.get('memory1', {}).get('hex', ''))[:row['arg2']]
            if marker is not None and data == marker:
                counts['markers'] += 1
        elif name == 'socket':
            if counts['markers']:
                counts['sockets'] += 1
                if row['arg0'] == AF_NETLINK:
                    counts['netlink_sockets'] += 1
            else:
                counts['before_sockets'] += 1
        elif name == 'recvmsg' and counts['markers']:
            counts['recvmsg'] += 1
    return counts


def socket_text(counts):
    return str(counts['netlink_sockets']) if counts['markers'] == 1 else 'invalid-marker'


def run_candidate(shell, args, label, traced):
    log = Path('trace-%s.jsonl' % label)
    argv = [shell, '--noprofile', '--norc', '-c', TRACED_SCRIPT if traced else PLAIN_SCRIPT, 'genl-case'] + list(args)
    if traced:
        argv = tracing(log) + argv
    ran = spawn(argv, env=dict(os.environ))
    counts = None
    if traced:
        marker, ran.out = split_marker(ran.raw_out)
        counts = trace_counts(log, marker)
    return ran, counts


def run_iproute2(args):
    return spawn([IPROUTE2] + list(args), env=dict(os.environ, PATH='/usr/bin:/bin:/usr/sbin:/sbin'))


def observe(row):
    with Path('observations.jsonl').open('a') as stream:
        stream.write(json.dumps(row, sort_keys=True) + '\n')


def b64(data):
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------------
# Per-kind evaluation: every key is computed for every vector.
# ---------------------------------------------------------------------------

def listing_values(ran, families):
    parsed = parse_listing(ran.out.decode('utf-8', 'surrogateescape'))
    shown = parsed['families']
    aligned = len(shown) == len(families)
    pairs = list(zip(shown, families)) if aligned else []
    records = aligned and all(core_of(p) == core_of(f) for p, f in pairs)
    groups = aligned and all(shown_groups(p) == wanted_groups(f) for p, f in pairs)
    commands = aligned and all([(n, i) for n, i, _ in shown_ops(p)] == [(n, i) for n, i, _ in wanted_ops(f)]
                               for p, f in pairs)
    caps = commands and all([o['flags'] for o in p['ops']] == [o['flags'] for o in (f['ops'] or [])]
                            for p, f in pairs)
    values = {'status': status_text(ran), 'stderr': 'empty' if not ran.err else 'nonempty',
              'exact': yes(ran.out == render_all(families)),
              'families-complete': yes([(p['name'], p['id']) for p in shown]
                                       == [(f['name'], f['id']) for f in families]),
              'records': yes(records), 'groups': yes(groups), 'commands': yes(commands), 'caps-hex': yes(caps)}
    for bit, phrase, suffix in WORDS:
        values['word-' + suffix] = yes(commands and all(
            op['words'] is not None and (phrase in op['words']) == bool(want['flags'] & bit)
            for p, f in pairs for op, want in zip(p['ops'], f['ops'] or [])))
    values['semantic'] = yes(records and groups and caps and not parsed['junk']
                             and all(values['word-' + suffix] == 'yes' for _, _, suffix in WORDS))
    return values, parsed


def record_values(ran, family, baseline):
    values, parsed = listing_values(ran, [family])
    shown = parsed['families']
    values['one-record'] = yes(len(shown) == 1 and not parsed['junk'])
    values['id-0x10'] = yes(len(shown) == 1 and shown[0]['id'] == GENL_ID_CTRL)
    values['groups-notify'] = yes(len(shown) == 1 and [g['name'] for g in shown[0]['groups']] == ['notify']
                                  and values['groups'] == 'yes')
    values['same-as-name'] = yes(baseline is not None and ran.out == baseline)
    return values


def kernel_error_text(number):
    return ('RTNETLINK answers: %s\nError talking to the kernel\n' % os.strerror(number)).encode()


def kernel_error_values(ran, number, reference):
    want = kernel_error_text(number)
    values = {'failed': yes(not ran.timed_out and ran.status not in (0, None)),
              'stdout-empty': yes(ran.out == b''), 'stderr-exact': yes(ran.err == want),
              'iproute2-stderr-same': 'no', 'iproute2-status-same': 'no'}
    if reference is not None and not reference.timed_out:
        values['iproute2-stderr-same'] = yes(reference.err == ran.err)
        values['iproute2-status-same'] = yes(reference.status == ran.status)
    return values


def usage_values(ran, prefix, message_text, counts):
    values = {'status': status_text(ran), 'stdout-empty': yes(ran.out == b''),
              'diag-exact': yes(ran.err == prefix + b'genl: ' + message_text.encode() + b'\n'),
              'sockets': 'untraced'}
    if counts is not None:
        values['sockets'] = socket_text(counts)
    return values


def control_values(ran, counts):
    return {'sockets': socket_text(counts), 'no-invalid-diag': yes(b'invalid family id' not in ran.err)}


def raw_errno(nl, label, lookup):
    kind, value = lookup
    started = time.monotonic()
    if kind == 'id':
        conversation = nl.get_family(label, family_id=int(value, 0))
    else:
        conversation = nl.get_family(label, name=value)
    elapsed = time.monotonic() - started
    if conversation.messages or conversation.error != errno.ENOENT:
        raise ControlFailure('%s: the kernel does not answer %s %s with ENOENT (error %d, %d records)'
                             % (label, kind, value, conversation.error, len(conversation.messages)))
    if elapsed > 1.5:
        raise ControlFailure('%s: the kernel needed %.1f s to refuse %s %s; the candidate gives up '
                             'after 2 s, so this would not test the error path' % (label, elapsed, kind, value))
    return conversation.error, elapsed


def usage_prefix():
    """How this bash frames a builtin usage error, learned from the reference shell (not the candidate)."""
    ran = spawn([REFERENCE_BASH, '--noprofile', '--norc', '-c', 'cd -z', 'genl-case'], env=dict(os.environ))
    match = re.fullmatch(rb'(genl-case: (?:line [0-9]+: )?)cd: -z: invalid option', ran.err.split(b'\n', 1)[0])
    if ran.timed_out or ran.status != 2 or match is None:
        raise ControlFailure('the reference bash does not frame a builtin usage error as expected: '
                             'status=%r stderr=%r' % (ran.status, ran.err))
    return match.group(1)


# ---------------------------------------------------------------------------
# Scenario execution.
# ---------------------------------------------------------------------------

def observe_scenario(shell, scenario):
    spec = SCENARIOS[scenario]
    needs = set(spec['needs'])
    context, families, ctrl, dynamic = {}, [], None, None
    nl = None
    if needs & {'oracle', 'errors'}:
        nl = Netlink('oracle-transcript.jsonl')
    if 'oracle' in needs:
        before = snapshot(nl, 'before')
        families = before['families']
        ctrl = nlctrl_of(families)
        if 'dynamic' in needs:
            dynamic = choose_dynamic(families)
            context = {'dyn_name': dynamic['name'], 'dyn_id_hex': '0x%x' % dynamic['id'],
                       'dyn_id_dec': str(dynamic['id'])}
        if 'caps' in needs:
            capability_coverage(families)
        if 'span' in needs:
            multipart_span(before)
    prefix = usage_prefix() if 'usage' in needs else None
    if prefix is not None:
        # Diagnostic only: how this shell frames the usage error of a stock builtin, for telling a shell-wide
        # framing difference from a genl defect. It never feeds an expected value.
        probe = spawn([shell, '--noprofile', '--norc', '-c', 'cd -z', 'genl-case'], env=dict(os.environ))
        observe({'scenario': scenario, 'label': '_framing-diagnostic', 'reference_prefix_base64': b64(prefix),
                 'candidate_status': probe.status, 'candidate_stderr_base64': b64(probe.err)})
    traced = 'observer' in needs
    results, printed = {}, []
    for line in spec['lines']:
        argv = [arg.format(**context) for arg in line['args']]
        label = line['label']
        extra = {}
        number = None
        if 'lookup' in line:
            number, elapsed = raw_errno(nl, 'errno-' + label, line['lookup'])
            extra['oracle_errno'], extra['oracle_seconds'] = number, elapsed
            if line['lookup'][0] == 'id' and int(line['lookup'][1], 0) in {f['id'] for f in families}:
                raise ControlFailure('%s: id %s is registered, so it is not an unknown id' % (label, line['lookup'][1]))
        ran, counts = run_candidate(shell, argv, label, traced)
        reference = run_iproute2(argv) if (line.get('reference') or line['kind'] == 'kernel-error') else None
        kind = line['kind']
        if kind == 'record':
            family = ctrl if line['family'] == 'ctrl' else dynamic
            baseline = results.get(line.get('baseline'))
            values = record_values(ran, family, baseline)
            extra['expected_stdout_base64'] = b64(render_all([family]))
            if reference is not None:
                extra['iproute2_same_table'] = yes(not reference.timed_out and same_table(
                    parse_listing(reference.out.decode('utf-8', 'surrogateescape')), [family]))
        elif kind == 'listing':
            values, _parsed = listing_values(ran, families)
            if counts is not None:
                values['sockets'] = socket_text(counts)
                values['recv-buffers-ge2'] = yes(counts['markers'] == 1 and counts['recvmsg'] >= 2)
            extra['expected_stdout_base64'] = b64(render_all(families))
            if reference is not None:
                extra['iproute2_same_table'] = yes(not reference.timed_out and same_table(
                    parse_listing(reference.out.decode('utf-8', 'surrogateescape')), families))
        elif kind == 'kernel-error':
            values = kernel_error_values(ran, number, reference)
            extra['expected_stderr_base64'] = b64(kernel_error_text(number))
        elif kind == 'usage':
            values = usage_values(ran, prefix, line['message'], counts)
        else:
            values = control_values(ran, counts)
        results[label] = ran.out
        keys = [item.partition('=')[0] for item in line['keys'].split()]
        missing = [key for key in keys if key not in values]
        if missing:
            raise RuntimeError('internal: no value computed for %s of %s' % (missing, label))
        row = {'scenario': scenario, 'label': label, 'argv': argv, 'status': ran.status,
               'timed_out': ran.timed_out, 'stdout_base64': b64(ran.out), 'stderr_base64': b64(ran.err),
               'raw_stdout_base64': b64(ran.raw_out), 'values': values, 'trace': counts, **extra}
        if reference is not None:
            row['iproute2'] = {'status': reference.status, 'timed_out': reference.timed_out,
                               'stdout_base64': b64(reference.out), 'stderr_base64': b64(reference.err)}
        observe(row)
        printed.append(label + ' ' + ' '.join('%s=%s' % (key, values[key]) for key in keys))
    if 'oracle' in needs:
        after = snapshot(nl, 'after')
        if after['families'] != families:
            raise ControlFailure('the kernel family table changed while the candidate was observed')
    if nl is not None:
        nl.close()
    for text in printed:
        print(text, flush=True)


# ---------------------------------------------------------------------------
# Independent controls (setup mode). A failed control is invalid evidence.
# ---------------------------------------------------------------------------

def check(condition, reason):
    if not condition:
        raise ControlFailure(reason)


def known_answer_tests():
    """Calibrate builder and parser on hand-encoded and synthetic vectors, before the kernel is asked."""
    passed = []

    def expect(condition, name):
        check(condition, 'oracle known-answer test failed: ' + name)
        passed.append(name)

    def rejects(action, name):
        try:
            action()
        except ProtocolError:
            passed.append(name)
        else:
            raise ControlFailure('oracle known-answer test failed: ' + name)

    expect(attribute(2, b'ab\0') == bytes.fromhex('0700020061620000'), 'attribute header, length and padding')
    expect(message(0x10, 2, 5, 7, b'\x01\x01\x00\x00') == bytes.fromhex('1400000010000200050000000700000001010000'),
           'netlink message header')

    def family(seq, pid, name, number, version, hdrsize, maxattr, ops, groups, nested=0, flags=NLM_F_MULTI):
        attrs = (attribute(CTRL_ATTR_FAMILY_NAME, name.encode() + b'\0') + attribute(CTRL_ATTR_FAMILY_ID, U16.pack(number))
                 + attribute(CTRL_ATTR_VERSION, U32.pack(version)) + attribute(CTRL_ATTR_HDRSIZE, U32.pack(hdrsize))
                 + attribute(CTRL_ATTR_MAXATTR, U32.pack(maxattr)))
        if ops is not None:
            body = b''.join(attribute((index + 1) | nested, attribute(CTRL_ATTR_OP_ID, U32.pack(op))
                                      + attribute(CTRL_ATTR_OP_FLAGS, U32.pack(op_flags)))
                            for index, (op, op_flags) in enumerate(ops))
            attrs += attribute(CTRL_ATTR_OPS | nested, body)
        if groups is not None:
            body = b''.join(attribute((index + 1) | nested, attribute(CTRL_ATTR_MCAST_GRP_ID, U32.pack(group))
                                      + attribute(CTRL_ATTR_MCAST_GRP_NAME, group_name.encode() + b'\0'))
                            for index, (group, group_name) in enumerate(groups))
            attrs += attribute(CTRL_ATTR_MCAST_GROUPS | nested, body)
        return message(GENL_ID_CTRL, flags, seq, pid, GENL.pack(CTRL_CMD_NEWFAMILY, 2, 0) + attrs)

    alpha = {'cmd': 1, 'name': 'alpha', 'id': 0x11, 'version': 1, 'hdrsize': 0, 'maxattr': 3,
             'ops': [{'index': 1, 'id': 3, 'flags': 6}, {'index': 2, 'id': 10, 'flags': 12}],
             'groups': [{'index': 1, 'id': 0x20, 'name': 'grp'}]}
    beta = {'cmd': 1, 'name': 'be', 'id': 0x12, 'version': 2, 'hdrsize': 4, 'maxattr': 5, 'ops': None, 'groups': None}
    seq, pid = 0x1234, 0x77
    done = message(NLMSG_DONE, NLM_F_MULTI, seq, pid, S32.pack(0))
    stranger = family(seq + 1, pid, 'stranger', 0x13, 1, 0, 0, None, None)
    wrong_port = family(seq, pid + 1, 'port', 0x14, 1, 0, 0, None, None)
    plain_b = family(seq, pid, 'be', 0x12, 2, 4, 5, None, None)
    for nested in (0, NLA_F_NESTED):
        plain_a = family(seq, pid, 'alpha', 0x11, 1, 0, 3, [(3, 6), (10, 12)], [(0x20, 'grp')], nested)
        conversation = Conversation(seq, pid, True)
        conversation.feed(stranger + plain_a + wrong_port + plain_b)
        expect(not conversation.complete, 'a dump is incomplete before NLMSG_DONE (nested=%#x)' % nested)
        conversation.feed(done)
        expect(conversation.complete and conversation.buffers == 2 and conversation.data_buffers == 1,
               'multi-message buffer, then a DONE-only buffer (nested=%#x)' % nested)
        expect(len(conversation.foreign) == 2, 'foreign sequence and port messages ignored (nested=%#x)' % nested)
        expect([parse_family(m['payload']) for m in conversation.messages] == [alpha, beta],
               'nested operation and group arrays, padding and flag masking (nested=%#x)' % nested)
        expect(conversation.multi and not conversation.interrupted, 'NLM_F_MULTI observed on every record')
        single = Conversation(seq, pid, True)
        single.feed(plain_a + plain_b + done)
        expect(single.complete and single.buffers == 1, 'records and NLMSG_DONE in one buffer (nested=%#x)' % nested)
    error = Conversation(seq, pid, False)
    error.feed(message(NLMSG_ERROR, 0, seq, pid, S32.pack(-errno.ENOENT) + b'\0' * NLMSG.size))
    expect(error.complete and error.error == errno.ENOENT and not error.messages, 'NLMSG_ERROR carries errno ENOENT')
    acked = Conversation(seq, pid, False, expect_ack=True)
    acked.feed(family(seq, pid, 'be', 0x12, 2, 4, 5, None, None, flags=0))
    expect(not acked.complete, 'a requested acknowledgement is still awaited after the record')
    acked.feed(message(NLMSG_ERROR, 0, seq, pid, S32.pack(0) + b'\0' * NLMSG.size))
    expect(acked.complete and acked.acked and acked.error == 0, 'NLMSG_ERROR with code 0 is an acknowledgement')
    rejects(lambda: Conversation(seq, pid, True).feed(b'\0' * 8), 'truncated netlink header rejected')
    rejects(lambda: Conversation(seq, pid, True).feed(plain_b[:-1]), 'message longer than its buffer rejected')
    rejects(lambda: Conversation(seq, pid, False).feed(done), 'NLMSG_DONE for a non-dump rejected')
    rejects(lambda: Conversation(seq, pid, True).feed(done + plain_b), 'message after NLMSG_DONE rejected')
    rejects(lambda: parse_family(GENL.pack(1, 2, 0) + NLA.pack(2, 1)), 'attribute shorter than its header rejected')
    rejects(lambda: parse_family(GENL.pack(1, 2, 0) + attribute(2, b'x') + attribute(2, b'y\0')),
            'repeated attribute rejected')
    rejects(lambda: parse_family(GENL.pack(1, 2, 0) + attribute(2, b'x')), 'unterminated family name rejected')
    return passed


def kernel_controls(nl):
    """The real kernel, asked by name, by id, by dump, interleaved, with ACK and with errors."""
    facts = {}
    by_name = nl.get_family('control-by-name', name='nlctrl')
    check(len(by_name.messages) == 1 and not by_name.foreign, 'a lookup by name returned %d records' % len(by_name.messages))
    ctrl = families_of(by_name, 'control-by-name')[0]
    check(ctrl['name'] == 'nlctrl' and ctrl['id'] == GENL_ID_CTRL, 'nlctrl is not family 0x10')
    check(ctrl['version'] >= 2 and ctrl['hdrsize'] == 0, 'nlctrl version/header size are implausible: %r' % ctrl)
    both = GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP
    check(ctrl['ops'] and ({o['id']: o['flags'] for o in ctrl['ops']}.get(CTRL_CMD_GETFAMILY, 0) & both) == both,
          'nlctrl does not list GETFAMILY as doit+dumpit')
    check(ctrl['groups'] and [g['name'] for g in ctrl['groups']] == ['notify'],
          'nlctrl does not have exactly the multicast group notify')
    for part in ('ops', 'groups'):
        check([e['index'] for e in ctrl[part]] == list(range(1, len(ctrl[part]) + 1)),
              'nlctrl %s array indexes are not 1..n' % part)
    by_id = nl.get_family('control-by-id', family_id=GENL_ID_CTRL)
    check(families_of(by_id, 'control-by-id') == [ctrl], 'a lookup by id 0x10 differs from the lookup by name')
    # Only a dump can list families: a plain GETFAMILY with neither name nor id is refused by the kernel.
    plain = nl.start('control-no-dump', CTRL_CMD_GETFAMILY, NLM_F_REQUEST)
    nl.wait('control-no-dump', [plain])
    check(not plain.messages and plain.error != 0,
          'a GETFAMILY request without NLM_F_DUMP and without an attribute was not refused')
    facts['no-dump-request-errno'] = plain.error
    first, second = snapshot(nl, 'control-first'), snapshot(nl, 'control-second')
    check(first['families'] == second['families'], 'two consecutive dumps differ')
    families = first['families']
    check(ctrl in families, 'the dump record of nlctrl differs from the lookups')
    check(len({f['id'] for f in families}) == len(families) and len({f['name'] for f in families}) == len(families),
          'the dump repeats a family id or name')
    check(all(GENL_MIN_ID <= f['id'] <= GENL_MAX_ID and 0 < len(f['name']) < 16 for f in families),
          'a family id or name is outside the generic netlink limits')
    for family in families:
        for part in ('ops', 'groups'):
            check([e['index'] for e in family[part] or []] == list(range(1, len(family[part] or []) + 1)),
                  '%s %s array indexes are not 1..n' % (family['name'], part))
    # Sequence handling against the real kernel: two requests in flight, replies sorted by sequence.
    one = nl.start('control-interleave-name', CTRL_CMD_GETFAMILY, NLM_F_REQUEST, name_attribute('nlctrl'))
    two = nl.start('control-interleave-id', CTRL_CMD_GETFAMILY, NLM_F_REQUEST, id_attribute(GENL_ID_CTRL))
    nl.wait('control-interleave', [one, two])
    check(one.seq != two.seq and len(one.messages) == 1 and len(two.messages) == 1
          and [f['seq'] for f in one.foreign] == [two.seq] and [f['seq'] for f in two.foreign] == [one.seq],
          'interleaved requests were not separated by sequence number')
    check(families_of(one, 'interleave') == families_of(two, 'interleave') == [ctrl],
          'interleaved replies differ from the single lookups')
    acked = nl.get_family('control-ack', name='nlctrl', ack=True)
    check(acked.acked and acked.error == 0 and families_of(acked, 'control-ack') == [ctrl],
          'a lookup with NLM_F_ACK did not return the record and then an acknowledgement')
    for lookup in (('name', 'bashos_nofam'), ('id', '0x3ff')):
        number, elapsed = raw_errno(nl, 'control-unknown-' + lookup[0], lookup)
        facts['unknown-%s' % lookup[0]] = {'errno': number, 'seconds': round(elapsed, 3)}
    check(0x3ff not in {f['id'] for f in families}, 'family id 0x3ff is registered')
    facts.update({'families': len(families), 'dump_buffers': first['buffers'], 'dump_data_buffers': first['data_buffers'],
                  'dump_bytes': first['bytes'], 'nlctrl': ctrl})
    return families, first, facts


def iproute2_crosscheck(families):
    ran = run_iproute2(['ctrl', 'list'])
    check(not ran.timed_out and ran.status == 0, 'iproute2 "genl ctrl list" failed: status=%r stderr=%r'
          % (ran.status, ran.err))
    parsed = parse_listing(ran.out.decode('utf-8', 'surrogateescape'))
    check([core_of(p) for p in parsed['families']] == [core_of(f) for f in families],
          'the raw oracle and iproute2 disagree on the family table (name, id, version, header size, max attribs)')
    Path('iproute2-list.txt').write_bytes(ran.out)
    return {'core_agrees': True, 'operations_and_groups_agree': same_table(parsed, families)}


def capability_coverage(families):
    ops = [op for f in families for op in f['ops'] or []]
    missing = [phrase for bit, phrase, _suffix in WORDS if not any(op['flags'] & bit for op in ops)]
    check(not missing, 'the guest family table has no operation exercising: ' + ', '.join(missing))
    return {'operations': len(ops), 'with_bit': {suffix: sum(1 for op in ops if op['flags'] & bit)
                                                  for bit, _phrase, suffix in WORDS},
            'without_any_flag_word': sum(1 for op in ops if not op['flags'] & 0xf)}


def multipart_span(first):
    check(first['data_buffers'] >= 2, 'the guest family table fits in %d receive buffer(s) with records, so no '
          'multipart consumption across buffers can be observed' % first['data_buffers'])


def observer_controls(receives):
    """The seccomp observer must count netlink sockets (and, when asked, recvmsg calls) after the stdout marker."""
    passed = []
    scripts = [("import os,socket; os.write(1,b'GENL-BEGIN:0\\n'); socket.socket(16,socket.SOCK_RAW,16)", 0, 1),
               ("import os; os.write(1,b'GENL-BEGIN:0\\n')", 0, 0),
               ("import os,socket; socket.socket(16,socket.SOCK_RAW,16); os.write(1,b'GENL-BEGIN:0\\n')", 1, 0)]
    for index, (code, before, after) in enumerate(scripts):
        log = Path('control-socket-%d.jsonl' % index)
        ran = spawn(tracing(log) + [PYTHON, '-c', code], env=dict(os.environ))
        check(not ran.timed_out and ran.status == 0 and ran.out == CONTROL_MARKER and not ran.err,
              'observer control %d did not run cleanly: %r %r' % (index, ran.status, ran.err))
        counts = trace_counts(log, CONTROL_MARKER)
        check((counts['markers'], counts['before_sockets'], counts['netlink_sockets']) == (1, before, after),
              'observer control %d counted %r' % (index, counts))
        passed.append('socket-%d' % index)
    if not receives:
        return passed
    log = Path('control-recvmsg.jsonl')
    ran = spawn(tracing(log) + [PYTHON, str(SELF), 'child-dump'], env=dict(os.environ))
    match = re.fullmatch(rb'GENL-BEGIN:0\nRECVMSG:([0-9]+)\n', ran.out)
    check(not ran.timed_out and ran.status == 0 and match is not None and not ran.err,
          'the recvmsg observer control did not run cleanly: %r %r %r' % (ran.status, ran.out, ran.err))
    counts = trace_counts(log, CONTROL_MARKER)
    check(counts['markers'] == 1 and counts['netlink_sockets'] == 1 and counts['recvmsg'] == int(match.group(1)) >= 1,
          'the observer counted %r recvmsg calls where the child made %s' % (counts, match.group(1).decode()))
    passed.append('recvmsg-%d' % counts['recvmsg'])
    return passed


def setup(scenario):
    needs = set(SCENARIOS[scenario]['needs'])
    report = {'scenario': scenario, 'controls': []}
    if needs & {'oracle', 'errors'}:
        report['controls'] += ['oracle known answers: %d' % len(known_answer_tests())]
        nl = Netlink('oracle-setup-transcript.jsonl')
        families, first, facts = kernel_controls(nl)
        nl.close()
        report['kernel'] = {key: value for key, value in facts.items() if key != 'nlctrl'}
        report['families'] = [{'name': f['name'], 'id': f['id'], 'ops': len(f['ops'] or []),
                               'groups': len(f['groups'] or [])} for f in families]
        report['controls'].append('kernel')
        if 'dynamic' in needs:
            report['dynamic'] = choose_dynamic(families)['name']
        if 'caps' in needs:
            report['capabilities'] = capability_coverage(families)
            report['controls'].append('capability coverage')
        if 'span' in needs:
            multipart_span(first)
            report['controls'].append('multipart span')
        if 'crosscheck' in needs:
            report['iproute2'] = iproute2_crosscheck(families)
            report['controls'].append('iproute2 table cross-check')
    if 'iproute2' in needs:
        ran = run_iproute2(['ctrl', 'get', 'id', '16'])
        check(not ran.timed_out and ran.status == 0 and parse_listing(ran.out.decode())['families'],
              'the reference iproute2 genl cannot look up family 0x10: status=%r stderr=%r' % (ran.status, ran.err))
        report['controls'].append('iproute2 reference runs')
    if 'usage' in needs:
        report['usage_prefix'] = usage_prefix().decode()
        report['controls'].append('usage framing and status')
    if 'observer' in needs:
        report['observer'] = observer_controls('span' in needs)
        report['controls'].append('syscall observer')
    print(json.dumps(report, sort_keys=True), flush=True)


def child_dump():
    """Calibration child: a raw dump through recvmsg(2), reporting how many receives it needed."""
    os.write(1, CONTROL_MARKER)
    nl = Netlink('child-dump-transcript.jsonl')
    conversation = nl.dump('child-dump')
    nl.close()
    os.write(1, b'RECVMSG:%d\n' % conversation.buffers)


def main(argv):
    if argv == ['child-dump']:
        require_guest()
        child_dump()
        return 0
    if len(argv) != 2 or argv[1] not in SCENARIOS:
        sys.stderr.write('usage: genl-review-observer.py setup|SHELL %s\n' % '|'.join(sorted(SCENARIOS)))
        return 2
    require_guest()
    try:
        if argv[0] == 'setup':
            setup(argv[1])
        else:
            observe_scenario(argv[0], argv[1])
    except ControlFailure as exc:
        print('CONTROL-INVALID %s %s: %s' % ('setup' if argv[0] == 'setup' else 'observe', argv[1], exc), flush=True)
        return 97
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
