#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic peers, bound only to the guest's private loopback interface.

Every response here is written from the protocol specifications (RFC 9110 and
RFC 9112 for HTTP/1.1, RFC 1035 for DNS, the documented BASHSSH1 framing for
the native ssh transport), never from a candidate or reference transcript.
Peers record what they receive so a case can assert the request wire shape.

A peer is a context manager yielding (port, records, errors). Records are
dictionaries; errors are strings and turn the side into a failure (ERROR for
the reference, FAIL for the candidate). Every peer has a request limit, a
socket timeout and bounded shutdown, and reports itself if it cannot stop.
"""
import base64
import contextlib
import datetime
import hashlib
import ipaddress
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

HOST = "127.0.0.1"
HEAD_LIMIT = 16 * 1024
BODY_LIMIT = 1024 * 1024
CONNECTION_LIMIT = 16
IO_TIMEOUT = 3.0
STOP_TIMEOUT = 5.0
READY_TIMEOUT = 5.0
BODY = b"fixture\x00body\n"
KINDS = ("http", "tcp", "tcp-hold", "tcp-eof", "tcp-ports", "tcp-client", "udp", "udp-client", "udp-clients",
         "dns", "dns-tls", "https", "bashssh")
# TLS peers publish their throwaway CA certificates here (public, readable by
# the unprivileged sides). Private keys never leave the peer's 0700 directory,
# which is deleted as soon as the context has loaded them.
TLS_EXPORT = "/tmp/parity-peer-tls"
# Bytes 0x00-0xFF once each: a response body exercising NUL and every high-bit octet.
ALL_OCTETS = bytes(range(256))


def b64(data):
    return base64.b64encode(data).decode()


def listener(kind, port):
    sock = socket.socket(socket.AF_INET, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, port))
    if kind == socket.SOCK_STREAM:
        sock.listen(8)
    sock.settimeout(0.1)
    return sock


def recv_until(conn, done, limit):
    """Read until done(buffer) is true, EOF, or limit; returns (bytes, eof)."""
    data = bytearray()
    while not done(data):
        if len(data) > limit:
            raise ValueError("request exceeds %d bytes" % limit)
        chunk = conn.recv(4096)
        if not chunk:
            return bytes(data), True
        data.extend(chunk)
    return bytes(data), False


def recv_more(conn, buffered, where):
    """One more read of a message whose framing promises more bytes."""
    if len(buffered) > BODY_LIMIT:
        raise ValueError("message exceeds %d bytes" % BODY_LIMIT)
    data = conn.recv(4096)
    if not data:
        raise ValueError("connection closed inside " + where)
    return data


def wait_bound(port, udp, stopping):
    """Wait until something in this namespace binds 127.0.0.1:port.

    /proc/net is per network namespace, so this only sees the guest's private
    loopback namespace. TCP needs LISTEN (0A); UDP needs any bound socket."""
    table = "/proc/net/udp" if udp else "/proc/net/tcp"
    local = "0100007F:%04X" % port
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline and not stopping.is_set():
        with open(table) as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if fields[1] == local and (udp or fields[3] == "0A"):
                    return True
        time.sleep(0.02)
    return False


# ---------------------------------------------------------------- HTTP/1.1

def parse_head(head):
    """Parse an RFC 9112 request head (without the final CRLF CRLF)."""
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or not parts[0].isalpha() or not parts[2].startswith(b"HTTP/1."):
        raise ValueError("malformed request line")
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        # RFC 9112 5.1/5.2: no whitespace before the colon, no obs-fold.
        if not colon or not name or name != name.strip() or line[:1] in (b" ", b"\t"):
            raise ValueError("malformed header field")
        headers.append((name.decode("latin-1").lower(), value.strip(b" \t").decode("latin-1")))
    return {"method": parts[0].decode(), "target": parts[1].decode("latin-1"),
            "version": parts[2].decode(), "request_line": lines[0].decode("latin-1"),
            "headers": headers}


def decode_chunked(data):
    """Decode an RFC 9112 7.1 chunked body; returns (body, rest) or None if incomplete."""
    body = bytearray()
    offset = 0
    while True:
        end = data.find(b"\r\n", offset)
        if end < 0:
            return None
        size = int(data[offset:end].split(b";")[0].strip(), 16)
        offset = end + 2
        if size == 0:
            trailer = data.find(b"\r\n\r\n", offset - 2)
            if trailer < 0:
                return None
            return bytes(body), data[trailer + 4:]
        if len(data) < offset + size + 2:
            return None
        if data[offset + size:offset + size + 2] != b"\r\n":
            raise ValueError("chunk not terminated by CRLF")
        body.extend(data[offset:offset + size])
        if len(body) > BODY_LIMIT:
            raise ValueError("chunked body exceeds limit")
        offset += size + 2


def response(status, reason, headers=(), body=b"", length=True):
    lines = ["HTTP/1.1 %d %s" % (status, reason)]
    lines += ["%s: %s" % pair for pair in headers]
    if length:
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def route(request, body, port):
    """Fixed resource table. Returns raw response bytes, or a special action."""
    path = request["target"].split("?", 1)[0]
    method = request["method"]
    octets = [("Content-Type", "application/octet-stream")]
    text = [("Content-Type", "text/plain")]
    if path == "/body":
        data = response(200, "OK", octets, BODY)
    elif path == "/chunked":
        data = response(200, "OK", octets + [("Transfer-Encoding", "chunked")], length=False)
        data += b"7\r\nfixture\r\n6\r\n\x00body\n\r\n0\r\n\r\n"
    elif path == "/chunked-trailer":
        # RFC 9112 7.1.1 extensions and 7.1.2 trailer fields are not content.
        data = response(200, "OK", octets + [("Transfer-Encoding", "chunked"), ("Trailer", "X-Fixture-Trailer")], length=False)
        data += b"7;ext=one\r\nfixture\r\n6;ext=\"two\"\r\n\x00body\n\r\n0\r\nX-Fixture-Trailer: done\r\n\r\n"
    elif path == "/eof":
        # RFC 9112 6.3 rule 8: no framing header, the body ends at close.
        data = response(200, "OK", octets, length=False) + BODY
    elif path == "/short":
        data = response(200, "OK", octets + [("Content-Length", "20")], length=False) + BODY
    elif path == "/slow":
        return "slow", response(200, "OK", octets + [("Content-Length", str(len(BODY)))], length=False)
    elif path == "/redirect":
        data = response(302, "Found", [("Location", "/body")])
    elif path == "/all-octets":
        data = response(200, "OK", octets, ALL_OCTETS)
    elif path == "/chunked-octets":
        # The same 256 octets split across three chunks (RFC 9112 7.1).
        chunks = (ALL_OCTETS[:100], ALL_OCTETS[100:200], ALL_OCTETS[200:])
        data = response(200, "OK", octets + [("Transfer-Encoding", "chunked")], length=False)
        data += b"".join(b"%x\r\n" % len(c) + c + b"\r\n" for c in chunks) + b"0\r\n\r\n"
    elif path == "/dns-query":
        # RFC 8484 4.1: POST body or GET ?dns= (base64url, no padding) is a DNS message.
        try:
            if method == "POST":
                message = body
            else:
                value = dict(p.split("=", 1) for p in request["target"].partition("?")[2].split("&") if "=" in p).get("dns", "")
                message = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            reply = answer(parse_query(message), "tcp")
            data = response(200, "OK", [("Content-Type", "application/dns-message")], reply)
        except (ValueError, UnicodeDecodeError, struct.error):
            data = response(400, "Bad Request", text, b"bad dns message\n")
    elif path == "/dir/redirect-relative":
        # RFC 3986 5.2: a relative-path reference merged with /dir/, dot segments removed.
        data = response(302, "Found", [("Location", "../body?from=relative")])
    elif path == "/dir/redirect-sibling":
        data = response(302, "Found", [("Location", "sub/../../echo")])
    elif path == "/redirect-long":
        # A deterministic multi-kilobyte target: /echo?sig= followed by 3000 octets.
        data = response(302, "Found", [("Location", "/echo?sig=" + "a" * 3000)])
    elif path == "/redirect-too-long":
        data = response(302, "Found", [("Location", "/echo?sig=" + "b" * 9000)])
    elif path == "/redirect-absolute":
        data = response(301, "Moved Permanently", [("Location", "http://%s:%d/body" % (HOST, port))])
    elif path == "/see-other":
        data = response(303, "See Other", [("Location", "/method")])
    elif path == "/temporary":
        data = response(307, "Temporary Redirect", [("Location", "/echo")])
    elif path == "/loop":
        data = response(302, "Found", [("Location", "/loop")])
    elif path == "/method":
        data = response(200, "OK", text, method.encode() + b"\n" if method != "HEAD" else b"")
    elif path == "/echo":
        data = response(200, "OK", octets, body)
    elif path == "/cookie":
        data = response(200, "OK", text + [("Set-Cookie", "session=abc123; Path=/")], b"ok\n")
    elif path == "/show-cookie":
        cookie = dict(request["headers"]).get("cookie", "none")
        data = response(200, "OK", text, cookie.encode("latin-1") + b"\n")
    elif path == "/no-content":
        data = response(204, "No Content", length=False)
    elif path == "/error":
        data = response(500, "Internal Server Error", text, b"error\n")
    else:
        data = response(404, "Not Found", text, b"missing\n")
    if method == "HEAD" and path not in ("/no-content",):
        data = data[:data.index(b"\r\n\r\n") + 4]
    return "send", data


def http_connection(conn, index, port, records, stopping):
    head, eof = recv_until(conn, lambda d: b"\r\n\r\n" in d, HEAD_LIMIT)
    if eof and not head:
        return
    if b"\r\n\r\n" not in head:
        raise ValueError("connection closed inside the request head")
    head, rest = head.split(b"\r\n\r\n", 1)
    request = parse_head(head)
    fields = {}
    for name, value in request["headers"]:
        fields[name] = fields[name] + ", " + value if name in fields else value
    if fields.get("expect", "").lower() == "100-continue":
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
    if "transfer-encoding" in fields:
        if "content-length" in fields:
            raise ValueError("request has both Transfer-Encoding and Content-Length")
        if fields["transfer-encoding"].lower() != "chunked":
            raise ValueError("unsupported request transfer coding")
        framing = "chunked"
        while decode_chunked(rest) is None:
            rest += recv_more(conn, rest, "a chunked body")
        body, rest = decode_chunked(rest)
    elif "content-length" in fields:
        framing = "content-length"
        if not fields["content-length"].isdigit() or int(fields["content-length"]) > BODY_LIMIT:
            raise ValueError("invalid Content-Length")
        size = int(fields["content-length"])
        while len(rest) < size:
            rest += recv_more(conn, rest, "the request body")
        body, rest = rest[:size], rest[size:]
    else:
        framing = "none"
        body = b""
    record = {"connection": index, "method": request["method"], "path": request["target"],
              "version": request["version"], "request_line": request["request_line"],
              "header_names": [name for name, _ in request["headers"]],
              # Order-insensitive projection for semantic header-set comparison.
              "header_set": sorted({name for name, _ in request["headers"]} - {"user-agent"}),
              "body_base64": b64(body), "body_framing": framing}
    record.update(("header:" + name, value) for name, value in fields.items())
    if request["target"].split("?", 1)[0] == "/dns-query":
        # Decoded RFC 8484 payload, so DoH cases can compare DNS fields.
        with contextlib.suppress(ValueError, UnicodeDecodeError, struct.error):
            if request["method"] == "POST":
                wire = body
            else:
                value = request["target"].partition("dns=")[2].split("&")[0]
                wire = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            record.update(("dns_" + key, value) for key, value in dns_record(parse_query(wire), "https").items()
                          if key in ("qname", "qtype", "qclass", "opcode", "rd"))
    if rest:
        record["pipelined_bytes"] = len(rest)
    records.append(record)
    action, data = route(request, body, port)
    conn.sendall(data)
    if action == "slow":
        # Withhold the promised body until the client gives up or the peer stops.
        conn.settimeout(0.1)
        deadline = time.monotonic() + STOP_TIMEOUT
        while not stopping.is_set() and time.monotonic() < deadline:
            try:
                if not conn.recv(4096):
                    return
            except socket.timeout:
                continue
            except OSError:
                return
    with contextlib.suppress(OSError):
        conn.shutdown(socket.SHUT_WR)
    # Drain briefly so an unread request byte cannot turn close into RST.
    conn.settimeout(0.2)
    with contextlib.suppress(OSError):
        while conn.recv(4096):
            pass


def serve_stream(server, handle, errors, stopping):
    """Accept sequential connections until stopped; one handler per connection."""
    count = 0
    while not stopping.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError as exc:
            if not stopping.is_set():
                errors.append("accept: %s" % exc)
            return
        count += 1
        with conn:
            if count > CONNECTION_LIMIT:
                errors.append("connection limit exceeded")
                return
            conn.settimeout(IO_TIMEOUT)
            try:
                handle(conn, count)
            except (OSError, ValueError) as exc:
                errors.append("connection %d: %s: %s" % (count, type(exc).__name__, exc))


# ------------------------------------------------------------- DNS (RFC 1035)

A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, OPT = 1, 2, 5, 6, 12, 15, 16, 28, 41
TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR", MX: "MX",
              TXT: "TXT", AAAA: "AAAA", OPT: "OPT"}
ORIGIN = "example.test"
TTL = 300
SOA_DATA = ("ns1.example.test", "hostmaster.example.test", 2026102601, 7200, 3600, 1209600, 300)
ZONE = {
    ("example.test", SOA): [SOA_DATA],
    ("example.test", NS): ["ns1.example.test"],
    ("example.test", MX): [(10, "mail.example.test"), (20, "backup.example.test")],
    ("ns1.example.test", A): ["192.0.2.53"],
    ("www.example.test", A): ["192.0.2.10"],
    ("www.example.test", AAAA): ["2001:db8::10"],
    ("alias.example.test", CNAME): ["www.example.test"],
    ("txt.example.test", TXT): [["hello world"], ["part one", "part two"]],
    ("big.example.test", A): ["198.51.100.%d" % n for n in range(1, 101)],
    ("10.2.0.192.in-addr.arpa", PTR): ["www.example.test"],
}
REVERSE_ORIGIN = "2.0.192.in-addr.arpa"
# Names whose replies deliberately break RFC 1035 (the client must not print an answer).
SERVFAIL_NAME = "servfail.example.test"      # RCODE 2
MALFORMED = {"short.malformed.example.test": "header cut to 11 octets",
             "pointer.malformed.example.test": "answer owner is a compression pointer past the message end",
             "wrongid.malformed.example.test": "message ID differs from the query ID"}


def encode_name(name):
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return bytes(out) + b"\x00"


def rdata(rtype, value):
    if rtype == A:
        return ipaddress.IPv4Address(value).packed
    if rtype == AAAA:
        return ipaddress.IPv6Address(value).packed
    if rtype in (NS, CNAME, PTR):
        return encode_name(value)
    if rtype == MX:
        return struct.pack("!H", value[0]) + encode_name(value[1])
    if rtype == TXT:
        return b"".join(bytes([len(s.encode())]) + s.encode() for s in value)
    if rtype == SOA:
        return encode_name(value[0]) + encode_name(value[1]) + struct.pack("!5I", *value[2:])
    raise ValueError("no rdata encoder for type %d" % rtype)


def rr(owner, rtype, value):
    data = rdata(rtype, value)
    owner = owner if isinstance(owner, bytes) else encode_name(owner)
    return owner + struct.pack("!HHIH", rtype, 1, TTL, len(data)) + data


def parse_query(message):
    if len(message) < 12:
        raise ValueError("DNS message shorter than its header")
    ident, flags, qd, an, ns, ar = struct.unpack("!6H", message[:12])
    if flags & 0x8000 or qd != 1 or an or ns:
        raise ValueError("not a single-question DNS query")
    offset, labels = 12, []
    while True:
        if offset >= len(message):
            raise ValueError("truncated QNAME")
        size = message[offset]
        if size & 0xC0:
            raise ValueError("compressed QNAME in a query")
        offset += 1
        if size == 0:
            break
        labels.append(message[offset:offset + size].decode("ascii"))
        offset += size
    if offset + 4 > len(message):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", message[offset:offset + 4])
    question_end = offset + 4
    # RFC 6891 6.1.2: an OPT RR has the root owner; its CLASS is the UDP size.
    udp_size, edns = 512, False
    extra = message[question_end:question_end + 5]
    if ar and len(extra) == 5 and extra[0] == 0 and struct.unpack("!H", extra[1:3])[0] == OPT:
        edns = True
        udp_size = struct.unpack("!H", extra[3:5])[0]
    return {"id": ident, "flags": flags, "counts": (qd, an, ns, ar), "qname": ".".join(labels), "qtype": qtype,
            "qclass": qclass, "question": message[12:question_end], "edns": edns,
            "wire_base64": b64(message),
            "wire_id_zero_base64": b64(b"\x00\x00" + message[2:]),
            "advertised_udp_size": udp_size,
            "udp_size": max(512, min(udp_size, 1232)) if edns else 512}


def answer(query, transport):
    """Authoritative answer for the fixed zone, honouring the UDP size limit."""
    name = query["qname"].lower()
    qtype = query["qtype"]
    pointer = b"\xc0\x0c"
    answers, authority, rcode = [], [], 0
    in_zone = name == ORIGIN or name.endswith("." + ORIGIN) or name.endswith("." + REVERSE_ORIGIN)
    if query["qclass"] != 1 or not in_zone:
        rcode = 5
    elif name == SERVFAIL_NAME:
        rcode = 2
    elif name in MALFORMED:
        pass
    else:
        owner, target = pointer, name
        if (name, CNAME) in ZONE and qtype != CNAME:
            target = ZONE[(name, CNAME)][0]
            answers.append(rr(pointer, CNAME, target))
            owner = target
        if (target, qtype) in ZONE:
            answers += [rr(owner, qtype, value) for value in ZONE[(target, qtype)]]
        elif not answers:
            exists = any(key[0] == name for key in ZONE)
            rcode = 0 if exists else 3
            apex = REVERSE_ORIGIN if name.endswith(REVERSE_ORIGIN) else ORIGIN
            authority.append(rr(apex, SOA, SOA_DATA))
    opcode = query["flags"] & 0x7800
    flags = 0x8000 | opcode | 0x0400 | (query["flags"] & 0x0100) | 0x0080 | rcode
    opt = encode_name("") + struct.pack("!HHIH", OPT, 1232, 0, 0) if query["edns"] else b""
    def build(flag_bits, ans, auth):
        header = struct.pack("!6H", query["id"], flag_bits, 1, len(ans), len(auth), 1 if opt else 0)
        return header + query["question"] + b"".join(ans) + b"".join(auth) + opt
    if name == "short.malformed.example.test":
        return build(flags, [], [])[:11]
    if name == "pointer.malformed.example.test":
        bad = struct.pack("!H", 0xC000 | 0x3FFF) + struct.pack("!HHIH", A, 1, TTL, 4) + bytes(4)
        return build(flags, [bad], [])
    if name == "wrongid.malformed.example.test":
        wrong = dict(query, id=query["id"] ^ 0xFFFF)
        return answer(dict(wrong, qname="www.example.test", question=query["question"]), transport)
    message = build(flags, answers, authority)
    if transport == "udp" and len(message) > query["udp_size"]:
        message = build(flags | 0x0200, [], [])  # RFC 1035 4.1.1 TC; client retries over TCP
    return message


def dns_record(query, transport):
    return {"transport": transport, "qname": query["qname"].lower(),
            "qname_case": query["qname"], "wire_base64": query["wire_base64"],
            "wire_id_zero_base64": query["wire_id_zero_base64"],
            "advertised_udp_size": query["advertised_udp_size"],
            "qtype": TYPE_NAMES.get(query["qtype"], str(query["qtype"])),
            "qclass": "IN" if query["qclass"] == 1 else str(query["qclass"]),
            "opcode": (query["flags"] >> 11) & 0xF, "rd": bool(query["flags"] & 0x0100),
            "edns": query["edns"],
            # RFC 1035 4.1.1 header of the query itself: QR/AA/TC/RA/Z/RCODE and section counts.
            "qr": bool(query["flags"] & 0x8000), "aa": bool(query["flags"] & 0x0400),
            "tc": bool(query["flags"] & 0x0200), "ra": bool(query["flags"] & 0x0080),
            "z": (query["flags"] >> 6) & 1, "ad": bool(query["flags"] & 0x0020),
            "cd": bool(query["flags"] & 0x0010), "rcode": query["flags"] & 0xF,
            "qdcount": query["counts"][0], "ancount": query["counts"][1],
            "nscount": query["counts"][2], "arcount": query["counts"][3]}


def validate_case(case):
    """Data-only checks of the peer fields; nothing is bound or sent."""
    def check(condition, message):
        if not condition:
            raise ValueError(case.get("id", "?") + ": " + message)
    def port_ok(value, low=1):
        return type(value) is int and low <= value <= 65535
    kind = case.get("peer")
    check(kind in KINDS, "unknown network peer")
    if "peer_port" in case:
        check(case["peer_port"] == 0 or port_ok(case["peer_port"]), "invalid peer_port")
    if "peer_install_ca" in case:
        check(kind == "https" and type(case["peer_install_ca"]) is bool,
              "peer_install_ca is a boolean for the HTTPS fixture only")
    if kind in ("tcp-client", "udp-client", "udp-clients"):
        # The listener is the candidate/reference itself, running unprivileged.
        check(port_ok(case.get("peer_port"), 1025), "client peers need a fixed unprivileged peer_port")
    if kind == "tcp-ports":
        ports = case.get("peer_ports")
        check(isinstance(ports, list) and ports and len(ports) <= 8 and len(set(ports)) == len(ports) and
              all(port_ok(p) for p in ports), "tcp-ports needs 1-8 distinct peer_ports")
    if "peer_send" in case:
        check(isinstance(case["peer_send"], str) and len(case["peer_send"].encode()) <= 65536, "invalid peer_send")
    for reply in case.get("peer_replies", []):
        check(kind == "bashssh", "peer_replies is only for bashssh")
        check(isinstance(reply, dict) and set(reply) <= {"cmd", "rc", "stdout", "stderr"} and
              isinstance(reply.get("cmd"), str) and type(reply.get("rc")) is int and 0 <= reply["rc"] <= 255 and
              all(isinstance(reply.get(k, ""), str) for k in ("stdout", "stderr")), "invalid peer_replies entry")
    if "peer_reply_delay_ms" in case:
        check(kind == "udp" and type(case["peer_reply_delay_ms"]) is int and 0 <= case["peer_reply_delay_ms"] <= 4000,
              "peer_reply_delay_ms is a 0-4000 ms udp reply delay")
    if kind == "udp-clients":
        plan = case.get("peer_datagrams")
        check(isinstance(plan, list) and 1 <= len(plan) <= 8 and
              all(isinstance(item, list) and len(item) == 3 and type(item[0]) is int and 0 <= item[0] <= 3 and
                  type(item[1]) is int and 0 <= item[1] <= 4000 and isinstance(item[2], str) and
                  len(item[2].encode()) <= 1024 for item in plan),
              "udp-clients needs peer_datagrams [[sender 0-3, delay_ms 0-4000, text], ...]")
    elif "peer_datagrams" in case:
        check(False, "peer_datagrams is only for udp-clients")
    check(len(case.get("expected_requests", [])) <= CONNECTION_LIMIT, "more expected requests than the peer allows")


# --------------------------------------------------------------------- TLS

class PeerRecords(list):
    """Wire records and separate trusted setup evidence."""
    def __init__(self):
        super().__init__()
        self.setup = {}


def require_trust_guest():
    """Refuse trust setup unless the disposable guest identity matches."""
    marker = Path("/etc/bashos-parity-vm")
    identity = Path("/sys/class/dmi/id/product_uuid")
    if (os.geteuid() != 0 or not marker.is_file() or not identity.is_file()
            or not marker.read_text().strip()
            or marker.read_text().strip().lower() != identity.read_text().strip().lower()):
        raise RuntimeError("fixture CA installation requires the disposable VM controller")


@contextlib.contextmanager
def fixture_ca(case, evidence, target=Path("/etc/ssl/cert.pem")):
    """Bind the throwaway public CA in the guest's private mount namespace.

    Preserve existing files and symlinks, and verify restoration even when
    behavioral execution raises. No private key is installed here.
    """
    if not case.get("peer_install_ca"):
        yield
        return
    require_trust_guest()
    source = Path(TLS_EXPORT) / "ca.pem"
    def state():
        if not target.exists() and not target.is_symlink():
            return None
        info = target.lstat()
        if not target.is_file():
            raise RuntimeError("fixture CA target must resolve to a regular file")
        return {"mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                "symlink": os.readlink(target) if target.is_symlink() else None,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
    before = state()
    created = before is None
    mounted = False
    record = evidence["fixture_ca"] = {
        "target": str(target), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "created_target": created, "installed": False, "restored": False}
    if created:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
    destination = target.resolve(strict=True)
    try:
        subprocess.run(["mount", "--bind", str(source), str(destination)], check=True,
                       capture_output=True, timeout=5)
        mounted = True
        subprocess.run(["mount", "-o", "remount,bind,ro,nosuid,nodev,noexec", str(destination)],
                       check=True, capture_output=True, timeout=5)
        record["installed"] = True
        yield
    finally:
        if mounted:
            subprocess.run(["umount", str(destination)], check=True, capture_output=True, timeout=5)
        if created:
            target.unlink()
        record["restored"] = state() == before
        if not record["restored"]:
            raise RuntimeError("fixture CA target was not restored")


def tls_material():
    """Generate a throwaway CA, a second unrelated CA and a 127.0.0.1 leaf.

    Runs in the trusted peer only. Returns (server_context, private_dir);
    the caller removes private_dir after loading. Public CA PEMs are exported
    to TLS_EXPORT as ca.pem (signed the leaf) and other-ca.pem (did not)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    pem = serialization.Encoding.PEM

    def authority(name):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             content_commitment=False, key_encipherment=False, data_encipherment=False,
                                             key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    ca_key, ca = authority("parity fixture CA")
    _, other = authority("parity unrelated CA")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca.subject).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(HOST)),
                                                        x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    os.makedirs(TLS_EXPORT, mode=0o755, exist_ok=True)
    os.chmod(TLS_EXPORT, 0o755)
    for name, cert in (("ca.pem", ca), ("other-ca.pem", other)):
        path = os.path.join(TLS_EXPORT, name)
        with open(path, "wb") as handle:
            handle.write(cert.public_bytes(pem))
        os.chmod(path, 0o644)
    private = tempfile.mkdtemp(prefix="parity-peer-key-")
    os.chmod(private, 0o700)
    chain, keyfile = os.path.join(private, "leaf.pem"), os.path.join(private, "leaf.key")
    with open(chain, "wb") as handle:
        handle.write(leaf.public_bytes(pem) + ca.public_bytes(pem))
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(chain, keyfile)
    return context, private


def tls_accept(context, conn, index, records):
    """Server handshake; a refused handshake is recorded, not a peer error.

    Returns the wrapped socket, or None when the client rejected the
    certificate or otherwise did not complete the handshake."""
    names = []
    context.sni_callback = lambda sock, name, ctx: names.append(name)
    try:
        wrapped = context.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as exc:
        records.append({"connection": index, "tls": "handshake-failed",
                        "tls_alert": getattr(exc, "reason", None) or type(exc).__name__})
        return None
    return wrapped, (names[0] if names else None)


# ------------------------------------------------------------------- peers

@contextlib.contextmanager
def running(targets, sockets, errors, stopping, name):
    threads = [threading.Thread(target=target, daemon=True) for target in targets]
    for thread in threads:
        thread.start()
    try:
        yield
    finally:
        stopping.set()
        for thread in threads:
            thread.join(timeout=STOP_TIMEOUT)
        for sock in sockets:
            sock.close()
        if any(thread.is_alive() for thread in threads):
            errors.append(name + " peer failed to stop")


@contextlib.contextmanager
def peer(kind, case):
    records = PeerRecords()
    errors = []
    stopping = threading.Event()
    port = case.get("peer_port", 0)
    payload = case.get("peer_send", "ping\n").encode()

    if kind == "http":
        server = listener(socket.SOCK_STREAM, port)
        port = server.getsockname()[1]

        def handle(conn, index):
            http_connection(conn, index, port, records, stopping)

        targets = [lambda: serve_stream(server, handle, errors, stopping)]
        sockets = [server]

    elif kind == "https":
        # The http resource table behind TLS 1.2+ with the throwaway CA.
        server = listener(socket.SOCK_STREAM, port)
        port = server.getsockname()[1]
        context, private = tls_material()
        shutil.rmtree(private)

        def handle(conn, index):
            accepted = tls_accept(context, conn, index, records)
            if accepted is None:
                return
            wrapped, sni = accepted
            before = len(records)
            try:
                http_connection(wrapped, index, port, records, stopping)
            finally:
                for record in records[before:]:
                    record.update(tls="ok", sni=sni)
                with contextlib.suppress(OSError):
                    wrapped.close()

        targets = [lambda: serve_stream(server, handle, errors, stopping)]
        sockets = [server]

    elif kind in ("tcp", "tcp-hold", "tcp-eof"):
        # tcp: read one line (or to EOF), reply "echo:" + request, close.
        # tcp-hold: read to EOF, never reply, hold the connection open.
        # tcp-eof: reply only after the client half-closes (recv returns 0);
        # a client that never shuts down its write side gets no reply.
        server = listener(socket.SOCK_STREAM, port)
        port = server.getsockname()[1]

        def handle(conn, index):
            if kind == "tcp":
                request, _ = recv_until(conn, lambda d: d.endswith(b"\n"), 65536)
                records.append({"connection": index, "body_base64": b64(request)})
                conn.sendall(b"echo:" + request)
                conn.shutdown(socket.SHUT_WR)
                return
            if kind == "tcp-eof":
                request, eof = recv_until(conn, lambda d: False, 65536)
                records.append({"connection": index, "body_base64": b64(request), "saw_eof": eof})
                conn.sendall(b"echo:" + request)
                conn.shutdown(socket.SHUT_WR)
                return
            request, _ = recv_until(conn, lambda d: False, 65536)
            records.append({"connection": index, "body_base64": b64(request)})
            while not stopping.wait(0.05):
                pass

        targets = [lambda: serve_stream(server, handle, errors, stopping)]
        sockets = [server]

    elif kind == "tcp-ports":
        # Listeners on each of peer_ports; connections are accepted and closed.
        sockets = [listener(socket.SOCK_STREAM, p) for p in case["peer_ports"]]
        port = case["peer_ports"][0]
        lock = threading.Lock()

        def watcher(server, number):
            def handle(conn, index):
                with lock:
                    records.append({"port": number})
            serve_stream(server, handle, errors, stopping)

        targets = [lambda s=s, p=p: watcher(s, p) for s, p in zip(sockets, case["peer_ports"])]

    elif kind == "tcp-client":
        # Connect once the candidate/reference listener is bound, send the
        # payload, then read until the other side shuts down its write half.
        sockets = []

        def target():
            if not wait_bound(port, False, stopping):
                errors.append("no TCP listener appeared on port %d" % port)
                return
            try:
                with socket.create_connection((HOST, port), timeout=IO_TIMEOUT) as conn:
                    conn.sendall(payload)
                    received, _ = recv_until(conn, lambda d: False, 65536)
                    records.append({"body_base64": b64(received)})
            except (OSError, ValueError) as exc:
                errors.append("tcp-client: %s: %s" % (type(exc).__name__, exc))

        targets = [target]

    elif kind == "udp":
        # Reply to each datagram with "echo:" + datagram.
        delay = case.get("peer_reply_delay_ms", 0) / 1000
        server = listener(socket.SOCK_DGRAM, port)
        port = server.getsockname()[1]

        def target():
            while not stopping.is_set():
                try:
                    data, source = server.recvfrom(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not stopping.is_set():
                        errors.append("udp: %s" % exc)
                    return
                records.append({"body_base64": b64(data)})
                if len(records) > CONNECTION_LIMIT:
                    errors.append("datagram limit exceeded")
                    return
                # peer_reply_delay_ms holds the reply back so a case can probe
                # the client's post-EOF drain window from either side.
                if stopping.wait(delay):
                    return
                with contextlib.suppress(OSError):
                    server.sendto(b"echo:" + data, source)

        targets = [target]
        sockets = [server]

    elif kind == "udp-client":
        # Send one datagram once the other side has bound its UDP socket.
        sockets = []

        def target():
            if not wait_bound(port, True, stopping):
                errors.append("no UDP socket appeared on port %d" % port)
                return
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
                conn.sendto(payload, (HOST, port))
            records.append({"sent_base64": b64(payload)})

        targets = [target]

    elif kind == "udp-clients":
        # Several sender sockets, each on its own ephemeral source port. Each
        # peer_datagrams entry is [sender, delay_ms_from_bind, text]; every
        # sender records what it sent and every datagram it receives back.
        sockets = []
        plan = case["peer_datagrams"]
        senders = sorted({item[0] for item in plan})

        def target():
            if not wait_bound(port, True, stopping):
                errors.append("no UDP socket appeared on port %d" % port)
                return
            start = time.monotonic()
            socks = {}
            log = {n: {"sender": n, "sent_base64": [], "received_base64": []} for n in senders}
            try:
                for n in senders:
                    socks[n] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    socks[n].bind((HOST, 0))
                    socks[n].settimeout(0.02)
                pending = sorted(plan, key=lambda item: item[1])
                while not stopping.is_set():
                    now = (time.monotonic() - start) * 1000
                    while pending and pending[0][1] <= now:
                        n, _, text = pending.pop(0)
                        socks[n].sendto(text.encode(), (HOST, port))
                        log[n]["sent_base64"].append(b64(text.encode()))
                    for n, sock in socks.items():
                        try:
                            data, source = sock.recvfrom(65536)
                        except socket.timeout:
                            continue
                        if source == (HOST, port):
                            log[n]["received_base64"].append(b64(data))
                    if now > READY_TIMEOUT * 1000 + 10000:
                        break
            except OSError as exc:
                errors.append("udp-clients: %s" % exc)
            finally:
                for sock in socks.values():
                    sock.close()
                records.extend(log[n] for n in senders)

        targets = [target]

    elif kind == "dns":
        port = port or 53
        udp = listener(socket.SOCK_DGRAM, port)
        tcp = listener(socket.SOCK_STREAM, port)
        lock = threading.Lock()

        def serve_udp():
            while not stopping.is_set():
                try:
                    message, source = udp.recvfrom(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if not stopping.is_set():
                        errors.append("dns udp: %s" % exc)
                    return
                try:
                    query = parse_query(message)
                except (ValueError, UnicodeDecodeError, struct.error) as exc:
                    errors.append("dns udp: %s" % exc)
                    continue
                with lock:
                    records.append(dns_record(query, "udp"))
                    if len(records) > CONNECTION_LIMIT:
                        errors.append("DNS query limit exceeded")
                        return
                with contextlib.suppress(OSError):
                    udp.sendto(answer(query, "udp"), source)

        def handle_tcp(conn, index):
            # RFC 1035 4.2.2: two-octet length prefix; several queries may share a connection.
            def complete(data):
                return len(data) >= 2 and len(data) >= 2 + struct.unpack("!H", data[:2])[0]
            buffered = b""
            while True:
                if not complete(buffered):
                    data = conn.recv(4096)
                    if not data:
                        if buffered:
                            raise ValueError("connection closed inside a TCP DNS message")
                        return
                    buffered += data
                    if len(buffered) > 65538:
                        raise ValueError("TCP DNS message exceeds limit")
                    continue
                size = struct.unpack("!H", buffered[:2])[0]
                query = parse_query(buffered[2:2 + size])
                buffered = buffered[2 + size:]
                with lock:
                    records.append(dns_record(query, "tcp"))
                reply = answer(query, "tcp")
                conn.sendall(struct.pack("!H", len(reply)) + reply)

        targets = [serve_udp, lambda: serve_stream(tcp, handle_tcp, errors, stopping)]
        sockets = [udp, tcp]

    elif kind == "dns-tls":
        # RFC 7858: the RFC 1035 4.2.2 TCP framing inside TLS.
        server = listener(socket.SOCK_STREAM, port)
        port = server.getsockname()[1]
        context, private = tls_material()
        shutil.rmtree(private)

        def handle(conn, index):
            accepted = tls_accept(context, conn, index, records)
            if accepted is None:
                return
            wrapped, sni = accepted
            buffered = b""
            try:
                while True:
                    while len(buffered) < 2 or len(buffered) < 2 + struct.unpack("!H", buffered[:2])[0]:
                        data = wrapped.recv(4096)
                        if not data:
                            if buffered:
                                raise ValueError("connection closed inside a DoT message")
                            return
                        buffered += data
                        if len(buffered) > 65538:
                            raise ValueError("DoT message exceeds limit")
                    size = struct.unpack("!H", buffered[:2])[0]
                    query = parse_query(buffered[2:2 + size])
                    buffered = buffered[2 + size:]
                    records.append(dict(dns_record(query, "tls"), tls="ok", sni=sni))
                    reply = answer(query, "tcp")
                    wrapped.sendall(struct.pack("!H", len(reply)) + reply)
            finally:
                with contextlib.suppress(OSError):
                    wrapped.close()

        targets = [lambda: serve_stream(server, handle, errors, stopping)]
        sockets = [server]

    elif kind == "bashssh":
        # Native ssh:// command-stream peer. Commands are never executed: each
        # exact command string maps to a canned reply from the case.
        server = listener(socket.SOCK_STREAM, port)
        port = server.getsockname()[1]
        replies = {item["cmd"]: item for item in case.get("peer_replies", [])}

        def handle(conn, index):
            head, eof = recv_until(conn, lambda d: b"\n\n" in d, HEAD_LIMIT)
            if b"\n\n" not in head:
                raise ValueError("connection closed inside the BASHSSH1 header")
            head, rest = head.split(b"\n\n", 1)
            lines = head.decode("latin-1").split("\n")
            if lines[0] != "BASHSSH1":
                raise ValueError("bad BASHSSH1 magic")
            fields = dict(line.split(" ", 1) for line in lines[1:])
            cmd_len, stdin_len = int(fields["cmd-len"]), int(fields["stdin-len"])
            if cmd_len + stdin_len > BODY_LIMIT:
                raise ValueError("BASHSSH1 request exceeds limit")
            while len(rest) < cmd_len + stdin_len:
                rest += recv_more(conn, rest, "the BASHSSH1 payload")
            command = rest[:cmd_len].decode("utf-8", "replace")
            records.append({"connection": index, "header_lines": lines[1:], "cmd": command,
                            "stdin_base64": b64(rest[cmd_len:cmd_len + stdin_len]),
                            "trailing_bytes": len(rest) - cmd_len - stdin_len})
            reply = replies.get(command, {"rc": 127, "stdout": "", "stderr": "fixture: unknown command\n"})
            out, err = reply.get("stdout", "").encode(), reply.get("stderr", "").encode()
            conn.sendall(b"BASHSSH1-RESP\nrc %d\nstdout-len %d\nstderr-len %d\n\n" % (reply["rc"], len(out), len(err)) + out + err)

        targets = [lambda: serve_stream(server, handle, errors, stopping)]
        sockets = [server]

    else:
        raise ValueError("unknown peer: " + kind)

    try:
        with fixture_ca(case, records.setup):
            with running(targets, sockets, errors, stopping, kind):
                yield port, records, errors
    finally:
        if kind in ("https", "dns-tls"):
            shutil.rmtree(TLS_EXPORT, ignore_errors=True)
        if kind == "tcp-ports":
            # Each port has its own accept thread; order by port, not by scheduling.
            records.sort(key=lambda record: record["port"])
