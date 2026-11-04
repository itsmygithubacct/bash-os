#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""w1 wg fixtures: the candidate wg builtin against the guest kernel's WireGuard driver.

Run inside `unshare --user --map-root-user --net --mount --uts`. The device is created with
iproute2 (`ip link add wg0 type wireguard`). Kernel state is read back and, for the show cases,
written with an independent generic-netlink codec implemented here from linux/wireguard.h
(there is no wg(8) in the image). Public keys are checked against the RFC 7748 section 6.1
X25519 vectors.
"""
import base64
import os
import socket
import struct
import sys

import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

CASE = "/tmp/parity-case"
ALICE_PRIV = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUB = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PRIV = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUB = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
# A distinct, nonzero public-key value for the second setconf peer.
THIRD_PUB = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
b64 = lambda b: base64.b64encode(b).decode()
NESTED = 0x8000


def clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def attr(t, payload, nested=False):
    n = 4 + len(payload)
    return struct.pack("=HH", n, t | (NESTED if nested else 0)) + payload + b"\0" * (-n % 4)


def parse(data):
    out, off = {}, 0
    while off + 4 <= len(data):
        n, t = struct.unpack_from("=HH", data, off)
        if n < 4:
            break
        out.setdefault(t & 0x3fff, []).append(data[off + 4:off + n])
        off += (n + 3) & ~3
    return out


class Genl:
    def __init__(self):
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
        self.s.bind((0, 0))
        self.seq = 1
        r = self.call(0x10, 3, 0x1, attr(2, b"wireguard\0"))
        self.fid = struct.unpack("=H", parse(r[0])[1][0])[0]

    def call(self, typ, cmd, flags, payload):
        self.seq += 1
        msg = struct.pack("=IHHII", 16 + 4 + len(payload), typ, 0x1 | flags, self.seq, 0) + struct.pack("=BBH", cmd, 1, 0) + payload
        self.s.send(msg)
        got = []
        while True:
            data = self.s.recv(65536)
            off = 0
            while off + 16 <= len(data):
                n, t, fl, sq, pid = struct.unpack_from("=IHHII", data, off)
                body = data[off + 16:off + n]
                if t == 2:
                    err = struct.unpack_from("=i", body)[0]
                    if err:
                        raise OSError(-err, os.strerror(-err))
                    return got
                if t == 3:
                    return got
                got.append(body[4:])
                off += (n + 3) & ~3
                if not (fl & 2):  # not multipart
                    return got
        return got

    def get(self, ifname):
        parts = self.call(self.fid, 0, 0x300, attr(2, ifname.encode() + b"\0"))
        dev = {"peers": []}
        for body in parts:
            a = parse(body)
            if 2 in a:
                dev["ifname"] = a[2][0].rstrip(b"\0").decode()
            if 3 in a:
                dev["private"] = a[3][0]
            if 4 in a:
                dev["public"] = a[4][0]
            if 6 in a:
                dev["port"] = struct.unpack("=H", a[6][0])[0]
            if 7 in a:
                dev["fwmark"] = struct.unpack("=I", a[7][0])[0]
            for pbuf in a.get(8, []):
                for pe in parse(pbuf).get(0, []):
                    pa = parse(pe)
                    peer = {"public": pa[1][0], "ips": set(), "keepalive": struct.unpack("=H", pa[5][0])[0] if 5 in pa else 0}
                    if 4 in pa:
                        sa = pa[4][0]
                        fam = struct.unpack_from("=H", sa)[0]
                        port = struct.unpack_from("!H", sa, 2)[0]
                        peer["endpoint"] = "%s:%d" % (socket.inet_ntop(socket.AF_INET, sa[4:8]), port) if fam == socket.AF_INET else "[%s]:%d" % (socket.inet_ntop(socket.AF_INET6, sa[8:24]), port)
                    for ipb in pa.get(9, []):
                        for ie in parse(ipb).get(0, []):
                            ia = parse(ie)
                            fam = struct.unpack("=H", ia[1][0])[0]
                            peer["ips"].add("%s/%d" % (socket.inet_ntop(fam, ia[2][0]), ia[3][0][0]))
                    peer["last_handshake"] = struct.unpack_from("=qq", pa[6][0])[0] if 6 in pa else 0
                    peer["rx"] = struct.unpack("=Q", pa[7][0])[0] if 7 in pa else 0
                    peer["tx"] = struct.unpack("=Q", pa[8][0])[0] if 8 in pa else 0
                    dev["peers"].append(peer)
        return dev

    def set(self, ifname, priv=None, port=None, fwmark=None, peers=()):
        p = attr(2, ifname.encode() + b"\0")
        if priv is not None:
            p += attr(3, priv)
        if port is not None:
            p += attr(6, struct.pack("=H", port))
        if fwmark is not None:
            p += attr(7, struct.pack("=I", fwmark))
        p += attr(5, struct.pack("=I", 1))  # WGDEVICE_F_REPLACE_PEERS
        pl = b""
        for peer in peers:
            pe = attr(1, peer["public"]) + attr(3, struct.pack("=I", 2))  # REPLACE_ALLOWEDIPS
            if "endpoint" in peer:
                h, pt = peer["endpoint"]
                pe += attr(4, struct.pack("=H", socket.AF_INET) + struct.pack("!H", pt) + socket.inet_aton(h) + b"\0" * 8)
            if peer.get("keepalive"):
                pe += attr(5, struct.pack("=H", peer["keepalive"]))
            ips = b""
            for cidr in peer.get("ips", []):
                addr, mask = cidr.split("/")
                fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
                ips += attr(0, attr(1, struct.pack("=H", fam)) + attr(2, socket.inet_pton(fam, addr)) + attr(3, bytes([int(mask)])), True)
            pe += attr(9, ips, True)
            pl += attr(0, pe, True)
        p += attr(8, pl, True)
        self.call(self.fid, 1, 0x4, p)


def wg(*args):
    return L.cand('wg "$@"', *args)


def newdev():
    L.seed([["link", "add", "wg0", "type", "wireguard"]])
    open(CASE + "/priv.key", "w").write(b64(ALICE_PRIV) + "\n")
    return Genl()


def peer_of(dev, pub):
    return next((p for p in dev["peers"] if p["public"] == pub), None) or {"public": pub, "ips": None, "keepalive": None, "missing": True}


def sc_set_apply():
    g = newdev()
    rc, out, err = wg("set", "wg0", "private-key", CASE + "/priv.key", "listen-port", "51820", "peer", b64(BOB_PUB), "endpoint", "192.0.2.9:5000",
                      "allowed-ips", "10.0.0.0/24,fd00::/64", "persistent-keepalive", "25")
    L.check("set rc0 (kernel ACK)", rc == 0, "rc=%s err=%s" % (rc, err))
    d = g.get("wg0")
    L.check("set listen-port visible in kernel state", d.get("port") == 51820, str(d.get("port")))
    L.check("set private-key applied: kernel holds the clamped RFC 7748 private key", d.get("private") == clamp(ALICE_PRIV), str(d.get("private")))
    L.check("set private-key applied: kernel public key equals the RFC 7748 Alice public key", d.get("public") == ALICE_PUB, str(d.get("public")))
    p = peer_of(d, BOB_PUB)
    L.check("set created the peer", not p.get("missing") and len(d["peers"]) == 1, str(d["peers"]))
    if not p.get("missing"):
        L.check("set peer endpoint 192.0.2.9:5000", p.get("endpoint") == "192.0.2.9:5000", str(p))
        L.check("set peer allowed ips {10.0.0.0/24, fd00::/64}", p["ips"] == {"10.0.0.0/24", "fd00::/64"}, str(p["ips"]))
        L.check("set peer persistent keepalive 25", p["keepalive"] == 25, str(p["keepalive"]))


def sc_set_errors():
    g = newdev()
    rc, out, err = wg("set", "wg0", "listen-port", "4242")
    L.check("set listen-port alone rc0 and applied", rc == 0 and g.get("wg0").get("port") == 4242, "rc=%s err=%s" % (rc, err))
    rc, out, err = wg("set", "nosuch0", "listen-port", "4242")
    L.check("set on a nonexistent interface fails with a diagnostic", rc != 0 and err.strip() != "", "rc=%s err=%r" % (rc, err))
    d = g.get("wg0")
    L.check("failed set did not change the real device", d.get("port") == 4242, str(d.get("port")))
    open(CASE + "/bad.key", "w").write("not-a-key\n")
    rc, out, err = wg("set", "wg0", "private-key", CASE + "/bad.key")
    priv = g.get("wg0").get("private")
    L.check("set with an invalid key file fails and leaves the key unset", rc != 0 and (priv is None or not any(priv)), "rc=%s err=%r priv=%r" % (rc, err, priv))


def sc_set_peers():
    g = newdev()
    wg("set", "wg0", "listen-port", "51820", "peer", b64(BOB_PUB), "allowed-ips", "10.0.0.0/24", "peer", b64(ALICE_PUB), "allowed-ips", "10.5.0.0/16")
    d = g.get("wg0")
    L.check("peers: both peers created", {p["public"] for p in d["peers"]} == {BOB_PUB, ALICE_PUB}, str(d["peers"]))
    rc, out, err = wg("set", "wg0", "peer", b64(BOB_PUB), "allowed-ips", "10.9.0.0/16")
    d = g.get("wg0")
    L.check("peers: allowed-ips of an existing peer are replaced", peer_of(d, BOB_PUB)["ips"] == {"10.9.0.0/16"}, str(d["peers"]))
    L.check("peers: other peer untouched by the replacement", peer_of(d, ALICE_PUB)["ips"] == {"10.5.0.0/16"}, str(d["peers"]))
    rc, out, err = wg("set", "wg0", "peer", b64(ALICE_PUB), "remove")
    d = g.get("wg0")
    L.check("peers: peer remove deletes only that peer", rc == 0 and [p["public"] for p in d["peers"]] == [BOB_PUB], "rc=%s %s" % (rc, d["peers"]))


CONF = """[Interface]
PrivateKey = %s
ListenPort = 51821
FwMark = 0x1234

[Peer]
PublicKey = %s
Endpoint = 192.0.2.9:5000
AllowedIPs = 10.1.0.0/24, fd01::/64
PersistentKeepalive = 15

[Peer]
PublicKey = %s
Endpoint = 198.51.100.4:6000
AllowedIPs = 10.2.0.0/16
"""


def sc_setconf():
    g = newdev()
    open(CASE + "/wg.conf", "w").write(CONF % (b64(ALICE_PRIV), b64(BOB_PUB), b64(THIRD_PUB)))
    rc, out, err = wg("setconf", "wg0", CASE + "/wg.conf")
    L.check("setconf rc0 (kernel accepted the encoded SET_DEVICE message)", rc == 0, "rc=%s err=%s" % (rc, err))
    d = g.get("wg0")
    L.check("setconf: listen port 51821", d.get("port") == 51821, str(d.get("port")))
    L.check("setconf: fwmark 0x1234", d.get("fwmark") == 0x1234, str(d.get("fwmark")))
    L.check("setconf: private key clamped and public key equals the RFC 7748 Alice vector", d.get("private") == clamp(ALICE_PRIV) and d.get("public") == ALICE_PUB, str((d.get("private"), d.get("public"))))
    b = peer_of(d, BOB_PUB)
    a = peer_of(d, THIRD_PUB)
    L.check("setconf: first peer endpoint, allowed IPv4+IPv6 prefixes and keepalive", not b.get("missing") and b.get("endpoint") == "192.0.2.9:5000" and b["ips"] == {"10.1.0.0/24", "fd01::/64"} and b["keepalive"] == 15, str(b))
    L.check("setconf: second peer endpoint and allowed prefix, no keepalive", not a.get("missing") and a.get("endpoint") == "198.51.100.4:6000" and a["ips"] == {"10.2.0.0/16"} and a["keepalive"] == 0, str(a))
    conf2 = CONF.split("[Peer]")[0] + "[Peer]" + CONF.split("[Peer]")[1].replace("10.1.0.0/24, fd01::/64", "10.7.0.0/16")
    open(CASE + "/wg2.conf", "w").write(conf2 % (b64(ALICE_PRIV), b64(BOB_PUB)))
    rc, out, err = wg("setconf", "wg0", CASE + "/wg2.conf")
    d = g.get("wg0")
    L.check("setconf replaces the previous configuration (one peer left with the new prefix)", rc == 0 and len(d["peers"]) == 1 and d["peers"][0]["ips"] == {"10.7.0.0/16"}, "rc=%s %s" % (rc, d["peers"]))
    # Independent encoder demonstrates why a device public key cannot be a peer.
    g.set("wg0", peers=[{"public": ALICE_PUB}, {"public": BOB_PUB}])
    d = g.get("wg0")
    L.check("kernel ignores its own public key as a peer", {p["public"] for p in d["peers"]} == {BOB_PUB}, str(d["peers"]))


def sc_show():
    g = newdev()
    g.set("wg0", priv=ALICE_PRIV, port=51820, fwmark=0x1234, peers=[
        {"public": BOB_PUB, "endpoint": ("192.0.2.9", 5000), "ips": ["10.0.0.0/24", "fd00::/64"], "keepalive": 25},
        {"public": ALICE_PUB, "ips": []}])
    d = g.get("wg0")
    L.check("show seed: independent encoder configured the device", d.get("port") == 51820 and len(d["peers"]) == 2 and d["public"] == ALICE_PUB, str(d))
    rc, out, err = wg("show", "wg0")
    L.check("show rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    lines = out.splitlines()
    L.check("show interface block: interface name, public key, hidden private key, listening port, fwmark",
            lines[:5] == ["interface: wg0", "  public key: " + b64(ALICE_PUB), "  private key: (hidden)", "  listening port: 51820", "  fwmark: 0x1234"], out)
    L.check("show private key value never printed", b64(clamp(ALICE_PRIV)) not in out and b64(ALICE_PRIV) not in out, out)
    L.check("show peer with endpoint, allowed ips and keepalive per wg(8) (comma-space list, 'every N seconds')",
            ("peer: " + b64(BOB_PUB)) in out and "  endpoint: 192.0.2.9:5000" in lines and "  allowed ips: 10.0.0.0/24, fd00::/64" in lines and "  persistent keepalive: every 25 seconds" in lines, out)
    L.check("show peer without allowed ips prints (none), without endpoint no endpoint line", "  allowed ips: (none)" in lines, out)
    L.check("show prints no handshake or transfer line while both are zero", "latest handshake" not in out and "transfer:" not in out, out)
    expected = ("interface: wg0\n  public key: %s\n  private key: (hidden)\n  listening port: 51820\n  fwmark: 0x1234\n\n"
                "peer: %s\n  endpoint: 192.0.2.9:5000\n  allowed ips: 10.0.0.0/24, fd00::/64\n  persistent keepalive: every 25 seconds\n\n"
                "peer: %s\n  allowed ips: (none)\n") % (b64(ALICE_PUB), b64(BOB_PUB), b64(ALICE_PUB))
    L.check("show full output equals the wg(8) contract text for the configured state", out == expected, "got=%r want=%r" % (out, expected))


SCEN = {"set-apply": sc_set_apply, "set-errors": sc_set_errors, "set-peers": sc_set_peers, "setconf": sc_setconf, "show": sc_show}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
