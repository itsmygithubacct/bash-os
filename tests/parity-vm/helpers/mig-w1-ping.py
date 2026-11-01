#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""w1 ping fixtures: the candidate ping/traceroute builtin against real namespaces and forged peers.

Run inside `unshare --user --map-root-user --net --mount --uts`. Peers are forked children in
their own network namespaces joined by veth pairs. Request bytes are read with an AF_PACKET
sniffer and decoded independently (RFC 792 / RFC 4443 checksums); replies are forged by a raw
ICMP socket in the peer namespace. Per-check detail goes to stderr, the verdict to stdout.
"""
import ctypes
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time

import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

libc = ctypes.CDLL(None, use_errno=True)
CASE = "/tmp/parity-case"


def csum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff


def proc_write(path, val):
    try:
        with open(path, "w") as f:
            f.write(val)
    except OSError:
        pass


def sysctl_dad_off():
    for p in ("default", "all"):
        proc_write("/proc/sys/net/ipv6/conf/%s/accept_dad" % p, "0")


# ------------------------------------------------------------------ peers
def forge(kind, fam, req, mode):
    """Build a reply message (without IP header) for echo request REQ (ICMP bytes)."""
    typ = 0 if fam == 4 else 129
    ident, seq = struct.unpack("!HH", req[4:8])
    payload = req[8:]
    if mode == "wrong-id":
        ident ^= 0x0101
    elif mode == "wrong-seq":
        seq = (seq + 1) & 0xffff
    elif mode == "wrong-payload":
        payload = payload[:-1] + bytes([payload[-1] ^ 0xff])
    msg = struct.pack("!BBHHH", typ, 0, 0, ident, seq) + payload
    if fam == 4:
        msg = msg[:2] + struct.pack("!H", csum(msg)) + msg[4:]
    return msg


def peer_main(rf, wf):
    os.unshare(os.CLONE_NEWNET)
    sysctl_dad_off()
    wf.write("ready\n")
    wf.flush()
    for line in rf:
        cmd = json.loads(line)
        if cmd[0] == "quit":
            break
        if cmd[0] == "run":
            p = subprocess.run(cmd[1], capture_output=True, text=True, env=L.ENV)
            res = [p.returncode, p.stdout[-300:], p.stderr[-300:]]
        elif cmd[0] == "respond":
            fam, plan = cmd[1], cmd[2]  # plan: list of [mode, src_addr or null]
            if fam == 4:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            else:
                s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
                s.bind(("fd77::2", 0))
            got = None
            end = time.time() + 8
            while time.time() < end and got is None:
                r, _, _ = select.select([s], [], [], 0.2)
                if not r:
                    continue
                data, frm = s.recvfrom(2048)
                msg = data[(data[0] & 15) * 4:] if fam == 4 else data
                if msg and msg[0] == (8 if fam == 4 else 128):
                    got, src = msg, frm[0]
            sent = 0
            if got is not None:
                for mode, srcaddr in plan:
                    sock = s
                    if srcaddr:
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
                        sock.bind((srcaddr, 0))
                    sock.sendto(forge("reply", fam, got, mode), (src, 0))
                    sent += 1
                    time.sleep(0.05)
            s.close()
            res = ["responded", got is not None, sent]
        wf.write(json.dumps(res) + "\n")
        wf.flush()


class Peer:
    def __init__(self):
        a_r, a_w = os.pipe()
        b_r, b_w = os.pipe()
        self.pid = os.fork()
        if self.pid == 0:
            os.close(a_w)
            os.close(b_r)
            peer_main(os.fdopen(a_r, "r"), os.fdopen(b_w, "w"))
            os._exit(0)
        os.close(a_r)
        os.close(b_w)
        self.w = os.fdopen(a_w, "w")
        self.r = os.fdopen(b_r, "r")
        assert self.r.readline().strip() == "ready"

    def send(self, *cmd):
        self.w.write(json.dumps(list(cmd)) + "\n")
        self.w.flush()

    def recv(self):
        return json.loads(self.r.readline())

    def call(self, *cmd):
        self.send(*cmd)
        return self.recv()

    def sh(self, text):
        return self.call("run", ["/bin/sh", "-c", text])

    def close(self):
        try:
            self.send("quit")
        except OSError:
            pass
        os.waitpid(self.pid, 0)


# ------------------------------------------------------------------ sniffing / running
def sniffer(ifn):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((ifn, 0))
    return s


def drain(s, pkttype):
    """Frames of one direction only (0 = PACKET_HOST incoming, 4 = PACKET_OUTGOING), so loopback copies are not double counted."""
    out = []
    while True:
        r, _, _ = select.select([s], [], [], 0.3)
        if not r:
            return out
        data, addr = s.recvfrom(65535)
        if addr[2] == pkttype:
            out.append(data)


def run_ping(args, timeout=30):
    t0 = time.time()
    p = subprocess.Popen([L.CAND, "--noprofile", "--norc", "-c", 'ping "$@"', "cand"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=L.ENV)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        err += "[fixture: killed]"
    return {"pid": p.pid, "rc": p.returncode, "out": out, "err": err, "elapsed": time.time() - t0}


def run_ping_async(args):
    return subprocess.Popen([L.CAND, "--noprofile", "--norc", "-c", 'ping "$@"', "cand"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=L.ENV)


def summary(out):
    m = re.search(r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss, time (\d+)ms", out)
    return tuple(int(x) for x in m.groups()) if m else None


def setup_peer_v4(peer_extra=""):
    peer = Peer()
    L.seed([["link", "add", "v0", "type", "veth", "peer", "name", "v1"], ["link", "set", "v1", "netns", str(peer.pid)], ["addr", "add", "10.77.0.1/24", "dev", "v0"], ["link", "set", "v0", "up"], ["link", "set", "lo", "up"]])
    peer.sh("/usr/bin/ip addr add 10.77.0.2/24 dev v1 && /usr/bin/ip link set v1 up && echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all" + peer_extra)
    return peer


# ------------------------------------------------------------------ deadline / timeout / quiet
def sc_deadline():
    peer = setup_peer_v4()
    try:
        r = run_ping(["-4", "-c", "2", "-W", "0.5", "-i", "0.2", "10.77.0.2"])
        s = summary(r["out"])
        L.check("no-reply: each probe prints a timeout after -W", "seq 1: timeout" in r["out"] and "seq 2: timeout" in r["out"], r["out"])
        L.check("no-reply: summary counts 2 transmitted, 0 received, 100% loss", s is not None and s[:3] == (2, 0, 100), r["out"])
        L.check("no-reply: exit status 1", r["rc"] == 1, str(r["rc"]))
        L.check("no-reply: each wait lasted about -W (total 0.8s..2.5s)", 0.8 <= r["elapsed"] <= 2.5, "elapsed=%.2f" % r["elapsed"])
        q = run_ping(["-4", "-q", "-c", "2", "-W", "0.5", "-i", "0.2", "10.77.0.2"])
        L.check("quiet: unanswered run prints no per-probe timeout lines but the summary", "timeout" not in q["out"] and summary(q["out"]) is not None and summary(q["out"])[:3] == (2, 0, 100), q["out"])
        q2 = run_ping(["-4", "-q", "-c", "2", "-i", "0.2", "127.0.0.1"])
        L.check("quiet: answered run prints no reply lines, only header and summary", "64 bytes from" not in q2["out"] and summary(q2["out"]) is not None and summary(q2["out"])[:3] == (2, 2, 0) and q2["rc"] == 0, q2["out"])
        n = run_ping(["-4", "-c", "2", "-i", "0.2", "127.0.0.1"])
        L.check("control: without -q the answered run prints a reply line per probe", n["out"].count("64 bytes from 127.0.0.1: icmp_seq=") == 2, n["out"])
        d = run_ping(["-4", "-c", "20", "-i", "0.5", "-W", "0.3", "-w", "1", "10.77.0.2"])
        sd = summary(d["out"])
        L.check("deadline: -w 1 ends a 20-probe run with exit status 1", d["rc"] == 1, str(d["rc"]))
        L.check("deadline: fewer probes than -c were transmitted", sd is not None and 1 <= sd[0] < 20, d["out"])
        L.check("timing: elapsed is near the deadline, not count*interval (0.9s..3s, count*interval is 10s)", 0.9 <= d["elapsed"] <= 3.0, "elapsed=%.2f" % d["elapsed"])
        L.check("timing: reported run time agrees (900..1600 ms)", sd is not None and 900 <= sd[3] <= 1600, d["out"])
    finally:
        peer.close()


# ------------------------------------------------------------------ IPv4 echo
def icmp_packets(frames, fam):
    out = []
    for f in frames:
        if fam == 4 and f[12:14] == b"\x08\x00" and f[23] == 1:
            ihl = (f[14] & 15) * 4
            out.append({"ip": f[14:14 + ihl], "icmp": f[14 + ihl:14 + struct.unpack("!H", f[16:18])[0]], "src": socket.inet_ntoa(f[26:30]), "dst": socket.inet_ntoa(f[30:34])})
        elif fam == 6 and f[12:14] == b"\x86\xdd" and f[20] == 58:
            plen = struct.unpack("!H", f[18:20])[0]
            out.append({"icmp": f[54:54 + plen], "src": f[22:38], "dst": f[38:54]})
    return out


def sc_v4_request():
    L.seed([["link", "set", "lo", "up"]])
    sn = sniffer("lo")
    r = run_ping(["-4", "-c", "1", "127.0.0.1"])
    pk = icmp_packets(drain(sn, 4), 4)
    req = [p for p in pk if p["icmp"][0] == 8]
    rep = [p for p in pk if p["icmp"][0] == 0]
    L.check("v4 request: exactly one echo request (type 8) observed to 127.0.0.1", len(req) == 1 and req[0]["dst"] == "127.0.0.1", str(len(req)))
    if req:
        m = req[0]["icmp"]
        L.check("v4 request: code 0, 64-byte ICMP message (8-byte header + 56 data bytes)", m[1] == 0 and len(m) == 64, "code=%d len=%d" % (m[1], len(m)))
        L.check("v4 request: identifier equals the pinging process id", struct.unpack("!H", m[4:6])[0] == r["pid"] & 0xffff, "id=%d pid=%d" % (struct.unpack("!H", m[4:6])[0], r["pid"]))
        L.check("v4 request: sequence number 1", struct.unpack("!H", m[6:8])[0] == 1, str(struct.unpack("!H", m[6:8])[0]))
        L.check("v4 request: ICMP checksum valid (RFC 792 ones-complement sum is 0)", csum(m) == 0, hex(csum(m)))
        L.check("v4 request: IPv4 header IHL 5, protocol 1, header checksum valid", req[0]["ip"][0] == 0x45 and req[0]["ip"][9] == 1 and csum(req[0]["ip"]) == 0, req[0]["ip"].hex())
        L.check("v4 request: the kernel echo reply returns the identical identifier, sequence and data", len(rep) == 1 and rep[0]["icmp"][4:] == m[4:], str(len(rep)))


def sc_v4_accounting():
    L.seed([["link", "set", "lo", "up"]])
    r = run_ping(["-4", "-c", "1", "127.0.0.1"])
    L.check("v4 accounting: header line names the target and 56 data bytes", r["out"].startswith("PING 127.0.0.1 (127.0.0.1) 56 data bytes\n"), r["out"])
    L.check("v4 accounting: one reply line with icmp_seq=1, ttl and time", re.search(r"^64 bytes from 127\.0\.0\.1: icmp_seq=1 ttl=\d+ time=\d+\.\d+ ms$", r["out"], re.M) is not None, r["out"])
    L.check("v4 accounting: summary 1 transmitted, 1 received, 0% loss", summary(r["out"]) is not None and summary(r["out"])[:3] == (1, 1, 0), r["out"])
    L.check("v4 accounting: rtt line present and exit status 0", "rtt min/avg/max/mdev" in r["out"] and r["rc"] == 0, str(r["rc"]))


def forge_run(fam, plan, target, args_extra=()):
    def body():
        if fam == 4:
            peer = setup_peer_v4()
        else:
            peer = Peer()
            L.seed([["link", "add", "v0", "type", "veth", "peer", "name", "v1"], ["link", "set", "v1", "netns", str(peer.pid)], ["addr", "add", "fd77::1/64", "dev", "v0", "nodad"], ["link", "set", "v0", "up"], ["link", "set", "lo", "up"]])
            peer.sh("/usr/bin/ip addr add fd77::2/64 dev v1 nodad && /usr/bin/ip addr add fd77::3/64 dev v1 nodad && /usr/bin/ip link set v1 up && echo 1 > /proc/sys/net/ipv6/icmp/echo_ignore_all")
            time.sleep(0.5)
        try:
            peer.send("respond", fam, plan)
            p = run_ping_async(["-%d" % fam, "-c", "1", "-W", "1.5"] + list(args_extra) + [target])
            out, err = p.communicate(timeout=20)
            res = peer.recv()
            return {"rc": p.returncode, "out": out, "err": err, "peer": res}
        finally:
            peer.close()
    return L.in_netns(body)


def sc_v4_matching():
    a = forge_run(4, [["wrong-id", None], ["wrong-seq", None], ["wrong-payload", None]], "10.77.0.2")
    L.check("v4 matching: the peer saw the request and sent three forged replies", a["peer"][1] is True and a["peer"][2] == 3, str(a["peer"]))
    L.check("v4 matching: replies with wrong identifier, sequence or payload are not accepted (0 received, status 1)", summary(a["out"]) is not None and summary(a["out"])[:3] == (1, 0, 100) and a["rc"] == 1 and "64 bytes from" not in a["out"], a["out"])
    b = forge_run(4, [["wrong-id", None], ["wrong-seq", None], ["wrong-payload", None], ["good", None]], "10.77.0.2")
    L.check("v4 matching: the exactly matching reply after forged ones is accepted (1 received, status 0)", summary(b["out"]) is not None and summary(b["out"])[:3] == (1, 1, 0) and b["rc"] == 0, b["out"])
    L.check("v4 matching: one reply line from 10.77.0.2 for icmp_seq=1", len(re.findall(r"^64 bytes from 10\.77\.0\.2: icmp_seq=1 ", b["out"], re.M)) == 1, b["out"])


# ------------------------------------------------------------------ IPv6 echo
def sc_v6_request():
    L.seed([["link", "set", "lo", "up"]])
    sysctl_dad_off()
    sn = sniffer("lo")
    r = run_ping(["-6", "-c", "1", "::1"])
    pk = icmp_packets(drain(sn, 4), 6)
    req = [p for p in pk if p["icmp"][0] == 128]
    rep = [p for p in pk if p["icmp"][0] == 129]
    L.check("v6 request: exactly one echo request (type 128) to ::1", len(req) == 1, str(len(pk)))
    if req:
        m = req[0]["icmp"]
        L.check("v6 request: code 0 and 64-byte ICMPv6 message", m[1] == 0 and len(m) == 64, "code=%d len=%d" % (m[1], len(m)))
        L.check("v6 request: identifier equals the process id and sequence is 1", struct.unpack("!HH", m[4:8]) == (r["pid"] & 0xffff, 1), str(struct.unpack("!HH", m[4:8])))
        pseudo = req[0]["src"] + req[0]["dst"] + struct.pack("!I", len(m)) + b"\0\0\0\x3a"
        L.check("v6 request: ICMPv6 checksum valid over the IPv6 pseudo-header (RFC 4443)", csum(pseudo + m) == 0, hex(csum(pseudo + m)))
        L.check("v6 request: kernel echo reply (type 129) carries the identical id, seq and data", len(rep) == 1 and rep[0]["icmp"][4:] == m[4:], str(len(rep)))


def sc_v6_matching():
    plan = [["wrong-id", None], ["wrong-seq", None], ["wrong-payload", None], ["good", "fd77::3"]]
    a = forge_run(6, plan, "fd77::2")
    L.check("v6 matching: the peer saw the request and sent four replies", a["peer"][1] is True and a["peer"][2] == 4, str(a["peer"]))
    L.check("v6 matching: forged replies and a correct reply from another source are ignored (0 received, status 1)", summary(a["out"]) is not None and summary(a["out"])[:3] == (1, 0, 100) and a["rc"] == 1 and "64 bytes from" not in a["out"], a["out"])
    b = forge_run(6, plan + [["good", None]], "fd77::2")
    L.check("v6 matching: the matching reply from the target is accepted (1 received, status 0)", summary(b["out"]) is not None and summary(b["out"])[:3] == (1, 1, 0) and b["rc"] == 0, b["out"])
    L.check("v6 matching: the reply line names the target address and icmp_seq=1", re.search(r"^64 bytes from fd77::2: icmp_seq=1 ", b["out"], re.M) is not None, b["out"])


def sc_v6_accounting():
    L.seed([["link", "set", "lo", "up"]])
    sysctl_dad_off()
    r = run_ping(["-6", "-c", "2", "-i", "0.2", "::1"])
    L.check("v6 accounting: two reply lines from ::1", r["out"].count("64 bytes from ::1: icmp_seq=") == 2, r["out"])
    L.check("v6 accounting: summary 2 transmitted, 2 received, 0% loss, status 0", summary(r["out"]) is not None and summary(r["out"])[:3] == (2, 2, 0) and r["rc"] == 0, r["out"])


# ------------------------------------------------------------------ traceroute
def trace_topology(drop_time_exceeded=False):
    r, d = Peer(), Peer()
    L.seed([["link", "add", "v0", "type", "veth", "peer", "name", "v1"], ["link", "add", "w0", "type", "veth", "peer", "name", "w1"],
            ["link", "set", "v1", "netns", str(r.pid)], ["link", "set", "w0", "netns", str(r.pid)], ["link", "set", "w1", "netns", str(d.pid)],
            ["addr", "add", "10.77.0.1/24", "dev", "v0"], ["link", "set", "v0", "up"], ["route", "add", "10.88.0.0/24", "via", "10.77.0.2"]])
    x = r.sh("/usr/bin/ip addr add 10.77.0.2/24 dev v1 && /usr/bin/ip link set v1 up && /usr/bin/ip addr add 10.88.0.1/24 dev w0 && /usr/bin/ip link set w0 up && echo 1 > /proc/sys/net/ipv4/ip_forward"
             + (" && /usr/sbin/iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j DROP" if drop_time_exceeded else ""))
    y = d.sh("/usr/bin/ip addr add 10.88.0.2/24 dev w1 && /usr/bin/ip link set w1 up && /usr/bin/ip route add default via 10.88.0.1")
    L.check("traceroute topology configured (router and destination namespaces)", x[0] == 0 and y[0] == 0, "%s %s" % (x, y))
    time.sleep(0.3)
    return r, d


def probes(frames, dst):
    out = []
    for f in frames:
        if f[12:14] == b"\x08\x00" and f[23] == 17 and socket.inet_ntoa(f[30:34]) == dst:
            ihl = (f[14] & 15) * 4
            out.append((f[22], struct.unpack("!H", f[14 + ihl + 2:14 + ihl + 4])[0]))
    return out


def hops(out):
    res = {}
    for ln in out.splitlines():
        m = re.match(r"^\s*(\d+) (.*)$", ln)
        if m and not ln.startswith("traceroute"):
            tail = m.group(2).split()
            res[int(m.group(1))] = tail[-1] if tail else ""
    return res


def trace(args, dst, topo_kw=None):
    def body():
        r, d = trace_topology(**(topo_kw or {}))
        sn = sniffer("v0")
        try:
            res = run_ping(["-T"] + args + [dst])
            res["probes"] = [list(x) for x in probes(drain(sn, 4), dst)]
            return res
        finally:
            sn.close()
            r.close()
            d.close()
    return L.in_netns(body)


def sc_trace_ttl():
    r = trace(["-Q", "1", "-W", "1", "-m", "5"], "10.88.0.2")
    L.check("traceroute: UDP probes carry increasing TTL 1, 2 with increasing destination ports", r["probes"] == [[1, 33434], [2, 33435]], str(r["probes"]))
    L.check("traceroute: header names the target and max hops", r["out"].startswith("traceroute to 10.88.0.2 (10.88.0.2), 5 hops max"), r["out"])
    L.check("traceroute: hop 1 is the router that sent time-exceeded", hops(r["out"]).get(1) == "10.77.0.2", r["out"])
    r2 = trace(["-Q", "3", "-W", "1", "-m", "3"], "10.88.0.2")
    L.check("traceroute: three probes per hop by default repeat each TTL", [t for t, _ in r2["probes"]] == [1, 1, 1, 2, 2, 2], str(r2["probes"]))


def sc_trace_hops():
    r = trace(["-Q", "1", "-W", "1", "-m", "5"], "10.88.0.2")
    h = hops(r["out"])
    L.check("traceroute: time-exceeded hop printed with its router address and an rtt", h.get(1) == "10.77.0.2" and re.search(r"^\s*1 .*\d+\.\d+ms", r["out"], re.M) is not None, r["out"])
    s = trace(["-Q", "1", "-W", "0.6", "-m", "5"], "10.88.0.2", {"drop_time_exceeded": True})
    L.check("traceroute: a non-answering hop prints a timeout (*)", re.search(r"^\s*1  \*\s*$|^\s*1\s+\*", s["out"], re.M) is not None and hops(s["out"]).get(1) == "*", s["out"])
    L.check("traceroute: the trace still continues to the next hop and reaches the destination", hops(s["out"]).get(2) == "10.88.0.2", s["out"])


def sc_trace_reached():
    r = trace(["-Q", "1", "-W", "1", "-m", "6"], "10.88.0.2")
    L.check("traceroute: destination port-unreachable ends the trace at hop 2", max(hops(r["out"])) == 2 and hops(r["out"]).get(2) == "10.88.0.2", r["out"])
    L.check("traceroute: reached destination gives exit status 0", r["rc"] == 0, str(r["rc"]))


def sc_trace_unreached():
    r = trace(["-Q", "1", "-W", "0.5", "-m", "3"], "10.88.0.99")
    L.check("traceroute: probes continue through max TTL 3 for an unreachable destination", [t for t, _ in r["probes"]] == [1, 2, 3], str(r["probes"]))
    L.check("traceroute: unreached destination after -m 3 gives exit status 1", r["rc"] == 1 and max(hops(r["out"])) == 3, "rc=%s out=%s" % (r["rc"], r["out"]))


# ------------------------------------------------------------------ option rejection never opens a socket
class Bpf(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


def kill_on_socket():
    """seccomp (x86_64): kill on socket() of any SOCK_RAW socket or any AF_INET SOCK_DGRAM socket
    (the ICMP socket and the resolver's UDP socket); other sockets the shell may open are allowed."""
    prog = [Bpf(0x20, 0, 0, 0), Bpf(0x15, 0, 7, 41), Bpf(0x20, 0, 0, 24), Bpf(0x54, 0, 0, 0xf), Bpf(0x15, 3, 0, 3), Bpf(0x15, 0, 3, 2),
            Bpf(0x20, 0, 0, 16), Bpf(0x15, 0, 1, 2), Bpf(0x06, 0, 0, 0x80000000), Bpf(0x06, 0, 0, 0x7fff0000)]
    arr = (Bpf * len(prog))(*prog)

    class Fprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    fp = Fprog(len(prog), ctypes.cast(arr, ctypes.c_void_p))

    def install():
        libc.prctl(38, 1, 0, 0, 0)
        if libc.prctl(22, 2, ctypes.byref(fp)) != 0:
            os._exit(97)
    return install


def sc_no_socket():
    L.seed([["link", "set", "lo", "up"]])
    inst = kill_on_socket()
    def run(args):
        p = subprocess.run([L.CAND, "--noprofile", "--norc", "-c", 'ping "$@"', "cand"] + args, capture_output=True, text=True, env=L.ENV, preexec_fn=inst, timeout=20)
        return p.returncode, p.stderr
    rc, err = run(["-c", ":"] if False else ["-V"])
    L.check("baseline: the shell and a non-network ping option (-V) run to completion under the socket-killing filter", rc == 0, "rc=%s err=%r" % (rc, err))
    rc, err = run(["-c", "1", "127.0.0.1"])
    L.check("control: a valid ping under the socket-killing filter is terminated by SIGSYS (so the filter observes socket creation)", rc < 0 or rc == 128 + 31, "rc=%s err=%r" % (rc, err))
    for args in (["-c", "0"], ["-c", "abc"], ["-c", "10001"], ["-W", "0"], ["-W", "61"], ["-w", "0"], ["-w", "86401"], ["-i", "0.01"], ["-i", "x"], ["-c", ""]):
        rc, err = run(args + ["nonexistent.invalid"])
        L.check("rejected %s: usage status 2 without any socket() call (not killed, no resolution failure)" % " ".join(args), rc == 2 and "cannot resolve" not in err, "rc=%s err=%r" % (rc, err))


SCEN = {"deadline": sc_deadline, "v4-request": sc_v4_request, "v4-accounting": sc_v4_accounting, "v4-matching": sc_v4_matching,
        "v6-request": sc_v6_request, "v6-matching": sc_v6_matching, "v6-accounting": sc_v6_accounting,
        "trace-ttl": sc_trace_ttl, "trace-hops": sc_trace_hops, "trace-reached": sc_trace_reached, "trace-unreached": sc_trace_unreached,
        "no-socket": sc_no_socket}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
