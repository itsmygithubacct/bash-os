#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""w1 ss/netstat fixtures: candidate socket listings versus a model of the sockets the fixture owns.

Run inside `unshare --user --map-root-user --net --mount --uts`. The fixture holds a
fixed set of sockets in a fresh network namespace (IPv4/IPv6 TCP listeners and an
established pair, bound and connected UDP sockets, unix stream/dgram sockets). The
expected rows come from those sockets (getsockname/getpeername, listen backlog), and
GNU iproute2 `ss` (/usr/bin/ss) is the oracle for row-set comparison and process
annotation format. Per-check detail goes to stderr, the verdict to stdout.
"""
import ctypes
import json
import os
import re
import signal
import socket
import struct
import sys
import time

import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

SS = "/usr/bin/ss"
CASE = "/tmp/parity-case"
HDR_NETSTAT = "Proto Recv-Q Send-Q Local Address Foreign Address State"
libc = ctypes.CDLL(None, use_errno=True)


class World:
    def __init__(self):
        libc.prctl(4, 1, 0, 0, 0)  # PR_SET_DUMPABLE=1: userns creation left the process non-dumpable
        L.seed([["link", "set", "lo", "up"]])
        self.socks = []
        self.t4l = self.tcp_listen(socket.AF_INET, "127.0.0.1", 7)
        self.t4c = socket.socket()
        self.t4c.connect(self.t4l.getsockname())
        self.t4a, _ = self.t4l.accept()
        self.t6l = self.tcp_listen(socket.AF_INET6, "::1", 5)
        self.u4 = self.udp(socket.AF_INET, "127.0.0.1")
        self.u6 = self.udp(socket.AF_INET6, "::1")
        self.u4c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.u4c.connect(self.u4.getsockname())
        self.xpath = CASE + "/srv.sock"
        self.xl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.xl.bind(self.xpath)
        self.xl.listen(3)
        self.xc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.xc.connect(self.xpath)
        self.xa, _ = self.xl.accept()
        self.dgpath = CASE + "/dg.sock"
        self.xd = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.xd.bind(self.dgpath)
        self.socks += [self.t4c, self.t4a, self.u4c, self.xl, self.xc, self.xa, self.xd]

    def tcp_listen(self, fam, addr, backlog):
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.bind((addr, 0))
        s.listen(backlog)
        self.socks.append(s)
        return s

    def udp(self, fam, addr):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.bind((addr, 0))
        self.socks.append(s)
        return s

    # model rows: (family, state, recvq, sendq, local, peer); address text is plain "a:p" (no brackets)
    @staticmethod
    def ep(sock, peer=False):
        a = sock.getpeername() if peer else sock.getsockname()
        return "%s:%d" % (a[0], a[1])

    def inet_rows(self):
        return {
            ("tcp", "LISTEN", 0, 7, self.ep(self.t4l), "0.0.0.0:*"),
            ("tcp", "ESTAB", 0, 0, self.ep(self.t4c), self.ep(self.t4c, True)),
            ("tcp", "ESTAB", 0, 0, self.ep(self.t4a), self.ep(self.t4a, True)),
            ("tcp6", "LISTEN", 0, 5, self.ep(self.t6l), ":::*"),
            ("udp", "UNCONN", 0, 0, self.ep(self.u4), "0.0.0.0:*"),
            ("udp", "ESTAB", 0, 0, self.ep(self.u4c), self.ep(self.u4c, True)),
            ("udp6", "UNCONN", 0, 0, self.ep(self.u6), ":::*"),
        }

    def ss_inet_rows(self):
        # ss brackets IPv6 endpoints; netstat retains its legacy spelling.
        def bracket(ep):
            addr, port = ep.rsplit(":", 1)
            return "[%s]:%s" % (addr, port)
        return {(net, state, rq, sq, bracket(local), bracket(peer))
                if net.endswith("6") else (net, state, rq, sq, local, peer)
                for net, state, rq, sq, local, peer in self.inet_rows()}

    def close(self):
        for s in self.socks + [self.t4l, self.t6l, self.u4, self.u6]:
            try:
                s.close()
            except OSError:
                pass


def parse_ss(text):
    rows = []
    for ln in text.splitlines()[1:]:
        t = ln.split()
        if len(t) >= 6:
            rows.append({"netid": t[0], "state": t[1], "rq": int(t[2]), "sq": int(t[3]), "local": t[4], "peer": t[5], "rest": " ".join(t[6:])})
    return rows


def parse_netstat(text):
    rows = []
    for ln in text.splitlines()[1:]:
        t = ln.split()
        if len(t) >= 6:
            rows.append({"proto": t[0], "rq": int(t[1]), "sq": int(t[2]), "local": t[3], "peer": t[4], "state": t[5], "rest": " ".join(t[6:])})
    return rows


def runp(argv, preexec=None, timeout=30):
    import subprocess
    p = subprocess.run(argv, capture_output=True, text=True, env=L.ENV, timeout=timeout, preexec_fn=preexec)
    return p.returncode, p.stdout, p.stderr


def cand_ss(*args, preexec=None, tool="ss"):
    return runp([L.CAND, "--noprofile", "--norc", "-c", tool + ' "$@"', "cand"] + list(args), preexec=preexec)


def inet_set_ss(rows):
    return {(r["netid"], r["state"], r["rq"], r["sq"], r["local"], r["peer"]) for r in rows if r["netid"].startswith(("tcp", "udp"))}


def inet_set_ns(rows):
    return {(r["proto"], r["state"], r["rq"], r["sq"], r["local"], r["peer"]) for r in rows if r["proto"].startswith(("tcp", "udp"))}


def netids(rows, key="netid"):
    return {r[key] for r in rows}


def eqset(name, got, want):
    L.check(name, got == want, "only-candidate=%s only-expected=%s" % (sorted(map(str, got - want)), sorted(map(str, want - got))))


def unix_rows_ss(rows, key="netid"):
    return [r for r in rows if r[key].startswith("u_")]


# --------------------------------------------------------------------------- ss selectors
def sc_ss_default():
    w = World()
    rc, out, err = cand_ss()
    L.check("ss default rc0", rc == 0, err)
    rows = parse_ss(out)
    L.check("ss default shows only TCP rows", netids(rows) <= {"tcp", "tcp6"} and rows, "netids=%s" % sorted(netids(rows)))
    eqset("ss default TCP rows equal the fixture's TCP sockets", inet_set_ss(rows), {r for r in w.ss_inet_rows() if r[0].startswith("tcp")})
    w.close()


def sc_ss_families():
    w = World()
    want = w.ss_inet_rows()
    tcp = {r for r in want if r[0].startswith("tcp")}
    udp = {r for r in want if r[0].startswith("udp")}
    for flags, fams in (("-t", {"tcp"}), ("-u", {"udp"}), ("-x", {"unix"}), ("-tu", {"tcp", "udp"}), ("-tx", {"tcp", "unix"}), ("-ux", {"udp", "unix"}), ("-tux", {"tcp", "udp", "unix"})):
        rc, out, err = cand_ss(flags)
        rows = parse_ss(out)
        L.check("ss %s rc0" % flags, rc == 0, err)
        exp = set()
        if "tcp" in fams:
            exp |= tcp
        if "udp" in fams:
            exp |= udp
        eqset("ss %s inet rows" % flags, inet_set_ss(rows), exp)
        ux = unix_rows_ss(rows)
        if "unix" in fams:
            L.check("ss %s includes unix rows (listener, pair, dgram)" % flags, len(ux) >= 4 and any(r["local"] == w.xpath for r in ux), str(ux))
        else:
            L.check("ss %s has no unix rows" % flags, not ux, str(ux))
    w.close()


def sc_ss_listen_all():
    w = World()
    want = w.ss_inet_rows()
    for flags, pred in (("-tl", lambda r: r[0].startswith("tcp") and r[1] == "LISTEN"), ("-ta", lambda r: r[0].startswith("tcp")),
                        ("-ul", lambda r: r[0].startswith("udp") and r[1] == "UNCONN"), ("-ua", lambda r: r[0].startswith("udp"))):
        rc, out, err = cand_ss(flags)
        eqset("ss %s rows" % flags, inet_set_ss(parse_ss(out)), {r for r in want if pred(r)})
    rc, out, err = cand_ss("-xl")
    ux = unix_rows_ss(parse_ss(out))
    L.check("ss -xl shows only the unix listener", len(ux) == 1 and ux[0]["state"] == "LISTEN" and ux[0]["local"] == w.xpath, str(ux))
    rc, out, err = cand_ss("-xa")
    ux = unix_rows_ss(parse_ss(out))
    L.check("ss -xa shows listener, both ends of the pair and the dgram socket", len(ux) == 4 and {r["state"] for r in ux} == {"LISTEN", "ESTAB", "UNCONN"}, str(ux))
    w.close()


def sc_ss_numeric():
    w = World()
    rc, out, err = cand_ss("-tuna")
    L.check("ss numeric exits 0", rc == 0, err)
    rows = parse_ss(out)
    local4 = w.ep(w.t4l)
    L.check("ss IPv4 TCP listener endpoint numeric 127.0.0.1:PORT", any(r["local"] == local4 and r["state"] == "LISTEN" for r in rows), out)
    L.check("ss IPv4 UDP endpoint numeric 127.0.0.1:PORT", any(r["local"] == w.ep(w.u4) for r in rows), out)
    p6 = w.t6l.getsockname()[1]
    L.check("ss IPv6 TCP listener endpoint is [::1]:PORT", any(r["local"] == "[::1]:%d" % p6 for r in rows), "locals=%s" % sorted({r["local"] for r in rows if r["netid"] == "tcp6"}))
    pu6 = w.u6.getsockname()[1]
    L.check("ss IPv6 UDP endpoint is [::1]:PORT", any(r["local"] == "[::1]:%d" % pu6 for r in rows), "locals=%s" % sorted({r["local"] for r in rows if r["netid"] == "udp6"}))
    L.check("ss IPv6 wildcard peer of the listener is [::]:*", any(r["netid"] == "tcp6" and r["peer"] == "[::]:*" for r in rows), "peers=%s" % sorted({r["peer"] for r in rows if r["netid"] == "tcp6"}))
    w.close()


def norm_ss_rows(rows, key_net="netid", numeric_unix=False):
    out = set()
    for r in rows:
        net = r[key_net]
        if net in ("tcp6",):
            net = "tcp"
        if net == "udp6":
            net = "udp"
        loc, peer = r["local"], r["peer"]
        if net.startswith("u_"):
            out.add((net, r["state"], loc.split()[0] if loc else loc))
        else:
            loc = loc.replace("[", "").replace("]", "")
            peer = peer.replace("[", "").replace("]", "")
            out.add((net, r["state"], r["rq"], r["sq"], loc, peer))
    return out


def parse_iproute2_ss(text, default_netid="udp"):
    """iproute2 omits the Netid column when one socket type is selected."""
    rows = []
    lines = text.splitlines()
    has_netid = bool(lines) and lines[0].startswith("Netid")
    for ln in lines[1:]:
        t = ln.split()
        if has_netid:
            if len(t) >= 6:
                rows.append({"netid": t[0], "state": t[1], "rq": int(t[2]), "sq": int(t[3]), "local": t[4], "peer": t[5]})
        elif len(t) >= 5:
            rows.append({"netid": default_netid, "state": t[0], "rq": int(t[1]), "sq": int(t[2]), "local": t[3], "peer": t[4]})
    return rows


def sc_ss_vs_iproute2():
    w = World()
    rc, ref_out, _ = L.run([SS, "-tuxan"])
    ref = parse_iproute2_ss(ref_out)
    rc, out, err = cand_ss("-tuxa")
    got = parse_ss(out)
    gs, rs = norm_ss_rows(got), norm_ss_rows(ref)
    L.check("ss reference produced rows for every family", {"tcp", "udp", "u_str", "u_dgr"} <= {r[0] for r in rs}, sorted(r[0] for r in rs))
    L.check("ss -tuxa unix rows equal iproute2's (netid, state, path)", {r for r in gs if r[0].startswith("u_")} == {r for r in rs if r[0].startswith("u_")},
            "only-candidate=%s only-iproute2=%s" % (sorted(r for r in gs - rs if r[0].startswith("u_")), sorted(r for r in rs - gs if r[0].startswith("u_"))))
    L.check("ss -tuxa inet rows equal iproute2's (netid, state, queues, endpoints)", {r for r in gs if not r[0].startswith("u_")} == {r for r in rs if not r[0].startswith("u_")},
            "only-candidate=%s only-iproute2=%s" % (sorted(r for r in gs - rs if not r[0].startswith("u_")), sorted(r for r in rs - gs if not r[0].startswith("u_"))))
    w.close()


# --------------------------------------------------------------------------- netstat
def cand_ns(*args, preexec=None):
    return cand_ss(*args, preexec=preexec, tool="netstat")


def ns_inet_model(w):
    # net-tools netstat spells TCP states in full (ESTABLISHED); UDP keeps the
    # ss labels this interface prints (UNCONN, ESTAB). See sc_ns_tcp_labels.
    return {(net, "ESTABLISHED" if net.startswith("tcp") and state == "ESTAB" else state, rq, sq, local, peer)
            for net, state, rq, sq, local, peer in w.inet_rows()}


def sc_ns_aliases():
    w = World()
    for a, b, fams in (("-t", "--tcp", "tcp"), ("-u", "--udp", "udp"), ("-x", "--unix", "unix")):
        ra = cand_ns(a)
        rb = cand_ns(b)
        L.check("netstat %s and %s both rc0" % (a, b), ra[0] == 0 and rb[0] == 0, "%s %s" % (ra[2], rb[2]))
        pa, pb = parse_netstat(ra[1]), parse_netstat(rb[1])
        L.check("netstat %s and %s print identical output" % (a, b), ra[1] == rb[1], "short=%r long=%r" % (ra[1][:300], rb[1][:300]))
        if fams == "tcp":
            eqset("netstat -t selects exactly the TCP sockets", inet_set_ns(pa), {r for r in ns_inet_model(w) if r[0].startswith("tcp")})
        elif fams == "udp":
            eqset("netstat -u selects exactly the UDP sockets", inet_set_ns(pa), {r for r in ns_inet_model(w) if r[0].startswith("udp")})
        else:
            L.check("netstat -x selects only unix rows including the listener path", pa and all(r["proto"].startswith("u_") for r in pa) and any(r["local"] == w.xpath for r in pa), str(pa))
    ra = cand_ns("-tl")
    rb = cand_ns("--tcp", "--listening")
    L.check("netstat -tl and --tcp --listening print identical output", ra[1] == rb[1] and ra[0] == 0, "%r %r" % (ra[1][:200], rb[1][:200]))
    ra = cand_ns("-ta")
    rb = cand_ns("--tcp", "--all")
    L.check("netstat -ta and --tcp --all print identical output", ra[1] == rb[1] and ra[0] == 0, "%r %r" % (ra[1][:200], rb[1][:200]))
    w.close()


def sc_ns_states():
    w = World()
    want = ns_inet_model(w)
    rc, out, err = cand_ns("-tl")
    eqset("netstat -tl shows only TCP listeners", inet_set_ns(parse_netstat(out)), {r for r in want if r[0].startswith("tcp") and r[1] == "LISTEN"})
    rc, out, err = cand_ns("-ta")
    eqset("netstat -ta shows every TCP state", inet_set_ns(parse_netstat(out)), {r for r in want if r[0].startswith("tcp")})
    rc, out, err = cand_ns("-t")
    eqset("netstat -t without -l/-a shows every TCP state", inet_set_ns(parse_netstat(out)), {r for r in want if r[0].startswith("tcp")})
    rc, out, err = cand_ns("-ul")
    eqset("netstat -ul shows only unconnected UDP sockets", inet_set_ns(parse_netstat(out)), {r for r in want if r[0].startswith("udp") and r[1] == "UNCONN"})
    rc, out, err = cand_ns("-xl")
    rows = parse_netstat(out)
    L.check("netstat -xl shows only the unix listener", len(rows) == 1 and rows[0]["local"] == w.xpath and rows[0]["state"] in ("LISTEN", "LISTENING"), str(rows))
    rc, out, err = cand_ns("-xa")
    L.check("netstat -xa shows every unix socket (listener, pair, dgram)", len(parse_netstat(out)) == 4, out)
    w.close()


def sc_ns_default_families():
    w = World()
    rc, out, err = cand_ns()
    rows = parse_netstat(out)
    L.check("netstat with no flags rc0", rc == 0, err)
    eqset("netstat with no flags shows every TCP and UDP socket", inet_set_ns(rows), ns_inet_model(w))
    L.check("netstat with no flags also shows the unix sockets", len([r for r in rows if r["proto"].startswith("u_")]) == 4, out)
    w.close()


def sc_ns_option_reset():
    w = World()
    script = 'netstat -tl; echo ==; netstat; echo ==; netstat -x; echo ==; netstat -ul; echo ==; netstat'
    rc, out, err = L.cand(script)
    parts = out.split("==\n")
    L.check("netstat option reset: five calls ran", rc == 0 and len(parts) == 5, "rc=%s parts=%d err=%s" % (rc, len(parts), err))
    if len(parts) == 5:
        all_rows = ns_inet_model(w)
        eqset("netstat after -tl shows the TCP listeners only", inet_set_ns(parse_netstat(parts[0])), {r for r in all_rows if r[0].startswith("tcp") and r[1] == "LISTEN"})
        r2 = parse_netstat(parts[1])
        eqset("plain netstat after -tl shows all TCP and UDP states again", inet_set_ns(r2), all_rows)
        L.check("plain netstat after -tl shows unix rows again", len([r for r in r2 if r["proto"].startswith("u_")]) == 4, parts[1])
        r3 = parse_netstat(parts[2])
        L.check("netstat -x after plain call shows unix rows only", r3 and all(r["proto"].startswith("u_") for r in r3), parts[2])
        r5 = parse_netstat(parts[4])
        L.check("final plain netstat is identical to the first plain netstat", parts[4] == parts[1], "first=%r last=%r" % (parts[1][:200], parts[4][:200]))
        eqset("netstat -ul after -x shows only unconnected UDP", inet_set_ns(parse_netstat(parts[3])), {r for r in all_rows if r[0].startswith("udp") and r[1] == "UNCONN"})
    w.close()


def sc_ns_tcp_rows():
    w = World()
    rc, out, err = cand_ns("-t")
    rows = parse_netstat(out)
    want = {r for r in ns_inet_model(w) if r[0] == "tcp"}
    eqset("netstat -t IPv4 rows (queues, endpoints, state) equal the fixture sockets", {r for r in inet_set_ns(rows) if r[0] == "tcp"}, want)
    L.check("netstat -t listener row shows the listen backlog as Send-Q", any(r["state"] == "LISTEN" and r["sq"] == 7 and r["local"] == w.ep(w.t4l) for r in rows), out)
    w.close()


def sc_ns_tcp_labels():
    w = World()
    rc, out, err = cand_ns("-t")
    rows = parse_netstat(out)
    L.check("netstat TCP states use the net-tools vocabulary (LISTEN, ESTABLISHED)", {r["state"] for r in rows if r["proto"] == "tcp"} == {"LISTEN", "ESTABLISHED"},
            "states=%s" % sorted({r["state"] for r in rows if r["proto"] == "tcp"}))
    w.close()


def sc_ns_udp_rows():
    w = World()
    rc, out, err = cand_ns("-u")
    rows = parse_netstat(out)
    eqset("netstat -u rows (queues, endpoints, state label) equal the fixture sockets", inet_set_ns(rows), {r for r in ns_inet_model(w) if r[0].startswith("udp")})
    L.check("netstat -u every row carries a state label", all(r["state"] for r in rows) and rows, out)
    ref = parse_iproute2_ss(L.run([SS, "-uan"])[1])
    L.check("netstat -u state labels equal iproute2 ss -uan", sorted((r["local"].replace("[", "").replace("]", ""), r["state"]) for r in ref) == sorted((r["local"], r["state"]) for r in rows),
            "ref=%s got=%s" % (sorted((r["local"], r["state"]) for r in ref), sorted((r["local"], r["state"]) for r in rows)))
    w.close()


def sc_ns_ipv6():
    w = World()
    rc, out, err = cand_ns("-tu")
    rows = parse_netstat(out)
    p6 = w.t6l.getsockname()[1]
    pu6 = w.u6.getsockname()[1]
    L.check("netstat IPv6 TCP listener uses a bracket-free numeric address ::1:PORT", any(r["proto"] == "tcp6" and r["local"] == "::1:%d" % p6 and r["state"] == "LISTEN" for r in rows), out)
    L.check("netstat IPv6 UDP socket uses a bracket-free numeric address ::1:PORT", any(r["proto"] == "udp6" and r["local"] == "::1:%d" % pu6 for r in rows), out)
    L.check("netstat IPv6 rows contain no brackets", not any("[" in r["local"] or "[" in r["peer"] for r in rows if r["proto"].endswith("6")), out)
    L.check("netstat IPv6 wildcard foreign address is :::*", any(r["proto"] == "tcp6" and r["peer"] == ":::*" for r in rows), out)
    w.close()


def sc_ns_header():
    w = World()
    for args in (["-t"], ["-u"], ["-x"], []):
        rc, out, err = cand_ns(*args)
        first = out.splitlines()[0] if out else ""
        L.check("netstat %s first line is the legacy header" % (" ".join(args) or "(no flags)"), " ".join(first.split()) == HDR_NETSTAT, repr(first))
    w.close()


# --------------------------------------------------------------------------- process annotation
def drop_caps():
    for cap in (19,):  # CAP_SYS_PTRACE only: non-dumpable owners become unreadable, dumpable ones stay readable
        libc.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP


def spawn_owner(mode):
    """Fork a child that owns a TCP listener and optionally becomes non-dumpable."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(3)
        libc.prctl(4, 0 if mode == "hidden" else 1, 0, 0, 0)  # PR_SET_DUMPABLE
        os.write(w, json.dumps({"port": s.getsockname()[1], "fd": s.fileno()}).encode() + b"\n")
        signal.pause()
        os._exit(0)
    os.close(w)
    info = json.loads(os.fdopen(r).readline())
    info["pid"] = pid
    return info


def stop(pid):
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


def sc_annot_ss():
    other = spawn_owner("plain")
    w = World()
    try:
        rc, out, err = cand_ss("-tp")
        rows = parse_ss(out)
        me = os.getpid()
        comm = open("/proc/self/comm").read().strip()
        def users(r):
            return re.findall(r'\("([^"]*)",pid=(\d+),fd=(\d+)\)', r["rest"])
        def row(port):
            return next((r for r in rows if r["local"].endswith(":%d" % port) and r["state"] == "LISTEN"), None)
        ours = row(w.t4l.getsockname()[1])
        L.check("ss -p annotates the fixture-owned listener with its pid and fd", ours is not None and (comm, str(me), str(w.t4l.fileno())) in users(ours), str(ours))
        acc = [r for r in rows if r["local"] == w.ep(w.t4a) and r["state"] == "ESTAB"]
        L.check("ss -p annotates the accepted connection with its own descriptor", acc and (comm, str(me), str(w.t4a.fileno())) in users(acc[0]), str(acc))
        cli = [r for r in rows if r["local"] == w.ep(w.t4c)]
        L.check("ss -p annotates the client end with its own descriptor", cli and (comm, str(me), str(w.t4c.fileno())) in users(cli[0]), str(cli))
        oth = row(other["port"])
        L.check("ss -p attributes the child's listener to the child pid and fd, not the parent", oth is not None and users(oth) == [(comm, str(other["pid"]), str(other["fd"]))], str(oth))
        rc, out, err = cand_ss("-xp")
        ux = [r for r in parse_ss(out) if r["local"] == w.xpath and r["state"] == "LISTEN"]
        L.check("ss -xp annotates the unix listener with pid and fd", ux and (comm, str(me), str(w.xl.fileno())) in users(ux[0]), str(ux))
        ref = L.run([SS, "-tpln"])[1]
        m = re.search(r'127\.0\.0\.1:%d\s.*users:\(\("([^"]*)",pid=(\d+),fd=(\d+)\)\)' % w.t4l.getsockname()[1], ref)
        L.check("ss -p annotation equals iproute2's for the same listener", m is not None and (m.group(1), m.group(2), m.group(3)) == (comm, str(me), str(w.t4l.fileno())), ref)
        rc, out, err = cand_ss("-t")
        L.check("ss without -p has no users annotation", "users:" not in out, out)
    finally:
        stop(other["pid"])
        w.close()


def sc_annot_denied():
    hidden = spawn_owner("hidden")
    plain = spawn_owner("plain")
    w = World()
    try:
        # Control: with capabilities intact every owner directory is readable and annotated.
        rc2, out2, err2 = cand_ss("-tp")
        rows2 = parse_ss(out2)
        def row(rows, port):
            return next((r for r in rows if r["local"].endswith(":%d" % port) and r["state"] == "LISTEN"), None)
        for label, o in (("hidden", hidden), ("plain", plain)):
            r2 = row(rows2, o["port"])
            L.check("control: with CAP_SYS_PTRACE the %s owner is annotated with its pid" % label, r2 is not None and "pid=%d" % o["pid"] in r2["rest"], str(r2))
        # Denied: the scanner has no CAP_SYS_PTRACE, so /proc/PID/fd of non-dumpable owners cannot be read.
        rc, out, err = cand_ss("-tp", preexec=drop_caps)
        rows = parse_ss(out)
        L.check("ss -tp with unreadable process directories exits 0", rc == 0, "rc=%s err=%s" % (rc, err))
        h = row(rows, hidden["port"])
        L.check("the unreadable owner's listener row is still listed", h is not None, out)
        L.check("the unreadable owner's row carries no annotation", h is not None and "users:" not in h["rest"], str(h))
        eqset("every fixture TCP row is still listed under denial", inet_set_ss(rows) & {r for r in w.ss_inet_rows() if r[0].startswith("tcp")}, {r for r in w.ss_inet_rows() if r[0].startswith("tcp")})
        rc, out, err = cand_ns("-tp", preexec=drop_caps)
        nrows = parse_netstat(out)
        hn = next((r for r in nrows if r["local"].endswith(":%d" % hidden["port"])), None)
        L.check("netstat -tp keeps the unreadable owner's row without an annotation and exits 0", rc == 0 and hn is not None and not hn["rest"], "rc=%s row=%s err=%s" % (rc, hn, err))
    finally:
        stop(hidden["pid"])
        stop(plain["pid"])
        w.close()


def sc_ns_annot():
    other = spawn_owner("plain")
    w = World()
    try:
        comm = open("/proc/self/comm").read().strip()
        rc, out, err = cand_ns("-tp")
        rows = parse_netstat(out)
        me = os.getpid()
        mine = next((r for r in rows if r["local"] == w.ep(w.t4l) and r["state"] == "LISTEN"), None)
        L.check("netstat -p annotates the fixture-owned listener with pid and program", mine is not None and str(me) in mine["rest"] and comm in mine["rest"], str(mine))
        theirs = next((r for r in rows if r["local"].endswith(":%d" % other["port"])), None)
        L.check("netstat -p attributes the child's listener to the child", theirs is not None and str(other["pid"]) in theirs["rest"] and str(me) not in theirs["rest"], str(theirs))
        L.check("netstat -p annotates the established pair's ends", all(any(r["local"] == ep and str(me) in r["rest"] for r in rows) for ep in (w.ep(w.t4c), w.ep(w.t4a))), out)
        rc, out, err = cand_ns("-t")
        L.check("netstat without -p carries no annotation", all(not r["rest"] for r in parse_netstat(out)), out)
    finally:
        stop(other["pid"])
        w.close()


def sc_annot_vanish():
    churn_pid = os.fork()
    if churn_pid == 0:
        end = time.time() + 8
        while time.time() < end:
            fds = [socket.socket() for _ in range(40)]
            for s in fds:
                s.close()
        os._exit(0)
    w = World()
    try:
        bad = 0
        anomalies = []
        for i in range(25):
            rc, out, err = cand_ss("-tp")
            rows = parse_ss(out)
            mine = next((r for r in rows if r["local"] == w.ep(w.t4l) and r["state"] == "LISTEN"), None)
            if rc != 0 or mine is None or "pid=%d" % os.getpid() not in mine["rest"]:
                bad += 1
                anomalies.append((rc, err[:100], mine))
        L.check("ss -tp repeated 25 times while a neighbour opens and closes descriptors never fails and keeps the stable owner annotated", bad == 0, str(anomalies[:3]))
        rc, out, err = cand_ns("-tp")
        L.check("netstat -tp under the same churn exits 0", rc == 0, err)
    finally:
        try:
            os.kill(churn_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(churn_pid, 0)
        w.close()


# --------------------------------------------------------------------------- unix (netstat)
def sc_ns_unix():
    w = World()
    rc, out, err = cand_ns("-x")
    rows = parse_netstat(out)
    lst = [r for r in rows if r["local"] == w.xpath and r["state"] != "CONNECTED"]
    L.check("netstat -x lists the stream listener with type u_str, state LISTENING and its path", any(r["proto"] == "u_str" and r["state"] == "LISTENING" for r in lst), str(rows))
    conn = [r for r in rows if r["proto"] == "u_str" and r["state"] == "CONNECTED"]
    L.check("netstat -x shows the connected pair as two CONNECTED rows", len(conn) == 2, str(rows))
    dg = [r for r in rows if r["local"] == w.dgpath]
    L.check("netstat -x shows the bound datagram socket as u_dgr UNCONNECTED", len(dg) == 1 and dg[0]["proto"] == "u_dgr" and dg[0]["state"] == "UNCONNECTED", str(dg))
    labels = {r["state"] for r in rows}
    L.check("netstat -x state labels come from the SS_* vocabulary only", labels <= {"LISTENING", "CONNECTED", "UNCONNECTED"} and not (labels & {"LISTEN", "ESTAB", "UNCONN"}), "labels=%s" % sorted(labels))
    # queue fields: queue data on the connected pair and read back through the row
    w.xc.send(b"abcde")
    rc, out, err = cand_ns("-x")
    rows = parse_netstat(out)
    recv = [r for r in rows if r["proto"] == "u_str" and r["state"] in ("CONNECTED", "ESTAB") and r["rq"] == 5]
    L.check("netstat -x Recv-Q of the receiving end equals the 5 queued bytes", len(recv) == 1, str(rows))
    w.close()


# --------------------------------------------------------------------------- proc fallback (seccomp blocks sock_diag)
class Bpf(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


def block_sock_diag():
    """seccomp: socket(AF_NETLINK, *, NETLINK_SOCK_DIAG) fails with EPROTONOSUPPORT (x86_64 only)."""
    BPF_LD, BPF_W, BPF_ABS, BPF_JMP, BPF_JEQ, BPF_K, BPF_RET = 0x00, 0x00, 0x20, 0x05, 0x10, 0x00, 0x06
    prog = [
        Bpf(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),                    # nr
        Bpf(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 41),                  # socket?
        Bpf(BPF_LD | BPF_W | BPF_ABS, 0, 0, 16),                   # arg0
        Bpf(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 16),                  # AF_NETLINK?
        Bpf(BPF_LD | BPF_W | BPF_ABS, 0, 0, 32),                   # arg2
        Bpf(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 4),                   # NETLINK_SOCK_DIAG?
        Bpf(BPF_RET | BPF_K, 0, 0, 0x00050000 | 93),               # ERRNO(EPROTONOSUPPORT)
        Bpf(BPF_RET | BPF_K, 0, 0, 0x7fff0000),                    # ALLOW
    ]
    # the first jf above jumps to ALLOW: recompute explicit offsets
    prog[1].jf = 5   # to index 7
    prog[3].jf = 3   # to index 7
    prog[5].jf = 1   # to index 7
    arr = (Bpf * len(prog))(*prog)

    class Fprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    fp = Fprog(len(prog), ctypes.cast(arr, ctypes.c_void_p))

    def install():
        libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
        if libc.prctl(22, 2, ctypes.byref(fp)) != 0:  # PR_SET_SECCOMP, SECCOMP_MODE_FILTER
            os._exit(97)
    return install


def sc_fallback():
    w = World()
    inst = block_sock_diag()
    rc0, out0, err0 = cand_ss("-tuxa")
    rc, out, err = cand_ss("-tuxa", preexec=inst)
    L.check("fallback control: sock_diag path lists rows", rc0 == 0 and len(parse_ss(out0)) >= 11, "rc=%s" % rc0)
    L.check("fallback: filtered ss -tuxa exits 0", rc == 0, "rc=%s err=%s" % (rc, err))
    rows = parse_ss(out)
    rs = inet_set_ss(rows)
    want = w.ss_inet_rows()
    # /proc tables do not carry the listen backlog separately in sock_diag form; compare identity and state only
    idr = lambda s: {(r[0], r[1], r[4], r[5]) for r in s}
    L.check("fallback IPv4 TCP/UDP rows (identity+state) equal the fixture sockets", idr({r for r in rs if r[0] in ("tcp", "udp")}) == idr({r for r in want if r[0] in ("tcp", "udp")}),
            "got=%s want=%s" % (sorted(idr({r for r in rs if r[0] in ("tcp", "udp")})), sorted(idr({r for r in want if r[0] in ("tcp", "udp")}))))
    L.check("fallback IPv6 TCP/UDP rows are read from /proc/net/tcp6 and udp6", idr({r for r in rs if r[0] in ("tcp6", "udp6")}) == idr({r for r in want if r[0] in ("tcp6", "udp6")}),
            "got=%s want=%s" % (sorted(idr({r for r in rs if r[0] in ("tcp6", "udp6")})), sorted(idr({r for r in want if r[0] in ("tcp6", "udp6")}))))
    ux = unix_rows_ss(rows)
    L.check("fallback unix rows are read from /proc/net/unix (listener, pair, dgram)", len(ux) == 4 and any(r["local"] == w.xpath and r["state"] == "LISTEN" for r in ux), str(ux))
    L.check("fallback unix rows report 0 queues", all(r["rq"] == 0 and r["sq"] == 0 for r in ux), str(ux))
    rc, out, err = cand_ss("-tuxa", preexec=inst, tool="netstat")
    L.check("fallback netstat -tuxa exits 0 and lists the IPv6 listener", rc == 0 and any(r["proto"] == "tcp6" and r["state"] == "LISTEN" for r in parse_netstat(out)), "rc=%s err=%s" % (rc, err))
    w.close()


SCEN = {
    "ss-default": sc_ss_default, "ss-families": sc_ss_families, "ss-listen-all": sc_ss_listen_all, "ss-numeric": sc_ss_numeric, "ss-vs-iproute2": sc_ss_vs_iproute2,
    "ns-aliases": sc_ns_aliases, "ns-states": sc_ns_states, "ns-default": sc_ns_default_families, "ns-reset": sc_ns_option_reset,
    "ns-tcp": sc_ns_tcp_rows, "ns-tcp-labels": sc_ns_tcp_labels, "ns-udp": sc_ns_udp_rows, "ns-ipv6": sc_ns_ipv6, "ns-header": sc_ns_header,
    "annot-ss": sc_annot_ss, "annot-denied": sc_annot_denied, "annot-ns": sc_ns_annot, "annot-vanish": sc_annot_vanish,
    "ns-unix": sc_ns_unix, "fallback": sc_fallback,
}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
