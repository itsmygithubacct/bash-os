#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""wg show on a device with a real handshake: two WireGuard interfaces in two network namespaces.

Needs the extended guest image (wireguard-tools). Runs inside
`unshare --user --map-root-user --net --mount --uts`: this process owns the first network
namespace (A); a forked child unshares a second one (C) and blocks on a pipe so the
namespace lives until the fixture ends. A veth pair joins them, wg0 in each namespace is
configured with the wg(8) tool, and ICMP echoes through the tunnel make the kernel complete a
real handshake and count transferred bytes. The expected text is built from the kernel's own
state as read by `wg show wg0 dump` (the independent wg(8) tool) using wg(8)'s documented
formatting rules; the real `wg show` output is a second oracle. The candidate is never used to
set anything up.
"""
import ctypes
import os
import re
import subprocess
import sys
import time

import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

WG = "/usr/bin/wg"
NSENTER = "/usr/bin/nsenter"
libc = ctypes.CDLL(None, use_errno=True)
CASE = "/tmp/parity-case"


class Pair:
    def __init__(self):
        libc.prctl(4, 1, 0, 0, 0)       # PR_SET_DUMPABLE=1 (userns left it non-dumpable; /proc/PID/ns needs it)
        r, w = os.pipe()                # child -> parent: ready
        r2, w2 = os.pipe()              # parent -> child: stay alive until EOF
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(r)
                os.close(w2)
                os.unshare(os.CLONE_NEWNET)
                os.write(w, b"R")
                os.read(r2, 1)          # blocks until the parent closes w2
            finally:
                os._exit(0)
        os.close(w)
        os.close(r2)
        self.hold = w2
        if os.read(r, 1) != b"R":
            raise RuntimeError("namespace child failed")
        os.close(r)
        self.nsarg = "--net=/proc/%d/ns/net" % self.pid

    def c(self, argv, env=None):
        return L.run([NSENTER, self.nsarg, "--"] + list(argv), env=env)

    def candc(self, script, *args):
        e = dict(L.ENV)
        return L.run([NSENTER, self.nsarg, "--", L.CAND, "--noprofile", "--norc", "-c", script, "cand"] + list(args), env=e)

    def close(self):
        os.close(self.hold)
        os.waitpid(self.pid, 0)


def must(label, res):
    rc, out, err = res
    if rc != 0:
        raise RuntimeError("%s failed rc=%s: %s %s" % (label, rc, out, err))
    return out


def setup(p):
    must("lo A", L.run(["/usr/sbin/ip", "link", "set", "lo", "up"]))
    must("lo C", p.c(["/usr/sbin/ip", "link", "set", "lo", "up"]))
    must("veth", L.run(["/usr/sbin/ip", "link", "add", "vA", "type", "veth", "peer", "name", "vC"]))
    must("move", L.run(["/usr/sbin/ip", "link", "set", "vC", "netns", str(p.pid)]))
    must("addr A", L.run(["/usr/sbin/ip", "addr", "add", "10.0.0.1/24", "dev", "vA"]))
    must("up A", L.run(["/usr/sbin/ip", "link", "set", "vA", "up"]))
    must("addr C", p.c(["/usr/sbin/ip", "addr", "add", "10.0.0.2/24", "dev", "vC"]))
    must("up C", p.c(["/usr/sbin/ip", "link", "set", "vC", "up"]))
    keys = {}
    for n in ("A", "C"):
        priv = must("genkey", L.run([WG, "genkey"])).strip()
        pub = must("pubkey", L.run([WG, "pubkey"], input=priv + "\n")).strip()
        path = "%s/key-%s" % (CASE, n)
        with open(path, "w") as f:
            f.write(priv + "\n")
        os.chmod(path, 0o600)
        keys[n] = (priv, pub, path)
    for ns, dev_run, me, peer, lport, pport, ip, pip in (
            ("A", L.run, "A", "C", 51820, 51821, "10.77.0.1/24", "10.77.0.2/32"),
            ("C", p.c, "C", "A", 51821, 51820, "10.77.0.2/24", "10.77.0.1/32")):
        runner = dev_run
        must("wg link " + ns, runner(["/usr/sbin/ip", "link", "add", "wg0", "type", "wireguard"]))
        endpoint = ["endpoint", "10.0.0.2:51821"] if ns == "A" else ["endpoint", "10.0.0.1:51820"]
        must("wg set " + ns, runner([WG, "set", "wg0", "private-key", keys[me][2], "listen-port", str(lport),
                                      "peer", keys[peer][1], "allowed-ips", pip] + endpoint))
        must("wg addr " + ns, runner(["/usr/sbin/ip", "addr", "add", ip, "dev", "wg0"]))
        must("wg up " + ns, runner(["/usr/sbin/ip", "link", "set", "wg0", "up"]))
    return keys


def dump(run):
    """`wg show wg0 dump` -> (interface fields, [peer fields]) from the independent wg(8) tool."""
    rc, out, err = run([WG, "show", "wg0", "dump"])
    lines = out.splitlines()
    if rc != 0 or not lines:
        return None
    return lines[0].split("\t"), [l.split("\t") for l in lines[1:]]


def human_bytes(n):
    if n < 1024:
        return "%d B" % n
    for unit, div in (("KiB", 1024.0), ("MiB", 1024.0 ** 2), ("GiB", 1024.0 ** 3), ("TiB", 1024.0 ** 4)):
        if n < div * 1024 or unit == "TiB":
            return "%.2f %s" % (n / div, unit)


def ago(left):
    """wg(8) 'time ago' rendering for a non-negative age in seconds."""
    if left == 0:
        return "Now"
    parts = []
    for name, size in (("year", 365 * 86400), ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        n, left = divmod(left, size)
        if n:
            parts.append("%d %s%s" % (n, name, "" if n == 1 else "s"))
    return ", ".join(parts) + " ago"


def expected_lines(keys, d, me, peer):
    iface, peers = d
    pk = peers[0]
    # dump: interface = private public listen-port fwmark; peer = public psk endpoint allowed-ips handshake rx tx keepalive
    exp = {
        "interface": "interface: wg0",
        "public key": "  public key: " + keys[me][1],
        "private key": "  private key: (hidden)",
        "listening port": "  listening port: " + iface[2],
        "peer": "peer: " + keys[peer][1],
        "endpoint": "  endpoint: " + pk[2],
        "allowed ips": "  allowed ips: " + pk[3],
    }
    if pk[7] != "off":
        exp["persistent keepalive"] = "  persistent keepalive: every %s second%s" % (pk[7], "" if pk[7] == "1" else "s")
    return exp, int(pk[4]), int(pk[5]), int(pk[6])


def ping_through():
    rc, out, err = L.run(["/usr/bin/ping", "-c", "3", "-i", "0.3", "-W", "3", "10.77.0.2"])
    return rc == 0, out + err


def sc_handshake():
    p = Pair()
    try:
        keys = setup(p)
        # ---- baseline: no traffic yet
        base_a = dump(L.run)
        L.check("fixture: kernel (wg dump) reports peer A->C with no handshake and zero counters before traffic",
                base_a is not None and base_a[1] and base_a[1][0][4] == "0" and base_a[1][0][5] == "0" and base_a[1][0][6] == "0", str(base_a))
        rc, out, err = L.cand('wg show wg0')
        lines = out.splitlines()
        L.check("zero state: candidate wg show exits 0 and prints neither 'latest handshake' nor 'transfer'",
                rc == 0 and out.strip() != "" and "latest handshake" not in out and "transfer:" not in out, "rc=%s out=%r err=%r" % (rc, out, err))
        # ---- real handshake and traffic
        must("keepalive", L.run([WG, "set", "wg0", "peer", keys["C"][1], "persistent-keepalive", "25"]))
        ok, pout = ping_through()
        L.check("fixture: ICMP echoes cross the tunnel (10.77.0.1 -> 10.77.0.2)", ok, pout)
        for name, run, candrun, me, peer in (("initiator A", L.run, lambda: L.cand('wg show wg0'), "A", "C"),
                                              ("responder C", p.c, lambda: p.candc('wg show wg0'), "C", "A")):
            d0 = dump(run)
            ok = d0 is not None and d0[1] and int(d0[1][0][4]) > 0 and int(d0[1][0][5]) > 0 and int(d0[1][0][6]) > 0
            L.check("fixture %s: kernel reports a nonzero handshake time and nonzero rx and tx counters" % name, ok, str(d0))
            if not ok:
                continue
            t0 = int(time.time())
            rc, out, err = candrun()
            t1 = int(time.time())
            d1 = dump(run)
            lines = out.splitlines()
            L.check("%s: candidate wg show exits 0 with output" % name, rc == 0 and out.strip() != "", "rc=%s out=%r err=%r" % (rc, out, err))
            exp, hs, rx, tx = expected_lines(keys, d0, me, peer)
            for k, want in exp.items():
                L.check("%s: line '%s' equals the wg(8) rendering %r" % (name, k, want), want in lines, "out=%r" % out)
            m = [l for l in lines if l.startswith("  latest handshake: ")]
            ages = {ago(a) for a in range(max(0, t0 - hs), t1 - hs + 1)}
            L.check("%s: 'latest handshake' line is rendered once, as wg(8) renders the elapsed time since the kernel's handshake (%s)" % (name, "|".join(sorted(ages))),
                    len(m) == 1 and m[0][len("  latest handshake: "):] in ages, "lines=%s ages=%s" % (m, sorted(ages)))
            counters_stable = d1 is not None and d1[1][0][5:7] == d0[1][0][5:7]
            m = [l for l in lines if l.startswith("  transfer: ")]
            want = "  transfer: %s received, %s sent" % (human_bytes(rx), human_bytes(tx))
            L.check("%s: 'transfer' line equals the wg(8) rendering of the kernel counters rx=%d tx=%d (counters unchanged during the read: %s)" % (name, rx, tx, counters_stable),
                    counters_stable and m == [want], "lines=%s want=%r" % (m, want))
            # order and completeness against the real wg show, ignoring the time-dependent handshake age
            rrc, rout, rerr = run([WG, "show", "wg0"])
            strip = lambda t: [re.sub(r"(latest handshake: ).*", r"\1<age>", l) for l in t.splitlines() if not l.startswith("  transfer:")]
            L.check("%s: candidate text equals real wg show line for line (handshake age and transfer lines compared separately)" % name,
                    counters_stable and strip(out) == strip(rout), "cand=%s\nwg=%s" % (strip(out), strip(rout)))
    finally:
        p.close()


def sc_handshake_counts():
    """Counters grow with traffic and the candidate follows them."""
    p = Pair()
    try:
        keys = setup(p)
        must("keepalive", L.run([WG, "set", "wg0", "peer", keys["C"][1], "persistent-keepalive", "25"]))
        ok, pout = ping_through()
        L.check("fixture: first ICMP burst crosses the tunnel", ok, pout)
        d0 = dump(L.run)
        rc, out, err = L.run(["/usr/bin/ping", "-c", "20", "-i", "0.05", "-s", "1200", "-W", "3", "10.77.0.2"])
        L.check("fixture: second burst of 20 large echoes crosses the tunnel", rc == 0, out + err)
        d1 = dump(L.run)
        rx0, tx0, rx1, tx1 = int(d0[1][0][5]), int(d0[1][0][6]), int(d1[1][0][5]), int(d1[1][0][6])
        L.check("fixture: kernel counters grew by more than 20 KiB each way (rx %d->%d, tx %d->%d)" % (rx0, rx1, tx0, tx1),
                rx1 - rx0 > 20000 and tx1 - tx0 > 20000, str((d0, d1)))
        rc, out, err = L.cand('wg show wg0')
        d2 = dump(L.run)
        want = "  transfer: %s received, %s sent" % (human_bytes(int(d2[1][0][5])), human_bytes(int(d2[1][0][6])))
        stable = d2[1][0][5:7] == d1[1][0][5:7]
        L.check("transfer line scales its units with the counters: wg(8) prints KiB/MiB with two decimals (expected %r, counters stable %s)" % (want, stable),
                stable and want in out.splitlines(), "rc=%s out=%r err=%r" % (rc, out, err))
        L.check("a repeated candidate read after more traffic still exits 0", rc == 0, "rc=%s err=%r" % (rc, err))
    finally:
        p.close()


SCEN = {"handshake": sc_handshake, "counters": sc_handshake_counts}

if __name__ == "__main__":
    try:
        SCEN[sys.argv[1]]()
    except Exception as exc:  # noqa: BLE001
        L.check("fixture setup/run completed without an exception", False, repr(exc))
    sys.exit(L.finish(sys.argv[1]))
