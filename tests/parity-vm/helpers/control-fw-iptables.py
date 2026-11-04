#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""w1 fw fixtures: the candidate fw builtin's iptables front-end against the guest kernel netfilter.

Run inside `unshare --user --map-root-user --net --mount --uts`. The guest image has
iptables (nf_tables backend) but no nft CLI and no ipset, so every live observation uses
the iptables backend (the nft text is only checked in dry-run). Expected ruleset text is
stated from iptables-save canonical form; the live ruleset is read back with
/usr/sbin/iptables and ip6tables, never through the candidate. The set/persistence cases
use a small stateful ipset stand-in placed first in PATH (the image has no ipset); it is
only the backend, the saved/restored rule state is read from the kernel.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time

import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

IPT = "/usr/sbin/iptables"
IPT6 = "/usr/sbin/ip6tables"
HOME = "/tmp/parity-home"


def fw(*args, env=None):
    return L.cand('fw "$@"', "-B", "iptables", *args, env=env)


def ipt(*args, tool=IPT):
    return L.run([tool] + list(args))


def chain_rules(chain, tool=IPT):
    rc, out, err = ipt("-S", chain, tool=tool)
    return out if rc == 0 else "rc=%d %s" % (rc, err.strip())


def expect_eq(name, got, want):
    L.check(name, got == want, "got=%r want=%r" % (got, want))


def reset_ok(label):
    rc, out, err = fw("reset")
    L.check(label + " fw reset rc0", rc == 0, "rc=%s err=%s" % (rc, err))


# ----------------------------------------------------------------------------- ruleset
def sc_allow_deny():
    reset_ok("allow-deny")
    r1 = fw("allow", "192.0.2.10", "-p", "tcp", "-d", "22")
    r2 = fw("deny", "198.51.100.0/24")
    r3 = fw("deny", "203.0.113.7", "-p", "udp", "-d", "53")
    L.check("allow-deny add rc0", r1[0] == 0 and r2[0] == 0 and r3[0] == 0, "rcs=%s errs=%s" % ((r1[0], r2[0], r3[0]), (r1[2], r2[2], r3[2])))
    expect_eq("allow-deny kernel BASHFW_IN ruleset", chain_rules("BASHFW_IN"),
              "-N BASHFW_IN\n"
              "-A BASHFW_IN -s 192.0.2.10/32 -p tcp -m tcp --dport 22 -j ACCEPT\n"
              "-A BASHFW_IN -s 198.51.100.0/24 -j DROP\n"
              "-A BASHFW_IN -s 203.0.113.7/32 -p udp -m udp --dport 53 -j DROP\n")
    expect_eq("allow-deny BASHFW_OUT untouched", chain_rules("BASHFW_OUT"), "-N BASHFW_OUT\n")


def sc_deny_v6():
    reset_ok("deny-v6")
    rc, out, err = fw("deny", "2001:db8::/32")
    L.check("deny-v6 fw deny rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("deny-v6 kernel ip6tables BASHFW_IN", chain_rules("BASHFW_IN", IPT6), "-N BASHFW_IN\n-A BASHFW_IN -s 2001:db8::/32 -j DROP\n")


def sc_list():
    reset_ok("list")
    fw("allow", "192.0.2.10", "-p", "tcp", "-d", "22")
    fw("deny", "198.51.100.0/24")
    rc, out, err = fw("list")
    want = ipt("-L", "BASHFW_IN", "-n", "-v")[1]
    L.check("list rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("list equals iptables -L BASHFW_IN -n -v", out, want)
    rows = [l.split() for l in out.splitlines()[2:]]
    L.check("list reports the allow rule", any(len(r) >= 9 and r[2] == "ACCEPT" and r[7] == "192.0.2.10" for r in rows), out)
    L.check("list reports the deny rule", any(len(r) >= 9 and r[2] == "DROP" and r[7] == "198.51.100.0/24" for r in rows), out)
    rc, out, err = fw("list", "-l")
    expect_eq("list -l equals --line-numbers form", out, ipt("-L", "BASHFW_IN", "-n", "-v", "--line-numbers")[1])
    L.check("list -l numbers the rules 1 and 2", re.search(r"^1\s", out, re.M) is not None and re.search(r"^2\s", out, re.M) is not None, out)
    rc, out, err = fw("list", "BASHFW_OUT")
    expect_eq("list BASHFW_OUT equals iptables", out, ipt("-L", "BASHFW_OUT", "-n", "-v")[1])


def sc_unban():
    reset_ok("unban")
    fw("deny", "192.0.2.50")
    fw("deny", "192.0.2.51")
    fw("deny", "192.0.2.50", "-p", "tcp", "-d", "22")
    rc, out, err = fw("unban", "192.0.2.50")
    L.check("unban rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("unban removed only the matching rule", chain_rules("BASHFW_IN"),
              "-N BASHFW_IN\n-A BASHFW_IN -s 192.0.2.51/32 -j DROP\n-A BASHFW_IN -s 192.0.2.50/32 -p tcp -m tcp --dport 22 -j DROP\n")
    rc, out, err = fw("unban", "192.0.2.50", "-p", "tcp", "-d", "22")
    L.check("unban with proto/port rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("unban proto/port removed only the tcp rule", chain_rules("BASHFW_IN"), "-N BASHFW_IN\n-A BASHFW_IN -s 192.0.2.51/32 -j DROP\n")
    rc, out, err = fw("unban", "192.0.2.99")
    L.check("unban of absent rule fails", rc != 0, "rc=%s err=%s" % (rc, err))
    expect_eq("unban of absent rule leaves the chain", chain_rules("BASHFW_IN"), "-N BASHFW_IN\n-A BASHFW_IN -s 192.0.2.51/32 -j DROP\n")


def sc_flush():
    reset_ok("flush")
    fw("allow", "192.0.2.10")
    fw("deny", "198.51.100.0/24")
    ipt("-A", "BASHFW_OUT", "-d", "192.0.2.77", "-j", "DROP")
    ipt("-N", "OTHER")
    ipt("-A", "OTHER", "-s", "192.0.2.88", "-j", "DROP")
    rc, out, err = fw("flush")
    L.check("flush rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("flush empties the default chain BASHFW_IN", chain_rules("BASHFW_IN"), "-N BASHFW_IN\n")
    expect_eq("flush leaves BASHFW_OUT", chain_rules("BASHFW_OUT"), "-N BASHFW_OUT\n-A BASHFW_OUT -d 192.0.2.77/32 -j DROP\n")
    expect_eq("flush leaves unrelated chain", chain_rules("OTHER"), "-N OTHER\n-A OTHER -s 192.0.2.88/32 -j DROP\n")
    rc, out, err = fw("flush", "BASHFW_OUT")
    L.check("flush BASHFW_OUT rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("flush BASHFW_OUT empties the selected chain", chain_rules("BASHFW_OUT"), "-N BASHFW_OUT\n")
    expect_eq("selected flush leaves unrelated chain", chain_rules("OTHER"), "-N OTHER\n-A OTHER -s 192.0.2.88/32 -j DROP\n")


def sc_reset():
    rc, out, err = ipt("-S")
    L.check("reset precondition: no fw chains", "BASHFW" not in out, out)
    reset_ok("reset-fresh")
    expect_eq("reset creates empty BASHFW_IN", chain_rules("BASHFW_IN"), "-N BASHFW_IN\n")
    expect_eq("reset creates empty BASHFW_OUT", chain_rules("BASHFW_OUT"), "-N BASHFW_OUT\n")
    fw("allow", "192.0.2.10")
    fw("deny", "198.51.100.0/24")
    ipt("-A", "BASHFW_OUT", "-d", "192.0.2.77", "-j", "DROP")
    reset_ok("reset-populated")
    expect_eq("reset returns BASHFW_IN to empty", chain_rules("BASHFW_IN"), "-N BASHFW_IN\n")
    expect_eq("reset returns BASHFW_OUT to empty", chain_rules("BASHFW_OUT"), "-N BASHFW_OUT\n")


# ----------------------------------------------------------------------------- dry-run text
def sc_dryrun_text():
    want = [
        (["-B", "iptables", "-n", "allow", "192.0.2.1"], "iptables -A BASHFW_IN -s 192.0.2.1 -j ACCEPT\n"),
        (["-B", "iptables", "-n", "deny", "192.0.2.1", "-p", "tcp", "-d", "22"], "iptables -A BASHFW_IN -s 192.0.2.1 -p tcp --dport 22 -j DROP\n"),
        (["-B", "iptables", "-n", "unban", "192.0.2.1"], "iptables -D BASHFW_IN -s 192.0.2.1 -j DROP\n"),
        (["-B", "iptables", "-n", "list"], "iptables -L BASHFW_IN -n -v\n"),
        (["-B", "iptables", "-n", "list", "-l"], "iptables -L BASHFW_IN -n -v --line-numbers\n"),
        (["-B", "iptables", "-n", "flush"], "iptables -F BASHFW_IN\n"),
        (["-B", "iptables", "-n", "reset"], "iptables -N BASHFW_IN\niptables -N BASHFW_OUT\n"),
        (["-B", "nft", "-n", "allow", "192.0.2.1"], "nft add rule inet fw input ip saddr 192.0.2.1 accept\n"),
        (["-B", "nft", "-n", "deny", "192.0.2.1", "-p", "tcp", "-d", "22"], "nft add rule inet fw input ip saddr 192.0.2.1 tcp dport 22 drop\n"),
        (["-B", "nft", "-n", "list"], "nft list ruleset\n"),
        (["-B", "nft", "-n", "list", "output"], "nft list chain inet fw output\n"),
        (["-B", "nft", "-n", "flush"], "nft flush chain inet fw input\n"),
        (["-B", "nft", "-n", "reset"],
         "nft delete table inet fw\nnft add table inet fw\n"
         "nft add chain inet fw input { type filter hook input priority 0 ; policy accept ; }\n"
         "nft add chain inet fw output { type filter hook output priority 0 ; policy accept ; }\n"
         "nft add chain inet fw prerouting { type nat hook prerouting priority -100 ; policy accept ; }\n"
         "nft add chain inet fw postrouting { type nat hook postrouting priority 100 ; policy accept ; }\n"),
    ]
    for args, text in want:
        rc, out, err = fw(*args)
        L.check("dryrun fw " + " ".join(args), rc == 0 and out == text, "rc=%s out=%r want=%r err=%r" % (rc, out, text, err))


# ----------------------------------------------------------------------------- packets
class PeerNS:
    """A child process in its own network namespace, driven over a pipe."""

    def __init__(self):
        a_r, a_w = os.pipe()   # parent -> child
        b_r, b_w = os.pipe()   # child -> parent
        self.pid = os.fork()
        if self.pid == 0:
            os.close(a_w)
            os.close(b_r)
            os.unshare(os.CLONE_NEWNET)
            os.write(b_w, b"ready\n")
            cmdf = os.fdopen(a_r, "r")
            out = os.fdopen(b_w, "w")
            for line in cmdf:
                cmd = json.loads(line)
                if cmd[0] == "quit":
                    break
                if cmd[0] == "run":
                    rc, so, se = L.run(cmd[1])
                    res = [rc, so[-300:], se[-300:]]
                elif cmd[0] == "connect":
                    res = self.connect(cmd[1], cmd[2], cmd[3])
                out.write(json.dumps(res) + "\n")
                out.flush()
            os._exit(0)
        os.close(a_r)
        os.close(b_w)
        self.w = os.fdopen(a_w, "w")
        self.r = os.fdopen(b_r, "r")
        assert self.r.readline().strip() == "ready"

    @staticmethod
    def connect(host, port, tmo):
        s = socket.socket()
        s.settimeout(tmo)
        try:
            s.connect((host, port))
            return ["connected"]
        except socket.timeout:
            return ["timeout"]
        except OSError as exc:
            return ["error", exc.errno]
        finally:
            s.close()

    def call(self, *cmd):
        self.w.write(json.dumps(list(cmd)) + "\n")
        self.w.flush()
        return json.loads(self.r.readline())

    def close(self):
        try:
            self.w.write(json.dumps(["quit"]) + "\n")
            self.w.flush()
        except OSError:
            pass
        os.waitpid(self.pid, 0)


def packet_setup():
    peer = PeerNS()
    L.seed([["link", "add", "v0", "type", "veth", "peer", "name", "v1"], ["link", "set", "v1", "netns", str(peer.pid)],
            ["addr", "add", "10.77.0.1/24", "dev", "v0"], ["link", "set", "v0", "up"], ["link", "set", "lo", "up"]])
    rc = peer.call("run", ["/usr/bin/ip", "addr", "add", "10.77.0.2/24", "dev", "v1"])
    rc2 = peer.call("run", ["/usr/bin/ip", "link", "set", "v1", "up"])
    L.check("packet setup peer configured", rc[0] == 0 and rc2[0] == 0, "%s %s" % (rc, rc2))
    srv = socket.socket()
    srv.bind(("10.77.0.1", 5000))
    srv.listen(8)
    time.sleep(0.3)
    return peer, srv


def sc_packet(hooked):
    peer, srv = packet_setup()
    try:
        reset_ok("packet")
        if hooked:
            rc, out, err = ipt("-I", "INPUT", "-j", "BASHFW_IN")
            L.check("packet fixture hook INPUT -> BASHFW_IN rc0", rc == 0, err)
        L.check("packet baseline connect succeeds", peer.call("connect", "10.77.0.1", 5000, 2.0) == ["connected"], "")
        rc, out, err = fw("deny", "10.77.0.2")
        L.check("packet fw deny rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        res = peer.call("connect", "10.77.0.1", 5000, 1.5)
        L.check("packet deny blocks the peer's connection", res == ["timeout"], "connect result=%s" % res)
        rc, out, err = fw("unban", "10.77.0.2")
        L.check("packet fw unban rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        res = peer.call("connect", "10.77.0.1", 5000, 2.0)
        L.check("packet unban restores the connection", res == ["connected"], "connect result=%s" % res)
        if hooked:
            fw("deny", "10.77.0.2")
            fw("flush")
            L.check("packet flush restores the connection", peer.call("connect", "10.77.0.1", 5000, 2.0) == ["connected"], "")
    finally:
        srv.close()
        peer.close()


# ----------------------------------------------------------------------------- sets & persistence
IPSET_MOCK = r'''#!/usr/bin/python3
import json, os, sys
st_path = os.path.join(os.environ.get("HOME", "/tmp"), "ipset-state.json")
try:
    st = json.load(open(st_path))
except OSError:
    st = {}
args = [a for a in sys.argv[1:] if a != "-exist"]
cmd = args[0] if args else ""
def save():
    json.dump(st, open(st_path, "w"))
def fmt(name):
    s = st[name]
    return "create %s %s family %s hashsize 1024 maxelem 65536" % (name, s["type"], s["family"])
if cmd == "create":
    st[args[1]] = {"type": args[2], "family": args[args.index("family") + 1], "members": st.get(args[1], {}).get("members", [])}
elif cmd == "add":
    if args[2] not in st[args[1]]["members"]:
        st[args[1]]["members"].append(args[2])
elif cmd == "del":
    st[args[1]]["members"].remove(args[2])
elif cmd == "destroy":
    del st[args[1]]
elif cmd == "list":
    for n in ([args[1]] if len(args) > 1 else sorted(st)):
        s = st[n]
        print("Name: %s\nType: %s\nRevision: 6\nHeader: family %s hashsize 1024 maxelem 65536\nSize in memory: 200\nReferences: 0\nNumber of entries: %d\nMembers:" % (n, s["type"], s["family"], len(s["members"])))
        for m in s["members"]:
            print(m)
elif cmd == "save":
    for n in sorted(st):
        print(fmt(n))
        for m in st[n]["members"]:
            print("add %s %s" % (n, m))
elif cmd == "restore":
    for line in sys.stdin:
        w = line.split()
        if not w:
            continue
        if w[0] == "create":
            st[w[1]] = {"type": w[2], "family": w[w.index("family") + 1], "members": st.get(w[1], {}).get("members", [])}
        elif w[0] == "add" and w[2] not in st[w[1]]["members"]:
            st[w[1]]["members"].append(w[2])
elif cmd == "flush":
    for n in st:
        st[n]["members"] = []
else:
    sys.exit(2)
save()
'''


def install_ipset_mock():
    d = os.path.join(HOME, "mockbin")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "ipset")
    with open(p, "w") as f:
        f.write(IPSET_MOCK)
    os.chmod(p, 0o755)
    return d


def ipset_state():
    try:
        return json.load(open(os.path.join(HOME, "ipset-state.json")))
    except OSError:
        return {}


def sc_sets_dryrun():
    cases = [
        (["-B", "iptables", "-n", "set", "create", "blk", "-f", "inet", "-t", "hash:ip"], "ipset create blk hash:ip family inet"),
        (["-B", "iptables", "-n", "set", "create", "nets6", "-f", "inet6", "-t", "hash:net"], "ipset create nets6 hash:net family inet6"),
        (["-B", "iptables", "-n", "set", "add", "blk", "192.0.2.1"], "ipset add blk 192.0.2.1"),
        (["-B", "iptables", "-n", "set", "del", "blk", "192.0.2.1"], "ipset del blk 192.0.2.1"),
        (["-B", "iptables", "-n", "set", "list", "blk"], "ipset list blk"),
        (["-B", "iptables", "-n", "set", "list"], "ipset list"),
        (["-B", "iptables", "-n", "set", "destroy", "blk"], "ipset destroy blk"),
        (["-B", "nft", "-n", "set", "create", "blk", "-f", "inet", "-t", "hash:ip"], "nft add set inet fw blk { type ipv4_addr; }"),
        (["-B", "nft", "-n", "set", "create", "nets6", "-f", "inet6", "-t", "hash:net"], "nft add set inet fw nets6 { type ipv6_addr; flags interval; }"),
        (["-B", "nft", "-n", "set", "add", "blk", "192.0.2.1"], "nft add element inet fw blk { 192.0.2.1 }"),
        (["-B", "nft", "-n", "set", "del", "blk", "192.0.2.1"], "nft delete element inet fw blk { 192.0.2.1 }"),
        (["-B", "nft", "-n", "set", "list", "blk"], "nft list set inet fw blk"),
        (["-B", "nft", "-n", "set", "list"], "nft list sets inet fw"),
        (["-B", "nft", "-n", "set", "destroy", "blk"], "nft delete set inet fw blk"),
    ]
    for args, core in cases:
        rc, out, err = fw(*args)
        words = out.split()
        cw = core.split()
        # ipset accepts the optional -exist flag after the core words; nothing else may differ.
        ok = rc == 0 and out.endswith("\n") and words[:len(cw)] == cw and set(words[len(cw):]) <= {"-exist"}
        L.check("sets dryrun fw " + " ".join(args[2:]) + " [" + args[1] + "]", ok, "rc=%s out=%r want core=%r err=%r" % (rc, out, core, err))


def sc_sets_live():
    d = install_ipset_mock()
    env = {"PATH": d + ":/usr/sbin:/usr/bin:/sbin:/bin"}
    f = lambda *a: fw(*a, env=env)
    reset_ok("sets-live")
    for args in (["set", "create", "blk", "-f", "inet", "-t", "hash:ip"], ["set", "add", "blk", "192.0.2.1"], ["set", "add", "blk", "192.0.2.2"],
                 ["set", "create", "nets", "-f", "inet", "-t", "hash:net"], ["set", "add", "nets", "198.51.100.0/24"]):
        rc, out, err = f(*args)
        L.check("sets-live fw " + " ".join(args) + " rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    st = ipset_state()
    L.check("sets-live blk exists with both members", st.get("blk", {}).get("members") == ["192.0.2.1", "192.0.2.2"] and st["blk"]["type"] == "hash:ip", str(st))
    L.check("sets-live nets exists with its prefix", st.get("nets", {}).get("members") == ["198.51.100.0/24"] and st["nets"]["type"] == "hash:net", str(st))
    rc, out, err = f("set", "list", "blk")
    L.check("sets-live fw set list shows members", rc == 0 and "Name: blk" in out and "192.0.2.1\n" in out and "192.0.2.2\n" in out, out)
    f("set", "del", "blk", "192.0.2.2")
    L.check("sets-live del removed one member", ipset_state()["blk"]["members"] == ["192.0.2.1"], str(ipset_state()))
    f("set", "destroy", "nets")
    L.check("sets-live destroy removed the set", "nets" not in ipset_state() and "blk" in ipset_state(), str(ipset_state()))


def strip_comments(text):
    return "".join(l + "\n" for l in text.splitlines() if not l.startswith("#"))


def sc_save():
    out_file = "/tmp/parity-case/saved.rules"
    reset_ok("save")
    fw("deny", "198.51.100.0/24")
    fw("allow", "192.0.2.10", "-p", "tcp", "-d", "22")
    rc, out, err = fw("save", out_file)
    L.check("save (no ipset) rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    saved = open(out_file).read()
    want = L.run(["/usr/sbin/iptables-save"])[1]
    expect_eq("save (no ipset) file equals iptables-save, comments aside", strip_comments(saved), strip_comments(want))
    L.check("save (no ipset) has no ipset marker", "# fw ipset-save begin" not in saved, saved)
    L.check("save contains the deny and allow rules", "-A BASHFW_IN -s 198.51.100.0/24 -j DROP" in saved and "-A BASHFW_IN -s 192.0.2.10/32 -p tcp -m tcp --dport 22 -j ACCEPT" in saved, saved)
    d = install_ipset_mock()
    env = {"PATH": d + ":/usr/sbin:/usr/bin:/sbin:/bin"}
    fw("set", "create", "blk", "-f", "inet", "-t", "hash:ip", env=env)
    fw("set", "add", "blk", "192.0.2.1", env=env)
    fw("set", "add", "blk", "192.0.2.2", env=env)
    rc, out, err = fw("save", out_file, env=env)
    L.check("save (ipset present) rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    saved = open(out_file).read()
    begin = saved.find("# fw ipset-save begin\n")
    end = saved.find("# fw ipset-save end\n")
    L.check("save has begin then end marker", 0 < begin < end, saved)
    L.check("save ipset section holds the set and members",
            saved[begin:end + len("# fw ipset-save end\n")] == "# fw ipset-save begin\ncreate blk hash:ip family inet hashsize 1024 maxelem 65536\nadd blk 192.0.2.1\nadd blk 192.0.2.2\n# fw ipset-save end\n", saved[begin:])
    L.check("save keeps the rules before the ipset section", strip_comments(saved[:begin]) == strip_comments(want), saved[:begin])


def sc_restore():
    out_file = "/tmp/parity-case/saved.rules"
    d = install_ipset_mock()
    env = {"PATH": d + ":/usr/sbin:/usr/bin:/sbin:/bin"}
    reset_ok("restore")
    fw("deny", "198.51.100.0/24")
    fw("allow", "192.0.2.10", "-p", "tcp", "-d", "22")
    fw("set", "create", "blk", "-f", "inet", "-t", "hash:ip", env=env)
    fw("set", "add", "blk", "192.0.2.1", env=env)
    fw("set", "add", "blk", "192.0.2.2", env=env)
    before_in = chain_rules("BASHFW_IN")
    before_all = strip_comments(L.run(["/usr/sbin/iptables-save"])[1])
    before_sets = json.dumps(ipset_state(), sort_keys=True)
    rc, out, err = fw("save", out_file, env=env)
    L.check("restore fixture: save rc0", rc == 0, err)
    # destroy the live state: wipe rules and the set backend
    ipt("-F")
    ipt("-X")
    os.unlink(os.path.join(HOME, "ipset-state.json"))
    L.check("restore fixture: state wiped", chain_rules("BASHFW_IN").startswith("rc=") and ipset_state() == {}, chain_rules("BASHFW_IN"))
    rc, out, err = fw("restore", out_file, env=env)
    L.check("restore rc0", rc == 0, "rc=%s out=%s err=%s" % (rc, out, err))
    expect_eq("restore reproduces BASHFW_IN rules", chain_rules("BASHFW_IN"), before_in)
    expect_eq("restore reproduces the complete saved ruleset", strip_comments(L.run(["/usr/sbin/iptables-save"])[1]), before_all)
    expect_eq("restore reproduces set membership in the set backend", json.dumps(ipset_state(), sort_keys=True), before_sets)
    # second round: reset then restore (sets survive reset by design)
    reset_ok("restore-after-reset")
    ipt("-F", "BASHFW_IN")
    ipt("-F", "BASHFW_OUT")
    expect_eq("recreated chain is empty before the second restore", chain_rules("BASHFW_IN"), "-N BASHFW_IN\n")
    rc, out, err = fw("restore", out_file, env=env)
    L.check("second restore rc0", rc == 0, "rc=%s err=%s" % (rc, err))
    expect_eq("restore after reset reproduces the rules", chain_rules("BASHFW_IN"), before_in)
    expect_eq("restore after reset keeps identical set membership", json.dumps(ipset_state(), sort_keys=True), before_sets)


SCEN = {
    "allow-deny": sc_allow_deny, "deny-v6": sc_deny_v6, "list": sc_list, "unban": sc_unban, "flush": sc_flush, "reset": sc_reset,
    "dryrun-text": sc_dryrun_text, "packet-unhooked": lambda: sc_packet(False), "packet-hooked": lambda: sc_packet(True),
    "sets-dryrun": sc_sets_dryrun, "sets-live": sc_sets_live, "save": sc_save, "restore": sc_restore,
}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
