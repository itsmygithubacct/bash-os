#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""fw named sets and persistence against real kernel sets (ipset and nftables).

Needs the extended guest image (ipset, nftables). Runs inside
`unshare --user --map-root-user --net --mount --uts`. The candidate's fw builtin is driven
with an explicit backend (-B iptables for ipset sets, -B nft for nftables sets); every
observation of the sets and rules is read back with the real ipset, nft, iptables and
iptables-save tools, never through the candidate. Round trips compare the state before
save with the state after the live ruleset and sets were destroyed and restored.
"""
import os
import re
import sys

import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

IPT = "/usr/sbin/iptables"
IPS = "/usr/sbin/ipset"
NFT = "/usr/sbin/nft"
SAVE = "/tmp/parity-case/fw.rules"
BEGIN = "# fw ipset-save begin\n"
END = "# fw ipset-save end\n"


def fw(backend, *args):
    return L.cand('fw "$@"', "-B", backend, *args)


def ipset(*args):
    return L.run([IPS] + list(args))


def ipset_names():
    rc, out, err = ipset("list", "-n")
    return sorted(out.split()) if rc == 0 else None


def ipset_dump():
    """{name: (header-tokens-without-random-parts, sorted members)} from the real `ipset save`."""
    rc, out, err = ipset("save")
    sets, members = {}, {}
    for ln in out.splitlines():
        t = ln.split()
        if not t:
            continue
        if t[0] == "create":
            sets[t[1]] = " ".join(t)
        elif t[0] == "add":
            members.setdefault(t[1], []).append(" ".join(t[2:]))
    return {n: (h, sorted(members.get(n, []))) for n, h in sets.items()}


def kv(header):
    t = header.split()
    d = {"type": t[2]}
    for i in range(3, len(t) - 1, 2):
        d[t[i]] = t[i + 1]
    return d


def strip_comments(text):
    return "".join(l + "\n" for l in text.splitlines() if not l.startswith("#"))


def chain(name):
    rc, out, err = L.run([IPT, "-S", name])
    return out if rc == 0 else "rc=%d %s" % (rc, err.strip())


def ipt_state():
    return strip_comments(L.run([IPT + "-save"])[1])


def nft_ruleset():
    rc, out, err = L.run([NFT, "list", "ruleset"])
    return out if rc == 0 else "rc=%d %s" % (rc, err.strip())


def ok(label, res):
    rc, out, err = res
    L.check(label + " exits 0", rc == 0, "rc=%s out=%r err=%r" % (rc, out, err))
    return rc == 0


def tool_check():
    for p in (IPS, NFT):
        L.check("extended image provides " + p, os.path.exists(p), p)


# --------------------------------------------------------------------------- ipset sets
def sc_ipset_sets():
    tool_check()
    f = lambda *a: fw("iptables", *a)
    ok("ipset: fw reset", f("reset"))
    ok("ipset: fw set create blk (hash:ip, inet)", f("set", "create", "blk", "-f", "inet", "-t", "hash:ip"))
    ok("ipset: fw set create nets (hash:net, inet)", f("set", "create", "nets", "-f", "inet", "-t", "hash:net"))
    ok("ipset: fw set create b6 (hash:ip, inet6)", f("set", "create", "b6", "-f", "inet6", "-t", "hash:ip"))
    for s, e in (("blk", "192.0.2.1"), ("blk", "192.0.2.2"), ("nets", "198.51.100.0/24"), ("b6", "2001:db8::5")):
        ok("ipset: fw set add %s %s" % (s, e), f("set", "add", s, e))
    d = ipset_dump()
    L.check("kernel holds exactly the three created sets", sorted(d) == ["b6", "blk", "nets"], str(d))
    if sorted(d) == ["b6", "blk", "nets"]:
        L.check("kernel set blk is hash:ip family inet holding 192.0.2.1 and 192.0.2.2",
                kv(d["blk"][0])["type"] == "hash:ip" and kv(d["blk"][0]).get("family") == "inet" and d["blk"][1] == ["192.0.2.1", "192.0.2.2"], str(d["blk"]))
        L.check("kernel set nets is hash:net family inet holding 198.51.100.0/24",
                kv(d["nets"][0])["type"] == "hash:net" and kv(d["nets"][0]).get("family") == "inet" and d["nets"][1] == ["198.51.100.0/24"], str(d["nets"]))
        L.check("kernel set b6 is hash:ip family inet6 holding 2001:db8::5",
                kv(d["b6"][0])["type"] == "hash:ip" and kv(d["b6"][0]).get("family") == "inet6" and d["b6"][1] == ["2001:db8::5"], str(d["b6"]))
    L.check("ipset test: 192.0.2.1 is in blk (rc 0)", ipset("test", "blk", "192.0.2.1")[0] == 0, "")
    L.check("ipset test: 192.0.2.3 is not in blk (rc 1)", ipset("test", "blk", "192.0.2.3")[0] == 1, "")
    L.check("ipset test: 198.51.100.77 is covered by the nets prefix", ipset("test", "nets", "198.51.100.77")[0] == 0, "")
    rc, out, err = f("set", "add", "blk", "192.0.2.1")
    L.check("re-adding an existing member succeeds and does not duplicate it (-exist)", rc == 0 and ipset_dump()["blk"][1] == ["192.0.2.1", "192.0.2.2"], "rc=%s err=%r %s" % (rc, err, ipset_dump().get("blk")))
    rc, out, err = f("set", "create", "blk", "-f", "inet", "-t", "hash:ip")
    L.check("re-creating an existing identical set succeeds and keeps its members (-exist)", rc == 0 and ipset_dump()["blk"][1] == ["192.0.2.1", "192.0.2.2"], "rc=%s err=%r" % (rc, err))
    rc, out, err = f("set", "list", "blk")
    rrc, rout, rerr = ipset("list", "blk")
    L.check("fw set list blk prints what ipset list blk prints for the kernel set", rc == 0 and out == rout and "192.0.2.2" in out, "cand=%r ref=%r err=%r" % (out, rout, err))
    rc, out, err = f("set", "list")
    rrc, rout, rerr = ipset("list")
    L.check("fw set list (all) prints what ipset list prints", rc == 0 and out == rout and "Name: nets" in out and "Name: b6" in out, "cand=%r ref=%r" % (out[:300], rout[:300]))
    ok("ipset: fw set del blk 192.0.2.2", f("set", "del", "blk", "192.0.2.2"))
    L.check("deleted member is gone from the kernel set", ipset("test", "blk", "192.0.2.2")[0] == 1 and ipset_dump()["blk"][1] == ["192.0.2.1"], str(ipset_dump().get("blk")))
    rc, out, err = f("set", "del", "blk", "192.0.2.9")
    L.check("deleting an absent member is tolerated (-exist)", rc == 0, "rc=%s err=%r" % (rc, err))
    # set-backed rule references the kernel set; destroy then needs the rule gone
    ok("ipset: fw deny -S blk", f("deny", "-S", "blk"))
    L.check("set-backed rule is installed in the kernel with -m set --match-set blk src",
            "-A BASHFW_IN -m set --match-set blk src -j DROP" in chain("BASHFW_IN"), chain("BASHFW_IN"))
    rc, out, err = f("set", "destroy", "blk")
    L.check("destroying a set still referenced by a rule fails with the kernel's diagnostic and keeps the set",
            rc != 0 and "blk" in (ipset_names() or []), "rc=%s err=%r names=%s" % (rc, err, ipset_names()))
    ok("ipset: fw destroy nets", f("set", "destroy", "nets"))
    L.check("destroyed set nets is gone, the others remain", ipset_names() == ["b6", "blk"], str(ipset_names()))
    rc, out, err = f("set", "destroy", "nosuch")
    L.check("destroying a nonexistent set fails with a diagnostic", rc != 0 and (err.strip() != "" or out.strip() != ""), "rc=%s out=%r err=%r" % (rc, out, err))
    ok("ipset: fw reset after sets exist", f("reset"))
    L.check("fw reset does not destroy the operator's kernel sets", ipset_names() == ["b6", "blk"], str(ipset_names()))


# --------------------------------------------------------------------------- nft sets
def nft_sets():
    import json
    rc, out, err = L.run([NFT, "-j", "list", "sets"])
    if rc != 0:
        return None
    sets = {}
    for item in json.loads(out).get("nftables", []):
        s = item.get("set")
        if s:
            sets[(s["family"], s["table"], s["name"])] = s
    return sets


def nft_elems(s):
    out = []
    for e in s.get("elem", []):
        if isinstance(e, dict) and "prefix" in e:
            out.append("%s/%s" % (e["prefix"]["addr"], e["prefix"]["len"]))
        else:
            out.append(str(e))
    return sorted(out)


def sc_nft_sets():
    tool_check()
    f = lambda *a: fw("nft", *a)
    ok("nft: fw reset", f("reset"))
    rc, out, err = L.run([NFT, "list", "tables"])
    L.check("fw reset created table inet fw in the kernel", "table inet fw" in out, "rc=%s out=%r err=%r" % (rc, out, err))
    ok("nft: fw set create blk (hash:ip, inet)", f("set", "create", "blk", "-f", "inet", "-t", "hash:ip"))
    ok("nft: fw set create nets (hash:net, inet)", f("set", "create", "nets", "-f", "inet", "-t", "hash:net"))
    ok("nft: fw set create b6 (hash:ip, inet6)", f("set", "create", "b6", "-f", "inet6", "-t", "hash:ip"))
    for s, e in (("blk", "192.0.2.1"), ("blk", "192.0.2.2"), ("nets", "198.51.100.0/24"), ("b6", "2001:db8::5")):
        ok("nft: fw set add %s %s" % (s, e), f("set", "add", s, e))
    sets = nft_sets()
    key = lambda n: ("inet", "fw", n)
    L.check("kernel table inet fw holds exactly the sets blk, nets and b6", sets is not None and sorted(k[2] for k in sets if k[:2] == ("inet", "fw")) == ["b6", "blk", "nets"], str(sets and sorted(sets)))
    if sets and key("blk") in sets and key("nets") in sets and key("b6") in sets:
        L.check("kernel set blk is ipv4_addr with 192.0.2.1 and 192.0.2.2", sets[key("blk")]["type"] == "ipv4_addr" and nft_elems(sets[key("blk")]) == ["192.0.2.1", "192.0.2.2"], str(sets[key("blk")]))
        L.check("kernel set nets is an ipv4_addr interval set holding 198.51.100.0/24",
                sets[key("nets")]["type"] == "ipv4_addr" and "interval" in sets[key("nets")].get("flags", []) and nft_elems(sets[key("nets")]) == ["198.51.100.0/24"], str(sets[key("nets")]))
        L.check("kernel set b6 is ipv6_addr holding 2001:db8::5", sets[key("b6")]["type"] == "ipv6_addr" and nft_elems(sets[key("b6")]) == ["2001:db8::5"], str(sets[key("b6")]))
    rc, out, err = f("set", "list", "blk")
    rrc, rout, rerr = L.run([NFT, "list", "set", "inet", "fw", "blk"])
    L.check("fw set list blk prints what nft list set inet fw blk prints", rc == 0 and out == rout and "192.0.2.2" in out, "cand=%r ref=%r err=%r" % (out, rout, err))
    rc, out, err = f("set", "list")
    rrc, rout, rerr = L.run([NFT, "list", "sets", "inet", "fw"])
    L.check("fw set list (all) prints what nft list sets inet fw prints", rc == 0 and out == rout and "blk" in out and "nets" in out, "cand=%r ref=%r err=%r" % (out, rout, err))
    ok("nft: fw set del blk 192.0.2.2", f("set", "del", "blk", "192.0.2.2"))
    s2 = nft_sets()
    L.check("deleted member is gone from the kernel set", s2 is not None and key("blk") in s2 and nft_elems(s2[key("blk")]) == ["192.0.2.1"], str(s2 and s2.get(key("blk"))))
    ok("nft: fw deny -S blk", f("deny", "-S", "blk"))
    L.check("set-backed rule is installed in the kernel as ip saddr @blk drop", "ip saddr @blk drop" in nft_ruleset(), nft_ruleset())
    ok("nft: fw set destroy nets", f("set", "destroy", "nets"))
    s3 = nft_sets()
    L.check("destroyed set nets is gone, blk and b6 remain", s3 is not None and sorted(k[2] for k in s3 if k[:2] == ("inet", "fw")) == ["b6", "blk"], str(s3 and sorted(s3)))
    rc, out, err = f("set", "destroy", "nosuch")
    L.check("destroying a nonexistent set fails with a diagnostic", rc != 0 and (err.strip() != "" or out.strip() != ""), "rc=%s out=%r err=%r" % (rc, out, err))


# --------------------------------------------------------------------------- ipset round trip
def snap_ipset():
    return {"rules": ipt_state(), "in": chain("BASHFW_IN"), "sets": ipset_dump()}


def diff_snap(a, b):
    out = []
    for k in a:
        if a[k] != b[k]:
            out.append("%s: before=%r after=%r" % (k, a[k], b[k]))
    return "; ".join(out)[:1500]


def wipe_ipset():
    L.run([IPT, "-F"])
    L.run([IPT, "-X"])
    L.run([IPS, "flush"])
    L.run([IPS, "destroy"])


def sc_ipset_roundtrip():
    tool_check()
    f = lambda *a: fw("iptables", *a)
    ok("roundtrip: fw reset", f("reset"))
    f("set", "create", "blk", "-f", "inet", "-t", "hash:ip")
    f("set", "create", "nets", "-f", "inet", "-t", "hash:net")
    f("set", "create", "b6", "-f", "inet6", "-t", "hash:ip")
    for s, e in (("blk", "192.0.2.1"), ("blk", "192.0.2.2"), ("blk", "192.0.2.3"), ("nets", "198.51.100.0/24"), ("nets", "203.0.113.0/25"), ("b6", "2001:db8::5")):
        f("set", "add", s, e)
    ok("roundtrip: fw deny 198.51.100.0/24", f("deny", "198.51.100.0/24"))
    ok("roundtrip: fw allow 192.0.2.10 -p tcp -d 22", f("allow", "192.0.2.10", "-p", "tcp", "-d", "22"))
    ok("roundtrip: fw deny -S blk (set-backed rule)", f("deny", "-S", "blk"))
    before = snap_ipset()
    L.check("fixture: three populated kernel sets and three BASHFW_IN rules exist before save",
            sorted(before["sets"]) == ["b6", "blk", "nets"] and before["in"].count("\n-A ") == 3, str(before))
    ok("roundtrip: fw save", f("save", SAVE))
    saved = open(SAVE).read() if os.path.exists(SAVE) else ""
    b, e = saved.find(BEGIN), saved.find(END)
    L.check("saved file has the ipset section after the rules", 0 < b < e, saved[:300])
    real_save = L.run([IPS, "save"])[1]
    L.check("ipset section equals the kernel's `ipset save` text (the kernel sets, byte for byte)", saved[b + len(BEGIN):e] == real_save, "file=%r real=%r" % (saved[b + len(BEGIN):e], real_save))
    L.check("rules section equals iptables-save of the live ruleset, comments aside", strip_comments(saved[:b]) == before["rules"], "file=%r live=%r" % (strip_comments(saved[:b]), before["rules"]))
    # round 1: destroy everything
    wipe_ipset()
    L.check("fixture: rules and sets are gone", ipset_names() == [] and chain("BASHFW_IN").startswith("rc="), "%s %s" % (ipset_names(), chain("BASHFW_IN")))
    rc, out, err = f("restore", SAVE)
    L.check("round 1 (wipe): fw restore exits 0", rc == 0, "rc=%s out=%r err=%r" % (rc, out, err))
    after = snap_ipset()
    L.check("round 1 (wipe): BASHFW_IN rules, the complete iptables-save text and every kernel set (type, family, parameters, members) equal the pre-save state",
            after == before, diff_snap(before, after))
    # round 2: sets destroyed and a member removed, rules kept
    f("deny", "198.51.100.77")      # rule added after the save: restore must drop it again
    L.run([IPT, "-F", "BASHFW_IN"])
    L.run([IPS, "flush"])
    L.run([IPS, "destroy"])
    rc, out, err = f("restore", SAVE)
    L.check("round 2 (sets destroyed, chain emptied): fw restore exits 0", rc == 0, "rc=%s out=%r err=%r" % (rc, out, err))
    after2 = snap_ipset()
    L.check("round 2: state equals the pre-save state again", after2 == before, diff_snap(before, after2))
    # round 3: reset keeps sets; restore onto surviving sets (ipset restore -exist)
    ok("round 3: fw reset", f("reset"))
    L.run([IPT, "-F", "BASHFW_IN"])
    L.run([IPT, "-F", "BASHFW_OUT"])
    L.run([IPS, "del", "blk", "192.0.2.3"])
    L.run([IPS, "add", "blk", "192.0.2.77"])
    rc, out, err = f("restore", SAVE)
    L.check("round 3 (reset, sets survive and drift): fw restore exits 0", rc == 0, "rc=%s out=%r err=%r" % (rc, out, err))
    after3 = snap_ipset()
    L.check("round 3: rules and saved members are back; the saved set membership is a subset of the restored sets",
            after3["rules"] == before["rules"] and after3["in"] == before["in"]
            and all(m in after3["sets"]["blk"][1] for m in before["sets"]["blk"][1]), diff_snap(before, after3))
    L.check("round 3: restore reproduces the exact saved membership (192.0.2.3 back, drifted 192.0.2.77 gone)", after3["sets"] == before["sets"], diff_snap(before, after3))
    # empty set section
    wipe_ipset()
    ok("empty: fw reset", f("reset"))
    f("deny", "192.0.2.200")
    before_e = snap_ipset()
    ok("empty: fw save with no sets", f("save", SAVE))
    saved = open(SAVE).read()
    L.check("empty: ipset section is present and empty", BEGIN + END in saved, saved[-200:])
    wipe_ipset()
    rc, out, err = f("restore", SAVE)
    L.check("empty: restoring a file with an empty ipset section exits 0 and reproduces the rules and no sets", rc == 0 and snap_ipset() == before_e, "rc=%s err=%r %s" % (rc, err, diff_snap(before_e, snap_ipset())))


# --------------------------------------------------------------------------- nft round trip
def sc_nft_roundtrip():
    tool_check()
    f = lambda *a: fw("nft", *a)
    ok("nft roundtrip: fw reset", f("reset"))
    f("set", "create", "blk", "-f", "inet", "-t", "hash:ip")
    f("set", "create", "nets", "-f", "inet", "-t", "hash:net")
    f("set", "create", "b6", "-f", "inet6", "-t", "hash:ip")
    for s, e in (("blk", "192.0.2.1"), ("blk", "192.0.2.2"), ("blk", "192.0.2.3"), ("nets", "198.51.100.0/24"), ("nets", "203.0.113.0/25"), ("b6", "2001:db8::5")):
        f("set", "add", s, e)
    ok("nft roundtrip: fw deny 198.51.100.0/24", f("deny", "198.51.100.0/24"))
    ok("nft roundtrip: fw allow 192.0.2.10 -p tcp -d 22", f("allow", "192.0.2.10", "-p", "tcp", "-d", "22"))
    ok("nft roundtrip: fw deny -S blk", f("deny", "-S", "blk"))
    before = nft_ruleset()
    L.check("fixture: ruleset holds the three sets and the three rules", all(x in before for x in ("set blk", "set nets", "set b6", "ip saddr @blk drop", "tcp dport 22 accept")), before)
    ok("nft roundtrip: fw save", f("save", SAVE))
    saved = open(SAVE).read() if os.path.exists(SAVE) else ""
    L.check("saved file equals nft list ruleset of the live kernel ruleset", saved == before, "file=%r live=%r" % (saved, before))
    L.run([NFT, "flush", "ruleset"])
    L.check("fixture: ruleset wiped", nft_ruleset().strip() == "", nft_ruleset())
    rc, out, err = f("restore", SAVE)
    L.check("round 1 (flush ruleset): fw restore exits 0", rc == 0, "rc=%s out=%r err=%r" % (rc, out, err))
    after = nft_ruleset()
    L.check("round 1: the kernel ruleset (tables, chains, rules, sets and elements) equals the pre-save ruleset", after == before, "before=%r after=%r" % (before, after))
    ok("round 2: fw reset", f("reset"))
    L.check("fixture: reset left an empty table (no sets)", "set blk" not in nft_ruleset(), nft_ruleset())
    rc, out, err = f("restore", SAVE)
    L.check("round 2 (reset): fw restore exits 0", rc == 0, "rc=%s out=%r err=%r" % (rc, out, err))
    after2 = nft_ruleset()
    L.check("round 2: ruleset equals the pre-save ruleset again", after2 == before, "before=%r after=%r" % (before, after2))
    sets = nft_sets()
    L.check("round 2: kernel set membership is back (blk has three members, nets two prefixes, b6 one address)",
            sets is not None and nft_elems(sets[("inet", "fw", "blk")]) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
            and nft_elems(sets[("inet", "fw", "nets")]) == ["198.51.100.0/24", "203.0.113.0/25"]
            and nft_elems(sets[("inet", "fw", "b6")]) == ["2001:db8::5"], str(sets))


SCEN = {"ipset-sets": sc_ipset_sets, "nft-sets": sc_nft_sets, "ipset-roundtrip": sc_ipset_roundtrip, "nft-roundtrip": sc_nft_roundtrip}

if __name__ == "__main__":
    try:
        SCEN[sys.argv[1]]()
    except Exception as exc:  # noqa: BLE001
        L.check("scenario ran without an exception", False, repr(exc))
    sys.exit(L.finish(sys.argv[1]))
