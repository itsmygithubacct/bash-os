#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""w1 ip fixtures: candidate `ip` builtin versus iproute2 in private network namespaces.

Usage: mig-w1-ip.py SCENARIO  (run inside `unshare --user --map-root-user --net --mount --uts`)

Mutation scenarios run the same operation list twice, each time in a fresh network
namespace: once through the candidate builtin and once through /usr/bin/ip
(iproute2), then compare rc class and the complete kernel state read back with
`ip -j` after every step. Literal expectations derived from iproute2 semantics
are asserted on the candidate state so an identical-but-empty result cannot pass.
Query scenarios seed one namespace with iproute2 and compare the facts parsed
from the candidate output with iproute2's own JSON readback.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

SCOPES = {"global": 0, "site": 200, "link": 253, "host": 254, "nowhere": 255}


def setup_ns():
    for p in ("default", "all"):
        try:
            with open("/proc/sys/net/ipv6/conf/%s/accept_dad" % p, "w") as f:
                f.write("0")
        except OSError:
            pass


def dump(v6routes=False, rules=True):
    st = {}
    st["link"] = L.jq(["link", "show"])
    st["addr"] = L.jq(["addr", "show"])
    st["route4"] = L.jq(["-4", "route", "show", "table", "all"])
    if v6routes:
        st["route6"] = L.jq(["-6", "route", "show", "table", "all"])
    if rules:
        st["rule4"] = L.jq(["-4", "rule", "show"])
    st["neigh4"] = L.jq(["-4", "neigh", "show", "nud", "all"])
    return st


def normalize(st, rand):
    """Mask kernel-assigned random MACs (and the link-local addresses derived from them); sort lists."""
    out = json.loads(json.dumps(st))
    for l in out["link"]:
        if l["ifname"] in rand:
            l["address"] = "<random>"
    for a in out["addr"]:
        if a["ifname"] in rand:
            a["address"] = "<random>"
            a["addr_info"] = [x for x in a.get("addr_info", []) if not x.get("local", "").startswith("fe80")]
    for key in ("route4", "route6"):
        if key in out:
            out[key] = [r for r in out[key] if not (r.get("dev") in rand and "fe80" in json.dumps(r))]
    for key, val in out.items():
        out[key] = sorted(val, key=lambda x: json.dumps(x, sort_keys=True))
    return out


def run_ops(who, ops):
    rcs, errs = [], []
    for op in ops:
        if isinstance(op, dict):
            body = op["batch"]
            path = "/tmp/parity-case/batch.txt"
            args = ["-batch", "-" if op.get("stdin") else path]
            if op.get("force"):
                args = ["-force"] + args
            if not op.get("stdin"):
                with open(path, "w") as f:
                    f.write(body)
            stdin = body if op.get("stdin") else None
        else:
            args, stdin = op, None
        fn = L.cand_ip if who == "cand" else L.ref_ip
        rc, out, err = fn(args, input=stdin)
        rcs.append(rc)
        errs.append(err.strip()[:300])
    return rcs, errs


def twin(who, seedcmds, steps, **dopts):
    def body():
        setup_ns()
        L.seed(seedcmds)
        res = []
        for step in steps:
            rcs, errs = run_ops(who, step["ops"])
            res.append({"rcs": rcs, "errs": errs, "state": dump(**dopts)})
        return res
    return L.in_netns(body)


def ips(st):
    out = set()
    for a in st["addr"]:
        for x in a.get("addr_info", []):
            out.add((a["ifname"], x["family"], "%s/%s" % (x["local"], x["prefixlen"]), x["scope"]))
    return out


def lk(st):
    return {l["ifname"]: l for l in st["link"]}


def routes(st, key="route4"):
    return {(r.get("dst"), r.get("gateway"), r.get("dev"), r.get("metric"), r.get("table", "main"), r.get("type", "unicast")) for r in st[key]}


def rules_of(st):
    return {(r.get("priority"), r.get("src"), r.get("srclen"), r.get("dst"), r.get("dstlen"), r.get("fwmark"), r.get("table"), r.get("uid_start"), r.get("ipproto")) for r in st["rule4"]}


def neighs(st):
    return {(n.get("dst"), n.get("dev"), n.get("lladdr"), tuple(n.get("state", []))) for n in st["neigh4"]}


def scenario_mutation(name, seedcmds, steps, rand=(), **dopts):
    c = twin("cand", seedcmds, steps, **dopts)
    r = twin("ref", seedcmds, steps, **dopts)
    if "__error__" in c or "__error__" in r:
        L.check(name + " harness", False, "candidate=%s reference=%s" % (c.get("__error__") if isinstance(c, dict) else "", r.get("__error__") if isinstance(r, dict) else ""))
        return
    for i, step in enumerate(steps):
        lab = "%s step%d" % (name, i + 1)
        cs, rs = c[i], r[i]
        L.check(lab + " rc-class", [bool(x) for x in cs["rcs"]] == [bool(x) for x in rs["rcs"]],
                "candidate rcs=%s errs=%s iproute2 rcs=%s errs=%s" % (cs["rcs"], cs["errs"], rs["rcs"], rs["errs"]))
        ns_c, ns_r = normalize(cs["state"], rand), normalize(rs["state"], rand)
        L.check(lab + " state-equals-iproute2", ns_c == ns_r, L.json_diff(ns_c, ns_r))
        for desc, fn in step.get("expect", []):
            try:
                ok_ref = bool(fn(rs["state"]))
            except Exception as exc:  # noqa: BLE001
                ok_ref = False
                desc += " (oracle error %r)" % (exc,)
            try:
                ok = bool(fn(cs["state"]))
            except Exception as exc:  # noqa: BLE001
                ok = False
            L.check(lab + " expect " + desc, ok and ok_ref, "candidate=%s iproute2-oracle=%s" % (ok, ok_ref))


D0 = [["link", "add", "d0", "type", "dummy"], ["link", "set", "d0", "address", "02:00:00:00:00:01", "up"]]
D0A = D0 + [["addr", "add", "192.0.2.1/24", "dev", "d0"]]


def has_addr(st, ifn, cidr):
    return any(a[0] == ifn and a[2] == cidr for a in ips(st))


def sc_addr_add_del():
    scenario_mutation("addr-add-del", D0, [
        {"ops": [["addr", "add", "192.0.2.1/24", "dev", "d0"], ["addr", "add", "198.51.100.7/32", "dev", "d0"],
                 ["addr", "add", "fd00::1/64", "dev", "d0"]],
         "expect": [("v4 /24 present", lambda s: has_addr(s, "d0", "192.0.2.1/24")),
                    ("v4 /32 present", lambda s: has_addr(s, "d0", "198.51.100.7/32")),
                    ("v6 present", lambda s: has_addr(s, "d0", "fd00::1/64")),
                    ("connected route created", lambda s: ("192.0.2.0/24", None, "d0", None, "main", "unicast") in routes(s))]},
        {"ops": [["addr", "del", "198.51.100.7/32", "dev", "d0"], ["addr", "del", "fd00::1/64", "dev", "d0"]],
         "expect": [("deleted v4 absent", lambda s: not has_addr(s, "d0", "198.51.100.7/32")),
                    ("deleted v6 absent", lambda s: not has_addr(s, "d0", "fd00::1/64")),
                    ("other v4 kept", lambda s: has_addr(s, "d0", "192.0.2.1/24"))]},
        {"ops": [["addr", "del", "198.51.100.7/32", "dev", "d0"], ["addr", "add", "192.0.2.1/24", "dev", "d0"]],
         "expect": [("deleting absent and re-adding present leave state unchanged", lambda s: has_addr(s, "d0", "192.0.2.1/24") and not has_addr(s, "d0", "198.51.100.7/32"))]},
    ], v6routes=True)


def sc_addr_change_replace():
    scenario_mutation("addr-change-replace", D0A, [
        {"ops": [["addr", "replace", "192.0.2.5/24", "dev", "d0"], ["addr", "replace", "fd00::5/64", "dev", "d0"]],
         "expect": [("replace creates absent v4", lambda s: has_addr(s, "d0", "192.0.2.5/24")),
                    ("replace creates absent v6", lambda s: has_addr(s, "d0", "fd00::5/64"))]},
        {"ops": [["addr", "replace", "192.0.2.5/24", "dev", "d0"], ["addr", "change", "192.0.2.1/24", "dev", "d0"]],
         "expect": [("replace of existing keeps one copy", lambda s: sum(1 for a in ips(s) if a[2] == "192.0.2.5/24") == 1),
                    ("change of existing keeps address", lambda s: has_addr(s, "d0", "192.0.2.1/24"))]},
        {"ops": [["addr", "change", "192.0.2.77/24", "dev", "d0"], ["addr", "replace", "10.0.0.1/8", "dev", "nosuchdev"]],
         "expect": [("replace on missing device leaves state", lambda s: not any(a[0] == "nosuchdev" for a in ips(s)))]},
    ], v6routes=True)


FLUSH_SEED = D0 + [["addr", "add", "192.0.2.1/24", "dev", "d0"], ["addr", "add", "192.0.2.2/24", "dev", "d0"],
                   ["addr", "add", "198.51.100.1/24", "dev", "d0"], ["addr", "add", "10.99.0.1/32", "scope", "host", "dev", "d0"],
                   ["addr", "add", "fd00::1/64", "dev", "d0"],
                   ["link", "add", "d1", "type", "dummy"], ["link", "set", "d1", "up"], ["addr", "add", "203.0.113.9/24", "dev", "d1"]]


def sc_addr_flush_to():
    scenario_mutation("addr-flush-to", FLUSH_SEED, [
        {"ops": [["addr", "flush", "dev", "d0", "to", "192.0.2.0/24"]],
         "expect": [("both 192.0.2.x removed", lambda s: not any(a[2].startswith("192.0.2.") for a in ips(s))),
                    ("others on d0 kept", lambda s: has_addr(s, "d0", "198.51.100.1/24") and has_addr(s, "d0", "10.99.0.1/32") and has_addr(s, "d0", "fd00::1/64")),
                    ("d1 untouched", lambda s: has_addr(s, "d1", "203.0.113.9/24"))]},
    ], v6routes=True, rand=("d1",))


def sc_addr_flush_scope():
    scenario_mutation("addr-flush-scope", FLUSH_SEED, [
        {"ops": [["addr", "flush", "dev", "d0", "scope", "host"]],
         "expect": [("host scope address removed", lambda s: not has_addr(s, "d0", "10.99.0.1/32")),
                    ("global addresses kept", lambda s: has_addr(s, "d0", "192.0.2.1/24") and has_addr(s, "d0", "198.51.100.1/24") and has_addr(s, "d0", "fd00::1/64")),
                    ("d1 untouched", lambda s: has_addr(s, "d1", "203.0.113.9/24"))]},
    ], v6routes=True, rand=("d1",))


def sc_addr_flush_dev():
    scenario_mutation("addr-flush-dev", FLUSH_SEED, [
        {"ops": [["addr", "flush", "dev", "d0"]],
         "expect": [("d0 has no addresses", lambda s: not any(a[0] == "d0" for a in ips(s))),
                    ("d1 untouched", lambda s: has_addr(s, "d1", "203.0.113.9/24"))]},
    ], v6routes=True, rand=("d1",))


SHOW_SEED = [["link", "add", "d0", "type", "dummy"], ["link", "set", "d0", "address", "02:00:00:00:00:01", "mtu", "1400", "up"],
             ["link", "add", "d1", "type", "dummy"], ["link", "set", "d1", "address", "02:00:00:00:00:02", "up"],
             ["link", "add", "d2", "type", "dummy"], ["link", "set", "d2", "address", "02:00:00:00:00:03"],
             ["link", "add", "v0", "address", "02:00:00:00:01:00", "type", "veth", "peer", "name", "v1", "address", "02:00:00:00:01:01"],
             ["addr", "add", "192.0.2.1/24", "dev", "d0"], ["addr", "add", "198.51.100.7/32", "dev", "d0"],
             ["addr", "add", "10.99.0.1/32", "scope", "host", "dev", "d0"], ["addr", "add", "fd00::1/64", "dev", "d0"],
             ["addr", "add", "203.0.113.9/24", "dev", "d1"], ["addr", "add", "fd01::1/64", "dev", "d1"],
             ["route", "add", "203.0.113.0/25", "via", "192.0.2.254", "dev", "d0", "metric", "50"],
             ["route", "add", "default", "via", "192.0.2.254", "dev", "d0", "metric", "100"],
             ["route", "add", "198.18.0.0/15", "dev", "d1"],
             ["route", "add", "10.20.0.0/16", "dev", "d0", "table", "100"],
             ["route", "add", "2001:db8:1::/64", "via", "fd00::2", "dev", "d0"],
             ["rule", "add", "from", "10.9.0.0/16", "table", "100", "priority", "500"],
             ["rule", "add", "to", "192.0.2.0/24", "fwmark", "0x10", "table", "100", "priority", "600"],
             ["neigh", "add", "192.0.2.99", "lladdr", "02:00:00:00:00:99", "dev", "d0", "nud", "permanent"],
             ["neigh", "add", "203.0.113.50", "lladdr", "02:00:00:00:00:50", "dev", "d1", "nud", "permanent"]]


def with_seed(fn):
    def body():
        setup_ns()
        L.seed(SHOW_SEED)
        fn()
        return {}
    L.in_netns(body)


def refjson(args):
    return L.jq(args)


def addr_facts_ref(args, scope_names=False):
    out = set()
    for a in refjson(args):
        for x in a.get("addr_info", []):
            out.add((a["ifname"], x["family"], "%s/%s" % (x["local"], x["prefixlen"]), x["scope"] if scope_names else SCOPES[x["scope"]]))
    return out


def addr_facts_text(text):
    out = set()
    for ln in text.splitlines():
        m = re.match(r"^\d+: (\S+)\s+(inet6?) (\S+) scope (\S+)", ln)
        if m:
            out.add((m.group(1), m.group(2), m.group(3), int(m.group(4)) if m.group(4).isdigit() else m.group(4)))
    return out


def addr_facts_json(text):
    out = set()
    for a in json.loads(text):
        for x in a.get("addr_info", []):
            out.add((a["ifname"], x["family"], "%s/%s" % (x["local"], x["prefixlen"]), x["scope"]))
    return out


def cmp_sets(name, cand_set, ref_set, expect_nonempty=None):
    L.check(name + " candidate-rows-equal-iproute2", cand_set == ref_set,
            "only-candidate=%s only-iproute2=%s" % (sorted(map(str, cand_set - ref_set)), sorted(map(str, ref_set - cand_set))))
    if expect_nonempty is not None:
        L.check(name + " expected rows present", expect_nonempty <= cand_set,
                "missing=%s" % sorted(map(str, expect_nonempty - cand_set)))


def sc_show_addr(name, flags, selector, expected_literal):
    def body():
        args = list(flags) + ["addr", "show"] + list(selector)
        rc, out, err = L.cand_ip(args)
        L.check(name + " text rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        cmp_sets(name + " text", addr_facts_text(out), addr_facts_ref(["addr", "show"] if False else [x for x in flags if x in ("-4", "-6")] + ["addr", "show"] + selector), expected_literal)
        rc, out, err = L.cand_ip(["-j"] + args)
        try:
            cj = addr_facts_json(out)
        except Exception as exc:  # noqa: BLE001
            L.check(name + " json parse", False, "%r out=%r err=%r" % (exc, out[:300], err))
            return
        cmp_sets(name + " json", cj, addr_facts_ref([x for x in flags if x in ("-4", "-6")] + ["addr", "show"] + selector, True))
    with_seed(body)


SHOW_ADDR = {
    "show-addr-dev": (["dev", "d0"] if False else ["d0"], ["d0"]),
}


def sc_show_addr_dev():
    exp_text = {("d0", "inet", "192.0.2.1/24", 0), ("d0", "inet", "198.51.100.7/32", 0), ("d0", "inet", "10.99.0.1/32", 254), ("d0", "inet6", "fd00::1/64", 0)}
    sc_show_addr("addr-show-dev", [], ["d0"], exp_text)


def sc_show_addr_to():
    sc_show_addr("addr-show-to", [], ["to", "192.0.2.0/24"], {("d0", "inet", "192.0.2.1/24", 0)})


def sc_show_addr_scope():
    sc_show_addr("addr-show-scope-host", [], ["scope", "host"], {("d0", "inet", "10.99.0.1/32", 254)})


def sc_show_addr_v4():
    sc_show_addr("addr-show-4", ["-4"], [], {("d0", "inet", "192.0.2.1/24", 0), ("d1", "inet", "203.0.113.9/24", 0)})


def sc_show_addr_v6():
    sc_show_addr("addr-show-6", ["-6"], [], {("d0", "inet6", "fd00::1/64", 0), ("d1", "inet6", "fd01::1/64", 0)})


# ---------------------------------------------------------------- link queries
def link_ref():
    return {l["ifname"]: l for l in refjson(["link", "show"])}


def parse_link_text(text, oneline=False):
    rows = {}
    cur = None
    for ln in text.splitlines():
        if oneline:
            m = re.match(r"^(\d+): (\S+): <([^>]*)> mtu (\d+) state (\S+) \\\s+link/(\S+)(?: (\S+))?", ln)
            if m:
                rows[m.group(2).split("@")[0]] = {"ifindex": int(m.group(1)), "flags": set(filter(None, m.group(3).split(","))),
                                                  "mtu": int(m.group(4)), "state": m.group(5), "mac": m.group(7)}
            continue
        m = re.match(r"^(\d+): (\S+): <([^>]*)> mtu (\d+) state (\S+)", ln)
        if m:
            cur = {"ifindex": int(m.group(1)), "flags": set(filter(None, m.group(3).split(","))), "mtu": int(m.group(4)), "state": m.group(5), "mac": None}
            rows[m.group(2).split("@")[0]] = cur
            continue
        m = re.match(r"^\s+link/(\S+)(?: (\S+))?", ln)
        if m and cur is not None:
            cur["mac"] = m.group(2)
    return rows


def parse_link_brief(text):
    rows = {}
    for ln in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+(?:(\S+)\s+)?<([^>]*)>", ln)
        if m:
            mac = m.group(3)
            rows[m.group(1).split("@")[0]] = {"state": m.group(2), "mac": mac, "flags": set(filter(None, m.group(4).split(",")))}
    return rows


def ref_facts(ref):
    out = {}
    for n, l in ref.items():
        out[n] = {"ifindex": l["ifindex"], "flags": set(l["flags"]) - {"M-DOWN"}, "mtu": l["mtu"], "state": l["operstate"], "mac": l.get("address")}
    return out


def cmp_link_fields(name, got, ref, fields):
    L.check(name + " link-names", set(got) == set(ref), "candidate=%s iproute2=%s" % (sorted(got), sorted(ref)))
    for f in fields:
        bad = {n: (got[n].get(f), ref[n].get(f)) for n in ref if n in got and got[n].get(f) != ref[n].get(f)}
        L.check(name + " field " + f, not bad, "differences(candidate,iproute2)=%s" % bad)


def sc_show_link(mode):
    def body():
        ref = ref_facts(link_ref())
        L.check("link-show-%s seed sane" % mode, {"lo", "d0", "d1", "d2", "v0", "v1"} <= set(ref) and ref["d0"]["mtu"] == 1400 and ref["d0"]["mac"] == "02:00:00:00:00:01", str(ref.get("d0")))
        if mode == "default":
            rc, out, err = L.cand_ip(["link", "show"])
            got = parse_link_text(out)
            fields = ["ifindex", "mtu", "state", "mac", "flags"]
        elif mode == "oneline":
            rc, out, err = L.cand_ip(["-o", "link", "show"])
            got = parse_link_text(out, True)
            fields = ["ifindex", "mtu", "state", "mac", "flags"]
        elif mode == "brief":
            rc, out, err = L.cand_ip(["-br", "link", "show"])
            got = parse_link_brief(out)
            fields = ["state", "mac", "flags"]
        L.check("link-show-%s rc0" % mode, rc == 0, "rc=%s err=%s" % (rc, err))
        if mode == "oneline":
            L.check("link-show-oneline one-line-per-link", len(out.strip().splitlines()) == len(ref), out)
        cmp_link_fields("link-show-" + mode, got, ref, fields)
    with_seed(body)


def sc_show_link_json():
    def body():
        ref = {l["ifname"]: l for l in refjson(["link", "show"])}
        rc, out, err = L.cand_ip(["-j", "link", "show"])
        L.check("link-show-json rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        try:
            got = {l["ifname"]: l for l in json.loads(out)}
        except Exception as exc:  # noqa: BLE001
            L.check("link-show-json parse", False, "%r %r" % (exc, out[:300]))
            return
        L.check("link-show-json link-names", set(got) == set(ref), "candidate=%s iproute2=%s" % (sorted(got), sorted(ref)))
        for f in ("ifindex", "mtu", "operstate", "link_type", "address", "broadcast", "flags"):
            fix = (lambda v: [x for x in v if x != "M-DOWN"]) if f == "flags" else (lambda v: v)
            bad = {n: (got[n].get(f), ref[n].get(f)) for n in ref if n in got and fix(got[n].get(f)) != fix(ref[n].get(f))}
            L.check("link-show-json field " + f, not bad, "differences(candidate,iproute2)=%s" % bad)
    with_seed(body)


def sc_show_link_json_schema():
    """Strict: the JSON object keys for each link equal iproute2's."""
    def body():
        ref = {l["ifname"]: l for l in refjson(["link", "show"])}
        rc, out, err = L.cand_ip(["-j", "link", "show"])
        got = {l["ifname"]: l for l in json.loads(out)}
        for n in sorted(ref):
            L.check("link-json-keys %s" % n, n in got and set(got[n]) == set(ref[n]),
                    "only-candidate=%s only-iproute2=%s" % (sorted(set(got.get(n, {})) - set(ref[n])), sorted(set(ref[n]) - set(got.get(n, {})))))
    with_seed(body)


# ---------------------------------------------------------------- route / rule / neigh queries
def norm_dst(d):
    if d is None:
        return None
    return re.sub(r"/(32|128)$", "", d)


def parse_route_text(text):
    out = set()
    for ln in text.splitlines():
        t = ln.split()
        if not t:
            continue
        d = {"dst": norm_dst(t[0]), "via": None, "dev": None, "metric": None, "src": None}
        i = 1
        while i < len(t) - 1:
            if t[i] in ("via", "dev", "metric", "src"):
                d[t[i]] = int(t[i + 1]) if t[i] == "metric" else t[i + 1]
                i += 2
            else:
                i += 1
        out.add((d["dst"], d["via"], d["dev"], d["metric"], d["src"]))
    return out


def ref_routes(args, fixdev=None):
    out = set()
    for r in refjson(args):
        out.add((norm_dst(r.get("dst")), r.get("gateway"), r.get("dev", fixdev), r.get("metric"), r.get("prefsrc")))
    return out


def sc_show_route(name, selector, flag=None):
    def body():
        rc, out, err = L.cand_ip(["route", "show"] + selector)
        L.check(name + " rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        fixdev = selector[selector.index("dev") + 1] if "dev" in selector else None
        refset = ref_routes((["-4"] if "all" not in selector else []) + ["route", "show"] + selector, fixdev)
        cmp_sets(name + " text", parse_route_text(out), refset)
    with_seed(body)


def sc_show_route_default():
    def body():
        rc, out, err = L.cand_ip(["route", "show"])
        got = parse_route_text(out)
        cmp_sets("route-show-default-selector plain", got, ref_routes(["-4", "route", "show"]),
                 {("203.0.113.0/25", "192.0.2.254", "d0", 50, None), ("default", "192.0.2.254", "d0", 100, None), ("198.18.0.0/15", None, "d1", None, None)})
        rc, out, err = L.cand_ip(["route", "show", "default"])
        L.check("route-show-default-selector rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        cmp_sets("route-show-default-selector default", parse_route_text(out), ref_routes(["-4", "route", "show", "default"]),
                 {("default", "192.0.2.254", "d0", 100, None)})
    with_seed(body)


def sc_show_route_all():
    def body():
        rc, out, err = L.cand_ip(["-j", "route", "show", "table", "all"])
        try:
            got = {(norm_dst(r.get("dst")), r.get("gateway"), r.get("dev"), r.get("metric"), r.get("table", "main")) for r in json.loads(out)}
        except Exception as exc:  # noqa: BLE001
            L.check("route-show-table-all json parse", False, "%r %r" % (exc, out[:300]))
            return
        ref = {(norm_dst(r.get("dst")), r.get("gateway"), r.get("dev"), r.get("metric"), r.get("table", "main")) for r in refjson(["route", "show", "table", "all"])}
        cmp_sets("route-show-table-all json", got, ref, {("10.20.0.0/16", None, "d0", None, "100"), ("203.0.113.0/25", "192.0.2.254", "d0", 50, "main")})
        rc, out, err = L.cand_ip(["route", "show", "table", "100"])
        cmp_sets("route-show-table-100 text", parse_route_text(out), ref_routes(["-4", "route", "show", "table", "100"]),
                 {("10.20.0.0/16", None, "d0", None, None)})
    with_seed(body)


def rule_norm_text(text):
    return {re.sub(r"\s+", " ", ln.strip()) for ln in text.splitlines() if ln.strip()}


def sc_show_rule_text():
    def body():
        rc, out, err = L.cand_ip(["rule", "show"])
        L.check("rule-show rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        rc2, ref, _ = L.ref_ip(["-4", "rule", "show"])
        got, exp = rule_norm_text(out), rule_norm_text(ref)
        cmp_sets("rule-show text", got, exp, {"500: from 10.9.0.0/16 lookup 100"})
        L.check("rule-show fwmark rule listed", any("fwmark 0x10" in x and "to 192.0.2.0/24" in x and "lookup 100" in x for x in got), sorted(got))
    with_seed(body)


def rule_facts_ref(args):
    out = set()
    for r in refjson(args):
        fw = r.get("fwmark")
        out.add((r.get("priority"), r.get("src"), r.get("srclen"), r.get("dst"), r.get("dstlen"), int(fw, 16) if isinstance(fw, str) else fw, r.get("table")))
    return out


def sc_show_rule_json():
    def body():
        rc, out, err = L.cand_ip(["-j", "rule", "show"])
        try:
            data = json.loads(out)
        except Exception as exc:  # noqa: BLE001
            L.check("rule-show-json parse", False, "%r %r" % (exc, out[:300]))
            return
        got = set()
        for r in data:
            src = r.get("from", r.get("src"))
            slen = r.get("from_prefix", r.get("srclen"))
            dst = r.get("to", r.get("dst"))
            dlen = r.get("to_prefix", r.get("dstlen"))
            got.add((r.get("priority"), src, slen, dst, dlen, r.get("fwmark"), r.get("table")))
        cmp_sets("rule-show-json facts", got, rule_facts_ref(["-4", "rule", "show"]),
                 {(500, "10.9.0.0", 16, None, None, None, "100"), (600, "all", None, "192.0.2.0", 24, 16, "100")})
    with_seed(body)


def sc_show_rule_json_schema():
    def body():
        rc, out, err = L.cand_ip(["-j", "rule", "show"])
        data = json.loads(out)
        ref = refjson(["-4", "rule", "show"])
        L.check("rule-show-json schema rows-equal-iproute2", data == ref, L.json_diff(data, ref))
    with_seed(body)


def neigh_facts_ref(args, fixdev=None, only=None):
    out = set()
    for n in refjson(args):
        st = tuple(n.get("state", []))
        if only and st != (only,):
            continue
        out.add((n["dst"], n.get("dev", fixdev), n.get("lladdr"), st))
    return out


def neigh_facts_text(text, only=None):
    out = set()
    for ln in text.splitlines():
        m = re.match(r"^(\S+) dev (\S+) lladdr (\S+) (\S+)", ln)
        if m:
            st = (m.group(4),)
            if only and st != (only,):
                continue
            out.add((m.group(1), m.group(2), m.group(3), st))
    return out


def sc_show_neigh(name, selector, perm_only):
    def body():
        rc, out, err = L.cand_ip(["neigh", "show"] + selector)
        L.check(name + " rc0", rc == 0, "rc=%s err=%s" % (rc, err))
        fixdev = selector[1] if selector else None
        only = "PERMANENT" if perm_only else None
        exp_lit = {("192.0.2.99", "d0", "02:00:00:00:00:99", ("PERMANENT",))}
        if not selector:
            exp_lit.add(("203.0.113.50", "d1", "02:00:00:00:00:50", ("PERMANENT",)))
        cmp_sets(name + " text", neigh_facts_text(out, only), neigh_facts_ref(["neigh", "show"] + selector, fixdev, only), exp_lit if perm_only else None)
        rc, out, err = L.cand_ip(["-j", "neigh", "show"] + selector)
        try:
            data = json.loads(out)
        except Exception as exc:  # noqa: BLE001
            L.check(name + " json parse", False, "%r %r" % (exc, out[:300]))
            return
        gj = set()
        for n in data:
            st = tuple(n.get("state", []))
            if only and st != (only,):
                continue
            gj.add((n["dst"], n.get("dev", fixdev), n.get("lladdr"), st))
        cmp_sets(name + " json", gj, neigh_facts_ref(["neigh", "show"] + selector, fixdev, only))
    with_seed(body)


# ---------------------------------------------------------------- mutation scenarios: link/route/rule/neigh/batch
def has_link(st, n):
    return n in lk(st)


def flags(st, n):
    return set(lk(st)[n]["flags"])


def sc_link_updown():
    scenario_mutation("link-updown", [["link", "add", "d0", "type", "dummy"]], [
        {"ops": [["link", "set", "d0", "up"]], "expect": [("d0 administratively up", lambda s: "UP" in flags(s, "d0") and lk(s)["d0"]["operstate"] == "UNKNOWN")]},
        {"ops": [["link", "set", "d0", "down"]], "expect": [("d0 administratively down", lambda s: "UP" not in flags(s, "d0") and lk(s)["d0"]["operstate"] == "DOWN")]},
        {"ops": [["link", "set", "nosuch0", "up"], ["link", "set", "d0", "up"]], "expect": [("unknown link rejected, d0 up again", lambda s: "UP" in flags(s, "d0"))]},
    ], rand=("d0",))


def sc_link_mtu_addr():
    scenario_mutation("link-mtu-address", [["link", "add", "d0", "type", "dummy"]], [
        {"ops": [["link", "set", "d0", "mtu", "1400"]], "expect": [("mtu 1400", lambda s: lk(s)["d0"]["mtu"] == 1400)]},
        {"ops": [["link", "set", "d0", "address", "02:11:22:33:44:55"]], "expect": [("mac set", lambda s: lk(s)["d0"]["address"] == "02:11:22:33:44:55")]},
        {"ops": [["link", "set", "d0", "mtu", "576", "address", "02:aa:bb:cc:dd:ee"]], "expect": [("mtu and mac together", lambda s: lk(s)["d0"]["mtu"] == 576 and lk(s)["d0"]["address"] == "02:aa:bb:cc:dd:ee")]},
        {"ops": [["link", "set", "d0", "mtu", "abc"], ["link", "set", "d0", "address", "zz:zz"]], "expect": [("invalid values leave link unchanged", lambda s: lk(s)["d0"]["mtu"] == 576 and lk(s)["d0"]["address"] == "02:aa:bb:cc:dd:ee")]},
    ], rand=("d0",))


def info_kind(st, n):
    return lk(st)[n].get("linkinfo", {}).get("info_kind")


def sc_link_add_dummy():
    scenario_mutation("link-add-dummy", [], [
        {"ops": [["link", "add", "d0", "type", "dummy"]],
         "expect": [("d0 exists", lambda s: has_link(s, "d0")), ("d0 is ether", lambda s: lk(s)["d0"]["link_type"] == "ether"), ("d0 down by default", lambda s: "UP" not in flags(s, "d0"))]},
        {"ops": [["link", "add", "d0", "type", "dummy"], ["link", "add", "d1", "type", "dummy"]],
         "expect": [("duplicate rejected and second added", lambda s: has_link(s, "d1") and [l["ifname"] for l in s["link"]].count("d0") == 1)]},
    ], rand=("d0", "d1"))


def sc_link_add_veth():
    scenario_mutation("link-add-veth", [], [
        {"ops": [["link", "add", "v0", "type", "veth", "peer", "v1"]],
         "expect": [("both ends exist", lambda s: has_link(s, "v0") and has_link(s, "v1")),
                    ("ends are peers", lambda s: lk(s)["v0"].get("link") == "v1" and lk(s)["v1"].get("link") == "v0")]},
        {"ops": [["link", "add", "v2", "type", "veth", "peer", "v3"], ["link", "set", "v2", "up"], ["link", "set", "v3", "up"]],
         "expect": [("second pair created", lambda s: has_link(s, "v2") and has_link(s, "v3")),
                    ("pair carrier up", lambda s: lk(s)["v2"]["operstate"] == "UP" and lk(s)["v3"]["operstate"] == "UP")]},
    ], rand=("v0", "v1", "v2", "v3"))


def sc_link_del():
    scenario_mutation("link-del", [["link", "add", "d0", "type", "dummy"], ["link", "add", "v0", "type", "veth", "peer", "name", "v1"]], [
        {"ops": [["link", "del", "d0"]], "expect": [("d0 removed", lambda s: not has_link(s, "d0")), ("veth untouched", lambda s: has_link(s, "v0") and has_link(s, "v1"))]},
        {"ops": [["link", "del", "v0"]], "expect": [("v0 removed", lambda s: not has_link(s, "v0")), ("peer v1 removed with it", lambda s: not has_link(s, "v1"))]},
        {"ops": [["link", "del", "nosuch0"]], "expect": [("deleting missing link fails with unchanged state", lambda s: not has_link(s, "d0") and not has_link(s, "v0"))]},
    ], rand=("v0", "v1", "v2", "v3"))


R_SEED = D0A + [["link", "add", "d1", "type", "dummy"], ["link", "set", "d1", "up"], ["addr", "add", "198.51.100.1/24", "dev", "d1"]]


def rt(st, dst, via=None, dev="d0", metric=None, table="main"):
    return (dst, via, dev, metric, table, "unicast") in routes(st)


def sc_route_add_del():
    scenario_mutation("route-add-del", R_SEED, [
        {"ops": [["route", "add", "203.0.113.0/24", "via", "192.0.2.254", "dev", "d0", "metric", "50"], ["route", "add", "10.20.0.0/16", "dev", "d0", "table", "100"],
                 ["route", "add", "default", "via", "192.0.2.254"]],
         "expect": [("via+metric route", lambda s: rt(s, "203.0.113.0/24", "192.0.2.254", "d0", 50)),
                    ("table 100 route", lambda s: rt(s, "10.20.0.0/16", None, "d0", None, "100")),
                    ("default route resolved to d0", lambda s: rt(s, "default", "192.0.2.254", "d0"))]},
        {"ops": [["route", "del", "203.0.113.0/24", "via", "192.0.2.254", "dev", "d0", "metric", "50"], ["route", "del", "10.20.0.0/16", "dev", "d0", "table", "100"],
                 ["route", "del", "default", "via", "192.0.2.254"]],
         "expect": [("via route removed", lambda s: not rt(s, "203.0.113.0/24", "192.0.2.254", "d0", 50)), ("table 100 route removed", lambda s: not rt(s, "10.20.0.0/16", None, "d0", None, "100")),
                    ("default removed", lambda s: not rt(s, "default", "192.0.2.254", "d0")), ("connected route kept", lambda s: rt(s, "192.0.2.0/24"))]},
        {"ops": [["route", "del", "203.0.113.0/24"], ["route", "add", "192.0.2.0/24", "via", "198.51.100.77"]],
         "expect": [("missing delete and unreachable gateway rejected", lambda s: not rt(s, "203.0.113.0/24", "192.0.2.254", "d0", 50))]},
    ], rand=("d1",))


def sc_route_change_replace_append():
    scenario_mutation("route-change-replace-append", R_SEED + [["route", "add", "203.0.113.0/24", "via", "192.0.2.254", "dev", "d0", "metric", "50"]], [
        {"ops": [["route", "replace", "203.0.113.0/24", "via", "192.0.2.253", "dev", "d0", "metric", "50"]],
         "expect": [("replace swaps gateway", lambda s: rt(s, "203.0.113.0/24", "192.0.2.253", "d0", 50) and not rt(s, "203.0.113.0/24", "192.0.2.254", "d0", 50))]},
        {"ops": [["route", "replace", "198.51.100.128/25", "via", "192.0.2.250", "dev", "d0"]],
         "expect": [("replace creates when absent", lambda s: rt(s, "198.51.100.128/25", "192.0.2.250", "d0"))]},
        {"ops": [["route", "append", "203.0.113.0/24", "via", "192.0.2.252", "dev", "d0", "metric", "50"]],
         "expect": [("append keeps first nexthop and adds second", lambda s: rt(s, "203.0.113.0/24", "192.0.2.253", "d0", 50) and rt(s, "203.0.113.0/24", "192.0.2.252", "d0", 50))]},
        {"ops": [["route", "change", "203.0.113.0/24", "via", "192.0.2.251", "dev", "d0", "metric", "50"]],
         "expect": [("change updates existing route", lambda s: rt(s, "203.0.113.0/24", "192.0.2.251", "d0", 50))]},
    ], rand=("d1",))


def sc_route_flush():
    scenario_mutation("route-flush-dev", R_SEED + [["route", "add", "203.0.113.0/24", "via", "192.0.2.254", "dev", "d0", "metric", "50"],
                                                   ["route", "add", "10.30.0.0/16", "dev", "d0"], ["route", "add", "10.31.0.0/16", "via", "198.51.100.254", "dev", "d1"],
                                                   ["route", "add", "10.20.0.0/16", "dev", "d0", "table", "100"]], [
        {"ops": [["route", "flush", "dev", "d0"]],
         "expect": [("d0 main routes gone", lambda s: not any(r[2] == "d0" and r[4] == "main" and r[5] == "unicast" for r in routes(s))),
                    ("d1 routes kept", lambda s: rt(s, "10.31.0.0/16", "198.51.100.254", "d1") and rt(s, "198.51.100.0/24", None, "d1")),
                    ("other table kept", lambda s: rt(s, "10.20.0.0/16", None, "d0", None, "100"))]},
        {"ops": [["route", "flush", "dev", "d0"], ["route", "flush", "dev", "missing0"]],
         "expect": [("other table still kept", lambda s: rt(s, "10.20.0.0/16", None, "d0", None, "100"))]},
    ], rand=("d1",))


RULE_FULL = ["from", "10.9.0.0/16", "to", "192.0.2.0/24", "fwmark", "0x10/0xff", "uidrange", "0-0", "ipproto", "tcp", "table", "100", "priority", "500"]


def sc_rule():
    seed = [["link", "add", "d0", "type", "dummy"]]
    scenario_mutation("rule-add-del-flush", seed, [
        {"ops": [["rule", "add", "from", "10.9.0.0/16", "table", "100", "priority", "400"], ["rule", "add"] + RULE_FULL,
                 ["rule", "add", "to", "198.51.100.0/24", "table", "main", "priority", "700"]],
         "expect": [("from-only rule", lambda s: (400, "10.9.0.0", 16, None, None, None, "100", None, None) in rules_of(s)),
                    ("to-only rule", lambda s: (700, "all", None, "198.51.100.0", 24, None, "main", None, None) in rules_of(s)),
                    ("full selector rule installed", lambda s: any(r[0] == 500 and r[1] == "10.9.0.0" and r[3] == "192.0.2.0" and r[5] == "0x10" and r[6] == "100" and r[7] == 0 and r[8] == "tcp" for r in rules_of(s)))]},
        {"ops": [["rule", "del"] + RULE_FULL[:-4] + ["priority", "500"], ["rule", "del", "from", "10.9.0.0/16", "priority", "400"]],
         "expect": [("full rule deleted by selectors", lambda s: not any(r[0] == 500 for r in rules_of(s))), ("from-only rule deleted", lambda s: not any(r[0] == 400 for r in rules_of(s))),
                    ("to-only rule kept", lambda s: any(r[0] == 700 for r in rules_of(s)))]},
        {"ops": [["rule", "add", "from", "10.8.0.0/16", "table", "100", "priority", "800"], ["rule", "flush"]],
         "expect": [("flush removes every rule except priority 0 (iproute2 semantics)", lambda s: sorted(r[0] for r in rules_of(s)) == [0])]},
    ], rules=True, rand=("d0",))


N_SEED = D0A


def sc_neigh():
    nb = lambda s, ip, mac, st: (ip, "d0", mac, (st,)) in neighs(s)
    scenario_mutation("neigh-add-change-replace-del", N_SEED, [
        {"ops": [["neigh", "add", "192.0.2.99", "lladdr", "02:00:00:00:00:99", "dev", "d0", "nud", "permanent"]],
         "expect": [("permanent entry present", lambda s: nb(s, "192.0.2.99", "02:00:00:00:00:99", "PERMANENT"))]},
        {"ops": [["neigh", "change", "192.0.2.99", "lladdr", "02:00:00:00:00:98", "dev", "d0", "nud", "permanent"]],
         "expect": [("lladdr changed", lambda s: nb(s, "192.0.2.99", "02:00:00:00:00:98", "PERMANENT") and not nb(s, "192.0.2.99", "02:00:00:00:00:99", "PERMANENT"))]},
        {"ops": [["neigh", "replace", "192.0.2.98", "lladdr", "02:00:00:00:00:97", "dev", "d0", "nud", "reachable"], ["neigh", "replace", "192.0.2.99", "lladdr", "02:00:00:00:00:96", "dev", "d0", "nud", "stale"]],
         "expect": [("replace created reachable", lambda s: any(n[0] == "192.0.2.98" and n[2] == "02:00:00:00:00:97" for n in neighs(s))),
                    ("replace updated existing with new state", lambda s: nb(s, "192.0.2.99", "02:00:00:00:00:96", "STALE"))]},
        {"ops": [["neigh", "del", "192.0.2.98", "dev", "d0"], ["neigh", "del", "192.0.2.99", "lladdr", "02:00:00:00:00:96", "dev", "d0"], ["neigh", "del", "192.0.2.55", "dev", "d0"]],
         "expect": [("deleted entries gone", lambda s: not any(n[0] in ("192.0.2.98", "192.0.2.99") for n in neighs(s)))]},
    ])


def sc_batch(kind):
    seed = [["link", "add", "d0", "type", "dummy"], ["link", "set", "d0", "address", "02:00:00:00:00:01", "up"]]
    have = lambda s, c: has_addr(s, "d0", c)
    if kind == "tokenize":
        text = "# leading comment\n\n  addr add 192.0.2.1/24 dev d0 # inline comment\n\n\taddr   add   192.0.2.2/24\tdev  d0   \n   # indented comment\n\n\naddr add 192.0.2.3/24 \\\n dev d0\n# last comment without newline"
        scenario_mutation("batch-tokenize", seed, [
            {"ops": [{"batch": text}],
             "expect": [("whitespace-separated commands applied", lambda s: have(s, "192.0.2.1/24") and have(s, "192.0.2.2/24")),
                        ("comment, blank and continuation lines handled", lambda s: have(s, "192.0.2.3/24"))]}])
    elif kind == "quoting":
        text = "addr add 192.0.2.1/24 dev \"d0\"\naddr add 192.0.2.2/24 dev 'd0'\n"
        scenario_mutation("batch-quoting", seed, [
            {"ops": [{"batch": text, "force": True}],
             "expect": [("double-quoted device accepted", lambda s: have(s, "192.0.2.1/24")),
                        ("single-quoted device accepted", lambda s: have(s, "192.0.2.2/24"))]}])
        # The assigned -force contract continues after a malformed line.
        malformed = "addr add 192.0.2.4/24 dev 'd0\naddr add 192.0.2.5/24 dev d0\n"
        scenario_mutation("batch-unterminated-quote", seed, [
            {"ops": [{"batch": malformed, "force": True}],
             "expect": [("force continues after unterminated quote", lambda s: have(s, "192.0.2.5/24"))]}])
    elif kind == "stop":
        text = "addr add 192.0.2.1/24 dev d0\nlink set nosuch0 up\naddr add 192.0.2.2/24 dev d0\n"
        scenario_mutation("batch-stop-first-failure", seed, [
            {"ops": [{"batch": text}],
             "expect": [("command before failure applied", lambda s: have(s, "192.0.2.1/24")), ("command after failure not applied", lambda s: not have(s, "192.0.2.2/24"))]}])
        # diagnostic names the failing line
        def body():
            setup_ns()
            L.seed(seed)
            with open("/tmp/parity-case/batch.txt", "w") as f:
                f.write(text)
            rc, out, err = L.cand_ip(["-batch", "/tmp/parity-case/batch.txt"])
            L.check("batch-stop nonzero status", rc != 0, "rc=%s" % rc)
            L.check("batch-stop diagnostic names failing line 2", re.search(r"batch.txt:2\b", err) is not None, err)
            return {}
        L.in_netns(body)
    elif kind == "force":
        text = "addr add 192.0.2.1/24 dev d0\nlink set nosuch0 up\naddr add 192.0.2.2/24 dev d0\nroute del 203.0.113.0/24\naddr add 192.0.2.3/24 dev d0\n"
        scenario_mutation("batch-force-continue", seed, [
            {"ops": [{"batch": text, "force": True}],
             "expect": [("later commands applied after failures", lambda s: have(s, "192.0.2.1/24") and have(s, "192.0.2.2/24") and have(s, "192.0.2.3/24"))]}])
        def body():
            setup_ns()
            L.seed(seed)
            with open("/tmp/parity-case/batch.txt", "w") as f:
                f.write(text)
            rc, out, err = L.cand_ip(["-force", "-batch", "/tmp/parity-case/batch.txt"])
            L.check("batch-force overall status nonzero", rc != 0, "rc=%s err=%s" % (rc, err))
            return {}
        L.in_netns(body)
    elif kind == "stdin":
        text = "addr add 192.0.2.1/24 dev d0\n# c\n\naddr add 192.0.2.2/24 dev d0\nlink set d0 mtu 1400\n"
        scenario_mutation("batch-stdin", seed, [
            {"ops": [{"batch": text, "stdin": True}],
             "expect": [("stdin commands applied", lambda s: have(s, "192.0.2.1/24") and have(s, "192.0.2.2/24") and lk(s)["d0"]["mtu"] == 1400)]}])


SCEN = {
    "addr-add-del": sc_addr_add_del, "addr-change-replace": sc_addr_change_replace,
    "addr-flush-to": sc_addr_flush_to, "addr-flush-scope": sc_addr_flush_scope, "addr-flush-dev": sc_addr_flush_dev,
    "addr-show-dev": sc_show_addr_dev, "addr-show-to": sc_show_addr_to, "addr-show-scope": sc_show_addr_scope,
    "addr-show-4": sc_show_addr_v4, "addr-show-6": sc_show_addr_v6,
    "link-show-default": lambda: sc_show_link("default"), "link-show-brief": lambda: sc_show_link("brief"),
    "link-show-oneline": lambda: sc_show_link("oneline"), "link-show-json": sc_show_link_json,
    "link-show-json-schema": sc_show_link_json_schema,
    "route-show-plain": lambda: sc_show_route("route-show-plain", []), "route-show-dev": lambda: sc_show_route("route-show-dev", ["dev", "d1"]),
    "route-show-default": sc_show_route_default, "route-show-table": sc_show_route_all,
    "rule-show-text": sc_show_rule_text, "rule-show-json": sc_show_rule_json, "rule-show-json-schema": sc_show_rule_json_schema,
    "neigh-show-all": lambda: sc_show_neigh("neigh-show", [], True), "neigh-show-dev": lambda: sc_show_neigh("neigh-show-dev", ["dev", "d0"], True),
    "neigh-show-strict": lambda: sc_show_neigh("neigh-show-strict", [], False),
    "link-updown": sc_link_updown, "link-mtu-address": sc_link_mtu_addr, "link-add-dummy": sc_link_add_dummy,
    "link-add-veth": sc_link_add_veth, "link-del": sc_link_del,
    "route-add-del": sc_route_add_del, "route-change": sc_route_change_replace_append, "route-flush": sc_route_flush,
    "rule": sc_rule, "neigh": sc_neigh,
    "batch-tokenize": lambda: sc_batch("tokenize"), "batch-stop": lambda: sc_batch("stop"),
    "batch-force": lambda: sc_batch("force"), "batch-quoting": lambda: sc_batch("quoting"), "batch-stdin": lambda: sc_batch("stdin"),
}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
