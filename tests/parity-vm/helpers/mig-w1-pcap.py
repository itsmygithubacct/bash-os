#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""w1 pcap/netids live-capture fixtures on veth pairs inside a mapped user+network namespace.

Frames are injected with AF_PACKET on one end of a veth pair and captured by the candidate on the
other end. Expected pcap content is derived from the injected bytes and decoded independently
with struct and tcpdump -r. netids blocking uses a recording `fw` executable placed first in PATH.
"""
import json, os, socket, struct, subprocess, sys, time
import importlib.util
_spec = importlib.util.spec_from_file_location("mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

CASE = "/tmp/parity-case"
HOME = "/tmp/parity-home"


def setup():
    for p in ("default", "all"):
        with open("/proc/sys/net/ipv6/conf/%s/disable_ipv6" % p, "w") as f:
            f.write("1")
    L.seed([["link", "add", "v0", "type", "veth", "peer", "name", "v1"], ["link", "add", "p0", "type", "veth", "peer", "name", "p1"]]
           + [["link", "set", n, "up"] for n in ("v0", "v1", "p0", "p1")])


def inject(ifn, frame):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((ifn, 0))
    s.send(frame)
    s.close()


def eth(size, tag):
    body = bytes((i * 7 + tag) & 0xff for i in range(size - 14))
    return bytes.fromhex("02000000aa01") + bytes.fromhex("02000000bb01") + b"\x88\xb5" + body


def csum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return bytes.fromhex("02000000aa01") + bytes.fromhex("02000000bb01") + b"\x08\x00" + ip + udp


def wait_sock(ifn, timeout=6.0):
    idx = socket.if_nametoindex(ifn) if ifn else 0
    end = time.time() + timeout
    while time.time() < end:
        for ln in open("/proc/net/packet").read().splitlines()[1:]:
            t = ln.split()
            if len(t) >= 5 and t[3] == "0003" and int(t[4]) == idx:
                return True
        time.sleep(0.05)
    return False


def capture(script, args, ifn, injects, env=None, timeout=20):
    e = dict(L.ENV)
    if env:
        e.update(env)
    t0 = time.time()
    p = subprocess.Popen([L.CAND, "--noprofile", "--norc", "-c", script, "cand"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=e, cwd=CASE)
    ok = True
    if injects:
        ok = wait_sock(ifn)
        for n, fr in injects:
            inject(n, fr)
            time.sleep(0.05)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        err += "\n[fixture: killed after timeout]"
    return {"rc": p.returncode, "out": out, "err": err, "elapsed": time.time() - t0, "armed": ok}


def decode(path):
    d = open(path, "rb").read()
    hdr = struct.unpack("<IHHiIII", d[:24])
    recs, off = [], 24
    while off + 16 <= len(d):
        ts, us, incl, orig = struct.unpack("<IIII", d[off:off + 16])
        recs.append({"ts": ts + us / 1e6, "incl": incl, "orig": orig, "data": d[off + 16:off + 16 + incl]})
        off += 16 + incl
    return hdr, recs, len(d)


def tcpdump(path):
    return L.run(["tcpdump", "-Z", "root", "-nn", "-e", "-r", path])


def pcap_run(args, injects, ifn="v0", script='pcap "$@"'):
    return capture(script, args, ifn, injects)


def sc_iface():
    setup()
    f = [eth(60, i) for i in range(3)]
    g = [eth(70, 50 + i) for i in range(2)]
    r = pcap_run(["-i", "v0", "-w", CASE + "/a.pcap", "-c", "3", "-W", "3"],
                 [("v1", f[0]), ("p1", g[0]), ("v1", f[1]), ("p1", g[1]), ("v1", f[2])])
    L.check("iface capture armed before injection", r["armed"], str(r))
    L.check("iface capture rc0 after 3 frames", r["rc"] == 0, "%s" % r)
    hdr, recs, size = decode(CASE + "/a.pcap")
    L.check("iface file holds exactly the three frames injected on the selected interface, in order", [x["data"] for x in recs] == f, "got %d records" % len(recs))
    L.check("iface frames injected on the other interface are absent", not any(x["data"] in g for x in recs), "")
    r2 = pcap_run(["-i", "p0", "-w", CASE + "/b.pcap", "-c", "2", "-W", "3"], [("p1", g[0]), ("v1", f[0]), ("p1", g[1])], ifn="p0")
    h2, recs2, _ = decode(CASE + "/b.pcap")
    L.check("iface selecting p0 captures only the p-pair frames", [x["data"] for x in recs2] == g, "records=%d rc=%s" % (len(recs2), r2["rc"]))
    r3 = pcap_run(["-i", "nosuch0", "-w", CASE + "/c.pcap", "-c", "1"], [])
    L.check("iface nonexistent interface fails with a diagnostic", r3["rc"] != 0 and "no such interface" in r3["err"], str(r3))


def sc_timeout():
    setup()
    r = pcap_run(["-i", "v0", "-w", CASE + "/e.pcap", "-c", "2", "-W", "0.5"], [])
    L.check("timeout no-traffic capture ends within a bounded interval (0.4s..3s)", 0.4 <= r["elapsed"] <= 3.0, "elapsed=%.2f" % r["elapsed"])
    L.check("timeout no-traffic capture exits with status 1 and reports the timeout", r["rc"] == 1 and "capture timeout after 0/2" in r["err"], str(r))
    hdr, recs, size = decode(CASE + "/e.pcap")
    L.check("timeout file is a valid empty pcap (24-byte header, magic a1b2c3d4, linktype 1, no records)", size == 24 and hdr[0] == 0xa1b2c3d4 and hdr[6] == 1 and not recs, str((hdr, size)))
    rc, out, err = tcpdump(CASE + "/e.pcap")
    L.check("timeout tcpdump -r reads the empty file without error or packets", rc == 0 and not [l for l in out.splitlines() if l.strip()], "rc=%s out=%r err=%r" % (rc, out, err))
    f = eth(60, 9)
    r = pcap_run(["-i", "v0", "-w", CASE + "/f.pcap", "-c", "3", "-W", "0.5"], [("v1", f)])
    hdr, recs, size = decode(CASE + "/f.pcap")
    L.check("timeout after traffic stops keeps the frame captured so far and ends by timeout", [x["data"] for x in recs] == [f] and "capture timeout after 1/3" in r["err"] and 0.4 <= r["elapsed"] <= 4, str((len(recs), r)))


def sc_count_header():
    setup()
    fr = [eth(n, i) for i, n in enumerate((60, 80, 100, 64))]
    r = pcap_run(["-i", "v0", "-w", CASE + "/h.pcap", "-c", "4", "-s", "100", "-W", "3"], [("v1", x) for x in fr])
    hdr, recs, size = decode(CASE + "/h.pcap")
    L.check("count capture -c 4 exits promptly with status 0", r["rc"] == 0 and r["elapsed"] < 5, str(r))
    L.check("count file has exactly 4 records", len(recs) == 4 and size == 24 + sum(16 + len(x) for x in fr), "records=%d size=%d" % (len(recs), size))
    L.check("header magic 0xa1b2c3d4 (microsecond, little-endian)", hdr[0] == 0xa1b2c3d4, hex(hdr[0]))
    L.check("header version 2.4", hdr[1:3] == (2, 4), str(hdr))
    L.check("header thiszone 0 and sigfigs 0", hdr[3] == 0 and hdr[4] == 0, str(hdr))
    L.check("header snaplen equals -s 100", hdr[5] == 100, str(hdr))
    L.check("header linktype 1 (Ethernet)", hdr[6] == 1, str(hdr))
    rc, out, err = tcpdump(CASE + "/h.pcap")
    L.check("count tcpdump decodes four ethernet records", rc == 0 and len([l for l in out.splitlines() if "ethertype" in l]) == 4, "rc=%s out=%r err=%r" % (rc, out, err))


def sc_records():
    setup()
    fr = [eth(n, 3 + i) for i, n in enumerate((60, 90, 100))]
    t0 = time.time()
    pcap_run(["-i", "v0", "-w", CASE + "/r.pcap", "-c", "3", "-s", "100", "-W", "3"], [("v1", x) for x in fr])
    t1 = time.time()
    hdr, recs, size = decode(CASE + "/r.pcap")
    L.check("records: three records", len(recs) == 3, str(len(recs)))
    L.check("records: incl_len and orig_len equal the injected frame lengths", [(x["incl"], x["orig"]) for x in recs] == [(len(x), len(x)) for x in fr], str([(x["incl"], x["orig"]) for x in recs]))
    L.check("records: bytes equal the injected frames", [x["data"] for x in recs] == fr, "")
    L.check("records: timestamps fall inside the capture window", all(t0 - 1 <= x["ts"] <= t1 + 1 for x in recs), str([x["ts"] for x in recs]))
    rc, out, err = tcpdump(CASE + "/r.pcap")
    L.check("records: tcpdump reports lengths 60, 90, 100", [l.split("length ")[1].split(":")[0] for l in out.splitlines() if "length " in l] == ["60", "90", "100"], out)


def sc_snaplen():
    setup()
    big = eth(200, 11)
    small = eth(60, 12)
    pcap_run(["-i", "v0", "-w", CASE + "/s.pcap", "-c", "2", "-s", "100", "-W", "3"], [("v1", small), ("v1", big)])
    hdr, recs, size = decode(CASE + "/s.pcap")
    L.check("snaplen: two records", len(recs) == 2, str(len(recs)))
    if len(recs) == 2:
        L.check("snaplen: frame longer than -s is stored truncated to snaplen", recs[1]["incl"] == 100 and recs[1]["data"] == big[:100], str((recs[1]["incl"], len(recs[1]["data"]))))
        L.check("snaplen: orig_len keeps the 200-byte wire length", recs[1]["orig"] == 200, "orig_len=%d" % recs[1]["orig"])
        L.check("snaplen: short frame untouched", recs[0]["incl"] == 60 and recs[0]["orig"] == 60, str(recs[0]["incl"]))
    rc, out, err = tcpdump(CASE + "/s.pcap")
    L.check("snaplen: tcpdump reports the long frame with length 200", "length 200" in out, out)


def sc_perms():
    setup()
    for um, want in (("022", 0o644), ("077", 0o600), ("027", 0o640), ("002", 0o664 & 0o644)):
        path = CASE + "/m%s.pcap" % um
        r = capture('umask %s; pcap "$@"' % um, ["-i", "v0", "-w", path, "-c", "1", "-W", "3"], "v0", [("v1", eth(60, 1))])
        mode = os.stat(path).st_mode & 0o777
        L.check("perms: umask %s gives mode %o (0644 & ~umask)" % (um, want), mode == want and r["rc"] == 0, "mode=%o rc=%s" % (mode, r["rc"]))


RULES = ('alert udp any any -> any any (msg:"w1 udp marker"; content:"w1-marker"; sid:1001; rev:1;)\n')
BRULES = ('drop udp any any -> any any (msg:"w1 drop"; content:"w1-bad"; sid:2001; rev:1;)\n'
          'reject udp any any -> any 5353 (msg:"w1 reject"; content:"w1-rej"; sid:2002; rev:1;)\n')


def events(path):
    try:
        return [json.loads(l) for l in open(path).read().splitlines() if l.strip()]
    except (OSError, ValueError):
        return None


def anyval(ev, val):
    return val in json.dumps(ev)


def sc_netids_live():
    setup()
    open(CASE + "/r.rules", "w").write(RULES)
    m = udp_frame("192.0.2.1", "192.0.2.2", 1234, 5678, b"xx w1-marker yy")
    r = capture('netids "$@"', ["scan", "-i", "v0", "-S", CASE + "/r.rules", "-o", CASE + "/o1.json", "--count", "1", "--timeout", "3"], "v0", [("v1", m)])
    ev = events(CASE + "/o1.json")
    L.check("netids live -i --count 1 exits 0", r["rc"] == 0, str(r))
    L.check("netids live emits exactly one alert event", ev is not None and len(ev) == 1 and ev[0].get("event_type") == "alert", str(ev))
    if ev and len(ev) == 1:
        e = ev[0]
        L.check("alert carries the injected packet's addresses, ports and UDP proto", all(anyval(e, v) for v in ('"192.0.2.1"', '"192.0.2.2"', "1234", "5678", '"UDP"')), json.dumps(e))
        L.check("alert carries the rule's signature and sid", anyval(e, '"w1 udp marker"') and anyval(e, "1001"), json.dumps(e))
    r = capture('netids "$@"', ["scan", "-i", "v0", "-S", CASE + "/r.rules", "-o", CASE + "/o3.json", "--count", "3", "--timeout", "3"], "v0",
                [("v1", udp_frame("192.0.2.1", "192.0.2.2", 1, 2, b"other")), ("v1", m), ("v1", udp_frame("192.0.2.1", "192.0.2.2", 1, 2, b"other2"))])
    ev = events(CASE + "/o3.json")
    L.check("netids live three packets give exactly one alert", r["rc"] == 0 and ev is not None and len(ev) == 1 and "3 live packet(s), 1 alert(s)" in r["err"], str((r, ev)))


def sc_netids_timeout():
    setup()
    open(CASE + "/r.rules", "w").write(RULES)
    r = capture('netids "$@"', ["scan", "-i", "v0", "-S", CASE + "/r.rules", "-o", CASE + "/o.json", "--count", "1", "--timeout", "0.5"], "v0", [])
    L.check("netids no-traffic --timeout 0.5 ends within a bounded interval", 0.4 <= r["elapsed"] <= 3.0, "elapsed=%.2f" % r["elapsed"])
    L.check("netids no-traffic ends with success and no event", r["rc"] == 0 and events(CASE + "/o.json") == [] and "0 live packet(s)" in r["err"], str(r))
    r = capture('netids "$@"', ["scan", "-i", "nosuch0", "-S", CASE + "/r.rules", "--count", "1", "--timeout", "0.5"], "v0", [])
    L.check("netids nonexistent interface fails with a diagnostic", r["rc"] != 0 and "no such interface: nosuch0" in r["err"], str(r))


def mockfw():
    d = HOME + "/mockfw"
    os.makedirs(d, exist_ok=True)
    open(d + "/fw", "w").write('#!/usr/bin/python3\nimport os,sys\nh=os.environ["HOME"]\nopen(h+"/fw.log","a").write(" ".join(sys.argv[1:])+"\\n")\ntry:\n    rc=int(open(h+"/fw.rc").read())\nexcept OSError:\n    rc=0\nsys.exit(rc)\n')
    os.chmod(d + "/fw", 0o755)
    return d


def fwlog():
    try:
        return open(HOME + "/fw.log").read().splitlines()
    except OSError:
        return []


def run_block(rules, frames, count, rc_file=None, path_env=None, tag="b"):
    open(CASE + "/b.rules", "w").write(rules)
    for f in (HOME + "/fw.log", HOME + "/fw.rc"):
        if os.path.exists(f):
            os.unlink(f)
    if rc_file is not None:
        open(HOME + "/fw.rc", "w").write(str(rc_file))
    out = CASE + "/%s.json" % tag
    r = capture('netids "$@"', ["scan", "-i", "v0", "-S", CASE + "/b.rules", "-o", out, "--enable-blocking", "--count", str(count), "--timeout", "3"], "v0",
                [("v1", f) for f in frames], env={"PATH": path_env or (mockfw() + ":/usr/sbin:/usr/bin:/bin")})
    return r, events(out)


def sc_block_drop():
    setup()
    bad = lambda ip: udp_frame(ip, "192.0.2.50", 4000, 4001, b"w1-bad")
    r, ev = run_block(BRULES, [bad("192.0.2.7"), bad("192.0.2.7"), bad("192.0.2.8")], 3)
    L.check("blocking live scan exits 0", r["rc"] == 0, str(r))
    L.check("blocking runs fw deny once per source (dedupe): 192.0.2.7 then 192.0.2.8", fwlog() == ["deny 192.0.2.7", "deny 192.0.2.8"], str(fwlog()))
    blocks = [e for e in (ev or []) if e.get("event_type") == "block"]
    L.check("blocking emits two block events", len(blocks) == 2, str(ev))
    if len(blocks) == 2:
        L.check("block events report dry_run false, bashfw_argv 'fw deny SRC' and bashfw_rc 0", [(b["dry_run"], b["bashfw_argv"], b["bashfw_rc"]) for b in blocks] == [(False, "fw deny 192.0.2.7", 0), (False, "fw deny 192.0.2.8", 0)], str(blocks))


def sc_block_reject():
    setup()
    r, ev = run_block(BRULES, [udp_frame("192.0.2.9", "192.0.2.50", 4000, 5353, b"w1-rej")], 1, tag="rj")
    L.check("reject rule runs fw deny SRC exactly once", fwlog() == ["deny 192.0.2.9"], str(fwlog()))
    blocks = [e for e in (ev or []) if e.get("event_type") == "block"]
    L.check("reject rule produces a block event with action reject, dry_run false and bashfw_rc 0", len(blocks) == 1 and blocks[0]["action"] == "reject" and blocks[0]["dry_run"] is False and blocks[0]["bashfw_rc"] == 0, str(ev))
    L.check("reject scan exits 0", r["rc"] == 0, str(r))


def sc_block_fail():
    setup()
    bad = udp_frame("192.0.2.7", "192.0.2.50", 4000, 4001, b"w1-bad")
    r, ev = run_block(BRULES, [bad], 1, rc_file=7, tag="f7")
    L.check("failing fw (status 7): fw was invoked", fwlog() == ["deny 192.0.2.7"], str(fwlog()))
    blocks = [e for e in (ev or []) if e.get("event_type") == "block"]
    L.check("failing fw: block event reports bashfw_rc 7", len(blocks) == 1 and blocks[0]["bashfw_rc"] == 7, str(ev))
    L.check("failing fw: netids exits nonzero", r["rc"] != 0, str(r))
    r, ev = run_block(BRULES, [bad], 1, path_env="/nonexistent", tag="f127")
    blocks = [e for e in (ev or []) if e.get("event_type") == "block"]
    L.check("missing fw: block event reports bashfw_rc 127", len(blocks) == 1 and blocks[0]["bashfw_rc"] == 127, str((ev, r)))
    L.check("missing fw: diagnostic names the failed exec and exit is nonzero", r["rc"] != 0 and "execvp fw" in r["err"], str(r))


SCEN = {"iface": sc_iface, "timeout": sc_timeout, "count-header": sc_count_header, "records": sc_records, "snaplen": sc_snaplen, "perms": sc_perms,
        "netids-live": sc_netids_live, "netids-timeout": sc_netids_timeout, "block-drop": sc_block_drop, "block-reject": sc_block_reject, "block-fail": sc_block_fail}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
