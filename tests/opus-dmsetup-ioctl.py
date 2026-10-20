#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""dmsetup DM-ioctl request/response checks against an injected mapper fixture.

tests/opus-dmsetup-ioctl.py [BASH]

The production builtin runs inside BASH with tests/opus-dmsetup-fixture.c
preloaded; that fixture turns /dev/mapper/control into an in-memory mapper
and logs every request byte for byte. This script decodes those bytes with
its own struct layout (an oracle independent of the C headers) and checks
headers, flags, target-spec packing, payloads, retry sizes, responses,
error wording, mutation policy and descriptor cleanup. No real device-mapper
node is opened. Set DMSETUP_FIXTURE_SO to a prebuilt fixture; otherwise it is
compiled with $CC (run this under the campaign build gate in that case).
"""

import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HDR = struct.Struct("<3I I I I i I I I Q 128s 129s 7s")   # struct dm_ioctl, 312 bytes
SPEC = struct.Struct("<Q Q i I 16s")                       # struct dm_target_spec, 40 bytes
assert HDR.size == 312 and SPEC.size == 40
F_READONLY, F_SUSPEND, F_PERSISTENT, F_TABLE = 1, 2, 8, 16
F_ACTIVE, F_INACTIVE, F_FULL, F_SKIP_LOCKFS = 32, 64, 256, 1024
F_NOFLUSH, F_QUERY_INACTIVE, F_UUID, F_DATA_OUT, F_DEFERRED = 2048, 4096, 16384, 65536, 131072
NR = dict(version=0, remove_all=1, names=2, create=3, remove=4, rename=5, suspend=6,
          info=7, reload=9, clear=10, deps=11, status=12, versions=13, message=14)

failures = []
checks = 0


def check(cond, what, detail=""):
    global checks
    checks += 1
    if not cond:
        failures.append(what)
        print(f"  FAIL  {what}" + (f"\n        {detail}" if detail else ""))


def align8(n):
    return (n + 7) & ~7


class Req:
    def __init__(self, nr, cmd, raw):
        self.nr, self.cmd, self.raw = nr, cmd, raw
        (v0, v1, v2, self.data_size, self.data_start, self.target_count, self.open_count,
         self.flags, self.event_nr, _pad, self.dev, name, uuid, _d) = HDR.unpack_from(raw)
        self.version = (v0, v1, v2)
        self.name = name.split(b"\0", 1)[0].decode()
        self.uuid = uuid.split(b"\0", 1)[0].decode()
        self.payload = raw[self.data_start:self.data_size]

    def specs(self):
        """Decode DM_TABLE_LOAD specs; next is relative to each spec."""
        out, off = [], 0
        for _ in range(self.target_count):
            start, length, status, nxt, ttype = SPEC.unpack_from(self.payload, off)
            params = self.payload[off + SPEC.size:].split(b"\0", 1)[0].decode()
            out.append(dict(start=start, length=length, status=status, next=nxt,
                            type=ttype.split(b"\0", 1)[0].decode(), params=params, off=off))
            off += nxt
        return out


def expected_load_payload(lines):
    """Bytes a correct client must send for these (start, len, type, params)."""
    out = b""
    for start, length, ttype, params in lines:
        p = params.encode() + b"\0"
        one = align8(SPEC.size + len(p))
        out += SPEC.pack(start, length, 0, one, ttype.encode().ljust(16, b"\0")) + p
        out += b"\0" * (one - SPEC.size - len(p))
    return out


class Run:
    def __init__(self, rc, out, err, log, stats):
        self.rc, self.out, self.err, self.stats = rc, out, err, stats
        self.reqs, self.results, self.events = [], [], []
        for line in log.splitlines():
            if line.startswith("ioctl "):
                m = re.match(r"ioctl nr=(\d+) cmd=(\S+) size=(\d+) hex=([0-9a-f]*)$", line)
                self.reqs.append(Req(int(m[1]), m[2], bytes.fromhex(m[4])))
                self.events.append(("ioctl", m[2]))
            elif line.startswith("result "):
                self.results.append(dict(kv.split("=", 1) for kv in line.split()[1:]))
            else:
                self.events.append(tuple(line.split()))

    def cmds(self):
        return [r.cmd for r in self.reqs]


class Fixture:
    def __init__(self, bash, so, tmp):
        self.bash, self.so, self.tmp, self.n = bash, so, tmp, 0

    def run(self, script, state="", root=True, allow=True, env=None, stdin=None, tty=False):
        self.n += 1
        base = os.path.join(self.tmp, f"run{self.n}")
        with open(base + ".state", "w") as f:
            f.write(state)
        e = {k: v for k, v in os.environ.items() if not k.startswith(("DMSFIX_", "BASHOS_DMSETUP"))}
        e.update(LD_PRELOAD=self.so + (":" + e["LD_PRELOAD"] if e.get("LD_PRELOAD") else ""),
                 DMSFIX_STATE=base + ".state", DMSFIX_LOG=base + ".log", DMSFIX_STATS=base + ".stats",
                 DMSFIX_EUID="0" if root else "1000")
        if allow:
            e["BASHOS_DMSETUP_ALLOW_MUTATE"] = "1"
        e.update(env or {})
        kw = dict(input=stdin) if stdin is not None else {}
        master = slave = None
        if tty:
            master, slave = os.openpty()
            kw = dict(stdin=slave)
        elif stdin is None:
            kw = dict(stdin=subprocess.DEVNULL)
        try:
            p = subprocess.run([self.bash, "-c", "PATH=; " + script], env=e, text=True,
                               capture_output=True, timeout=120, **kw)
        finally:
            for fd in (master, slave):
                if fd is not None:
                    os.close(fd)
        log = open(base + ".log").read() if os.path.exists(base + ".log") else ""
        stats = {}
        if os.path.exists(base + ".stats"):
            for line in open(base + ".stats"):
                k, _, v = line.rstrip("\n").partition(" ")
                if k in ("ioctls", "opens", "closes", "open_now", "devices"):
                    stats[k] = int(v)
                elif k == "dev":
                    stats.setdefault("devs", {})[v.split()[0]] = v
            stats["text"] = open(base + ".stats").read()
        return Run(p.returncode, p.stdout, p.stderr, log, stats)


STATE = """dev alpha - 0 0 0
live 0 100 linear 8:0 2048
live 100 50 linear 8:16 0
dev beta UUID-BETA 1 1 0
live 0 10 zero
dev gamma - 2 0 0
"""
MUTATORS = ["create n0 --table '0 1 zero'", "load alpha --table '0 1 zero'",
            "reload alpha --table '0 1 zero'", "remove alpha", "remove_all", "suspend alpha",
            "resume alpha", "rename alpha a2", "message alpha 0 ping", "clear alpha",
            "wipe_table alpha"]


def balanced(r, what):
    check(r.stats.get("opens") == r.stats.get("closes") and r.stats.get("open_now") == 0,
          f"{what}: every control descriptor closed", str(r.stats))
    for ev in r.events:
        if ev[0] == "open" and ev[1].startswith("fd="):
            check(ev[2] == "cloexec=1", f"{what}: control opened O_CLOEXEC")


def headers_sane(r, what):
    for q in r.reqs:
        check(q.version == (4, 48, 0) or q.version[0] == 4, f"{what}: {q.cmd} header version 4.x")
        check(q.data_start == HDR.size, f"{what}: {q.cmd} data_start is sizeof(struct dm_ioctl)")
        check(q.data_size == len(q.raw), f"{what}: {q.cmd} data_size matches the buffer")


def t_policy(fx):
    print("== mutation policy ==")
    for root, allow, label in ((False, True, "non-root"), (True, False, "root without opt-in"),
                               (False, False, "neither")):
        for m in MUTATORS:
            r = fx.run("dmsetup " + m, STATE, root=root, allow=allow)
            verb = m.split()[0]
            check(r.rc == 1 and f"dmsetup: {verb} requires root and BASHOS_DMSETUP_ALLOW_MUTATE=1" in r.err,
                  f"{label}: {verb} refused", r.err)
            check(r.stats.get("opens") == 0, f"{label}: {verb} never opens the control node", str(r.stats))
    r = fx.run("dmsetup remove alpha", STATE, env={"BASHOS_DMSETUP_ALLOW_MUTATE": "yes"})
    check(r.rc == 1 and r.stats.get("opens") == 0, "opt-in value must be exactly 1")
    r = fx.run("dmsetup table alpha; dmsetup info beta", STATE, root=False, allow=False)
    check(r.rc == 0 and "0 100 linear 8:0 2048" in r.out, "queries need no mutation policy", r.err)


def t_create(fx):
    print("== create: request sequence, aligned specs, flags ==")
    table = "# comment\n0 100 linear 8:0 2048\n\n100 7 zero\n107 1 error  \n"
    r = fx.run("dmsetup create newdev -u NEW-UUID -r --table \"$T\"", STATE, env={"T": table})
    check(r.rc == 0, "create with table succeeds", r.err)
    check(r.cmds() == ["create", "reload", "resume"], "create sends create, reload, resume", r.cmds())
    headers_sane(r, "create")
    c, l, s = r.reqs
    check(c.name == "newdev" and c.uuid == "NEW-UUID" and c.flags == 0 and c.payload == b"",
          "create header: name, uuid, no flags, no payload")
    check(l.name == "newdev" and l.uuid == "" and l.flags & F_READONLY and l.target_count == 3,
          "reload header: by name, READONLY, three targets", (l.name, l.uuid, l.flags, l.target_count))
    want = expected_load_payload([(0, 100, "linear", "8:0 2048"), (100, 7, "zero", ""), (107, 1, "error", "")])
    check(l.payload == want, "reload payload matches the independent encoding",
          f"got {l.payload.hex()}\n        want {want.hex()}")
    check(all(sp["next"] % 8 == 0 and sp["off"] % 8 == 0 for sp in l.specs()), "every spec 8-aligned")
    check(s.flags & F_SUSPEND == 0 and s.name == "newdev", "resume clears DM_SUSPEND_FLAG")
    check("dev newdev NEW-UUID" in r.stats["text"] and "ro=1 live=3" in r.stats["text"],
          "fixture holds the created read-only device", r.stats["text"])
    balanced(r, "create")

    with tempfile.NamedTemporaryFile("w", dir=fx.tmp, delete=False) as f:
        f.write("0 64 zero\n64 64 linear 7:3 9\n")
    r = fx.run(f"dmsetup create fromfile {f.name}; dmsetup table fromfile", STATE)
    check(r.rc == 0 and r.out == "0 64 zero \n64 64 linear 7:3 9\n", "table read from a file", r.out + r.err)
    r = fx.run("dmsetup create fromstdin; dmsetup table fromstdin", STATE, stdin="0 5 zero\n")
    check(r.rc == 0 and r.out == "0 5 zero \n", "table read from stdin", r.out + r.err)
    r = fx.run("dmsetup create inline '0 9 zero'; dmsetup table inline", STATE)
    check(r.rc == 0 and r.out == "0 9 zero \n", "inline table argument kept from the old builtin", r.out + r.err)

    r = fx.run("dmsetup create bare -n; dmsetup info bare", STATE)
    check(r.cmds() == ["create", "info"] and "Tables present:    None" in r.out,
          "--notable creates without a table", r.cmds())
    r = fx.run("dmsetup create pinned -n -j 253 -m 77; dmsetup ls", STATE)
    c = r.reqs[0]
    check(c.flags & F_PERSISTENT and c.dev == (253 << 8 | 77), "--major/--minor request a persistent dev",
          (c.flags, c.dev))
    check("pinned\t(253:77)" in r.out, "persistent minor appears in ls", r.out)
    r = fx.run("dmsetup create half -n -j 253", STATE)
    check(r.rc == 1 and not r.reqs, "--major without --minor rejected before any ioctl")

    print("== create: failures revert ==")
    r = fx.run("dmsetup create bad --table '0 10 bogus'", STATE)
    check(r.rc == 1 and r.cmds() == ["create", "reload", "remove"], "kernel-rejected table reverts the create",
          r.cmds())
    check("device-mapper: reload ioctl on bad  failed: Invalid argument" in r.err, "reload failure wording", r.err)
    check(r.err.count("Command failed.") == 1, "one Command failed. line", r.err)
    check("dev bad " not in r.stats["text"], "reverted device is gone")
    r = fx.run("dmsetup create gap --table $'0 10 zero\\n20 5 zero'", STATE)
    check(r.rc == 1 and r.cmds() == ["create", "reload", "remove"], "gapped table rejected and reverted")
    r = fx.run("dmsetup create bad2 --table '0 10 zero'", STATE, env={"DMSFIX_FAIL": "resume@bad2=5"})
    check(r.rc == 1 and r.cmds() == ["create", "reload", "resume", "remove"], "failed resume reverts too",
          r.cmds())
    r = fx.run("dmsetup create alpha --table '0 1 zero'", STATE)
    check(r.rc == 1 and r.cmds() == ["create"] and "Device or resource busy" in r.err,
          "duplicate name: EBUSY, nothing else sent", r.err)
    balanced(r, "create failure")


def t_malformed_tables(fx):
    print("== malformed table text never reaches the kernel ==")
    cases = {"0 x linear 8:0 0": 1, "abc": 1, "-1 5 zero": 1, "0 5": 1, "0 5 \t": 1,
             "0 1 abcdefghijklmnopq": 1, "0 99999999999999999999 zero": 1, "0 1 zero\n0x5 1 zero": 2,
             "# ok\n\n2 3": 3, "0 10zero": 1}
    for text, line in cases.items():
        for verb in ("create m", "load alpha"):
            r = fx.run(f"dmsetup {verb} --table \"$T\"", STATE, env={"T": text})
            check(r.rc == 1 and f"Invalid format on line {line} of table (--table)" in r.err and not r.reqs,
                  f"{verb.split()[0]} rejects {text!r} on line {line}", r.err + str(r.cmds()))
    r = fx.run("dmsetup load alpha --table '# nothing'", STATE)
    check(r.rc == 1 and r.cmds() == ["reload"] and r.reqs[0].target_count == 0,
          "an empty table is sent and the kernel refuses it", r.cmds())
    r = fx.run("dmsetup load alpha", STATE, stdin="")
    check(r.rc == 1 and r.cmds() == ["reload"], "empty stdin table refused by kernel")
    nul = os.path.join(fx.tmp, "nul.table")
    with open(nul, "w") as f:
        f.write("0 1 zero\0\n")
    r = fx.run(f"dmsetup load alpha {nul}", STATE)
    check(r.rc == 1 and "NUL byte" in r.err and not r.reqs, "NUL in table file rejected", r.err)
    r = fx.run("dmsetup create " + "n" * 128 + " -n", STATE)
    check(r.rc == 1 and "too long" in r.err and not r.reqs, "128-byte name rejected, not truncated", r.err)
    r = fx.run("dmsetup create ok -n -u " + "u" * 129, STATE)
    check(r.rc == 1 and "too long" in r.err and not r.reqs, "129-byte uuid rejected", r.err)
    r = fx.run("dmsetup create " + "n" * 127 + " -n", STATE)
    check(r.rc == 0 and r.reqs[0].name == "n" * 127, "127-byte name is the maximum", r.err)


def t_load_cycle(fx):
    print("== load / reload / clear / inactive tables ==")
    r = fx.run("dmsetup reload alpha --table '0 200 zero'; dmsetup info alpha; "
               "dmsetup table --inactive alpha; dmsetup table alpha; dmsetup resume alpha; dmsetup table alpha",
               STATE)
    check(r.rc == 0, "reload cycle exit", r.err)
    check(r.cmds() == ["reload", "info", "table", "table", "resume", "table"], "reload cycle requests", r.cmds())
    check("Tables present:    LIVE & INACTIVE" in r.out, "info reports both tables", r.out)
    check(r.reqs[2].flags & F_QUERY_INACTIVE and r.reqs[2].flags & F_TABLE, "--inactive sets the query flag")
    check(r.out.endswith("0 200 zero \n0 100 linear 8:0 2048\n100 50 linear 8:16 0\n0 200 zero \n"),
          "inactive, old live, swapped live", r.out)
    r = fx.run("dmsetup load alpha --table '0 1 zero'; dmsetup clear alpha; dmsetup info alpha", STATE)
    check(r.rc == 0 and r.cmds() == ["reload", "clear", "info"] and "Tables present:    LIVE\n" in r.out,
          "clear drops the inactive table", r.out)
    r = fx.run("dmsetup load -u UUID-BETA --table '0 3 zero'", STATE)
    check(r.rc == 0 and r.reqs[0].uuid == "UUID-BETA" and r.reqs[0].name == "", "load by -u sends only uuid")
    r = fx.run("dmsetup remove alpha -u UUID-BETA; dmsetup info alpha -u UUID-BETA", STATE)
    check(r.rc == 1 and not r.reqs and r.err.count("not both") == 2, "name list and -u together refused")
    with open(os.path.join(fx.tmp, "u.table"), "w") as f:
        f.write("0 4 zero\n")
    r = fx.run(f"dmsetup load -u UUID-BETA {fx.tmp}/u.table", STATE)
    check(r.rc == 0 and r.reqs[0].uuid == "UUID-BETA" and r.reqs[0].target_count == 1,
          "load -u UUID takes the table file positionally", r.err)
    r = fx.run("dmsetup load alpha", STATE, tty=True)
    check(r.rc == 1 and "requires a table" in r.err and not r.reqs,
          "load with a terminal stdin and no table refused before ioctl", r.err)
    r = fx.run("dmsetup create ttydev; dmsetup info ttydev", STATE, tty=True)
    check(r.rc == 0 and r.cmds() == ["create", "info"] and "Tables present:    None" in r.out,
          "create with a terminal stdin creates without a table", r.cmds())

    print("== large table: buffer sized to the payload ==")
    lines = [(i * 8, 8, "linear", f"8:{i % 16} {i * 8}") for i in range(600)]
    text = "\n".join(f"{a} {b} {c} {d}" for a, b, c, d in lines)
    r = fx.run("dmsetup create big --table \"$T\"; dmsetup table big", STATE, env={"T": text})
    check(r.rc == 0 and r.reqs[1].payload == expected_load_payload(lines), "600-target payload exact", r.err)
    want = "".join(f"{a} {b} {c} {d}\n" for a, b, c, d in lines)
    check(r.out == want, "600-target table read back (status buffer grew)", r.out[-200:])
    need, want_sizes = HDR.size + len(expected_load_payload(lines)), [16384]
    while want_sizes[-1] < need:
        want_sizes.append(want_sizes[-1] * 2)
    sizes = [q.data_size for q in r.reqs if q.cmd == "table"]
    check(sizes == want_sizes and len(sizes) > 1, "table status doubled until the reply fit",
          (sizes, need))


def t_suspend_remove(fx):
    print("== suspend / resume / remove: flags and multi-device errors ==")
    r = fx.run("dmsetup suspend --noflush --nolockfs alpha gamma; dmsetup info alpha", STATE)
    check(r.rc == 0 and all(q.flags == F_SUSPEND | F_NOFLUSH | F_SKIP_LOCKFS for q in r.reqs[:2]),
          "suspend flags", [q.flags for q in r.reqs])
    check("State:             SUSPENDED" in r.out, "info shows SUSPENDED")
    r = fx.run("dmsetup suspend alpha beta gamma; rc=$?; dmsetup info alpha gamma; exit $rc", STATE,
               env={"DMSFIX_FAIL": "suspend@beta=1"})
    check(r.rc == 1 and r.cmds()[:3] == ["suspend"] * 3, "multi-device suspend continues past a failure")
    check("device-mapper: suspend ioctl on beta  failed: Operation not permitted" in r.err, "EPERM wording", r.err)
    check(r.out.count("SUSPENDED") == 2 and r.err.count("Command failed.") == 1, "a and c suspended", r.out)
    r = fx.run("dmsetup remove gamma beta nope alpha", STATE)
    check(r.rc == 1 and r.cmds() == ["remove"] * 4, "remove tries every device")
    check("remove ioctl on beta  failed: Device or resource busy" in r.err
          and "remove ioctl on nope  failed: No such device or address" in r.err, "remove errors", r.err)
    check(r.stats["devices"] == 1 and "dev beta" in r.stats["text"], "only the open device remains")
    r = fx.run("dmsetup remove --deferred beta; dmsetup info beta", STATE)
    check(r.rc == 0 and r.reqs[0].flags == F_DEFERRED and "(DEFERRED REMOVE)" in r.out, "deferred remove", r.out)
    r = fx.run("dmsetup remove -f alpha", STATE)
    check(r.rc == 0 and r.cmds() == ["table", "reload", "resume", "remove"], "remove --force wipes first",
          r.cmds())
    check(r.reqs[1].payload == expected_load_payload([(0, 150, "error", "")]), "force wipe loads one error target")
    r = fx.run("dmsetup remove -f gamma", STATE)
    check(r.rc == 0 and r.err == "" and r.cmds() == ["table", "remove"], "remove -f of a table-less device",
          r.err)
    r = fx.run("dmsetup remove -u UUID-BETA", STATE)
    check(r.reqs[0].uuid == "UUID-BETA" and r.reqs[0].name == "" and r.rc == 1, "remove by uuid")
    r = fx.run("dmsetup remove", STATE)
    check(r.rc == 1 and not r.reqs and "requires a device" in r.err, "remove without a device")
    r = fx.run("dmsetup resume alpha", STATE, env={"DMSFIX_FAIL": "resume=6"})
    check(r.rc == 1 and "resume ioctl on alpha  failed: No such device or address" in r.err, "resume error")

    print("== remove_all ==")
    r = fx.run("dmsetup remove_all; dmsetup ls", STATE)
    q = r.reqs[0]
    check(r.rc == 0 and q.cmd == "remove_all" and q.name == "" and q.uuid == "" and q.payload == b"",
          "remove_all request is an empty header")
    check(r.out == "beta\t(253:1)\n", "open device survives remove_all", r.out)
    r = fx.run("dmsetup remove_all --force", STATE)
    check(r.rc == 0 and r.err == "" and r.cmds() == ["names", "table", "reload", "resume", "table", "reload", "resume", "table", "remove_all"],
          "remove_all --force wipes each device then removes", r.cmds())
    r = fx.run("dmsetup remove_all alpha", STATE)
    check(r.rc == 1 and not r.reqs, "remove_all refuses device arguments")

    print("== wipe_table ==")
    r = fx.run("dmsetup wipe_table alpha; dmsetup table alpha", STATE)
    check(r.rc == 0 and r.cmds()[:3] == ["table", "reload", "resume"] and r.out == "0 150 error \n",
          "wipe_table replaces the live table with error", r.out)
    r = fx.run("dmsetup wipe_table gamma", STATE)
    check(r.rc == 1 and "no live table" in r.err and r.cmds() == ["table"], "wipe_table needs a live table")
    r = fx.run("dmsetup wipe_table alpha", STATE, env={"DMSFIX_FAIL": "resume@alpha=16"})
    check(r.rc == 1 and r.cmds() == ["table", "reload", "resume", "clear"], "failed wipe resume clears", r.cmds())


def t_rename(fx):
    print("== rename ==")
    r = fx.run("dmsetup rename alpha omega; dmsetup ls", STATE)
    q = r.reqs[0]
    check(r.rc == 0 and q.name == "alpha" and q.flags == 0 and q.payload == b"omega\0", "rename payload")
    check("omega\t(253:0)" in r.out, "renamed device listed", r.out)
    r = fx.run("dmsetup rename gamma --setuuid NEWU; dmsetup info gamma", STATE)
    check(r.rc == 0 and r.reqs[0].flags == F_UUID and r.reqs[0].payload == b"NEWU\0", "setuuid payload/flag")
    check("UUID:              NEWU" in r.out, "uuid set", r.out)
    r = fx.run("dmsetup rename beta --setuuid X", STATE)
    check(r.rc == 1 and "rename ioctl on beta  failed: Invalid argument" in r.err, "uuid cannot change twice")
    r = fx.run("dmsetup rename alpha beta", STATE)
    check(r.rc == 1 and "Device or resource busy" in r.err, "rename onto an existing name")
    for bad in ("a/b", "x" * 128, "''"):
        r = fx.run(f"dmsetup rename alpha {bad}", STATE)
        check(r.rc == 1 and not r.reqs, f"rename to {bad[:12]!r} refused before ioctl", r.err)
    r = fx.run("dmsetup rename alpha", STATE)
    check(r.rc == 1 and not r.reqs, "rename needs a new name")
    r = fx.run("dmsetup rename -u UUID-BETA b2; dmsetup ls", STATE)
    q = r.reqs[0]
    check(r.rc == 0 and q.uuid == "UUID-BETA" and q.name == "" and q.payload == b"b2\0"
          and "b2\t(253:1)" in r.out, "rename -u UUID NEWNAME", r.err)


def t_message(fx):
    print("== message ==")
    r = fx.run("dmsetup message alpha 120 ping", STATE)
    q = r.reqs[0]
    sector, = struct.unpack_from("<Q", q.payload)
    check(r.rc == 0 and sector == 120 and q.payload[8:].rstrip(b"\0") == b"ping", "message payload")
    check(len(q.payload) % 8 == 0 and q.data_size == 16384, "message buffer is the retryable 16 KiB")
    check(r.out == "pong sector=120\n", "message response printed", r.out)
    r = fx.run("dmsetup message alpha 0 silent", STATE)
    check(r.rc == 0 and r.out == "", "no DATA_OUT, no output")
    r = fx.run("dmsetup message alpha 0 dump 40000", STATE)
    check(r.rc == 0 and len(r.out) == 40001 and r.out.startswith("abcdefghijklmnopqrstuvwxyza"),
          "40000-byte reply after growth", len(r.out))
    check([q.data_size for q in r.reqs] == [16384, 32768, 65536], "message retried 16->32->64 KiB",
          [q.data_size for q in r.reqs])
    check(all(q.payload[8:].rstrip(b"\0") == b"dump 40000" for q in r.reqs), "payload rebuilt on every retry")
    r = fx.run("dmsetup message -u UUID-BETA 3 ping", STATE)
    check(r.rc == 0 and r.reqs[0].uuid == "UUID-BETA" and r.out == "pong sector=3\n", "message -u UUID", r.err)
    r = fx.run("dmsetup message alpha 999 ping", STATE)
    check(r.rc == 1 and "message ioctl on alpha  failed: Invalid argument" in r.err, "sector outside table")
    for args in ("alpha x ping", "alpha -1 ping", "alpha 5", "alpha"):
        r = fx.run(f"dmsetup message {args}", STATE)
        check(r.rc == 1 and not r.reqs, f"message {args!r} refused before ioctl", r.err)


def t_queries(fx):
    print("== queries ==")
    r = fx.run("dmsetup ls; dmsetup info alpha; dmsetup info -u UUID-BETA; dmsetup deps alpha; dmsetup deps;"
               "dmsetup status beta; dmsetup table; dmsetup targets", STATE)
    check(r.rc == 0, "query batch", r.err)
    want = ("alpha\t(253:0)\nbeta\t(253:1)\ngamma\t(253:2)\n"
            "Name:              alpha\nState:             ACTIVE\nTables present:    LIVE\nOpen count:        0\n"
            "Event number:      0\nMajor, minor:      253, 0\nNumber of targets: 2\n\n"
            "Name:              beta\nState:             ACTIVE\nTables present:    LIVE\nOpen count:        1\n"
            "Event number:      0\nMajor, minor:      253, 1\nNumber of targets: 1\nUUID:              UUID-BETA\n\n"
            "2 dependencies\t: (8, 0) (8, 16)\n"
            "alpha: 2 dependencies\t: (8, 0) (8, 16)\nbeta: 0 dependencies\t:\ngamma: 0 dependencies\t:\n"
            "0 10 zero \n"
            "alpha: 0 100 linear 8:0 2048\nalpha: 100 50 linear 8:16 0\nbeta: 0 10 zero \ngamma: \n"
            "linear           v1.5.0\nzero             v1.2.0\nerror            v1.7.0\nstriped          v1.7.0\n"
            "crypt            v1.27.0\n")
    check(r.out == want, "query output", f"got:\n{r.out}")
    st = [q for q in r.reqs if q.cmd in ("status", "table")]
    check(st[0].cmd == "status" and not st[0].flags & F_TABLE and st[1].flags & F_TABLE, "status vs table flag")
    r = fx.run("dmsetup table --target zero; dmsetup ls --target linear; dmsetup status --target=linear alpha",
               STATE)
    check(r.out == "beta: 0 10 zero \nalpha\t(253:0)\n0 100 linear \n100 50 linear \n", "--target filters", r.out)
    r = fx.run("dmsetup info nope; dmsetup table nope; dmsetup deps nope", STATE)
    check(r.rc == 1 and r.err == "Device does not exist.\nCommand failed.\n" * 3, "missing device wording",
          r.err)
    r = fx.run("dmsetup table nope", STATE)
    check(r.rc == 1 and r.err == "Device does not exist.\nCommand failed.\n", "missing device wording (table)",
          r.err)
    r = fx.run("dmsetup ls; dmsetup table; dmsetup info", "")
    check(r.rc == 0 and r.out == "No devices found\n" * 3, "empty mapper", r.out)
    key = "a" * 64
    crypt = f"dev c - 9 0 0\nlive 0 8 crypt aes-xts-plain64 {key} 0 8:0 4096\n" \
            "dev k - 10 0 0\nlive 0 8 crypt aes-xts-plain64 :64:logon:cryptsetup:x 0 8:0 0\n"
    r = fx.run("dmsetup table c; dmsetup table --showkeys c; dmsetup table k", crypt)
    check(r.out == f"0 8 crypt aes-xts-plain64 {'0' * 64} 0 8:0 4096\n0 8 crypt aes-xts-plain64 {key} 0 8:0 4096\n"
          "0 8 crypt aes-xts-plain64 :64:logon:cryptsetup:x 0 8:0 0\n", "crypt keys hidden without --showkeys",
          r.out)
    r = fx.run("dmsetup version; dmsetup --version", STATE)
    check(r.rc == 0 and r.out.count("Driver version:    4.48.0") == 2, "version via DM_VERSION")
    r = fx.run("dmsetup version", STATE, env={"DMSFIX_OPEN_ERRNO": "2"})
    check(r.rc == 0 and "Driver version:    unavailable" in r.out, "version without a control node")

    print("== buffer growth for many devices ==")
    r = fx.run("dmsetup ls; dmsetup info bulk02999", "bulk 3000\n")
    names = [l.split("\t")[0] for l in r.out.splitlines()]
    check(r.rc == 0 and names[:3000] == [f"bulk{i:05d}" for i in range(3000)], "3000 names listed", r.err)
    sizes = [q.data_size for q in r.reqs if q.cmd == "names"]
    check(sizes == [16384, 32768, 65536, 131072], "names retried up to 128 KiB", sizes)
    check(all(q.payload == b"\0" * (q.data_size - HDR.size) for q in r.reqs if q.cmd == "names"),
          "retry buffers start zeroed")
    r = fx.run("dmsetup deps", "bulk 200\n")
    check(r.rc == 0 and r.out.count("1 dependencies\t: (7, ") == 200, "deps for 200 devices")


def t_malformed_responses(fx):
    print("== malformed kernel responses are bounded ==")
    for kind, script in (("names", "dmsetup ls"), ("table", "dmsetup table alpha"),
                         ("status", "dmsetup table alpha"), ("deps", "dmsetup deps alpha"),
                         ("versions", "dmsetup targets"), ("message", "dmsetup message alpha 0 ping"),
                         ("header", "dmsetup info alpha"),
                         ("header-strings", "dmsetup info alpha"),
                         ("unaligned", "dmsetup ls")):
        r = fx.run(script, STATE, env={"DMSFIX_MALFORM": kind})
        check(r.rc == 1 and "malformed" in r.err and r.rc != 0, f"malformed {kind} response rejected",
              f"rc={r.rc} err={r.err!r} out={r.out[:80]!r}")
        balanced(r, f"malformed {kind}")


def t_permissions(fx):
    print("== permission and open failures ==")
    for script in ("dmsetup info alpha", "dmsetup info -u UUID-BETA", "dmsetup ls --target zero"):
        r = fx.run(script, STATE, env={"DMSFIX_OPEN_ERRNO": "13", "DMSFIX_OPEN_ONCE": "1"})
        check(r.rc == 1 and "Permission denied" in r.err,
              f"{script}: original open failure diagnosed", r.err)
        check(r.stats.get("opens") == 1 and r.stats.get("open_now") == 0,
              f"{script}: diagnostic never reopens control", str(r.stats))
    r = fx.run("dmsetup table alpha", STATE, env={"DMSFIX_OPEN_ERRNO": "13"})
    check(r.rc == 1 and "/dev/mapper/control: open failed: Permission denied" in r.err, "EACCES on open", r.err)
    r = fx.run("dmsetup remove alpha", STATE, env={"DMSFIX_OPEN_ERRNO": "13"})
    check(r.rc == 1 and "Permission denied" in r.err, "mutation with EACCES on open")
    r = fx.run("dmsetup info alpha", STATE, env={"DMSFIX_OPEN_ERRNO": "13"})
    check(r.rc == 1 and "open failed" in r.err, "named info needs the control node")
    r = fx.run("dmsetup ls", STATE, env={"DMSFIX_OPEN_ERRNO": "13"})
    check(r.rc == 0, "ls falls back to sysfs when the control node is unavailable")
    r = fx.run("dmsetup table alpha; dmsetup create z -n; dmsetup ls", STATE, env={"DMSFIX_FAIL": "*=1"})
    check(r.rc == 1 and r.err.count("Operation not permitted") == 3, "EPERM from every ioctl", r.err)
    balanced(r, "EPERM")


def t_shell(fx):
    print("== one shell: repeated calls, fd hygiene, output errors, usage ==")
    script = ('before=(/proc/$$/fd/*); '
              'for i in {1..40}; do dmsetup create r$i --table "0 $i zero" || exit 9; dmsetup suspend r$i; '
              'dmsetup resume r$i; dmsetup message r$i 0 ping >/dev/null; dmsetup rename r$i s$i; '
              'dmsetup remove s$i x$i 2>/dev/null; done; dmsetup info nope 2>/dev/null; '
              'after=(/proc/$$/fd/*); [[ ${before[*]} == "${after[*]}" ]] && echo fds-same; type -t dmsetup')
    r = fx.run(script, STATE)
    check(r.rc == 0 and r.out == "fds-same\nbuiltin\n", "40 lifecycles in one shell", r.out + r.err)
    check(r.stats["devices"] == 3 and r.stats["ioctls"] == 40 * 9 + 1, "fixture back to its start state",
          r.stats)
    balanced(r, "repeated")
    r = fx.run("dmsetup ls > /dev/full; echo rc=$?; dmsetup table >/dev/full; echo rc=$?", STATE)
    check(r.out == "rc=1\nrc=1\n" and r.err.count("write error") == 2, "stdout write errors reported", r.err)
    r = fx.run("dmsetup", STATE)
    check(r.rc == 1 and "Usage:" in r.err, "no arguments")
    r = fx.run("dmsetup help; dmsetup -h", STATE)
    check(r.rc == 0 and r.err.count("Usage:") == 2, "help")
    r = fx.run("dmsetup frobnicate", STATE)
    check(r.rc == 1 and "Unknown command." in r.err, "unknown command")
    r = fx.run("dmsetup --bogus ls", STATE)
    check(r.rc == 1 and "unrecognized option '--bogus'" in r.err and not r.reqs, "unknown option")
    r = fx.run("dmsetup info -u", STATE)
    check(r.rc == 1 and "requires an argument" in r.err, "missing option value")
    r = fx.run("dmsetup create m -n -j 9999999", STATE)
    check(r.rc == 1 and "invalid major" in r.err and not r.reqs, "out-of-range major")
    r = fx.run("dmsetup -- table alpha", STATE)
    check(r.rc == 0 and "0 100 linear" in r.out, "-- ends options")


def t_kernel_abi(fx):
    print("== kernel-sized replies (header tail padding is not copied) ==")
    for script, cmds in (
        ("dmsetup create fresh --table '0 8 zero'", ["create", "reload", "resume"]),
        ("dmsetup info alpha", ["info"]),
        ("dmsetup suspend alpha", ["suspend"]),
        ("dmsetup resume alpha", ["resume"]),
        ("dmsetup clear alpha", ["clear"]),
        ("dmsetup rename alpha renamed", ["rename"]),
        ("dmsetup remove alpha", ["remove"]),
        ("dmsetup message alpha 0 silent", ["message"]),
        ("dmsetup table gamma", ["table"]),
        ("dmsetup deps gamma", ["deps"]),
    ):
        r = fx.run(script, STATE)
        check(r.rc == 0 and r.err == "" and r.cmds() == cmds, script + ": valid kernel reply", r.err)
        check(all(int(x["data_size"]) == 305 for x in r.results),
              script + ": fixture copies offsetof(dm_ioctl, data), not sizeof", r.results)
        balanced(r, script)
    r = fx.run("dmsetup remove_all", STATE)
    check(r.rc == 0 and int(r.results[0]["data_size"]) == 0,
          "remove_all succeeds with no copy-back", r.err)
    r = fx.run("dmsetup ls", "")
    check(r.rc == 0 and r.out == "No devices found\n" and int(r.results[0]["data_size"]) == HDR.size,
          "empty names list has exactly zero payload", r.results)
    r = fx.run("dmsetup table alpha", STATE)
    # Two records: first is 56 padded bytes; last is 40 + len('8:16 0') + NUL.
    check(r.rc == 0 and int(r.results[0]["data_size"]) == HDR.size + 56 + 47,
          "last status record excludes alignment padding", r.results)
    r = fx.run("dmsetup deps --inactive alpha; dmsetup table --inactive alpha", STATE)
    check(r.rc == 0 and r.out == "0 dependencies\t:\n",
          "no inactive table accepts a header-only reply despite a live table", r.out + r.err)


def t_record_boundaries(fx):
    print("== record boundaries, wipe geometry and bounded retry ==")
    cases = [(x, "dmsetup ls") for x in ("names-short", "names-cross", "names-next-end")]
    cases += [(x, "dmsetup targets") for x in
              ("versions-short", "versions-cross", "versions-next-end", "versions-short-next")]
    cases += [(x, f"dmsetup {verb} alpha") for x in
              ("table-cross-params", "table-overlap", "table-type")
              for verb in ("table", "status", "wipe_table")]
    cases += [(x, "dmsetup wipe_table alpha") for x in ("table-gap", "table-overflow", "status")]
    for fault, script in cases:
        r = fx.run(script, STATE, env={"DMSFIX_MALFORM": fault})
        check(r.rc == 1 and "malformed" in r.err, f"{script}: rejects {fault}", r.out + r.err)
        if "wipe_table" in script:
            check(r.cmds() == ["table"], f"{fault}: malformed live table never reaches TABLE_LOAD", r.cmds())
        balanced(r, script + "/" + fault)
    r = fx.run("dmsetup ls", STATE, env={"DMSFIX_FULL": "names", "DMSFIX_LOG": ""})
    check(r.rc == 1 and "response exceeds 67108864 bytes" in r.err,
          "permanently full response stops at 64 MiB", r.err)
    check(r.stats.get("ioctls") == 13, "growth is bounded to 13 attempts (16 KiB through 64 MiB)", r.stats)
    balanced(r, "full response")


def t_failure_recovery(fx):
    print("== cleanup failures, multi-device continuation and shell recovery ==")
    r = fx.run("dmsetup create stranded --table '0 5 zero'", STATE,
               env={"DMSFIX_FAIL": "resume@stranded=5,remove@stranded=16"})
    check(r.rc == 1 and r.cmds() == ["create", "reload", "resume", "remove"],
          "rollback attempted after failed activation even when removal fails", r.cmds())
    check("Input/output error" in r.err and "Device or resource busy" in r.err
          and "dev stranded " in r.stats["text"],
          "both errors reported and fixture exposes remaining device", r.err)
    balanced(r, "failed rollback")
    state = STATE + "live 0 20 zero\n"
    for verb, failed_cmd in (("resume", "resume"), ("clear", "clear"), ("wipe_table", "table")):
        r = fx.run(f"dmsetup {verb} alpha beta gamma", state,
                   env={"DMSFIX_FAIL": f"{failed_cmd}@beta=1"})
        check(r.rc == 1 and "Operation not permitted" in r.err,
              verb + ": failure is aggregated", r.err)
        check([q.name for q in r.reqs if q.cmd == failed_cmd] == ["alpha", "beta", "gamma"],
              verb + ": later devices still attempted", r.cmds())
        balanced(r, verb + " multi-device failure")
    r = fx.run("dmsetup info alpha >/dev/full; [[ $? == 1 ]] || exit 9; "
               "dmsetup message alpha 0 ping >/dev/full; [[ $? == 1 ]] || exit 9; "
               "dmsetup message alpha 0 ping", STATE)
    check(r.rc == 0 and r.out == "pong sector=0\n" and r.err.count("write error") == 2,
          "stdout failures do not poison the next invocation", r.out + r.err)
    balanced(r, "output recovery")
    oversized = os.path.join(fx.tmp, "oversized.table")
    with open(oversized, "wb") as f:
        f.truncate(16 << 20)
    r = fx.run(f"dmsetup load alpha {oversized}", STATE)
    check(r.rc == 1 and "exceeds 16777216 bytes" in r.err and not r.reqs,
          "oversized input refused before TABLE_LOAD", r.err)
    balanced(r, "oversized input")


def main():
    bash = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "out", "bash"))
    with tempfile.TemporaryDirectory(prefix="dmsfix.") as tmp:
        so = os.environ.get("DMSETUP_FIXTURE_SO")
        if not so:
            so = os.path.join(tmp, "dmsfix.so")
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-fPIC", "-shared",
                            "-o", so, os.path.join(HERE, "opus-dmsetup-fixture.c"), "-ldl"], check=True)
        fx = Fixture(bash, os.path.abspath(so), tmp)
        for t in (t_policy, t_create, t_malformed_tables, t_load_cycle, t_suspend_remove, t_rename,
                  t_message, t_queries, t_malformed_responses, t_permissions, t_shell,
                  t_kernel_abi, t_record_boundaries, t_failure_recovery):
            try:
                t(fx)
            except Exception as exc:   # a section that cannot even decode its run fails as a whole
                check(False, f"{t.__name__} aborted: {type(exc).__name__}: {exc}")
    print(f"dmsetup ioctl fixture: {checks - len(failures)}/{checks} checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
