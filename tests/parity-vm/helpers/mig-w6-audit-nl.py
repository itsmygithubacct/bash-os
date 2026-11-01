#!/usr/bin/python3 -I
"""Independent raw-netlink model of the kernel audit control interface.

Used as the oracle for the audit builtin's root fixtures: it talks to
NETLINK_AUDIT with struct.pack/unpack only (no shared code with audit.c),
so what it reads back is the kernel's own record of the state the builtin
changed.  Verbs (all print one line of JSON or text on stdout):

  status                      AUDIT_GET as JSON
  rules                       AUDIT_LIST_RULES decoded as JSON (list)
  snapshot FILE               save status + raw rule data to FILE
  restore FILE                delete current rules, re-add saved rules, put
                              back enabled/rate_limit/backlog_limit/failure
  flush                       delete every rule
  set KEY=VAL ...             AUDIT_SET of enabled|failure|rate_limit|
                              backlog_limit (AUDIT_STATUS_* mask bits)
  add SPEC | del SPEC         AUDIT_ADD_RULE / AUDIT_DEL_RULE; SPEC is JSON
                              {"flags":N,"action":N,"syscalls":[nr..]|"all",
                               "fields":[[type,op,val]..],"key":"str"}
  matches FILE                print 1 if current enabled/failure/rate_limit/
                              backlog_limit/pid and the raw rule list equal
                              the snapshot in FILE, else 0
  waitpid PID TIMEOUT         poll AUDIT_GET until pid==PID; print elapsed
                              seconds or "timeout"
  waitpid0 TIMEOUT            poll until pid==0

A kernel refusal prints "error=<errno name>" and exits 3.
"""
import errno
import json
import os
import socket
import struct
import sys
import time

NETLINK_AUDIT = 9
AUDIT_GET, AUDIT_SET = 1000, 1001
AUDIT_ADD_RULE, AUDIT_DEL_RULE, AUDIT_LIST_RULES = 1011, 1012, 1013
NLM_F_REQUEST, NLM_F_ACK = 1, 4
NLMSG_ERROR, NLMSG_DONE = 2, 3
ST_ENABLED, ST_FAILURE, ST_PID, ST_RATE, ST_BACKLOG = 1, 2, 4, 8, 0x10
MASKS = {"enabled": ST_ENABLED, "failure": ST_FAILURE, "rate_limit": ST_RATE,
         "backlog_limit": ST_BACKLOG}
RULE_HDR = "<III"
RULE_ARR = "<64I64I64I64I"
FILTERKEY = 210


class Refused(Exception):
    def __init__(self, err):
        self.err = err


def sock():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
    s.bind((0, 0))
    s.settimeout(5)
    return s


_seq = [int(time.time()) & 0xffff]


def send(s, typ, flags, payload):
    _seq[0] += 1
    msg = struct.pack("<IHHII", 16 + len(payload), typ, NLM_F_REQUEST | flags, _seq[0], 0) + payload
    s.send(msg + b"\0" * ((-len(msg)) % 4))
    return _seq[0]


def messages(s):
    data = s.recv(65536)
    off = 0
    while off + 16 <= len(data):
        ln, typ, fl, sq, pid = struct.unpack_from("<IHHII", data, off)
        yield typ, sq, data[off + 16:off + ln]
        off += (ln + 3) & ~3


def ack(s, seq):
    while True:
        for typ, sq, body in messages(s):
            if typ == NLMSG_ERROR and sq == seq:
                e = -struct.unpack_from("<i", body)[0]
                if e:
                    raise Refused(e)
                return


def status(s=None):
    own = s is None
    s = s or sock()
    seq = send(s, AUDIT_GET, 0, b"")
    while True:
        for typ, sq, body in messages(s):
            if typ == NLMSG_ERROR and sq == seq:
                e = -struct.unpack_from("<i", body)[0]
                if e:
                    raise Refused(e)
            if typ == AUDIT_GET:
                v = struct.unpack_from("<8I", body)
                if own:
                    s.close()
                return dict(zip(("mask", "enabled", "failure", "pid", "rate_limit",
                                 "backlog_limit", "lost", "backlog"), v))


def set_status(**kw):
    s = sock()
    mask, vals = 0, dict(enabled=0, failure=0, pid=0, rate_limit=0, backlog_limit=0)
    for k, v in kw.items():
        mask |= MASKS[k]
        vals[k] = v
    body = struct.pack("<8I", mask, vals["enabled"], vals["failure"], vals["pid"],
                       vals["rate_limit"], vals["backlog_limit"], 0, 0)
    ack(s, send(s, AUDIT_SET, NLM_F_ACK, body))
    s.close()


def raw_rules():
    s = sock()
    seq = send(s, AUDIT_LIST_RULES, 0x300, b"")
    out = []
    while True:
        done = False
        for typ, sq, body in messages(s):
            if typ == NLMSG_DONE:
                done = True
                break
            if typ == NLMSG_ERROR:
                e = -struct.unpack_from("<i", body)[0]
                if e:
                    raise Refused(e)
                done = True
                break
            if typ == AUDIT_LIST_RULES:
                out.append(body)
        if done:
            break
    s.close()
    return out


def decode(body):
    flags, action, count = struct.unpack_from(RULE_HDR, body)
    arr = struct.unpack_from(RULE_ARR, body, 12)
    mask, fields, values, fflags = arr[0:64], arr[64:128], arr[128:192], arr[192:256]
    buflen = struct.unpack_from("<I", body, 12 + 4 * 256)[0]
    buf = body[12 + 4 * 256 + 4:12 + 4 * 256 + 4 + buflen]
    syscalls = [i for i in range(64 * 32) if mask[i // 32] >> (i % 32) & 1]
    out, off = [], 0
    for i in range(count):
        if fields[i] == FILTERKEY:
            out.append([fields[i], fflags[i], buf[off:off + values[i]].decode()])
            off += values[i]
        else:
            out.append([fields[i], fflags[i], values[i]])
    return {"flags": flags, "action": action,
            "syscalls": "all" if len(syscalls) == 64 * 32 else syscalls, "fields": out}


def encode(spec):
    mask = [0] * 64
    if spec["syscalls"] == "all":
        mask = [0xffffffff] * 64
    else:
        for nr in spec["syscalls"]:
            mask[nr // 32] |= 1 << (nr % 32)
    fields, values, fflags, buf = [0] * 64, [0] * 64, [0] * 64, b""
    items = list(spec["fields"])
    if spec.get("key"):
        items.append([FILTERKEY, 0x40000000, spec["key"]])
    for i, (t, op, v) in enumerate(items):
        fields[i], fflags[i] = t, op
        if t == FILTERKEY:
            values[i] = len(v)
            buf += v.encode()
        else:
            values[i] = v
    return (struct.pack(RULE_HDR, spec["flags"], spec["action"], len(items))
            + struct.pack(RULE_ARR, *mask, *fields, *values, *fflags)
            + struct.pack("<I", len(buf)) + buf)


def change(typ, body):
    s = sock()
    try:
        ack(s, send(s, typ, NLM_F_ACK, body))
    finally:
        s.close()


def main(argv):
    verb = argv[1] if len(argv) > 1 else ""
    try:
        if verb == "status":
            print(json.dumps(status(), sort_keys=True))
        elif verb == "rules":
            print(json.dumps([decode(b) for b in raw_rules()], sort_keys=True))
        elif verb == "snapshot":
            snap = {"status": status(), "rules": [b.hex() for b in raw_rules()]}
            json.dump(snap, open(argv[2], "w"))
            print(json.dumps({"enabled": snap["status"]["enabled"], "rules": len(snap["rules"])}))
        elif verb == "matches":
            snap = json.load(open(argv[2]))
            cur, old = status(), snap["status"]
            same = all(cur[k] == old[k] for k in ("enabled", "failure", "rate_limit", "backlog_limit"))
            print(1 if same and cur["pid"] == 0 and [b.hex() for b in raw_rules()] == snap["rules"] else 0)
        elif verb in ("flush", "restore"):
            for b in raw_rules():
                change(AUDIT_DEL_RULE, b)
            if verb == "restore":
                snap = json.load(open(argv[2]))
                for h in snap["rules"]:
                    change(AUDIT_ADD_RULE, bytes.fromhex(h))
                st = snap["status"]
                set_status(failure=st["failure"], rate_limit=st["rate_limit"],
                           backlog_limit=st["backlog_limit"], enabled=st["enabled"])
            print("ok")
        elif verb == "set":
            kw = {a.split("=")[0]: int(a.split("=")[1]) for a in argv[2:]}
            set_status(**kw)
            print("ok")
        elif verb in ("add", "del"):
            change(AUDIT_ADD_RULE if verb == "add" else AUDIT_DEL_RULE, encode(json.loads(argv[2])))
            print("ok")
        elif verb in ("waitpid", "waitpid0"):
            want = int(argv[2]) if verb == "waitpid" else 0
            limit = float(argv[-1])
            t0 = time.time()
            while time.time() - t0 < limit:
                if status()["pid"] == want:
                    print("%.2f" % (time.time() - t0))
                    return 0
                time.sleep(0.05)
            print("timeout")
            return 1
        else:
            print(__doc__)
            return 2
    except Refused as r:
        print("error=%s" % errno.errorcode.get(r.err, r.err))
        return 3
    except PermissionError:
        print("error=EPERM")
        return 3
    except OSError as e:
        print("error=%s" % errno.errorcode.get(e.errno, e.errno))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
