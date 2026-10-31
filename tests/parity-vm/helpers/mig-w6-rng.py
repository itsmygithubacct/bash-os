#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only fixture model for rngseed cases (no candidate involvement).

Seeds are deterministic (shake_256 of a fixed label), so expected bytes are
independent of the candidate. A seccomp-notify JSONL trace from
system-sequence.py is summarized into the documented operation order.

  gen NAME N [MODE]     write NAME with the N deterministic bytes and MODE (octal)
  state NAME [N]        absent | present size= mode= nlink= content=original|other
  report PREFIX FILE N ERR...  print rc/stderr probes/fds/file state/temps/copies and the trace
  payload NAME N        compare the logged RNDADDENTROPY buffer with the model
"""
import hashlib, json, os, stat, struct, sys

RNDADD = 0x40085203
SYNTH = {"continue": "real"}


def seed_bytes(n):
    return hashlib.shake_256(b"bash-os-w6-rngseed-%d" % n).digest(n)


def state(name="seed", n=None):
    try:
        st = os.lstat(name)
    except FileNotFoundError:
        return "absent"
    if not stat.S_ISREG(st.st_mode):
        return "present kind=%s" % ("dir" if stat.S_ISDIR(st.st_mode) else "link" if stat.S_ISLNK(st.st_mode)
                                     else "fifo" if stat.S_ISFIFO(st.st_mode) else "other")
    data = open(name, "rb").read()
    content = "original" if n is not None and data == seed_bytes(n) else "other"
    return "present size=%d mode=%04o nlink=%d content=%s" % (len(data), stat.S_IMODE(st.st_mode), st.st_nlink, content)


def suffix(rec):
    return "" if rec.get("reply") == "continue" else "[" + rec["reply"] + "]"


def summary(path, n=None):
    recs = [json.loads(l) for l in open(path)] if os.path.exists(path) else []
    dirfd = next((r["arg0"] for r in recs if r["syscall"] in ("unlinkat", "renameat", "renameat2")), None)
    tmpfd = next((r["arg0"] for r in recs if r["syscall"] == "write"), None)
    out, closed, opened = [], False, False
    for r in recs:
        s = r["syscall"]
        if s == "unlinkat":
            name = r.get("string1", "")
            out.append("unlinkat %s%s" % ("tmp" if name.startswith(".rngseed-") else name, suffix(r)))
        elif s == "openat" and str(r.get("string1", "")).startswith(".rngseed-"):
            opened = True
            out.append("openat tmp")
        elif s == "write":
            out.append("write tmp %d%s" % (r["arg2"], suffix(r)))
        elif s == "fsync":
            fd = r["arg0"]
            out.append("fsync %s%s" % ("dir" if fd == dirfd else "tmp" if fd == tmpfd or tmpfd is None else "fd?", suffix(r)))
        elif s == "close" and opened and not closed and tmpfd is not None and r["arg0"] == tmpfd:
            closed = True
            out.append("close tmp")
        elif s in ("renameat", "renameat2"):
            out.append("renameat %s%s" % ("tmp" if str(r.get("string1", "")).startswith(".rngseed-") else r.get("string1"), suffix(r)))
        elif s == "ioctl":
            out.append("ioctl RNDADDENTROPY reply=%s" % SYNTH.get(r["reply"], r["reply"]))
        elif s == "getrandom" and (n is None or r["arg1"] == n):
            out.append("getrandom len=%d nonblock=%d%s" % (r["arg1"], r["arg2"] & 1, suffix(r)))
        elif s == "read":
            out.append("read %d%s" % (r["arg2"], suffix(r)))
    return " | ".join(out) if out else "(none)"


def copies(n):
    count = 0
    for f in os.listdir("."):
        if os.path.isfile(f) and not os.path.islink(f) and open(f, "rb").read() == seed_bytes(n):
            count += 1
    return count


def report(argv):
    name, file, n, probes = argv[0], argv[1], int(argv[2]), argv[3:]
    rc = open(name + ".rc").read().strip()
    err = open(name + ".err").read() if os.path.exists(name + ".err") else ""
    fds = open(name + ".fds").read().strip() if os.path.exists(name + ".fds") else "?"
    temps = sorted(f for f in os.listdir(".") if f.startswith(".rngseed-"))
    parts = ["%s: rc=%s" % (os.path.basename(name), rc)] + ["err[%s]=%d" % (p, p in err) for p in probes]
    parts += ["fds=%s" % fds, "file=%s" % state(file, n), "temps=%s" % (",".join(temps) or "none"), "orig-copies=%d" % copies(n)]
    print(" ".join(parts))
    print("  trace: " + summary(name + ".jsonl", n))
    if fds != "same" and os.path.exists(name + ".fdl"):
        print("  fd-lists: " + open(name + ".fdl").read().strip())


def payload(argv):
    name, n = argv[0], int(argv[1])
    recs = [json.loads(l) for l in open(name + ".jsonl")]
    rec = next(r for r in recs if r["syscall"] == "ioctl")
    raw = bytes.fromhex(rec["memory2"]["hex"])
    pool = int(open("/proc/sys/kernel/random/poolsize").read())
    entropy, size = struct.unpack_from("<ii", raw)
    print("n=%d len-ok=%d buf_size-ok=%d entropy-ok=%d buf-equals-seed=%d" % (
        n, len(raw) == 8 + n, size == n, entropy == min(8 * n, pool), raw[8:] == seed_bytes(n)))


def main(argv):
    cmd = argv[1]
    if cmd == "gen":
        n = int(argv[3]); mode = int(argv[4], 8) if len(argv) > 4 else 0o600
        fd = os.open(argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, seed_bytes(n)); os.fchmod(fd, mode); os.close(fd)
    elif cmd == "state":
        print(state(argv[2], int(argv[3]) if len(argv) > 3 else None))
    elif cmd == "report":
        report(argv[2:])
    elif cmd == "payload":
        payload(argv[2:])
    else:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
