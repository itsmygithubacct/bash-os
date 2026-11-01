#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Synthetic /proc/net tables for ss, served through seccomp user notification.

Runs inside a mapped user namespace (unshare --user --map-root-user --net ...).
A forked child installs a seccomp filter (no_new_privs, unprivileged) that
  * fails socket(AF_NETLINK, *, NETLINK_SOCK_DIAG) with EPROTONOSUPPORT, so the
    candidate must take its /proc/net route, and
  * stops open/openat at the supervisor (this process), which answers an open
    of exactly one of the mocked /proc/net paths by creating a memfd holding
    synthetic table text and installing it as the call's result with
    SECCOMP_IOCTL_NOTIF_ADDFD (SEND flag). Every other open continues unchanged.
The child then execs the candidate shell running `ss ...`. The expectation is
encoded here, independently of the candidate, from the kernel's documented
/proc/net/{tcp,tcp6,udp,udp6,unix} line formats. GNU iproute2 ss, run with
PROC_ROOT on the same table text, is a second oracle for ambiguous mappings.
"""
import ctypes
import errno
import fcntl
import importlib.util
import os
import select
import shutil
import signal
import socket
import struct
import sys

_spec = importlib.util.spec_from_file_location(
    "mig_w1_netlib", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-netlib.py"))
L = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(L)

SS_IPR = "/usr/bin/ss"
libc = ctypes.CDLL(None, use_errno=True)

NOTIF_RECV = 0xc0502100
NOTIF_SEND = 0xc0182101
NOTIF_ADDFD = 0x40182103
ADDFD_FLAG_SEND = 2
FLAG_CONTINUE = 1
SYS_SECCOMP = 317
NR_OPEN, NR_OPENAT, NR_SOCKET = 2, 257, 41

PATHS = ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6", "/proc/net/unix"]


# --------------------------------------------------------------------------- seccomp filter
class Insn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


def build_filter(block_diag):
    LD, JEQ, RET = 0x20, 0x15, 0x06
    prog = []   # entries: (code, k, jt_label, jf_label)

    def add(code, k=0, jt=None, jf=None):
        prog.append([code, k, jt, jf])
    labels = {}
    add(LD, 4)                                   # arch
    add(JEQ, 0xc000003e, None, "kill")
    add(LD, 0)                                   # nr
    add(JEQ, NR_OPENAT, "notif", None)
    add(JEQ, NR_OPEN, "notif", None)
    if block_diag:
        add(JEQ, NR_SOCKET, None, "allow")
        add(LD, 16)                              # arg0 (low word): domain
        add(JEQ, 16, None, "allow")              # AF_NETLINK
        add(LD, 32)                              # arg2 (low word): protocol
        add(JEQ, 4, None, "allow")               # NETLINK_SOCK_DIAG
        add(RET, 0x00050000 | errno.EPROTONOSUPPORT)
    labels["allow"] = len(prog)
    add(RET, 0x7fff0000)
    labels["notif"] = len(prog)
    add(RET, 0x7fc00000)
    labels["kill"] = len(prog)
    add(RET, 0x80000000)
    out = []
    for i, (code, k, jt, jf) in enumerate(prog):
        t = (labels[jt] - i - 1) if jt else 0
        f = (labels[jf] - i - 1) if jf else 0
        out.append(Insn(code, t, f, k))
    return (Insn * len(out))(*out)


class Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install(block_diag):
    arr = build_filter(block_diag)
    fp = Fprog(len(arr), ctypes.cast(arr, ctypes.c_void_p))
    libc.prctl(38, 1, 0, 0, 0)                   # PR_SET_NO_NEW_PRIVS
    libc.syscall.restype = ctypes.c_long
    fd = libc.syscall(SYS_SECCOMP, 1, 8, ctypes.byref(fp))   # SET_MODE_FILTER, FLAG_NEW_LISTENER
    if fd < 0:
        raise OSError(ctypes.get_errno(), "seccomp")
    return fd


def memread(pid, addr, n):
    with open("/proc/%d/mem" % pid, "rb", buffering=0) as m:
        m.seek(addr)
        return m.read(n)


def run_mocked(argv, tables, block_diag=True, timeout=30):
    """Run argv with TABLES {path: bytes} substituted. Returns (rc, out, err, opened)."""
    libc.prctl(4, 1, 0, 0, 0)                    # PR_SET_DUMPABLE=1 (userns left it non-dumpable)
    po, pw = os.pipe()
    pe, pew = os.pipe()
    parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child = os.fork()
    if child == 0:
        try:
            parent.close()
            os.dup2(pw, 1)
            os.dup2(pew, 2)
            for fd in (po, pw, pe, pew):
                os.close(fd)
            listener = install(block_diag)
            os.set_inheritable(listener, False)
            socket.send_fds(peer, [b"L"], [listener])
            peer.close()
            os.execve(argv[0], argv, L.ENV)
        except BaseException as exc:  # noqa: BLE001
            os.write(2, ("procmock child: %r\n" % exc).encode())
        os._exit(126)
    peer.close()
    os.close(pw)
    os.close(pew)
    ready, _, _ = select.select([parent], [], [], 10)
    fds = socket.recv_fds(parent, 16, 1)[1] if ready else []
    if not fds:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        raise RuntimeError("child did not install the filter")
    listener = fds[0]
    opened = []
    chunks = {po: [], pe: []}
    open_fds = [po, pe]
    status = None
    import time
    deadline = time.time() + timeout
    while status is None or open_fds:
        if time.time() > deadline:
            os.kill(child, signal.SIGKILL)
            raise RuntimeError("procmock timeout")
        rl, _, _ = select.select([listener] + open_fds, [], [], 0.05)
        for fd in rl:
            if fd == listener:
                req = bytearray(80)
                try:
                    fcntl.ioctl(listener, NOTIF_RECV, req, True)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.EINTR):
                        continue
                    raise
                ident, pid, _fl, nr = struct.unpack_from("<QIIi", req)
                args = struct.unpack_from("<6Q", req, 32)
                path = None
                try:
                    path = memread(pid, args[0 if nr == NR_OPEN else 1], 4096).split(b"\0", 1)[0].decode("utf-8", "replace")
                except OSError:
                    pass
                if path in tables:
                    flags = args[1 if nr == NR_OPEN else 2]
                    mfd = os.memfd_create("synthetic-proc", os.MFD_CLOEXEC)
                    os.write(mfd, tables[path])
                    os.lseek(mfd, 0, os.SEEK_SET)
                    addfd = struct.pack("<QIIII", ident, ADDFD_FLAG_SEND, mfd, 0,
                                        os.O_CLOEXEC if flags & os.O_CLOEXEC else 0)
                    try:
                        fcntl.ioctl(listener, NOTIF_ADDFD, addfd)
                        opened.append(path)
                    except OSError as exc:
                        if exc.errno != errno.ENOENT:
                            raise
                    os.close(mfd)
                else:
                    resp = struct.pack("<QqiI", ident, 0, 0, FLAG_CONTINUE)
                    try:
                        fcntl.ioctl(listener, NOTIF_SEND, resp)
                    except OSError as exc:
                        if exc.errno != errno.ENOENT:
                            raise
            else:
                data = os.read(fd, 65536)
                if data:
                    chunks[fd].append(data)
                else:
                    open_fds.remove(fd)
                    os.close(fd)
        if status is None:
            done, wait = os.waitpid(child, os.WNOHANG)
            if done:
                status = wait
    os.close(listener)
    parent.close()
    rc = os.waitstatus_to_exitcode(status)
    return rc, b"".join(chunks[po]).decode(), b"".join(chunks[pe]).decode(), opened


def cand_ss(args, tables, block_diag=True):
    return run_mocked([L.CAND, "--noprofile", "--norc", "-c", 'ss "$@"', "cand"] + list(args), tables, block_diag)


# --------------------------------------------------------------------------- table encoders (kernel formats)
TCP_HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
UDP_HDR = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
UNIX_HDR = "Num       RefCount Protocol Flags    Type St Inode Path\n"


def hex4(ip):
    """IPv4 text -> /proc form: the s_addr word printed %08X on a little-endian host."""
    b = bytes(int(x) for x in ip.split("."))
    return "%08X" % struct.unpack("<I", b)[0]


def hex6(ip):
    """IPv6 text -> /proc form: four s6_addr32 words, each printed %08X on a little-endian host."""
    raw = socket.inet_pton(socket.AF_INET6, ip)
    return "".join("%08X" % w for w in struct.unpack("<4I", raw))


def inet_line(idx, fam, local, lport, remote, rport, st, tx, rx, inode, udp=False):
    h = hex4 if fam == 4 else hex6
    tail = " 2 0000000000000000 0" if udp else " 1 0000000000000000 100 0 0 10 0"
    return "%4d: %s:%04X %s:%04X %02X %08X:%08X 00:00000000 00000000     0        0 %d%s\n" % (
        idx, h(local), lport, h(remote), rport, st, tx, rx, inode, tail)


def unix_line(idx, flags, typ, st, inode, path=""):
    return "%016x: 00000002 00000000 %08X %04X %02X %5d%s\n" % (idx, flags, typ, st, inode, (" " + path) if path else "")


# State names iproute2 ss prints (TCP_* numbering used for /proc/net/{tcp,udp}).
SSNAME = {1: "ESTAB", 2: "SYN-SENT", 3: "SYN-RECV", 4: "FIN-WAIT-1", 5: "FIN-WAIT-2", 6: "TIME-WAIT",
          7: "UNCONN", 8: "CLOSE-WAIT", 9: "LAST-ACK", 10: "LISTEN", 11: "CLOSING"}


def fmt(fam, ip, port):
    if port == 0:
        return ("[%s]:*" % ip) if fam == 6 else ("%s:*" % ip)
    return ("[%s]:%d" % (ip, port)) if fam == 6 else ("%s:%d" % (ip, port))


# Synthetic socket model: (netid, fam, local, lport, remote, rport, state, tx, rx, inode)
TCP4 = [
    ("tcp", 4, "0.0.0.0", 22, "0.0.0.0", 0, 10, 0, 0, 1101),
    ("tcp", 4, "10.1.2.3", 44310, "10.9.8.7", 443, 1, 16, 42, 1102),
    ("tcp", 4, "127.0.0.1", 8080, "127.0.0.1", 50000, 6, 0, 0, 1103),
    ("tcp", 4, "192.168.5.9", 51000, "198.51.100.4", 25, 2, 3, 0, 1104),
    ("tcp", 4, "172.16.0.1", 3128, "172.16.0.2", 61000, 8, 0, 7, 1105),
]
TCP6 = [
    ("tcp6", 6, "::", 22, "::", 0, 10, 0, 0, 1201),
    ("tcp6", 6, "::1", 5000, "::1", 40000, 1, 7, 5, 1202),
    ("tcp6", 6, "2001:db8::1", 443, "2001:db8:0:1::99", 52111, 1, 0, 0, 1203),
]
UDP4 = [
    ("udp", 4, "127.0.0.1", 5353, "0.0.0.0", 0, 7, 0, 0, 1301),
    ("udp", 4, "10.0.0.1", 4000, "10.0.0.2", 53, 1, 0, 5, 1302),
]
UDP6 = [
    ("udp6", 6, "::", 546, "::", 0, 7, 0, 0, 1401),
]
# unix: (kind, flags, type, st, inode, path)
UNIX = [
    ("listener", 0x10000, 1, 1, 1501, "/run/synth/listen.sock"),
    ("connected-named", 0, 1, 3, 1502, "/run/synth/conn.sock"),
    ("connected-unnamed", 0, 1, 3, 1503, ""),
    ("dgram-bound", 0, 2, 1, 1504, "/run/synth/dgram.sock"),
    ("seqpacket-listener", 0x10000, 5, 1, 1505, "/run/synth/seq.sock"),
    ("abstract", 0, 1, 3, 1506, "@synthetic-abstract"),
]
UNIX_CS = [("connecting", 0, 1, 2, 1601, "/run/synth/connecting.sock"),
           ("disconnecting", 0, 1, 4, 1602, "/run/synth/disc.sock")]


def tcp_table(rows, udp=False):
    s = UDP_HDR if udp else TCP_HDR
    for i, (_, fam, lip, lp, rip, rp, st, tx, rx, ino) in enumerate(rows):
        s += inet_line(i, fam, lip, lp, rip, rp, st, tx, rx, ino, udp)
    return s.encode()


def unix_table(rows):
    s = UNIX_HDR
    for i, (_, fl, ty, st, ino, p) in enumerate(rows):
        s += unix_line(i, fl, ty, st, ino, p)
    return s.encode()


def tables(tcp4=(), tcp6=(), udp4=(), udp6=(), unix=()):
    return {"/proc/net/tcp": tcp_table(tcp4), "/proc/net/tcp6": tcp_table(tcp6),
            "/proc/net/udp": tcp_table(udp4, True), "/proc/net/udp6": tcp_table(udp6, True),
            "/proc/net/unix": unix_table(unix)}


def expect_inet(rows):
    return [(r[0], SSNAME[r[6]], r[8], r[7], fmt(r[1], r[2], r[3]), fmt(r[1], r[4], r[5])) for r in rows]


UTYPE = {1: "u_str", 2: "u_dgr", 5: "u_seq"}


def expect_unix(rows):
    out = []
    for _, fl, ty, st, ino, p in rows:
        state = "LISTEN" if fl & 0x10000 else {1: "UNCONN", 3: "ESTAB"}[st]
        out.append((UTYPE[ty], state, 0, 0, p or "*", "*"))
    return out


def parse(text):
    """-> (header_line, [(netid, state, rq, sq, local, peer)]) from candidate/ss text."""
    lines = text.splitlines()
    rows = []
    for ln in lines[1:]:
        t = ln.split()
        if len(t) >= 6:
            rows.append((t[0], t[1], int(t[2]), int(t[3]), t[4], t[5]))
    return (lines[0] if lines else ""), rows


def by_netid(rows):
    d = {}
    for r in rows:
        d.setdefault(r[0], []).append(r)
    return d


HDR_TOK = ["Netid", "State", "Recv-Q", "Send-Q", "Local", "Address:Port", "Peer", "Address:Port"]


# --------------------------------------------------------------------------- reference ss on the same text (PROC_ROOT)
def ref_ss(args, tabs):
    d = "/tmp/parity-case/procroot-%d" % os.getpid()
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d + "/net")
    for p, data in tabs.items():
        open(d + "/net/" + p.rsplit("/", 1)[1], "wb").write(data)
    env = dict(L.ENV)
    env["PROC_ROOT"] = d
    rc, out, err = L.run([SS_IPR, "-n"] + list(args), env=env)   # -n: no service-name lookup
    shutil.rmtree(d, ignore_errors=True)
    return rc, out, err


def ref_rows(text):
    """iproute2 prints unix endpoints as 'path inode' and 'peer-addr peer-inode'; fold to the same columns."""
    rows = []
    for ln in text.splitlines()[1:]:
        t = ln.split()
        if len(t) < 6:
            continue
        if t[0].startswith("u_"):
            # netid state rq sq PATH INODE PEER PEERINODE
            rows.append((t[0], t[1], int(t[2]), int(t[3]), t[4], t[6] if len(t) > 6 else "*"))
        else:
            # iproute2 prints IPv6 TCP/UDP sockets under netid tcp/udp; the candidate uses tcp6/udp6
            # (and prints the IPv6 wildcard as *:PORT / *:*)
            loc, peer = t[4], t[5]
            v6 = loc.startswith("[") or loc.startswith("*:")
            if loc.startswith("*:"):
                loc = "[::]:" + loc[2:]
            if peer == "*:*" and v6:
                peer = "[::]:*"
            rows.append((t[0] + "6" if v6 else t[0], t[1], int(t[2]), int(t[3]), loc, peer))
    return rows


# --------------------------------------------------------------------------- scenarios
def world():
    """Real sockets in the namespace so a leak of real table rows would show up."""
    L.seed([["link", "set", "lo", "up"]])
    s = socket.socket()
    s.bind(("127.0.0.1", 9))
    s.listen(1)
    u = socket.socket(socket.AF_UNIX)
    u.bind("/tmp/parity-case/real-leak.sock")
    u.listen(1)
    return [s, u]


def check_all_opened(label, opened):
    L.check(label + ": every /proc/net table was served from the synthetic memfd (no real table opened)",
            sorted(set(opened)) == sorted(PATHS), "opened=%s" % opened)


def sc_empty():
    keep = world()
    for variant, tabs in (("header-only tables", tables()),
                          ("zero-byte tables", {p: b"" for p in PATHS})):
        rc, out, err, _op = cand_ss(["-tuxa"], tabs)
        L.check("empty/%s: ss -tuxa exits 0" % variant, rc == 0, "rc=%s err=%s" % (rc, err))
        hdr, rows = parse(out)
        L.check("empty/%s: no rows at all, in particular none of the real namespace sockets" % variant,
                rows == [], "out=%r" % out)
        L.check("empty/%s: the Netid/State/Recv-Q/Send-Q/Local/Peer header is printed once and alone" % variant,
                hdr.split() == HDR_TOK and len(out.splitlines()) == 1, "out=%r" % out)
        L.check("empty/%s: stderr is silent" % variant, err == "", "err=%r" % err)
    rc, out, err, opened = cand_ss(["-tuxa"], tables())
    check_all_opened("empty", opened)
    # reference: real iproute2 ss prints nothing but its header for the same text
    rrc, rout, rerr = ref_ss(["-tuxa"], tables())
    L.check("empty: iproute2 ss with PROC_ROOT on the same text lists no rows either",
            rrc == 0 and ref_rows(rout) == [], "rc=%s out=%r err=%r" % (rrc, rout, rerr))
    for k in keep:
        k.close()


def sc_populated():
    keep = world()
    t = tables(TCP4, TCP6, UDP4, UDP6, UNIX)
    rc, out, err, opened = cand_ss(["-tuxa"], t)
    L.check("populated: ss -tuxa exits 0 with no diagnostics", rc == 0 and err == "", "rc=%s err=%r" % (rc, err))
    check_all_opened("populated", opened)
    hdr, rows = parse(out)
    got = by_netid(rows)
    L.check("populated: header is the ss header", hdr.split() == HDR_TOK, hdr)
    L.check("populated: no real-namespace socket (127.0.0.1:9, real-leak.sock) leaks into the output",
            "127.0.0.1:9" not in out and "real-leak" not in out, out)
    L.check("populated: row count equals the synthetic table row counts (%d)" % (len(TCP4) + len(TCP6) + len(UDP4) + len(UDP6) + len(UNIX)),
            len(rows) == len(TCP4) + len(TCP6) + len(UDP4) + len(UDP6) + len(UNIX), "got %d rows:\n%s" % (len(rows), out))
    # IPv4 TCP rows: states, queues, endpoints, in table order
    e = expect_inet(TCP4)
    L.check("populated tcp: netid, state, Recv-Q (rx_queue), Send-Q (tx_queue), local, peer for five states in table order",
            got.get("tcp", []) == e, "got=%s\nwant=%s" % (got.get("tcp"), e))
    e = expect_inet(UDP4)
    L.check("populated udp: bound row is UNCONN and connected row is ESTAB with its queues and peer",
            got.get("udp", []) == e, "got=%s\nwant=%s" % (got.get("udp"), e))
    # IPv6: split into identity/state/queues (independent of address text) and the bracketed endpoint text
    e6 = expect_inet(TCP6)
    g6 = got.get("tcp6", [])
    L.check("populated tcp6: state and queues for the three rows in table order",
            [(r[1], r[2], r[3]) for r in g6] == [(r[1], r[2], r[3]) for r in e6], "got=%s\nwant=%s" % (g6, e6))
    L.check("populated tcp6: endpoints print as [addr]:port with [::]:* for wildcard peers, decoded from the little-endian word form",
            [(r[4], r[5]) for r in g6] == [(r[4], r[5]) for r in e6], "got=%s\nwant=%s" % ([(r[4], r[5]) for r in g6], [(r[4], r[5]) for r in e6]))
    e6 = expect_inet(UDP6)
    g6 = got.get("udp6", [])
    L.check("populated udp6: state and queues", [(r[1], r[2], r[3]) for r in g6] == [(r[1], r[2], r[3]) for r in e6], "got=%s" % g6)
    L.check("populated udp6: endpoints print as [::]:546 and [::]:*", [(r[4], r[5]) for r in g6] == [(r[4], r[5]) for r in e6],
            "got=%s want=%s" % ([(r[4], r[5]) for r in g6], [(r[4], r[5]) for r in e6]))
    # unix
    gu = [r for r in rows if r[0].startswith("u_")]
    eu = expect_unix(UNIX)
    L.check("populated unix: type column (u_str/u_dgr/u_seq) and state (LISTEN/ESTAB/UNCONN) follow the Type, St and flags columns",
            [(r[0], r[1]) for r in gu] == [(r[0], r[1]) for r in eu], "got=%s\nwant=%s" % (gu, eu))
    L.check("populated unix: queues are 0/0 (the proc table has no queue columns) and each row shows its path or '*'",
            [(r[2], r[3], r[4]) for r in gu] == [(r[2], r[3], r[4]) for r in eu], "got=%s\nwant=%s" % (gu, eu))
    for k in keep:
        k.close()


def sc_listening():
    keep = world()
    t = tables(TCP4, TCP6, UDP4, UDP6, UNIX)
    rc, out, err, opened = cand_ss(["-tuxl"], t)
    hdr, rows = parse(out)
    L.check("listening: ss -tuxl exits 0", rc == 0, "rc=%s err=%r" % (rc, err))
    want = ([r for r in expect_inet(TCP4) if r[1] == "LISTEN"] + [r for r in expect_inet(TCP6) if r[1] == "LISTEN"]
            + [r for r in expect_inet(UDP4) if r[1] == "UNCONN"] + [r for r in expect_inet(UDP6) if r[1] == "UNCONN"]
            + [r for r in expect_unix(UNIX) if r[1] == "LISTEN"])
    key = lambda r: (r[0], r[4])
    L.check("listening: only LISTEN TCP rows, bound-only UDP rows and listening unix rows remain (identity, state, queues)",
            sorted((r[0], r[1], r[2], r[3]) for r in rows) == sorted((r[0], r[1], r[2], r[3]) for r in want),
            "got=%s\nwant=%s" % (rows, want))
    L.check("listening: the surviving rows are the ones whose Local Address is in the filtered synthetic set (v4 and unix text)",
            sorted((r[0], r[4]) for r in rows if r[0] in ("tcp", "udp") or r[0].startswith("u_")) ==
            sorted((r[0], r[4]) for r in want if r[0] in ("tcp", "udp") or r[0].startswith("u_")), "got=%s\nwant=%s" % (rows, want))
    rrc, rout, rerr = ref_ss(["-tuxl"], t)
    ref = ref_rows(rout)
    L.check("listening: candidate rows (identity, state, queues of IPv4 and unix rows) equal iproute2 ss -tuxl on the same text",
            sorted((r[0], r[1], r[4]) for r in rows if r[0] in ("tcp", "udp") or r[0].startswith("u_")) ==
            sorted((r[0], r[1], r[4]) for r in ref if r[0] in ("tcp", "udp") or r[0].startswith("u_")),
            "cand=%s\nref=%s\nrefout=%r" % (rows, ref, rout))
    for k in keep:
        k.close()


def sc_one_table():
    """Only one table is populated; the others are header-only. Rows come from that table alone."""
    keep = world()
    for name, kw, e in (("tcp", {"tcp4": TCP4}, expect_inet(TCP4)), ("udp6", {"udp6": UDP6}, expect_inet(UDP6)),
                        ("unix", {"unix": UNIX}, expect_unix(UNIX))):
        rc, out, err, opened = cand_ss(["-tuxa"], tables(**kw))
        hdr, rows = parse(out)
        L.check("one-table/%s: only that table's rows are printed, with identity, state and queues" % name,
                rc == 0 and [(r[0], r[1], r[2], r[3]) for r in rows] == [(r[0], r[1], r[2], r[3]) for r in e],
                "rc=%s err=%r got=%s\nwant=%s" % (rc, err, rows, e))
    for k in keep:
        k.close()


def sc_ss_unix_states():
    """iproute2 is the oracle for the unix St values 2 (connecting) and 4 (disconnecting)."""
    keep = world()
    t = tables(unix=UNIX_CS)
    rc, out, err, opened = cand_ss(["-xa"], t)
    hdr, rows = parse(out)
    L.check("unix-states: ss -xa exits 0 and lists both rows", rc == 0 and len(rows) == 2, "rc=%s err=%r out=%r" % (rc, err, out))
    rrc, rout, rerr = ref_ss(["-xa"], t)
    ref = ref_rows(rout)
    L.check("unix-states: iproute2 ss lists both rows on the same text", rrc == 0 and len(ref) == 2, "rc=%s out=%r err=%r" % (rrc, rout, rerr))
    L.check("unix-states: St=2 (connecting) and St=4 (disconnecting) get the state names iproute2 ss prints for the same table",
            [r[1] for r in rows] == [r[1] for r in ref], "cand=%s ref=%s" % (rows, ref))
    for k in keep:
        k.close()


def sc_inet_vs_iproute2():
    keep = world()
    t = tables(TCP4, TCP6, UDP4, UDP6, UNIX)
    rc, out, err, opened = cand_ss(["-tua"], t)
    hdr, rows = parse(out)
    rrc, rout, rerr = ref_ss(["-tua"], t)
    ref = ref_rows(rout)
    L.check("vs-iproute2: iproute2 ss -tua with PROC_ROOT lists all %d inet rows" % (len(TCP4) + len(TCP6) + len(UDP4) + len(UDP6)),
            rrc == 0 and len(ref) == len(TCP4) + len(TCP6) + len(UDP4) + len(UDP6), "rc=%s out=%r err=%r" % (rrc, rout, rerr))
    v4 = lambda rs: sorted(r for r in rs if not r[0].endswith("6"))
    v6 = lambda rs: sorted(r for r in rs if r[0].endswith("6"))
    L.check("vs-iproute2: candidate and iproute2 agree on every IPv4 TCP/UDP row (netid, state, Recv-Q, Send-Q, local, peer)",
            v4(rows) == v4(ref), "cand-only=%s\nref-only=%s" % (sorted(set(v4(rows)) - set(v4(ref))), sorted(set(v4(ref)) - set(v4(rows)))))
    L.check("vs-iproute2: candidate and iproute2 agree on IPv6 row identity, state and queues",
            [r[:4] for r in v6(rows)] == [r[:4] for r in v6(ref)] and len(v6(ref)) == len(TCP6) + len(UDP6),
            "cand=%s\nref=%s" % (v6(rows), v6(ref)))
    L.check("vs-iproute2: candidate and iproute2 print the same IPv6 endpoint text",
            [(r[0], r[4], r[5]) for r in v6(rows)] == [(r[0], r[4], r[5]) for r in v6(ref)],
            "cand=%s\nref=%s" % ([(r[0], r[4], r[5]) for r in v6(rows)], [(r[0], r[4], r[5]) for r in v6(ref)]))
    for k in keep:
        k.close()


SCEN = {"empty": sc_empty, "populated": sc_populated, "listening": sc_listening, "one-table": sc_one_table,
        "unix-states": sc_ss_unix_states, "vs-iproute2": sc_inet_vs_iproute2}

if __name__ == "__main__":
    SCEN[sys.argv[1]]()
    sys.exit(L.finish(sys.argv[1]))
