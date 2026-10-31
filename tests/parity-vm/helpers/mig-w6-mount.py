#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only independent oracle for mount fixtures (no candidate involvement).

  mi PATH FIELD      parse /proc/self/mountinfo independently; print one field of
                     the topmost mount at PATH (mounted fstype source mopts sopts
                     root majmin) or "absent"
  rawmount SRC DST TYPE FLAGS DATA   call mount(2) directly; print errno name
  rawumount PATH FLAGS               call umount2(2) directly; print errno name
  outer-has SUBSTR   print "yes" when any mountpoint contains SUBSTR
"""
import ctypes, errno, os, sys

def unesc(text):
    out, i = bytearray(), 0
    raw = text.encode()
    while i < len(raw):
        if raw[i:i+1] == b"\\" and i + 3 < len(raw) + 0 and raw[i+1:i+4].isdigit():
            out.append(int(raw[i+1:i+4], 8)); i += 4
        else:
            out.append(raw[i]); i += 1
    return out.decode()

def entries():
    rows = []
    for line in open("/proc/self/mountinfo"):
        left, right = line.rstrip("\n").split(" - ")
        a = left.split(" ")
        b = right.split(" ")
        rows.append({"majmin": a[2], "root": unesc(a[3]), "mp": unesc(a[4]),
                     "mopts": ",".join(sorted(a[5].split(","))),
                     "fstype": b[0], "source": b[1],
                     "sopts": ",".join(sorted(b[2].split(",")))})
    return rows

def libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    lib.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    return lib

def main(argv):
    cmd = argv[1]
    if cmd == "mi":
        hits = [e for e in entries() if e["mp"] == argv[2]]
        if not hits:
            print("absent"); return 0
        e = hits[-1]
        field = argv[3]
        print("yes" if field == "mounted" else e[field])
        return 0
    if cmd == "outer-has":
        print("yes" if any(argv[2] in e["mp"] for e in entries()) else "no"); return 0
    lib = libc()
    if cmd == "rawmount":
        src, dst, typ, flags, data = argv[2:7]
        r = lib.mount(src.encode() or None, dst.encode(), typ.encode() or None, int(flags, 0), data.encode() or None)
    elif cmd == "rawumount":
        r = lib.umount2(argv[2].encode(), int(argv[3], 0))
    else:
        return 2
    print("OK" if r == 0 else errno.errorcode[ctypes.get_errno()])
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
