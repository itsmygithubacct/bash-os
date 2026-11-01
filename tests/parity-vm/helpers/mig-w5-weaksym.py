#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Drive a candidate shell so that expect's weak bashcrypto_secret_write_fd reference reads as unresolved.

Usage: mig-w5-weaksym.py BASH SCRIPT

The candidate links crypto and expect into one image, so the weak reference in
send-secret always resolves. The compiled test is `cmp qword [rip+slot],0`
followed by a branch to the "send-secret requires crypto secret handle
support" diagnostic. This helper starts the candidate shell as its own child
running SCRIPT, finds that test by its machine-code shape in the candidate's
own executable segments (verifying the branch lands on code that loads that
exact diagnostic string), and, when SCRIPT prints READY, stores zero into the
slot through /proc/PID/mem: the value an unresolved weak symbol has. The
candidate file is never modified. SCRIPT then continues with the same
send-secret request. The shell's output is passed through; the helper adds
one "weaksym:" line. Exit status is the shell's, or 90..93 for helper errors.
"""
import os
import re
import struct
import subprocess
import sys

MESSAGE = b"send-secret requires crypto secret handle support"


def segments(data):
    kind = struct.unpack_from("<H", data, 16)[0]
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    loads = []
    for i in range(phnum):
        p_type, flags, off, vaddr, _paddr, filesz, memsz, _align = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == 1:
            loads.append((off, vaddr, filesz, flags))
    return kind, loads


def vaddr_to_off(loads, vaddr):
    for off, va, size, _flags in loads:
        if va <= vaddr < va + size:
            return off + vaddr - va
    return None


def find_slot(path):
    data = open(path, "rb").read()
    kind, loads = segments(data)
    found = []
    pattern = re.compile(rb"\x48\x83\x3d(....)\x00\x89\xc6\x0f\x84(....)", re.S)
    for off, va, size, flags in loads:
        if not flags & 1:
            continue
        for m in pattern.finditer(data, off, off + size):
            at = va + m.start() - off
            disp, = struct.unpack("<i", m.group(1))
            rel, = struct.unpack("<i", m.group(2))
            slot = at + 8 + disp
            target = at + 8 + 2 + 6 + rel
            t_off = vaddr_to_off(loads, target)
            if t_off is None or data[t_off:t_off + 3] != b"\x48\x8d\x3d":
                continue
            lea_disp, = struct.unpack_from("<i", data, t_off + 3)
            s_off = vaddr_to_off(loads, target + 7 + lea_disp)
            if s_off is not None and data[s_off:s_off + len(MESSAGE)] == MESSAGE:
                found.append(slot)
    return kind, found


def load_base(pid, path):
    real = os.path.realpath(path)
    with open("/proc/%d/maps" % pid) as maps:
        for line in maps:
            fields = line.split(None, 5)
            if len(fields) == 6 and os.path.realpath(fields[5].strip()) == real and int(fields[2], 16) == 0:
                return int(fields[0].split("-")[0], 16)
    return None


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    bash, script = argv
    kind, slots = find_slot(os.path.realpath(bash))
    if len(slots) != 1:
        print("weaksym: found %d candidate slots" % len(slots))
        return 90
    child = subprocess.Popen([bash, "--noprofile", "--norc", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    status = 93
    try:
        for line in child.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            if line.strip() != "READY":
                continue
            base = load_base(child.pid, bash) if kind == 3 else 0
            if base is None:
                print("weaksym: no load base")
                child.kill()
                return 91
            address = base + slots[0]
            with open("/proc/%d/mem" % child.pid, "r+b", buffering=0) as mem:
                mem.seek(address)
                before, = struct.unpack("<Q", mem.read(8))
                mem.seek(address)
                mem.write(b"\0" * 8)
                mem.seek(address)
                after, = struct.unpack("<Q", mem.read(8))
            print("weaksym: slot-found=1 before=%s after=%s" % ("resolved" if before else "null", "null" if after == 0 else "nonzero"))
            sys.stdout.flush()
            child.stdin.write("go\n")
            child.stdin.flush()
        status = child.wait()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
