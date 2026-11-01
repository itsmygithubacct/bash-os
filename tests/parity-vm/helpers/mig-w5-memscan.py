#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Independent secret-residue scanner for disposable parity-VM fixtures.

  mig-w5-memscan.py mem PID PART [PART...]        count the secret in the process memory
  mig-w5-memscan.py files DIR [DIR...] -- PART... count the secret in regular files below DIR

The secret is the concatenation of the PART arguments, so no argument, script
or environment of the caller needs to contain it as one contiguous string.
"mem" reads every readable mapping of /proc/PID/mem (heap, stack, anonymous
and file mappings, including freed but unwiped memory) and prints
"found=N". "files" prints "files=N". The target is read, never modified.
"""
import os
import re
import sys

CHUNK = 1 << 20


def scan_stream(read_at, start, end, needle, keep):
    count = 0
    tail = b""
    pos = start
    while pos < end:
        size = min(CHUNK, end - pos)
        try:
            data = read_at(pos, size)
        except OSError:
            break
        if not data:
            break
        buf = tail + data
        count += buf.count(needle)
        tail = buf[-keep:] if keep else b""
        # a match wholly inside the kept tail was already counted
        if keep and needle in tail:
            tail = tail[tail.rfind(needle) + len(needle):]
        pos += len(data)
    return count


def scan_memory(pid, needle):
    total = 0
    with open("/proc/%d/maps" % pid) as maps, open("/proc/%d/mem" % pid, "rb", buffering=0) as mem:
        for line in maps:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
            if not m or "r" not in m.group(3) or m.group(4) in ("[vvar]", "[vsyscall]", "[vvar_vclock]"):
                continue
            start, end = int(m.group(1), 16), int(m.group(2), 16)

            def read_at(pos, size):
                mem.seek(pos)
                return mem.read(size)
            total += scan_stream(read_at, start, end, needle, len(needle) - 1)
    return total


def scan_files(roots, needle):
    hits = 0
    for root in roots:
        for base, _dirs, names in os.walk(root, followlinks=False):
            for name in names:
                path = os.path.join(base, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                try:
                    with open(path, "rb") as handle:
                        if needle in handle.read():
                            hits += 1
                except OSError:
                    pass
    return hits


def main(argv):
    if len(argv) >= 4 and argv[0] == "mem":
        needle = "".join(argv[2:]).encode()
        print("found=%d" % scan_memory(int(argv[1]), needle))
    elif len(argv) >= 4 and argv[0] == "files" and "--" in argv:
        i = argv.index("--")
        needle = "".join(argv[i + 1:]).encode()
        print("files=%d" % scan_files(argv[1:i], needle))
    else:
        sys.stderr.write(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
