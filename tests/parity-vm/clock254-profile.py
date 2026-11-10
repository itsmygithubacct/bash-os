#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Derive the clock254 exact-callsite profile of a candidate binary.

Host-side static analysis only: the candidate is read and disassembled with
objdump, never executed. The helpers clock254_trace.py and
clock-release-trace.py inject at fixed call sites of one pinned binary, so
every fresh release build needs its own profile.

A site is the bashclock shape "call clock_gettime; test %eax,%eax; js E",
where E is the error branch "call __errno_location; ...; mov (%rax),%edi;
call strerror; lea "clock_gettime: %s"(%rip),%rdi". bc_since passes
CLOCK_MONOTONIC as an immediate ("mov $0x1,%edi" just before the call);
bc_get_clock passes its argument. Anything other than exactly one of each
is refused. Other builtins share the read shape, so the read site must be
the only one within NEAR bytes of the since site.

Usage: clock254-profile.py CANDIDATE [--write HELPER...]
"""
import hashlib
import json
import re
import struct
import subprocess
import sys

ANCHOR = b'clock_gettime: %s\0'
NEAR = 0x1000
LINE = re.compile(r'^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$')


def die(msg):
    raise SystemExit('clock254-profile: ' + msg)


def elf(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        die('not a little-endian ELF64 file')
    e_type, = struct.unpack_from('<H', data, 16)
    phoff, = struct.unpack_from('<Q', data, 32)
    shoff, = struct.unpack_from('<Q', data, 40)
    phentsize, phnum, shentsize, shnum = struct.unpack_from('<HHHH', data, 54)
    loads = []
    for i in range(phnum):
        p_type, p_flags, p_offset, p_vaddr = struct.unpack_from('<IIQQ', data, phoff + i * phentsize)
        p_filesz, = struct.unpack_from('<Q', data, phoff + i * phentsize + 32)
        if p_type == 1:
            loads.append((p_flags, p_offset, p_vaddr, p_filesz))
    return e_type, loads


def vaddr_to_off(loads, vaddr):
    for _, off, va, size in loads:
        if va <= vaddr < va + size:
            return off + vaddr - va
    die('address %#x is not file backed' % vaddr)


def off_to_vaddr(loads, off):
    hits = [va + off - o for _, o, va, size in loads if o <= off < o + size]
    if len(hits) != 1:
        die('file offset %#x maps to %d load segments' % (off, len(hits)))
    return hits[0]


def disassemble(path):
    out = subprocess.run(['objdump', '-d', '-w', path], capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            rows.append((int(m.group(1), 16), bytes.fromhex(m.group(2).replace(' ', '')), m.group(3).strip()))
    return rows


def call_target(row):
    addr, raw, _ = row
    if len(raw) != 5 or raw[0] != 0xe8:
        return None
    return addr + 5 + struct.unpack('<i', raw[1:])[0]


def profile(path):
    data = open(path, 'rb').read()
    e_type, loads = elf(data)
    if e_type not in (2, 3):
        die('unsupported ELF type %d' % e_type)
    text = [x for x in loads if x[0] & 1]
    if len(text) != 1:
        die('expected one executable load segment')
    map_delta = (text[0][2] & ~0xfff) - (text[0][1] & ~0xfff)
    anchors = [m.start() for m in re.finditer(re.escape(ANCHOR), data)]
    if len(anchors) != 1:
        die('expected one "clock_gettime: %%s" string, found %d' % len(anchors))
    anchor = off_to_vaddr(loads, anchors[0])
    rows = disassemble(path)
    index = {r[0]: i for i, r in enumerate(rows)}
    sites = {}
    for i, (addr, raw, text_) in enumerate(rows):
        if not (raw[:3] == b'\x48\x8d\x3d' and len(raw) == 7):
            continue  # lea disp32(%rip),%rdi
        if addr + 7 + struct.unpack('<i', raw[3:])[0] != anchor:
            continue
        if i < 3 or call_target(rows[i - 1]) is None or rows[i - 2][1] != b'\x8b\x38':
            continue  # call strerror; mov (%rax),%edi
        j = i - 3
        while j >= 0 and call_target(rows[j]) is None and i - j <= 4:
            j -= 1  # skip register set-up between the errno call and its load
        if j < 0 or call_target(rows[j]) is None:
            continue
        errno_call = rows[j]
        errno_site = errno_call[0] + 5
        if errno_site not in index:
            continue
        for k, (a, r, _) in enumerate(rows):
            if k < 2:
                continue
            if r[:1] == b'\x78' and len(r) == 2:
                dest = a + 2 + struct.unpack('<b', r[1:])[0]
            elif r[:2] == b'\x0f\x88' and len(r) == 6:
                dest = a + 6 + struct.unpack('<i', r[2:])[0]
            else:
                continue
            if dest != errno_call[0] or rows[k - 1][1] != b'\x85\xc0' or call_target(rows[k - 2]) is None:
                continue
            call = rows[k - 2]
            monotonic = any(x[1] == b'\xbf\x01\x00\x00\x00' for x in rows[max(0, k - 4):k - 2])
            kind = 'since' if monotonic else 'read'
            sites.setdefault(kind, []).append((call[0], errno_site, call_target(call)))
    if len(sites.get('since', [])) != 1:
        die('expected one since call site, found %d' % len(sites.get('since', [])))
    (since_call, since_errno, since_fn), = sites['since']
    # Other builtins share the read shape; bc_get_clock is the one in
    # bashclock's own translation unit, next to the inlined bc_since.
    near = [x for x in sites.get('read', []) if abs(x[0] - since_call) <= NEAR]
    if len(near) != 1:
        die('expected one read call site within %#x of since, found %d' % (NEAR, len(near)))
    (read_call, read_errno, read_fn), = near
    if read_fn != since_fn:
        die('read and since sites call different functions')
    result = {'elf_type': e_type, 'map_delta': map_delta}
    for key, va in (('read_call', read_call), ('read_errno', read_errno),
                    ('since_call', since_call), ('since_errno', since_errno)):
        off = vaddr_to_off(loads, va)
        result[key] = va
        result[key + '_hex'] = data[off:off + 16].hex()
    result['sha256'] = hashlib.sha256(data).hexdigest()
    return result


def write_helpers(helpers, name, value):
    for helper in helpers:
        src = open(helper).read()
        m = re.search(r'^PROFILES = (\{.*?\}\})\n', src, re.S | re.M)
        if not m:
            die(helper + ': PROFILES block not found')
        import ast
        profiles = ast.literal_eval(m.group(1))
        profiles[name] = value
        import pprint
        block = 'PROFILES = ' + pprint.pformat(profiles, width=100, sort_dicts=True) + '\n'
        open(helper, 'w').write(src[:m.start()] + block + src[m.end():])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        die('usage: clock254-profile.py CANDIDATE [--write HELPER...]')
    value = profile(sys.argv[1])
    name = 'static' if value['elf_type'] == 2 else 'dynamic'
    print(json.dumps({name: value}, indent=1, sort_keys=True))
    if len(sys.argv) > 2:
        if sys.argv[2] != '--write':
            die('unknown option ' + sys.argv[2])
        write_helpers(sys.argv[3:], name, value)
