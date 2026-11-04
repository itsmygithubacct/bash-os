#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Capture deterministic veth frames across the snaplen boundary in a VM."""
import importlib.util
import os
import struct

base = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pcap_fixture", os.path.join(base, "mig-w1-pcap.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

P.setup()
for snap, sizes in ((100, (60, 100, 101, 200)), (32, (60, 120))):
    frames = [P.eth(size, i + snap) for i, size in enumerate(sizes)]
    path = P.CASE + "/boundary-%d.pcap" % snap
    result = P.pcap_run(["-i", "v0", "-w", path, "-c", str(len(frames)),
                         "-s", str(snap), "-W", "3"], [("v1", f) for f in frames])
    P.L.check("snap %d: capture armed and succeeded" % snap,
              result["armed"] and result["rc"] == 0, str(result))
    data = open(path, "rb").read()
    valid = len(data) >= 24
    if valid:
        magic, major, minor, zone, sig, header_snap, link = struct.unpack_from("<IHHiIII", data)
        valid = (magic, major, minor, zone, sig, header_snap, link) == (0xa1b2c3d4, 2, 4, 0, 0, snap, 1)
    offset = 24
    for frame in frames:
        if offset + 16 > len(data):
            valid = False
            break
        _, usec, incl, orig = struct.unpack_from("<IIII", data, offset)
        offset += 16
        expected = frame[:snap]
        valid = valid and usec < 1000000 and incl == len(expected) and orig == len(frame)
        valid = valid and data[offset:offset + incl] == expected
        offset += incl
    valid = valid and offset == len(data)
    P.L.check("snap %d: complete header and exact records, lengths and bytes" % snap,
              valid, "file size=%d parsed end=%d" % (len(data), offset))

raise SystemExit(P.L.finish("fixed-frames-boundaries"))
