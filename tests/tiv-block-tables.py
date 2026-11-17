#!/usr/bin/env python3
"""Check tiv's block-glyph tables against Unicode's cell layout.

usage: tiv-block-tables.py [loadables/common/_bashtiv_blocks.h]

tiv sets bit i for sub-pixel i in reading order: row by row, left cell then
right cell. Unicode numbers sextant and octant cells the same way and encodes
the patterns in increasing order, leaving out every pattern that already had a
character. Those earlier characters are listed here by pattern, so each of the
4 + 16 + 64 + 256 entries has exactly one expected code point.
"""
import re
import sys
from pathlib import Path

HALF = {0: 0x20, 1: 0x2580, 2: 0x2584, 3: 0x2588}
QUAD = {0: 0x20, 1: 0x2598, 2: 0x259D, 3: 0x2580, 4: 0x2596, 5: 0x258C,
        6: 0x259E, 7: 0x259B, 8: 0x2597, 9: 0x259A, 10: 0x2590, 11: 0x259C,
        12: 0x2584, 13: 0x2599, 14: 0x259F, 15: 0x2588}
# Sextants U+1FB00..U+1FB3B omit blank, both half columns and the full block.
SEXT_EARLIER = {0: 0x20, 21: 0x258C, 42: 0x2590, 63: 0x2588}
# Octants U+1CD00..U+1CDE5 omit the 26 patterns below: blank and full block,
# halves, the ten quadrant shapes, quarter and three-quarter rows, the middle
# half columns, and the four single corner cells.
OCT_EARLIER = {
    0: 0x20, 255: 0x2588,
    15: 0x2580, 240: 0x2584, 85: 0x258C, 170: 0x2590,
    5: 0x2598, 10: 0x259D, 80: 0x2596, 160: 0x2597, 90: 0x259E, 165: 0x259A,
    95: 0x259B, 175: 0x259C, 245: 0x2599, 250: 0x259F,
    3: 0x1FB82, 63: 0x1FB85, 192: 0x2582, 252: 0x2586,
    20: 0x1FBE6, 40: 0x1FBE7,
    1: 0x1CEA8, 2: 0x1CEAB, 64: 0x1CEA3, 128: 0x1CEA0,
}


def sequential(earlier, first, last, count):
    want, code = dict(earlier), first
    for pattern in range(count):
        if pattern not in want:
            want[pattern] = code
            code += 1
    if code != last + 1:
        raise SystemExit(f"layout table is inconsistent: ended at U+{code - 1:04X}")
    return want


def table(source, name, count):
    match = re.search(r"static const char \*const %s\[(\d+)\] = \{(.*?)\};" % name, source, re.S)
    if not match or int(match.group(1)) != count:
        raise SystemExit(f"{name}[{count}] not found")
    entries = re.findall(r'"((?:\\x[0-9a-f]{2})+)"', match.group(2))
    if len(entries) != count:
        raise SystemExit(f"{name}: {len(entries)} entries, expected {count}")
    out = []
    for entry in entries:
        text = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-f]{2})", entry)).decode("utf-8")
        if len(text) != 1:
            raise SystemExit(f"{name}: an entry is not one character")
        out.append(ord(text))
    return out


def main():
    default = Path(__file__).resolve().parent.parent / "loadables/common/_bashtiv_blocks.h"
    source = Path(sys.argv[1] if len(sys.argv) > 1 else default).read_text()
    failed = 0
    for name, want, rows in (
            ("btv_half", HALF, 2), ("btv_quad", QUAD, 2),
            ("btv_sext", sequential(SEXT_EARLIER, 0x1FB00, 0x1FB3B, 64), 3),
            ("btv_oct", sequential(OCT_EARLIER, 0x1CD00, 0x1CDE5, 256), 4)):
        got = table(source, name, len(want))
        if len(set(got)) != len(got):
            print(f"{name}: two patterns share a character")
            failed += 1
        bad = [i for i in range(len(want)) if got[i] != want[i]]
        print(f"{name}: {len(want) - len(bad)} of {len(want)} match")
        width = 1 if name == "btv_half" else 2
        for i in bad:
            cells = " ".join(format((i >> (width * r)) & ((1 << width) - 1), f"0{width}b")[::-1]
                             for r in range(rows))
            print(f"  pattern {i:3d}  rows {cells}  table U+{got[i]:04X}  expected U+{want[i]:04X}")
        failed += len(bad)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
