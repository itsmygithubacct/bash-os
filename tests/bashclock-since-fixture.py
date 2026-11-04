#!/usr/bin/env python3
"""Run the source-inclusion fixture in a coordinator-owned disposable VM."""
import subprocess
import sys

binary = sys.argv[1]
cases = [
    ("borrow", (101, 100000001, 0, "100.900000000"), 0, "0.200000001\n", ""),
    ("zero", (100, 500000000, 0, "100.500000000"), 0, "0.000000000\n", ""),
    ("future-fraction", (100, 100000000, 0, "100.200000000"), 0, "-0.100000000\n", ""),
    ("future-cross-second", (100, 900000000, 0, "101.100000000"), 0, "-0.200000000\n", ""),
    ("future-multiple", (100, 100000000, 0, "102.300000000"), 0, "-2.200000000\n", ""),
    ("future-integer", (100, 500000000, 0, "101.500000000"), 0, "-1.000000000\n", ""),
    ("negative-start", (0, 100000000, 0, "-0.200000000"), 0, "0.300000000\n", ""),
    ("scaled-truncated", (1, 500000000, 0, "1.1234567899"), 0, "0.376543211\n", ""),
    ("missing", (0, 0, 0), 2, "", "since: needs T0"),
    ("extra", (0, 0, 0, "0", "extra"), 2, "", "since: unexpected extra argument"),
    ("empty", (0, 0, 0, ""), 2, "", "since: bad T0 format"),
    ("sign-only", (0, 0, 0, "-"), 2, "", "since: bad T0 format"),
    ("dot-only", (0, 0, 0, "."), 2, "", "since: bad T0 format"),
    ("trailing-dot", (0, 0, 0, "1."), 2, "", "since: bad T0 format"),
    ("newline", (0, 0, 0, "1\nmore"), 2, "", "since: bad T0 format"),
    ("overflow", (0, 0, 0, "999999999999999999999999999999"), 2, "", "since: bad T0 format"),
    ("clock-error", (100, 0, 1, "100"), 1, "", "clock_gettime: Input/output error"),
]
for name, args, status, stdout, stderr in cases:
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, check=False)
    if (result.returncode != status or result.stdout != stdout or
            (stderr not in result.stderr if stderr else bool(result.stderr))):
        raise AssertionError((name, result.returncode, result.stdout, result.stderr))
    print("PASS", name)
