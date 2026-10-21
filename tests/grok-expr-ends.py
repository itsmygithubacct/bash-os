#!/usr/bin/env python3
"""el_ends_add must survive a failed realloc of the end list.

Usage: grok-expr-ends.py BASH-BINARY

The preload fails the first 128-byte realloc. On the unfixed builtin that
write goes before the buffer and glibc aborts. The fixed builtin returns
a normal expr status.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
here = Path(__file__).resolve().parent
src = here / "grok-expr-ends-fail.c"
if not os.access(binary, os.X_OK):
    sys.exit(f"not executable: {binary}")
if not src.is_file():
    sys.exit(f"missing {src}")

with tempfile.TemporaryDirectory(prefix="expr-ends-") as tmp:
    so = str(Path(tmp) / "fail.so")
    build = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", so, str(src), "-ldl"],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        sys.exit(build.stderr or "gcc failed")
    subject = "a" * 40
    pattern = r".*\(\|^b\)\+"
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["FAIL_N"] = "1"
    env["LD_PRELOAD"] = so
    proc = subprocess.run(
        [binary, "--noprofile", "--norc", "-c",
         'PATH=; expr "$1" : "$2"', "_", subject, pattern],
        capture_output=True,
        env=env,
        timeout=5,
    )
    err = proc.stderr
    bad = proc.returncode < 0 or proc.returncode >= 128
    heap = b"invalid old size" in err or b"invalid size" in err or b"heap-buffer" in err
    if bad or heap or proc.returncode not in (0, 1, 2):
        sys.exit(
            f"FAIL ends realloc rc={proc.returncode} "
            f"out={proc.stdout[:80]!r} err={err[:240]!r}"
        )
    print(f"PASS ends realloc rc={proc.returncode}")
