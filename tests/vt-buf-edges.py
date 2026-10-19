#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Edges that overflowed the terminal or freed a buffer twice.

A drained device-attribute reply is cloned, a cell carries the maximum
number of combining marks through diff and scrollback, a CSI parameter
runs past a 32-bit int, a buffer is loaded again after an edit, and a
save keeps the buffer's own name. The sanitizer build is what reports a
bad access; these checks also require the visible results to stay intact.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
checks = 0


def run(script, env=None, rc=0):
    global checks
    child = os.environ.copy()
    if os.environ.get("VTBUF_LOAD_ENV"):
        child["BASH_ENV"] = os.environ["VTBUF_LOAD_ENV"]
        child["LD_PRELOAD"] = os.environ["VTBUF_ASAN_LIB"]
        child["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        child["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    if env:
        child.update(env)
    result = subprocess.run(
        [binary, "-e", "-o", "pipefail", "-c", "PATH=; " + script],
        capture_output=True, timeout=20, env=child)
    assert result.returncode == rc, (result.returncode, result.stdout, result.stderr)
    err = result.stderr.decode(errors="replace")
    assert "AddressSanitizer" not in err and "runtime error:" not in err, err
    checks += 1
    return result.stdout


with tempfile.TemporaryDirectory(prefix="vt-buf-edges-") as tmp:
    d = Path(tmp)
    run(r"""
vt new -h v -W 8 -H 2
vt feed "$v" $'\e[c'
# Bind in this shell. A command substitution would drain a forked copy
# and leave the parent's reply in place for the clone.
vt response "$v" -V first
[[ -n "$first" ]]
vt clone "$v" -h c
vt feed "$c" $'\e[c'
vt response "$c" -V second
[[ "$second" == "$first" ]]
vt free "$c"
vt free "$v"
""")

    marks = "e" + ("\u0301" * 32)
    run(r"""
vt new -h v -W 4 -H 2
vt scrollback-enable "$v" -L 4
vt feed "$v" "$MARKS"$'\r\n'"$MARKS"$'\r\n'"$MARKS"$'\r\n'
diff=$(vt diff "$v")
[[ $diff == *"$MARKS"* ]]
row=$(vt scrollback-row "$v" 0)
[[ $row == "0 $MARKS" ]]
render=$(vt scrollback-render "$v")
[[ $render == *"$MARKS"* ]]
vt free "$v"
""", env={"MARKS": marks})

    run(r"""
vt new -h v -W 4 -H 2
nines=$(printf '9%.0s' {1..20})
vt feed "$v" $'\e['"$nines"H
vt cursor "$v" >/dev/null
vt free "$v"
""")

    original = d / "original"
    original.write_bytes(b"alpha\nbeta\n")
    env = {"TEST_DIR": str(d)}
    run(r"""
buf new -h b
buf load "$b" "$TEST_DIR/original"
buf insert-line "$b" 0 gamma
buf load "$b" "$TEST_DIR/original"
[[ $(buf line "$b" 0) == alpha ]]
buf save "$b"
buf free "$b"
[[ $(cat "$TEST_DIR/original") == $'alpha\nbeta' ]]
""", env=env)
    assert original.read_bytes() == b"alpha\nbeta\n"

print(f"vt-buf-edges: {checks} checks passed")
