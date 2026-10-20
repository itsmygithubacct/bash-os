#!/usr/bin/env python3
"""Independent byte oracles for vi tail deletion, fragmented saves and errors.

Run with a vi-only Bash build. nvim is required, with nofixeol/startofline.
The reference uses headless scripts only for cases without undo; interactive
undo comparisons live in opus-vi-dd.py. This script never compiles or times.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

BINARY = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
NVIM = shutil.which("nvim")
assert NVIM, "nvim is required for sol-vi-delete.py"
checks = 0
references = 0


def shell(script, *args, rc=0):
    global checks
    env = {**os.environ, "LC_ALL": "C", "TZ": "UTC", "PATH": ""}
    if os.environ.get("HELPER_LOAD_ENV"):
        env.update(BASH_ENV=os.environ["HELPER_LOAD_ENV"],
                   LD_PRELOAD=os.environ["HELPER_ASAN_LIB"],
                   ASAN_OPTIONS="detect_leaks=0:abort_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    p = subprocess.run([BINARY, "--noprofile", "--norc", "-c", script,
                        "_", *map(str, args)], env=env, capture_output=True,
                       timeout=60, start_new_session=True)
    assert p.returncode == rc, (script, p.returncode, rc, p.stderr)
    assert b"AddressSanitizer" not in p.stderr and b"runtime error:" not in p.stderr, p.stderr
    checks += 1
    return p


def check(d, name, data, keys, expected, ex=None, binary=False):
    global references
    src, keyfile, output = (d / n for n in ("input", "keys", "output"))
    src.write_bytes(data)
    output.unlink(missing_ok=True)
    keyfile.write_bytes(keys + b":w " + bytes(output) + b"\r:q!\r")
    shell('vi "$@"', *(["-b"] if binary else []), "--keys", keyfile, src)
    assert output.read_bytes() == expected, (name, "keys", output.read_bytes(), expected)
    assert src.read_bytes() == data, (name, "source changed")
    if ex is not None:
        output.unlink()
        script = d / "ex"
        script.write_text("\n".join([*ex, f"w {output}", "q!", ""]))
        shell('vi "$@"', *(["-b"] if binary else []), "-s", script, src)
        assert output.read_bytes() == expected, (name, "ex", output.read_bytes(), expected)
    output.unlink()
    keyfile.write_bytes(keys + b":w! " + bytes(output) + b"\r:q!\r")
    p = subprocess.run([NVIM, "--headless", "-u", "NONE", "-i", "NONE", "-n",
                        *(["-b"] if binary else []), "-c", "set nofixeol sol",
                        "-s", str(keyfile), str(src)], capture_output=True, timeout=60)
    assert p.returncode == 0, (name, "nvim", p.returncode, p.stderr)
    assert output.read_bytes() == expected, (name, "nvim", output.read_bytes(), expected)
    references += 1


with tempfile.TemporaryDirectory(prefix="sol-vi-test-") as tmp:
    d = Path(tmp)
    # A missing final newline and a blank penultimate line must retain that
    # blank line in memory after deleting the last nonempty line.
    check(d, "noeol-blank-tail", b"a\n\nb", b"Gdddd", b"a",
          ["$", "d", "d"])
    for binary in (False, True):
        for eol in (False, True):
            for n in (0, 1, 2, 3, 6):
                lines = [(b"" if i % 2 else
                          (b"\x00\xff" if binary else "界é".encode()) + str(i).encode())
                         for i in range(n)]
                # An initial file cannot distinguish a trailing empty line
                # without EOL from the preceding line's terminating newline.
                if lines:
                    lines[-1] += b"last"
                data = b"\n".join(lines) + (b"\n" if eol and lines else b"")
                for count in sorted({0, 1, 2, n, n + 2}):
                    remaining = lines[:max(0, n - count)]
                    want = b"\n".join(remaining) + (b"\n" if eol and remaining else b"")
                    check(d, f"matrix-{binary}-{eol}-{n}-{count}", data,
                          b"G" + b"dd" * count, want, ["$"] + ["d"] * count, binary)
    print("sol-vi: tail matrix passed", flush=True)

    # 250 actual edits, including the empty unterminated tail at an
    # intermediate step. Check the entire remaining prefix, not just a size.
    for eol in (False, True):
        lines = [(b"" if i % 5 == 3 else f"{i:04d}:payload".encode()) for i in range(1000)]
        data = b"\n".join(lines) + (b"\n" if eol else b"")
        remaining = lines[:750]
        want = b"\n".join(remaining) + (b"\n" if eol else b"")
        check(d, f"250-deletes-{eol}", data, b"G" + b"dd" * 250, want,
              ["$"] + ["d"] * 250)

    # Many ORIG/ADD piece boundaries survive the 250 deletes. Saving over
    # the mapped input and then continuing must still use valid old mappings.
    lines = [f"line-{i:04d}".encode() for i in range(1000)]
    data = b"\n".join(lines) + b"\n"
    edits = b""
    for i in range(0, 1000, 37):
        edits += str(i + 1).encode() + b"GiADD-\x1b"
        lines[i] = b"ADD-" + lines[i]
    want = b"\n".join(lines[:750]) + b"\n"
    check(d, "fragmented-250", data, edits + b"G" + b"dd" * 250, want)
    src, k = d / "mapped", d / "mapped-keys"
    src.write_bytes(data)
    k.write_bytes(edits + b":w\rG" + b"dd" * 250 + b":w\rdd:wq\r")
    shell('vi --keys "$1" "$2"', k, src)
    assert src.read_bytes() == b"\n".join(lines[:749]) + b"\n"
    print("sol-vi: exact 250-delete and fragmented mmap/save checks passed", flush=True)

    # A directory as the destination exercises rename failure AFTER a
    # temporary file was created and synced, without privileged fixtures.
    dest = d / "destination-directory"
    dest.mkdir()
    (dest / "sentinel").write_bytes(b"keep")
    src.write_bytes(b"a\nb\nc\n")
    k.write_bytes(b"Gdd:w " + bytes(dest) + b"\r:q!\r")
    shell('vi --keys "$1" "$2"', k, src, rc=1)
    assert src.read_bytes() == b"a\nb\nc\n"
    assert (dest / "sentinel").read_bytes() == b"keep"
    assert not list(d.glob("*.tmp.*"))
    k.write_bytes(b"Gdd:w " + bytes(dest) + b"\r:wq " + bytes(d / "after-error") + b"\r")
    shell('vi --keys "$1" "$2"', k, src, rc=1)
    assert (d / "after-error").read_bytes() == b"a\nb\n"
    # Restore the failure-only script for the descriptor loop.
    k.write_bytes(b"Gdd:w " + bytes(dest) + b"\r:q!\r")

    # Repeated failures, empty-PATH native dispatch, descriptor stability,
    # and a successful invocation after failure in the same shell.
    p = shell(r'''
fds() { local n=0 f; for f in /proc/$$/fd/*; do n=$((n+1)); done; echo "$n"; }
before=$(fds)
for ((i=0;i<20;i++)); do
    vi --keys "$1" "$2" && exit 9
    vi -c '$d' -c "w $3" -c 'q!' "$2" 2>/dev/null && exit 10
done
vi -c '$d' -c "w $4" -c 'q!' "$2" || exit 11
after=$(fds)
[[ $before == "$after" ]] || exit 12
type -t vi
''', k, src, dest, d / "recovered")
    assert p.stdout == b"builtin\n", p.stdout
    assert (d / "recovered").read_bytes() == b"a\nb\n"
    assert not list(d.glob("*.tmp.*"))
    assert (dest / "sentinel").read_bytes() == b"keep"

    # Limit only the owned child. Ignoring SIGXFSZ makes the real write()
    # return EFBIG, exercising cleanup after a partial temporary-file write.
    src.write_bytes(b"long line\n" * 1000)
    p = shell(r'''
trap '' XFSZ
ulimit -f 1
vi -c '$d' -c 'w' -c 'q!' "$1"
''', src, rc=1)
    assert b"E212: write failed" in p.stderr, p.stderr
    assert src.read_bytes() == b"long line\n" * 1000
    assert not list(d.glob("*.tmp.*"))

print(f"sol-vi-delete: {checks} builtin checks, {references} nvim comparisons, 0 skipped")
