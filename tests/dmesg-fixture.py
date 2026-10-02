#!/usr/bin/env python3
"""Regression checks for dmesg's regular-file /dev/kmsg fixture reader."""

import os
import subprocess
import sys
import tempfile


def main():
    bash = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "out/bash")
    first = b"7,1,1000000;"
    # Put the next record's two-byte prefix at the end of dmesg's 8192-byte
    # read buffer, forcing the fixture reader to join data from two reads.
    filler = first + b"x" * (8190 - len(first) - 1) + b"\n"
    split_record = b"0,2,2000000;split record\n"
    with tempfile.NamedTemporaryFile() as fixture:
        fixture.write(filler + split_record)
        fixture.flush()
        env = os.environ.copy()
        env["BASHDMESG_DEV_KMSG_FILE"] = fixture.name
        proc = subprocess.run(
            [bash, "-c", "dmesg -l emerg"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    expected = "[    2.000000] split record\n"
    if proc.stdout != expected:
        raise SystemExit(
            f"dmesg split-record mismatch: expected {expected!r}, got {proc.stdout!r}; "
            f"stderr={proc.stderr!r}"
        )
    with tempfile.NamedTemporaryFile() as fixture:
        fixture.write(b"0,3,3000000;final record")
        fixture.flush()
        env["BASHDMESG_DEV_KMSG_FILE"] = fixture.name
        proc = subprocess.run(
            [bash, "-c", "dmesg -l emerg"], env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
    if proc.stdout != "[    3.000000] final record\n":
        raise SystemExit(f"dmesg unterminated record mismatch: {proc.stdout!r}")
    print("dmesg fixture split-record check: passed")


if __name__ == "__main__":
    main()
