#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent Argon2id PHC checker: recomputes the digest with `openssl kdf` and compares it."""
import base64
import re
import subprocess
import sys


def b64(text):
    value = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    if base64.b64encode(value).rstrip(b"=").decode("ascii") != text:
        raise ValueError("noncanonical PHC base64")
    return value


def phc_for(path, user):
    for line in open(path, encoding="ascii"):
        fields = line.rstrip("\n").split(":")
        if fields and fields[0] == user:
            return fields[1]
    raise SystemExit("no shadow entry for " + user)


def matches(phc, password):
    parts = phc.split("$")
    if len(parts) != 6 or parts[1] != "argon2id" or parts[2] != "v=19":
        return False
    params = dict(item.split("=") for item in parts[3].split(","))
    # Legacy fixtures use hex; newly generated PHC fields use unpadded base64.
    # The project's fixed 32-byte hash distinguishes the old 64-digit encoding.
    if re.fullmatch(r"[0-9a-fA-F]{64}", parts[5]):
        salt, digest = bytes.fromhex(parts[4]), bytes.fromhex(parts[5])
    else:
        salt, digest = b64(parts[4]), b64(parts[5])
    if not 8 <= len(salt) <= 64 or len(digest) != 32:
        return False
    command = ["/usr/bin/openssl", "kdf", "-keylen", str(len(digest)), "-binary",
               "-kdfopt", "pass:" + password, "-kdfopt", "hexsalt:" + salt.hex(),
               "-kdfopt", "iter:" + params["t"], "-kdfopt", "memcost:" + params["m"],
               "-kdfopt", "lanes:" + params["p"], "ARGON2ID"]
    out = subprocess.run(command, capture_output=True, check=True).stdout
    return out == digest


def main():
    mode = sys.argv[1]
    if mode == "match":          # match FILE USER PASSWORD -> prints match|differ
        print("match" if matches(phc_for(sys.argv[2], sys.argv[3]), sys.argv[4]) else "differ")
    else:
        raise SystemExit("usage: mig-w5-phc-check.py match FILE USER PASSWORD")


if __name__ == "__main__":
    main()
