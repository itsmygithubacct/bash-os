#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent Argon2id PHC checker: recomputes the digest with `openssl kdf` and compares it."""
import base64
import subprocess
import sys


def b64(text):
    return base64.b64decode(text + "=" * (-len(text) % 4))


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
    salt, digest = bytes.fromhex(parts[4]), bytes.fromhex(parts[5])  # this product stores salt and hash as hex
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
