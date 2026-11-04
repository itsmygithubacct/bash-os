#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only source preparation; never builds or executes candidate code."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re


def key_table(source):
    body = source.split("static const bw_keydef bw_keys[] = {", 1)[1].split("\n};", 1)[0]
    rows = re.findall(r'\{\s*"([^"]+)",\s*([^,]+),\s*("(?:[^"\\]|\\.)*")\s*\}', body)
    if len(rows) != 34:
        raise ValueError("review required: original key table changed")
    return [{"name":name, "code":code.strip(), "hex":ast.literal_eval(seq).encode("ascii").hex()}
            for name, code, seq in rows]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("output"); a = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    out = Path(a.output).resolve(); out.mkdir(parents=True, exist_ok=False)
    source = (root / "loadables/wgetch.c").read_text()
    keys = key_table(source)
    pairs = [(a["hex"],b["hex"]) for a in keys for b in keys
             if len(a["hex"]) < len(b["hex"]) and b["hex"].startswith(a["hex"])]
    if pairs: raise ValueError("original table is no longer prefix-free")
    anchor = "static const bw_keydef bw_keys[] = {\n"
    extension = ('  { "qualification_short", 0x700, "\\033[9" },\n'
                 '  { "qualification_long", 0x701, "\\033[9~" },\n')
    if source.count(anchor) != 1: raise ValueError("table anchor changed")
    (out / "wgetch-original.c").write_text(source)
    (out / "wgetch-extended.c").write_text(source.replace(anchor, anchor + extension, 1))
    hashes = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
              for p in [root / ("loadables/"+n+".c") for n in
                        ("bashpoll","dmesg","tput","utf8","vec","wgetch")]}
    manifest = dict(scope="qualification variants, never unchanged release evidence",
                    source_sha256=hashes, original_keys=keys, proper_prefix_pairs=pairs,
                    test_keys=[{"hex":"1b5b39","code":1792},{"hex":"1b5b397e","code":1793}],
                    generated_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in out.glob("*.c")})
    (out / "inputs.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__": main()
