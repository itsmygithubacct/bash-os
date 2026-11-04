#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unicode's published break markers are the oracle, including U+0000."""
import argparse
import hashlib
from pathlib import Path
from guest import digest, entrypoint, guard, run, save

PIN = "e2d134d2c52919bace503ebb6a551c1855fe1a1faec18478c78fff254a1793ec"


def corpus(path):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError("Unicode 17 corpus hash mismatch")
    rows = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        if tokens[0] != "÷" or tokens[-1] != "÷" or len(tokens) % 2 != 1:
            raise ValueError("malformed boundary row")
        data, offsets = bytearray(), []
        for i, token in enumerate(tokens):
            if i % 2 == 0:
                if token not in ("÷", "×"):
                    raise ValueError("missing boundary token")
                if token == "÷": offsets.append(len(data))
            else:
                data.extend(chr(int(token, 16)).encode("utf-8"))
        clusters = [bytes(data[a:b]) for a, b in zip(offsets, offsets[1:])]
        rows.append({"line": number, "hex": data.hex(), "nul": 0 in data,
                     "offsets": offsets, "clusters": [s.hex() for s in clusters]})
    if len(rows) != 766 or sum(r["nul"] for r in rows) != 74:
        raise ValueError("unexpected corpus partition")
    return rows


def expected(row):
    return (str(len(row["clusters"])) + "\t" +
            ",".join(map(str, row["offsets"])) + "\t" +
            ",".join(row["clusters"]) + "\n").encode()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("corpus"); p.add_argument("probe"); p.add_argument("truncating_control")
    p.add_argument("output")
    a = p.parse_args(); guard()
    rows = corpus(a.corpus)
    # Hand-specified protocol controls, independent of either segmenter.
    controls = [dict(hex="", offsets=[0], clusters=[]),
                dict(hex="6162", offsets=[0,1,2], clusters=["61","62"]),
                dict(hex="0d0a", offsets=[0,2], clusters=["0d0a"]),
                dict(hex="610062", offsets=[0,1,2,3], clusters=["61","00","62"])]
    inputs = controls + rows
    data = "".join(r["hex"] + "\n" for r in inputs).encode()
    oracle = b"".join(expected(r) for r in inputs)
    real = run([a.probe], data)
    bad = run([a.truncating_control], data)
    actual = bytes.fromhex(real["stdout_hex"]).splitlines(keepends=True)
    bad_lines = bytes.fromhex(bad["stdout_hex"]).splitlines(keepends=True)
    shape = len(actual) == len(inputs) and len(bad_lines) == len(inputs)
    detected = shape and all(bad_lines[i+4] != expected(r) for i,r in enumerate(rows) if r["nul"])
    # The adapter must leave non-NUL inputs unchanged. Compare its output with
    # the real probe here, not with Unicode: a genuine segmentation error must
    # remain a product FAIL rather than being hidden as a broken control.
    no_false_alarm = shape and all(bad_lines[i+4] == actual[i+4] for i,r in enumerate(rows) if not r["nul"])
    result = "ERROR"
    if real["status"] == bad["status"] == 0 and not real["stderr_hex"] and not bad["stderr_hex"] and detected and no_false_alarm:
        result = "PASS" if bytes.fromhex(real["stdout_hex"]) == oracle else "FAIL"
    save(a.output, dict(scope="rebuilt length-aware libgrapheme; never frozen utf8 TEXT evidence",
                        result=result, corpus_sha256=PIN, total=766, nul=74,
                        input_sha256=hashlib.sha256(data).hexdigest(),
                        oracle_sha256=hashlib.sha256(oracle).hexdigest(),
                        binaries={a.probe:digest(a.probe), a.truncating_control:digest(a.truncating_control)},
                        truncation_detected=detected, non_nul_control_unchanged=no_false_alarm,
                        candidate=real, negative_control=bad,
                        mismatches=[r.get("line", "control") for i,r in enumerate(inputs)
                                    if i >= len(actual) or actual[i] != expected(r)]))
    return {"PASS":0,"FAIL":1,"ERROR":125}[result]


if __name__ == "__main__":
    entrypoint(main)
