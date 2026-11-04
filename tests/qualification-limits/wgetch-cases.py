#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Predeclared temporal contracts for a test-only exact/longer pair."""
import argparse
from pathlib import Path
from guest import clean_env, digest, entrypoint, guard, run, save

# Neither expected output nor expected deadlines are read from candidate code.
COMMON = [
    ("lone", "0 1b\n", 1, b"27 50 1\n"),
    ("up_within", "0 1b\n20 5b\n20 41\n", 1, b"257 20 3\n"),
    ("up_after", "0 1b\n80 5b\n80 41\n", 3, b"27 50 1\n91 80 2\n65 80 3\n"),
]
AMBIGUOUS = [
    ("short_silence", "0 1b\n0 5b\n0 39\n", 1, b"1792 50 3\n"),
    ("long_within", "0 1b\n0 5b\n0 39\n20 7e\n", 1, b"1793 20 4\n"),
    ("long_after", "0 1b\n0 5b\n0 39\n80 7e\n", 2, b"1792 50 3\n126 80 4\n"),
    ("prefix_relative_slice", "0 1b\n20 5b\n40 39\n80 7e\n", 1, b"1793 80 4\n"),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("original_table_probe"); p.add_argument("extended_table_probe"); p.add_argument("output")
    a = p.parse_args(); guard()
    env = clean_env(); env["BASHESCDELAY"] = "50"
    rows = []
    for binary in (a.original_table_probe, a.extended_table_probe):
        for name, data, count, expected in COMMON + AMBIGUOUS:
            observation = run([binary, str(count)], data.encode(), env=env)
            observation.update(case=name, binary_sha256=digest(binary), expected_hex=expected.hex(),
                               matches=observation["stdout_hex"] == expected.hex())
            rows.append(observation)
    n = len(COMMON) + len(AMBIGUOUS)
    originals, extended = rows[:n], rows[n:]
    # Original table is a negative control for the proposed table prerequisite.
    controls = all(r["matches"] for r in originals[:len(COMMON)]) and all(
        not r["matches"] for r in originals[len(COMMON):])
    runnable = all(r["status"] == 0 and not r["stderr_hex"] for r in rows)
    result = "ERROR" if not (controls and runnable) else (
        "PASS" if all(r["matches"] for r in extended) else "FAIL")
    save(a.output, dict(scope="rebuilt reader with synthetic clock and test-only keys",
                        result=result, frozen_evidence=False, controls=controls, observations=rows))
    return {"PASS":0,"FAIL":1,"ERROR":125}[result]


if __name__ == "__main__":
    entrypoint(main)
