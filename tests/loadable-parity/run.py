#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run reviewed JSON fixtures through the mandatory isolated parity runner."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from runner import run_suite, validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suites", nargs="*", type=Path,
                        help="JSON files or directories (default: regressions)")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory for raw evidence and summary.json")
    args = parser.parse_args()
    paths = args.suites or [Path(__file__).resolve().parent / "regressions"]
    files = sorted({p.resolve() for path in paths
                    for p in (path.glob("*.json") if path.is_dir() else [path])})
    if not files:
        parser.error("no fixture files found")
    suites = []
    for path in files:
        data = path.read_bytes()
        suite = validate(json.loads(data))
        suites.append((path, suite, hashlib.sha256(data).hexdigest()))
    counts = Counter(suite["loadable"] for _, suite, _ in suites)
    binary = args.binary.resolve(strict=True)
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    totals = dict.fromkeys(("PASS", "FAIL", "ERROR", "SKIP", "DEFERRED", "MIGRATED"), 0)
    by_kind = {kind: totals.copy() for kind in ("parity", "contract", "deferred", "migrated")}
    reports = []
    for index, (path, suite, digest) in enumerate(suites, 1):
        loadable = suite["loadable"]
        evidence = Path(loadable)
        if counts[loadable] > 1:
            evidence /= f"{index:04d}-{path.stem}"
        report = run_suite(suite, binary, output / evidence)
        report["evidence_directory"] = str(evidence)
        report["fixture_name"] = path.name
        report["fixture_sha256"] = digest
        reports.append(report)
        for status, count in report["summary"].items():
            totals[status] += count
        for case in report["cases"]:
            by_kind[case["kind"]][case["status"]] += 1
    unchanged = hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash
    summary = {"binary_sha256": binary_hash, "binary_unchanged": unchanged,
               "summary": totals, "by_kind": by_kind, "suites": reports}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"summary": totals, "by_kind": by_kind,
                      "binary_unchanged": unchanged}, sort_keys=True))
    return int(bool(totals["FAIL"] or totals["ERROR"] or not unchanged))


if __name__ == "__main__":
    raise SystemExit(main())
