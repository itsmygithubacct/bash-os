#!/usr/bin/env python3
"""Independently compare two bash-gnu-parity.sh runs, including fixture trees.

Usage: python3 tests/compare-parity.py GNU-RESULT-DIR BASHOS-RESULT-DIR
Raw stdout bytes, status, and filesystem contents/modes/link topology must match.
Successful cases require empty stderr. Error cases require diagnostics but their
wording may differ. Timestamps, inode values and directory sizes are not compared.
"""
import argparse
import base64
import json
from pathlib import Path
import stat


def snapshot(root):
    cache = root.parent / "tree.json"
    if root.is_symlink():
        raise ValueError("A fixture tree must not be a symlink")
    if not root.exists():
        return json.loads(cache.read_text())
    result, links = {}, {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        info = path.lstat()
        entry = {"mode": stat.S_IMODE(info.st_mode)}
        if path.is_symlink():
            entry.update(kind="symlink", target=str(path.readlink()))
        elif stat.S_ISDIR(info.st_mode):
            entry.update(kind="directory")
        elif stat.S_ISREG(info.st_mode):
            group = links.setdefault((info.st_dev, info.st_ino), name)
            entry.update(kind="file", hardlink=group,
                         data=base64.b64encode(path.read_bytes()).decode("ascii"))
        else:
            raise ValueError(f"Unexpected fixture type: {name}")
        result[name] = entry
    cache.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    for root in (args.reference, args.candidate):
        if (root / "suite").read_text() != "bash-gnu-parity-v1\n":
            raise ValueError("Unknown suite")
        if (root / "complete").read_text() != "complete\n":
            raise ValueError("Incomplete run")
    catalog = (args.reference / "catalog.tsv").read_text()
    if catalog != (args.candidate / "catalog.tsv").read_text():
        raise ValueError("The two runs used different cases")
    results = []
    for line in catalog.splitlines():
        name, expected, diagnostic = line.split("\t")
        left = args.reference / "cases" / name
        right = args.candidate / "cases" / name
        if (left / "command").read_bytes() != (right / "command").read_bytes():
            raise ValueError(f"Different commands for {name}")
        a, b = int((left / "status").read_text()), int((right / "status").read_text())
        differences = []
        if a != int(expected):
            differences.append(f"reference exit {a}, expected {expected}")
        if b != a:
            differences.append(f"exit: GNU={a}, bash-os={b}")
        if (left / "stdout").read_bytes() != (right / "stdout").read_bytes():
            differences.append("stdout bytes")
        stderr_a = (left / "stderr").read_bytes()
        stderr_b = (right / "stderr").read_bytes()
        if diagnostic == "diagnostic":
            if not stderr_a or not stderr_b:
                differences.append("missing error diagnostic")
        elif stderr_a or stderr_b:
            differences.append("unexpected stderr")
        tree_a, tree_b = snapshot(left / "tree"), snapshot(right / "tree")
        if tree_a != tree_b:
            differences.append("filesystem contents/modes/links")
        record = {"case": name, "passed": not differences, "differences": differences,
                  "reference_status": a, "candidate_status": b,
                  "reference_tree": tree_a, "candidate_tree": tree_b}
        results.append(record)
        print(f'{"PASS" if not differences else "FAIL"} {name}'
              + (": " + "; ".join(differences) if differences else ""))
    failed = sum(not item["passed"] for item in results)
    report = {"total": len(results), "passed": len(results) - failed,
              "failed": failed, "cases": results}
    (args.candidate / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f'\nParity: {report["passed"]}/{report["total"]} passed; {failed} differences')
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
