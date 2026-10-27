#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate fixture data without executing a candidate or reference command."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
GROUPS = {"shell", "terminal", "network", "reference", "legacy", "selfcheck", "inventory"}
DEFAULT_FILE_SIZE_LIMIT = 8 * 1024**2
MAX_FILE_SIZE_LIMIT = 128 * 1024**2


def check(condition, message):
    if not condition:
        raise ValueError(message)


def file_size_limit(case):
    value = case.get("file_size_limit", DEFAULT_FILE_SIZE_LIMIT)
    check(type(value) is int and DEFAULT_FILE_SIZE_LIMIT <= value <= MAX_FILE_SIZE_LIMIT,
          "file_size_limit must be an integer from 8 MiB through 128 MiB")
    return value


def blob(value):
    if isinstance(value, str):
        return value.encode()
    check(isinstance(value, dict) and set(value) == {"base64"}, "expected text or a base64 object")
    return base64.b64decode(value["base64"], validate=True)


def filename(name):
    check(isinstance(name, str) and name and "\0" not in name, "invalid fixture filename")
    path = PurePosixPath(name)
    check(not path.is_absolute() and ".." not in path.parts and str(path) == name and name != ".",
          "unsafe or noncanonical fixture filename: " + name)


def dimensions(value):
    check(isinstance(value, list) and len(value) == 2 and
          all(type(n) is int and 1 <= n <= 500 for n in value), "invalid terminal dimensions")


def validate(case):
    check(isinstance(case, dict), "case must be an object")
    for field in ("id", "loadable"):
        check(isinstance(case.get(field), str) and NAME.fullmatch(case[field]), "invalid " + field)
    check(case.get("group") in ("shell", "terminal", "network"), "invalid fixture group")
    check(case.get("driver") == {"shell": "plain", "terminal": "pty", "network": "network"}[case["group"]],
          "driver/group mismatch")
    check(case.get("kind", "parity") in ("parity", "contract"), "invalid kind")
    if "file_size_limit" in case:
        check(case["driver"] == "plain", "file_size_limit is supported only by the plain driver")
        file_size_limit(case)
    if "comparison" in case:
        check(isinstance(case["comparison"], str) and bool(case["comparison"].strip()),
              "comparison must describe the actual observations")
    if "helpers_sha256" in case:
        check(isinstance(case["helpers_sha256"], dict), "helpers_sha256 must be a mapping")
        for name, value in case["helpers_sha256"].items():
            filename(name)
            check(name.startswith("helpers/") and isinstance(value, str)
                  and re.fullmatch(r"[0-9a-f]{64}", value), "invalid helper digest")
    if "requires" in case:
        check(isinstance(case["requires"], list) and
              all(isinstance(name, str) and NAME.fullmatch(name) for name in case["requires"]),
              "requires must name guest executable dependencies")
    if "optional" in case:
        check(type(case["optional"]) is bool, "optional must be boolean")
    if "features" in case:
        check(isinstance(case["features"], list) and
              all(name in {"userns", "seccomp-notify"} for name in case["features"]),
              "unknown guest feature prerequisite")
    if "setup_script" in case:
        check(isinstance(case["setup_script"], str) and case["setup_script"].strip()
              and "\0" not in case["setup_script"], "invalid fixture setup script")
        check(type(case.get("setup_timeout", 30)) in (int, float)
              and 0 < case.get("setup_timeout", 30) <= 60, "setup timeout must be in (0, 60]")
    if "diagnostic_files" in case:
        names = case["diagnostic_files"]
        check(isinstance(names, list) and len(names) <= 16,
              "diagnostic_files must list at most 16 relative HOME paths")
        for name in names:
            filename(name)
        check(len(set(names)) == len(names), "duplicate diagnostic file")
    if case.get("kind") == "contract":
        check(isinstance(case.get("oracle"), str) and bool(case["oracle"].strip()),
              "contract needs an independent oracle description")
        check(any(k in case for k in ("stdout", "stderr", "stdout_base64", "stderr_base64")) or
              bool(case.get("expected_files")) or bool(case.get("expected_requests")) or
              any(set(step) & {"expect", "screen", "termios", "output_lacks"} for step in case.get("steps", [])),
              "contract needs observable expectations beyond exit status")
    check(type(case.get("expected_status")) is int and 0 <= case["expected_status"] <= 255,
          "expected_status must be explicit")
    check(type(case.get("timeout", 12)) in (int, float) and 0 < case.get("timeout", 12) <= 60,
          "timeout must be in (0, 60]")
    for key in ("interactive_shell", "restore_terminal", "compare_screen"):
        if key in case:
            check(type(case[key]) is bool, key + " must be boolean")
    for side in ("candidate", "reference"):
        if side == "reference" and case.get("kind") == "contract":
            continue
        if not case.get("interactive_shell"):
            script = case.get(side + "_script", case.get("script"))
            check(isinstance(script, str) and script and "\0" not in script, "missing/invalid " + side + " script")
    for key in ("stdin", "stdout", "stderr"):
        if key in case:
            check(isinstance(case[key], str), key + " must be text")
    for key in ("stdout_base64", "stderr_base64"):
        if key in case:
            base64.b64decode(case[key], validate=True)
    for key in ("files", "expected_files"):
        files = case.get(key, {})
        check(isinstance(files, dict) and len(files) <= 2048, "invalid " + key)
        size = 0
        for name, value in files.items():
            filename(name)
            size += len(blob(value))
        check(size <= 16 * 1024**2, "fixture data exceeds size limit")
    covers = case.get("covers", [])
    check(isinstance(covers, list) and all(isinstance(s, str) and s.count("/") == 1 for s in covers),
          "covers must name loadable/case topics")
    if case["driver"] == "pty":
        import terminal
        terminal.validate_case(case)
    if case["driver"] == "network":
        import network
        network.validate_case(case)
        check(isinstance(case.get("peer"), str) and NAME.fullmatch(case["peer"]), "invalid network peer")
        if "expected_requests" in case:
            check(isinstance(case["expected_requests"], list) and
                  all(isinstance(item, dict) for item in case["expected_requests"]), "invalid expected_requests")
        check(isinstance(case.get("compare_request_keys", []), list) and
              all(isinstance(k, str) for k in case.get("compare_request_keys", [])), "invalid request comparison keys")
    return case


def verify_helpers(case, harness):
    for name, expected in case.get("helpers_sha256", {}).items():
        filename(name)
        path = Path(harness) / name
        check(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
              "stale helper definition: " + name)


def load(directory):
    cases, hashes, seen = [], {}, set()
    for path in sorted(Path(directory).glob("*.json")):
        data = path.read_bytes()
        suite = json.loads(data)
        check(isinstance(suite, dict) and suite.get("schema") == 1 and isinstance(suite.get("cases"), list),
              "invalid suite: " + path.name)
        check(bool(suite["cases"]), "empty suite: " + path.name)
        hashes[path.name] = hashlib.sha256(data).hexdigest()
        for case in suite["cases"]:
            validate(case)
            verify_helpers(case, Path(directory).parent)
            if case.get("optional"):
                legacy = Path(directory).parent.parent / "loadable-parity/suites" / (case["loadable"] + ".json")
                check(legacy.is_file() and json.loads(legacy.read_text()).get("optional") is True,
                      "optional fixture must match the optional loadable catalog: " + case["loadable"])
            check(case["id"] not in seen, "duplicate fixture id: " + case["id"])
            seen.add(case["id"])
            cases.append(case)
    check(bool(cases), "no fixtures found")
    return cases, hashes


def select(cases, groups, case_ids=None):
    """Select an explicit bounded batch without silently dropping unknown IDs."""
    if case_ids is not None:
        check(bool(case_ids), "empty case selection")
        known = {case["id"]: case for case in cases}
        check(not (case_ids - known.keys()), "unknown case IDs: " + ",".join(sorted(case_ids - known.keys())))
        check(all(known[name]["group"] in groups for name in case_ids),
              "selected case belongs to an unselected group")
    return [case for case in cases if case["group"] in groups
            and (case_ids is None or case["id"] in case_ids)]


if __name__ == "__main__":
    cases, hashes = load(Path(__file__).parent / "suites")
    print(json.dumps({"validated_cases": len(cases), "fixture_sha256": hashes}, sort_keys=True))
