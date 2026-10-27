#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a traceable parity inventory from source and fixtures, without execution."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def catalog(path):
    return dict(line.partition("|")[::2] for raw in path.read_text().splitlines()
                if (line := raw.strip()) and not line.startswith("#"))


def array_names(path, name):
    text = path.read_text()
    block = text.split(name + "[] = {", 1)[1].split("\n};", 1)[0]
    return sorted(set(re.findall(r'\{\s*"([a-zA-Z0-9_-]+)"', block)))


# Comments are dropped first so prose such as "getopt(1)" is not read as a parser call.
COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
PARSER = re.compile(r"\b(internal_getopt|getopt_long|getopt)\s*\(([^;]*?)\)", re.S)


def parser_options(text):
    """Option strings from getopt-style calls; None when the parser is manual."""
    calls = PARSER.findall(COMMENTS.sub(" ", text))
    if not calls:
        return None, "manual parser: options not extractable from source; empty is not 'no options'"
    strings = sorted({literal for _, args in calls for literal in re.findall(r'"([^"\n]*)"', args)[:1]})
    if not strings:
        return None, "getopt-style call without a literal option string; manual review required"
    return strings, "literal getopt-style option strings; long options and argument grammar need manual review"


def generate(bash, interfaces=None):
    full = catalog(REPO / "config/bash-loadables.list")
    optional = catalog(REPO / "config/bash-loadables-optional.list")
    suites = {s["loadable"]: (p, s) for p in sorted((REPO / "tests/loadable-parity/suites").glob("*.json"))
              for s in [json.loads(p.read_text())]}
    modern = [c for p in sorted((REPO / "tests/parity-vm/suites").glob("*.json"))
              for c in json.loads(p.read_text())["cases"]]
    links = {}
    for c in modern:
        for topic in c.get("covers", []):
            links.setdefault(topic, []).append(c["id"])
    ledger_path = REPO / "tests/parity-vm/deferrals.json"
    ledger = None
    review_by_topic = {}
    if ledger_path.exists():
        import deferrals as review
        ledger = json.loads(ledger_path.read_text())
        review.validate(ledger, REPO)
        review_by_topic = {entry["topic"]: entry for entry in ledger["entries"]}
    commands, deferrals, migrations = [], [], []
    for name, synopsis in sorted((full | optional).items()):
        path, suite = suites.get(name, (None, {}))
        cases = suite.get("cases", [])
        source = REPO / "loadables" / (name + ".c")
        upstream = bash / "examples/loadables" / (name + ".c")
        if not source.is_file():
            source = upstream
        text = source.read_text(errors="replace") if source.is_file() else ""
        declarations, extraction = parser_options(text)
        item = {"name": name, "profile": "optional" if name in optional else "full",
                "synopsis": synopsis, "source_sha256": sha(source) if source.is_file() else None,
                "reference_description": suite.get("reference"),
                "fixture": str(path.relative_to(REPO)) if path else None,
                "fixture_sha256": sha(path) if path else None,
                "case_counts": dict(Counter(c["kind"] for c in cases)),
                "cases": [{"id": c["id"], "kind": c["kind"], "purpose": c["purpose"],
                           "reference_commands": c.get("requires", [])} for c in cases],
                "vm_cases": [c["id"] for c in modern if c["loadable"] == name],
                "declared_coverage": suite.get("coverage", []), "exclusions": suite.get("exclusions", []),
                "parser_option_strings": declarations,
                "option_extraction": extraction,
                "option_inventory_status": "synopsis/parser extraction; manual per-option review remains open",
                "validation_status": "see separately hashed execution reports; inventory is not a pass"}
        commands.append(item)
        for c in cases:
            topic = name + "/" + c["id"]
            reviewed = review_by_topic.get(topic)
            if c["kind"] == "deferred":
                deferrals.append({"topic": topic, "purpose": c["purpose"], "reason": c["reason"],
                                  "related_vm_cases": links.get(topic, []), "status": "DEFERRED",
                                  "review_coverage": reviewed["coverage"] if reviewed else "unreviewed",
                                  "remaining_requirements": [r["behavior"] for r in reviewed["requirements"]
                                                             if r["coverage"] != "covered"] if reviewed else [],
                                  "resolution": "See the requirement-level deferral review and execution evidence."
                                      if reviewed else "Not reviewed against execution evidence."})
            elif reviewed and reviewed.get("migration"):
                migrations.append({"topic": topic, "purpose": reviewed["original"]["purpose"],
                                   "mode": reviewed["migration"], "status": "MIGRATED",
                                   "replacement_cases": c.get("replacement_cases", [
                                       {"group": "legacy", "id": "legacy/" + topic}]),
                                   "counting": "Index into executed checks; not an additional behavioral pass."})
    builtins, help_topics = {}, {}
    for path in sorted((bash / "builtins").glob("*.def")):
        name, function, synopsis = None, None, None
        for line in path.read_text(errors="replace").splitlines():
            if line.startswith("$BUILTIN "):
                name = line.removeprefix("$BUILTIN ").strip()
                function, synopsis = None, None
            elif line.startswith("$FUNCTION "):
                function = line.removeprefix("$FUNCTION ").strip()
            elif name and line.startswith("$SHORT_DOC "):
                synopsis = line.removeprefix("$SHORT_DOC ")
            elif line == "$END" and name and synopsis:
                (builtins if function else help_topics).setdefault(name, []).append(synopsis)
    manual = (bash / "doc/bashref.texi").read_text()
    domains = [line.removeprefix("@node ").split(",")[0].strip()
               for line in manual.splitlines() if line.startswith("@node ")]
    variable_section = manual.split("@node Bourne Shell Variables", 1)[1].split("@node Bash Features", 1)[0]
    variables = sorted(set(re.findall(r"^@item ([A-Za-z_][A-Za-z_0-9]*)(?:\s|$)", variable_section, re.M)))
    report = {"schema": 1, "project_version": (REPO / "VERSION").read_text().strip(),
            "claim": "scope inventory, not complete parity qualification",
            "inputs": {"versions_sha256": sha(REPO / "config/versions.sh"),
                       "catalog_sha256": sha(REPO / "config/bash-loadables.list"),
                       "optional_sha256": sha(REPO / "config/bash-loadables-optional.list"),
                       "vm_fixture_sha256": {p.name: sha(p) for p in sorted((REPO / "tests/parity-vm/suites").glob("*.json"))},
                       "bash_patchlevel_sha256": sha(bash / "patchlevel.h"),
                       "bash_manual_sha256": sha(bash / "doc/bashref.texi")},
            "totals": {"full_commands": len(full), "optional_commands": len(optional),
                       "legacy_suites": len(suites), "legacy_cases": sum(len(s[1]["cases"]) for s in suites.values()),
                       "legacy_deferred": len(deferrals), "migrated_topics": len(migrations),
                       "vm_cases": len(modern),
                       "native_bash_builtin_names": len(builtins)},
            "commands": commands, "deferrals": deferrals, "migrations": migrations,
            "bash": {"builtin_synopses": {k: sorted(set(v)) for k, v in sorted(builtins.items())},
                     "reserved_word_help_topics": {k: sorted(set(v)) for k, v in sorted(help_topics.items())},
                     "set_options": array_names(bash / "builtins/set.def", "o_options"),
                     "shopt_options": array_names(bash / "builtins/shopt.def", "shopt_vars"),
                     "invocation_long_options": array_names(bash / "shell.c", "long_args"),
                     "manual_domains": domains, "documented_variables": variables,
                     "status": "source inventory includes conditional features; use guest runtime metadata to confirm availability",
                     "shell_fixtures": [c["id"] for c in modern if c["loadable"] == "bash"]},
            "open_dimensions": {
                "interface": ["every option and operand form", "short option clustering", "long aliases and abbreviations",
                              "-- and leading-dash filenames", "missing/extra/invalid arguments", "option ordering and conflicts",
                              "help/version contract and branding", "diagnostic bytes under pinned locale"],
                "observable": ["stdout/stderr bytes including NUL", "status and signals", "file data/types/modes/owners",
                               "ACLs/xattrs/timestamps/hardlinks/symlinks", "descriptor offsets and inheritance",
                               "atomicity and failure rollback", "interactive screen/cursor/modes", "wire bytes and peer state"],
                "environment": ["static/dynamic", "build profiles and optional commands", "C/C.UTF-8/non-English locales",
                                "timezone/DST", "UTF-8 invalid/truncated sequences", "empty/large/binary inputs",
                                "TTY sizes and TERM variants", "pipe/file/PTY stdin", "umask and permissions",
                                "synthetic users/groups", "filesystems and mount flags", "architecture/word size",
                                "kernel capability/device variants", "POSIX and Bash compatibility modes"],
                "unresolved": ["upstream Bash regression corpus integration", "all GNU Coreutils commands including absent candidates",
                               "per-option reference inventory and evidence mapping", "fault injection and non-loopback protocols",
                               "privileged device/kernel behavior using synthetic VM resources only"]}}
    if ledger:
        report["deferral_review"] = {"file": str(ledger_path.relative_to(REPO)),
                                    "sha256": sha(ledger_path), "original_topics": ledger["original_count"],
                                    "coverage": dict(Counter(e["coverage"] for e in ledger["entries"])),
                                    "claim": "Reviewed obligations; execution results are recorded separately."}
    if interfaces:
        observed = json.loads(interfaces.read_text())
        report["runtime_inventory_sha256"] = sha(interfaces)
        report["reference_packages"] = observed["packages"]
        report["gnu_coreutils"] = [{"name": c["name"], "candidate_builtin": c["candidate_builtin"],
                                   "reference_option_tokens": c.get("reference_option_tokens", []),
                                   "reference_help": c.get("gnu_help"), "status": "behavioral mapping required"}
                                  for c in observed["commands"] if c["gnu_coreutils"]]
        report["coreutils_without_candidate_builtin"] = observed["coreutils_without_candidate_builtin"]
        report["runtime_shells"] = observed["shells"]
        report["totals"]["gnu_coreutils_commands"] = len(report["gnu_coreutils"])
        report["totals"]["gnu_coreutils_missing_builtins"] = len(report["coreutils_without_candidate_builtin"])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interfaces", type=Path, help="VM results/inventory/interfaces.json, read as data")
    args = parser.parse_args()
    report = generate(args.bash_source, args.interfaces)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps(report["totals"], sort_keys=True))


if __name__ == "__main__":
    main()
