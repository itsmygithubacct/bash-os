#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Review historical deferrals against fixture definitions and saved VM evidence.

This module only reads data. A migrated topic is an index into executed checks,
not another behavioral pass. Missing evidence, partial requirements and skipped
or invalid reference checks cannot close a historical scenario.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tarfile

import schema


REPO = Path(__file__).resolve().parents[2]
EXECUTED = {"PASS", "FAIL"}
GROUPS = {"shell", "terminal", "network", "legacy", "reference"}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def key(reference):
    return reference["group"], reference["id"]


def definitions(repo):
    """Index individual definitions, so unrelated metadata cannot mask changes."""
    result, historical = {}, {}
    for path in sorted((repo / "tests/parity-vm/suites").glob("*.json")):
        for case in read(path)["cases"]:
            schema.verify_helpers(case, repo / "tests/parity-vm")
            name = (case["group"], case["id"])
            check(name not in result, "duplicate fixture: " + str(name))
            result[name] = case
    for path in sorted((repo / "tests/loadable-parity/suites").glob("*.json")):
        suite = read(path)
        for case in suite["cases"]:
            topic = suite["loadable"] + "/" + case["id"]
            historical[topic] = case
            if case["kind"] in {"parity", "contract"}:
                result[("legacy", "legacy/" + topic)] = case
    return result, historical


def reference_sources(repo):
    root = repo / "tests/parity-vm"
    return {str(path.relative_to(root)): file_digest(path)
            for path in [root / "references.py", *sorted((root / "references").glob("*"))]
            if path.is_file()}


def validate(ledger, repo=REPO):
    check(ledger.get("schema") == 1, "unsupported deferral ledger schema")
    entries = ledger.get("entries")
    check(isinstance(entries, list) and entries, "empty deferral review")
    check(len(entries) == ledger.get("original_count"), "original topic count changed")
    fixtures, historical = definitions(repo)
    topics = set()
    originals = []
    for entry in entries:
        topic = entry.get("topic")
        check(isinstance(topic, str) and topic.count("/") == 1 and topic not in topics,
              "invalid or duplicate topic: " + str(topic))
        topics.add(topic)
        check(topic in historical, "historical case disappeared: " + topic)
        original = entry.get("original", {})
        check(original.get("kind") == "deferred" and original.get("id") == topic.split("/")[1]
              and original.get("purpose") and original.get("reason"),
              "missing original scenario: " + topic)
        originals.append({"topic": topic, "case": original})
        requirements = entry.get("requirements")
        check(isinstance(requirements, list) and requirements, "unreviewed topic: " + topic)
        seen = set()
        refs = set()
        for requirement in requirements:
            rid = requirement.get("id")
            check(isinstance(rid, str) and rid and rid not in seen,
                  "invalid or duplicate requirement: " + topic)
            seen.add(rid)
            check(bool(requirement.get("behavior", "").strip()), "missing behavior: " + topic)
            coverage = requirement.get("coverage")
            check(coverage in {"covered", "partial", "missing"}, "invalid coverage: " + topic)
            evidence = requirement.get("evidence")
            check(isinstance(evidence, list), "missing evidence list: " + topic)
            check(coverage == "missing" or evidence, "coverage claimed without evidence: " + topic)
            check(coverage == "covered" or requirement.get("gap", "").strip(),
                  "uncovered requirement without a specific gap: " + topic)
            check(coverage != "covered" or not requirement.get("gap", "").strip(),
                  "covered requirement still has a gap: " + topic)
            for reference in evidence:
                check(reference.get("group") in GROUPS and reference.get("id")
                      and reference.get("assertion", "").strip(), "invalid evidence reference: " + topic)
                name = key(reference)
                refs.add(name)
                if name[0] == "reference":
                    check(reference.get("sources_sha256") == reference_sources(repo),
                          "stale reference evaluator/data: " + topic)
                else:
                    check(name in fixtures, "unknown executable fixture: " + str(name))
                    check(reference.get("definition_sha256") == digest(fixtures[name]),
                          "stale fixture evidence mapping: " + str(name))
        coverage = ("full" if all(r["coverage"] == "covered" for r in requirements)
                    else "partial" if any(r["coverage"] != "missing"
                                          for r in requirements) else "none")
        check(entry.get("coverage") == coverage, "inconsistent topic coverage: " + topic)
        migration = entry.get("migration")
        check(migration in {None, "replacement", "inline"}, "invalid migration mode: " + topic)
        current = historical[topic]
        if migration:
            check(coverage == "full", "partial scenario cannot be migrated: " + topic)
            if migration == "inline":
                check(current["kind"] in {"parity", "contract"}
                      and ("legacy", "legacy/" + topic) in refs,
                      "inline migration has no executable historical case: " + topic)
            else:
                check(current["kind"] == "migrated", "replacement lacks migration marker: " + topic)
                check({key(r) for r in current.get("replacement_cases", [])} == refs,
                      "replacement marker differs from reviewed obligations: " + topic)
        else:
            check(current["kind"] == "deferred", "unreviewed historical migration: " + topic)
            check(entry.get("current_reason", "").strip()
                  and current.get("reason") == entry["current_reason"],
                  "historical reason does not match current review: " + topic)
    check(digest(sorted(originals, key=lambda x: x["topic"])) == ledger.get("original_sha256"),
          "original scenario definitions changed")
    unmapped = {topic for topic, case in historical.items()
                if case["kind"] in {"deferred", "migrated"}} - topics
    check(not unmapped, "historical topics missing from review: " + repr(sorted(unmapped)))
    return fixtures


def archive_data(archive, name):
    member = archive.getmember(name)
    check(member.isfile() and member.size <= 16 * 1024**2, "invalid archived data: " + name)
    return archive.extractfile(member).read()


def load_run(spec, expected_binary):
    directory = Path(spec["path"])
    summary, provenance = read(directory / "summary.json"), read(directory / "provenance.json")
    check(provenance.get("status") == "completed", "incomplete VM run: " + directory.name)
    for field in ("candidate_unchanged", "prepared_unchanged", "overlay_discarded", "candidate_matches_guest"):
        check(provenance.get(field) is True, "invalid VM provenance: " + field)
    check(summary["binary_sha256"] == provenance["candidate_sha256"] == expected_binary,
          "wrong candidate: " + directory.name)
    check(not provenance["identity"]["host_shared_mounts"], "shared host mounts in evidence")
    check(provenance["runtime_network"]["canary_accepted"] == 0, "runtime network escaped")
    check(file_digest(directory / "payload.tar") == provenance["payload_sha256"], "payload hash mismatch")
    fixtures, sources, helpers = {}, {}, {}
    with tarfile.open(directory / "payload.tar") as archive:
        for member in archive:
            name = member.name
            if name.startswith("harness/suites/") and name.endswith(".json"):
                for case in json.loads(archive_data(archive, name))["cases"]:
                    fixtures[(case["group"], case["id"])] = case
            elif name.startswith("loadable-parity/suites/") and name.endswith(".json"):
                suite = json.loads(archive_data(archive, name))
                for case in suite["cases"]:
                    fixtures[("legacy", "legacy/" + suite["loadable"] + "/" + case["id"])] = case
            elif name == "harness/references.py" or name.startswith("harness/references/"):
                sources[name.removeprefix("harness/")] = hashlib.sha256(archive_data(archive, name)).hexdigest()
            elif name.startswith("harness/helpers/") and member.isfile():
                helpers[name.removeprefix("harness/")] = hashlib.sha256(archive_data(archive, name)).hexdigest()
    for case in fixtures.values():
        check(all(helpers.get(name) == expected for name, expected in case.get("helpers_sha256", {}).items()),
              "archived helper does not match fixture: " + case["id"])
    selected = []
    for record in summary["cases"]:
        if record["group"] not in spec["groups"]:
            continue
        if "ids" in spec and record["id"] not in spec["ids"]:
            continue
        if record["id"] in spec.get("exclude_ids", []):
            continue
        selected.append({"record": record, "definition": fixtures.get(key(record)), "sources": sources,
                         "run": spec.get("name", directory.name)})
    check(selected, "run selection is empty: " + directory.name)
    metadata = {"name": spec.get("name", directory.name), "groups": spec["groups"],
                "selected_records": len(selected), "candidate_sha256": expected_binary,
                "prepared_sha256": provenance["prepared_sha256"],
                "artifacts_sha256": {name: file_digest(directory / name) for name in
                                     ("summary.json", "provenance.json", "payload.tar", "evidence.tar")},
                "teardown": provenance["teardown"], "overlay_discarded": True,
                "candidate_unchanged": True, "candidate_matches_guest": True, "prepared_unchanged": True}
    return selected, metadata


def assess(requirement, evidence, fixtures, sources):
    observations = []
    for reference in requirement["evidence"]:
        name = key(reference)
        item = evidence.get(name)
        if item is None:
            observations.append({"group": name[0], "id": name[1], "status": "NOT_RUN"})
            continue
        record = item["record"]
        same = (item["sources"] == sources if name[0] == "reference"
                else item["definition"] == fixtures[name])
        status = record["status"] if same else "STALE"
        if name[0] == "reference" and (record.get("unexecuted", 0) or
                                        record.get("validation_complete") is False):
            status = "INCOMPLETE"
        observations.append({"group": name[0], "id": name[1], "status": status, "run": item["run"]})
    executed = bool(observations) and all(o["status"] in EXECUTED for o in observations)
    complete = requirement["coverage"] == "covered" and executed
    return {"id": requirement["id"], "behavior": requirement["behavior"],
            "coverage": requirement["coverage"], "gap": requirement.get("gap", ""),
            "evidence": observations, "fully_exercised": complete,
            "result": ("FAIL" if any(o["status"] == "FAIL" for o in observations) else "PASS")
                      if complete else "UNRESOLVED"}


def reconcile(ledger, configuration, repo=REPO):
    fixtures = validate(ledger, repo)
    sources = reference_sources(repo)
    builds = {}
    for build, spec in configuration["builds"].items():
        binary = file_digest(spec["binary"])
        evidence, runs = {}, []
        for run in spec["runs"]:
            selected, metadata = load_run(run, binary)
            runs.append(metadata)
            for item in selected:
                name = key(item["record"])
                check(name not in evidence, "ambiguous evidence selection: " + repr(name))
                evidence[name] = item
        entries = []
        for entry in ledger["entries"]:
            requirements = [assess(r, evidence, fixtures, sources) for r in entry["requirements"]]
            complete = all(r["fully_exercised"] for r in requirements)
            entries.append({"topic": entry["topic"], "migration": entry.get("migration"),
                            "coverage": entry["coverage"], "fully_exercised": complete,
                            "result": ("FAIL" if any(r["result"] == "FAIL" for r in requirements) else "PASS")
                                      if complete else "UNRESOLVED", "requirements": requirements})
        builds[build] = {"candidate_sha256": binary, "source_runs": runs, "entries": entries,
                         "results": dict(Counter(e["result"] for e in entries)),
                         "migration_without_complete_evidence": [e["topic"] for e in entries
                                                                  if e["migration"] and not e["fully_exercised"]]}
    check(set(builds) == {"static", "dynamic"}, "both static and dynamic evidence are required")
    return {"schema": 1, "original_topics": len(ledger["entries"]), "ledger_sha256": digest(ledger),
            "counting": "Topic results summarize existing checks; they are not additional behavioral cases.",
            "coverage": dict(Counter(e["coverage"] for e in ledger["entries"])),
            "migrations": dict(Counter(e.get("migration") or "deferred" for e in ledger["entries"])),
            "pending_full_topics": [e["topic"] for e in ledger["entries"]
                                    if e["coverage"] == "full" and not e.get("migration")],
            "builds": builds}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=Path(__file__).with_name("deferrals.json"))
    parser.add_argument("--evidence", type=Path, help="private configuration naming raw runs and candidate files")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    ledger = read(args.ledger)
    validate(ledger)
    if not args.evidence:
        print(json.dumps({"validated_topics": len(ledger["entries"])}))
        return 0
    check(args.output is not None, "--evidence requires --output")
    report = reconcile(ledger, read(args.evidence))
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps({name: data["results"] for name, data in report["builds"].items()}))
    return int(bool(report["pending_full_topics"]) or
               any(data["migration_without_complete_evidence"] for data in report["builds"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
