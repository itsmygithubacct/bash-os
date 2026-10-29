#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Review historical deferrals against fixture definitions and saved VM evidence.

This module only reads data. A migrated topic is an index into executed checks,
not another behavioral pass. Missing evidence, partial requirements and skipped
or invalid reference checks cannot close a historical scenario.
"""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import os
import shlex
from pathlib import Path
import tarfile
import uuid

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


def pinned_json(path, expected, label):
    """Read exactly the pinned bytes; the trusted selection supplies the pin."""
    check(isinstance(expected, str) and len(expected) == 64
          and all(c in "0123456789abcdef" for c in expected), "invalid " + label + " SHA-256 pin")
    check(isinstance(path, (str, Path)) and Path(path).is_absolute(), "invalid " + label + " path")
    data = Path(path).read_bytes()
    check(hashlib.sha256(data).hexdigest() == expected, label + " SHA-256 mismatch")
    return json.loads(data)


def option_value(argv, option):
    positions = [i for i, arg in enumerate(argv) if arg == option]
    check(len(positions) == 1 and positions[0] + 1 < len(argv), "invalid VM " + option)
    return argv[positions[0] + 1]


def positive_integer(value):
    return type(value) is int and value > 0


def retained_overlay_cleanup(spec, directory, summary, provenance, expected_binary, expected_build):
    """Validate a narrowly pinned later cleanup; never edit the original provenance."""
    pin = spec.get("post_run_overlay_cleanup")
    check(isinstance(pin, dict) and type(pin.get("schema")) is int and pin.get("schema") == 1,
          "missing pinned overlay cleanup")
    check(expected_build in ("static", "dynamic") and pin.get("build") == expected_build,
          "overlay cleanup build mismatch")
    check(isinstance(spec.get("name"), str) and spec["name"] and pin.get("run_name") == spec["name"],
          "overlay cleanup run name mismatch")
    check(directory.is_absolute() and pin.get("run_directory") == str(directory.resolve()),
          "overlay cleanup run directory mismatch")
    check(pin.get("candidate_sha256") == expected_binary == provenance.get("candidate_sha256"),
          "overlay cleanup candidate mismatch")
    pinned_provenance = pinned_json(directory / "provenance.json", pin.get("original_provenance_sha256"),
                                    "original provenance")
    check(pinned_provenance == provenance and provenance.get("overlay_discarded") is False,
          "overlay cleanup original provenance mismatch")
    pinned_summary = pinned_json(directory / "summary.json", pin["summary_sha256"], "VM summary")
    check(pinned_summary == summary, "VM summary changed during loading")
    check(file_digest(directory / "evidence.tar") == pin["evidence_sha256"], "VM evidence SHA-256 mismatch")
    selfchecks = [case for case in summary["cases"] if case.get("group") == "selfcheck"]
    required = {"selfcheck-bounded-output", "selfcheck-bounded-time", "selfcheck-invalid-oracle-is-error",
                "selfcheck-candidate-mismatch-is-fail", "selfcheck-network-isolation", "selfcheck-orphan-cleanup",
                "selfcheck-detached-orphan-cleanup", "selfcheck-scratch-isolation", "selfcheck-migration-is-metadata",
                "selfcheck-setup-classification", "selfcheck-diagnostic-capture", "selfcheck-file-size-allowance",
                "selfcheck-syscall-sequence-observer"}
    ids = [case["id"] for case in selfchecks]
    check(len(ids) == len(set(ids)) and required.issubset(ids) and sorted(ids) == pin["selfcheck_ids"]
          and all(case.get("status") == "PASS" for case in selfchecks), "invalid retained-run selfchecks")
    with tarfile.open(directory / "evidence.tar") as archive:
        check(json.loads(archive_data(archive, "results/summary.json")) == summary,
              "archived summary differs from pinned summary")
        for case in selfchecks:
            name = "results/selfcheck/" + case["id"].removeprefix("selfcheck-") + ".json"
            stored = json.loads(archive_data(archive, name))
            check(all(stored.get(key) == case.get(key) for key in ("id", "group", "status", "detail")),
                  "archived selfcheck differs from summary: " + case["id"])
    receipt_spec, handles_spec = pin["receipt"], pin["handles"]
    receipt = pinned_json(receipt_spec["path"], receipt_spec["sha256"], "overlay cleanup receipt")
    handles = pinned_json(handles_spec["path"], handles_spec["sha256"], "overlay cleanup handles")
    vm = pinned_json(directory / "vm/vm.json", pin["vm_sha256"], "VM record")
    teardown = pinned_json(directory / "vm/teardown.json", pin["teardown_sha256"], "VM teardown")
    vm_uuid = pin["vm_uuid"]
    check(isinstance(vm_uuid, str) and str(uuid.UUID(vm_uuid)) == vm_uuid
          and receipt.get("uuid") == handles.get("vm_uuid") == vm.get("uuid")
          == provenance.get("vm_uuid") == vm_uuid, "overlay cleanup UUID mismatch")
    scope = pin["scope"]
    check(scope == "parity-vm-" + vm_uuid[:8] + ".scope"
          and receipt.get("scope") == handles.get("scope") == scope,
          "overlay cleanup scope mismatch")
    check(option_value(vm["scope"], "--unit") + ".scope" == scope, "VM scope mismatch")
    check(receipt.get("recorded_cgroup") == handles.get("scope_control_group")
          and Path(receipt["recorded_cgroup"]).is_absolute()
          and Path(receipt["recorded_cgroup"]).name == scope, "overlay cleanup cgroup mismatch")
    check(str(Path(handles["run_outputs"][expected_build]).resolve()) == pin["run_directory"],
          "overlay cleanup build/run binding mismatch")
    overlay = directory.resolve() / "overlay.qcow2"
    check(pin.get("overlay_path") == receipt.get("overlay_path") == str(overlay),
          "overlay cleanup path mismatch")
    check(not os.path.lexists(overlay), "owned overlay still present")
    argv = vm["argv"]
    check(option_value(argv, "-uuid") == vm_uuid, "VM argv UUID mismatch")
    drives = [argv[i + 1] for i, arg in enumerate(argv) if arg == "-drive" and i + 1 < len(argv)]
    overlay_drives = [arg for arg in drives if arg.split(",")[0] == "file=" + str(overlay)]
    check(len(overlay_drives) == 1 and "format=qcow2" in overlay_drives[0].split(","),
          "VM argv overlay mismatch")
    qemus = handles["qemu_processes"]
    check(isinstance(qemus, list) and len(qemus) == 1, "ambiguous owned QEMU identities")
    qemu = qemus[0]
    qemu_argv = shlex.split(qemu["argv"])
    check(qemu_argv and Path(qemu_argv[0]).name == Path(argv[0]).name
          and qemu_argv[1:] == argv[1:], "QEMU argv mismatch")
    controller = pin["controller"]
    expected_qemu = pin["qemu"]
    check(controller == {"pid": handles["controller_pid"], "start_ticks": handles["controller_start_ticks"]}
          and expected_qemu == {"pid": qemu["pid"], "start_ticks": qemu["start_ticks"]}
          and all(positive_integer(item[k]) for item in (controller, expected_qemu) for k in ("pid", "start_ticks"))
          and controller["pid"] != expected_qemu["pid"], "overlay cleanup process pin mismatch")
    processes = receipt["owned_processes"]
    check(isinstance(processes, list) and len(processes) == 2, "ambiguous cleanup processes")
    by_role = {item.get("role"): item for item in processes}
    check(set(by_role) == {"controller", "qemu"}, "missing cleanup process role")
    for role, identity in (("controller", controller), ("qemu", expected_qemu)):
        item = by_role[role]
        current = item.get("current_pid_start_ticks")
        check("current_pid_start_ticks" in item
              and item.get("pid") == identity["pid"] and item.get("start_ticks") == identity["start_ticks"]
              and item.get("owned_process_alive") is False
              and (current is None or (positive_integer(current) and current != identity["start_ticks"])),
              "owned " + role + " not quiescent")
    props = receipt["scope_properties"]
    check(receipt.get("state") == "OWNED_OVERLAY_DISCARDED_AFTER_QUIESCENCE"
          and receipt.get("cache_lock_exclusive") is True
          and "owned_cgroup_procs" in receipt and receipt.get("owned_cgroup_procs") in (None, "")
          and receipt.get("note") == ("Only the recorded scope, recorded process identities and this overlay were "
                                     "inspected; no unrelated processes were inspected or signaled.")
          and props.get("ActiveState") == "inactive" and props.get("SubState") == "dead"
          and props.get("ControlGroup") == "", "unclean overlay quiescence")
    check(positive_integer(receipt.get("overlay_inode"))
          and positive_integer(receipt.get("overlay_logical_bytes_before_removal"))
          and type(receipt.get("overlay_owner_uid")) is int and receipt["overlay_owner_uid"] >= 0,
          "missing owned overlay identity")
    overlay_digest = receipt.get("overlay_sha256_before_removal")
    check(isinstance(overlay_digest, str) and len(overlay_digest) == 64
          and all(c in "0123456789abcdef" for c in overlay_digest), "missing owned overlay digest")
    check(teardown == receipt.get("vm_teardown") == provenance.get("teardown")
          and teardown.get("clean_poweroff") is True and teardown.get("forced_stop") is False
          and type(teardown.get("qemu_exit_status")) is int and teardown["qemu_exit_status"] == 0
          and type(teardown.get("poweroff_request")) is int and teardown["poweroff_request"] == 0,
          "unclean or unattributed VM teardown")
    started, stopped = vm["started_at"], teardown["stopped_at"]
    check(type(started) in (int, float) and type(stopped) in (int, float)
          and 0 < started < stopped, "invalid VM lifetime")
    finished = datetime.fromisoformat(receipt["utc"])
    check(finished.tzinfo is not None and finished.timestamp() > stopped, "cleanup is not later than teardown")
    return {"original_overlay_discarded": False, "method": "pinned_post_run_quiescence",
            "build": expected_build, "vm_uuid": vm_uuid, "scope": scope,
            "overlay_artifact": overlay.name, "original_provenance_sha256": pin["original_provenance_sha256"],
            "receipt": {"artifact": Path(receipt_spec["path"]).name, "sha256": receipt_spec["sha256"]},
            "handles": {"artifact": Path(handles_spec["path"]).name, "sha256": handles_spec["sha256"]},
            "vm_sha256": pin["vm_sha256"], "teardown_sha256": pin["teardown_sha256"],
            "summary_sha256": pin["summary_sha256"], "evidence_sha256": pin["evidence_sha256"],
            "selfcheck_ids": pin["selfcheck_ids"]}


def load_run(spec, expected_binary, expected_build=None):
    directory = Path(spec["path"])
    summary, provenance = read(directory / "summary.json"), read(directory / "provenance.json")
    check(provenance.get("status") == "completed", "incomplete VM run: " + directory.name)
    for field in ("candidate_unchanged", "prepared_unchanged", "candidate_matches_guest"):
        check(provenance.get(field) is True, "invalid VM provenance: " + field)
    overlay_cleanup = None
    if provenance.get("overlay_discarded") is not True:
        check(provenance.get("overlay_discarded") is False, "invalid VM provenance: overlay_discarded")
        try:
            overlay_cleanup = retained_overlay_cleanup(spec, directory, summary, provenance, expected_binary, expected_build)
        except (KeyError, TypeError, OSError, OverflowError) as error:
            raise ValueError("invalid post-run overlay cleanup proof: " + str(error)) from error
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
    if overlay_cleanup is not None:
        check(metadata["artifacts_sha256"]["provenance.json"] == overlay_cleanup["original_provenance_sha256"]
              and metadata["artifacts_sha256"]["summary.json"] == overlay_cleanup["summary_sha256"]
              and metadata["artifacts_sha256"]["evidence.tar"] == overlay_cleanup["evidence_sha256"],
              "original run data changed during loading")
        if "/" in metadata["name"]:
            metadata["name"] = metadata["name"].rsplit("/", 1)[-1] or directory.name
            for item in selected:
                item["run"] = metadata["name"]
        metadata["post_run_overlay_cleanup"] = overlay_cleanup
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
            selected, metadata = load_run(run, binary, build)
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
