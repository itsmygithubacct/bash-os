#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Meaningful evaluator checks; command execution is restricted to the VM."""
import base64
import copy
import json
from pathlib import Path
import socket
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import schema


class SchemaChecks(unittest.TestCase):
    def setUp(self):
        self.case = {"id": "example", "loadable": "bash", "group": "shell", "driver": "plain",
                     "script": "printf expected", "expected_status": 0, "stdout": "expected"}

    def test_duplicate_ids_across_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for file in ("one.json", "two.json"):
                (root / file).write_text(json.dumps({"schema": 1, "cases": [self.case]}))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                schema.load(root)

    def test_changed_helper_cannot_reuse_a_fixture_digest(self):
        import hashlib
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "suites").mkdir()
            (root / "helpers").mkdir()
            helper = root / "helpers/reader.py"
            helper.write_text("original helper data")
            case = {**self.case, "helpers_sha256": {
                "helpers/reader.py": hashlib.sha256(helper.read_bytes()).hexdigest()}}
            (root / "suites/example.json").write_text(json.dumps({"schema": 1, "cases": [case]}))
            schema.load(root / "suites")
            helper.write_text("changed helper data")
            with self.assertRaisesRegex(ValueError, "stale helper"):
                schema.load(root / "suites")

    def test_notification_supervisor_reaps_after_listener_hangup(self):
        import errno
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "system_seccomp_check", Path(__file__).parent / "helpers/system-seccomp.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with patch.object(helper.os, "waitpid", side_effect=[(0, 0), (55, 0)]), \
                patch.object(helper.select, "select", side_effect=[([99], [], []),
                             AssertionError("retried a closed listener without reaping")]), \
                patch.object(helper.fcntl, "ioctl", side_effect=OSError(errno.ENOENT, "caller exited")), \
                patch.object(helper.os, "kill", side_effect=AssertionError("already reaped")):
            self.assertEqual(helper.supervise(None, 99, 55, {}, {}, {}, None), 0)

    def test_traversal_and_absolute_paths(self):
        for name in ("../escape", "/tmp/escape", "a/../../escape", "a//b", "."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                schema.validate({**self.case, "files": {name: "bad"}})

    def test_diagnostic_paths_are_bounded_and_relative(self):
        for names in (["../escape"], ["/tmp/escape"], ["a", "a"], ["file"] * 17):
            with self.subTest(names=names), self.assertRaises(ValueError):
                schema.validate({**self.case, "diagnostic_files": names})
        schema.validate({**self.case, "diagnostic_files": ["server.log", "child/state.json"]})

    def test_diagnostics_do_not_follow_links_or_open_special_files(self):
        import guest
        import os
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "log").write_bytes(b"observed\0bytes")
            (root / "link").symlink_to("log")
            os.mkfifo(root / "pipe")
            result = guest.diagnostics({"diagnostic_files": ["log", "link", "pipe", "absent"]}, root)
            self.assertEqual(base64.b64decode(result["log"]["base64"]), b"observed\0bytes")
            self.assertFalse(result["log"]["truncated"])
            self.assertIn("symlink", result["link"]["error"])
            self.assertIn("regular file", result["pipe"]["error"])
            self.assertEqual(result["absent"], {"missing": True})

    def test_large_diagnostic_is_explicitly_truncated(self):
        import guest
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "log").write_bytes(b"x" * (1024**2 + 1))
            result = guest.diagnostics({"diagnostic_files": ["log"]}, root)["log"]
            self.assertTrue(result["truncated"])
            self.assertEqual(result["captured_bytes"], 1024**2)

    def test_malformed_expectations(self):
        for change in ({"driver": "unknown"}, {"group": "unknown"}, {"expected_status": True},
                       {"timeout": 0}, {"timeout": 100}, {"stdout_base64": "!"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                schema.validate({**self.case, **change})

    def test_file_size_allowance_is_bounded_and_explicit(self):
        self.assertEqual(schema.file_size_limit(self.case), 8 * 1024**2)
        for value in (8 * 1024**2, 72 * 1024**2, 128 * 1024**2):
            schema.validate({**self.case, "file_size_limit": value})
        for value in (True, "75497472", 0, 8 * 1024**2 - 1, 128 * 1024**2 + 1):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "file_size_limit"):
                schema.validate({**self.case, "file_size_limit": value})
        with self.assertRaisesRegex(ValueError, "plain driver"):
            schema.validate({**self.case, "group": "terminal", "driver": "pty",
                             "file_size_limit": 72 * 1024**2, "steps": []})

    def test_terminal_step_errors(self):
        case = {**self.case, "group": "terminal", "driver": "pty"}
        for steps in ([{"resize": [0, 80]}], [{"expect": "["}], [{"unexpected": "action"}]):
            with self.subTest(steps=steps), self.assertRaises((ValueError, __import__("re").error)):
                schema.validate({**case, "steps": steps})

    def test_contract_needs_observable_oracle(self):
        case = {k: v for k, v in self.case.items() if k != "stdout"}
        with self.assertRaisesRegex(ValueError, "observable"):
            schema.validate({**case, "kind": "contract", "oracle": "exit success"})

    def test_case_selection_rejects_silent_omissions(self):
        cases = [self.case, {**self.case, "id": "second", "group": "terminal"}]
        self.assertEqual(schema.select(cases, {"shell"}, {"example"}), [self.case])
        for selected in (set(), {"missing"}, {"second"}):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                schema.select(cases, {"shell"}, selected)

    def test_fixture_ca_refuses_host_setup(self):
        import network
        with patch.object(network.os, "geteuid", return_value=2000), \
                patch.object(network.subprocess, "run", side_effect=AssertionError("must not mount")):
            with self.assertRaisesRegex(RuntimeError, "disposable VM"):
                with network.fixture_ca({"peer_install_ca": True}, {}):
                    self.fail("host trust setup accepted")

    def test_fixture_ca_restores_target_on_behavior_failure(self):
        import network
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                (root / "ca.pem").write_text("public fixture certificate")
                target = root / "trust.pem"
                if existing:
                    (root / "original.pem").write_text("original trust")
                    target.symlink_to("original.pem")
                evidence = {}
                with patch.object(network, "TLS_EXPORT", name), \
                        patch.object(network, "require_trust_guest"), \
                        patch.object(network.subprocess, "run") as mount:
                    with self.assertRaisesRegex(RuntimeError, "behavior failed"):
                        with network.fixture_ca({"peer_install_ca": True}, evidence, target):
                            raise RuntimeError("behavior failed")
                self.assertEqual(mount.call_args.args[0][0], "umount")
                self.assertTrue(evidence["fixture_ca"]["restored"])
                self.assertEqual(target.exists(), existing)
                if existing:
                    self.assertTrue(target.is_symlink())
                    self.assertEqual(target.read_text(), "original trust")

    def test_harness_failure_is_never_candidate_failure(self):
        import guest
        result = {"status": 0, "stdout_base64": "", "stderr_base64": "", "tree": {},
                  "error": "decoder unavailable", "harness_error": "decoder unavailable"}
        for kind in ("contract", "parity"):
            with tempfile.TemporaryDirectory() as name, patch.object(guest, "side", return_value=result):
                record = guest.evaluate({**self.case, "kind": kind, "oracle": "explicit stdout"}, Path(name) / "case")
                self.assertEqual(record["status"], "ERROR")

    def test_missing_fixture_tool_is_an_error_before_candidate_execution(self):
        import guest
        with tempfile.TemporaryDirectory() as name, patch.object(guest.shutil, "which", return_value=None), \
                patch.object(guest, "side", side_effect=AssertionError("candidate must not run")):
            record = guest.evaluate({**self.case, "loadable": "example", "requires": ["missing-fixture-tool"]},
                                    Path(name) / "case")
            self.assertEqual(record["status"], "ERROR")
            self.assertEqual(record["missing_dependencies"], ["missing-fixture-tool"])

    def test_absent_optional_builtin_is_not_a_candidate_failure(self):
        import guest
        absent = {"status": 1, "stdout_base64": "", "error": None}
        with tempfile.TemporaryDirectory() as name, patch.object(guest, "plain", return_value=absent), \
                patch.object(guest, "workspace", return_value=Path(name)), \
                patch.object(guest, "side", side_effect=AssertionError("missing builtin must not run")):
            record = guest.evaluate({**self.case, "loadable": "example", "optional": True}, Path(name) / "case")
            self.assertEqual(record["status"], "SKIP")

    def test_setup_failure_is_not_a_candidate_failure(self):
        import guest
        failed = {"status": 1, "stdout_base64": "", "stderr_base64": "", "error": None}
        with tempfile.TemporaryDirectory() as name, patch.object(guest, "plain", return_value=failed) as run, \
                patch.object(guest, "workspace", return_value=Path(name)), \
                patch.object(guest.terminal, "execute", side_effect=AssertionError("candidate must not run")):
            record = guest.evaluate({**self.case, "loadable": "example", "driver": "pty", "kind": "contract",
                                     "oracle": "independent expectation", "setup_script": "compile-helper"},
                                    Path(name) / "case")
            self.assertEqual(record["status"], "ERROR")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][0], str(guest.REFERENCE_SHELL))

    def test_namespace_preflight_distinguishes_policy_from_probe_errors(self):
        import guest
        for message, expected in ((b"unshare: Operation not permitted", "SKIP"),
                                  (b"unshare: invalid option", "ERROR")):
            failed = {"status": 1, "stdout_base64": "", "stderr_base64": base64.b64encode(message).decode(),
                      "error": None}
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as name, \
                    patch.object(guest, "plain", return_value=failed), \
                    patch.object(guest.shutil, "which", return_value="/usr/bin/unshare"), \
                    patch.object(guest, "workspace", return_value=Path(name)), \
                    patch.object(guest, "side", side_effect=AssertionError("candidate must not run")):
                record = guest.evaluate({**self.case, "loadable": "example", "features": ["userns"]},
                                        Path(name) / "case")
                self.assertEqual(record["status"], expected)

    def test_payload_permissions_do_not_depend_on_host_umask(self):
        import vm
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for directory in (root / "harness", root / "tests/loadable-parity"):
                directory.mkdir(parents=True)
                source = directory / "private.py"
                source.write_text("# source data only\n")
                source.chmod(0o600)
            candidate = root / "candidate"
            candidate.write_bytes(b"not executed")
            with patch.object(vm, "HERE", root / "harness"), patch.object(vm, "REPO", root):
                vm.payload(candidate, root / "payload.tar", None)
            with tarfile.open(root / "payload.tar") as archive:
                for entry in archive:
                    self.assertEqual(entry.mode, 0o755 if entry.name == "candidate" else 0o644)
                    self.assertEqual((entry.uid, entry.gid, entry.uname, entry.gname), (0, 0, "", ""))

    def test_legacy_child_failure_keeps_the_case_denominator(self):
        import guest
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "one.json").write_text(json.dumps({"loadable": "one", "cases": [
                {"id": "done", "kind": "parity"}, {"id": "not-run", "kind": "contract"},
                {"id": "deferred", "kind": "deferred", "reason": "unimplemented fixture"},
                {"id": "migrated", "kind": "migrated",
                 "replacement_cases": [{"group": "terminal", "id": "replacement"}]}]}))
            records = [{"id": "legacy/one/done", "status": "PASS"}]
            accounting = guest.backfill_legacy(records, root, "child failed")
            self.assertEqual(accounting, {"expected_cases": 4, "backfilled_cases": 3, "invalid_suite_files": 0})
            self.assertEqual([r["status"] for r in records], ["PASS", "ERROR", "DEFERRED", "MIGRATED"])


class DeferralChecks(unittest.TestCase):
    def setUp(self):
        import deferrals
        self.review = deferrals
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fixture = {"id": "replacement", "loadable": "example", "group": "shell", "driver": "plain",
                        "script": "printf expected", "expected_status": 0, "stdout": "expected"}
        reference = {"group": "shell", "id": "replacement", "assertion": "Expected output is compared",
                     "definition_sha256": deferrals.digest(self.fixture)}
        original = {"id": "old", "kind": "deferred", "purpose": "Observe output", "reason": "Old missing fixture"}
        self.entry = {"topic": "example/old", "original": original, "coverage": "full",
                      "migration": "replacement", "requirements": [
                          {"id": "r1", "behavior": "Expected output", "coverage": "covered",
                           "evidence": [reference], "gap": ""}]}
        self.ledger = {"schema": 1, "original_count": 1,
                       "original_sha256": deferrals.digest([{"topic": "example/old", "case": original}]),
                       "entries": [self.entry]}
        for directory in ("tests/parity-vm/suites", "tests/loadable-parity/suites"):
            (self.root / directory).mkdir(parents=True)
        (self.root / "tests/parity-vm/suites/example.json").write_text(
            json.dumps({"schema": 1, "cases": [self.fixture]}))
        (self.root / "tests/loadable-parity/suites/example.json").write_text(json.dumps(
            {"version": 1, "loadable": "example", "cases": [{"id": "old", "kind": "migrated",
             "purpose": "Observe output", "replacement_cases": [{"group": "shell", "id": "replacement"}]}]}))

    def test_partial_obligation_cannot_be_retired(self):
        self.entry["requirements"].append({"id": "r2", "behavior": "Cancellation cleanup",
                                          "coverage": "missing", "gap": "No cancellation assertion", "evidence": []})
        self.entry["coverage"] = "partial"
        with self.assertRaisesRegex(ValueError, "partial scenario"):
            self.review.validate(self.ledger, self.root)

    def test_scenario_loss_and_scope_rewrite_are_rejected(self):
        with self.subTest("lost topic"):
            changed = copy.deepcopy(self.ledger)
            changed["entries"] = []
            with self.assertRaises(ValueError):
                self.review.validate(changed, self.root)
        with self.subTest("rewritten original"):
            self.entry["original"]["purpose"] = "A smaller obligation"
            with self.assertRaisesRegex(ValueError, "original scenario definitions"):
                self.review.validate(self.ledger, self.root)

    def test_skips_errors_and_absent_results_do_not_close_coverage(self):
        fixtures = self.review.validate(self.ledger, self.root)
        name = ("shell", "replacement")
        for status in ("SKIP", "ERROR", "DEFERRED", "MIGRATED", None):
            with self.subTest(status=status):
                evidence = {name: {"definition": self.fixture, "sources": {}, "run": "synthetic",
                                  "record": {"group": name[0], "id": name[1], "status": status}}} if status else {}
                result = self.review.assess(self.entry["requirements"][0], evidence, fixtures, {})
                self.assertFalse(result["fully_exercised"])
                self.assertEqual(result["result"], "UNRESOLVED")

    def test_observed_failure_is_executed_and_remains_a_failure(self):
        fixtures = self.review.validate(self.ledger, self.root)
        name = ("shell", "replacement")
        evidence = {name: {"definition": self.fixture, "sources": {}, "run": "synthetic",
                           "record": {"group": name[0], "id": name[1], "status": "FAIL"}}}
        result = self.review.assess(self.entry["requirements"][0], evidence, fixtures, {})
        self.assertTrue(result["fully_exercised"])
        self.assertEqual(result["result"], "FAIL")

    def test_changed_fixture_cannot_reuse_old_pass(self):
        fixtures = self.review.validate(self.ledger, self.root)
        name = ("shell", "replacement")
        evidence = {name: {"definition": {**self.fixture, "script": "printf different"}, "sources": {},
                           "run": "synthetic", "record": {"group": name[0], "id": name[1], "status": "PASS"}}}
        result = self.review.assess(self.entry["requirements"][0], evidence, fixtures, {})
        self.assertFalse(result["fully_exercised"])
        self.assertEqual(result["evidence"][0]["status"], "STALE")

    def test_payload_rejects_stale_migration_before_upload(self):
        import vm
        root = self.root / "tests/parity-vm"
        (root / "deferrals.json").write_text(json.dumps(self.ledger))
        (root / "suites/example.json").write_text(json.dumps(
            {"schema": 1, "cases": [{**self.fixture, "script": "printf changed"}]}))
        candidate = self.root / "candidate"
        candidate.write_bytes(b"not executed")
        with patch.object(vm, "HERE", root), patch.object(vm, "REPO", self.root):
            with self.assertRaisesRegex(ValueError, "stale fixture"):
                vm.payload(candidate, self.root / "payload.tar", None)
        self.assertFalse((self.root / "payload.tar").exists())


def evaluate(root, output):
    import guest
    guest.require_guest(Path("/etc/bashos-parity-vm").read_text().strip())
    records = []
    directory = output / "selfcheck"
    directory.mkdir()

    def run(name, check):
        try:
            detail = check()
            record = {"id": "selfcheck-" + name, "group": "selfcheck", "status": "PASS", "detail": detail}
        except Exception as exc:
            record = {"id": "selfcheck-" + name, "group": "selfcheck", "status": "ERROR", "reason": str(exc)}
        records.append(record)
        guest.write_json(directory / (name + ".json"), record)

    def bounded_output():
        cwd = guest.workspace({})
        result = guest.plain(["/usr/bin/python3", "-c", "import os; os.write(1,b'x'*131072)"],
                             guest.environment("reference"), cwd, {"output_limit": 4096})
        assert result["error"] == "output limit", result
        assert result["captured_bytes"] <= 4096, result
        return {"error": result["error"], "captured_bytes": result["captured_bytes"]}

    def bounded_time():
        cwd = guest.workspace({})
        start = time.monotonic()
        result = guest.plain(["/usr/bin/python3", "-c", "import time; time.sleep(2)"],
                             guest.environment("reference"), cwd, {"timeout": .1})
        elapsed = time.monotonic() - start
        assert result["error"] == "wall-clock limit" and elapsed < 2, result
        return {"error": result["error"], "elapsed": elapsed, "status": result["status"]}

    def classification(wanted):
        case = {"id": "classification", "loadable": "bash", "group": "shell", "driver": "plain",
                "script": "printf expected", "expected_status": 0, "stdout": "expected", "stderr": ""}
        case[("reference" if wanted == "ERROR" else "candidate") + "_script"] = "printf incorrect"
        result = guest.evaluate(case, directory / ("classification-" + wanted))
        assert result["status"] == wanted, result
        return result

    def network_isolation():
        results = []
        for address in ("10.0.2.2", "192.0.2.1"):
            with socket.socket() as client:
                client.settimeout(.2)
                try:
                    client.connect((address, 9))
                except OSError as exc:
                    results.append({"address": address, "reachable": False, "errno": exc.errno})
                else:
                    raise AssertionError("namespace has unexpected outbound connectivity")
        return results

    def orphan_cleanup(detach):
        cwd = guest.workspace({})
        result = guest.plain(["/usr/bin/python3", "-c",
                             "import os,time; p=os.fork(); "
                             "os._exit(0) if p else None; "
                             + ("os.setsid(); " if detach else "") +
                             "os.close(0); os.close(1); os.close(2); time.sleep(2)"],
                             guest.environment("reference"), cwd, {"timeout": 1})
        assert result["stray_processes"], result
        for process in result["stray_processes"]:
            assert not Path('/proc/' + str(process['pid'])).exists(), process
        return {"stray_processes_cleaned": result["stray_processes"], "error": result["error"]}

    def scratch_isolation():
        guest.workspace({})
        for name, _, _ in guest.SCRATCH:
            (Path(name) / "selfcheck-leaked-state").write_text("reference state")
        guest.workspace({})
        for name, _, _ in guest.SCRATCH:
            assert not (Path(name) / "selfcheck-leaked-state").exists(), name
        return {"reset": [name for name, _, _ in guest.SCRATCH]}

    def migration_metadata():
        import importlib.util
        path = root / "loadable-parity/runner.py"
        spec = importlib.util.spec_from_file_location("migration_runner_check", path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        suite = runner.validate({"version": 1, "loadable": "cat", "cases": [
            {"id": "moved-scenario", "kind": "migrated", "purpose": "Metadata must not execute a script",
             "script": "exit 99", "replacement_cases": [{"group": "terminal", "id": "example"}]}]})
        report = runner.run_suite(suite, root / "candidate", directory / "migration-marker")
        assert report["summary"]["MIGRATED"] == 1, report
        assert all(count == 0 for status, count in report["summary"].items() if status != "MIGRATED"), report
        return {"summary": report["summary"], "executed_behavioral_cases": 0}

    def setup_classification():
        case = {"id": "setup-classification", "loadable": "bash", "group": "shell", "driver": "plain",
                "kind": "contract", "oracle": "Fixed setup file and exact independent output",
                "setup_script": "printf setup-noise; printf prepared > resource",
                "script": "test \"$(cat resource)\" = prepared && printf observed",
                "expected_status": 0, "stdout": "observed", "stderr": "",
                "expected_files": {"resource": "prepared"}}
        passed = guest.evaluate(case, directory / "setup-success")
        assert passed["status"] == "PASS", passed
        raw = json.loads((directory / "setup-success/candidate.json").read_text())
        assert base64.b64decode(raw["setup"]["stdout_base64"]) == b"setup-noise", raw
        failed = guest.evaluate({**case, "setup_script": "exit 7",
                                 "script": "printf should-not-run > candidate-ran; printf observed"},
                                directory / "setup-failure")
        assert failed["status"] == "ERROR", failed
        raw = json.loads((directory / "setup-failure/candidate.json").read_text())
        assert "candidate-ran" not in raw["tree"], raw
        return {"successful_setup": passed["status"], "failed_setup": failed["status"],
                "behavior_skipped_after_failed_setup": True}

    def diagnostic_capture():
        case = {"id": "diagnostic-capture", "loadable": "bash", "group": "shell", "driver": "plain",
                "reference_script": 'printf reference-log > "$HOME/server.log"; printf observed',
                "candidate_script": 'printf candidate-log > "$HOME/server.log"; printf observed',
                "expected_status": 0, "stdout": "observed", "stderr": "",
                "diagnostic_files": ["server.log", "absent"]}
        passed = guest.evaluate(case, directory / "diagnostics")
        assert passed["status"] == "PASS", passed
        for side in ("reference", "candidate"):
            raw = json.loads((directory / "diagnostics" / (side + ".json")).read_text())
            assert base64.b64decode(raw["diagnostics"]["server.log"]["base64"]) == (side + "-log").encode()
            assert raw["diagnostics"]["absent"] == {"missing": True}
            assert "server.log" not in raw["tree"]
        failed = guest.evaluate({**case, "id": "diagnostic-setup-failure",
                                 "setup_script": 'printf setup-log > "$HOME/server.log"; exit 7'},
                                directory / "diagnostics-setup-failure")
        assert failed["status"] == "ERROR", failed
        raw = json.loads((directory / "diagnostics-setup-failure/candidate.json").read_text())
        assert base64.b64decode(raw["diagnostics"]["server.log"]["base64"]) == b"setup-log"
        return {"different_diagnostics_do_not_change_parity": True,
                "setup_failure_diagnostics_retained": True}

    def file_size_allowance():
        probe = '''import errno, os, resource, signal, sys
limit = int(sys.argv[1])
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (limit, limit)
assert resource.getrlimit(resource.RLIMIT_AS) == (512 * 1024**2,) * 2
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (128, 128)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert os.getuid() == os.getgid() == 2000 and os.getgroups() == []
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
fd = os.open('limit-probe', os.O_CREAT | os.O_RDWR, 0o600)
try:
    os.ftruncate(fd, limit)
    assert os.fstat(fd).st_size == limit
    try:
        os.pwrite(fd, b'x', limit)
    except OSError as error:
        assert error.errno == errno.EFBIG, error
    else:
        raise AssertionError('file size allowance was not enforced')
finally:
    os.close(fd)
    os.unlink('limit-probe')
print('limit=%d enforced' % limit)
'''
        outcomes = []
        for limit in (8 * 1024**2, 72 * 1024**2):
            command = '/usr/bin/python3 limits.py ' + str(limit)
            expected = 'limit=%d enforced\n' % limit
            case = {"id": "file-limit-" + str(limit), "loadable": "bash", "group": "shell",
                    "driver": "plain", "files": {"limits.py": probe},
                    "setup_script": command + ' > setup-limit', "script": command,
                    "expected_status": 0, "stdout": expected, "stderr": "",
                    "expected_files": {"setup-limit": expected}}
            if limit != 8 * 1024**2:
                case["file_size_limit"] = limit
            output = directory / ("file-limit-" + str(limit))
            result = guest.evaluate(case, output)
            assert result["status"] == "PASS", result
            for side in ("reference", "candidate"):
                raw = json.loads((output / (side + '.json')).read_text())
                assert raw["configured_file_size_limit"] == limit
                assert raw["setup"]["configured_file_size_limit"] == limit
            outcomes.append({"limit": limit, "result": result["status"],
                             "setup_and_behavior_both_sides": True})
        return {"cases": outcomes, "other_identity_and_resource_limits_unchanged": True}

    def syscall_sequence_observer():
        probe = r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "probe line %d\n", __LINE__); return 90; } } while (0)
int main(void) {
    const unsigned char data[8] = {'A', 0, 'B', 255, 'C', 0, 'D', 127};
    int fd = open("sequence-output", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    REQUIRE(fd >= 0);
    REQUIRE(dup2(fd, 9) == 9);
    if (fd != 9) REQUIRE(close(fd) == 0);
    REQUIRE(syscall(SYS_getpgid, 0) == 17);
    errno = 0;
    REQUIRE(syscall(SYS_getpgid, 0) == -1 && errno == EIO);
    REQUIRE(syscall(SYS_getpgid, 0) == getpgrp());
    REQUIRE(syscall(SYS_write, 9, data, sizeof(data)) == 2);
    errno = 0;
    REQUIRE(syscall(SYS_write, 9, data, sizeof(data)) == -1 && errno == EIO);
    REQUIRE(syscall(SYS_write, 9, data, sizeof(data)) == sizeof(data));
    errno = 0;
    REQUIRE(syscall(SYS_write, 9, 0, sizeof(data)) == -1 && errno == EFAULT);
    REQUIRE(close(9) == 0);
    puts("sequence-and-memory-ok");
    return 0;
}
'''
        observer = '''import json, pathlib, subprocess, sys
helper = '/opt/bashos-parity/harness/helpers/system-sequence.py'
rows = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert [r['syscall'] for r in rows] == ['getpgid'] * 3 + ['write'] * 4, rows
assert [r['reply'] for r in rows[:3]] == ['value:17', 'errno:5', 'continue']
assert [r['reply'] for r in rows[3:]] == ['value:2', 'errno:5', 'continue', 'continue']
for group in (rows[:3], rows[3:]):
    assert [r['sequence_index'] for r in group] == list(range(1, len(group) + 1))
    assert [r['sequence_exhausted'] for r in group] == [i >= 2 for i in range(len(group))]
for row in rows[3:]:
    assert row['arg0'] == 9 and row['arg2'] == 8
for row in rows[3:6]:
    assert row['memory1'] == {'requested': 8, 'length': 8, 'hex': '410042ff4300447f'}
assert rows[-1]['memory1']['requested'] == 8 and 'unreadable' in rows[-1]['memory1']
assert pathlib.Path('sequence-output').read_bytes() == bytes.fromhex('410042ff4300447f')
invalid = [
    ['--reply-seq', 'getpid='],
    ['--reply-seq', 'getpid=continue,'],
    ['--reply-seq', 'getpid=1', '--reply', 'getpid=continue'],
    ['--log-mem', 'write=6:8'],
    ['--log-mem', 'write=1:0'],
    ['--log-mem', 'write=1:4097'],
]
for options in invalid:
    result = subprocess.run(['/usr/bin/python3', helper, *options, '--', '/usr/bin/touch', 'unexpected-child'], capture_output=True)
    assert result.returncode == 125 and not pathlib.Path('unexpected-child').exists(), (options, result)
print('sequence-exhaustion bounded-memory invalid-inputs-ok')
'''
        script = '''/usr/bin/python3 /opt/bashos-parity/harness/helpers/system-sequence.py --notify getpgid:0=0 --reply-seq getpgid=17,EIO --notify write:0=9 --reply-seq write=2,EIO --log-args write=0,2 --log-mem write=1:8 --log "$HOME/sequence.jsonl" -- ./sequence-control || exit $?
/usr/bin/python3 observe.py "$HOME/sequence.jsonl"
'''
        case = {"id": "syscall-sequence-observer", "loadable": "bash", "group": "shell",
                "driver": "plain", "files": {"control.c": probe, "observe.py": observer},
                "requires": ["cc", "python3", "touch"], "features": ["seccomp-notify"],
                "setup_script": "/usr/bin/cc -O0 -Wall -Wextra control.c -o sequence-control",
                "script": script, "timeout": 15, "expected_status": 0, "stderr": "",
                "stdout": "sequence-and-memory-ok\nsequence-exhaustion bounded-memory invalid-inputs-ok\n",
                "diagnostic_files": ["sequence.jsonl"]}
        result = guest.evaluate(case, directory / "syscall-sequence-observer")
        assert result["status"] == "PASS", result
        return {"sequence_values_errno_and_continue": True, "continues_after_exhaustion": True,
                "bounded_binary_memory_read": True, "unreadable_pointer_observed": True,
                "synthetic_success_does_not_write": True, "invalid_options_do_not_spawn": True}

    run("bounded-output", bounded_output)
    run("bounded-time", bounded_time)
    run("invalid-oracle-is-error", lambda: classification("ERROR"))
    run("candidate-mismatch-is-fail", lambda: classification("FAIL"))
    run("network-isolation", network_isolation)
    run("orphan-cleanup", lambda: orphan_cleanup(False))
    run("detached-orphan-cleanup", lambda: orphan_cleanup(True))
    run("scratch-isolation", scratch_isolation)
    run("migration-is-metadata", migration_metadata)
    run("setup-classification", setup_classification)
    run("diagnostic-capture", diagnostic_capture)
    run("file-size-allowance", file_size_allowance)
    run("syscall-sequence-observer", syscall_sequence_observer)
    return records


if __name__ == "__main__":
    # Only data-validation tests run here. VM behavior tests are guest groups.
    unittest.main()
