#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks for isolation and honest classification in the fixture runner."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("runner.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.binary = Path(os.environ.get("BASHOS_TEST_BINARY", "out/bash-static")).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_rejects_unverifiable_contracts_and_duplicate_ids(self):
        case = dict(id="a", kind="contract", purpose="contract", script="true",
                    expected_status=0, stderr="empty")
        with self.assertRaises(ValueError):
            runner.validate(dict(version=1, loadable="cat", cases=[case]))
        case["stdout"] = ""
        with self.assertRaises(ValueError):
            runner.validate(dict(version=1, loadable="cat", cases=[case, case]))
        case["timeout"] = 60
        with self.assertRaises(ValueError):
            runner.validate(dict(version=1, loadable="cat", cases=[case]))

    def test_classifications_do_not_turn_absence_or_bad_oracles_into_passes(self):
        cases = [dict(id="pass", kind="parity", purpose="small ordinary input",
                      script="printf abc | cat", requires=["cat"], expected_status=0,
                      stderr="empty"),
                 dict(id="bad-oracle", kind="parity", purpose="invalid reference status",
                      script="false", requires=["cat"], expected_status=0, stderr="empty"),
                 dict(id="difference", kind="contract", purpose="independent mismatch",
                      script="printf actual", expected_status=0, stdout="expected", stderr="empty"),
                 dict(id="missing-oracle", kind="parity", purpose="absent comparator",
                      script="false", requires=["nonexistent-parity-oracle-47"], expected_status=0,
                      stderr="empty"),
                 dict(id="deferred", kind="deferred", purpose="do not execute a deferred fixture",
                      script="exit 99", reason="requires separate hardware")]
        suite = runner.validate(dict(version=1, loadable="cat", cases=cases))
        result = runner.run_suite(suite, self.binary, self.root / "results")
        self.assertEqual(result["summary"], dict(PASS=1, FAIL=1, ERROR=1, SKIP=1, DEFERRED=1))

    def test_isolation_has_private_network_processes_and_no_host_paths(self):
        # These are read-only observations, not attempts at privileged operations.
        code = r'''/usr/bin/python3 - <<'PY'
import os, pathlib
assert os.readlink('/proc/self/ns/net') != 'HOST_NETNS'
assert not pathlib.Path('/sys').exists()
assert not pathlib.Path('/run').exists()
assert not pathlib.Path('/home').exists()
assert not pathlib.Path('/dev/sda').exists()
assert not pathlib.Path('/dev/nvme0n1').exists()
assert 'CapEff:\t0000000000000000' in pathlib.Path('/proc/self/status').read_text()
assert len([p for p in pathlib.Path('/proc').iterdir() if p.name.isdecimal()]) < 12
assert all('rw' not in line.split()[5].split(',') for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] in ('/usr', '/proc'))
print('isolated')
PY'''.replace("HOST_NETNS", os.readlink("/proc/self/ns/net"))
        case = dict(id="boundary", kind="contract", purpose="namespace boundary",
                    script=code, expected_status=0, stdout="isolated\n", stderr="empty")
        result = runner.run_suite(dict(version=1, loadable="cat", cases=[case]),
                                  self.binary, self.root / "boundary")
        self.assertEqual(result["summary"]["PASS"], 1)

    def test_optional_absence_is_a_skip(self):
        case = dict(id="absent", kind="contract", purpose="optional absence",
                    script="printf unexpected", expected_status=0, stdout="", stderr="empty")
        result = runner.run_suite(dict(version=1, loadable="nonexistent_loadable_47",
                                      optional=True, cases=[case]), self.binary, self.root / "optional")
        self.assertEqual(result["summary"]["SKIP"], 1)
        self.assertEqual(result["summary"]["PASS"], 0)


if __name__ == "__main__":
    unittest.main()
