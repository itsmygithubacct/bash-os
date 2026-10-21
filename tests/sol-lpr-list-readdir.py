#!/usr/bin/env python3
"""lpr list treats a directory read error as failure and keeps its descriptors.

The spool is a private temporary directory. Nothing is sent to a printer.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ROOT = Path(__file__).resolve().parents[1]
PRELOAD_SRC = ROOT / "tests" / "sol-lpr-readdir-preload.c"


class ListRead(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="sol-lpr-readdir-")
        cls.shim = Path(cls.tmp.name) / "readdir.so"
        built = subprocess.run(
            ["cc", "-shared", "-fPIC", "-O2", str(PRELOAD_SRC), "-o", str(cls.shim), "-ldl"],
            capture_output=True, text=True)
        if built.returncode != 0:
            raise AssertionError(built.stderr)
        cls.addClassCleanup(cls.tmp.cleanup)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sol-lpr-spool-")
        self.addCleanup(self.directory.cleanup)
        self.spool = Path(self.directory.name) / "spool"
        self.spool.mkdir(mode=0o700)
        self.spool.chmod(0o700)
        self.jobs = ("0123456789abcdef", "fedcba9876543210")
        for job in self.jobs:
            (self.spool / f"{job}.lpr").write_bytes(b"job-bytes")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("BASHLPR_")}
        self.env["BASHLPR_SPOOL"] = str(self.spool.resolve())
        self.env["PATH"] = "/usr/bin:/bin"

    def run_shell(self, script, env):
        return subprocess.run(
            [BINARY, "--norc", "--noprofile", "-c", script, "sol-lpr"],
            env=env, capture_output=True, timeout=20)

    def test_private_list_shows_jobs_and_keeps_descriptors(self):
        script = r'''
        before=(/proc/self/fd/*)
        out=
        for ((i = 0; i < 20; i++)); do
          one=$(lpr list) || exit 4
          out=$one
        done
        after=(/proc/self/fd/*)
        [[ ${#before[@]} -eq ${#after[@]} ]] || { printf 'fd %s / %s\n' "${before[*]}" "${after[*]}"; exit 3; }
        printf '%s\n' "$out"
        '''
        result = self.run_shell(script, self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout.decode()
        for job in self.jobs:
            self.assertIn(f"{self.spool.resolve()}/{job}.lpr", text)
        self.assertNotIn("notes", text)

    def test_readdir_error_is_failure_and_keeps_descriptors(self):
        env = dict(self.env)
        env["LD_PRELOAD"] = str(self.shim)
        env["BASHLPR_READDIR_FAIL_DIR"] = str(self.spool.resolve())
        script = r'''
        before=(/proc/self/fd/*)
        for ((i = 0; i < 20; i++)); do
          lpr list >/dev/null
          rc=$?
          [[ $rc -ne 0 ]] || exit 2
        done
        after=(/proc/self/fd/*)
        [[ ${#before[@]} -eq ${#after[@]} ]] || { printf 'fd %s / %s\n' "${before[*]}" "${after[*]}"; exit 3; }
        echo ok
        '''
        result = self.run_shell(script, env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, b"ok\n")
        self.assertIn(b"cannot read spool", result.stderr)
        self.assertNotIn(b"0123456789abcdef", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
