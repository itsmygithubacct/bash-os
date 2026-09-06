#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise builtin behavior in a real bash-os process, using only temporary files."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())


class BuiltinTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-regression-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def shell(self, script, *args, **kwargs):
        return subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "regression", *args],
            cwd=self.root,
            env={**os.environ, "PATH": "", "LC_ALL": "C"},
            capture_output=True,
            text=True,
            timeout=10,
            **kwargs,
        )


class CopyTests(BuiltinTest):
    def test_same_file_aliases_preserve_source(self):
        source = self.root / "source"
        source.write_text("keep this data\n")
        (self.root / "hardlink").hardlink_to(source)
        (self.root / "symlink").symlink_to("source")
        (self.root / "indirect").symlink_to("hardlink")
        for target in ("source", "hardlink", "symlink", "indirect"):
            with self.subTest(target=target):
                result = self.shell('cp source "$1"', target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("same file", result.stderr)
                self.assertEqual(source.read_text(), "keep this data\n")

    def test_overwrite_truncates_and_follows_other_destination(self):
        (self.root / "source").write_text("new\n")
        target = self.root / "target"
        (self.root / "alias").symlink_to("target")
        for destination in ("target", "alias"):
            with self.subTest(destination=destination):
                target.write_text("long old contents\n")
                result = self.shell('cp source "$1"', destination)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(target.read_text(), "new\n")
                self.assertTrue((self.root / "alias").is_symlink())

    def test_force_replaces_destination_symlink(self):
        source = self.root / "source"
        source.write_text("keep this data\n")
        alias = self.root / "alias"
        alias.symlink_to("source")
        result = self.shell("cp -f source alias")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_text(), "keep this data\n")
        self.assertEqual(alias.read_text(), source.read_text())
        self.assertFalse(alias.is_symlink())


if __name__ == "__main__":
    unittest.main()
