#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise recursive-copy bounds and collision-safe symlink replacement."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class CopySafety(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-cp-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "file").write_bytes(b"original\x00bytes\n")

    def shell(self, script, *args):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "cp-test", *map(str, args)],
            capture_output=True, timeout=10, env=ENV, cwd=self.root)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_copy_into_self_fails_without_recursing(self):
        for target in ("source/nested", "alias/nested"):
            with self.subTest(target=target):
                if not (self.root / "alias").exists():
                    (self.root / "alias").symlink_to("source")
                result = self.shell('cp -R source "$1"; status=$?; '
                                    'printf "alive:%s\\n" "$status"', target)
                self.assertEqual(result.stdout, b"alive:1\n")
                self.assertFalse((self.source / "nested" / "nested").exists())
                self.assertEqual((self.source / "file").read_bytes(), b"original\x00bytes\n")
                if (self.source / "nested").exists():
                    shutil.rmtree(self.source / "nested")

    def test_same_directory_is_rejected_before_contents_change(self):
        result = self.shell('cp -R source/. source')
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"same file", result.stderr)
        self.assertEqual(sorted(p.name for p in self.source.iterdir()), ["file"])

    def test_followed_symlink_cycle_is_bounded_and_state_recovers(self):
        (self.source / "back").symlink_to(".")
        result = self.shell('cp -RL source target; printf "first=%s\\n" "$?"; '
                            'cp -R source second; printf "second=%s\\n" "$?"')
        self.assertEqual(result.stdout, b"first=1\nsecond=0\n")
        self.assertFalse((self.root / "target" / "back").exists())
        self.assertTrue((self.root / "second" / "back").is_symlink())
        self.assertEqual((self.root / "target" / "file").read_bytes(), b"original\x00bytes\n")

    def test_followed_sibling_aliases_are_not_cycles(self):
        (self.source / "directory").mkdir()
        (self.source / "directory" / "data").write_bytes(b"aliased\n")
        (self.source / "alias").symlink_to("directory")
        result = self.shell('cp -RL source target')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("directory", "alias"):
            self.assertEqual((self.root / "target" / name / "data").read_bytes(), b"aliased\n")

    def test_temporary_name_collision_preserves_unrelated_entries(self):
        (self.root / "link-source").symlink_to("new-target")
        (self.root / "destination").symlink_to("old-target")
        for kind, setup, verify in (
            ("file", 'printf keep > "$collision"', '[[ $(<"$collision") == keep ]]'),
            ("symlink", 'ln -s untouched "$collision"', '[[ $(readlink "$collision") == untouched ]]'),
            ("directory", 'mkdir "$collision"', '[[ -d "$collision" ]]'),
        ):
            with self.subTest(kind=kind):
                result = self.shell('collision="destination.bcptmp.$$"; ' + setup + '; '
                                    'cp link-source destination || exit; ' + verify)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(os.readlink(self.root / "destination"), "new-target")

    def test_failed_symlink_replacement_cleans_private_temporary_directory(self):
        (self.root / "link-source").symlink_to("new-target")
        (self.root / "destination" / "link-source").mkdir(parents=True)
        sentinel = self.root / "destination" / "link-source" / "sentinel"
        sentinel.write_bytes(b"keep\n")
        result = self.shell('cp link-source destination')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(sentinel.read_bytes(), b"keep\n")
        self.assertEqual(sorted(p.name for p in (self.root / "destination").iterdir()), ["link-source"])

    def test_overlong_child_paths_never_copy_a_truncated_name(self):
        directory = self.source
        while len(os.fsencode(directory)) < 4090:
            width = min(200, 4090 - len(os.fsencode(directory)) - 1)
            if width < 1:
                self.skipTest("fixture prefix cannot reach the boundary")
            directory /= "d" * width
            directory.mkdir()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name, contents in (("abcd", b"short\n"), ("abcdefghijklmnop", b"long\n")):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=descriptor)
                os.write(fd, contents)
                os.close(fd)
            result = self.shell('cp -R "$1" "$2"', self.source, self.root / "t")
            self.assertEqual(result.returncode, 1, result.stderr)
            destination = self.root / "t" / directory.relative_to(self.source)
            self.assertEqual(sorted(os.listdir(destination)), ["abcd"])
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
