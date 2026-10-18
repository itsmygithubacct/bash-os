#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Protect exact names and metadata during same- and cross-filesystem moves."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class MoveSafety(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-mv-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def second_filesystem(self):
        for parent in ("/dev/shm", "/tmp"):
            try:
                directory = tempfile.TemporaryDirectory(prefix="bash-os-mv-other-", dir=parent)
            except OSError:
                continue
            root = Path(directory.name)
            if root.stat().st_dev != self.root.stat().st_dev:
                self.addCleanup(directory.cleanup)
                return root
            directory.cleanup()
        self.skipTest("no writable second filesystem")

    def shell(self, script, *args):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "mv-test", *map(str, args)],
            cwd=self.root, env=ENV, capture_output=True, timeout=15)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def long_directory(self, root, length):
        path = root
        while len(os.fsencode(path)) < length:
            width = min(200, length - len(os.fsencode(path)) - 1)
            if width < 1:
                self.skipTest("fixture prefix cannot reach the boundary")
            path /= "d" * width
            path.mkdir()
        self.assertEqual(len(os.fsencode(path)), length)
        return path

    def test_overlong_top_destination_never_overwrites_a_shorter_name(self):
        destination = self.long_directory(self.root, 4090)
        sentinel = destination / "abcd"
        sentinel.write_bytes(b"unrelated\n")
        source = self.root / "abcdefghijklmnop"
        source.write_bytes(b"moving\n")
        result = self.shell('mv "$1" "$2"', source, destination)
        self.assertEqual(sentinel.read_bytes(), b"unrelated\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(source.read_bytes(), b"moving\n")

    def test_overlong_destination_child_does_not_move_to_a_shorter_name(self):
        other = self.second_filesystem()
        parent = self.long_directory(other, 4088)
        destination = parent / "t"
        source = self.root / "source"
        source.mkdir()
        (source / "abcdefghijklmnop").write_bytes(b"moving\n")
        result = self.shell('mv "$1" "$2"', source, destination)
        self.assertFalse((destination / "abcd").exists(), "move used a truncated destination name")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((source / "abcdefghijklmnop").read_bytes(), b"moving\n")

    def test_overlong_source_child_never_reads_or_removes_a_shorter_name(self):
        destination = self.second_filesystem() / "target"
        source = self.long_directory(self.root, 4090)
        descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        for name, data in (("abcd", b"short\n"), ("abcdefghijklmnop", b"long\n")):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=descriptor)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        result = self.shell('mv "$1" "$2"', source, destination)
        self.assertEqual(result.returncode, 1, result.stderr)
        for name, data in (("abcd", b"short\n"), ("abcdefghijklmnop", b"long\n")):
            fd = os.open(name, os.O_RDONLY, dir_fd=descriptor)
            with os.fdopen(fd, "rb") as stream:
                self.assertEqual(stream.read(), data)
        self.assertFalse((destination / "abcdefghijklmnop").exists())

    def test_valid_destination_at_path_boundary_succeeds(self):
        destination = self.long_directory(self.root, 4090)
        source = self.root / "abcd"
        source.write_bytes(b"exact boundary\n")
        result = self.shell('mv "$1" "$2"', source, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / "abcd").read_bytes(), b"exact boundary\n")
        self.assertFalse(source.exists())

    def test_trailing_slash_keeps_the_directory_basename(self):
        for cross_device in (False, True):
            with self.subTest(cross_device=cross_device):
                source = self.root / "source"
                source.mkdir()
                (source / "child").write_bytes(b"child\n")
                destination = self.second_filesystem() if cross_device else self.root / "target"
                destination.mkdir(exist_ok=True)
                result = self.shell('mv "$1" "$2"', str(source) + "///", destination)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((destination / "source" / "child").read_bytes(), b"child\n")
                self.assertFalse(source.exists())

    def test_cross_device_symlink_keeps_its_own_metadata(self):
        source = self.root / "link"
        target = self.root / "file"
        target.write_bytes(b"keep target\n")
        source.symlink_to(target)
        os.utime(target, ns=(1234567890000000001, 1234567890000000002))
        os.utime(source, ns=(1234567890000000123, 1234567890000000456), follow_symlinks=False)
        before_link = source.lstat()
        before_target = target.stat()
        destination = self.second_filesystem() / "moved"
        result = self.shell('mv "$1" "$2"', source, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        after_link = destination.lstat()
        self.assertEqual((after_link.st_uid, after_link.st_gid, after_link.st_atime_ns, after_link.st_mtime_ns),
                         (before_link.st_uid, before_link.st_gid, before_link.st_atime_ns, before_link.st_mtime_ns))
        after_target = target.stat()
        self.assertEqual((after_target.st_atime_ns, after_target.st_mtime_ns),
                         (before_target.st_atime_ns, before_target.st_mtime_ns))
        self.assertEqual(os.readlink(destination), str(target))
        self.assertFalse(source.is_symlink())

    def test_cross_device_nested_hardlinks_and_directory_modes_survive(self):
        source = self.root / "source"
        source.mkdir()
        nested = source / "nested"
        nested.mkdir()
        (source / "file").write_bytes(b"shared\x00bytes\n")
        os.link(source / "file", nested / "alias")
        os.chmod(source / "file", 0o6750)
        os.chmod(nested, 0o2750)
        os.chmod(source, 0o2755)
        destination = self.second_filesystem() / "moved"
        result = self.shell('umask 077; mv "$1" "$2"', source, destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        file = (destination / "file").stat()
        alias = (destination / "nested" / "alias").stat()
        self.assertEqual(file.st_ino, alias.st_ino)
        self.assertEqual(file.st_nlink, 2)
        self.assertEqual(stat.S_IMODE(file.st_mode), 0o6750)
        self.assertEqual(stat.S_IMODE((destination / "nested").stat().st_mode), 0o2750)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o2755)
        self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
