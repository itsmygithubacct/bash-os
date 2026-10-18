#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inject real close/metadata failures into private cp/mv fixtures.

Needs a dynamically linked Bash binary, a C compiler, and /proc/self/fd.
Cross-device cases use temporary directories on a second writable filesystem.
"""
import errno
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())


class CopyMoveErrors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-fs-fault-library-")
        cls.addClassCleanup(directory.cleanup)
        cls.library = Path(directory.name) / "faults.so"
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-O2", "-Wall", "-Wextra", "-fPIC", "-shared",
            str(ROOT / "tests/fixtures/copy-move-faults.c"), "-ldl", "-o", str(cls.library)]
        subprocess.run(command, capture_output=True, check=True, timeout=60)

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-copy-move-errors-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        self.target = self.root / "target"
        self.log = self.root / "fault.log"
        self.source.write_bytes(b"original\x00contents\n" * 5000)

    def second_filesystem(self):
        for parent in ("/dev/shm", "/tmp"):
            try:
                directory = tempfile.TemporaryDirectory(prefix="bash-os-move-errors-", dir=parent)
            except OSError:
                continue
            root = Path(directory.name)
            if root.stat().st_dev != self.root.stat().st_dev:
                self.addCleanup(directory.cleanup)
                return root
            directory.cleanup()
        self.skipTest("no writable second filesystem")

    def run_fault(self, command, args, operation, path, error=errno.EIO, script='"$@"',
                  extra_env=None, input=None):
        self.log.unlink(missing_ok=True)
        environment = {**os.environ, "PATH": "", "LC_ALL": "C",
                       "BASHOS_IO_FAULT": operation, "BASHOS_IO_FAULT_PATH": str(path),
                       "BASHOS_IO_FAULT_LOG": str(self.log), "BASHOS_IO_FAULT_ERRNO": str(error)}
        environment.pop("BASH_ENV", None)
        environment.update(extra_env or {})
        environment["LD_PRELOAD"] = str(self.library) + (
            ":" + environment["LD_PRELOAD"] if environment.get("LD_PRELOAD") else "")
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "fault-test", command, *map(str, args)],
            cwd=self.root, env=environment, input=input, capture_output=True, timeout=15)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertIn(operation, calls, ("fault did not reach the selected operation", result.stderr))
        return result, calls

    def assert_failed(self, result):
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assertTrue(result.stderr)

    def test_cp_reports_close_errors_for_both_owned_files(self):
        for path in (self.source, self.target):
            with self.subTest(path=path.name):
                before = self.source.read_bytes()
                result, _ = self.run_fault("cp", ["-v", self.source, self.target], "close", path)
                self.assert_failed(result)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(self.source.read_bytes(), before)

    def test_cp_reports_regular_file_metadata_errors(self):
        for operation in ("chown", "chmod", "utimensat"):
            with self.subTest(operation=operation):
                result, calls = self.run_fault("cp", ["-pv", self.source, self.target],
                                              operation, self.target)
                self.assert_failed(result)
                self.assertEqual(result.stdout, b"")
                if operation == "utimensat":
                    self.assertNotIn("utimes", calls, "EIO is not an unsupported-syscall fallback")

    def test_cp_keeps_the_old_kernel_timestamp_fallback(self):
        os.utime(self.source, ns=(1234567890123456000, 1234567890987654000))
        expected = self.source.stat()
        result, calls = self.run_fault("cp", ["-p", self.source, self.target],
                                      "utimensat", self.target, errno.ENOSYS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("utimes", calls)
        actual = self.target.stat()
        self.assertEqual((actual.st_atime_ns, actual.st_mtime_ns),
                         (expected.st_atime_ns, expected.st_mtime_ns))

    def test_cp_reports_a_failed_legacy_timestamp_fallback(self):
        result, calls = self.run_fault("cp", ["-p", self.source, self.target], "utimes", self.target)
        self.assert_failed(result)
        self.assertIn("utimensat", calls)

    def test_cp_reports_directory_metadata_and_closedir_errors(self):
        self.source.unlink()
        self.source.mkdir()
        (self.source / "file").write_bytes(b"child\n")
        self.target.mkdir()
        destination = self.target / "source"
        destination.mkdir()
        for operation in ("chown", "chmod", "utimensat", "closedir"):
            with self.subTest(operation=operation):
                watched = self.source if operation == "closedir" else destination
                result, _ = self.run_fault("cp", ["-Rp", self.source, self.target],
                                           operation, watched)
                self.assert_failed(result)
                self.assertEqual((self.source / "file").read_bytes(), b"child\n")

    def test_cp_reports_symlink_ownership_errors(self):
        self.source.unlink()
        self.source.symlink_to("missing")
        result, _ = self.run_fault("cp", ["-p", self.source, self.target], "lchown", self.target)
        self.assert_failed(result)
        self.assertEqual(os.readlink(self.source), "missing")

    def test_move_preserves_source_after_close_or_regular_metadata_error(self):
        target = self.second_filesystem() / "target"
        original = self.source.read_bytes()
        for operation, watched in (("close", self.source), ("close", target),
                                   ("chown", target), ("chmod", target), ("utimensat", target)):
            with self.subTest(operation=operation, watched=watched.name):
                self.source.write_bytes(original)
                result, _ = self.run_fault("mv", [self.source, target], operation, watched)
                self.assert_failed(result)
                self.assertEqual(self.source.read_bytes(), original)

    def test_move_preserves_whole_tree_when_parent_metadata_fails(self):
        destination = self.second_filesystem()
        self.source.unlink()
        for operation in ("chown", "chmod", "utimensat", "closedir"):
            with self.subTest(operation=operation):
                self.source.mkdir(exist_ok=True)
                (self.source / "file").write_bytes(b"keep child\n")
                target = destination / operation
                watched = self.source if operation == "closedir" else target
                result, _ = self.run_fault("mv", [self.source, target], operation, watched,
                                           extra_env={"BASHOS_IO_FAULT_SKIP": "1" if operation == "chmod" else "0"})
                self.assert_failed(result)
                self.assertEqual((self.source / "file").read_bytes(), b"keep child\n")

    def test_move_keeps_previously_copied_siblings_after_child_failure(self):
        target = self.second_filesystem() / "tree"
        self.source.unlink()
        self.source.mkdir()
        for name in ("first", "second"):
            (self.source / name).write_text(name)
        last = list(self.source.iterdir())[-1].name
        result, _ = self.run_fault("mv", [self.source, target], "chmod", target / last)
        self.assert_failed(result)
        for name in ("first", "second"):
            self.assertEqual((self.source / name).read_text(), name)

    def test_move_reports_symlink_metadata_errors(self):
        destination = self.second_filesystem()
        self.source.unlink()
        for operation in ("lchown", "utimensat"):
            with self.subTest(operation=operation):
                if self.source.is_symlink():
                    self.source.unlink()
                self.source.symlink_to("missing")
                target = destination / operation
                result, _ = self.run_fault("mv", [self.source, target], operation, target)
                self.assert_failed(result)
                self.assertEqual(os.readlink(self.source), "missing")

    def test_move_readdir_error_does_not_remove_even_an_empty_source(self):
        target = self.second_filesystem() / "directory"
        self.source.unlink()
        self.source.mkdir()
        result, _ = self.run_fault("mv", [self.source, target], "readdir", self.source)
        self.assert_failed(result)
        self.assertTrue(self.source.is_dir())

    def test_move_never_removes_a_new_uncopied_source_entry(self):
        target = self.second_filesystem() / "tree"
        self.source.unlink()
        self.source.mkdir()
        (self.source / "file").write_bytes(b"copied\n")
        newcomer = self.root / "newcomer"
        newcomer.write_bytes(b"not copied\n")
        result, _ = self.run_fault("mv", [self.source, target], "utimensat", target, error=0,
                                   extra_env={"BASHOS_IO_RENAME_FROM": str(newcomer),
                                              "BASHOS_IO_RENAME_TO": str(self.source / "new")})
        self.assert_failed(result)
        self.assertEqual((self.source / "new").read_bytes(), b"not copied\n")
        self.assertFalse((target / "new").exists())

    def test_move_never_removes_a_replaced_source_entry(self):
        target = self.second_filesystem() / "tree"
        self.source.unlink()
        self.source.mkdir()
        (self.source / "file").write_bytes(b"copied\n")
        replacement = self.root / "replacement"
        replacement.write_bytes(b"not copied\n")
        result, _ = self.run_fault("mv", [self.source, target], "utimensat", target, error=0,
                                   extra_env={"BASHOS_IO_RENAME_FROM": str(replacement),
                                              "BASHOS_IO_RENAME_TO": str(self.source / "file")})
        self.assert_failed(result)
        self.assertEqual((self.source / "file").read_bytes(), b"not copied\n")
        self.assertEqual((target / "file").read_bytes(), b"copied\n")

    def test_shell_recovers_and_retries_after_a_failed_copy(self):
        result, _ = self.run_fault("cp", [self.source, self.target], "close", self.target,
                                  script='"$@"; printf "failed=%s\\n" "$?"; '
                                         'unset BASHOS_IO_FAULT; "$@"; printf "retry=%s\\n" "$?"')
        self.assertEqual(result.stdout, b"failed=1\nretry=0\n")
        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())

    def test_failed_copy_or_move_does_not_close_shell_stdin(self):
        other = self.second_filesystem()
        for command, target in (("cp", self.target), ("mv", other / "target")):
            with self.subTest(command=command):
                result, _ = self.run_fault(
                    command, [self.source, target], "close", target,
                    script='"$@"; printf "failed=%s\\n" "$?"; '
                           'IFS= read -r line; printf "input=%s\\n" "$line"', input=b"still available\n")
                self.assertEqual(result.stdout, b"failed=1\ninput=still available\n")

    def test_failed_copy_or_move_releases_an_owned_descriptor_zero(self):
        other = self.second_filesystem()
        for command, target in (("cp", self.target), ("mv", other / "target")):
            with self.subTest(command=command):
                result, _ = self.run_fault(
                    command, [self.source, target], "close", self.source,
                    script='exec 0<&-; "$@"; printf "failed=%s\\n" "$?"; '
                           'if [[ -e /proc/self/fd/0 ]]; then printf "leaked\\n"; fi')
                self.assertEqual(result.stdout, b"failed=1\n")


if __name__ == "__main__":
    unittest.main()
