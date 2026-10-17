#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check diff's edit addresses, record endings, and allocation failure recovery."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class DiffSafety(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-diff-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def shell(self, script, *args):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "diff-test", *map(str, args)],
            capture_output=True, timeout=20, env=ENV, cwd=self.root)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def compare(self, a, b, mode=()):
        (self.root / "a").write_bytes(a)
        (self.root / "b").write_bytes(b)
        reference = subprocess.run(["/usr/bin/diff", *mode, "a", "b"],
                                   capture_output=True, timeout=10, env=ENV, cwd=self.root)
        result = self.shell('diff "$@" a b', *mode)
        self.assertEqual(result.returncode, reference.returncode, result.stderr)
        self.assertEqual(result.stderr, reference.stderr)
        actual, expected = result.stdout, reference.stdout
        if "-u" in mode and actual:
            # The builtin's headers intentionally omit filesystem timestamps.
            actual = b"\n".join(actual.split(b"\n")[2:])
            expected = b"\n".join(expected.split(b"\n")[2:])
        self.assertEqual(actual, expected)

    def test_edit_addresses_after_earlier_insertions_and_deletions(self):
        records = [f"line {i}\n".encode() for i in range(6)]
        complete = b"".join(records)
        for mask in range(64):
            subset = b"".join(record for i, record in enumerate(records) if mask & (1 << i))
            for a, b in ((complete, subset), (subset, complete)):
                with self.subTest(mask=mask, reverse=a == subset):
                    self.compare(a, b)
                    self.compare(a, b, ("-u",))

    def test_final_newline_and_context_markers(self):
        for a, b in ((b"same", b"same\n"), (b"same\n", b"same"),
                     (b"a\nsame", b"b\nsame"), (b"a\nsame", b"b\nsame\n"),
                     (b"", b"only"), (b"only", b"")):
            for mode in ((), ("-u",), ("-q",), ("-i",)):
                with self.subTest(a=a, b=b, mode=mode):
                    self.compare(a, b, mode)
        context = b"".join(f"context {i}\n".encode() for i in range(6))
        self.compare(b"old\n" + context + b"old\n", b"new\n" + context + b"new\n", ("-u",))

    def test_nul_beyond_first_block_does_not_hide_changes(self):
        prefix = b"prefix\n" * 1000 + b"last\x00"
        for mode in ((), ("-u",), ("-i",), ("-q",)):
            with self.subTest(mode=mode):
                self.compare(prefix + b"old\n", prefix + b"new\n", mode)

    @unittest.skipIf(os.environ.get("BASHOS_TEST_SANITIZED"),
                     "ASan reserves a large virtual address range")
    def test_exhausted_memory_reports_error_and_shell_remains_usable(self):
        (self.root / "a").write_bytes(b"left\n" * 3000)
        (self.root / "b").write_bytes(b"right\n" * 3000)
        (self.root / "small").write_bytes(b"small\n")
        result = self.shell('ulimit -v 32768 || exit; diff a b; '
                            'printf "alive=%s\\n" "$?"; '
                            'diff small small; printf "again=%s\\n" "$?"')
        self.assertEqual((result.returncode, result.stdout), (0, b"alive=2\nagain=0\n"))
        self.assertIn(b"out of memory", result.stderr)

    def test_write_failures_and_subsequent_invocation(self):
        for data in (b"old\n", b"old\x00\n"):
            (self.root / "a").write_bytes(data)
            (self.root / "b").write_bytes(b"new\n")
            for mode in ("", "-u", "-q"):
                with self.subTest(data=data, mode=mode):
                    result = self.shell('diff ' + mode + ' a b >/dev/full; '
                                        'printf "failed=%s\\n" "$?"; '
                                        'diff a a; printf "again=%s\\n" "$?"')
                    self.assertEqual(result.stdout, b"failed=2\nagain=0\n")
                    self.assertIn(b"write error", result.stderr)


if __name__ == "__main__":
    unittest.main()
