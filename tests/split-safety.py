#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check split's byte/line pieces, failure status, and source preservation."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class SplitSafety(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-split-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def shell(self, script, *args, data=b""):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "split-test", *map(str, args)],
            input=data, capture_output=True, timeout=10, env=ENV, cwd=self.root)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_binary_pieces_match_gnu(self):
        payloads = [b"", b"unterminated", b"a\x00b\nlast\x00", bytes(range(256)) * 97]
        for number, data in enumerate(payloads):
            for args in (("-l", "2"), ("-b", "8192"), ("-b", "1k"), ("-b", "13", "-a", "3")):
                with self.subTest(payload=number, args=args):
                    actual = self.root / "actual"
                    expected = self.root / "expected"
                    actual.mkdir(exist_ok=True)
                    expected.mkdir(exist_ok=True)
                    for directory in (actual, expected):
                        for path in directory.iterdir():
                            path.unlink()
                    reference = subprocess.run(
                        ["/usr/bin/split", *args, "-", str(expected / "piece")], input=data,
                        capture_output=True, timeout=10, env=ENV)
                    result = self.shell('split "$@"', *args, "-", actual / "piece", data=data)
                    self.assertEqual((result.returncode, result.stderr),
                                     (reference.returncode, reference.stderr))
                    self.assertEqual({p.name: p.read_bytes() for p in actual.iterdir()},
                                     {p.name: p.read_bytes() for p in expected.iterdir()})

    def test_output_failure_is_reported_for_full_and_partial_chunks(self):
        for args in (("-l", "1"), ("-l", "3"), ("-b", "2"), ("-b", "32")):
            with self.subTest(args=args):
                target = self.root / "xaa"
                if target.is_symlink():
                    target.unlink()
                target.symlink_to("/dev/full")
                result = self.shell('split "$@"; printf "status=%s\\n" "$?"',
                                    *args, data=b"one\ntwo\n")
                self.assertEqual(result.stdout, b"status=1\n")
                self.assertTrue(result.stderr)
                self.assertFalse((self.root / "xab").exists())

    def test_read_errors_fail_without_creating_output(self):
        for args in (("-l", "1"), ("-b", "8192")):
            with self.subTest(args=args):
                result = self.shell('split "$@" .', *args)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(result.stderr)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_input_and_its_aliases_are_never_truncated(self):
        data = b"preserve\x00this\n" * 2000
        source = self.root / "input"
        source.write_bytes(data)
        for args in (("-l", "1"), ("-b", "8192")):
            for alias in ("same", "hardlink", "symlink"):
                with self.subTest(args=args, alias=alias):
                    output = self.root / "xaa"
                    if output.exists() or output.is_symlink():
                        output.unlink()
                    if alias == "hardlink":
                        output.hardlink_to(source)
                    elif alias == "symlink":
                        output.symlink_to("input")
                    else:
                        output.write_bytes(data)
                    operand = output if alias == "same" else source
                    result = self.shell('split "$@"', *args, operand, "x")
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(operand.read_bytes(), data)
                    self.assertEqual(source.read_bytes(), data)
                    self.assertFalse((self.root / "xab").exists())

    def test_later_output_alias_also_preserves_input(self):
        source = self.root / "input"
        source.write_bytes(b"abcdef")
        (self.root / "xab").hardlink_to(source)
        result = self.shell('split -b 2 input x')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.root / "xaa").read_bytes(), b"ab")
        self.assertEqual(source.read_bytes(), b"abcdef")

    def test_invalid_sizes_are_rejected_before_any_output(self):
        cases = [("-l", "1junk"), ("-l", "999999999999999999999999"),
                 ("-a", "2junk"), ("-a", "4294967298"),
                 ("-b", "1kjunk"), ("-b", "1cjunk"),
                 ("-b", "9223372036854775807k"), ("-b", "999999999999999999999999")]
        for args in cases:
            with self.subTest(args=args):
                result = self.shell('split "$@"', *args, data=b"leave intact\n")
                self.assertEqual(result.returncode, 2)
                self.assertTrue(result.stderr)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_long_output_prefix_and_repeated_stdin(self):
        directory = self.root / ("a" * 150) / ("b" * 150)
        directory.mkdir(parents=True)
        (self.root / "first").write_bytes(b"first\x00\n")
        (self.root / "second").write_bytes(b"second\n")
        result = self.shell('split -l 1 - "$1/one" <first; '
                            'split -b 3 - "$1/two" <second', directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((directory / "oneaa").read_bytes(), b"first\x00\n")
        self.assertEqual(b"".join(p.read_bytes() for p in sorted(directory.glob("two*"))), b"second\n")


if __name__ == "__main__":
    unittest.main()
