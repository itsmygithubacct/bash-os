#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check dd reblocking bounds, seek semantics, and descriptor ownership."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class CopyBlocks(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-dd-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def shell(self, script, *args, data=b""):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "dd-test", *map(str, args)],
            input=data, capture_output=True, timeout=10, env=ENV, cwd=self.root)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def reference(self, args, data):
        return subprocess.run(["/usr/bin/dd", *args, "status=none"], input=data,
                              capture_output=True, timeout=10, env=ENV, cwd=self.root)

    def test_unblock_expansion_and_spaces_carried_between_blocks(self):
        payloads = [b"x" * 256, b" " * 63 + b"x", b"left  right   ",
                    b" " * 128, bytes(range(256)) * 3]
        for ibs in (1, 3, 7, 32, 512):
            for cbs in (1, 2, 5, 64):
                for number, data in enumerate(payloads):
                    with self.subTest(ibs=ibs, cbs=cbs, payload=number):
                        args = [f"ibs={ibs}", f"cbs={cbs}", "conv=unblock", "iflag=fullblock"]
                        expected = self.reference(args, data)
                        actual = self.shell('dd "$@" status=none', *args, data=data)
                        self.assertEqual((actual.returncode, actual.stdout, actual.stderr),
                                         (expected.returncode, expected.stdout, expected.stderr))

    def test_block_and_swab_conversions_still_match(self):
        data = b"first\n\nlast record without newline"
        for ibs in (1, 3, 32):
            for conv in ("block", "unblock", "swab", "swab,sync", "ucase,block"):
                with self.subTest(ibs=ibs, conv=conv):
                    args = [f"ibs={ibs}", "cbs=5", f"conv={conv}", "iflag=fullblock"]
                    expected = self.reference(args, data)
                    actual = self.shell('dd "$@" status=none', *args, data=data)
                    self.assertEqual((actual.returncode, actual.stdout, actual.stderr),
                                     (expected.returncode, expected.stdout, expected.stderr))

    def test_seek_preserves_existing_prefix_and_truncates_at_new_end(self):
        for original in (b"", b"abcdefghij"):
            for args in (["bs=1", "seek=3"], ["bs=1", "seek=3", "count=0"],
                         ["bs=1", "seek=15"], ["bs=1", "seek=3", "conv=notrunc"],
                         ["obs=4", "seek=3", "oflag=seek_bytes"],
                         ["obs=4", "seek=5", "oflag=seek_bytes"]):
                with self.subTest(original=original, args=args):
                    expected_path, actual_path = self.root / "expected", self.root / "actual"
                    expected_path.write_bytes(original)
                    actual_path.write_bytes(original)
                    expected = self.reference([f"of={expected_path}", *args], b"XYZ")
                    actual = self.shell('dd "$@" status=none', f"of={actual_path}", *args, data=b"XYZ")
                    self.assertEqual((actual.returncode, actual.stderr),
                                     (expected.returncode, expected.stderr))
                    self.assertEqual(actual_path.read_bytes(), expected_path.read_bytes())

    def test_borrowed_output_seek_does_not_truncate_or_close_it(self):
        (self.root / "out").write_bytes(b"abcdefghij")
        result = self.shell('exec 1<>out; dd bs=1 seek=3 count=0 status=none; '
                            '[[ -e /proc/self/fd/1 ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "out").read_bytes(), b"abcdefghij")

    def test_owned_standard_descriptor_numbers_are_closed(self):
        (self.root / "input").write_bytes(b"payload")
        for target in ("output", "missing/output"):
            with self.subTest(target=target):
                result = self.shell('exec 0<&-; dd if=input "of=$1" status=none; '
                                    'status=$?; [[ ! -e /proc/self/fd/0 ]] || exit 90; '
                                    'printf "%s\\n" "$status"', target)
                self.assertEqual((result.returncode, result.stdout),
                                 (0, b"0\n" if target == "output" else b"1\n"))
        result = self.shell('exec 1>&-; dd if=input of=output status=none || exit; '
                            '[[ ! -e /proc/self/fd/1 ]]')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_offset_cannot_truncate_destination(self):
        target = self.root / "target"
        for args in (("ibs=2", "skip=9223372036854775807"),
                     ("obs=2", "seek=9223372036854775807")):
            with self.subTest(args=args):
                target.write_bytes(b"preserve")
                result = self.shell('dd of=target status=none "$@"', *args, data=b"new")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(target.read_bytes(), b"preserve")

    def test_new_file_mode_obeys_umask(self):
        for mask in ("000", "022", "077", "777"):
            with self.subTest(mask=mask):
                target = self.root / f"mode-{mask}"
                result = self.shell('umask "$1"; dd "of=$2" status=none', mask, target, data=b"data")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(target.stat().st_mode & 0o777, 0o666 & ~int(mask, 8))
                target.chmod(0o600)

    def test_sync_failure_on_borrowed_pipe_and_write_errors(self):
        for conv in ("fsync", "fdatasync"):
            with self.subTest(conv=conv):
                expected = self.reference([f"conv={conv}"], b"data")
                result = self.shell('dd "$@" status=none', f"conv={conv}", data=b"data")
                self.assertEqual((result.returncode, result.stdout),
                                 (expected.returncode, expected.stdout))
                self.assertTrue(result.stderr)
        result = self.shell('dd of=/dev/full status=none; printf "status=%s\\n" "$?"', data=b"data")
        self.assertEqual(result.stdout, b"status=1\n")


if __name__ == "__main__":
    unittest.main()
