#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare byte streams with GNU cmp and check the containing shell survives."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class CompareStreams(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-cmp-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.first = self.root / "first"
        self.second = self.root / "second"

    def shell(self, script, *args, data=b""):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "cmp-test", *map(str, args)],
            input=data, capture_output=True, timeout=10, env=ENV, cwd=self.root)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def compare(self, args, data=b"", listing=False):
        expected = subprocess.run(["/usr/bin/cmp", *map(str, args)], input=data,
                                  capture_output=True, timeout=10, env=ENV)
        actual = self.shell('cmp "$@"', *args, data=data)
        self.assertEqual(actual.returncode, expected.returncode, actual.stderr)
        if listing:
            # GNU pads columns according to the file size; compare each byte record.
            self.assertEqual(actual.stdout.split(), expected.stdout.split())
        else:
            self.assertEqual(actual.stdout, expected.stdout)

    def test_regular_binary_inputs_and_buffer_boundaries(self):
        for length in (0, 1, 8191, 8192, 8193, 65537):
            data = (bytes(range(256)) * ((length + 255) // 256))[:length]
            self.first.write_bytes(data)
            for other in (data, data + b"tail", data[:-1], bytes(x ^ 1 for x in data)):
                self.second.write_bytes(other)
                for mode in ("-s", "-l"):
                    with self.subTest(length=length, other=len(other), mode=mode):
                        self.compare([mode, self.first, self.second], listing=mode == "-l")
                        self.compare([mode, "-", self.second], data, listing=mode == "-l")
                        self.compare([mode, self.first, "-"], other, listing=mode == "-l")

    def test_fragmented_pipe_is_not_eof(self):
        data = bytes(range(256)) * 65
        for reverse in (False, True):
            for mode in ("-s", "-l"):
                with self.subTest(reverse=reverse, mode=mode):
                    self.first.write_bytes(data)
                    operands = [str(self.first), "-"] if reverse else ["-", str(self.first)]
                    process = subprocess.Popen(
                        [BINARY, "-c", 'cmp "$@"', "cmp-test", mode, *operands],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=ENV, cwd=self.root, bufsize=0)
                    try:
                        offset = 0
                        for count in (1, 7, 513, 8191, len(data)):
                            part = data[offset:offset + count]
                            if not part:
                                continue
                            process.stdin.write(part)
                            offset += len(part)
                            time.sleep(0.03)
                            self.assertIsNone(process.poll(), "short read was treated as EOF")
                        process.stdin.close()
                        process.stdin = None
                        stdout, stderr = process.communicate(timeout=10)
                        self.assertEqual((process.returncode, stdout, stderr), (0, b"", b""))
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=10)

    def test_silent_difference_returns_before_the_producer_closes(self):
        self.first.write_bytes(b"A" * 20000)
        process = subprocess.Popen(
            [BINARY, "-c", 'cmp -s - "$1"', "cmp-test", str(self.first)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=ENV, cwd=self.root, bufsize=0)
        try:
            process.stdin.write(b"Z")
            self.assertEqual(process.wait(timeout=5), 1)
            self.assertEqual(process.stdout.read(), b"")
            self.assertEqual(process.stderr.read(), b"")
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)

    def test_open_failure_preserves_borrowed_stdin(self):
        result = self.shell('cmp - missing; status=$?; IFS= read -r line; '
                            'printf "%s:%s:%s\\n" "$status" "$?" "$line"',
                            data=b"available\n")
        self.assertEqual(result.stdout, b"2:0:available\n")

    def test_owned_descriptor_zero_is_closed_on_every_exit(self):
        self.first.write_bytes(b"abc")
        self.second.write_bytes(b"xyz")
        for target, status in ((self.first, 0), (self.second, 1), ("missing", 2)):
            with self.subTest(target=target):
                result = self.shell('exec 0<&-; cmp -s "$1" "$2"; status=$?; '
                                    '[[ ! -e /proc/self/fd/0 ]] || exit 90; '
                                    'printf "%s\\n" "$status"', self.first, target)
                self.assertEqual((result.returncode, result.stdout), (0, f"{status}\n".encode()))
        result = self.shell('exec 0<&-; cmp -s "$1" -', self.first)
        self.assertEqual(result.returncode, 2)

    def test_skip_starts_at_current_stdin_position(self):
        self.first.write_bytes(b"abcXYZ")
        result = self.shell('exec 0<"$1"; IFS= read -r -N 3 prefix; '
                            'cmp -s - "$1" 1 4', self.first)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_skip_past_eof_is_a_comparison_not_a_read_error(self):
        self.first.write_bytes(b"abc")
        for count in (4, 8192, 2**63, 2**64 - 1):
            with self.subTest(count=count):
                self.compare(["-s", "-", self.first, count, count], b"abc")
                self.compare(["-s", "-", self.first, count, 0], b"abc")

    def test_write_error_and_repeated_calls(self):
        self.first.write_bytes(b"a" * 20000)
        self.second.write_bytes(b"b" * 20000)
        for mode in ("", "-l"):
            with self.subTest(mode=mode):
                result = self.shell('cmp ' + mode + ' "$1" "$2" >/dev/full; '
                                    'printf "status=%s\\n" "$?"; '
                                    'cmp -s "$1" "$1"; printf "again=%s\\n" "$?"',
                                    self.first, self.second)
                self.assertEqual(result.stdout, b"status=2\nagain=0\n")
                self.assertIn(b"write error", result.stderr)

    def test_read_error_and_extra_operands(self):
        self.first.write_bytes(b"abc")
        result = self.shell('cmp -s "$1" "$2"', self.root, self.first)
        self.assertEqual(result.returncode, 2)
        result = self.shell('cmp -- "$1" "$1" 0 0 excess', self.first)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
