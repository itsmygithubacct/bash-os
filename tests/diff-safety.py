#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check diff's edit addresses, record endings, and allocation failure recovery."""
import os
from pathlib import Path
import random
import re
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
        if any("u" in option[1:] for option in mode) and actual.startswith(b"--- "):
            # The builtin's headers intentionally omit filesystem timestamps.
            self.assertEqual(actual.split(b"\n")[:2], [b"--- a", b"+++ b"])
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

    def test_workload_shapes(self):
        records = [f"record {i:06d}\n".encode() for i in range(1000)]
        sparse = records.copy()
        for i in (0, 100, 501, 999):
            sparse[i] = f"replacement {i}\n".encode()
        cases = [(b"", b""), (b"".join(records), b"".join(records)),
                 (b"".join(records), b"".join(sparse)),
                 (b"left\n" * 180, b"right\n" * 180),
                 (b"x" * 131072 + b"old\nend", b"x" * 131072 + b"new\nend"),
                 (b"a\0b\n", b"a\0b\n"), (b"a\0b\n", b"a\0c\n"),
                 (b"", b"\0"), (b"\0", b""),
                 (b"UPPER\nSame", b"upper\nsame")]
        for a, b in cases:
            for mode in ((), ("-u",), ("-q",), ("-i",), ("-ui",), ("-qi",)):
                with self.subTest(lengths=(len(a), len(b)), mode=mode):
                    self.compare(a, b, mode)
        for offset in (4095, 4096, 65535, 65536):
            prefix = b"x" * offset + b"\0"
            for mode in ((), ("-u",), ("-q",), ("-i",)):
                self.compare(prefix + b"old\n", prefix + b"new\n", mode)

    def test_stdin_operands(self):
        for data in (b"", b"text\n", b"no newline", b"nul\0bytes\n"):
            (self.root / "a").write_bytes(data)
            for operands in (("-", "-"), ("-", "a"), ("a", "-")):
                for mode in ((), ("-u",), ("-q",), ("-i",)):
                    reference = subprocess.run(["/usr/bin/diff", *mode, *operands],
                                               input=data, capture_output=True, env=ENV,
                                               cwd=self.root, timeout=10)
                    result = subprocess.run([BINARY, "--noprofile", "--norc", "-c",
                                             'diff "$@"', "test", *mode, *operands],
                                            input=data, capture_output=True, env=ENV,
                                            cwd=self.root, timeout=10)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (reference.returncode, reference.stdout, reference.stderr))

    def test_same_stdin_leaves_input_for_the_shell(self):
        for mode in ((), ("-u",), ("-q",), ("-i",), ("-ui",), ("-qi",)):
            script = ('COMMAND "$@" - -; printf "diff=%s\\n" "$?"; '
                      'IFS= read -r line; printf "read=%s value=%s\\n" "$?" "$line"')
            results = []
            for command in ("/usr/bin/diff", "diff"):
                # Keep sanitizer preloads in the tested wrapper out of GNU's
                # independent reference process.
                shell_binary = "/bin/bash" if command == "/usr/bin/diff" else BINARY
                results.append(subprocess.run(
                    [shell_binary, "--noprofile", "--norc", "-c", script.replace("COMMAND", command),
                     "test", *mode], input=b"unconsumed\n", capture_output=True,
                    env=ENV, cwd=self.root, timeout=10))
            reference, actual = results
            self.assertEqual((reference.returncode, reference.stdout, reference.stderr),
                             (0, b"diff=0\nread=0 value=unconsumed\n", b""))
            self.assertEqual((actual.returncode, actual.stdout, actual.stderr),
                             (reference.returncode, reference.stdout, reference.stderr))
        result = self.shell('exec 0<&-; diff - -')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))

    def test_invalid_inputs_and_descriptor_cleanup(self):
        (self.root / "a").write_bytes(b"a\n")
        result = self.shell('ulimit -n 32; for ((i=0;i<80;i++)); do '
                            'diff a absent 2>/dev/null; [[ $? == 2 ]] || exit 1; '
                            'diff . a 2>/dev/null; [[ $? == 2 ]] || exit 1; '
                            'diff a a || exit 1; done; printf alive')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"alive", b""))
        for args in ((), ("a",), ("a", "a", "a"), ("-Z", "a", "a")):
            result = self.shell('diff "$@"; r=$?; diff a a || exit 1; exit "$r"', *args)
            self.assertEqual(result.returncode, 2)
            self.assertTrue(result.stderr)

    def test_long_filenames_and_output_order(self):
        left, right = "a" * 180, "b" * 180
        (self.root / left).write_bytes(b"old\n")
        (self.root / right).write_bytes(b"new\n")
        result = self.shell('printf "before:"; diff -u "$1" "$2"; '
                            'printf "status=%s\\n" "$?"', left, right)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, b"before:--- " + left.encode() + b"\n+++ " +
                         right.encode() + b"\n@@ -1 +1 @@\n-old\n+new\nstatus=1\n")

    def test_edit_integrity_with_repeated_records(self):
        # Repeated records can admit several minimal scripts. Independently
        # apply each emitted script and check its cost against an LCS oracle.
        rng = random.Random(20261019)
        for _ in range(120):
            a = [f"record {rng.randrange(5)}\n".encode() for _ in range(rng.randrange(30))]
            b = [f"record {rng.randrange(5)}\n".encode() for _ in range(rng.randrange(30))]
            (self.root / "a").write_bytes(b"".join(a))
            (self.root / "b").write_bytes(b"".join(b))
            result = self.shell('diff a b')
            self.assertEqual(result.returncode, 0 if a == b else 1, result.stderr)
            self.assertEqual(result.stderr, b"")
            lines = iter(result.stdout.splitlines(keepends=True))
            rebuilt, cursor, cost = [], 0, 0
            for header in lines:
                match = re.fullmatch(rb"(\d+)(?:,(\d+))?([acd])(\d+)(?:,(\d+))?\n", header)
                self.assertIsNotNone(match, header)
                lo, hi, op, blo, bhi = match.groups()
                lo, hi = int(lo), int(hi or lo)
                blo, bhi = int(blo), int(bhi or blo)
                before = lo if op == b"a" else lo - 1
                self.assertGreaterEqual(before, cursor)
                rebuilt.extend(a[cursor:before])
                cursor = before
                if op != b"a":
                    for record in a[lo - 1:hi]:
                        self.assertEqual(next(lines), b"< " + record)
                    cost += hi - lo + 1
                    cursor = hi
                if op == b"c":
                    self.assertEqual(next(lines), b"---\n")
                if op != b"d":
                    self.assertEqual(len(rebuilt), blo - 1)
                    for _ in range(bhi - blo + 1):
                        line = next(lines)
                        self.assertTrue(line.startswith(b"> "))
                        rebuilt.append(line[2:])
                        cost += 1
                else:
                    self.assertEqual(len(rebuilt), blo)
            rebuilt.extend(a[cursor:])
            self.assertEqual(rebuilt, b)
            row = [0] * (len(b) + 1)
            for left in a:
                previous = row
                row = [0]
                for j, right in enumerate(b):
                    row.append(previous[j] + 1 if left == right else max(row[-1], previous[j + 1]))
            self.assertEqual(cost, len(a) + len(b) - 2 * row[-1])

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
            for mode in ("", "-u", "-q", "-ui", "-qi"):
                with self.subTest(data=data, mode=mode):
                    result = self.shell('diff ' + mode + ' a b >/dev/full; '
                                        'printf "failed=%s\\n" "$?"; '
                                        'diff a a; printf "again=%s\\n" "$?"')
                    self.assertEqual(result.stdout, b"failed=2\nagain=0\n")
                    self.assertIn(b"write error", result.stderr)


if __name__ == "__main__":
    unittest.main()
