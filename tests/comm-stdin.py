#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare comm's stdin lifetime and recovery with separate GNU processes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class CommStdin(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-comm-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "first").write_bytes(b"a\nb\n")
        (self.root / "second").write_bytes(b"b\nc\n")
        (self.root / "common").write_bytes(b"b\n")

    def compare(self, script, data=b"", expected=None):
        results = []
        for binary, prefix in (("/bin/bash", 'comm() { /usr/bin/comm "$@"; };\n'),
                               (BINARY, "")):
            result = subprocess.run(
                [binary, "--noprofile", "--norc", "-c", prefix + script],
                input=data, capture_output=True, timeout=15, cwd=self.root, env=ENV)
            self.assertNotIn(b"AddressSanitizer", result.stderr)
            self.assertNotIn(b"runtime error:", result.stderr)
            results.append((result.returncode, result.stdout, result.stderr))
        self.assertEqual(results[0][0], 0, results[0])
        self.assertEqual(results[0][2], b"", results[0])
        if expected is not None:
            self.assertEqual(results[0][1], expected)
        self.assertEqual(results[1], results[0])

    def test_repeated_redirected_stdin_in_either_operand(self):
        for zero in (False, True):
            delimiter = b"\0" if zero else b"\n"
            for name, lines in (("first", [b"a", b"b"]), ("second", [b"b", b"c"]),
                                ("common", [b"b"])):
                (self.root / name).write_bytes(delimiter.join(lines) + delimiter)
            for operands in ("- common", "common -"):
                with self.subTest(zero=zero, operands=operands):
                    flags = "-z12" if zero else "-12"
                    self.compare(f"comm {flags} {operands} <first; "
                                 f"comm {flags} {operands} <second",
                                 expected=(b"b" + delimiter) * 2)

    def test_empty_and_unterminated_inputs_do_not_poison_next_call(self):
        (self.root / "empty").write_bytes(b"")
        (self.root / "unterminated").write_bytes(b"b")
        self.compare("comm -12 - common <empty; comm -12 - common <unterminated; "
                     "comm -12 - common <second", expected=b"b\nb\n")

    def test_sort_error_discards_buffered_records_before_next_redirection(self):
        (self.root / "bad").write_bytes(b"b\na\n" + b"z\n" * 4000)
        (self.root / "later").write_bytes(b"y\n")
        for operands in ("- later", "later -"):
            with self.subTest(operands=operands):
                self.compare(f"comm --check-order {operands} <bad >/dev/null 2>/dev/null; "
                             'printf "status=%s\\n" "$?"; '
                             "comm -12 - common <second", expected=b"status=1\nb\n")

    def test_success_and_open_failure_release_private_descriptors(self):
        self.compare(
            "ulimit -n 48; for ((i=0; i<128; i++)); do "
            "comm - missing <first 2>/dev/null; [[ $? == 1 ]] || exit 90; "
            "comm missing - <first 2>/dev/null; [[ $? == 1 ]] || exit 91; "
            "comm -12 - common <first >/dev/null || exit 92; done; "
            "comm -12 common - <second", expected=b"b\n")

    def test_shell_stdin_is_still_available_after_redirection(self):
        self.compare("comm -12 - common <first; IFS= read -r line; "
                     'printf "%s\\n" "$line"', data=b"shell input\n",
                     expected=b"b\nshell input\n")

    def test_closed_stdin_reports_failure_and_next_call_recovers(self):
        for operands in ("- common", "common -"):
            with self.subTest(operands=operands):
                self.compare(f"comm {operands} 0<&- >/dev/null 2>/dev/null; "
                             'printf "status=%s\\n" "$?"; '
                             "comm -12 - common <second", expected=b"status=1\nb\n")


if __name__ == "__main__":
    unittest.main()
