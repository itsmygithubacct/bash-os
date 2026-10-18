#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signal lookup never sends signals; exercise bounded names and numbers."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class SignalLookup(unittest.TestCase):
    def run_lookup(self, *args):
        result = subprocess.run([BINARY, "--noprofile", "--norc", "-c", 'signal "$@"',
                                 "signal-test", *args], env=ENV,
                                capture_output=True, timeout=5)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_numeric_arguments_cannot_wrap_or_discard_suffixes(self):
        for value in ("", " ", "4294967311", "9223372036854775807",
                      "9223372036854775808", "15junk", "-4294967281"):
            for args in ([value], ["-s", value]):
                with self.subTest(args=args):
                    result = self.run_lookup(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_realtime_names_require_complete_bounded_offsets(self):
        for value in ("RTMINjunk", "RTMAXjunk", "RTMIN+", "RTMAX-", "RTMIN-1",
                      "RTMAX+1", "RTMIN+-1", "RTMAX--1", "RTMIN+2147483647",
                      "RTMAX-2147483648", "RTMIN+4294967296", "RTMAX-4294967296",
                      "RTMIN+9223372036854775807", "RTMIN+" + "0" * 40 + "1"):
            for args in ([value], ["-n", value]):
                with self.subTest(args=args):
                    result = self.run_lookup(*args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_valid_names_match_bash_signal_table(self):
        for name in ("TERM", "HUP", "USR1", "RTMIN", "RTMAX", "RTMIN+1", "RTMAX-1"):
            with self.subTest(name=name):
                reference = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c",
                                            'kill -l "$1"', "reference", name],
                                           env=ENV, capture_output=True, timeout=5, check=True)
                result = self.run_lookup("-n", "SIG" + name)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, reference.stdout, b""))

    def test_repeated_realtime_lookups_keep_own_values(self):
        command = 'for value in RTMIN RTMIN+1 RTMAX-1 RTMAX; do signal -n "$value"; done; signal -s 15'
        result = subprocess.run([BINARY, "--noprofile", "--norc", "-c", command],
                                env=ENV, capture_output=True, timeout=5)
        expected = f"{signal.SIGRTMIN}\n{signal.SIGRTMIN + 1}\n{signal.SIGRTMAX - 1}\n{signal.SIGRTMAX}\nTERM\n".encode()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))


if __name__ == "__main__":
    unittest.main()
