#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Only read sysctl values; never write a kernel parameter."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)
MISSING = "bash_os_private_review_missing_key"


class SysctlReadonly(unittest.TestCase):
    def shell(self, script, *args):
        result = subprocess.run([BINARY, "--noprofile", "--norc", "-c", script,
                                 "sysctl-test", *args],
                                env=ENV, capture_output=True, timeout=5)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_ignore_unknown_returns_success_for_all_read_formats(self):
        for flags in ([], ["-n"], ["-N"]):
            with self.subTest(flags=flags):
                result = self.shell('sysctl -e "$@"', *flags, MISSING)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
                result = self.shell('sysctl "$@"', *flags, MISSING)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr)

    def test_regular_reads_match_proc_and_installed_sysctl(self):
        value = Path("/proc/sys/kernel/ostype").read_bytes().rstrip(b"\n")
        for flags, expected in (([], b"kernel.ostype = " + value + b"\n"),
                                (["-n"], value + b"\n"), (["-N"], b"kernel.ostype\n")):
            with self.subTest(flags=flags):
                result = self.shell('sysctl "$@"', *flags, "kernel.ostype")
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))
                if Path("/usr/sbin/sysctl").exists():
                    reference = subprocess.run(["/usr/sbin/sysctl", *flags, "kernel.ostype"],
                                               env=ENV, capture_output=True, timeout=5)
                    self.assertEqual(result.stdout, reference.stdout)

    def test_ignore_and_pattern_flags_do_not_leak_between_calls(self):
        result = self.shell('sysctl -e "$1"; printf "ignored=%s\\n" "$?"; '
                            'sysctl "$1" 2>/dev/null; printf "strict=%s\\n" "$?"; '
                            'sysctl -r "^never_matches$" kernel.ostype; sysctl -N kernel.ostype', MISSING)
        self.assertEqual((result.returncode, result.stdout),
                         (0, b"ignored=0\nstrict=1\nkernel.ostype\n"), result.stderr)

    def test_repeated_reads_preserve_closed_stdin_and_descriptor_count(self):
        result = self.shell('exec 0<&-; before=(/proc/$$/fd/*); '
                            'for i in 1 2 3; do sysctl -n kernel.ostype >/dev/null || exit; done; '
                            'after=(/proc/$$/fd/*); '
                            '[[ ${#before[@]} == ${#after[@]} && ! -e /proc/$$/fd/0 ]]')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
