#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate process targets and timer bounds without touching other processes."""
import fcntl
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class ProcessNumeric(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-syscall-fixture-")
        cls.addClassCleanup(directory.cleanup)
        cls.launcher = str(Path(directory.name) / "deny-syscall")
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-O2", "-Wall", "-Wextra", str(ROOT / "tests/fixtures/deny-wrapper-syscall.c"),
            "-o", cls.launcher], check=True, capture_output=True, timeout=60)

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-process-numeric-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def shell(self, script, *args, deny=None, increase_nice=False, timeout=5):
        command = [BINARY, "--noprofile", "--norc", "-c", script, "numeric-test", *map(str, args)]
        if deny:
            command = [self.launcher, deny, *command]
        result = subprocess.run(command, env=ENV, cwd=self.root, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout,
                                preexec_fn=(lambda: os.nice(1)) if increase_nice else None)
        if deny and result.returncode == 77:
            self.skipTest("private seccomp fixture is unavailable")
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_overflowed_descriptor_never_aliases_an_open_descriptor(self):
        result = self.shell('exec 9>lock; flock 4294967305; printf "bad=%s\\n" "$?"; '
                            'flock -n lock /bin/true; printf "free=%s\\n" "$?"')
        self.assertNotEqual(result.stdout.splitlines()[0], b"bad=0")
        self.assertEqual(result.stdout.splitlines()[-1], b"free=0")

    def test_conflict_status_is_validated_before_locking(self):
        for flag in ("-E", "--conflict-exit-code"):
            for value in ("", "garbage", "256", "-1", "4294967296", "7tail"):
                with self.subTest(flag=flag, value=value):
                    result = self.shell('flock "$1" "$2" lock /bin/true', flag, value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((self.root / "lock").exists())

    def test_nonfinite_lock_wait_is_rejected_even_without_contention(self):
        for flag in ("-w", "--wait"):
            for value in ("nan", "inf", "-inf"):
                with self.subTest(flag=flag, value=value):
                    result = self.shell('exec 9>lock; flock "$1" "$2" 9', flag, value)
                    self.assertNotEqual(result.returncode, 0)

    def test_nan_lock_wait_cannot_spin_forever_when_contended(self):
        with (self.root / "lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.shell('flock -w nan lock /bin/true', timeout=1)
            self.assertNotEqual(result.returncode, 0)

    def test_large_nice_adjustments_saturate_without_integer_wrap(self):
        for value in ("2147483647", "4294967296", "9223372036854775807"):
            with self.subTest(value=value):
                result = self.shell('before=$(/usr/bin/nice); nice -n "$1" /usr/bin/nice; '
                                    'after=$(/usr/bin/nice); [[ $before == "$after" ]]',
                                    value, increase_nice=True)
                self.assertEqual((result.returncode, result.stdout), (0, b"19\n"), result.stderr)

    def test_timeout_rejects_nan_before_running_a_command(self):
        for value in ("nan", "NAN", "nan(payload)"):
            with self.subTest(value=value):
                (self.root / "marker").unlink(missing_ok=True)
                result = self.shell('timeout "$1" /bin/sh -c \'printf ran > marker\'', value)
                self.assertEqual(result.returncode, 125)
                self.assertFalse((self.root / "marker").exists())

    def test_timeout_accepts_large_durations_without_unsafe_time_casts(self):
        for value in ("inf", "1e999", "1e300d", "9223372036854775808"):
            with self.subTest(value=value):
                result = self.shell('timeout "$1" /bin/sleep .01; printf "alive=%s\\n" "$?"', value)
                self.assertEqual((result.returncode, result.stdout), (0, b"alive=0\n"), result.stderr)

    def test_timeout_rejects_wrapped_or_overflowed_signal_numbers(self):
        for value in ("4294967311", "9223372036854775808", "RTMIN+9223372036854775807"):
            with self.subTest(value=value):
                (self.root / "marker").unlink(missing_ok=True)
                result = self.shell('timeout -s "$1" 1 /bin/sh -c \'printf ran > marker\'', value)
                self.assertEqual(result.returncode, 125)
                self.assertFalse((self.root / "marker").exists())

    def test_timeout_without_pidfd_returns_when_the_child_finishes(self):
        start = time.monotonic()
        result = self.shell('timeout 1.5 /bin/sleep .01', deny="pidfd")
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, .75, f"short child took {elapsed:.3f}s without pidfd")

    def test_overflowed_process_queries_do_not_alias_pid_zero(self):
        for command in ("ionice", "taskset", "chrt", "uclampset"):
            for value in ("4294967296", "9223372036854775807", " ", ""):
                with self.subTest(command=command, value=value):
                    result = self.shell('"$1" -p "$2"', command, value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_missing_io_priority_target_reports_failure(self):
        result = self.shell('ionice -p 2147483647')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_io_priority_never_silently_drops_excess_targets(self):
        result = self.shell('ionice "$@"', *(["-p", "0"] * 257))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)

    def test_io_priority_classes_without_data_work(self):
        for value, expected in (("0", b"none: prio 0\n"), ("3", b"idle\n")):
            with self.subTest(value=value):
                result = self.shell('ionice -c "$1" /usr/bin/ionice', value)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b""))

    def test_failed_io_priority_setup_stops_command_unless_ignored(self):
        result = self.shell('ionice -c2 -n4 /bin/sh -c \'printf ran > marker\'', deny="ioprio")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "marker").exists())
        result = self.shell('ionice -t -c2 -n4 /bin/sh -c \'printf ran > marker\'', deny="ioprio")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "marker").read_bytes(), b"ran")

    def test_invalid_renice_targets_never_change_the_calling_process(self):
        for value in ("", "garbage", "4294967296", "9223372036854775807"):
            with self.subTest(value=value):
                result = self.shell('before=$(/usr/bin/nice); renice 19 -p "$1"; printf "bad=%s\\n" "$?"; '
                                    'after=$(/usr/bin/nice); [[ $before == "$after" ]]', value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotEqual(result.stdout, b"bad=0\n")

    def test_invalid_renice_priority_and_uid_are_rejected_before_syscall(self):
        for priority, uid in (("garbage", "0"), ("19", ""), ("19", "4294967296")):
            with self.subTest(priority=priority, uid=uid):
                result = self.shell('renice "$1" -u "$2"', priority, uid, deny="priority")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()
