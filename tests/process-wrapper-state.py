#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise wrapper state using only private files and child processes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C"}
ENV.pop("BASH_ENV", None)


class ProcessWrapperState(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-wrapper-state-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        cpu = min(os.sched_getaffinity(0))
        self.wrappers = [
            ["flock", str(self.root / "lock")], ["setsid", "-w"],
            ["ionice", "-c", "2", "-n", "4"], ["taskset", "-c", str(cpu)],
            ["chrt", "-o", "0"], ["prlimit", "--nofile=64:64"],
            ["nice", "-n", "0"], ["nohup"], ["timeout", "2"],
        ]

    def shell(self, script, *args):
        result = subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "wrapper-test", *map(str, args)],
            env=ENV, cwd=self.root, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=8)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_newly_exported_variables_reach_external_commands(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                result = self.shell('export BOS_WRAPPER_PRIVATE_VALUE=visible; '
                                    '"$@" /bin/sh -c \'printf "%s\\n" "$BOS_WRAPPER_PRIVATE_VALUE"\'', *wrapper)
                self.assertEqual((result.returncode, result.stdout), (0, b"visible\n"), result.stderr)

    def test_command_local_environment_reaches_external_commands(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                result = self.shell('BOS_WRAPPER_PRIVATE_VALUE=local "$@" /bin/sh -c '
                                    '\'printf "%s\\n" "$BOS_WRAPPER_PRIVATE_VALUE"\'; '
                                    'printf "parent=%s\\n" "${BOS_WRAPPER_PRIVATE_VALUE-unset}"', *wrapper)
                self.assertEqual((result.returncode, result.stdout), (0, b"local\nparent=unset\n"), result.stderr)

    def test_updated_path_is_used_for_command_lookup(self):
        command = self.root / "private-wrapper-command"
        command.write_text("#!/bin/sh\nprintf 'found\\n'\n")
        command.chmod(0o700)
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                result = self.shell('export PATH=$PWD; "$@" private-wrapper-command', *wrapper)
                self.assertEqual((result.returncode, result.stdout), (0, b"found\n"), result.stderr)

    def test_background_children_are_reaped_and_chld_traps_survive(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                (self.root / "ready").unlink(missing_ok=True)
                result = self.shell(
                    'chld=0; trap "chld=1" CHLD; '
                    '/bin/sh -c \'n=0; while [ ! -e ready ] && [ "$n" -lt 200 ]; '
                    'do /bin/sleep .005; n=$((n+1)); done\' & bg=$!; '
                    '"$@" /bin/sh -c \'printf ready > ready; /bin/sleep .1\'; rc=$?; '
                    'if [[ -r /proc/$bg/stat ]]; then read -r pid comm state rest < /proc/$bg/stat; '
                    'else state=gone; fi; printf "rc=%s state=%s trap=%s\\n" "$rc" "$state" "$chld"; '
                    'wait "$bg"', *wrapper)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"rc=0 state=gone trap=1\n", result.stderr)

    def test_child_status_and_parent_shell_survive_repeated_calls(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                result = self.shell('for status in 7 0 42; do "$@" /bin/sh -c \'exit "$1"\' child "$status"; '
                                    'printf "%s\\n" "$?"; done; printf alive', *wrapper)
                self.assertEqual((result.returncode, result.stdout), (0, b"7\n0\n42\nalive"), result.stderr)

    def test_failed_controlling_terminal_setup_does_not_run_command(self):
        result = self.shell('setsid -w -c /bin/sh -c \'printf ran > marker\'')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "marker").exists())
        self.assertTrue(result.stderr)

    def test_exec_errors_and_shell_stdin_are_preserved(self):
        (self.root / "not-executable").write_text("private fixture\n")
        (self.root / "input").write_text("still open\n")
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                result = self.shell('exec 0<input; "$@" /missing-bash-os-private-command; '
                                    'printf "missing=%s\\n" "$?"; "$@" ./not-executable; '
                                    'printf "denied=%s\\n" "$?"; IFS= read -r line; '
                                    'printf "stdin=%s\\n" "$line"', *wrapper)
                self.assertEqual(result.stdout, b"missing=127\ndenied=126\nstdin=still open\n", result.stderr)

    def test_closed_stdin_and_parent_descriptors_remain_unchanged(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper[0]):
                result = self.shell('exec 0<&-; before=(/proc/$$/fd/*); '
                                    'for i in 1 2 3; do "$@" /bin/true || exit; done; '
                                    'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]] && '
                                    '[[ ! -e /proc/$$/fd/0 ]]', *wrapper)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_fork_flock_exec_failure_releases_descriptor_and_lock(self):
        result = self.shell(
            'before=(/proc/$$/fd/*); '
            'for i in 1 2 3; do flock -F lock /missing-bash-os-private-command; printf "fail=%s\\n" "$?"; done; '
            'after=(/proc/$$/fd/*); printf "fds=%s:%s\\n" "${#before[@]}" "${#after[@]}"; '
            'flock -n lock /bin/true; printf "retry=%s\\n" "$?"')
        lines = result.stdout.splitlines()
        self.assertEqual(lines[:3], [b"fail=127"] * 3, result.stderr)
        before, after = lines[3].removeprefix(b"fds=").split(b":")
        self.assertEqual(before, after)
        self.assertEqual(lines[-1], b"retry=0")

    def test_no_fork_flock_rejects_close_before_exec(self):
        result = self.shell('flock -Fo lock /bin/sh -c \'printf ran > marker\'')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "marker").exists())


if __name__ == "__main__":
    unittest.main()
