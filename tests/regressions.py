#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise builtin behavior in a real bash-os process, using only temporary files."""

import os
from pathlib import Path
import pty
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())


class BuiltinTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-regression-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def shell(self, script, *args, **kwargs):
        return subprocess.run(
            [BINARY, "--noprofile", "--norc", "-c", script, "regression", *args],
            cwd=self.root,
            env={**os.environ, "PATH": "", "LC_ALL": "C"},
            capture_output=True,
            text=True,
            timeout=10,
            **kwargs,
        )


class CopyTests(BuiltinTest):
    def test_same_file_aliases_preserve_source(self):
        source = self.root / "source"
        source.write_text("keep this data\n")
        (self.root / "hardlink").hardlink_to(source)
        (self.root / "symlink").symlink_to("source")
        (self.root / "indirect").symlink_to("hardlink")
        for target in ("source", "hardlink", "symlink", "indirect"):
            with self.subTest(target=target):
                result = self.shell('cp source "$1"', target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("same file", result.stderr)
                self.assertEqual(source.read_text(), "keep this data\n")

    def test_overwrite_truncates_and_follows_other_destination(self):
        (self.root / "source").write_text("new\n")
        target = self.root / "target"
        (self.root / "alias").symlink_to("target")
        for destination in ("target", "alias"):
            with self.subTest(destination=destination):
                target.write_text("long old contents\n")
                result = self.shell('cp source "$1"', destination)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(target.read_text(), "new\n")
                self.assertTrue((self.root / "alias").is_symlink())

    def test_force_replaces_destination_symlink(self):
        source = self.root / "source"
        source.write_text("keep this data\n")
        alias = self.root / "alias"
        alias.symlink_to("source")
        result = self.shell("cp -f source alias")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_text(), "keep this data\n")
        self.assertEqual(alias.read_text(), source.read_text())
        self.assertFalse(alias.is_symlink())


class NohupTests(BuiltinTest):
    def test_parent_signal_trap_survives(self):
        for command in ("/bin/true", "missing-command"):
            with self.subTest(command=command):
                result = self.shell(
                    "trap 'printf handled' HUP; nohup \"$1\"; "
                    "kill -HUP $$; printf ':after\\n'",
                    command,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "handled:after\n")

    def test_parent_terminal_survives(self):
        for command in ("/bin/true", "missing-command"):
            with self.subTest(command=command):
                master, slave = pty.openpty()
                try:
                    result = subprocess.run(
                        [BINARY, "--noprofile", "--norc", "-c",
                         'nohup "$1"; [[ -t 0 && -t 1 && -t 2 ]] || exit 1; '
                         "printf 'after\\n'", "regression", command],
                        cwd=self.root, stdin=slave, stdout=slave, stderr=slave,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertNotIn("after", (self.root / "nohup.out").read_text())
                finally:
                    os.close(slave)
                    os.close(master)

    def test_child_ignores_hangup_and_preserves_exit_status(self):
        result = self.shell('nohup "$1" -c \'kill -HUP $$; exit 23\'', BINARY)
        self.assertEqual(result.returncode, 23, result.stderr)


class WrapperTests(BuiltinTest):
    wrappers = ("env", "nice -n 0", "nohup")

    def test_literal_arguments_without_path(self):
        args = ("", "two words", "*", "$(touch injected)", "`touch injected`",
                "a; touch injected", "a'b\"c", "two\nlines")
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper):
                result = self.shell(wrapper + ' printf "%s\\n" "$@"', *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "\n".join(args) + "\n")
                self.assertFalse((self.root / "injected").exists())

    def test_builtin_statuses_and_missing_commands(self):
        for wrapper in self.wrappers:
            for command, status in (("true", 0), ("false", 1), ("exit 23", 23),
                                    ("missing-command", 127), ("/bin/false", 1)):
                with self.subTest(wrapper=wrapper, command=command):
                    result = self.shell(wrapper + " " + command)
                    self.assertEqual(result.returncode, status, result.stderr)

    def test_disabled_builtin_and_explicit_external_path(self):
        executable = self.root / "printf"
        executable.write_text(f"#!{BINARY}\nprintf 'external\\n'\n")
        executable.chmod(0o755)
        for wrapper in self.wrappers:
            for script, expected in (
                ('PATH=.; printf() { echo shadow; }; ' + wrapper + ' printf builtin', "builtin"),
                ('PATH=.; enable -n printf; ' + wrapper + ' printf', "external\n"),
                (wrapper + ' ./printf', "external\n"),
                ('enable -n printf; ' + wrapper + ' printf', "external\n"),
            ):
                with self.subTest(wrapper=wrapper, script=script):
                    result = self.shell(script)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, expected)
            result = self.shell('enable -n true; ' + wrapper + ' true')
            self.assertEqual(result.returncode, 127, result.stderr)

    def test_child_state_does_not_escape(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper):
                result = self.shell(
                    "trap 'printf exit-trap' EXIT; " + wrapper + " exit 23; "
                    "printf 'status=%s:after:' \"$?\""
                )
                self.assertEqual(result.stdout, "status=23:after:exit-trap")
                result = self.shell(
                    'f() { for i in 1; do ' + wrapper +
                    ' return 7; printf "after:%s" "$?"; done; }; f'
                )
                self.assertEqual(result.stdout, "after:2")
                self.assertIn("can only `return'", result.stderr)

    def test_nested_shell_execution_and_signal_options(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper):
                result = self.shell(
                    wrapper + " eval 'printf one; (printf two); printf three'; "
                    "printf after"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "onetwothreeafter")
        result = self.shell(
            'env --ignore-signal=HUP nice -n 0 "$1" -c '
            "'kill -HUP $$; printf ignored'", BINARY,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ignored")

    def test_external_children_receive_new_exports(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper):
                result = self.shell(
                    'export NAME=updated; ' + wrapper +
                    ' "$1" -c \'printf "%s" "$NAME"\'', BINARY,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "updated")

    def test_wrapper_preserves_parent_job_status(self):
        for wrapper in self.wrappers:
            with self.subTest(wrapper=wrapper):
                result = self.shell(
                    '(sleep 0.05; exit 19) & background=$!; ' + wrapper +
                    ' true; wait "$background"; printf "status=%s" "$?"'
                )
                self.assertEqual(result.stdout, "status=19")

    def test_modified_environment_and_parent_attributes(self):
        result = self.shell(
            'readonly NAME=parent; export NAME; '
            'env -i NAME=child printenv NAME; printf "%s\\n" "$NAME"'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "child\nparent\n")
        result = self.shell('f() { local NAME=local; env NAME=child printenv NAME; }; f')
        self.assertEqual(result.stdout, "child\n")
        result = self.shell('export NAME=parent; env -u NAME printenv NAME')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_clean_and_nested_environment(self):
        for script, expected in (
            ("env -i env", ""),
            ("env -i NAME=child env", "NAME=child\n"),
            ("env -i 'odd-name=literal $value' env", "odd-name=literal $value\n"),
            ("env -i NAME=child nice -n 0 printenv NAME", "child\n"),
            ("env -i NAME=child nohup env", "NAME=child\n"),
            ("env -a alternate printf ok", "ok"),
        ):
            with self.subTest(script=script):
                result = self.shell(script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_child_directory_and_priority(self):
        (self.root / "subdir").mkdir()
        result = self.shell('env -C subdir pwd; pwd')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.root}/subdir\n{self.root}\n")
        result = self.shell('nice; nice -n 1 nice; nice')
        self.assertEqual(result.returncode, 0, result.stderr)
        before, child, after = map(int, result.stdout.split())
        self.assertEqual(after, before)
        self.assertEqual(child, min(before + 1, 19))

    def test_xargs_serial_and_parallel(self):
        args = ["a b", "*", "$(touch injected)", "", "last"]
        for parallel in (1, 2):
            with self.subTest(parallel=parallel):
                result = self.shell(
                    'xargs -0 -n 1 -P "$1" printf "%s\\n"', str(parallel),
                    input="\0".join(args) + "\0",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(sorted(result.stdout.splitlines()), sorted(args))
                self.assertFalse((self.root / "injected").exists())
        for command, data, status in (("false", "", 123), ("exit", "255\0", 124),
                                      ("missing-command", "", 127)):
            with self.subTest(command=command):
                result = self.shell('xargs -0 "$1"', command, input=data)
                self.assertEqual(result.returncode, status, result.stderr)

    def test_find_exec_modes(self):
        (self.root / "files").mkdir()
        for name in ("one", "two words"):
            (self.root / "files" / name).touch()
        for ending in (";", "+"):
            with self.subTest(ending=ending):
                result = self.shell(
                    'find files -type f -exec printf "%s\\n" "{}" "$1"', ending
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(sorted(result.stdout.splitlines()),
                                 ["files/one", "files/two words"])
        result = self.shell('find files -type f -execdir pwd ";"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.root}/files\n" * 2)


if __name__ == "__main__":
    unittest.main()
