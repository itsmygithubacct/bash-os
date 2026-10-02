#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare selected command behavior with the installed Debian/GNU programs.

Usage: python3 tests/debian-parity.py [BINARY] [--reference-only]

This is a strict audit: existing mismatches fail instead of being accepted as
the builtin's contract. --reference-only runs the host on both sides to check
fixture isolation and determinism. No system files are modified. Filesystem
cases use independent temporary trees, compare bytes, modes, ownership, link
topology and symlink targets. Selected fixtures also compare seeded timestamps;
other timestamps and absolute inodes are ignored.
Text comparisons preserve every stdout byte and compare exit status; diagnostic
wording is not required to match, but rejected input must produce a diagnostic.
"""

import argparse
import grp
import itertools
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", nargs="?", default="out/bash")
parser.add_argument("--reference-only", action="store_true")
args, unittest_args = parser.parse_known_args()
BINARY = str(Path(args.binary).resolve())
ENV = {**os.environ, "LC_ALL": "C", "TZ": "UTC"}
for key in ("BASH_ENV", "ENV"):
    ENV.pop(key, None)


def snapshot(root, metadata=None):
    """Use the first path for each inode as a stable hard-link group name."""
    entries, links = {}, {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        st = path.lstat()
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            group = links.setdefault((st.st_dev, st.st_ino), name)
            entries[name] = ("symlink", os.readlink(path), group)
        elif stat.S_ISDIR(st.st_mode):
            entries[name] = ("directory", mode)
        elif stat.S_ISREG(st.st_mode):
            group = links.setdefault((st.st_dev, st.st_ino), name)
            entries[name] = ("file", mode, path.read_bytes(), group)
        else:
            raise AssertionError(f"unexpected fixture type: {path}")
        entries[name] += (st.st_uid, st.st_gid)
        if metadata and name in metadata:
            entries[name] += tuple(getattr(st, field) for field in metadata[name])
    return entries


class DebianParity(unittest.TestCase):
    def run_command(self, program, arguments, root, builtin, data=b"", script=None):
        reference = Path("/usr/bin") / program
        if not reference.is_file():
            self.skipTest(f"missing reference: {reference}")
        if builtin and not args.reference_only:
            command = ["coreutils", program] if program == "install" else [program]
            argv = [BINARY, "--noprofile", "--norc", "-c",
                    'umask 022; PATH=; ' + (script or '"$@"'), "parity", *command, *arguments]
        else:
            argv = ["/bin/bash", "--noprofile", "--norc", "-c",
                    'umask 022; ' + (script or 'exec "$@"'), "parity", str(reference), *arguments]
        return subprocess.run(argv, cwd=root, env=ENV, input=data,
                              capture_output=True, timeout=10)

    def compare(self, program, arguments, data=b"", setup=None, status=0, script=None,
                metadata=None):
        results = []
        for builtin in (False, True):
            with tempfile.TemporaryDirectory(prefix="bash-os-debian-") as directory:
                root = Path(directory)
                if setup:
                    setup(root)
                result = self.run_command(program, arguments, root, builtin, data, script)
                results.append((result, snapshot(root, metadata) if setup else None))
        expected, actual = results
        self.assertEqual(expected[0].returncode, status,
                         f"reference failed: {expected[0].stderr!r}")
        if status:
            self.assertTrue(expected[0].stderr, "reference omitted error diagnostic")
            self.assertTrue(actual[0].stderr, "builtin accepted invalid input silently")
        else:
            self.assertEqual(actual[0].stderr, expected[0].stderr)
        self.assertEqual(actual[0].returncode, expected[0].returncode,
                         f"builtin stderr: {actual[0].stderr!r}")
        self.assertEqual(actual[0].stdout, expected[0].stdout)
        self.assertEqual(actual[1], expected[1])

    def test_tr_translation_and_squeezing(self):
        cases = [
            (["a-z", "A-Z"], b"abc XYZ\n\n"),
            (["-d", "\\000"], b"a\0b\0\n"),
            (["-s", " "], b"a   b  \n"),
            (["-ds", "[:digit:]", " "], b"a1  2 b3\n"),
            (["-cd", "[:alnum:] "], b"a!  b?\n"),
            (["-cs", "[:alnum:]", " "], b"a!!!b??c\n"),
            (["-t", "abc", "XY"], b"abcabc\n"),
            (["abc", "[x*]"], b"abc\n"),
            (["[:lower:]", "[:upper:]"], b"letters\n"),
            (["-s", "\\n"], b"a\n\nb\n\n"),
        ]
        for arguments, data in cases:
            with self.subTest(arguments=arguments):
                self.compare("tr", arguments, data)

    def test_tr_complement_delete_squeeze(self):
        self.compare("tr", ["-cds", "[:alnum:] ", " "], b"a   b\n")

    def test_tr_whitespace_class_order(self):
        self.compare("tr", ["[:space:]", "123456"], b" \t\n\v\f\r")
        self.compare("tr", ["[:blank:]", "12"], b" \t")

    def test_tr_long_expanded_operands(self):
        self.compare("tr", [r"\000-\377a", "[x*256]y"], bytes(range(256)))
        for count in (255, 256, 257, 1024):
            with self.subTest(count=count):
                self.compare("tr", ["a" * count + "b", f"[x*{count}]y"], b"ab\n")
                self.compare("tr", ["-t", "a" * count + "b", "[x*256]y"], b"ab\n")
        self.compare("tr", ["ab", "[x*1000000000]"], b"ab\n")

    def test_tr_indefinite_repeat_reserves_other_elements(self):
        for set2 in ("[x*]y", "p[x*]yz", "[x*0]a-c", "[x*][y*2]",
                     "p[x*]", "[x*]abcdef"):
            with self.subTest(set2=set2):
                self.compare("tr", ["abcde", set2], b"abcde\n")
                self.compare("tr", ["-t", "abcde", set2], b"abcde\n")
        self.compare("tr", ["-s", "a", "[x*]y"], b"xxxaaa")
        self.compare("tr", ["", "[x*]"], b"abc")
        self.compare("tr", ["-c", "a", "[x*]y"], b"a\0\xff")

    def test_tr_rejects_invalid_indefinite_repeats(self):
        for arguments in (["abc", "[x*][y*]"], ["-ds", "a", "[x*]y"]):
            with self.subTest(arguments=arguments):
                self.compare("tr", arguments, b"abc", status=1)

    def test_tr_unknown_character_class_is_rejected(self):
        for arguments in (["[:bogus:]", "x"], ["a", "[:bogus:]"],
                          ["-d", "[:bogus:]"], ["-s", "[::]"],
                          ["-d", "[:unknownclassname:]"]):
            with self.subTest(arguments=arguments):
                self.compare("tr", arguments, b"abc\n", status=1)

    def test_date_integral_epochs_and_timezones(self):
        for value in ("@0", "@1", "@-1", "2024-02-29T12:34:56Z",
                      "2024-02-29T12:34:56+05:30"):
            with self.subTest(value=value):
                self.compare("date", ["-u", "-d", value, "+%Y-%m-%d %H:%M:%S %s %:z"])

    def test_date_fractional_epoch(self):
        self.compare("date", ["-u", "-d", "@1.25", "+%s.%N"])

    def test_date_negative_fractional_epoch(self):
        self.compare("date", ["-u", "-d", "@-0.5", "+%s.%N"])

    def test_date_rejects_invalid_calendar_dates(self):
        for value in ("2024-02-30", "2023-02-29", "2024-04-31T12:00:00Z",
                      "2024-02-30T01:00:00+01:00", "30 Feb 2024 00:00:00 UTC"):
            with self.subTest(value=value):
                self.compare("date", ["-u", "-d", value, "+%F"], status=1)

    def test_date_pre_epoch_calendar_timestamp(self):
        for value in ("1969-12-31T23:59:59Z", "1969-12-31 23:59:59",
                      "1970-01-01T00:59:59+01:00", "31 Dec 1969 23:59:59 GMT"):
            with self.subTest(value=value):
                self.compare("date", ["-d", value, "+%s"])

    def test_date_nanosecond_precision(self):
        for value in ("@0.000000001", "@-0.000000001", "@+1.25",
                      "@1.1234567899", "@-1.1234567899", "@-0.0000000001",
                      "@-1.0000000000"):
            with self.subTest(value=value):
                self.compare("date", ["-u", "-d", value, "+%s.%N|%3N|%1N"])

    @staticmethod
    def copy_tree(root):
        (root / "src").mkdir()
        (root / "src" / "file").write_bytes(b"contents\0\n")
        (root / "dst").mkdir()

    def test_copy_directory(self):
        self.compare("cp", ["-R", "src", "dst"], setup=self.copy_tree)

    def test_copy_directory_trailing_slash(self):
        for source in ("src/", "src///", "./src/"):
            with self.subTest(source=source):
                self.compare("cp", ["-R", source, "dst"], setup=self.copy_tree)

    def test_copy_archive_hardlinks(self):
        def setup(root):
            self.copy_tree(root)
            os.link(root / "src" / "file", root / "src" / "alias")
        self.compare("cp", ["-a", "src", "dst"], setup=setup)

    def test_copy_hardlinks_across_operands(self):
        def setup(root):
            self.copy_tree(root)
            os.link(root / "src" / "file", root / "src" / "alias")
        self.compare("cp", ["-a", "src/file", "src/alias", "dst"], setup=setup)

    def test_copy_hardlink_tracking_is_per_invocation(self):
        def setup(root):
            self.copy_tree(root)
            os.link(root / "src" / "file", root / "src" / "alias")
        self.compare("cp", ["-a", "src", "dst"], setup=setup,
                     script='"$@" || exit; printf changed > src/file; "$@"')

    def test_copy_plain_recursive_does_not_preserve_hardlinks(self):
        def setup(root):
            self.copy_tree(root)
            os.link(root / "src" / "file", root / "src" / "alias")
        self.compare("cp", ["-R", "src", "dst"], setup=setup)

    def test_copy_archive_hardlinked_symlinks(self):
        def setup(root):
            self.copy_tree(root)
            (root / "src" / "link").symlink_to("file")
            os.link(root / "src" / "link", root / "src" / "alias", follow_symlinks=False)
        self.compare("cp", ["-a", "src", "dst"], setup=setup)

    def test_copy_archive_dereferenced_alias(self):
        def setup(root):
            self.copy_tree(root)
            (root / "src" / "alias").symlink_to("file")
        self.compare("cp", ["-aL", "src", "dst"], setup=setup)

    def test_copy_archive_symlink(self):
        def setup(root):
            self.copy_tree(root)
            (root / "src" / "alias").symlink_to("file")
        self.compare("cp", ["-a", "src", "dst"], setup=setup)

    def test_copy_archive_preserves_symlink_times(self):
        for dangling in (False, True):
            for existing in (False, True):
                def setup(root):
                    (root / "target").write_bytes(b"target contents\n")
                    (root / "src").symlink_to("missing" if dangling else "target")
                    os.utime(root / "src", ns=(1234567890123456789, 1234567890987654321),
                             follow_symlinks=False)
                    if existing:
                        (root / "dst").symlink_to("old-target")
                with self.subTest(dangling=dangling, existing=existing):
                    self.compare("cp", ["-a", "src", "dst"], setup=setup,
                                 metadata={"dst": ("st_atime_ns", "st_mtime_ns")})

    def test_copy_archive_destination_collision(self):
        def setup(root):
            for name in ("a", "b", "dst"):
                (root / name).mkdir()
            (root / "a/file").write_bytes(b"first source\n")
            (root / "b/file").write_bytes(b"second source\n")
            os.link(root / "a/file", root / "a/alias")
        self.compare("cp", ["-a", "a/file", "b/file", "a/alias", "dst"],
                     setup=setup, status=1)

    def test_copy_preserves_special_modes(self):
        for mode in (0o4755, 0o2755, 0o6755):
            def setup(root):
                (root / "src").write_bytes(b"mode fixture\n")
                (root / "src").chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.compare("cp", ["-p", "src", "dst"], setup=setup)

    def test_copy_timestamps_through_destination_symlink(self):
        def setup(root):
            (root / "src").write_bytes(b"new contents\n")
            (root / "target").write_bytes(b"old contents\n")
            (root / "dst").symlink_to("target")
            os.utime(root / "src", ns=(1234567890123456789, 1234567890765432100))
            os.utime(root / "dst", ns=(1200000000000000000, 1200000000000000000),
                     follow_symlinks=False)
        self.compare("cp", ["-p", "src", "dst"], setup=setup,
                     metadata={"target": ("st_atime_ns", "st_mtime_ns"),
                               "dst": ("st_mtime_ns",)})

    def compare_move(self, setup, sources, flags=(), cross_device=False, status=0,
                     script=None):
        results = []
        if cross_device and (not Path("/dev/shm").is_dir() or
                             not os.access("/dev/shm", os.W_OK)):
            self.skipTest("need a writable second filesystem")
        for builtin in (False, True):
            with tempfile.TemporaryDirectory() as source_dir, \
                    tempfile.TemporaryDirectory(dir="/dev/shm" if cross_device else None) as dest_dir:
                root, dest = Path(source_dir), Path(dest_dir)
                if cross_device and root.stat().st_dev == dest.stat().st_dev:
                    self.skipTest("temporary directories use the same filesystem")
                setup(root, dest)
                result = self.run_command("mv", [*flags, *sources, str(dest)], root, builtin,
                                          script=script)
                self.assertEqual(result.returncode, status, result.stderr)
                if status:
                    self.assertTrue(result.stderr)
                else:
                    self.assertEqual(result.stderr, b"")
                results.append((snapshot(root), snapshot(dest)))
        self.assertEqual(results[0], results[1])

    def test_move_operand_collisions(self):
        def setup(root, dest):
            for name in ("a", "b"):
                (root / name).mkdir()
                (root / name / "file").write_bytes(name.encode())
        for cross in (False, True):
            for flags in ([], ["-f"], ["-n"]):
                with self.subTest(cross_device=cross, flags=flags):
                    self.compare_move(setup, ["a/file", "b/file"], flags, cross,
                                      status=0 if flags == ["-n"] else 1)

    def test_move_cross_device_special_modes(self):
        for directory in (False, True):
            for mode in (0o4755, 0o2755, 0o6755):
                def setup(root, dest):
                    path = root / "src"
                    if directory:
                        path.mkdir()
                        (path / "file").write_bytes(b"directory contents\n")
                    else:
                        path.write_bytes(b"file contents\n")
                    path.chmod(mode)
                with self.subTest(directory=directory, mode=oct(mode)):
                    self.compare_move(setup, ["src"], cross_device=True)

    def test_move_empty_directory_collisions(self):
        def setup(root, dest):
            for name in ("a", "b"):
                (root / name / "empty").mkdir(parents=True)
        for cross in (False, True):
            with self.subTest(cross_device=cross):
                self.compare_move(setup, ["a/empty", "b/empty"], cross_device=cross)

    def test_move_cross_device_directory_under_restrictive_umask(self):
        def setup(root, dest):
            (root / "src/nested").mkdir(parents=True)
            (root / "src/nested/file").write_bytes(b"move contents\n")
            (root / "src").chmod(0o750)
            (root / "src/nested").chmod(0o751)
        for mask in ("077", "0777"):
            with self.subTest(mask=mask):
                self.compare_move(setup, ["src"], cross_device=True,
                                  script=f'umask {mask}; "$@"')

    def test_copy_archive_merges_directory_operands(self):
        def setup(root):
            for name in ("a/src", "b/src", "dst"):
                (root / name).mkdir(parents=True)
            (root / "a/src/file").write_bytes(b"first\n")
            os.link(root / "a/src/file", root / "a/src/alias")
            (root / "b/src/file").write_bytes(b"second\n")
        self.compare("cp", ["-a", "a/src", "b/src", "dst"], setup=setup)

    def test_copy_archive_refreshes_symlinks(self):
        def setup(root):
            self.copy_tree(root)
            (root / "src/link").symlink_to("file")
        self.compare("cp", ["-a", "src", "dst"], setup=setup,
                     script='"$@" || exit; "$@"')

    def test_copy_archive_symlink_interactive(self):
        def setup(root):
            (root / "src").symlink_to("new-target")
            (root / "dst").symlink_to("old-target")
        for answer in (b"n\n", b"y\n"):
            with self.subTest(answer=answer):
                # Prompt wording differs; compare resulting state and status.
                self.compare("cp", ["-ai", "src", "dst"], setup=setup,
                             data=answer, status=1 if answer == b"n\n" else 0,
                             script=None if answer == b"n\n" else '"$@" 2>/dev/null')

    def test_move_cross_device_hardlinks(self):
        if not Path("/dev/shm").is_dir() or not os.access("/dev/shm", os.W_OK):
            self.skipTest("need a writable second filesystem")
        for kind in ("regular", "symlink", "operands", "repeated"):
            results = []
            with self.subTest(kind=kind):
                for builtin in (False, True):
                    with tempfile.TemporaryDirectory() as source_dir, \
                            tempfile.TemporaryDirectory(dir="/dev/shm") as dest_dir:
                        root, dest = Path(source_dir), Path(dest_dir)
                        if root.stat().st_dev == dest.stat().st_dev:
                            self.skipTest("temporary directories use the same filesystem")
                        (root / "src").mkdir()
                        first = root / "src/first"
                        if kind == "symlink":
                            first.symlink_to("target")
                        else:
                            first.write_bytes(b"linked contents\n")
                        for name in ("second", "third"):
                            os.link(first, root / "src" / name, follow_symlinks=False)
                        if kind == "repeated":
                            (root / "src2").mkdir()
                            os.link(first, root / "src2/first")
                        sources = (["src/first", "src/second", "src/third"]
                                   if kind == "operands" else ["src"])
                        if kind == "repeated":
                            result = self.run_command("mv", [str(dest)], root, builtin,
                                script='"$1" src "$2" || exit; "$1" src2 "$2"')
                        else:
                            result = self.run_command("mv", [*sources, str(dest)], root, builtin)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, b"")
                        results.append((snapshot(root), snapshot(dest)))
                self.assertEqual(results[0], results[1])

    @staticmethod
    def install_files(root):
        (root / "src").write_bytes(b"new\n")
        (root / "dst").write_bytes(b"old contents\n")

    def test_install_regular_file(self):
        self.compare("install", ["-m", "644", "src", "dst"], setup=self.install_files)

    def test_install_D_preserves_existing_parent_modes(self):
        for mode in (0o700, 0o750, 0o2750):
            def setup(root):
                (root / "src").write_bytes(b"contents\n")
                (root / "private").mkdir()
                (root / "private").chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.compare("install", ["-D", "src", "private/dst"], setup=setup)

    def test_install_D_creates_missing_parents(self):
        def setup(root):
            (root / "src").write_bytes(b"contents\n")
        self.compare("install", ["-D", "src", "new/parent/dst"], setup=setup)

    def test_install_D_parent_modes_ignore_umask(self):
        for mask in ("077", "0777"):
            for mode in (0o700, 0o2750):
                def setup(root):
                    (root / "src").write_bytes(b"contents\n")
                    (root / "private").mkdir()
                    (root / "private").chmod(mode)
                with self.subTest(mask=mask, mode=oct(mode)):
                    self.compare("install", ["-D", "src", "private/new/parent/dst"],
                                 setup=setup,
                                 script=f'umask {mask}; "$@"; rc=$?; umask; exit "$rc"')

    def test_install_d_changes_existing_directory_mode(self):
        def setup(root):
            (root / "dst").mkdir(mode=0o700)
        self.compare("install", ["-d", "-m", "750", "dst"], setup=setup)

    def test_install_invalid_ownership_preserves_destination(self):
        for flag, lookup in (("-o", pwd.getpwnam), ("-g", grp.getgrnam)):
            missing = "bashos-missing-account-6fd583"
            try:
                lookup(missing)
            except KeyError:
                pass
            else:
                self.skipTest("invalid identity fixture unexpectedly exists")
            for name in (missing, "", "-1", "999999999999999999999999999999999"):
                with self.subTest(flag=flag, name=name):
                    self.compare("install", [flag, name, "src", "dst"],
                                 setup=self.install_files, status=1)

    def test_install_requested_ownership(self):
        groups = [g for g in os.getgroups() if g != os.getgid()]
        gid = groups[0] if groups else os.getgid()
        owners = (pwd.getpwuid(os.getuid()).pw_name, str(os.getuid()))
        groups = (grp.getgrgid(gid).gr_name, str(gid))
        for owner, group, directory, mode in itertools.product(
                owners, groups, (False, True), ("755", "6755")):
            with self.subTest(owner=owner, group=group, directory=directory, mode=mode):
                arguments = ["-o", owner, "-g", group, "-m", mode]
                arguments += ["-d", "dst"] if directory else ["src", "dst"]
                def setup(root):
                    (root / "src").write_bytes(b"ownership fixture\n")
                self.compare("install", arguments, setup=setup)

    def test_install_denied_ownership_fails(self):
        if os.geteuid() == 0:
            self.skipTest("needs an unprivileged caller")
        self.compare("install", ["-o", "0", "src", "dst"],
                     setup=self.install_files, status=1)

    def test_install_missing_source_preserves_destination(self):
        self.compare("install", ["missing", "dst"], setup=self.install_files, status=1)

    def test_install_read_error_is_reported(self):
        # This proc file opens successfully but a read at offset zero fails.
        # It exercises the read-error path without accessing another process.
        try:
            with open("/proc/self/mem", "rb", buffering=0) as stream:
                try:
                    stream.read(1)
                except OSError:
                    pass
                else:
                    self.skipTest("proc fixture does not generate a read error")
        except OSError:
            self.skipTest("proc read-error fixture unavailable")
        self.compare("install", ["/proc/self/mem", "dst"],
                     setup=self.install_files, status=1)

    def test_install_directory_source_preserves_destination(self):
        def setup(root):
            (root / "src").mkdir()
            (root / "dst").write_bytes(b"keep this file\n")
        self.compare("install", ["src", "dst"], setup=setup, status=1)

    def test_install_destination_hardlink(self):
        def setup(root):
            self.install_files(root)
            os.link(root / "dst", root / "alias")
        self.compare("install", ["-m", "644", "src", "dst"], setup=setup)

    def test_install_destination_symlink(self):
        def setup(root):
            self.install_files(root)
            (root / "alias").symlink_to("dst")
        self.compare("install", ["-m", "644", "src", "alias"], setup=setup)

    def test_snapshot_detects_hardlink_and_symlink_changes(self):
        with tempfile.TemporaryDirectory(prefix="bash-os-snapshot-") as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"same bytes")
            os.link(root / "a", root / "b")
            linked = snapshot(root)
            (root / "b").unlink()
            (root / "b").write_bytes(b"same bytes")
            separate = snapshot(root)
            self.assertNotEqual(linked, separate)
            (root / "b").unlink()
            (root / "b").symlink_to("a")
            self.assertNotEqual(separate, snapshot(root))

    def test_comparison_detects_missing_newlines_and_nuls(self):
        for changed in (b"a\0b", b"ab\n\n"):
            with self.subTest(changed=changed):
                results = [subprocess.CompletedProcess([], 0, output, b"")
                           for output in (b"a\0b\n\n", changed)]
                with mock.patch.object(self, "run_command", side_effect=results):
                    with self.assertRaises(AssertionError):
                        self.compare("printf", ["unused"])


if __name__ == "__main__":
    unittest.main(argv=[__file__, *unittest_args])
