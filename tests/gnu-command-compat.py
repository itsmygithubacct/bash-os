#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent GNU comparisons and cross-reader checks in private fixtures."""
import base64
import gzip
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "LC_ALL": "C", "TZ": "UTC", "BASH_ENV": "", "ENV": ""}


class Compatibility(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="bash-os-gnu-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def run_shell(self, script, *args, data=b"", gnu=False, cwd=None):
        environment = {**ENV, "PATH": "/usr/bin:/bin" if gnu else ""}
        if not gnu and environment.get("BASHOS_GNU_TEST_LOAD"):
            script = '. "$BASHOS_GNU_TEST_LOAD" || exit 99;\n' + script
        if not gnu and environment.get("BASHOS_GNU_ASAN_LIB"):
            environment["LD_PRELOAD"] = environment["BASHOS_GNU_ASAN_LIB"]
            environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        result = subprocess.run(
            ["/bin/bash" if gnu else BINARY, "--noprofile", "--norc", "-c", script, "compat", *args],
            cwd=cwd or self.root, input=data, capture_output=True, timeout=15,
            env=environment)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def compare(self, script, *args, data=b"", diagnostic=False):
        expected = self.run_shell(script, *args, data=data, gnu=True)
        actual = self.run_shell(script, *args, data=data)
        self.assertEqual((actual.returncode, actual.stdout), (expected.returncode, expected.stdout),
                         (script, args, actual.stderr, expected.stderr))
        if diagnostic:
            self.assertEqual(bool(actual.stderr), bool(expected.stderr))
        else:
            self.assertEqual(actual.stderr, expected.stderr)
        return actual

    def test_base64_binary_wrapping_and_decoding(self):
        for size in (0, 1, 2, 3, 56, 57, 58, 16385, 65539):
            data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
            for flags in ((), ("-w0",), ("--wrap=7",), ("-w", "76")):
                with self.subTest(size=size, flags=flags):
                    self.compare('base64 "$@"', *flags, data=data)
            for encoded in (base64.b64encode(data), base64.encodebytes(data)):
                self.compare("base64 -d", data=encoded)

    def test_base64_invalid_and_concatenated_groups(self):
        for data in (b"YQ", b"YWI", b"Y", b"YQ=", b"YQ===", b"YQ==Yg==", b"Y Q==",
                     b"YQ=\n=", b"YQ==$foo", b"YQ== ", b"YWJj$", b"\x00YWI=\r"):
            for flag in ("-d", "-di"):
                with self.subTest(data=data, flag=flag):
                    self.compare('base64 "$1"', flag, data=data, diagnostic=True)
        for args in (("--bad",), ("-w", "bad"), ("-w", "-1"), ("-w",), ("one", "two")):
            self.compare('base64 "$@"', *args, diagnostic=True)

    def test_cat_options_and_option_terminator(self):
        (self.root / "-n").write_bytes(b"literal\x00\n")
        (self.root / "--").write_bytes(b"double dash\n")
        self.compare("cat -- -n --")
        self.compare("cat --", data=b"stdin\x00\n")
        for flags in ("-n", "-b", "-nbs", "-A", "-bE", "-s", "-evT", "-u"):
            self.compare('cat "$1"', flags, data=b"\n\nfoo\n\n\x00\t\xff\n\r\x7f\n")
        (self.root / "one").write_bytes(b"partial")
        (self.root / "two").write_bytes(b" line\n\n\nlast")
        self.compare("cat -ns one two")
        self.compare("cat missing-one missing-two", diagnostic=True)

    def test_cp_no_clobber(self):
        (self.root / "source").write_bytes(b"new")
        for flags in (("-n",), ("-nf",), ("-fn",), ("-in",), ("--no-clobber",)):
            for target in ("regular", "dangling", "source"):
                with self.subTest(flags=flags, target=target):
                    path = self.root / target
                    if target == "regular": path.write_bytes(b"old")
                    if target == "dangling" and not path.is_symlink(): path.symlink_to("absent")
                    result = self.run_shell('cp "$@"', *flags, "source", target)
                    self.assertEqual(result.returncode, 1 if target == "dangling" else 0, result.stderr)
                    self.assertEqual(bool(result.stderr), target == "dangling")
                    if target == "regular": self.assertEqual(path.read_bytes(), b"old")
                    if target == "dangling": self.assertEqual(os.readlink(path), "absent")
        result = self.run_shell("cp -ni source regular", data=b"y\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "regular").read_bytes(), b"new")
        (self.root / "dest").mkdir()
        result = self.run_shell("cp -n source dest")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "dest/source").read_bytes(), b"new")

    def test_touch_epoch_exact_nanoseconds(self):
        for value in ("@1234567890", "@0", "@-1", "@-0.25", "@1234567890.123456789",
                      "@-1.000000001", "@+42.5", "@-0.0000000001"):
            with self.subTest(value=value):
                expected = self.run_shell('touch -d "$1" gnu', value, gnu=True)
                actual = self.run_shell('touch --date="$1" ours', value)
                self.assertEqual(actual.returncode, expected.returncode, actual.stderr)
                self.assertEqual((self.root / "ours").stat().st_mtime_ns,
                                 (self.root / "gnu").stat().st_mtime_ns)
                self.assertEqual((self.root / "ours").stat().st_atime_ns,
                                 (self.root / "gnu").stat().st_atime_ns)
        for value in ("@", "@bad", "@1junk", "@999999999999999999999999999999"):
            result = self.run_shell('touch -d "$1" invalid', value)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "invalid").exists())

    def test_sha256_print_and_check(self):
        names = ["data", "two words", "line\nname", "back\\slash", "carriage\rreturn", "-file"]
        for name in names: (self.root / name).write_bytes(b"abc\x00\n" * 10000)
        self.compare("sha256sum", data=b"abc")
        for flags in ((), ("-b",), ("-z",), ("--tag",)):
            self.compare('sha256sum "$@"', *flags, "--", *names)
        manifest = self.run_shell('sha256sum -- "$@"', *names, gnu=True).stdout
        (self.root / "sums").write_bytes(manifest)
        self.compare("sha256sum -c sums")
        self.compare("sha256sum --check --quiet sums")
        self.compare("sha256sum --check --status sums")
        tagged = self.run_shell('sha256sum --tag -- "$@"', *names, gnu=True).stdout
        (self.root / "tagged").write_bytes(tagged)
        self.compare("sha256sum -c tagged")
        (self.root / "data").write_bytes(b"changed")
        result = self.run_shell("sha256sum -c sums")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"data: FAILED\n", result.stdout)
        self.compare("sha256sum --status -c sums")
        (self.root / "invalid-sums").write_bytes(b"bad line\n")
        self.compare("sha256sum -c invalid-sums", diagnostic=True)

    def test_gzip_cross_reader_and_concatenation(self):
        data = bytes(range(256)) * 4096 + b"tail\x00"
        for level in ("-1", "-6", "-9"):
            result = self.run_shell('gzip -nc "$1"', level, data=data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(gzip.decompress(result.stdout), data)
        packed = gzip.compress(data, mtime=0) + gzip.compress(b"second", mtime=0)
        self.compare("gzip -dc", data=packed)
        self.compare("gzip -t", data=packed)
        for bad in (b"", packed[:20], packed[:-8]):
            result = self.run_shell("gzip -t", data=bad)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(result.stderr)
        damaged = bytearray(gzip.compress(data, mtime=0)); damaged[-8] ^= 1
        self.assertEqual(self.run_shell("gzip -t", data=damaged).returncode, 1)

    def test_gzip_file_lifecycle(self):
        source = self.root / "data"
        source.write_bytes(b"contents\x00\n"); source.chmod(0o640)
        os.utime(source, ns=(1234567890000000000, 1234567890000000000))
        result = self.run_shell("gzip -k data")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(gzip.decompress((self.root / "data.gz").read_bytes()), source.read_bytes())
        self.assertEqual((self.root / "data.gz").stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.run_shell("gzip -k data").returncode, 2)
        source.unlink()
        result = self.run_shell("gzip -d data.gz")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_bytes(), b"contents\x00\n")
        self.assertFalse((self.root / "data.gz").exists())
        self.assertEqual(source.stat().st_mtime_ns, 1234567890000000000)
        (self.root / "bad.gz").write_bytes(b"invalid")
        self.assertEqual(self.run_shell("gzip -d bad.gz").returncode, 1)
        self.assertTrue((self.root / "bad.gz").exists())
        self.assertFalse((self.root / "bad").exists())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["bad.gz", "data"])

    def test_tar_interoperability_and_cwd(self):
        source = self.root / "source"; source.mkdir()
        (source / "data").write_bytes(b"archive\x00bytes\n")
        (source / "link").symlink_to("data")
        long_name = "long-" + "x" * 120
        (source / long_name).write_bytes(b"long name")
        for flags, archive in (("-cf", "plain.tar"), ("-czf", "packed.tar.gz"), ("cf", "old.tar")):
            result = self.run_shell('before=$PWD; tar "$1" "$2" -C source data link "$3"; r=$?; [[ $PWD == "$before" ]] || exit 99; exit "$r"', flags, archive, long_name)
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(self.root / archive) as tf:
                self.assertEqual(tf.extractfile("data").read(), b"archive\x00bytes\n")
                self.assertEqual(tf.getmember("link").linkname, "data")
                self.assertEqual(tf.extractfile(long_name).read(), b"long name")
            self.compare('tar "$1" "$2"', "-tzf" if "gz" in archive else "-tf", archive)
        result = self.run_shell("tar -cf from-gnu.tar -C source .", gnu=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        restored = self.root / "restored"; restored.mkdir()
        result = self.run_shell("tar -xf from-gnu.tar -C restored")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((restored / "data").read_bytes(), b"archive\x00bytes\n")
        self.assertEqual(os.readlink(restored / "link"), "data")
        self.assertEqual((restored / long_name).read_bytes(), b"long name")
        self.compare("tar -xOf from-gnu.tar ./data")
        self.compare("tar -tf from-gnu.tar missing", diagnostic=True)
        failed = self.run_shell('old=$PWD; tar -cf bad.tar -C missing data; r=$?; [[ $PWD == "$old" ]] || exit 99; exit "$r"')
        self.assertEqual(failed.returncode, 2)
        self.assertTrue(failed.stderr)

    def test_output_failures_and_same_shell_recovery(self):
        if not Path("/dev/full").exists(): self.skipTest("/dev/full unavailable")
        for command in ("cat", "base64", "sha256sum", "gzip -c"):
            with self.subTest(command=command):
                result = self.run_shell(f"{command} >/dev/full; r=$?; printf 'alive:%s\\n' \"$r\"", data=b"data")
                self.assertEqual(result.stdout, b"alive:1\n", result.stderr)
                self.assertTrue(result.stderr)

    def test_awk_slash_inside_bracket_expression(self):
        data = b"a/b\nab\na]b\n1:2\n"
        for program in ("/[/]/", "$0 ~ /[/]/ {print \"slash\", $0}", "/[]/]/", "/[^]/]b/",
                        "/[[:digit:]/]/", "{ print ($0 ~ /a[/]b/) }", "{ print 6 / 2 / 3 }"):
            with self.subTest(program=program):
                self.compare('awk "$1"', program, data=data)
        self.compare("awk '/[/'", data=data, diagnostic=True)

    def test_date_relative_items(self):
        for value in ("2024-01-31 +1 month", "2024-03-10 12:00:00 -2 days", "2024-02-29 1 year ago",
                      "2024-01-01 next week", "2024-01-01 3 hours ago", "2024-01-01 +90 minutes",
                      "2024-01-01 tomorrow", "2024-01-01 yesterday", "2024-01-01 12:00 +1 day",
                      "2024-03-10 12:00 +0130", "2024-01-03 12:00 2 weeks ago",
                      "2024-01-03 1 fortnight", "2024-01-03 monday", "2024-01-03 12:00 monday"):
            with self.subTest(value=value):
                self.compare('date -u -d "$1" "+%F %T"', value)
        # Relative to now: compare at day granularity, or at the weekday's midnight.
        for value in ("yesterday", "tomorrow", "2 days ago", "+1 week", "-3 months", "today",
                      "now", "next monday", "monday", "last friday", "this sunday", "Tuesday",
                      "1 year", "next month"):
            with self.subTest(value=value):
                self.compare('date -d "$1" "+%F %a"', value)
        for value in ("bogus words", "@0 +1 day", "3 parsecs ago", "next"):
            with self.subTest(value=value):
                self.compare('date -d "$1"', value, diagnostic=True)

    def test_mv_verbose(self):
        def fixture():
            for name in os.listdir(self.root):
                path = self.root / name
                if path.is_dir() and not path.is_symlink():
                    subprocess.run(["rm", "-rf", "--", str(path)], check=True)
                else:
                    path.unlink()
            (self.root / "f").write_bytes(b"1\n"); (self.root / "g").write_bytes(b"2\n")
            (self.root / "it's").write_bytes(b"q\n"); (self.root / "D").mkdir()
            (self.root / "tree/sub").mkdir(parents=True); (self.root / "tree/sub/x").write_bytes(b"x")
        for script in ("mv -v f f2", "mv -v f g D", "mv -v tree D", "mv -v \"it's\" q",
                       "mv --verbose g h", "mv -vn f g", "mv -v missing f; echo $?"):
            with self.subTest(script=script):
                fixture(); expected = self.run_shell(script, gnu=True)
                fixture(); actual = self.run_shell(script)
                self.assertEqual((actual.returncode, actual.stdout), (expected.returncode, expected.stdout))
        if Path("/dev/shm").is_dir() and os.stat("/dev/shm").st_dev != os.stat(self.root).st_dev:
            for runner in (True, False):
                fixture()
                result = self.run_shell(f'mv -v tree "$1" | sed "s|$1|DEST|"',
                                        f"/dev/shm/bash-os-mv-{os.getpid()}-{int(runner)}", gnu=runner)
                if runner: expected = result.stdout
                else: self.assertEqual(result.stdout, expected, result.stderr)
                subprocess.run(["rm", "-rf", f"/dev/shm/bash-os-mv-{os.getpid()}-{int(runner)}"], check=True)

    def test_rm_verbose(self):
        def fixture():
            for name in os.listdir(self.root):
                subprocess.run(["rm", "-rf", "--", str(self.root / name)], check=True)
            (self.root / "f").write_bytes(b"1\n"); (self.root / "it's").write_bytes(b"2\n")
            (self.root / "d/e").mkdir(parents=True); (self.root / "d/e/h").write_bytes(b"h")
        for script in ("rm -v f", "rm -v \"it's\"", "rm -rv d", "rm -vr d f", "rm -fv missing",
                       "rm -v missing; echo $?", "rm -v d; echo $?", "printf 'y\\ny\\n' | rm -iv f \"it's\""):
            with self.subTest(script=script):
                fixture(); expected = self.run_shell(script, gnu=True)
                fixture(); actual = self.run_shell(script)
                lines = lambda out: sorted(out.splitlines()) if "-r" in script else out.splitlines()
                self.assertEqual((actual.returncode, lines(actual.stdout)),
                                 (expected.returncode, lines(expected.stdout)), actual.stderr)

    def test_cmp_byte_limit(self):
        (self.root / "f").write_bytes(b"b 2\na 1\nc 3\n"); (self.root / "g").write_bytes(b"x\n")
        (self.root / "p").write_bytes(b"abc"); (self.root / "q").write_bytes(b"abd")
        (self.root / "r").write_bytes(b"ab"); (self.root / "s").write_bytes(b"xbz")
        for args in (("-n", "1", "f", "g"), ("-n", "0", "f", "g"), ("-n2", "f", "f"),
                     ("-n", "2", "p", "q"), ("-n", "3", "p", "q"), ("-n", "2", "p", "r"),
                     ("-n", "3", "p", "r"), ("-l", "-n", "3", "p", "s"), ("--bytes=1", "-l", "p", "s"),
                     ("-s", "-n", "3", "p", "q"), ("-n", "2", "p", "q", "1", "1")):
            with self.subTest(args=args):
                self.compare('cmp "$@"', *args, diagnostic=True)
        self.compare("cmp -n 2 - q", data=b"abz", diagnostic=True)
        self.compare('cmp -n "$1" p q', "bad", diagnostic=True)

    def test_split_number_of_chunks(self):
        def listing():
            return self.run_shell('for f in y*; do printf "%s:%q|" "$f" "$(cat "$f"; echo .)"; done', gnu=True).stdout
        inputs = {"t": b"abcdefghij", "l": b"a\nbbbbbbbbbbbb\nc\nd\n", "m": b"a\nb\nc\nd\ne\n",
                  "e": b"", "s": b"ab", "n": b"one\ntwo\nthree"}
        for name, data in inputs.items():
            for chunks in ("1", "2", "3", "4", "5", "l/2", "l/3", "l/4", "l/7", "r/2", "r/3", "r/7"):
                with self.subTest(name=name, chunks=chunks):
                    found = []
                    for gnu in (True, False):
                        for old in self.root.glob("y*"): old.unlink()
                        (self.root / name).write_bytes(data)
                        result = self.run_shell('split -n "$1" "$2" y', chunks, name, gnu=gnu)
                        found.append((result.returncode, listing()))
                    self.assertEqual(found[1], found[0])
                for k in (1, 2, 3):
                    for kind in ("", "l/", "r/"):
                        self.compare('split -n "$1" "$2"', f"{kind}{k}/3", name)
        self.compare("split -n 2 - p; cat paa; echo; cat pab", data=b"abcdefghij")
        for chunks in ("0", "3/2", "x", "l/0/2", "r/", ""):
            self.compare('split -n "$1" t y', chunks, diagnostic=True)

    def test_ps_user_selection(self):
        uid = str(os.getuid())
        import pwd
        name = pwd.getpwuid(os.getuid()).pw_name
        for flag in ("-u", "-U"):
            for who in (uid, name, f"{name},{uid}"):
                with self.subTest(flag=flag, who=who):
                    result = self.run_shell(f'ps {flag} "$1" -o pid,uid; echo "self=$$"', who)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    lines = result.stdout.decode().splitlines()
                    self.assertEqual(lines[0].split(), ["PID", "UID"])
                    rows = [line.split() for line in lines[1:-1]]
                    self.assertTrue(rows)
                    self.assertTrue(all(row[1] == uid for row in rows), rows)
                    self.assertIn(lines[-1].split("=")[1], [row[0] for row in rows])
        result = self.run_shell("ps -u 4000000 -o pid")
        self.assertEqual(result.stdout.decode().split(), ["PID"])
        result = self.run_shell(f"ps --user={uid} -o uid")
        self.assertEqual(set(result.stdout.decode().split()[1:]), {uid})
        result = self.run_shell("ps -u no-such-user-here")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)

    def test_diff_side_by_side(self):
        files = {"f": b"b 2\na 1\nc 3\n", "g": b"x\n",
                 "L": b"one\ttab\nlong line that goes on and on and on and on and on and on and on and on and on\nsame\nno newline",
                 "R": b"one\ttab\nshort\nsame\nadded\nno newline\n",
                 "C": b"ctl\x01char\rback\bspace\tend\n\xff\xfehigh\n", "E": b""}
        for name, data in files.items(): (self.root / name).write_bytes(data)
        for args in (("-y", "f", "g"), ("-y", "L", "R"), ("-y", "R", "L"), ("-y", "-W", "40", "L", "R"),
                     ("-yW60", "f", "g"), ("-y", "f", "f"), ("--side-by-side", "--width=50", "f", "g"),
                     ("-y", "C", "f"), ("-y", "E", "f"), ("-y", "f", "E"), ("-yi", "f", "f"),
                     ("-y", "-W", "7", "L", "R"), ("-y", "-W", "1", "f", "g")):
            with self.subTest(args=args):
                self.compare('diff "$@"', *args)

    def test_diff_directories(self):
        layout = {"A/c": b"1\n2\n3\n", "B/c": b"1\nX\n3\n", "A/s/k": b"same\n", "B/s/k": b"same\n",
                  "A/s/m": b"a\n", "B/s/m": b"b\n", "B/onlyb": b"o\n", "A/bin": b"\x00bin",
                  "B/bin": b"\x00bon", "A/t": b"t\n", "A/only/z": b"z\n", "P/a": b"p\n"}
        for path, data in layout.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_bytes(data)
        (self.root / "B/t").mkdir(); (self.root / "Q").mkdir(); (self.root / "Q/a").write_bytes(b"p\n")
        for script in ("diff -r A B", "diff -rq A B", "diff A B", "diff -r A A", "diff -r P Q",
                       "diff -ry P Q", "diff -r A/ B/", "diff --recursive A B", "diff A/c B",
                       "diff A B/c", "diff -r A/s B/s"):
            with self.subTest(script=script):
                self.compare(script)
        # GNU's unified headers add timestamps; compare everything else.
        strip = lambda out: b"\n".join(line.split(b"\t")[0] for line in out.splitlines())
        expected = self.run_shell("diff -ru A B", gnu=True)
        actual = self.run_shell("diff -ru A B")
        self.assertEqual((actual.returncode, strip(actual.stdout)), (expected.returncode, strip(expected.stdout)))
        self.compare("diff -r A missing", diagnostic=True)

if __name__ == "__main__":
    unittest.main()
