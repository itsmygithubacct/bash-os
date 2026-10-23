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


if __name__ == "__main__":
    unittest.main()
