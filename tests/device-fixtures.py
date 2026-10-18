#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Device reporting and argument validation using regular files only."""
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {**os.environ, "PATH": "", "LC_ALL": "C", "TZ": "UTC"}
ENV.pop("BASH_ENV", None)


class DeviceFixtures(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-device-fixture-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "sys").mkdir()
        (self.root / "dev").mkdir()
        (self.root / "mounts").touch()
        self.kmsg = self.root / "kmsg"
        self.kmsg.write_text("0,1,1000000,-;kernel\n8,2,2000000,-;user\n")
        self.env = {
            **ENV, "BASHDMESG_DEV_KMSG_FILE": str(self.kmsg),
            "BASHLSBLK_SYS_BLOCK_DIR": str(self.root / "sys"),
            "BASHLSBLK_DEV_ROOT": str(self.root / "dev"),
            "BASHLSBLK_PROC_MOUNTS": str(self.root / "mounts"),
        }

    def shell(self, script, *args):
        result = subprocess.run([BINARY, "--noprofile", "--norc", "-c", script,
                                 "device-test", *map(str, args)],
                                env=self.env, cwd=self.root, capture_output=True, timeout=10)
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        return result

    def test_dmesg_rejects_unrepresentable_time_filters(self):
        for flag in ("--since", "--until"):
            for value in ("", " ", "nan", "inf", "1e30", "18446744073709.554", "-1"):
                for joined in (False, True):
                    with self.subTest(flag=flag, value=value, joined=joined):
                        args = [flag + "=" + value] if joined else [flag, value]
                        result = self.shell('dmesg "$@"', *args)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, b"")

    def test_dmesg_filters_finite_times_at_record_boundaries(self):
        result = self.shell('dmesg -t --since .999999 --until 1; '
                            'dmesg -t --since 1.1 --until 2; '
                            'dmesg -t --since 3 --until 1e12')
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, b"kernel\nuser\n", b""))

    def test_dmesg_facility_filter_does_not_wrap_shift_counts(self):
        self.kmsg.write_text("256,1,1000000,-;facility32\n"
                             "2047,2,1000000,-;facility255\n"
                             "0,3,1000000,-;kernel\n")
        result = self.shell('dmesg -t -f kern; dmesg -t')
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, b"kernel\nfacility32\nfacility255\nkernel\n", b""))

    def test_dmesg_skips_malformed_numeric_fields_and_accepts_extensions(self):
        self.kmsg.write_text(
            "4294967296,1,1000000,-;wrapped priority\n"
            "2048,1,1000000,-;priority outside ABI\n"
            "-1,1,1000000,-;negative priority\n"
            "0,-1,1000000,-;negative sequence\n"
            "0,18446744073709551616,1000000,-;overflowed sequence\n"
            "0,1,-1,-;negative time\n"
            "0,1,18446744073709551616,-;overflowed time\n"
            "0,1,1000000junk;invalid time\n"
            "0,1,1000000,unknown,more=fields;valid extension\n"
            "0,2,2000000;short fixture\n")
        result = self.shell('dmesg -t')
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, b"valid extension\nshort fixture\n", b""))

    def test_dmesg_rejects_levels_outside_three_bit_range(self):
        # Only the read filter is exercised; -n would affect the host console.
        for level in ("8", "9", "-1", "10", "", ","):
            with self.subTest(level=level):
                result = self.shell('dmesg -l "$1"', level)
                self.assertNotEqual(result.returncode, 0)
        for facility in ("", ",", "256"):
            with self.subTest(facility=facility):
                result = self.shell('dmesg -f "$1"', facility)
                self.assertNotEqual(result.returncode, 0)

    def test_dmesg_unrepresentable_wall_time_falls_back_to_monotonic(self):
        for epoch in ("9223372036854775807", "9223372036854775790"):
            with self.subTest(epoch=epoch):
                self.env["BASHDMESG_BOOT_EPOCH"] = epoch
                result = self.shell('dmesg -T -k')
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, b"[    1.000000] kernel\n", b""))

    def check_ext(self, image, expected):
        before = hashlib.sha256(image.read_bytes()).digest()
        (self.root / "sys" / image.name).mkdir(exist_ok=True)
        result = self.shell('blkid -s TYPE -o value "$1"; '
                            'lsblk -n -r -o FSTYPE "$2"', image, image.name)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, (expected + "\n" + expected + "\n").encode(), b""))
        self.assertEqual(hashlib.sha256(image.read_bytes()).digest(), before)

    def test_ext_feature_classification_without_block_devices(self):
        cases = [
            (0, 2, 3, "ext2"), (4, 2, 3, "ext3"), (4, 6, 3, "ext3"),
            (4, 0x42, 3, "ext4"), (0, 0x42, 3, "ext4"),
            (0, 0x82, 3, "ext4"), (0, 2, 0xb, "ext4"), (0, 8, 0, "jbd"),
        ]
        for index, (compat, incompat, ro_compat, expected) in enumerate(cases):
            with self.subTest(features=(compat, incompat, ro_compat)):
                data = bytearray(4096)
                struct.pack_into("<H", data, 1024 + 0x38, 0xef53)
                struct.pack_into("<III", data, 1024 + 0x5c, compat, incompat, ro_compat)
                image = self.root / "dev" / f"disk{index}"
                image.write_bytes(data)
                self.check_ext(image, expected)
                result = self.shell('blkid -s SEC_TYPE -o value "$1"', image)
                secondary = b"ext2\n" if expected in ("ext3", "ext4") and not (incompat & ~0x12) else b""
                self.assertEqual(result.stdout, secondary, result.stderr)

    def test_real_ext_images_match_installed_blkid(self):
        mke2fs = shutil.which("mke2fs", path="/usr/sbin:/sbin:/usr/bin:/bin")
        blkid = shutil.which("blkid", path="/usr/sbin:/sbin:/usr/bin:/bin")
        if not mke2fs or not blkid:
            self.skipTest("mke2fs and util-linux blkid are required for image parity")
        cases = [("ext2", []), ("ext3", []), ("ext4", []),
                 ("ext4", ["-O", "^has_journal"]),
                 ("ext4", ["-O", "^has_journal,^extent,^64bit"])]
        for index, (kind, features) in enumerate(cases):
            with self.subTest(kind=kind, features=features):
                image = self.root / "dev" / f"real{index}"
                with image.open("wb") as f:
                    f.truncate(32 * 1024 * 1024)
                subprocess.run([mke2fs, "-q", "-F", "-t", kind, *features, str(image)],
                               capture_output=True, timeout=30, check=True)
                reference = subprocess.run([blkid, "-p", "-s", "TYPE", "-o", "value", str(image)],
                                           capture_output=True, timeout=10, check=True)
                self.assertEqual(reference.stdout.strip().decode(), kind)
                self.check_ext(image, kind)

    def test_loop_byte_counts_are_rejected_before_read_only_listing(self):
        # --list has no attach/detach ioctl and observes existing sysfs only.
        for flag in ("-o", "--offset", "--sizelimit"):
            for value in ("", " ", "garbage", "-1", "18446744073709551616", "8junk"):
                with self.subTest(flag=flag, value=value):
                    result = self.shell('losetup "$1" "$2" --list', flag, value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"invalid byte count", result.stderr)
                    self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
