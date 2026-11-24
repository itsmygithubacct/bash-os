#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ramdisk: setup, list, create, resize, remove and zram, for real.

The test re-runs itself inside `unshare -rmi` (a user, mount and IPC
namespace, so mounting tmpfs and mqueue needs no root), and every mount is
made below a private scratch root in TMPDIR: never the host's /dev/shm,
/run or /tmp. The mount namespace, and every mount in it, ends with the
test. Mount state is read back from /proc/self/mountinfo, statvfs(3) and
stat(2), never from ramdisk's own output alone. zram runs against a fake
sysfs tree under the scratch root (--root), since no kernel module is
loaded here.

usage: ramdisk-smoke.py [BASH_OS_BINARY]   (needs unprivileged user namespaces)
"""
import ctypes
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
INNER = "RAMDISK_SMOKE_INNER"
MiB = 1024 * 1024
TRY = "Try 'ramdisk --help' for more information.\n"
LIBC = ctypes.CDLL(None, use_errno=True)


def outer():
    """Re-run this file in a private user + mount + IPC namespace."""
    unshare = shutil.which("unshare", path="/usr/bin:/bin")
    if not unshare or subprocess.run([unshare, "-rmi", "true"], capture_output=True).returncode:
        print("SKIP ramdisk smoke: unprivileged user namespaces are not available")
        return 0
    env = {**os.environ, INNER: "1"}
    return subprocess.run([unshare, "-rmi", "--propagation", "private", sys.executable,
                           os.path.abspath(__file__), BINARY, *sys.argv[1:]], env=env).returncode


def unescape(field):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mounts():
    """(mount point, fstype, per-mount options, super options) rows, in order."""
    rows = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split(" ")
        dash = fields.index("-", 6)
        rows.append((unescape(fields[4]), fields[dash + 1], fields[5].split(","),
                     fields[dash + 3].split(",")))
    return rows


def mounts_at(path):
    return [row for row in mounts() if row[0] == os.path.realpath(path)]


def top(path):
    rows = mounts_at(path)
    return rows[-1] if rows else None


def umount(path, flags=2):
    if LIBC.umount2(os.fsencode(path), flags):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), path)


class RamdiskTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="bash-os-ramdisk-")).resolve()
        self.addCleanup(self.cleanup)
        os.umask(0o022)

    def cleanup(self):
        prefix = str(self.root)
        for point, *_ in reversed(mounts()):
            if point == prefix or point.startswith(prefix + "/"):
                try:
                    umount(point)
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)

    def sh(self, script, ok=None):
        result = subprocess.run([BINARY, "--noprofile", "--norc", "-c", script], cwd=self.root,
                                capture_output=True, text=True, timeout=60,
                                env={"PATH": "", "LC_ALL": "C", "HOME": "/", "BASH_ENV": "", "ENV": ""})
        if ok is not None:
            self.assertEqual(result.returncode == 0, ok, (script, result.stdout, result.stderr))
        return result

    def ramdisk(self, args, ok=None):
        return self.sh("ramdisk " + args, ok)

    def errors(self, result):
        """stderr with the shell's "NAME: line N: " prefix taken off each line."""
        return re.sub(r"(?m)^.*?: line \d+: ", "", result.stderr)

    def size(self, path):
        s = os.statvfs(path)
        return s.f_blocks * s.f_frsize


class Basics(RamdiskTest):
    def test_builtin_help_version(self):
        self.assertEqual(self.sh("type -t ramdisk").stdout, "builtin\n")
        version = self.ramdisk("--version", ok=True)
        self.assertEqual(version.stdout, "ramdisk (bash-os) 0.1.5\n")
        self.assertEqual(self.ramdisk("setup --version", ok=True).stdout, version.stdout)
        text = self.ramdisk("--help", ok=True).stdout
        for line in ("ramdisk [list] [-b|-h] [PATH...]",
                     "ramdisk setup [-n|--dry-run] [--tmp] [--no-run] [--root DIR]",
                     "ramdisk create [-s SIZE] [-m MODE] [-u UID] [-g GID] [-i INODES]",
                     "ramdisk resize PATH SIZE", "ramdisk remove [-l|--lazy] [--rmdir] PATH...",
                     "ramdisk zram [--root DIR] add SIZE [-a ALGO] | remove N..."):
            self.assertIn("    " + line + "\n", text)
        for verb in ("list", "setup", "create", "resize", "remove", "zram"):
            self.assertEqual(self.ramdisk(verb + " --help", ok=True).stdout, text)
        # help(1) shows the same text, indented, under the short synopsis.
        helped = self.sh("help ramdisk", ok=True).stdout
        self.assertTrue(helped.startswith(
            "ramdisk: ramdisk [list|setup|create|resize|remove|zram] [OPTION]... [ARG]...\n"))
        self.assertEqual([l.strip() for l in helped.splitlines()[1:]],
                         [l.strip() for l in text.splitlines()])

    def test_option_errors(self):
        cases = {
            "--x": "ramdisk: unrecognized option '--x'\n",
            "-Z": "ramdisk: invalid option -- 'Z'\n",
            "list --bogus": "ramdisk: unrecognized option '--bogus'\n",
            "setup -q": "ramdisk: invalid option -- 'q'\n",
            "setup --root": "ramdisk: option '--root' requires an argument\n",
            "setup --tmp=1": "ramdisk: option '--tmp' doesn't allow an argument\n",
            "create -s": "ramdisk: option requires an argument -- 's'\n",
            "create --nope d": "ramdisk: unrecognized option '--nope'\n",
            "resize -x d 1m": "ramdisk: invalid option -- 'x'\n",
            "remove --lazyy d": "ramdisk: unrecognized option '--lazyy'\n",
            "zram --algo": "ramdisk: option '--algorithm' requires an argument\n",
            "frob": "ramdisk: unknown command 'frob'\n",
            "setup extra": "ramdisk: setup: extra operand 'extra'\n",
            "create": "ramdisk: create: missing PATH operand\n",
            "create a b": "ramdisk: create: extra operand 'b'\n",
            "resize d": "ramdisk: resize: missing SIZE operand\n",
            "resize": "ramdisk: resize: missing PATH and SIZE operands\n",
            "resize a 1m b": "ramdisk: resize: extra operand 'b'\n",
            "remove": "ramdisk: remove: missing PATH operand\n",
            "zram": "ramdisk: zram: missing command (add or remove)\n",
            "zram frob": "ramdisk: zram: unknown command 'frob'\n",
        }
        before = mounts()
        for args, message in cases.items():
            with self.subTest(args=args):
                result = self.ramdisk(args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(self.errors(result), message + TRY)
        self.assertEqual(mounts(), before)
        self.assertEqual(sorted(os.listdir(self.root)), [])


class Setup(RamdiskTest):
    ITEMS = [("run", "tmpfs", 0o755, {"nosuid", "nodev"}, ", mode 755"),
             ("run/lock", "tmpfs", 0o1777, {"nosuid", "nodev", "noexec"}, ", mode 1777, size 5m"),
             ("dev/shm", "tmpfs", 0o1777, {"nosuid", "nodev"}, ", mode 1777"),
             ("dev/mqueue", "mqueue", 0o1777, {"nosuid", "nodev", "noexec"}, ""),
             ("tmp", "tmpfs", 0o1777, {"nosuid", "nodev"}, ", mode 1777")]

    def setUp(self):
        super().setUp()
        self.fake = self.root / "root"
        self.fake.mkdir()
        if "mqueue" not in Path("/proc/filesystems").read_text().split():
            self.ITEMS = [item for item in self.ITEMS if item[1] != "mqueue"]

    def items(self, tmp=True, run=True):
        return [i for i in self.ITEMS if (tmp or i[0] != "tmp") and (run or not i[0].startswith("run"))]

    def test_setup_fake_root_and_idempotence(self):
        host = {path: mounts_at(path) for path in ("/dev/shm", "/run", "/run/lock", "/dev/mqueue", "/tmp")}
        result = self.ramdisk("setup --root root --tmp", ok=True)
        expect = "".join(f"created root/{p}\nmounted root/{p} ({t}{shown})\n"
                         for p, t, _, _, shown in self.items())
        self.assertEqual(result.stdout, expect)
        self.assertEqual(result.stderr, "")
        for path, fstype, mode, flags, _ in self.items():
            with self.subTest(path=path):
                row = top(self.fake / path)
                self.assertIsNotNone(row, path)
                self.assertEqual(row[1], fstype)
                self.assertLessEqual(flags, set(row[2]))
                self.assertEqual(os.stat(self.fake / path).st_mode & 0o7777, mode)
        self.assertEqual(self.size(self.fake / "run/lock"), 5 * MiB)
        # Nothing outside the scratch root changed: the real places keep the
        # mounts they had (this namespace started as a copy of the host's).
        self.assertEqual({path: mounts_at(path) for path in host}, host)

        snapshot = Path("/proc/self/mountinfo").read_text()
        again = self.ramdisk("setup --root root --tmp", ok=True)
        self.assertEqual(again.stdout, "".join(f"root/{p} already mounted\n" for p, *_ in self.items()))
        self.assertEqual(Path("/proc/self/mountinfo").read_text(), snapshot)
        self.assertEqual(self.ramdisk("setup --root root/ --tmp -n", ok=True).stdout,
                         "".join(f"root/{p} already mounted\n" for p, *_ in self.items()))

    def test_no_run_and_no_tmp(self):
        result = self.ramdisk("setup --no-run --root root", ok=True)
        self.assertEqual(result.stdout, "".join(f"created root/{p}\nmounted root/{p} ({t}{s})\n"
                                                for p, t, _, _, s in self.items(tmp=False, run=False)))
        self.assertFalse((self.fake / "run").exists())
        self.assertFalse((self.fake / "tmp").exists())

    def test_dry_run_changes_nothing(self):
        before = Path("/proc/self/mountinfo").read_text()
        result = self.ramdisk("setup -n --tmp --root root", ok=True)
        self.assertEqual(result.stdout, "".join(f"would create root/{p}\nwould mount root/{p} ({t}{s})\n"
                                                for p, t, _, _, s in self.items()))
        self.assertEqual(Path("/proc/self/mountinfo").read_text(), before)
        self.assertEqual(os.listdir(self.fake), [])
        # With /run already there, its lock directory still "would" be made
        # and mounted; nothing else is reported for /run.
        (self.fake / "run").mkdir()
        self.ramdisk("create -m 755 root/run", ok=True)
        before = Path("/proc/self/mountinfo").read_text()
        result = self.ramdisk("setup --dry-run --root root", ok=True)
        self.assertTrue(result.stdout.startswith(
            "root/run already mounted\nwould create root/run/lock\n"
            "would mount root/run/lock (tmpfs, mode 1777, size 5m)\n"), result.stdout)
        self.assertEqual(Path("/proc/self/mountinfo").read_text(), before)
        self.assertEqual(os.listdir(self.fake / "run"), [])

    def test_fresh_run_hides_old_lock(self):
        # A /run/lock directory on the root filesystem is not a mount; once
        # /run is mounted over it, setup makes and mounts a new one.
        (self.fake / "run/lock").mkdir(parents=True)
        result = self.ramdisk("setup --root root", ok=True)
        self.assertTrue(result.stdout.startswith(
            "mounted root/run (tmpfs, mode 755)\ncreated root/run/lock\nmounted root/run/lock"),
            result.stdout)
        self.assertEqual(top(self.fake / "run/lock")[1], "tmpfs")

    def test_existing_mount_is_kept(self):
        self.ramdisk("create -s 1m root/dev/shm", ok=True)
        result = self.ramdisk("setup --no-run --root root", ok=True)
        self.assertIn("root/dev/shm already mounted\n", result.stdout)
        self.assertEqual(len(mounts_at(self.fake / "dev/shm")), 1)
        self.assertEqual(self.size(self.fake / "dev/shm"), MiB)

    def test_failures_are_reported_per_item(self):
        (self.fake / "dev").mkdir()
        (self.fake / "dev/shm").write_text("not a directory\n")
        result = self.ramdisk("setup --no-run --root root")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result),
                         "ramdisk: setup: cannot create root/dev/shm: Not a directory\n")
        self.assertIsNone(top(self.fake / "dev/shm"))
        if any(i[1] == "mqueue" for i in self.ITEMS):
            self.assertIn("mounted root/dev/mqueue (mqueue)\n", result.stdout)
        missing = self.ramdisk("setup --root nosuch")
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(self.errors(missing), "ramdisk: setup: nosuch: No such file or directory\n")

    def test_root_escape_is_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.fake / "dev").symlink_to(outside)
        result = self.ramdisk("setup --no-run --root root")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ramdisk: setup: root/dev/shm resolves outside root; not mounting it\n",
                      self.errors(result))
        self.assertEqual(os.listdir(outside), [])
        self.assertFalse([m for m in mounts() if m[0].startswith(str(outside))])


class ListCreate(RamdiskTest):
    def test_list_against_statfs(self):
        self.ramdisk("create -s 4m -m 750 disk", ok=True)
        (self.root / "disk/f").write_bytes(b"x" * MiB)
        result = self.ramdisk("list -b disk/f", ok=True)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0].split(), ["TYPE", "SIZE", "USED", "AVAIL", "USE%", "MODE", "MOUNTPOINT"])
        s = os.statvfs(self.root / "disk")
        row = lines[1].split()
        self.assertEqual(row, ["tmpfs", str(s.f_blocks * s.f_frsize),
                               str((s.f_blocks - s.f_bfree) * s.f_frsize), str(s.f_bavail * s.f_frsize),
                               "%d%%" % -(-(s.f_blocks - s.f_bfree) * 100 // (s.f_blocks - s.f_bfree + s.f_bavail)),
                               "750", str(self.root / "disk")])
        self.assertEqual(int(row[1]), 4 * MiB)
        self.assertGreaterEqual(int(row[2]), MiB)
        human = self.ramdisk("list disk", ok=True).stdout.splitlines()[1].split()
        self.assertEqual(human[:2], ["tmpfs", "4.0M"])
        self.assertIn(human[2], ("1.0M", "1.1M"))
        # Columns line up: every row is as wide as the header up to MOUNTPOINT.
        width = lines[0].index("MOUNTPOINT")
        self.assertTrue(all(len(line) > width and line[width - 1] == " " for line in lines))
        everything = self.ramdisk("list -b", ok=True).stdout
        self.assertIn(row, [line.split() for line in everything.splitlines()])
        # No command is list; leading options are list's.
        self.assertEqual(self.ramdisk("-b disk", ok=True).stdout, self.ramdisk("list -b disk", ok=True).stdout)
        self.assertIn(" " + str(self.root / "disk") + "\n", self.ramdisk("", ok=True).stdout)

    def test_list_refuses_non_ram(self):
        if self.ram_fstype(self.root):
            self.skipTest("the scratch directory is itself on a RAM filesystem")
        result = self.ramdisk("list . nosuch")
        self.assertEqual(result.returncode, 1)
        errors = self.errors(result)
        self.assertRegex(errors, r"^ramdisk: \.: not on a RAM-backed filesystem \(\S+\)\n"
                                 r"ramdisk: nosuch: No such file or directory\n$")
        self.assertEqual(result.stdout.split(), ["TYPE", "SIZE", "USED", "AVAIL", "USE%", "MODE", "MOUNTPOINT"])

    def ram_fstype(self, path):
        real = os.path.realpath(path)
        best = max((m for m in mounts() if real == m[0] or real.startswith(m[0].rstrip("/") + "/")),
                   key=lambda m: len(m[0]))
        return best[1] in ("tmpfs", "ramfs")

    def test_create_options(self):
        result = self.ramdisk("create -s 8m -m 700 -u 0 -g 0 -i 1k a/b", ok=True)
        self.assertEqual(result.stdout, "mounted a/b (tmpfs, size=8m,nr_inodes=1k,mode=700,uid=0,gid=0)\n")
        path = self.root / "a/b"
        s, st = os.statvfs(path), os.stat(path)
        self.assertEqual(s.f_blocks * s.f_frsize, 8 * MiB)
        self.assertEqual(s.f_files, 1024)
        self.assertEqual((st.st_mode & 0o7777, st.st_uid, st.st_gid), (0o700, 0, 0))
        row = top(path)
        self.assertEqual(row[1], "tmpfs")
        self.assertLessEqual({"nosuid", "nodev"}, set(row[2]))
        self.assertNotIn("noexec", row[2])

        self.ramdisk("create --size=2M --mode 1750 -o noexec,suid,dev,nr_inodes=2k c", ok=True)
        row = top(self.root / "c")
        self.assertIn("noexec", row[2])
        self.assertFalse({"nosuid", "nodev"} & set(row[2]))
        self.assertEqual(os.statvfs(self.root / "c").f_files, 2048)
        self.assertEqual(self.size(self.root / "c"), 2 * MiB)
        self.assertEqual(os.stat(self.root / "c").st_mode & 0o7777, 0o1750)

        self.ramdisk("create d", ok=True)       # kernel defaults: mode 1777
        self.assertEqual(os.stat(self.root / "d").st_mode & 0o7777, 0o1777)

        self.ramdisk("create -s 1% e", ok=True)
        pages = os.sysconf("SC_PHYS_PAGES") // 100
        self.assertAlmostEqual(self.size(self.root / "e") // os.sysconf("SC_PAGE_SIZE"), pages, delta=1)

    def test_create_refusals(self):
        self.ramdisk("create -s 1m m", ok=True)
        before = mounts()
        result = self.ramdisk("create m")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result),
                         "ramdisk: create: m is already a mount point (--force mounts over it)\n")
        self.assertEqual(mounts(), before)
        self.ramdisk("create --force -s 2m m", ok=True)
        self.assertEqual(len(mounts_at(self.root / "m")), 2)
        self.assertEqual(self.size(self.root / "m"), 2 * MiB)
        self.ramdisk("create -f -s 3m m", ok=True)
        self.assertEqual(len(mounts_at(self.root / "m")), 3)

        bad = {"-s 12x n": "invalid size '12x'", "-s 5%x n": "invalid size '5%x'",
               "-s -1 n": "invalid size '-1'", "-i 5% n": "invalid inode count '5%'",
               "-m 8 n": "invalid mode '8'", "-m 17777 n": "invalid mode '17777'",
               "-u x n": "invalid user ID 'x'", "-g -1 n": "invalid group ID '-1'"}
        before = mounts()
        for args, message in bad.items():
            with self.subTest(args=args):
                result = self.ramdisk("create " + args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.errors(result), "ramdisk: create: " + message + "\n")
        self.assertEqual(mounts(), before)
        self.assertFalse((self.root / "n").exists())
        # The kernel refuses an owner the namespace cannot map; the
        # directories created for the mount are removed again.
        result = self.ramdisk("create -u 4242 p/q/r")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result),
                         "ramdisk: create: cannot mount tmpfs on p/q/r: Invalid argument\n")
        self.assertFalse((self.root / "p").exists())
        (self.root / "s").mkdir()
        self.assertEqual(self.ramdisk("create -o nr_inodes=1x s/t").returncode, 1)
        self.assertEqual(os.listdir(self.root / "s"), [])


class ResizeRemove(RamdiskTest):
    def digest(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def test_resize(self):
        self.ramdisk("create -s 4m -m 700 -o noexec disk", ok=True)
        data = self.root / "disk/data"
        data.write_bytes(os.urandom(2 * MiB))
        digest = self.digest(data)
        flags = set(top(self.root / "disk")[2])

        result = self.ramdisk("resize disk 1m")
        self.assertEqual(result.returncode, 1)
        self.assertRegex(self.errors(result),
                         r"^ramdisk: resize: cannot shrink disk to 1m: 2\.\dM is in use: Invalid argument\n$")
        self.assertEqual(self.size(self.root / "disk"), 4 * MiB)

        self.assertEqual(self.ramdisk("resize disk 8m", ok=True).stdout, "resized disk to 8.0M\n")
        self.assertEqual(self.size(self.root / "disk"), 8 * MiB)
        self.assertEqual(self.ramdisk("resize disk/ 3M", ok=True).stdout, "resized disk/ to 3.0M\n")
        self.assertEqual(self.size(self.root / "disk"), 3 * MiB)
        self.ramdisk("resize disk 3072k", ok=True)
        self.assertEqual(self.size(self.root / "disk"), 3 * MiB)
        self.assertEqual(self.ramdisk("resize disk 0", ok=True).stdout, "resized disk to no limit\n")
        self.assertEqual(self.size(self.root / "disk"), 0)
        # Contents, root mode and the mount's own flags survive every remount.
        self.assertEqual(self.digest(data), digest)
        self.assertEqual(os.stat(self.root / "disk").st_mode & 0o7777, 0o700)
        self.assertEqual(set(top(self.root / "disk")[2]), flags)
        self.assertLessEqual({"nosuid", "nodev", "noexec"}, flags)
        # The kernel will not give a tmpfs without a limit a new one.
        result = self.ramdisk("resize disk 4m")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result), "ramdisk: resize: cannot limit disk to 4m: it has no size "
                                              "limit, and the kernel cannot add one: Invalid argument\n")
        self.assertEqual(self.size(self.root / "disk"), 0)

    def test_resize_refusals(self):
        (self.root / "plain").mkdir()
        (self.root / "r").mkdir()
        self.sh("bashmount -t ramfs ramfs r", ok=True)
        cases = {"plain 1m": "ramdisk: resize: plain is not a mount point\n",
                 "r 1m": "ramdisk: resize: r is a ramfs mount, not tmpfs\n",
                 "nosuch 1m": "ramdisk: resize: nosuch: No such file or directory\n",
                 "r 1q": "ramdisk: resize: invalid size '1q'\n"}
        for args, message in cases.items():
            with self.subTest(args=args):
                result = self.ramdisk("resize " + args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.errors(result), message)
        self.assertEqual(top(self.root / "r")[1], "ramfs")

    def test_remove(self):
        self.ramdisk("create a", ok=True)
        self.assertEqual(self.ramdisk("remove a", ok=True).stdout, "unmounted a\n")
        self.assertIsNone(top(self.root / "a"))
        self.assertTrue((self.root / "a").is_dir())

        self.ramdisk("create b", ok=True)
        self.assertEqual(self.ramdisk("remove --rmdir b", ok=True).stdout, "unmounted b\nremoved b\n")
        self.assertFalse((self.root / "b").exists())

        result = self.ramdisk("remove a nosuch")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result), "ramdisk: remove: a is not a mount point\n"
                                              "ramdisk: remove: nosuch: No such file or directory\n")

        # Busy: a plain unmount fails, a lazy one detaches it at once.
        self.ramdisk("create c", ok=True)
        with open(self.root / "c/held", "w"):
            result = self.ramdisk("remove c")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(self.errors(result),
                             "ramdisk: remove: cannot unmount c: Device or resource busy\n")
            self.assertIsNotNone(top(self.root / "c"))
            self.assertEqual(self.ramdisk("remove -l c", ok=True).stdout, "unmounted c\n")
            self.assertIsNone(top(self.root / "c"))

        # A stacked mount: --rmdir unmounts the top one and keeps PATH.
        self.ramdisk("create d", ok=True)
        self.ramdisk("create --force d", ok=True)
        result = self.ramdisk("remove --rmdir d")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "unmounted d\n")
        self.assertEqual(self.errors(result), "ramdisk: remove: d is still a mount point; not removing it\n")
        self.assertEqual(len(mounts_at(self.root / "d")), 1)

        # Other RAM types are removable; a disk-backed bind mount is not.
        (self.root / "r").mkdir()
        self.sh("bashmount -t ramfs ramfs r", ok=True)
        self.assertEqual(self.ramdisk("remove r", ok=True).stdout, "unmounted r\n")
        (self.root / "src").mkdir()
        (self.root / "dst").mkdir()
        self.sh("bashmount -B src dst", ok=True)
        fstype = top(self.root / "dst")[1]
        if fstype in ("tmpfs", "ramfs"):
            self.skipTest("the scratch directory is itself on a RAM filesystem")
        result = self.ramdisk("remove dst")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result), f"ramdisk: remove: dst is not a RAM-backed mount ({fstype})\n")
        self.assertIsNotNone(top(self.root / "dst"))


class Zram(RamdiskTest):
    def fake_sysfs(self, number):
        ctl = self.root / "sys/class/zram-control"
        ctl.mkdir(parents=True)
        (ctl / "hot_add").write_text(f"{number}\n")
        (ctl / "hot_remove").write_text("")
        dev = self.root / f"sys/block/zram{number}"
        dev.mkdir(parents=True)
        for name in ("comp_algorithm", "disksize", "reset"):
            (dev / name).write_text("")
        return ctl, dev

    def test_unavailable(self):
        result = self.ramdisk("zram --root . add 64m")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result),
                         f"ramdisk: zram not available in this kernel (no ./sys/class/zram-control)\n")
        self.assertEqual(result.stdout, "")

    def test_add_remove_writes_the_sysfs_sequence(self):
        ctl, dev = self.fake_sysfs(3)
        result = self.ramdisk("zram --root . add 64m -a zstd", ok=True)
        self.assertEqual(result.stdout, "/dev/zram3\n")
        self.assertEqual((dev / "comp_algorithm").read_text(), "zstd")
        self.assertEqual((dev / "disksize").read_text(), "64m")
        self.assertEqual((ctl / "hot_remove").read_text(), "")

        result = self.ramdisk("zram remove --root . /dev/zram3", ok=True)
        self.assertEqual(result.stdout, "removed /dev/zram3\n")
        self.assertEqual((dev / "reset").read_text(), "1")
        self.assertEqual((ctl / "hot_remove").read_text(), "3")

        result = self.ramdisk("zram --root . remove 9 zramx")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result), "ramdisk: zram remove: no such device: zram9\n"
                                              "ramdisk: zram remove: invalid device 'zramx'\n")

    def test_add_failure_rolls_back(self):
        ctl, dev = self.fake_sysfs(0)
        (dev / "disksize").unlink()
        (dev / "disksize").mkdir()
        result = self.ramdisk("zram --root . add 1g")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.errors(result),
                         "ramdisk: zram add: cannot set disk size 1g on zram0: Is a directory\n")
        self.assertEqual((ctl / "hot_remove").read_text(), "0")
        for args, message in {"add 5%": "zram add: invalid size '5%'", "add 0": "zram add: invalid size '0'",
                              "add 1m -a a/b": "zram add: invalid algorithm 'a/b'"}.items():
            result = self.ramdisk("zram --root . " + args)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(self.errors(result), "ramdisk: " + message + "\n")
        result = self.ramdisk("zram --root . remove -a lz4 0")
        self.assertEqual(self.errors(result), "ramdisk: zram remove: -a only applies to zram add\n" + TRY)


if __name__ == "__main__":
    if os.environ.get(INNER) != "1":
        sys.exit(outer())
    if not os.access(BINARY, os.X_OK):
        sys.exit(f"no bash-os binary at {BINARY}")
    unittest.main()
