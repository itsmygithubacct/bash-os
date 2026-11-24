#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tar -g/-G/-N against GNU tar, both ways.

A source tree goes through a level-0 dump and two increments (files added,
modified, chmod'ed and deleted; files and directories renamed, a directory
moved into another, two directories swapped, a tree deleted). At each level
GNU tar and the bash-os tar builtin each dump it with their own snapshot
file, and a third chain alternates the tools on one snapshot file. Every
chain is then restored by both tools with -g /dev/null and with -G, and
each restored tree must equal the source at that level. Listings of every
archive (-tvv -G) must be identical between the tools, and -N/--newer-mtime
must select the same members.

usage: tar-incremental-gnu.py [BASH_OS_BINARY]   (needs GNU tar on PATH)
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
GNU_TAR = shutil.which("tar", path="/usr/bin:/bin")
ENV = {"LC_ALL": "C", "TZ": "UTC", "HOME": "/", "BASH_ENV": "", "ENV": ""}


def gnu_tar_present():
    if not GNU_TAR:
        return False
    out = subprocess.run([GNU_TAR, "--version"], capture_output=True, text=True)
    return out.returncode == 0 and "GNU tar" in out.stdout


def manifest(root):
    """Every entry below ROOT: type, mode, size, content digest, link target,
    file mtime and link count (directory times are not compared: neither tool
    restores them once later members land in a directory)."""
    rows = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            st = os.lstat(path)
            if os.path.islink(path):
                rows[rel] = ("l", os.readlink(path))
            elif os.path.isdir(path):
                rows[rel] = ("d", oct(st.st_mode & 0o7777))
            else:
                digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
                rows[rel] = ("f", oct(st.st_mode & 0o7777), st.st_size, digest, st.st_mtime_ns // 10**9, st.st_nlink)
    return rows


class Incremental(unittest.TestCase):
    maxDiff = None
    def setUp(self):
        if not gnu_tar_present():
            self.skipTest("GNU tar is not on PATH")
        temp = tempfile.TemporaryDirectory(prefix="bash-os-tar-incr-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        os.umask(0o022)
        check = self.bashos("type -t tar")
        self.assertEqual(check.stdout, b"builtin\n", "the bash-os binary has no tar builtin")

    def bashos(self, script, *args, cwd=None):
        return subprocess.run([BINARY, "--noprofile", "--norc", "-c", script, "tar", *args],
                              cwd=cwd or self.root, capture_output=True, timeout=60,
                              env={**ENV, "PATH": ""})

    def gnu(self, *args, cwd=None):
        return subprocess.run(["tar", *args], executable=GNU_TAR, cwd=cwd or self.root,
                              capture_output=True, timeout=60, env={**ENV, "PATH": "/usr/bin:/bin"})

    def tar(self, tool, *args, cwd=None):
        if tool == "gnu":
            result = self.gnu(*args, cwd=cwd)
        else:
            result = self.bashos('tar "$@"', *args, cwd=cwd)
        self.assertEqual(result.returncode, 0, (tool, args, result.stderr))
        return result

    # The source tree and its changes between dumps.
    def stage0(self, s):
        for d in ("a/b", "c", "empty", "keep/deep", "x", "y", "gone/sub"):
            (s / d).mkdir(parents=True)
        (s / "a/one").write_text("one\n")
        (s / "a/b/two").write_bytes(bytes(range(256)) * 12)
        (s / "c/three").write_text("three\n")
        (s / "c/with space").write_text("space\n")
        (s / "keep/deep/file").write_text("deep\n")
        (s / "keep/stay").mkdir()
        (s / "keep/stay/s").write_text("s\n")
        (s / "x/xf").write_text("X\n")
        (s / "y/yf").write_text("Y\n")
        (s / "gone/sub/g").write_text("g\n")
        (s / "exec").write_text("#!/bin/sh\n")
        os.chmod(s / "exec", 0o700)
        os.symlink("a/one", s / "link")
        os.link(s / "c/three", s / "c/three-hard")
        (s / "zero").write_bytes(b"")

    def stage1(self, s):
        with open(s / "a/one", "a") as f:
            f.write("more\n")
        (s / "a/new").write_text("new\n")
        (s / "fresh/inner").mkdir(parents=True)
        (s / "fresh/inner/f").write_text("fresh\n")
        os.remove(s / "c/with space")
        shutil.rmtree(s / "gone")
        os.rename(s / "c/three-hard", s / "c/renamed-file")
        os.rename(s / "keep/deep", s / "a/moved-deep")
        os.chmod(s / "zero", 0o600)
        os.remove(s / "link")
        os.symlink("c/three", s / "link")

    def stage2(self, s):
        os.rename(s / "x", s / "tmp-swap")
        os.rename(s / "y", s / "x")
        os.rename(s / "tmp-swap", s / "y")
        os.rename(s / "a/b", s / "c/b-renamed")
        os.rename(s / "fresh", s / "fresh2")
        os.rename(s / "fresh2/inner", s / "fresh2/inner2")
        (s / "fresh2/inner2/added").write_text("added\n")
        (s / "newdir").mkdir()
        os.rename(s / "keep", s / "newdir/keep-moved")
        os.remove(s / "a/new")
        (s / "empty/now-full").write_text("full\n")
        (s / "exec").write_text("#!/bin/sh\nexit 0\n")

    def test_round_trip_both_ways(self):
        src = self.root / "src"
        src.mkdir()
        stages = (self.stage0, self.stage1, self.stage2)
        chains = {"gnu": ["gnu"] * 3, "bashos": ["bashos"] * 3, "mixed-gb": ["gnu", "bashos", "gnu"],
                  "mixed-bg": ["bashos", "gnu", "bashos"]}
        expected = []
        for level, stage in enumerate(stages):
            # GNU tar takes a dump's start from the fine clock, while file
            # times come from the kernel's coarse one: a change made within
            # a clock tick of the last GNU dump can look older than it.
            # bash-os uses the coarse clock; let one tick pass for GNU.
            if level:
                time.sleep(0.05)
            stage(src)
            expected.append(manifest(src))
            for chain, tools in chains.items():
                self.tar(tools[level], "-cf", f"{chain}.{level}.tar", "-g", f"{chain}.snar", "src")
        # Both tools list every archive alike, dumpdirs included.
        for chain in chains:
            for level in range(3):
                archive = f"{chain}.{level}.tar"
                for flags in (("-tvv", "-G"), ("-t",), ("-tv", "-g", "/dev/null")):
                    g = self.tar("gnu", *flags, "-f", archive)
                    b = self.tar("bashos", *flags, "-f", archive)
                    self.assertEqual(b.stdout.decode(), g.stdout.decode(), (archive, flags))
        # Every chain restored by each tool matches the source at each level.
        for chain in chains:
            for extractor in ("gnu", "bashos"):
                for mode in (("-g", "/dev/null"), ("-G",)):
                    out = self.root / f"out-{chain}-{extractor}-{mode[0]}"
                    out.mkdir()
                    for level in range(3):
                        self.tar(extractor, "-xf", f"../{chain}.{level}.tar", *mode, cwd=out)
                        with self.subTest(chain=chain, extractor=extractor, mode=mode[0], level=level):
                            self.assertEqual(manifest(out / "src"), expected[level])
        # Both snapshot files name the same directories and contents.
        def records(path):
            data = path.read_bytes().split(b"\n", 1)[1].split(b"\0")[2:]
            out, i = {}, 0
            while i + 6 <= len(data) and data[i]:
                name, i = data[i + 5], i + 6
                entries = []
                while data[i]:
                    entries.append(data[i]); i += 1
                i += 2
                out[name] = entries
            return out
        self.assertEqual(records(self.root / "bashos.snar"), records(self.root / "gnu.snar"))
        self.assertTrue((self.root / "bashos.snar").read_bytes().startswith(b"GNU tar-1.35-2\n"))

    def test_increment_right_after_a_dump(self):
        """A change made just before a dump is not stored again by the next
        level, and one made just after it is stored: the builtin runs both
        dumps in one shell, well inside one tick of the clock file times use."""
        script = ('for i in $(seq 1 40); do d=t$i; mkdir -p $d/src; echo a > $d/src/a\n'
                  '  tar -cf $d/0.tar -g $d/snar -C $d src || exit 1; echo b > $d/src/b\n'
                  '  tar -cf $d/1.tar -g $d/snar -C $d src || exit 1\n'
                  '  l=$(tar -tf $d/1.tar | tr "\\n" " "); [[ $l == "src/ src/b " ]] || { echo "$i: [$l]"; exit 1; }\n'
                  'done; echo ok')
        result = self.bashos(script)
        self.assertEqual((result.returncode, result.stdout), (0, b"ok\n"), result.stderr)

    def test_extract_deletes_and_verbose(self):
        src = self.root / "src"
        (src / "d").mkdir(parents=True)
        (src / "d/f").write_text("f\n")
        (src / "d/g").write_text("g\n")
        self.tar("gnu", "-cf", "l0.tar", "-g", "snar", "src")
        os.remove(src / "d/g")
        self.tar("gnu", "-cf", "l1.tar", "-g", "snar", "src")
        for tool in ("gnu", "bashos"):
            out = self.root / f"out-{tool}"
            out.mkdir()
            self.tar(tool, "-xf", "../l0.tar", "-G", cwd=out)
            (out / "src/d/junk").mkdir()
            (out / "src/d/junk/x").write_text("x\n")
            result = self.tar(tool, "-xvf", "../l1.tar", "-g", "/dev/null", cwd=out)
            self.assertIn(b"tar: Deleting 'src/d/g'\n", result.stdout)
            self.assertIn(b"tar: Deleting 'src/d/junk'\n", result.stdout)
            # Replaying the increment: the deleted file is gone already, the
            # rest is extracted again.
            again = self.tar(tool, "-xf", "../l1.tar", "-G", cwd=out)
            self.assertEqual(again.stderr, b"")
            self.assertEqual(sorted(os.listdir(out / "src/d")), ["f"])
        # Without -G the 'D' members are plain directories: nothing is deleted.
        out = self.root / "plain"
        out.mkdir()
        self.tar("bashos", "-xf", "../l0.tar", cwd=out)
        self.tar("bashos", "-xf", "../l1.tar", cwd=out)
        self.assertEqual(sorted(os.listdir(out / "src/d")), ["f", "g"])

    def test_newer_selects_like_gnu(self):
        src = self.root / "src"
        (src / "sub").mkdir(parents=True)
        for name, when in (("old", "2020-01-01"), ("edge", "2021-01-01"), ("sub/new", "2022-06-01")):
            (src / name).write_text(name + "\n")
            subprocess.run(["touch", "-d", when, str(src / name)], check=True)
        subprocess.run(["touch", "-d", "2021-01-01", str(self.root / "ref")], check=True)
        cases = (("--newer-mtime=2021-01-01",), ("--newer-mtime", "./ref"), ("-N", "2030-01-01"),
                 ("--after-date=2021-01-01",), ("--newer-mtime=@1609459201",))
        for flags in cases:
            for tool in ("gnu", "bashos"):
                self.tar(tool, "-cf", f"{tool}.tar", *flags, "src")
            # bash-os writes ustar by default, GNU its own format: directory
            # names differ only by GNU's trailing '/'.
            g = [n.rstrip(b"/") for n in self.tar("gnu", "-tf", "gnu.tar").stdout.splitlines()]
            b = [n.rstrip(b"/") for n in self.tar("gnu", "-tf", "bashos.tar").stdout.splitlines()]
            self.assertEqual(sorted(b), sorted(g), flags)
            gv = self.gnu("-cvf", "/dev/null", *flags, "src")
            bv = self.bashos('tar "$@"', "-cvf", "/dev/null", *flags, "src")
            self.assertEqual(sorted(bv.stderr.splitlines()), sorted(gv.stderr.splitlines()), flags)
        self.tar("gnu", "-cf", "all.tar", "src")
        for flags in (("--newer-mtime=2021-01-01",), ("-N", "2021-01-01 00:00:01")):
            g = self.gnu("-tvf", "all.tar", *flags)
            b = self.bashos('tar "$@"', "-tvf", "all.tar", *flags)
            self.assertEqual((b.returncode, b.stdout, b.stderr), (g.returncode, g.stdout, g.stderr), flags)

    def test_diagnostics_like_gnu(self):
        (self.root / "src").mkdir()
        for args in (("-cf", "x.tar", "-g", "s", "-N", "2021-01-01", "src"),
                     ("-cf", "x.tar", "--level=x", "-g", "s", "src"),
                     ("-cf", "x.tar", "-N", "/nonexistent", "src"),
                     ("-cf", "x.tar", "--format=ustar", "-g", "s", "src"),
                     ("-cf", "x.tar", "--level=1", "src"),
                     ("-cf", "x.tar", "-N", "nonsense words", "src")):
            g = self.gnu(*args)
            b = self.bashos('tar "$@"', *args)
            self.assertEqual((b.returncode, b.stderr), (g.returncode, g.stderr), args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
