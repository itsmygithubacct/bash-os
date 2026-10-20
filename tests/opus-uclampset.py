#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""uclampset: PID/system setters and command mode, against owned children,
an interposed sched_setattr and private sysctl fixtures.

tests/opus-uclampset.py [BINARY]

The production builtin runs unchanged. tests/opus-uclampset-shim.c is
LD_PRELOADed into the shell to record every sched_setattr request it builds
and, where the kernel lacks CONFIG_UCLAMP_TASK, to inject errors or emulate
clamp bookkeeping. Expected values come from ctypes sched_getattr/setattr,
os.sched_getscheduler and os.getpriority, not from the builtin. The test
compiles the shim, so run it through the campaign build gate.
"""
import ctypes
import errno
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
# (sched_getattr, sched_setattr)
SYSNR = {"x86_64": (315, 314), "aarch64": (275, 274), "riscv64": (275, 274)}
GETATTR, SETATTR = SYSNR.get(platform.machine(), (None, None))
KEEP_POLICY, KEEP_PARAMS, UMIN, UMAX, RESET = 0x08, 0x10, 0x20, 0x40, 0x01
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


class Attr(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("policy", ctypes.c_uint32),
                ("flags", ctypes.c_uint64), ("nice", ctypes.c_int32),
                ("prio", ctypes.c_uint32), ("runtime", ctypes.c_uint64),
                ("deadline", ctypes.c_uint64), ("period", ctypes.c_uint64),
                ("util_min", ctypes.c_uint32), ("util_max", ctypes.c_uint32)]


def oracle_get(pid):
    attr = Attr()
    rc = LIBC.syscall(ctypes.c_long(GETATTR), ctypes.c_long(pid), ctypes.byref(attr),
                      ctypes.c_ulong(ctypes.sizeof(attr)), ctypes.c_ulong(0))
    if rc < 0:
        raise OSError(ctypes.get_errno(), "sched_getattr")
    return attr


def oracle_set_errno(pid, util_min, util_max):
    """errno the kernel gives this request, 0 on success."""
    attr = oracle_get(pid)
    attr.size = ctypes.sizeof(attr)
    attr.flags = KEEP_POLICY | KEEP_PARAMS | UMIN | UMAX
    attr.util_min, attr.util_max = util_min, util_max
    rc = LIBC.syscall(ctypes.c_long(SETATTR), ctypes.c_long(pid), ctypes.byref(attr),
                      ctypes.c_ulong(0))
    return ctypes.get_errno() if rc < 0 else 0


def uclamp_kernel():
    return Path("/proc/sys/kernel/sched_util_clamp_min").exists()


CHILD = r"""
import os, sys, threading, time
os.nice(5)
os.sched_setscheduler(0, os.SCHED_BATCH, os.sched_param(0))
for _ in range(int(sys.argv[1])):
    threading.Thread(target=time.sleep, args=(120,), daemon=True).start()
print("ready", flush=True)
time.sleep(120)
"""


@unittest.skipIf(GETATTR is None, "sched_getattr number unknown for this architecture")
class Uclampset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix="bash-os-uclampset-shim-")
        cls.addClassCleanup(tmp.cleanup)
        cls.shim = str(Path(tmp.name) / "uclamp-shim.so")
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
            str(ROOT / "tests/opus-uclampset-shim.c"), "-o", cls.shim, "-ldl"],
            check=True, capture_output=True, timeout=60)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="bash-os-uclampset-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "shim"
        self.state.mkdir()
        self.proc = self.root / "proc"
        (self.proc / "sys/kernel").mkdir(parents=True)

    # -- helpers ---------------------------------------------------------
    def child(self, threads=0):
        p = subprocess.Popen([sys.executable, "-c", CHILD, str(threads)],
                             stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
        self.addCleanup(lambda: (p.kill(), p.wait(), p.stdout.close()))
        self.assertEqual(p.stdout.readline(), b"ready\n")
        return p.pid

    def run_sh(self, script, *args, shim=None, get=None, env=None, timeout=10):
        e = {"PATH": "", "LC_ALL": "C", "BASHOS_PROC_ROOT": str(self.proc)}
        for option in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
            if option in os.environ:
                e[option] = os.environ[option]
        e.update(env or {})
        if shim:
            e.update(LD_PRELOAD=self.shim, UCLAMP_SHIM_DIR=str(self.state),
                     UCLAMP_SHIM_SET=shim)
            if get:
                e["UCLAMP_SHIM_GET"] = get
        r = subprocess.run([BINARY, "--noprofile", "--norc", "-c", script, "uc",
                            *map(str, args)], env=e, cwd=self.root,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        self.assertNotIn(b"AddressSanitizer", r.stderr)
        self.assertNotIn(b"runtime error:", r.stderr)
        return r

    def uc(self, *args, **kw):
        return self.run_sh('uclampset "$@"', *args, **kw)

    def log(self):
        path = self.state / "log"
        lines = path.read_text().splitlines() if path.exists() else []
        out = []
        for line in lines:
            kind, *fields = line.split()
            out.append((kind, dict(f.split("=", 1) for f in fields)))
        return out

    def sets(self):
        return [f for kind, f in self.log() if kind == "set"]

    def comm(self, pid):
        return Path(f"/proc/{pid}/comm").read_text().strip()

    def write_sysctl(self, lo, hi):
        (self.proc / "sys/kernel/sched_util_clamp_min").write_text(f"{lo}\n")
        (self.proc / "sys/kernel/sched_util_clamp_max").write_text(f"{hi}\n")

    def sysctl(self):
        return ((self.proc / "sys/kernel/sched_util_clamp_min").read_text(),
                (self.proc / "sys/kernel/sched_util_clamp_max").read_text())

    # -- presence and queries ---------------------------------------------
    def test_builtin_with_help_under_empty_path(self):
        r = self.run_sh('type -t uclampset; help uclampset >/dev/null && echo help; '
                        'mapfile -t h < <(uclampset --help); printf "%s\\n" "${h[@]:0:2}"; '
                        'uclampset -V; uclampset >/dev/null; echo $?')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode().splitlines(),
                         ["builtin", "help", "Usage:", " uclampset [options]", "uclampset 0.2", "0"])

    def test_query_owned_child_matches_kernel(self):
        pid = self.child()
        a = oracle_get(pid)
        expect = f"{self.comm(pid)} ({pid}) util_clamp: min: {a.util_min} max: {a.util_max}\n"
        for args in (("-p", pid), (f"--pid={pid}",), (f"-p{pid}",), ("--pid", pid)):
            r = self.uc(*args)
            self.assertEqual((r.returncode, r.stdout.decode(), r.stderr), (0, expect, b""), args)

    def test_all_tasks_lists_every_thread(self):
        pid = self.child(threads=3)
        tids = sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))
        self.assertEqual(len(tids), 4)
        r = self.uc("-a", "-p", pid)
        self.assertEqual(r.returncode, 0, r.stderr)
        got = sorted(int(m) for m in re.findall(rb"\((\d+)\) util_clamp", r.stdout))
        self.assertEqual(got, tids)
        r = self.run_sh('uclampset -a -p 0; echo "self=$$"')
        shell = re.search(rb"self=(\d+)", r.stdout).group(1)
        self.assertEqual(re.findall(rb"\((\d+)\) util_clamp", r.stdout), [shell])
        r = self.uc("-a", "-p", 2147483647)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"cannot obtain the list of tasks for pid 2147483647", r.stderr)

    def test_repeated_queries_keep_descriptors_and_output_stable(self):
        pid = self.child()
        r = self.run_sh('fds() { local f=(/proc/$$/fd/*); echo ${#f[@]}; }; before=$(fds); '
                        'first=$(uclampset -p "$1"); for i in {1..200}; do '
                        '[[ $(uclampset -p "$1") == "$first" ]] || { echo drift; exit 1; }; done; '
                        'uclampset -s >/dev/null 2>&1; uclampset -m 1 -p 2147483647 2>/dev/null; '
                        'echo "$before $(fds)"', pid)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        before, after = r.stdout.split()
        self.assertEqual(before, after)

    def test_output_failure_is_reported(self):
        pid = self.child()
        r = self.run_sh('uclampset -p "$1" >/dev/full; echo "rc=$?"; uclampset -p "$1" | :; '
                        'uclampset -p "$1" >/dev/null; echo "after=$?"', pid)
        self.assertIn(b"rc=1", r.stdout)
        self.assertIn(b"after=0", r.stdout)
        self.assertIn(b"write error", r.stderr)

    @unittest.skipUnless(Path("/usr/bin/uclampset").exists(), "util-linux uclampset absent")
    def test_util_linux_parity(self):
        pid = self.child(threads=1)
        cases = [("-p", pid), ("-a", "-p", pid), (f"--pid={pid}",), ("-p", "abc"),
                 ("-p",), ("-m",), ("-m", 5), ("-m", "1.5", "-p", pid),
                 ("-M", "x", "-p", pid), ("-p", 2147483647)]
        if not uclamp_kernel():  # both refuse on this kernel; never mutates
            cases.append(("-m", 0, "-M", 512, "-p", pid))
        for args in cases:
            with self.subTest(args=args):
                ours = self.uc(*args)
                ref = subprocess.run(["uclampset", *map(str, args)], executable="/usr/bin/uclampset",
                                     capture_output=True,
                                     env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}, timeout=10)
                self.assertEqual((ours.returncode, ours.stdout, ours.stderr),
                                 (ref.returncode, ref.stdout, ref.stderr))

    # -- validation before any request ------------------------------------
    def test_invalid_values_never_reach_the_kernel(self):
        pid = self.child()
        bad = ["", " 5", "5 ", "1025", "-2", "1.5", "5x", "1e3", "nan", "inf",
               "4294967296", "-4294967297", "0x10", "--1"]
        for flag in ("-m", "-M"):
            for value in bad:
                with self.subTest(flag=flag, value=value):
                    r = self.uc(flag, value, "-p", pid, shim="emulate")
                    self.assertEqual(r.returncode, 1)
                    self.assertEqual(r.stdout, b"")
                    self.assertIn(b"invalid util_m", r.stderr)
        self.assertEqual(self.log(), [])

    def test_min_above_max_rejected_before_reading(self):
        pid = self.child()
        for args in (("-m", 600, "-M", 512), ("-M", 0, "-m", 1), ("-m", 1024, "-M", 1023)):
            r = self.uc(*args, "-p", pid, shim="emulate")
            self.assertEqual(r.returncode, 1)
            self.assertIn(b"must be <= util_max", r.stderr)
        r = self.uc("-m", 600, "-M", 512, "true", shim="emulate")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.log(), [])

    def test_all_leading_whitespace_rejected_before_reads_or_writes(self):
        pid = self.child()
        self.write_sysctl(100, 900)
        files = [self.proc / f"sys/kernel/sched_util_clamp_{side}" for side in ("min", "max")]
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in files]
        for whitespace in (" ", "\t", "\n", "\r", "\v", "\f"):
            for flag in ("-m", "-M"):
                for value in (whitespace + "5", whitespace + "-1"):
                    for target in (("-p", pid), ("-s",), ("true",)):
                        with self.subTest(flag=flag, value=repr(value), target=target):
                            r = self.uc(flag, value, *target, shim="emulate")
                            self.assertEqual((r.returncode, r.stdout), (1, b""))
                            self.assertIn(b"invalid util_", r.stderr)
            r = self.uc("-m", 5, "-p", whitespace + str(pid), shim="emulate")
            self.assertEqual((r.returncode, r.stdout), (1, b""))
            self.assertIn(b"invalid PID argument", r.stderr)
        self.assertEqual(self.log(), [])
        self.assertEqual([(p.read_bytes(), p.stat().st_mtime_ns) for p in files], before)

    def test_invalid_pids_and_operands(self):
        pid = self.child()
        cases = [
            (("-p", "abc"), b"invalid PID argument"),
            (("-p", "-1"), b"invalid PID argument"),
            (("-p", "4294967296"), b"invalid PID argument"),
            (("-p", ""), b"invalid PID argument"),
            (("-p", "12x"), b"invalid PID argument"),
            (("-m", 5, "-p"), b"requires an argument"),
            (("-p",), b"requires an argument"),
            (("--pid",), b"requires an argument"),
            (("-m",), b"requires an argument"),
            (("-M",), b"requires an argument"),
            (("-m", 5), b"no cmd to execute"),
            (("-R",), b"no cmd to execute"),
            (("-m", 5, "-s", "-p", pid), b"mutually exclusive"),
            (("-p", pid, "extra"), b"unexpected operand"),
            (("-m", 5, "-s", "extra"), b"unexpected operand"),
            (("-a", "-m", 5, "true"), b"--all-tasks requires --pid"),
            (("-R", "-m", 5, "-s"), b"does not apply"),
            (("true",), b"no util value"),
            (("-x",), b"invalid option"),
            (("--bogus",), b"unrecognized option"),
            (("--system=1",), b"unrecognized option"),
        ]
        for args, msg in cases:
            with self.subTest(args=args):
                r = self.uc(*args, shim="emulate")
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertEqual(r.stdout, b"")
                self.assertIn(msg, r.stderr)
        self.assertEqual(self.sets(), [])

    def test_missing_target_fails_on_read_without_set(self):
        r = self.uc("-m", 1, "-p", 2147483647, shim="emulate")
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"failed to get pid 2147483647's uclamp values: No such process", r.stderr)
        self.assertEqual(self.sets(), [])
        r = self.uc("-m", 1, "-p", os.getpid(), shim="emulate", get="errno:1")
        self.assertIn(b"Operation not permitted", r.stderr)
        self.assertEqual(self.sets(), [])

    # -- kernel paths ------------------------------------------------------
    def test_real_kernel_pid_setter(self):
        pid = self.child()
        before = oracle_get(pid)
        nice = os.getpriority(os.PRIO_PROCESS, pid)
        expected = oracle_set_errno(pid, 64, 512)
        r = self.uc("-m", 64, "-M", 512, "-p", pid, shim="real")
        sent = self.sets()
        self.assertEqual(len(sent), 1)
        self.assertEqual(int(sent[0]["result"]), expected)
        if expected:
            # This kernel refuses: same errno, nothing changed.
            self.assertEqual(r.returncode, 1)
            self.assertIn(os.strerror(expected).encode(), r.stderr)
            after = oracle_get(pid)
            self.assertEqual((after.util_min, after.util_max), (before.util_min, before.util_max))
            if not uclamp_kernel():
                self.assertEqual(expected, errno.EOPNOTSUPP)
            return
        # CONFIG_UCLAMP_TASK kernel: read/set/read on the owned child.
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.uc("-m", 100, "-M", 900, "-p", pid)
        self.assertEqual(r.returncode, 0, r.stderr)
        after = oracle_get(pid)
        self.assertEqual((after.util_min, after.util_max), (100, 900))
        self.assertEqual(os.sched_getscheduler(pid), os.SCHED_BATCH)
        self.assertEqual(os.getpriority(os.PRIO_PROCESS, pid), nice)
        r = self.uc("-p", pid)
        self.assertIn(b"min: 100 max: 900", r.stdout)

    @unittest.skipIf(uclamp_kernel(), "requires a kernel without CONFIG_UCLAMP_TASK")
    def test_unsupported_single_clamp_reaches_real_kernel(self):
        pid = self.child()
        before = oracle_get(pid)
        self.assertEqual((before.util_min, before.util_max), (0, 0))
        # The private system fixture must not be used as the kernel support probe.
        self.write_sysctl(0, 1024)
        r = self.uc("-m", 1, "-p", pid, shim="real")
        self.assertEqual((r.returncode, r.stdout), (1, b""))
        self.assertIn(os.strerror(errno.EOPNOTSUPP).encode(), r.stderr)
        self.assertEqual([int(s["result"]) for s in self.sets()], [errno.EOPNOTSUPP])
        after = oracle_get(pid)
        self.assertEqual((after.util_min, after.util_max), (0, 0))

    def test_injected_kernel_errors(self):
        pid = self.child()
        for err in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL):
            with self.subTest(err=err):
                r = self.uc("-m", 1, "-p", pid, shim=f"errno:{err}")
                self.assertEqual(r.returncode, 1)
                self.assertEqual(r.stdout, b"")
                self.assertEqual(r.stderr.decode(),
                                 f"uclampset: failed to set pid {pid}'s uclamp values: "
                                 f"{os.strerror(err)}\n")

    def test_emulated_read_set_read_preserves_scheduler_fields(self):
        pid = self.child()
        policy, nice = os.sched_getscheduler(pid), os.getpriority(os.PRIO_PROCESS, pid)
        expected_nice = min(19, os.getpriority(os.PRIO_PROCESS, 0) + 5)
        self.assertEqual((policy, nice), (os.SCHED_BATCH, expected_nice))
        name = self.comm(pid)

        def show():
            r = self.uc("-p", pid, shim="emulate")
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout.decode()

        self.assertEqual(show(), f"{name} ({pid}) util_clamp: min: 0 max: 1024\n")
        steps = [
            (("-m", 128, "-M", 768), KEEP_POLICY | KEEP_PARAMS | UMIN | UMAX, (128, 768)),
            (("-m", 200), KEEP_POLICY | KEEP_PARAMS | UMIN, (200, 768)),
            (("-M", -1), KEEP_POLICY | KEEP_PARAMS | UMAX, (200, 1024)),
            (("-M", 300), KEEP_POLICY | KEEP_PARAMS | UMAX, (200, 300)),
            (("-m", -1, "-M", -1), KEEP_POLICY | KEEP_PARAMS | UMIN | UMAX, (0, 1024)),
            (("-R", "-m", 10), RESET | KEEP_PARAMS | UMIN, (10, 1024)),
        ]
        for args, flags, (lo, hi) in steps:
            with self.subTest(args=args):
                start = len(self.sets())
                r = self.uc(*args, "-p", pid, shim="emulate")
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))
                new = self.sets()[start:]
                self.assertEqual(len(new), 1)
                req = new[0]
                self.assertEqual(int(req["pid"]), pid)
                self.assertEqual(int(req["flags"], 16), flags)
                self.assertEqual(int(req["size"]), 56)
                self.assertEqual(int(req["uflags"]), 0)
                self.assertEqual(int(req["policy"]), policy)
                self.assertEqual(int(req["nice"]), nice)
                k = oracle_get(pid)  # e.g. the EEVDF slice arrives as runtime
                self.assertEqual((int(req["prio"]), int(req["runtime"]),
                                  int(req["deadline"]), int(req["period"])),
                                 (k.prio, k.runtime, k.deadline, k.period))
                if "-m" in args:
                    self.assertEqual(int(req["min"]), args[args.index("-m") + 1])
                if "-M" in args:
                    self.assertEqual(int(req["max"]), args[args.index("-M") + 1])
                self.assertEqual(int(req["result"]), 0)
                self.assertEqual(show(), f"{name} ({pid}) util_clamp: min: {lo} max: {hi}\n")
        # The kernel's own view of the child never changed policy or nice.
        self.assertEqual((os.sched_getscheduler(pid), os.getpriority(os.PRIO_PROCESS, pid)),
                         (policy, nice))
        r = self.uc("-v", "-m", 300, "-M", 400, "-p", pid, shim="emulate")
        self.assertEqual(r.stdout.decode(), f"{name} ({pid}) util_clamp: min: 300 max: 400\n")

    def test_effective_pair_validation_and_reset_exemptions(self):
        pid = self.child()
        state = self.state / f"state-{pid}"
        for initial, args in (((200, 300), ("-M", 100)),
                              ((200, 300), ("-m", 400)),
                              ((0, 0), ("-m", 1))):
            with self.subTest(initial=initial, args=args):
                state.write_text(f"{initial[0]} {initial[1]}\n")
                (self.state / "log").unlink(missing_ok=True)
                r = self.uc(*args, "-p", pid, shim="emulate")
                self.assertEqual((r.returncode, r.stdout), (1, b""))
                self.assertIn(b"must be <= util_max", r.stderr)
                self.assertEqual([kind for kind, _ in self.log()], ["get"])
                self.assertEqual(state.read_text(), f"{initial[0]} {initial[1]}\n")
        # A -1 is exempt from the comparison before the kernel resets it.
        for args, expected in ((("-m", -1, "-M", 100), (0, 100)),
                               (("-m", 600, "-M", -1), (600, 1024)),
                               (("-m", -1), (0, 300)),
                               (("-M", -1), (200, 1024))):
            with self.subTest(args=args):
                state.write_text("200 300\n")
                (self.state / "log").unlink(missing_ok=True)
                r = self.uc(*args, "-p", pid, shim="emulate")
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))
                self.assertEqual(len(self.sets()), 1)
                self.assertEqual(state.read_text(), f"{expected[0]} {expected[1]}\n")

    def test_shim_rejects_invalid_single_clamp_without_builtin_preflight(self):
        pid = self.child()
        state = self.state / f"state-{pid}"
        # This independent syscall client verifies the fixture's validation,
        # rather than relying on requests the corrected builtin rejects first.
        client = r"""
import ctypes, errno, sys
class Attr(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("policy", ctypes.c_uint32),
                ("flags", ctypes.c_uint64), ("nice", ctypes.c_int32),
                ("prio", ctypes.c_uint32), ("runtime", ctypes.c_uint64),
                ("deadline", ctypes.c_uint64), ("period", ctypes.c_uint64),
                ("util_min", ctypes.c_uint32), ("util_max", ctypes.c_uint32)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
pid, getnr, setnr, flag = map(int, sys.argv[1:])
attr = Attr()
assert libc.syscall(ctypes.c_long(getnr), ctypes.c_long(pid), ctypes.byref(attr),
                    ctypes.c_ulong(ctypes.sizeof(attr)), ctypes.c_ulong(0),
                    ctypes.c_ulong(0), ctypes.c_ulong(0)) == 0
attr.flags = 0x08 | 0x10 | flag
if flag == 0x20:
    attr.util_min = 400
else:
    attr.util_max = 100
assert libc.syscall(ctypes.c_long(setnr), ctypes.c_long(pid), ctypes.byref(attr),
                    ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0),
                    ctypes.c_ulong(0)) == -1
assert ctypes.get_errno() == errno.EINVAL
"""
        for flag in (UMIN, UMAX):
            with self.subTest(flag=flag):
                state.write_text("200 300\n")
                (self.state / "log").unlink(missing_ok=True)
                r = self.run_sh('"$1" -c "$2" "$3" "$4" "$5" "$6"',
                                sys.executable, client, pid, GETATTR, SETATTR, flag,
                                shim="emulate")
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))
                self.assertEqual([int(s["result"]) for s in self.sets()], [errno.EINVAL])
                self.assertEqual(state.read_text(), "200 300\n")

    def test_all_tasks_with_different_limits_fail_without_partial_mutation(self):
        pid = self.child(threads=2)
        tids = sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))
        self.assertEqual(len(tids), 3)
        cases = [(((0, 1024), (0, 100), (0, 1024)), ("-m", 200)),
                 (((0, 1024), (200, 1024), (0, 1024)), ("-M", 100)),
                 (((0, 1024), (0, 0), (0, 1024)), ("-m", 1))]
        for limits, args in cases:
            with self.subTest(limits=limits, args=args):
                states = [self.state / f"state-{tid}" for tid in tids]
                for path, (lo, hi) in zip(states, limits):
                    path.write_text(f"{lo} {hi}\n")
                before = [path.read_text() for path in states]
                (self.state / "log").unlink(missing_ok=True)
                r = self.uc("-a", *args, "-p", pid, shim="emulate")
                self.assertEqual((r.returncode, r.stdout), (1, b""))
                self.assertIn(b"must be <= util_max", r.stderr)
                self.assertEqual(self.sets(), [])
                self.assertEqual([path.read_text() for path in states], before)

    def test_all_tasks_validates_every_thread_before_setting(self):
        pid = self.child(threads=2)
        tids = sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))
        r = self.uc("-a", "-m", 50, "-p", pid, shim="emulate")
        self.assertEqual(r.returncode, 0, r.stderr)
        kinds = [k for k, _ in self.log()]
        self.assertEqual(kinds, ["get"] * len(tids) + ["set"] * len(tids))
        self.assertEqual(sorted(int(s["pid"]) for s in self.sets()), tids)
        r = self.uc("-a", "-p", pid, shim="emulate")
        self.assertEqual(r.stdout.count(b"min: 50 max: 1024"), len(tids))

    # -- command mode --------------------------------------------------------
    def test_command_runs_literal_argv_in_a_clamped_child(self):
        r = self.run_sh(
            'x=keep; uclampset -m 64 -M 512 "$1" --noprofile --norc -c '
            '\'printf "%s|" "$@"; uclampset -p $$; echo "child=$$"; exit 7\' sh "a b" "*" "\\$HOME" ""; '
            'echo "rc=$? parent=$$ x=$x"; uclampset -p $$', BINARY, shim="emulate")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout.decode()
        self.assertTrue(out.startswith("a b|*|$HOME||"), out)
        child = int(re.search(r"child=(\d+)", out).group(1))
        parent = int(re.search(r"parent=(\d+)", out).group(1))
        self.assertNotEqual(child, parent)
        self.assertIn(f"({child}) util_clamp: min: 64 max: 512", out)
        self.assertIn("rc=7 ", out)
        self.assertIn("x=keep", out)
        self.assertIn(f"({parent}) util_clamp: min: 0 max: 1024", out)
        sent = self.sets()
        self.assertEqual(len(sent), 1)
        self.assertEqual((int(sent[0]["caller"]), int(sent[0]["pid"])), (child, 0))
        self.assertEqual(int(sent[0]["flags"], 16), KEEP_POLICY | KEEP_PARAMS | UMIN | UMAX)
        self.assertFalse((self.state / f"state-{parent}").exists())

    def test_command_status_signal_and_lookup_errors(self):
        (self.root / "noexec").write_text("#!/bin/sh\n")
        r = self.run_sh(
            'uclampset -m 1 /bin/sh -c \'kill -TERM $$\'; echo "sig=$?"; '
            'uclampset -m 1 ./missing; echo "missing=$?"; '
            'uclampset -m 1 ./noexec; echo "noexec=$?"; '
            'uclampset -m 1 false; echo "false=$?"; '
            'uclampset -m 1 cd /; echo "pwd=$PWD"; '
            'uclampset -M 9 printf "%s\\n" builtin; echo "printf=$?"', shim="emulate")
        out = r.stdout.decode()
        for want in ("sig=143", "missing=127", "noexec=126", "false=1",
                     f"pwd={self.root}", "builtin\nprintf=0"):
            self.assertIn(want, out)
        self.assertIn(b"./missing", r.stderr)

    def test_failed_command_setup_does_not_run_command(self):
        for err in (errno.EOPNOTSUPP, errno.EPERM):
            r = self.run_sh('uclampset -m 1 /bin/sh -c "echo ran > marker"; echo "rc=$?"',
                            shim=f"errno:{err}")
            self.assertEqual(r.stdout, b"rc=1\n")
            self.assertRegex(r.stderr.decode(), r"^uclampset: failed to set pid \d+'s uclamp "
                             f"values: {os.strerror(err)}\n$")
            self.assertFalse((self.root / "marker").exists())

    def test_repeated_commands_do_not_leak_descriptors(self):
        r = self.run_sh('fds() { local f=(/proc/$$/fd/*); echo ${#f[@]}; }; before=$(fds); '
                        'for i in {1..30}; do uclampset -m 1 true || exit 9; done; '
                        'echo "$before $(fds)"', shim="emulate")
        self.assertEqual(r.returncode, 0, r.stderr)
        before, after = r.stdout.split()
        self.assertEqual(before, after)
        self.assertEqual(len(self.sets()), 30)

    # -- system limits (private sysctl fixture) -----------------------------
    def test_system_query_and_missing_files(self):
        r = self.uc("-s")
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"cannot read", r.stderr)
        self.write_sysctl(0, 1024)
        r = self.uc("--system")
        self.assertEqual((r.returncode, r.stdout), (0, b"system util_clamp: min: 0 max: 1024\n"))

    def test_system_setters(self):
        self.write_sysctl(1024, 1024)
        steps = [(("-m", 128), ("128\n", "1024\n")),
                 (("-M", 512), ("128\n", "512\n")),
                 (("-m", -1, "-M", 700), ("128\n", "700\n")),
                 (("-m", 700, "-M", -1), ("700\n", "700\n")),
                 (("-m", 0, "-M", 1024), ("0\n", "1024\n"))]
        for args, want in steps:
            with self.subTest(args=args):
                r = self.uc(*args, "-s")
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))
                self.assertEqual(self.sysctl(), want)
        r = self.uc("-v", "-m", 10, "-s")
        self.assertEqual(r.stdout, b"system util_clamp: min: 10 max: 1024\n")

    def test_system_validation_before_any_write(self):
        self.write_sysctl(300, 400)
        cases = [(("-m", 500), b"must be <= util_max"),
                 (("-M", 200), b"must be <= util_max"),
                 (("-m", 9, "-M", 8), b"must be <= util_max"),
                 (("-m", 1025), b"invalid util_min")]
        for args, msg in cases:
            r = self.uc(*args, "-s")
            self.assertEqual(r.returncode, 1)
            self.assertIn(msg, r.stderr)
            self.assertEqual(self.sysctl(), ("300\n", "400\n"))
        (self.proc / "sys/kernel/sched_util_clamp_max").write_text("garbage\n")
        r = self.uc("-m", 10, "-s")
        self.assertIn(b"cannot parse", r.stderr)
        self.assertEqual((self.proc / "sys/kernel/sched_util_clamp_min").read_text(), "300\n")

    def test_system_permission_checked_before_first_write(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses file modes")
        self.write_sysctl(300, 400)
        mx = self.proc / "sys/kernel/sched_util_clamp_max"
        mx.chmod(0o444)
        stamp = os.stat(self.proc / "sys/kernel/sched_util_clamp_min").st_mtime_ns
        r = self.uc("-m", 100, "-M", 500, "-s")
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"Permission denied", r.stderr)
        self.assertEqual(self.sysctl(), ("300\n", "400\n"))
        self.assertEqual(os.stat(self.proc / "sys/kernel/sched_util_clamp_min").st_mtime_ns, stamp)
        # Only the changed file needs to be writable.
        r = self.uc("-m", 100, "-s")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.sysctl(), ("100\n", "400\n"))

    def test_system_write_order_and_rollback(self):
        def writes():
            return [(f["path"].rsplit("_", 1)[1], int(f["result"]))
                    for kind, f in self.log() if kind == "write"]

        cases = [
            # Raising the floor above the current ceiling moves the ceiling first.
            ((100, 200), ("-m", 500, "-M", 600), None, 0, ("500\n", "600\n"),
             [("max", 0), ("min", 0)]),
            ((100, 200), ("-m", 50, "-M", 150), None, 0, ("50\n", "150\n"),
             [("min", 0), ("max", 0)]),
            # A failed second open is rejected before either file is written.
            ((100, 200), ("-m", 50, "-M", 150), "sched_util_clamp_max", 1, ("100\n", "200\n"),
             []),
            ((100, 200), ("-m", 500, "-M", 600), "sched_util_clamp_min", 1, ("100\n", "200\n"),
             []),
            # An unchanged value is not rewritten.
            ((100, 200), ("-m", 100, "-M", 300), None, 0, ("100\n", "300\n"), [("max", 0)]),
            ((100, 200), ("-m", 100), None, 0, ("100\n", "200\n"), []),
        ]
        for start, args, fail, rc, want, order in cases:
            with self.subTest(start=start, args=args, fail=fail):
                (self.state / "log").unlink(missing_ok=True)
                self.write_sysctl(*start)
                env = {"UCLAMP_SHIM_FAIL_WRITE": fail} if fail else {}
                r = self.uc(*args, "-s", shim="real", env=env)
                self.assertEqual(r.returncode, rc, r.stderr)
                self.assertEqual(self.sysctl(), want)
                self.assertEqual(writes(), order)
                if fail:
                    self.assertIn(b"Input/output error", r.stderr)
                    opened = [f for kind, f in self.log() if kind == "open"]
                    self.assertEqual([int(f["result"]) for f in opened], [0, errno.EIO])

if __name__ == "__main__":
    unittest.main(verbosity=2)
