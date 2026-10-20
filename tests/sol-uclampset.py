#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent follow-up regressions plus the complete predecessor suite.
Compiles the syscall interposer: run through the campaign build gate.
"""
import importlib.util
import errno
import os
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("uclamp_tests", Path(__file__).with_name("opus-uclampset.py"))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class SolUclampset(u.Uclampset):
    def test_verbose_command_output_failure_stops_execution(self):
        for options, mode in (("-m 1", "emulate"), ("-R", "real")):
            with self.subTest(options=options):
                (self.root / "marker").unlink(missing_ok=True)
                r = self.run_sh('uclampset -v ' + options +
                                ' /bin/sh -c "echo ran > marker" >/dev/full; '
                                'echo "rc=$?"; uclampset -p $$ >/dev/null; echo "alive=$?"',
                                shim=mode)
                self.assertEqual(r.stdout, b"rc=1\nalive=0\n")
                self.assertFalse((self.root / "marker").exists())

    def test_second_system_open_denied_before_mutation(self):
        self.write_sysctl(100, 200)
        files = [self.proc / f"sys/kernel/sched_util_clamp_{s}" for s in ("min", "max")]
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in files]
        r = self.uc("-m", 50, "-M", 150, "-s", shim="real", env={
            "UCLAMP_SHIM_FAIL_WRITE": "sched_util_clamp_max", "UCLAMP_SHIM_OPEN_ERRNO": "13"})
        self.assertEqual((r.returncode, r.stdout), (1, b""))
        self.assertIn(b"Permission denied", r.stderr)
        self.assertEqual([(p.read_bytes(), p.stat().st_mtime_ns) for p in files], before)
        self.assertFalse(any(k == "write" for k, _ in self.log()))
        self.assertTrue(all(not (int(f["flags"]) & os.O_TRUNC)
                            for k, f in self.log() if k == "open"))

    def test_system_write_failures_restore_both_files(self):
        for initial, args, side in (((100, 200), ("-m", 50, "-M", 150), "max"),
                                    ((100, 200), ("-m", 500, "-M", 600), "min")):
            for fault in ("error", "short", "zero", "error-always"):
                with self.subTest(args=args, fault=fault):
                    self.write_sysctl(*initial)
                    (self.state / "log").unlink(missing_ok=True)
                    r = self.uc(*args, "-s", shim="real", env={
                        "UCLAMP_SHIM_IO_FILE": f"sched_util_clamp_{side}",
                        "UCLAMP_SHIM_IO_FAULT": fault})
                    self.assertEqual((r.returncode, r.stdout), (1, b""))
                    self.assertIn(b"Input/output error", r.stderr)
                    if fault == "error-always":
                        self.assertIn(b"cannot restore", r.stderr)
                    self.assertEqual(self.sysctl(), ("100\n", "200\n"))
                    writes = [f for k, f in self.log() if k == "write"]
                    self.assertEqual(len(writes), 4)  # two attempts, inverse-order restoration

    def test_system_eintr_and_close_errors_and_no_descriptor_leaks(self):
        self.write_sysctl(100, 200)
        for fault, rc in (("eintr", 0), ("close", 1)):
            with self.subTest(fault=fault):
                r = self.run_sh('fds() { local a=(/proc/$$/fd/*); echo ${#a[@]}; }; '
                                'before=$(fds); uclampset -m 50 -M 150 -s; echo "rc=$?"; '
                                'echo "fds=$before:$(fds)"', shim="real", env={
                                    "UCLAMP_SHIM_IO_FILE": "sched_util_clamp_max",
                                    "UCLAMP_SHIM_IO_FAULT": fault})
                self.assertIn(f"rc={rc}\n".encode(), r.stdout)
                a, b = r.stdout.split(b"fds=")[1].strip().split(b":")
                self.assertEqual(a, b)
                self.assertEqual(self.sysctl(), ("50\n", "150\n"))
                self.write_sysctl(100, 200)

    def test_reset_only_reaches_real_kernel_and_preserves_parameters(self):
        pid = self.child()
        before = u.oracle_get(pid)
        r = self.uc("-R", "-p", pid, shim="real")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"", b""))
        after = u.oracle_get(pid)
        self.assertEqual(after.flags & u.RESET, u.RESET)
        for name in ("policy", "nice", "prio", "runtime", "deadline", "period", "util_min", "util_max"):
            self.assertEqual(getattr(before, name), getattr(after, name), name)
        self.assertEqual(int(self.sets()[0]["flags"], 16), u.RESET | u.KEEP_PARAMS)

    def test_real_reset_command_and_later_fork(self):
        client = r"""
import os, sys
assert os.sched_getscheduler(0) & os.SCHED_RESET_ON_FORK
assert not (os.sched_getscheduler(os.getppid()) & os.SCHED_RESET_ON_FORK)
print("parent-reset=1", flush=True)
pid = os.fork()
if pid == 0:
    assert not (os.sched_getscheduler(0) & os.SCHED_RESET_ON_FORK)
    print("child-reset=0", flush=True)
    os._exit(0)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
"""
        r = self.run_sh('uclampset -R "$1" -c "$2"; echo "rc=$?"',
                        u.sys.executable, client, shim="real")
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (0, b"parent-reset=1\nchild-reset=0\nrc=0\n", b""))

    def test_repeated_setters_and_command_leave_parent_jobs_and_traps_intact(self):
        pid = self.child()
        self.write_sysctl(0, 1024)
        r = self.run_sh('fds() { local a=(/proc/$$/fd/*); echo ${#a[@]}; }; before=$(fds); '
                        'trap "seen=yes" CHLD; /bin/sleep .02 & bg=$!; '
                        'for ((i=0;i<50;i++)); do '
                        'uclampset -m 0 -M 512 -p "$1" || exit 8; '
                        'uclampset -p "$1" >/dev/null || exit 11; '
                        'uclampset -m "$((i%2 ? 100 : 200))" -s || exit 9; '
                        'done; for i in {1..5}; do uclampset -m 1 exit 7; [[ $? == 7 ]] || exit 10; done; '
                        'wait "$bg"; echo "job=$? seen=$seen"; '
                        'echo "fds=$before:$(fds)"; uclampset -p $$', pid, shim="emulate")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"job=0 seen=yes\n", r.stdout)
        a, b = r.stdout.split(b"fds=")[1].splitlines()[0].split(b":")
        self.assertEqual(a, b)
        self.assertIn(b"min: 0 max: 1024", r.stdout)
        self.assertEqual(self.sysctl(), ("100\n", "1024\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
