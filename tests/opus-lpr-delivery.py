#!/usr/bin/env python3
"""lpr delivery to a fixture backend in a private spool; nothing is printed.

Every job goes to a fake backend executable written into a temporary
directory. It records its argv, the bytes it read, its stdin and descriptor
state and the signals it saw, so the tests check what the production
submit/list/cancel paths actually handed it. The only processes signalled are
children of this test or of the shell under test.
"""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = {k: v for k, v in os.environ.items() if not k.startswith("BASHLPR_")}
if ENV.get("LPR_LOAD_ENV"):
    ENV["BASH_ENV"] = ENV["LPR_LOAD_ENV"]
if ENV.get("LPR_ASAN_LIB"):
    ENV["LD_PRELOAD"] = ENV["LPR_ASAN_LIB"]
    ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    ENV["UBSAN_OPTIONS"] = "halt_on_error=1"
# The preload instruments bash and the module; backends run without it.
PREFIX = "PATH=; unset LD_PRELOAD; "

BACKEND = r'''#!PYTHON -I
import json, os, signal, sys, time
d = os.environ["LPR_FAKE_DIR"]; mode = os.environ.get("LPR_FAKE_MODE", "ok")
def note(name, value):   # atomic: a cancelled backend never leaves half a file
    tmp = os.path.join(d, ".%s.%d" % (name, os.getpid()))
    with open(tmp, "w") as f: json.dump(value, f)
    os.replace(tmp, os.path.join(d, name))
note("pid.json", os.getpid())
st = os.fstat(0)
fds = sorted(int(x) for x in os.listdir("/proc/self/fd"))
note("info.json", {"argv": sys.argv[1:], "pid": os.getpid(), "fds": fds,
                   "stdin_mode": st.st_mode, "stdin_size": st.st_size,
                   "stdin_nlink": st.st_nlink, "fixture_env": os.environ.get("FIXTURE_ENV"),
                   "hidden": os.environ.get("HIDDEN_VAR"), "path": os.environ.get("PATH")})
seen = []
def on_term(sig, frame):
    seen.append(sig); note("signals.json", seen)
    if mode != "ignore-term": os._exit(143)
if mode in ("hang", "ignore-term", "read-hang"):
    signal.signal(signal.SIGTERM, on_term)
def read_all():
    data = b""
    while True:
        chunk = os.read(0, 1 << 20)
        if not chunk: return data
        data += chunk
if mode == "partial":
    data = os.read(0, int(sys.argv[2]) // 2)
elif mode in ("hang", "ignore-term"):
    data = b""
else:
    data = read_all()
with open(os.path.join(d, "received"), "wb") as f: f.write(data)
if mode in ("hang", "ignore-term", "read-hang"):
    open(os.path.join(d, "ready"), "w").close()
    while True: time.sleep(0.05)
if mode == "fail": sys.exit(3)
if mode == "crash": os.kill(os.getpid(), signal.SIGSEGV)
if mode == "late":
    time.sleep(float(os.environ.get("LPR_FAKE_DELAY", "0")))
open(os.path.join(d, "done"), "w").close()
'''.replace("PYTHON", sys.executable)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def wait_for(predicate, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class LprFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.dir = Path(self.temporary.name)
        self.spool = self.dir / "spool"
        self.fake = self.dir / "fake"
        self.fake.mkdir()
        self.backend = self.dir / "backend"
        self.backend.write_text(BACKEND)
        self.backend.chmod(0o700)
        self.input = self.dir / "job.txt"
        self.payload = bytes(range(256)) * 300 + b"tail\n"
        self.input.write_bytes(self.payload)
        self.env = ENV | {"BASHLPR_SPOOL": str(self.spool), "BASHLPR_BACKEND": str(self.backend),
                          "LPR_FAKE_DIR": str(self.fake), "LPR_FAKE_MODE": "ok"}
        self.stray = []
        self.addCleanup(self.reap_strays)

    def reap_strays(self):
        for pid in self.stray:
            if alive(pid):
                os.kill(pid, signal.SIGKILL)

    def check(self, result):
        if b"runtime error:" in result.stderr or b"ERROR: AddressSanitizer" in result.stderr:
            raise AssertionError(result.stderr)
        return result

    def run_shell(self, script, *args, env=None, timeout=20, **kw):
        return self.check(subprocess.run(
            [BINARY, "-c", PREFIX + script, "lpr-test", *map(str, args)],
            env=env or self.env, capture_output=True, timeout=timeout, **kw))

    def spawn(self, script, *args, env=None, **kw):
        kw.setdefault("stdout", subprocess.PIPE)
        kw.setdefault("stderr", subprocess.PIPE)
        p = subprocess.Popen([BINARY, "-c", PREFIX + script, "lpr-test", *map(str, args)],
                             env=env or self.env, **kw)
        self.addCleanup(lambda: p.poll() is None and (p.kill(), p.wait()))
        return p

    def info(self):
        return json.loads((self.fake / "info.json").read_text())

    def spool_files(self):
        return sorted(p.name for p in self.spool.iterdir()) if self.spool.exists() else []

    def wait_ready(self, p):
        self.assertTrue(wait_for(lambda: (self.fake / "ready").exists() or p.poll() is not None),
                        "backend never became ready")
        if p.poll() is not None:
            self.fail(p.communicate()[1])
        pid = self.info()["pid"]
        self.stray.append(pid)
        return pid


class Delivery(LprFixture):
    def test_builtin_with_empty_path_and_help(self):
        self.assertEqual(self.run_shell('type -t lpr').stdout, b"builtin\n")
        if ENV.get("LPR_LOAD_ENV"):   # the sanitized module, not the linked-in builtin
            self.assertEqual(self.run_shell('m=$(< /proc/$$/maps); [[ $m == */lpr.so* ]]').returncode, 0)
        r = self.run_shell('lpr --help')
        self.assertEqual(r.returncode, 0)
        self.assertIn(b"BASHLPR_BACKEND", r.stdout)
        self.assertEqual(self.run_shell('lpr bogus').returncode, 2)
        self.assertEqual(self.run_shell('lpr submit').returncode, 2)
        self.assertEqual(self.run_shell('lpr submit a b').returncode, 2)

    def test_private_spool_success_delivers_exact_bytes_with_literal_argv(self):
        odd = self.dir / "a b;$(touch pwned)'\"*"
        odd.write_bytes(self.payload)
        r = self.run_shell('lpr submit "$1"', odd)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.decode().splitlines()
        self.assertEqual(len(lines), 2, lines)
        spooled = Path(lines[0].removeprefix("lpr: spooled "))
        job = spooled.name.removesuffix(".lpr")
        self.assertEqual(spooled.parent, self.spool)
        self.assertRegex(job, r"^[0-9a-f]{16}$")
        self.assertEqual(lines[1], f"lpr: accepted {job} ({len(self.payload)} bytes)")
        self.assertEqual((self.fake / "received").read_bytes(), self.payload)
        info = self.info()
        self.assertEqual(info["argv"], [job, str(len(self.payload)), odd.name])
        self.assertTrue(stat.S_ISREG(info["stdin_mode"]))
        self.assertEqual(stat.S_IMODE(info["stdin_mode"]), 0o600)
        self.assertEqual(info["stdin_size"], len(self.payload))
        self.assertEqual(info["fds"][:3], [0, 1, 2])
        self.assertLessEqual(len(info["fds"]), 4, info["fds"])   # + the listdir handle
        self.assertFalse((self.dir / "pwned").exists())
        self.assertEqual(stat.S_IMODE(self.spool.stat().st_mode), 0o700)
        self.assertEqual(self.spool_files(), [])

    def test_stdin_submission_and_exported_environment(self):
        r = self.run_shell('export FIXTURE_ENV=seen; HIDDEN_VAR=no; exec 7>"$1"; '
                           'lpr submit - < "$2"', self.dir / "fd7", self.input)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.fake / "received").read_bytes(), self.payload)
        info = self.info()
        self.assertEqual(info["argv"][2], "stdin")
        self.assertEqual(info["fixture_env"], "seen")
        self.assertIsNone(info["hidden"])
        self.assertNotIn(7, info["fds"])
        self.assertEqual(self.spool_files(), [])

    def test_closed_stdin_still_hands_the_job_to_backend(self):
        r = self.run_shell('lpr submit "$1" <&-', self.input)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.fake / "received").read_bytes(), self.payload)
        self.assertTrue(stat.S_ISREG(self.info()["stdin_mode"]))

    def test_empty_job(self):
        empty = self.dir / "empty"
        empty.write_bytes(b"")
        r = self.run_shell('lpr submit "$1"', empty)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"(0 bytes)", r.stdout)
        self.assertEqual(self.info()["argv"][1], "0")

    def test_backend_error_exit_and_signal(self):
        for mode, reason in (("fail", b"backend exited with status 3"),
                             ("crash", b"backend killed by signal 11"),
                             ("partial", b"backend exited 0 after consuming %d of %d bytes"
                              % (len(self.payload) // 2, len(self.payload)))):
            with self.subTest(mode=mode):
                r = self.run_shell('lpr submit "$1"', self.input,
                                   env=self.env | {"LPR_FAKE_MODE": mode})
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertNotIn(b"accepted", r.stdout)
                self.assertIn(b"lpr: failed ", r.stderr)
                self.assertIn(reason, r.stderr)
                self.assertEqual(self.spool_files(), [])

    def test_missing_or_invalid_backend_spools_nothing(self):
        script = self.dir / "noexec"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o600)
        badinterp = self.dir / "badinterp"
        badinterp.write_text("#!/nonexistent/interpreter\n")
        badinterp.chmod(0o700)
        for name, value, rc, needle in (
                ("unset", None, 1, b"no backend configured"),
                ("empty", "", 1, b"no backend configured"),
                ("relative", "backend", 1, b"absolute path"),
                ("missing", str(self.dir / "nope"), 1, b"not an executable file"),
                ("directory", str(self.dir), 1, b"not an executable file"),
                ("not-executable", str(script), 1, b"not an executable file")):
            with self.subTest(name=name):
                env = dict(self.env)
                env.pop("BASHLPR_BACKEND")
                if value is not None:
                    env["BASHLPR_BACKEND"] = value
                r = self.run_shell('lpr submit "$1"', self.input, env=env)
                self.assertEqual(r.returncode, rc, r.stderr)
                self.assertIn(needle, r.stderr)
                self.assertEqual(r.stdout, b"")
                self.assertFalse(self.spool.exists())
        # An exec failure is found only after spooling; the entry is withdrawn.
        r = self.run_shell('lpr submit "$1"', self.input,
                           env=self.env | {"BASHLPR_BACKEND": str(badinterp)})
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"cannot execute backend", r.stderr)
        self.assertNotIn(b"accepted", r.stdout)
        self.assertEqual(self.spool_files(), [])
        self.assertFalse((self.fake / "info.json").exists())

    def test_no_sleep_knob_claims_delivery(self):
        env = dict(self.env)
        env.pop("BASHLPR_BACKEND")
        r = self.run_shell('lpr submit "$1"', self.input, env=env | {"BASHLPR_PRINT_SEC": "0"})
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(b"spooled", r.stdout)

    def test_non_private_spool_is_refused(self):
        self.spool.mkdir(mode=0o700)
        self.spool.chmod(0o777)
        r = self.run_shell('lpr submit "$1"', self.input)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"not private", r.stderr)
        self.assertEqual(self.spool_files(), [])
        self.assertEqual(self.run_shell('lpr cancel 0123456789abcdef').returncode, 1)
        real = self.dir / "real"
        real.mkdir(mode=0o700)
        link = self.dir / "link"
        link.symlink_to(real)
        r = self.run_shell('lpr submit "$1"', self.input, env=self.env | {"BASHLPR_SPOOL": str(link)})
        self.assertEqual(r.returncode, 1)
        self.assertEqual(list(real.iterdir()), [])
        self.assertFalse((self.fake / "info.json").exists())

    def test_timeout_fails_and_terminates_owned_backend(self):
        p = self.spawn('lpr submit "$1"', self.input,
                       env=self.env | {"LPR_FAKE_MODE": "hang", "BASHLPR_TIMEOUT": "1"})
        pid = self.wait_ready(p)
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 1, err)
        self.assertIn(b"backend timed out after 1 s", err)
        self.assertFalse(alive(pid))
        self.assertEqual(json.loads((self.fake / "signals.json").read_text()), [signal.SIGTERM])
        self.assertEqual(self.spool_files(), [])
        for bad in ("-1", "x", "86401"):
            self.assertEqual(self.run_shell('lpr submit "$1"', self.input,
                                            env=self.env | {"BASHLPR_TIMEOUT": bad}).returncode, 2)


class PartialInput(LprFixture):
    def test_unreadable_or_missing_source(self):
        for src, needle in ((self.dir, b"Is a directory"), (self.dir / "nope", b"cannot open")):
            r = self.run_shell('lpr submit "$1"', src)
            self.assertEqual(r.returncode, 1)
            self.assertIn(needle, r.stderr)
            self.assertEqual(self.spool_files(), [])
        self.assertFalse((self.fake / "info.json").exists())

    def test_spool_write_failure_withdraws_partial_entry(self):
        big = self.dir / "big"
        big.write_bytes(b"x" * 300000)
        r = self.run_shell("trap '' XFSZ; ulimit -f 64; lpr submit \"$1\"", big)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn(b"write spool", r.stderr)
        self.assertEqual(r.stdout, b"")
        self.assertEqual(self.spool_files(), [])
        self.assertFalse((self.fake / "info.json").exists())

    def test_signal_during_partial_stdin_cleans_spool(self):
        rfd, wfd = os.pipe()
        p = self.spawn('lpr submit -', stdin=rfd)
        os.close(rfd)
        os.write(wfd, b"half a job\n")
        self.assertTrue(wait_for(lambda: any(n.endswith(".lpr") for n in self.spool_files())))
        entry = next(self.spool / n for n in self.spool_files() if n.endswith(".lpr"))
        self.assertTrue(wait_for(lambda: entry.stat().st_size == 11))
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=10)
        os.close(wfd)
        self.assertEqual(p.returncode, -signal.SIGTERM, err)
        self.assertIn(b"interrupted by signal 15", err)
        self.assertEqual(out, b"")
        self.assertEqual(self.spool_files(), [])
        self.assertFalse((self.fake / "info.json").exists())

    def test_cancel_during_partial_stdin(self):
        rfd, wfd = os.pipe()
        p = self.spawn('lpr submit -; echo "rc=$?"', stdin=rfd)
        os.close(rfd)
        os.write(wfd, b"partial")
        self.assertTrue(wait_for(lambda: any(n.endswith(".lpr") for n in self.spool_files())))
        job = next(n for n in self.spool_files() if n.endswith(".lpr"))
        c = self.run_shell('lpr cancel "$1"', job)
        self.assertEqual(c.returncode, 0, c.stderr)
        out, err = p.communicate(timeout=10)
        os.close(wfd)
        self.assertEqual(out, b"rc=3\n")
        self.assertIn(b"lpr: cancelled", err)
        self.assertEqual(self.spool_files(), [])


class Cancellation(LprFixture):
    def test_list_and_cancel_running_job(self):
        p = self.spawn('lpr submit "$1"; echo "rc=$?"', self.input,
                       env=self.env | {"LPR_FAKE_MODE": "hang"})
        pid = self.wait_ready(p)
        job = self.info()["argv"][0]
        listing = self.run_shell('lpr list')
        self.assertEqual(listing.stdout.decode(), f"{self.spool}/{job}.lpr\n")
        long = self.run_shell('lpr list -l')
        self.assertEqual(long.stdout.decode(), f"{job} active {len(self.payload)}\n")
        c = self.run_shell('lpr cancel "$1"', job + ".lpr")
        self.assertEqual(c.returncode, 0, c.stderr)
        self.assertIn(f"cancel request for {job} handled".encode(), c.stdout)
        out, err = p.communicate(timeout=10)
        self.assertIn(b"rc=3\n", out)
        self.assertNotIn(b"accepted", out)
        self.assertIn(f"lpr: cancelled {job}".encode(), err)
        self.assertFalse(alive(pid))
        self.assertEqual(json.loads((self.fake / "signals.json").read_text()), [signal.SIGTERM])
        self.assertEqual(self.spool_files(), [])
        self.assertEqual(self.run_shell('lpr cancel "$1"', job).returncode, 1)

    def test_backend_ignoring_sigterm_is_killed_after_grace(self):
        p = self.spawn('lpr submit "$1"', self.input, env=self.env | {"LPR_FAKE_MODE": "ignore-term"})
        pid = self.wait_ready(p)
        job = self.info()["argv"][0]
        start = time.monotonic()
        c = self.run_shell('lpr cancel "$1"', job)
        self.assertEqual(c.returncode, 0, c.stderr)
        self.assertGreater(time.monotonic() - start, 1.5)
        p.communicate(timeout=10)
        self.assertEqual(p.returncode, 3)
        self.assertFalse(alive(pid))
        self.assertEqual(self.spool_files(), [])

    def test_signal_to_submitting_shell_stops_backend(self):
        p = self.spawn('lpr submit "$1"', self.input, env=self.env | {"LPR_FAKE_MODE": "hang"})
        pid = self.wait_ready(p)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, -signal.SIGTERM)
        self.assertIn(b"interrupted by signal 15", err)
        self.assertFalse(alive(pid))
        self.assertEqual(self.spool_files(), [])

    def test_trapped_signal_returns_to_shell(self):
        p = self.spawn("trap 'echo trapped' TERM; lpr submit \"$1\"; echo \"rc=$?\"", self.input,
                       env=self.env | {"LPR_FAKE_MODE": "hang"})
        pid = self.wait_ready(p)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=10)
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(out, b"lpr: spooled " + str(self.spool).encode() + b"/"
                         + self.info()["argv"][0].encode() + b".lpr\ntrapped\nrc=143\n")
        self.assertFalse(alive(pid))
        self.assertEqual(self.spool_files(), [])

    def test_cancel_races_with_completion(self):
        outcomes = {}
        for i in range(24):
            for f in self.fake.iterdir():
                f.unlink()
            delay = (i % 6) * 0.01
            p = self.spawn('lpr submit "$1"', self.input,
                           env=self.env | {"LPR_FAKE_MODE": "late", "LPR_FAKE_DELAY": str(delay)})
            assert wait_for(lambda: any(n.endswith(".lpr") for n in self.spool_files())
                            or p.poll() is not None)
            names = [n for n in self.spool_files() if n.endswith(".lpr")]
            time.sleep((i % 4) * 0.015)
            c = self.run_shell('lpr cancel "$1"', names[0]) if names else None
            out, err = p.communicate(timeout=10)
            self.assertIn(p.returncode, (0, 3), err)
            if p.returncode == 0:
                self.assertIn(b"accepted", out)
                self.assertEqual((self.fake / "received").read_bytes(), self.payload)
                self.assertTrue((self.fake / "done").exists())
            else:
                self.assertIn(b"cancelled", err)
                self.assertNotIn(b"accepted", out)
            if c is not None:
                self.assertIn(c.returncode, (0, 1), c.stderr)
            if (self.fake / "pid.json").exists():
                self.assertFalse(alive(json.loads((self.fake / "pid.json").read_text())))
            self.assertEqual(self.spool_files(), [])
            outcomes[p.returncode] = outcomes.get(p.returncode, 0) + 1
        print(f"\ncancel race outcomes: {outcomes}", file=sys.stderr)


class StaleAndForged(LprFixture):
    def forge(self, job, ctl="none"):
        self.spool.mkdir(mode=0o700, exist_ok=True)
        (self.spool / f"{job}.lpr").write_bytes(b"forged\n")
        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: (victim.kill(), victim.wait()))
        (self.spool / f"{job}.lpr.pid").write_text(f"{victim.pid}\n")
        if ctl == "file":
            (self.spool / f"{job}.ctl").write_text(f"{victim.pid}\n")
        elif ctl == "fifo":
            os.mkfifo(self.spool / f"{job}.ctl", 0o600)
        return victim

    def test_forged_pid_metadata_is_never_signalled(self):
        for i, ctl in enumerate(("none", "file", "fifo")):
            with self.subTest(ctl=ctl):
                job = f"{i:016x}"
                victim = self.forge(job, ctl)
                listing = self.run_shell('lpr list -l')
                self.assertIn(f"{job} stale 7\n".encode(), listing.stdout)
                r = self.run_shell('lpr cancel "$1"', job)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(b"removed stale job", r.stdout)
                time.sleep(0.05)
                self.assertIsNone(victim.poll())
                self.assertEqual(self.spool_files(), [])

    def test_symlinked_control_fifo_is_not_followed(self):
        job = "00000000000000aa"
        self.forge(job)
        outside = self.dir / "outside.fifo"
        os.mkfifo(outside)
        reader = os.open(outside, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        (self.spool / f"{job}.ctl").symlink_to(outside)
        r = self.run_shell('lpr cancel "$1"', job)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(os.read(reader, 16), b"")   # no writer ever sent a byte

    def test_invalid_ids_are_rejected(self):
        self.spool.mkdir(mode=0o700)
        for bad in ("../x", "/etc/passwd", "abc", "0123456789ABCDEF", "0123456789abcdef0", ""):
            with self.subTest(bad=bad):
                self.assertEqual(self.run_shell('lpr cancel "$1"', bad).returncode, 2)
        self.assertEqual(self.run_shell('lpr cancel 0123456789abcdef').returncode, 1)

    def test_killed_submitter_leaves_stale_job_and_orphan_is_untouched(self):
        p = self.spawn('lpr submit "$1"', self.input, env=self.env | {"LPR_FAKE_MODE": "hang"})
        pid = self.wait_ready(p)
        job = self.info()["argv"][0]
        p.kill()
        p.wait()
        p.stdout.close()   # the orphaned backend still holds the write ends
        p.stderr.close()
        listing = self.run_shell('lpr list -l')
        self.assertEqual(listing.stdout.decode(), f"{job} stale {len(self.payload)}\n")
        r = self.run_shell('lpr cancel "$1"', job)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"nothing signalled", r.stdout)
        self.assertTrue(alive(pid), "cancel signalled a process it does not own")
        self.assertEqual(self.spool_files(), [])
        os.kill(pid, signal.SIGKILL)   # the orphan is this test's to clean up


class ShellState(LprFixture):
    def test_repeat_submissions_keep_shell_state(self):
        script = r'''
        status() { local l; st=; while read -r l; do case $l in SigBlk:*|SigIgn:*|SigCgt:*) st+="$l;";; esac; done < /proc/self/status; }
        exec 9>"$2"
        { exit 7; } & bg=$!
        trap -p > "$3"   # trap -p itself installs handlers, so it precedes the snapshot
        before_fd=(/proc/self/fd/*); status; before=$st
        for ((i = 0; i < 30; i++)); do lpr submit "$1" > /dev/null || exit 9; done
        LPR_FAKE_MODE=fail; for ((i = 0; i < 5; i++)); do lpr submit "$1" >/dev/null 2>&1; [[ $? == 1 ]] || exit 10; done
        after_fd=(/proc/self/fd/*); status; after=$st
        wait "$bg"; echo "bg=$?"
        [[ ${#before_fd[@]} == "${#after_fd[@]}" ]] || { echo "fd leak ${before_fd[*]} / ${after_fd[*]}"; exit 11; }
        [[ $before == "$after" && $before == *SigCgt* ]] || { echo "signal state: $before / $after"; exit 12; }
        trap -p > "$4"; echo ok
        '''
        r = self.run_shell(script, self.input, self.dir / "fd9", self.dir / "t1", self.dir / "t2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout, b"bg=7\nok\n")
        self.assertEqual((self.dir / "t1").read_bytes(), (self.dir / "t2").read_bytes())
        self.assertEqual(self.spool_files(), [])

    def test_repeat_submissions_have_unique_ids(self):
        r = self.run_shell('for ((i = 0; i < 20; i++)); do lpr submit "$1" || exit; done', self.input)
        self.assertEqual(r.returncode, 0, r.stderr)
        ids = [l.split()[2] for l in r.stdout.decode().splitlines() if l.startswith("lpr: accepted")]
        self.assertEqual(len(ids), 20)
        self.assertEqual(len(set(ids)), 20)

    def test_output_failures(self):
        r = self.run_shell('lpr submit "$1" > /dev/full', self.input)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"write error on stdout", r.stderr)
        self.assertFalse((self.fake / "info.json").exists())
        self.assertEqual(self.spool_files(), [])
        self.spool.mkdir(exist_ok=True)
        (self.spool / "0123456789abcdef.lpr").write_bytes(b"x")
        self.assertEqual(self.run_shell('lpr list > /dev/full').returncode, 1)
        self.assertEqual(self.run_shell('lpr list -l > /dev/full').returncode, 1)
        self.assertEqual(self.run_shell('lpr list -x').returncode, 2)

    def test_list_keeps_v1_format_and_missing_spool(self):
        r = self.run_shell('lpr list')
        self.assertEqual((r.returncode, r.stdout), (0, b""))
        self.spool.mkdir()
        (self.spool / "0123456789abcdef.lpr").write_bytes(b"x")
        (self.spool / "notes.txt").write_bytes(b"x")
        r = self.run_shell('lpr list')
        self.assertEqual(r.stdout.decode(), f"{self.spool}/0123456789abcdef.lpr\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
