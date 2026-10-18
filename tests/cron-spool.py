#!/usr/bin/env python3
"""Scheduler file handling in a private spool; no daemon or real jobs run."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = dict(os.environ)
if ENV.get("SPOOL_LOAD_ENV"):
    ENV["BASH_ENV"] = ENV["SPOOL_LOAD_ENV"]
if ENV.get("SPOOL_ASAN_LIB"):
    ENV["LD_PRELOAD"] = ENV["SPOOL_ASAN_LIB"]
    ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    ENV["UBSAN_OPTIONS"] = "halt_on_error=1"


class SpoolFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.spool = self.directory / "spool"
        self.tabs = self.spool / "tabs"
        self.tabs.mkdir(parents=True)
        self.target = self.tabs / "fixture"
        self.target.write_bytes(b"original\n")
        self.source = self.directory / "source"
        self.source.write_bytes(b"* * * * * echo private-fixture\n")
        self.editor = self.directory / "editor"
        self.editor.write_text(f"#!{sys.executable}\n")
        self.editor.chmod(0o700)
        self.env = ENV | {"BASHCRON_SPOOL_DIR": str(self.spool), "USER": "fixture",
                          "VISUAL": str(self.editor), "EDITOR": str(self.editor)}

    def run_shell(self, script, *args):
        result = subprocess.run([BINARY, "-c", "PATH=; " + script, "cron-spool", *map(str, args)],
                                env=self.env, capture_output=True, timeout=8)
        if b"runtime error:" in result.stderr or b"ERROR: AddressSanitizer" in result.stderr:
            raise AssertionError(result.stderr)
        return result


class CrontabTests(SpoolFixture):
    def test_predictable_temp_names_cannot_overwrite_or_remove_existing_files(self):
        victim = self.directory / "victim"
        for operation in ("tmp", "edit"):
            for symlink in (False, True):
                with self.subTest(operation=operation, symlink=symlink):
                    victim.write_bytes(b"preserve victim")
                    self.target.write_bytes(b"original\n")
                    argument = str(self.source) if operation == "tmp" else "-e"
                    process = subprocess.Popen(
                        [BINARY, "-c", 'PATH=; read -r; crontab "$1"', "cron-spool", argument],
                        env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stale = self.tabs / f"fixture.{operation}.{process.pid}"
                    try:
                        if symlink:
                            stale.symlink_to(victim)
                        else:
                            stale.write_bytes(b"preserve stale file")
                        _, error = process.communicate(b"go\n", timeout=8)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate(timeout=3)
                    self.assertEqual(process.returncode, 0, error)
                    self.assertEqual(victim.read_bytes(), b"preserve victim")
                    self.assertTrue(stale.exists())
                    if not symlink:
                        self.assertEqual(stale.read_bytes(), b"preserve stale file")
                    self.assertFalse(self.target.is_symlink())
                    expected = self.source.read_bytes() if operation == "tmp" else b"original\n"
                    self.assertEqual(self.target.read_bytes(), expected)
                    stale.unlink()

    def test_edit_read_error_keeps_existing_table_and_does_not_run_editor(self):
        self.target.unlink()
        self.target.symlink_to("fixture")
        marker = self.directory / "editor-ran"
        self.editor.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                               f"Path({str(marker)!r}).write_text('ran')\n")
        result = self.run_shell("crontab -e")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(self.target.is_symlink())
        self.assertFalse(marker.exists())
        self.assertEqual(list(self.tabs.iterdir()), [self.target])

    def test_failed_editor_keeps_original_and_cleans_its_temp(self):
        self.editor.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(7)\n")
        result = self.run_shell("crontab -e")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.target.read_bytes(), b"original\n")
        self.assertEqual(list(self.tabs.iterdir()), [self.target])

    def test_editor_symlink_is_not_published(self):
        victim = self.directory / "victim"
        victim.write_bytes(b"preserve victim")
        self.editor.write_text(f"#!{sys.executable}\nimport os, sys\n"
                               f"os.unlink(sys.argv[1]); os.symlink({str(victim)!r}, sys.argv[1])\n")
        result = self.run_shell("crontab -e")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.target.read_bytes(), b"original\n")
        self.assertFalse(self.target.is_symlink())
        self.assertEqual(victim.read_bytes(), b"preserve victim")
        self.assertEqual(list(self.tabs.iterdir()), [self.target])

    def test_replacement_from_editor_is_private(self):
        self.editor.write_text(f"#!{sys.executable}\nimport os, sys\nfrom pathlib import Path\n"
                               "os.umask(0); p=Path(sys.argv[1]); p.unlink(); p.write_text('edited\\n')\n")
        result = self.run_shell("crontab -e")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), b"edited\n")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)

    def test_copy_respects_restrictive_umask(self):
        result = self.run_shell('umask 0777; crontab "$1"', self.source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0)

    def test_read_and_output_errors_preserve_shell_state(self):
        result = self.run_shell('before=(/proc/self/fd/*); for ((i=0;i<10;i++)); do '
                                'crontab "$1" && exit 8; crontab -l >/dev/full && exit 9; done; '
                                'after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]] && crontab -l',
                                self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"original\n")
        self.assertEqual(list(self.tabs.iterdir()), [self.target])

    def test_editor_calls_preserve_jobs_traps_and_descriptors(self):
        result = self.run_shell('trap : CHLD; saved=$(trap -p CHLD); before=(/proc/self/fd/*); '
                                '(exit 23) & job=$!; for ((i=0;i<8;i++)); do crontab -e || exit; done; '
                                'wait "$job"; [[ $? == 23 ]] || exit 8; after=(/proc/self/fd/*); '
                                '[[ ${#before[@]} == ${#after[@]} && $(trap -p CHLD) == "$saved" ]]')
        self.assertEqual(result.returncode, 0, result.stderr)


class AtTests(SpoolFixture):
    def test_multiple_jobs_from_one_shell_keep_every_script(self):
        result = self.run_shell('at @2000000000 <<<"echo first" && '
                                'at @2000000000 <<<"echo second" && '
                                'at @2000000001 <<<"echo third"')
        self.assertEqual(result.returncode, 0, result.stderr)
        jobs = sorted((self.spool / "atjobs").glob("*.job"))
        self.assertEqual(len(jobs), 3)
        self.assertEqual({job.read_bytes() for job in jobs}, {
            b"# run_at=2000000000\necho first\n", b"# run_at=2000000000\necho second\n",
            b"# run_at=2000000001\necho third\n"})
        self.assertEqual(len(list((self.spool / "atjobs").iterdir())), 3)
        self.assertEqual(len(result.stdout.splitlines()), 3)
        for job in jobs:
            self.assertEqual(stat.S_IMODE(job.stat().st_mode) & 0o077, 0)
            dumped = self.run_shell('at -c "$1"', job.stem)
            self.assertEqual(dumped.returncode, 0, dumped.stderr)
            self.assertEqual(dumped.stdout, job.read_bytes().split(b"\n", 1)[1])

    def test_existing_pid_job_remains_untouched(self):
        jobs = self.spool / "atjobs"
        jobs.mkdir()
        process = subprocess.Popen(
            [BINARY, "-c", 'PATH=; read -r; at @2000000000 <<<"echo fresh"', "cron-spool"],
            env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        existing = jobs / f"2000000000.{process.pid}.job"
        try:
            existing.write_bytes(b"existing job\n")
            _, error = process.communicate(b"go\n", timeout=8)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, error)
        self.assertEqual(existing.read_bytes(), b"existing job\n")
        self.assertEqual(len(list(jobs.glob("*.job"))), 2)

    def test_time_overflow_and_partial_numbers_are_rejected(self):
        for value in ("@99999999999999999999999", "99999999999999999999999",
                      "+9223372036854775807d", "+9223372036854775807s", "+-1h",
                      "+1mextra", "4294967296:00", "12:4294967296", "12:00extra"):
            with self.subTest(value=value):
                result = self.run_shell('at "$1" <<<"never queued"', value)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
        self.assertEqual(list(self.spool.glob("atjobs/*")), [])

    def test_input_error_does_not_poison_the_next_invocation(self):
        result = self.run_shell('at @2000000000 <"$1" && exit 8; '
                                'at @2000000001 <<<"echo after-error"', self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        jobs = list((self.spool / "atjobs").glob("*.job"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].read_bytes(), b"# run_at=2000000001\necho after-error\n")

    def test_dump_is_binary_exact_and_reports_output_errors(self):
        jobs = self.spool / "atjobs"
        jobs.mkdir()
        script = b"echo a\0b\n"
        (jobs / "fixture.job").write_bytes(b"# run_at=2000000000\n" + script)
        result = self.run_shell('for ((i=0;i<4;i++)); do at -c fixture >/dev/full && exit 8; done; at -c fixture')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, script)

    def test_schedule_respects_restrictive_umask(self):
        (self.spool / "atjobs").mkdir()
        result = self.run_shell('umask 0777; at @2000000000 <<<"echo private"')
        self.assertEqual(result.returncode, 0, result.stderr)
        jobs = list((self.spool / "atjobs").glob("*.job"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(stat.S_IMODE(jobs[0].stat().st_mode), 0)


if __name__ == "__main__":
    unittest.main()
