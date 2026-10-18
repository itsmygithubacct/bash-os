#!/usr/bin/env python3
"""Account parsing checks confined to private passwd files and fake providers."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import signal
import time
import resource
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = dict(os.environ)
if ENV.get("USERDB_LOAD_ENV"):
    ENV["BASH_ENV"] = ENV["USERDB_LOAD_ENV"]
if ENV.get("USERDB_ASAN_LIB"):
    ENV["LD_PRELOAD"] = ENV["USERDB_ASAN_LIB"]
    ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    ENV["UBSAN_OPTIONS"] = "halt_on_error=1"


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.passwd = self.directory / "passwd"
        self.passwd.write_bytes(b"")
        self.config = self.directory / "providers"
        self.config.write_bytes(b"")
        self.env = ENV | {"BASHUSERDB_PASSWD": str(self.passwd), "BASHUSERDB_CONF": str(self.config)}

    def run_shell(self, script, *args):
        return subprocess.run([BINARY, "-c", "PATH=; " + script, "userdb-records", *map(str, args)],
                              env=self.env, capture_output=True, timeout=8)

    def provider(self, name, program):
        provider = self.directory / "provider"
        pidfile = self.directory / "provider-pid"
        provider.write_text(f"#!{sys.executable}\nimport os, sys, time\nfrom pathlib import Path\n"
                            f"Path({str(pidfile)!r}).write_text(str(os.getpid()))\n" + program)
        provider.chmod(0o700)
        self.config.write_text(f"provider {name} {provider}\n")

        def cleanup():
            # If a regression times out the shell, remove only our fixture.
            if pidfile.exists():
                pid = int(pidfile.read_text())
                try:
                    if str(provider).encode() in Path(f"/proc/{pid}/cmdline").read_bytes():
                        os.kill(pid, signal.SIGKILL)
                except (FileNotFoundError, ProcessLookupError):
                    pass
        self.addCleanup(cleanup)
        return provider, pidfile

    def lookup(self):
        return self.run_shell('userdb lookup fixture -V record && printf "%s" "$record"')

    def test_empty_fields_preserve_positions(self):
        for record in ("1234:5678::/fixture:/bin/false", "1234:5678:Name::/bin/false",
                       "1234:5678:Name:/fixture:", "1234:5678:::" ):
            for password in ("x", ""):
                with self.subTest(record=record, password=password):
                    self.passwd.write_text(f"fixture:{password}:{record}\n")
                    result = self.lookup()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.decode(), record)

    def test_invalid_ids_and_field_counts_are_rejected(self):
        for record in ("-1:1:Name:/fixture:/bin/false", "1:+2:Name:/fixture:/bin/false",
                       "1x:2:Name:/fixture:/bin/false", "1: 2:Name:/fixture:/bin/false",
                       ":2:Name:/fixture:/bin/false", "1::Name:/fixture:/bin/false",
                       "4294967295:2:Name:/fixture:/bin/false", "1:4294967296:Name:/fixture:/bin/false",
                       "99999999999999999999999:1:Name:/fixture:/bin/false",
                       "1:2:Name:/fixture:/bin/false:extra", "1:2:Name:/fixture"):
            with self.subTest(record=record):
                self.passwd.write_text(f"fixture:x:{record}\n")
                result = self.lookup()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_no_record_is_silently_truncated(self):
        prefix, suffix = "1234:5678:Name:/fixture:/", "shell"
        for length in (4095, 4096, 8192):
            with self.subTest(length=length):
                record = prefix + "x" * (length - len(prefix) - len(suffix)) + suffix
                self.passwd.write_text(f"fixture:x:{record}\n")
                result = self.lookup()
                self.assertEqual(result.returncode, 0 if length == 4095 else 1, result.stderr)
                self.assertEqual(result.stdout, record.encode() if length == 4095 else b"")

    def test_embedded_nul_is_not_a_record_terminator(self):
        self.passwd.write_bytes(b"fixture:x:1234:5678:Name:/fixture:/bin/false\0:extra\n")
        result = self.lookup()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_readonly_binding_reports_failure(self):
        self.passwd.write_text("fixture:x:1234:5678:Name:/fixture:/bin/false\n")
        result = self.run_shell('readonly record=original; userdb lookup fixture -V record; '
                                'rc=$?; [[ $rc == 1 && $record == original ]]')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_provider_records_obey_the_same_id_rules(self):
        provider = self.directory / "provider"
        record_file = self.directory / "record"
        provider.write_text(f"#!{sys.executable}\nfrom pathlib import Path\n"
                            f"print(Path({str(record_file)!r}).read_text(), end='')\n")
        provider.chmod(0o700)
        self.config.write_text(f"provider fixture {provider}\n")
        for record, valid in (("1234:5678::/fixture:/bin/false", True),
                              ("1:-2:Name:/fixture:/bin/false", False),
                              ("+1:2:Name:/fixture:/bin/false", False)):
            with self.subTest(record=record):
                record_file.write_text(record + "\n")
                result = self.lookup()
                self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)
                self.assertEqual(result.stdout, record.encode() if valid else b"")

    def test_repeated_lookup_does_not_leak_descriptors(self):
        self.passwd.write_text("fixture:x:1234:5678::/fixture:/bin/false\n")
        result = self.run_shell('before=(/proc/self/fd/*); for ((i=0;i<50;i++)); do '
                                'userdb lookup fixture -V record || exit; done; '
                                'after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]]')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ldap_password_descriptor_survives_remapping(self):
        self.provider("ldap", "fd = int(os.environ['BASHUSERDB_VERIFY_FD'])\n"
                      "data = b''.join(iter(lambda: os.read(fd, 4096), b''))\n"
                      "sys.exit(0 if fd == 3 and data == b'fixture-password\\n' else 1)\n")
        for closed in ("", "exec 0<&-; ", "exec 1>&-; ", "exec 2>&-; ", "exec 0<&- 1>&- 2>&-; "):
            with self.subTest(closed=closed):
                result = self.run_shell(closed + 'userdb verify fixture fixture-password')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_provider_streams_drain_while_password_is_sent(self):
        self.provider("ldap", "os.write(1, b'output\\n' + b'o' * 200000)\n"
                      "os.write(2, b'diagnostic\\n' + b'e' * 200000)\n"
                      "data = b''.join(iter(lambda: os.read(3, 4096), b''))\n"
                      "sys.exit(0 if data == b'x' * 100000 + b'\\n' else 1)\n")
        result = self.run_shell('userdb verify fixture "$1"', "x" * 100000)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_early_provider_exit_does_not_signal_the_shell(self):
        self.provider("ldap", "sys.exit(1)\n")
        result = self.run_shell('userdb verify fixture "$1"; rc=$?; printf "continued=%s\\n" "$rc"',
                                "x" * 100000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"continued=1\n")

    def test_password_writer_obeys_provider_deadline(self):
        _, pidfile = self.provider("ldap", "time.sleep(30)\n")
        started = time.monotonic()
        result = self.run_shell('printf -v password "%1048576s" ""; '
                                'userdb verify fixture "$password"; rc=$?; printf "continued=%s\\n" "$rc"')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"continued=1\n")
        self.assertIn(b"timed out", result.stderr)
        self.assertLess(elapsed, 7.5)
        self.assertFalse(Path(f"/proc/{int(pidfile.read_text())}").exists(), "provider was not reaped")

    def test_truncated_or_nul_provider_records_are_rejected(self):
        record_file = self.directory / "record"
        self.provider("fixture", f"os.write(1, Path({str(record_file)!r}).read_bytes())\n")
        for record in (b"1234:5678::/fixture:/" + b'x' * 8192,
                       b"1234:5678::/fixture:/bin/false\0extra\n"):
            with self.subTest(length=len(record)):
                record_file.write_bytes(record)
                result = self.lookup()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b"")
        record_file.write_bytes(b"1234:5678::/fixture:/bin/false\n" + b'x' * 200000)
        result = self.lookup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"1234:5678::/fixture:/bin/false")

    def test_provider_calls_preserve_traps_jobs_and_descriptors(self):
        self.provider("ldap", "data = b''.join(iter(lambda: os.read(3, 4096), b''))\n"
                      "sys.exit(0 if data == b'fixture-password\\n' else 1)\n")
        result = self.run_shell('trap : PIPE; trap : CHLD; saved=$(trap -p PIPE CHLD); '
                                'before=(/proc/self/fd/*); (exit 23) & job=$!; '
                                'for ((i=0;i<12;i++)); do userdb verify fixture fixture-password || exit; done; '
                                'wait "$job"; [[ $? == 23 ]] || exit 8; '
                                'after=(/proc/self/fd/*); '
                                '[[ ${#before[@]} == ${#after[@]} && $(trap -p PIPE CHLD) == "$saved" ]]')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_pipe_setup_does_not_leak_descriptors(self):
        self.provider("ldap", "sys.exit(1)\n")
        result = self.run_shell('ulimit -n 8; before=(/proc/self/fd/*); '
                                'for ((i=0;i<10;i++)); do userdb verify fixture fixture-password && exit 9; done; '
                                'after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]]')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_continuous_output_cannot_hide_the_deadline(self):
        _, pidfile = self.provider("fixture", "while True:\n os.write(1, b'x' * 4096)\n")
        started = time.monotonic()
        result = self.lookup()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"timed out", result.stderr)
        self.assertLess(time.monotonic() - started, 7.5)
        self.assertFalse(Path(f"/proc/{int(pidfile.read_text())}").exists())

    def test_provider_descriptors_above_fd_setsize(self):
        if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 1120:
            self.skipTest("requires at least 1120 file descriptors")
        self.provider("fixture", "print('1234:5678::/fixture:/bin/false')\n")
        filler = self.directory / "filler"
        filler.write_bytes(b"")
        result = self.run_shell('exec 3<"$1" 4<"$1" 5<"$1" 6<"$1" 7<"$1" 8<"$1" 9<"$1"; '
                                'for ((i=0;i<1040;i++)); do exec {f}<"$1" || exit; done; '
                                '((f > 1024)) || exit 8; userdb lookup fixture -V record && '
                                '[[ $record == 1234:5678::/fixture:/bin/false ]]', filler)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_builtin_password_provider_uses_private_shadow_only(self):
        self.passwd.write_text("fixture:x:1234:5678::/fixture:/bin/false\n")
        shadow, group = self.directory / "shadow", self.directory / "group"
        shadow.write_text("fixture:!:20000:0:99999:7:::\n")
        group.write_text("fixture:x:5678:\n")
        self.env.update(PHCLIB_PASSWD=str(self.passwd), PHCLIB_SHADOW=str(shadow),
                        PHCLIB_GROUP=str(group), BPW_LOCK_DIR=str(self.directory / "locks"),
                        BASHPASSWD_KERNEL_SECRETS="0", PHCLIB_M="1024", PHCLIB_T="1")
        result = self.run_shell('[[ $(type -t passwd) == builtin ]] || exit 8; '
                                'passwd set-fd fixture 0 <<<fixture-password || exit; '
                                'userdb verify fixture fixture-password || exit; '
                                'userdb verify fixture wrong && exit 9; '
                                'userdb verify fixture "$1"; rc=$?; printf "continued=%s\\n" "$rc"',
                                "x" * 100000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"continued=1\n")


if __name__ == "__main__":
    unittest.main()
