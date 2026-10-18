#!/usr/bin/env python3
"""Account parsing checks confined to private passwd files and fake providers."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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


if __name__ == "__main__":
    unittest.main()
