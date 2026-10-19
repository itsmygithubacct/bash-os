#!/usr/bin/env python3
"""Exercise crypto handle cleanup with synthetic, non-credential input."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = dict(os.environ)
if ENV.get("CRYPTO_STATE_LOAD_ENV"):
    ENV["BASH_ENV"] = ENV["CRYPTO_STATE_LOAD_ENV"]
if ENV.get("CRYPTO_STATE_ASAN_LIB"):
    ENV["LD_PRELOAD"] = ENV["CRYPTO_STATE_ASAN_LIB"]
    ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    ENV["UBSAN_OPTIONS"] = "halt_on_error=1"


def shell(script, *args):
    result = subprocess.run([BINARY, "-c", "PATH=; " + script, "crypto-state", *map(str, args)],
                            env=ENV, capture_output=True, timeout=8)
    if b"runtime error:" in result.stderr or b"ERROR: AddressSanitizer" in result.stderr:
        raise AssertionError(result.stderr)
    return result


class StateTests(unittest.TestCase):
    def test_failed_read_binding_does_not_exhaust_pool(self):
        result = shell('readonly handle=original; bad=0; for ((i=0;i<40;i++)); do '
                       'crypto secret-read -h handle <<<fixture; [[ $? == 1 ]] || bad=1; done; '
                       '[[ $bad == 0 && $handle == original ]] || exit 8; '
                       'crypto secret-read -h fresh <<<fixture && '
                       '[[ $(crypto secret-len "$fresh") == 7 ]] && crypto secret-scrub "$fresh"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_derived_binding_preserves_source_and_pool(self):
        result = shell('crypto secret-read -h source <<<fixture || exit; readonly derived=original; bad=0; '
                       'for ((i=0;i<40;i++)); do crypto secret-hkdf "$source" -L 16 -h derived; '
                       '[[ $? == 1 ]] || bad=1; done; [[ $bad == 0 && $derived == original ]] || exit 8; '
                       'crypto secret-hkdf "$source" -L 16 -h fresh && '
                       '[[ $(crypto secret-len "$fresh") == 16 && $(crypto secret-len "$source") == 7 ]] && '
                       'crypto secret-scrub "$fresh" && crypto secret-scrub "$source"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_typed_or_invalid_outputs_fail_without_ending_shell(self):
        for declaration, name in (("declare -i result=0", "result"),
                                  ("declare -a result=()", "result"),
                                  ("declare -A result=()", "result"),
                                  ("readonly target=original; declare -n result=target", "result"),
                                  (":", "RANDOM"), (":", "1invalid")):
            with self.subTest(declaration=declaration, name=name):
                result = shell(declaration + '; crypto secret-read -h "$1" <<<fixture; '
                               'rc=$?; printf "continued=%s\\n" "$rc"', name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"continued=1\n")

    def test_writable_nameref_output_works(self):
        result = shell('declare -n reference=target; crypto secret-read -h reference <<<fixture && '
                       '[[ $(crypto secret-len "$target") == 7 ]] && crypto secret-scrub "$target"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_oversized_generation_does_not_alias_a_live_handle(self):
        result = shell('crypto secret-read -h handle <<<fixture || exit; '
                       'index=${handle%%:*}; generation=${handle#*:}; '
                       'for bad in "$index:$((generation+4294967296))" "$index:+$generation" '
                       '"$index: $generation" "$index:99999999999999999999999"; do '
                       'crypto secret-scrub "$bad" && exit 8; done; '
                       '[[ $(crypto secret-len "$handle") == 7 ]] && crypto secret-scrub "$handle"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pool_capacity_and_generation_after_reuse(self):
        result = shell('handles=(); for ((i=0;i<16;i++)); do '
                       'crypto secret-read -h handle <<<fixture || exit; handles+=("$handle"); done; '
                       'crypto secret-read -h extra <<<fixture && exit 8; '
                       'old=${handles[0]}; for handle in "${handles[@]}"; do crypto secret-scrub "$handle" || exit; done; '
                       'crypto secret-read -h fresh <<<fixture || exit; crypto secret-len "$old" && exit 9; '
                       '[[ $(crypto secret-len "$fresh") == 7 ]] && crypto secret-scrub "$fresh"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_input_does_not_leave_a_handle(self):
        result = shell('for ((i=0;i<20;i++)); do crypto secret-read -h failed <<<"$1" && exit 8; done; '
                       'crypto secret-read -h fresh <<<fixture && crypto secret-scrub "$fresh"', 'x' * 4096)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_closed_and_reused_handles_across_consumers(self):
        result = shell('crypto secret-read -h live <<<fixture || exit; '
                       'old=$live; crypto secret-scrub "$old" || exit; '
                       'crypto secret-read -h live <<<fixture || exit; '
                       'for bad in "" : 0:0 16:1 -1:1 0:-1 0:1x 0:1:1 "$old"; do '
                       'for op in secret-len secret-scrub; do crypto "$op" "$bad" && exit 8; done; '
                       'crypto secret-verify "$bad" "$live" && exit 9; '
                       'crypto secret-verify "$live" "$bad" && exit 10; '
                       'out=unchanged; crypto secret-hkdf "$bad" -h out && exit 11; '
                       '[[ $out == unchanged ]] || exit 12; '
                       'crypto secret-pwhash "$bad" -Q -t 1 -m 8 && exit 13; '
                       'crypto secret-pwverify "$bad" invalid && exit 14; done; '
                       'crypto secret-verify "$live" "$live" && crypto secret-scrub "$live"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_repeated_derivation_and_scrub_preserves_source(self):
        result = shell('crypto secret-read -h source <<<fixture || exit; '
                       'for ((i=0;i<100;i++)); do '
                       'crypto secret-hkdf "$source" -L 32 -h derived || exit; '
                       'crypto secret-scrub "$derived" || exit; '
                       'crypto secret-len "$derived" && exit 8; done; '
                       '[[ $(crypto secret-len "$source") == 7 ]] && crypto secret-scrub "$source"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_handle_output_failures_preserve_live_secret(self):
        result = shell('crypto secret-read -h handle <<<fixture || exit; '
                       'crypto secret-len "$handle" >/dev/full && exit 8; '
                       'crypto secret-pwhash "$handle" -Q -t 1 -m 8 -L 16 >/dev/full && exit 9; '
                       '[[ $(crypto secret-len "$handle") == 7 ]] && crypto secret-scrub "$handle"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_derived_text_binding_reports_readonly_failure(self):
        result = shell('readonly output=original; crypto argon2id -Q -p fixture -s 0001020304050607 '
                       '-t 1 -m 8 -l 1 -L 16 -x -o output; rc=$?; [[ $rc == 1 && $output == original ]]')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
