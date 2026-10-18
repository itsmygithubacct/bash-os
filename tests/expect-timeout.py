#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Expect's deadline covers the entire wait, including continuously arriving bytes."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'out/bash').resolve())


class ExpectTimeout(unittest.TestCase):
    def shell(self, script, chunks=(), interval=0.05, hold=0):
        env = {**os.environ, 'LC_ALL': 'C'}
        env.pop('BASH_ENV', None)
        env.pop('ENV', None)
        script = 'expect log_user off; ' + script
        if module := os.environ.get('EXPECT_TEST_LOADABLE'):
            script = 'enable -f ' + shlex.quote(module) + ' expect || exit; ' + script
        if preload := os.environ.get('EXPECT_TEST_ASAN_LIB'):
            env.update(LD_PRELOAD=preload, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        reader, writer = os.pipe()
        stopped = threading.Event()

        def feed():
            try:
                for chunk in chunks:
                    os.write(writer, chunk)
                    if stopped.wait(interval):
                        return
                stopped.wait(hold)
            except BrokenPipeError:
                pass
            finally:
                os.close(writer)

        try:
            process = subprocess.Popen([BINARY, '--noprofile', '--norc', '-c',
                                        'PATH=; ' + script],
                                       env=env, stdin=reader, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
        except BaseException:
            os.close(writer)
            raise
        finally:
            os.close(reader)
        feeder = threading.Thread(target=feed)
        feeder.start()
        try:
            stdout, stderr = process.communicate(timeout=8)
        finally:
            stopped.set()
            if process.poll() is None:
                process.kill()
                process.communicate()
            feeder.join(timeout=2)
        self.assertNotIn('AddressSanitizer', stderr)
        self.assertNotIn('runtime error:', stderr)
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def test_continuous_output_does_not_extend_timeout(self):
        for command in ('expect expect 0 NEVER -t 1',
                        'expect expect-alt 0 NEVER ALSO_NEVER -t 1',
                        'expect eof 0 -t 1'):
            with self.subTest(command=command):
                # Before the fix each chunk reset the timeout, so these waits
                # incorrectly returned EOF after the three-second stream.
                result = self.shell(command, [b'tick\n'] * 60)
                self.assertEqual(result.returncode, 1, result)

    def test_matches_can_span_reads_before_deadline(self):
        for command, wanted in [
            ('expect expect 0 READY -t 2 -V match && printf "%s" "$match"', 'READY'),
            ('expect expect-alt 0 NEVER READY -t 2 -V which -V match && '
             'printf "%s:%s" "$which" "$match"', '1:READY'),
        ]:
            with self.subTest(command=command):
                result = self.shell(command, [b'RE', b'AD', b'Y'])
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stdout, wanted)

    def test_eof_and_buffered_zero_timeout(self):
        result = self.shell('expect eof 0 -t 2', [b'finished\n'])
        self.assertEqual(result.returncode, 0, result)
        result = self.shell('expect expect 0 READY -t 2 && '
                            'expect expect 0 READY -t 0 && '
                            'expect expect-alt 0 NEVER READY -t 0 && '
                            'printf "buffered matches passed\\n"; '
                            'expect expect 0 MISSING -t 0', [b'READY\n'])
        self.assertEqual(result.returncode, 1, result)
        self.assertEqual(result.stdout, 'buffered matches passed\n')
        for command in ('expect expect 0 MISSING -t 2',
                        'expect expect-alt 0 MISSING ABSENT -t 2'):
            result = self.shell(command)
            self.assertEqual(result.returncode, 2, result)

    def test_zero_timeout_checks_immediately_readable_input(self):
        for command in ('expect expect 0 READY -t 0 -V match',
                        'expect expect-alt 0 NEVER READY -t 0 -V which -V match'):
            with self.subTest(command=command):
                # The here-string is populated before expect starts. More than
                # one read is needed to reach the match in the kernel buffer.
                result = self.shell('printf -v payload "%600sREADY" ""; ' +
                                    command + ' <<< "$payload" && printf "%s" "$match"')
                self.assertEqual(result.returncode, 0, result)
                self.assertEqual(result.stdout, 'READY')
        result = self.shell('expect eof 0 -t 0 </dev/null')
        self.assertEqual(result.returncode, 0, result)
        result = self.shell('expect expect 0 MISSING -t 0', hold=3)
        self.assertEqual(result.returncode, 1, result)

    def test_invalid_timeout_is_usage_error(self):
        for command in ('expect expect 0 NEVER', 'expect expect-alt 0 NEVER', 'expect eof 0'):
            for value in ('', 'x', '1x', '-1', '2147483648', '999999999999999999999999999'):
                with self.subTest(command=command, value=value):
                    result = self.shell(command + ' -t ' + shlex.quote(value))
                    self.assertEqual(result.returncode, 2, result)
                    self.assertIn('invalid timeout', result.stderr)
            result = self.shell(command + ' -t')
            self.assertEqual(result.returncode, 2, result)


if __name__ == '__main__':
    unittest.main()
