#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Renice contract for util-linux 2.41.5 argument order.

The first argument is the priority. -n is absolute unless POSIXLY_CORRECT is
set. --priority is absolute and --relative is an increment. Success prints
"ID (kind) old priority OLD, new priority NEW". The fixture answers
getpriority with old priority 10 and records setpriority without calling it.
Owned-child cases run without the fixture. Build the fixture through the
campaign build gate. No compilation here.
Usage: python3 tests/sol-renice-check.py BINARY FIXTURE_SO
"""
import contextlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = str(Path(sys.argv.pop(1)).resolve())
FIXTURE = str(Path(sys.argv.pop(1)).resolve())
ENV = {k: v for k, v in os.environ.items()
       if k not in ('BASH_ENV', 'ENV', 'LD_PRELOAD', 'POSIXLY_CORRECT', 'SOL_RENICE_AUDIT')}
ENV.update(PATH='', LC_ALL='C')
PID = 'process ID'
PGRP = 'process group ID'
USER = 'user ID'
OLD = 10
TRY = b"Try 'renice --help' for more information.\n"


def success(who, kind, new, old=OLD):
    return f'{who} ({kind}) old priority {old}, new priority {new}\n'.encode()


@contextlib.contextmanager
def children(group=False):
    """A pipe holds owned children alive; fork only inside this single-thread test."""
    hold_r, hold_w = os.pipe()
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(hold_w)
            os.close(ready_r)
            os.setsid()
            base = os.getpriority(os.PRIO_PROCESS, 0)
            if base > 15:
                os._exit(90)
            os.setpriority(os.PRIO_PROCESS, 0, max(10, base))
            other = os.fork() if group else 0
            if other == 0 and group:
                os.close(ready_w)
                os.read(hold_r, 1)
                os._exit(0)
            os.write(ready_w, f'{os.getpid()} {other}\n'.encode())
            os.close(ready_w)
            os.read(hold_r, 1)
            if other:
                os.waitpid(other, 0)
            os._exit(0)
        except BaseException:
            os._exit(91)
    os.close(hold_r)
    os.close(ready_w)
    try:
        with os.fdopen(ready_r) as stream:
            values = stream.read().split()
        assert len(values) == 2, 'owned-child setup failed'
        yield [int(v) for v in values if v != '0']
    finally:
        os.close(hold_w)
        _, status = os.waitpid(pid, 0)
        assert status == 0, f'owned-child cleanup: {status}'


def independent_priority(pid):
    nice = os.getpriority(os.PRIO_PROCESS, pid)
    proc_nice = int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[16])
    assert nice == proc_nice, (nice, proc_nice)
    return nice


class Renice(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='sol-renice-')
        self.addCleanup(self.directory.cleanup)
        self.audit = Path(self.directory.name) / 'audit'
        self.parent_priority = independent_priority(os.getpid())
        # Prove interception with an impossible Linux PID before any zero-ID,
        # process-group or user selection. A static binary must fail safely.
        self.assertLess(int(Path('/proc/sys/kernel/pid_max').read_text()), 2147483647)
        probe = self.shell(args=(19, '-p', 2147483647))
        self.assertEqual((probe.returncode, probe.stdout, probe.stderr, self.calls()),
                         (0, success(2147483647, PID, 19), b'', [(0, 2147483647, 19)]),
                         'setpriority interception unavailable: ' + repr(probe.stderr))
        self.audit.unlink()

    def tearDown(self):
        self.assertEqual(independent_priority(os.getpid()), self.parent_priority)

    def shell(self, script='renice "$@"', args=(), fixture=True, extra_env=None):
        env = dict(ENV)
        if fixture:
            env.update(LD_PRELOAD=FIXTURE, SOL_RENICE_AUDIT=str(self.audit))
        if env.get('SOL_RENICE_ASAN_RUNTIME'):
            env['LD_PRELOAD'] = env['SOL_RENICE_ASAN_RUNTIME'] + (':' + env['LD_PRELOAD'] if 'LD_PRELOAD' in env else '')
        env.update(extra_env or {})
        if env.get('SOL_RENICE_MODULE'):
            script = 'enable -f "$SOL_RENICE_MODULE" renice || exit 99; ' + script
        if not fixture:
            script = r'''IFS= read -r parent_before < /proc/$$/stat
parent_before=${parent_before##*) }
read -r -a parent_fields <<< "$parent_before"
parent_nice=${parent_fields[16]}
trap 'rc=$?; IFS= read -r parent_after < /proc/$$/stat; parent_after=${parent_after##*) }; read -r -a parent_fields <<< "$parent_after"; [[ ${parent_fields[16]} == "$parent_nice" ]] || exit 98; exit "$rc"' EXIT
''' + script
        result = subprocess.run([BINARY, '--noprofile', '--norc', '-c', script, '_', *map(str, args)],
                                env=env, capture_output=True, timeout=10)
        self.assertNotIn(b'AddressSanitizer', result.stderr)
        self.assertNotIn(b'runtime error:', result.stderr)
        return result

    def calls(self):
        return [tuple(map(int, line.split())) for line in self.audit.read_text().splitlines()] if self.audit.exists() else []

    def test_absolute_pid_repeated_calls_empty_path_and_parent_unchanged(self):
        with children() as (pid,):
            start = independent_priority(pid)
            self.assertEqual(start, max(10, self.parent_priority))
            result = self.shell('[[ $(type -t renice) == builtin ]] || exit 9; '
                                'renice 16 -p "$1" || exit; renice -n 16 "$1" || exit; '
                                'renice 17 "$1"', (pid,), fixture=False,
                                extra_env={'POSIXLY_CORRECT': '1'})
            # POSIXLY_CORRECT makes -n relative: 16 + 16 clamps to 19, then 17 is absolute.
            expected = (success(pid, PID, 16, start)
                        + success(pid, PID, 19, 16)
                        + success(pid, PID, 17, 19))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
            self.assertEqual(independent_priority(pid), 17)

    def test_private_process_group(self):
        with children(group=True) as pids:
            start = independent_priority(pids[0])
            result = self.shell(args=(18, '-g', pids[0]), fixture=False)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, success(pids[0], PGRP, 18, start), b''))
            self.assertEqual([independent_priority(pid) for pid in pids], [18, 18])

    def test_real_range_clamps_and_partial_failure(self):
        with children() as (pid,):
            start = independent_priority(pid)
            result = self.shell(args=(2147483647, '-p', 'garbage', pid), fixture=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stderr, b'renice: bad process ID value: garbage\n')
            self.assertEqual(result.stdout, success(pid, PID, 19, start))
            self.assertEqual(independent_priority(pid), 19)

    def test_kernel_denies_negative_priority_and_leaves_child_unchanged(self):
        # This unprivileged test process has no CAP_SYS_NICE and RLIMIT_NICE=0.
        import resource
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NICE)[0], 0)
        caps = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines()
                    if line.startswith('CapEff:'))
        self.assertEqual(int(caps, 16) & (1 << 23), 0)
        with children() as (pid,):
            before = independent_priority(pid)
            result = self.shell(args=('-1', '-p', pid), fixture=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr,
                             f'renice: failed to set priority for {pid} (process ID): Permission denied\n'.encode())
            self.assertEqual(independent_priority(pid), before)

    def test_selector_construction_and_uid_resolution(self):
        result = self.shell(args=('12', '11', '-g', '22', '-u', 'renice-fixture-user',
                                  '4294967294', '0', '-p', '0', '-g', '0', '-p', '+33'))
        # 4294967294 narrows below zero and is not passed to setpriority.
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, b'renice: unknown user 4294967294\n')
        self.assertEqual(result.stdout, b''.join([
            success(11, PID, 12), success(22, PGRP, 12), success(4242, USER, 12),
            success(0, USER, 12), success(0, PID, 12), success(0, PGRP, 12),
            success(33, PID, 12)]))
        self.assertEqual(self.calls(), [(0, 11, 12), (1, 22, 12), (2, 4242, 12),
                                       (2, 0, 12), (0, 0, 12),
                                       (1, 0, 12), (0, 33, 12)])

    def test_selectors_before_priority_are_rejected(self):
        result = self.shell(args=('-g', '-n', '+19', '42', '-p', '43'))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr,
                         b"renice: invalid priority '-g'\n" + TRY)
        self.assertEqual(self.calls(), [])

    def test_priority_validation(self):
        rejected = (' ', '19 ', 'garbage', '19x', '1.5', 'nan', 'inf')
        for value in rejected:
            with self.subTest(value=value):
                result = self.shell(args=(value, '-p', '0'))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr,
                                 f"renice: invalid priority '{value}'\n".encode() + TRY)
                self.assertEqual(result.stdout, b'')
        # Fully consumed text is a priority. strtol's low 32 bits are kept.
        # Empty text is zero. A negative result still reaches setpriority.
        reached = (
            ('', 0, 0, 0),
            (' 19', 19, 0, 19),
            ('2147483648', -2147483648, 1, None),
            ('-2147483649', 2147483647, 0, 19),
            ('99999999999999999999999', -1, 1, None),
        )
        for value, passed, status, printed in reached:
            with self.subTest(value=value):
                result = self.shell(args=(value, '-p', '0'))
                self.assertEqual(result.returncode, status, result.stderr)
                if status == 0:
                    self.assertEqual(result.stdout, success(0, PID, printed))
                    self.assertEqual(result.stderr, b'')
                else:
                    self.assertEqual(result.stdout, b'')
                    self.assertIn(b'failed to set priority for 0 (process ID)', result.stderr)
        self.assertEqual(self.calls(), [(0, 0, passed) for _, passed, _, _ in reached])

    def test_priority_integer_boundaries_reach_setpriority_unchanged(self):
        values = (-2147483648, -20, -1, 0, 19, 20, 2147483647)
        for value in values:
            result = self.shell(args=('-n', value, '-p', 7))
            self.assertEqual(result.returncode, 1 if value < 0 else 0, result.stderr)
            if value < 0:
                self.assertEqual(result.stdout, b'')
            else:
                printed = 19 if value > 19 else value
                self.assertEqual(result.stdout, success(7, PID, printed))
        self.assertEqual(self.calls(), [(0, 7, v) for v in values])

    def test_usage_and_a_selector_without_an_id(self):
        for args in ((), ('-n',), ('19',)):
            with self.subTest(args=args):
                result = self.shell(args=args)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'renice: not enough arguments\n' + TRY)
        result = self.shell(args=('-p',))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"renice: invalid priority '-p'\n" + TRY)
        result = self.shell(args=('19', '-g'))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
        self.assertEqual(self.calls(), [])
        result = self.shell(args=('19', '0', '-n', '10', '0'))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, b'renice: bad process ID value: -n\n')
        self.assertEqual(result.stdout, success(0, PID, 19) + success(10, PID, 19) + success(0, PID, 19))
        result = self.shell(args=('-n', '19', '-n', '10', '0'))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, b'renice: bad process ID value: -n\n')
        self.assertEqual(self.calls(),
                         [(0, 0, 19), (0, 10, 19), (0, 0, 19), (0, 10, 19), (0, 0, 19)])

    def test_bad_targets_are_failures_and_do_not_stop_later_targets(self):
        rejected = (' ', '0 ', '-1', '1x', '2147483648',
                    '9223372036854775807', '999999999999999999999999')
        # Empty text, leading space before zero, and 2**32 all narrow to id 0.
        accepted_zero = ('', ' 0', '4294967296')
        for selector, kind in (('-p', PID), ('-g', PGRP)):
            for value in rejected:
                with self.subTest(selector=selector, value=value):
                    result = self.shell(args=(19, selector, value))
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr,
                                     f'renice: bad {kind} value: {value}\n'.encode())
            for value in accepted_zero:
                with self.subTest(selector=selector, value=repr(value)):
                    result = self.shell(args=(19, selector, value))
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, success(0, kind, 19), b''))
        for value in (' ', '0 ', '-1', '4294967295', '999999999999999999999999',
                      'unknown-fixture-user'):
            with self.subTest(uid=value):
                result = self.shell(args=(19, '-u', value))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, f'renice: unknown user {value}\n'.encode())
        for value in ('', ' 0', '4294967296'):
            with self.subTest(uid=repr(value)):
                result = self.shell(args=(19, '-u', value))
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, success(0, USER, 19), b''))
        self.audit.unlink()
        result = self.shell(args=(15, '-p', 'bad', 404404, 9, '-u', 'unknown-fixture-user',
                                  'renice-fixture-user', '-g', 8))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b'No such process', result.stderr)
        self.assertIn(b'renice: unknown user renice-fixture-user\n', result.stderr)
        self.assertEqual(result.stdout, success(9, PID, 15) + success(8, PGRP, 15))
        # The failed numeric user parse leaves endptr set, so the next resolved
        # name is rejected and does not reach setpriority.
        self.assertEqual(self.calls(), [(0, 404404, 15), (0, 9, 15), (1, 8, 15)])

    def test_denied_negative_priority_continues(self):
        result = self.shell(args=('-1', '-p', 12, 13))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.calls(), [(0, 12, -1), (0, 13, -1)])
        self.assertEqual(result.stderr.count(b'Permission denied'), 2)

    def test_repeated_calls_state_and_file_descriptors(self):
        result = self.shell('for ((i=0;i<200;i++)); do '
                            'renice 19 -u renice-fixture-user || exit; '
                            'renice 18 123 || exit; done; '
                            'set -- /proc/$$/fd/*; printf "%s\\n" "$#"')
        baseline = self.shell('set -- /proc/$$/fd/*; printf "%s\\n" "$#"')
        self.assertEqual((result.returncode, result.stdout), (0, baseline.stdout), result.stderr)
        self.assertEqual(self.calls(), [(2, 4242, 19), (0, 123, 18)] * 200)

    def test_failed_diagnostics_do_not_poison_later_calls(self):
        result = self.shell('renice -1 -p 12 2>/dev/full; a=$?; '
                            'renice 19 13; b=$?; printf "%s %s\\n" "$a" "$b"')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'1 0\n', b''))
        self.assertEqual(self.calls(), [(0, 12, -1), (0, 13, 19)])

    def test_closed_stdout_fails_the_success_line(self):
        result = self.shell('renice 19 -p 12 >&-; printf "%s\\n" "$?"')
        self.assertEqual((result.returncode, result.stdout), (0, b'1\n'), result.stderr)
        self.assertEqual(result.stderr, b'renice: write error: Bad file descriptor\n')
        self.assertEqual(self.calls(), [(0, 12, 19)])

    def test_help_version_and_priority_forms(self):
        help_result = self.shell(args=('-h',))
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn(b'Alter the priority of running processes.', help_result.stdout)
        self.assertIn(b'POSIXLY_CORRECT', help_result.stdout)
        self.assertEqual(help_result.stderr, b'')
        for flag in ('-v', '-V', '--version'):
            result = self.shell(args=(flag,))
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, b'renice from util-linux 2.41.5\n', b''))
        forms = (
            (('--priority', 5, '-p', 7), 5, 5),
            (('--relative', 5, '-p', 7), 15, 15),
            (('-n', 5, '-p', 7), 5, 5),
        )
        for args, passed, printed in forms:
            result = self.shell(args=args)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, success(7, PID, printed), b''))
        posix = self.shell(args=('-n', 5, '-p', 7), extra_env={'POSIXLY_CORRECT': '1'})
        self.assertEqual((posix.returncode, posix.stdout, posix.stderr),
                         (0, success(7, PID, 15), b''))
        self.assertEqual(self.calls(),
                         [(0, 7, passed) for _, passed, _ in forms] + [(0, 7, 15)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
