#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Captured clear bytes, host comparisons, private PTYs and shell recovery.

Usage: python3 tests/clear-check.py [BINARY] [--load-dir DIR]
DIR contains independently built bashclear.so and clear.so; each invocation
loads only the command it exercises. No output is sent to the caller's terminal.
"""
import argparse
import fcntl
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import tempfile
import termios
import tty
import unittest


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', nargs='?', default='out/bash')
parser.add_argument('--load-dir', type=Path)
args = parser.parse_args()
BINARY = str(Path(args.binary).resolve())
HOST = shutil.which('clear', path='/usr/bin:/bin')
COMMANDS = ('bashclear', 'clear')
GROUPS = (
    ('xterm xterm-256color alacritty foot foot-direct', b'\x1b[H\x1b[2J', True),
    ('xterm-color xterm-kitty screen.xterm-256color rxvt rxvt-unicode '
     'rxvt-unicode-256color st st-256color', b'\x1b[H\x1b[2J', False),
    ('screen screen-256color vt100 vt102 vt220 ansi', b'\x1b[H\x1b[J', False),
    ('tmux tmux-256color linux', b'\x1b[H\x1b[J', True),
)
EXPECTED = {name: (screen, e3) for names, screen, e3 in GROUPS for name in names.split()}
REQUIRED_HOST = {'xterm', 'xterm-256color', 'screen', 'linux', 'vt100', 'ansi'}


class ClearChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HOST:
            raise RuntimeError('host clear is required for terminal comparisons')
        cls.scratch = tempfile.TemporaryDirectory(prefix='bashclear-check-')
        cls.env = {'HOME': cls.scratch.name, 'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}
        if args.load_dir:
            cls.env['BASHCLEAR_TEST_LOAD_DIR'] = str(args.load_dir.resolve())
        cls.host_comparisons = 0
        cls.pty_comparisons = 0
        cls.missing_host = set()
        cls.padding = {}

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()
        print(f'clear-check: {cls.host_comparisons} host byte comparisons; '
              f'{cls.pty_comparisons} private PTY comparisons')
        if cls.missing_host:
            print('Host terminfo entries unavailable (fixed-byte checks still run): '
                  + ', '.join(sorted(cls.missing_host)))
        print('Host VT padding bytes omitted by bashclear:', cls.padding)

    def invocation(self, name, options=(), script='"$@"', term='xterm'):
        env = dict(self.env)
        prefix = 'PATH=; '
        if term is None:
            prefix += 'unset TERM; '
        else:
            env['TERM'] = term
        if args.load_dir:
            prefix += 'enable -f "$BASHCLEAR_TEST_LOAD_DIR/$1.so" "$1" || exit 99; '
        return [BINARY, '--noprofile', '--norc', '-c', prefix + script,
                'clear-check', name, *options], env

    def run_builtin(self, name, options=(), script='"$@"', term='xterm', **kwargs):
        command, env = self.invocation(name, options, script, term)
        return subprocess.run(command, env=env, capture_output=True, timeout=10, **kwargs)

    def run_host(self, term, options=()):
        env = dict(self.env)
        if term is not None:
            env['TERM'] = term
        return subprocess.run([HOST, *options], env=env, capture_output=True, timeout=10)

    def test_registration_and_help(self):
        for name in COMMANDS:
            with self.subTest(name=name):
                p = self.run_builtin(name, script='type -t "$1"; help "$1"')
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertTrue(p.stdout.startswith(b'builtin\n'))
                self.assertIn(b'[-x] [-T TERM]', p.stdout)
                for option in ('--help', '-V', '--version'):
                    p = self.run_builtin(name, [option], term=None)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertNotIn(b'\x1b', p.stdout)
                    self.assertTrue(p.stdout)
                    self.assertEqual(p.stderr, b'')

    def test_terminal_bytes_and_host(self):
        for term, (screen, e3) in EXPECTED.items():
            for opts in ([], ['-x']):
                expected = screen + (b'\x1b[3J' if e3 and not opts else b'')
                host = self.run_host(term, opts)
                if host.returncode and term not in REQUIRED_HOST:
                    self.missing_host.add(term)
                else:
                    self.assertEqual((host.returncode, host.stdout, host.stderr),
                                     (0, expected, b''), (term, opts))
                    type(self).host_comparisons += 1
                for name in COMMANDS:
                    with self.subTest(name=name, term=term, options=opts):
                        p = self.run_builtin(name, opts, term=term)
                        self.assertEqual((p.returncode, p.stdout, p.stderr),
                                         (0, expected, b''))

    def test_options(self):
        for name in COMMANDS:
            for opts, term in ((['-T', 'linux'], 'linux'), (['-Txterm'], 'xterm'),
                               (['-Tscreen', '-Tlinux'], 'linux'), (['--'], 'xterm')):
                with self.subTest(name=name, options=opts):
                    p = self.run_builtin(name, opts)
                    host = self.run_host('xterm', opts)
                    self.assertEqual((p.returncode, p.stdout, p.stderr),
                                     (host.returncode, host.stdout, host.stderr))
            p = self.run_builtin(name, ['-xTlinux'], term='unsupported')
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, b'\x1b[H\x1b[J', b''))
            p = self.run_builtin(name, ['-Txterm'], term=None)
            self.assertEqual((p.returncode, p.stdout), (0, b'\x1b[H\x1b[2J\x1b[3J'))
            for opts in (['-T'], ['-z'], ['operand'], ['-'], ['--', 'operand'],
                         ['--unknown'], ['-x', 'operand']):
                with self.subTest(name=name, options=opts):
                    p = self.run_builtin(name, opts)
                    self.assertEqual((p.returncode, p.stdout), (1, b''))
                    self.assertTrue(p.stderr)
                    host = self.run_host('xterm', opts)
                    self.assertEqual((host.returncode, host.stdout), (1, b''))

    def test_terminal_errors(self):
        for name in COMMANDS:
            for term in (None, '', 'dumb', 'bashclear-unknown', 'xterm-made-up', '../xterm'):
                with self.subTest(name=name, term=term):
                    p = self.run_builtin(name, term=term)
                    host = self.run_host(term)
                    self.assertEqual((p.returncode, p.stdout), (1, b''))
                    self.assertEqual((host.returncode, host.stdout), (1, b''))
                    self.assertEqual(bool(p.stderr), term != 'dumb')
            p = self.run_builtin(name, ['-T', ''])
            self.assertEqual((p.returncode, p.stdout), (1, b''))

    def test_repeated_calls_input_and_shell_state(self):
        script = '''
cmd=$1
TERM=xterm; export -n TERM
OPTIND=7; IFS=:
trap ':' USR1
before=$(trap -p USR1)
for ((i=0; i<3; i++)); do "$cmd" -x || exit; done
TERM=linux "$cmd" || exit
[[ $TERM == xterm && $OPTIND == 7 && $IFS == : ]] || exit 90
[[ $(trap -p USR1) == "$before" ]] || exit 91
IFS= read -r line
printf '%s' "$line"
'''
        expected = b'\x1b[H\x1b[2J' * 3 + b'\x1b[H\x1b[J\x1b[3Jsentinel'
        for name in COMMANDS:
            p = self.run_builtin(name, script=script, input=b'sentinel\n')
            self.assertEqual((p.returncode, p.stdout, p.stderr), (0, expected, b''))

    def test_output_errors_and_recovery(self):
        self.assertTrue(Path('/dev/full').exists(), '/dev/full is required')
        script = '''
cmd=$1; shift
"$cmd" "$@" >/dev/full; a=$?
"$cmd" "$@" >&-; b=$?
printf 'status=%s,%s;' "$a" "$b"
"$cmd" -x
printf 'recovered'
'''
        for name in COMMANDS:
            for opts in ([], ['--help'], ['-V'], ['--version']):
                p = self.run_builtin(name, opts, script=script)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, b'status=1,1;\x1b[H\x1b[2Jrecovered')
                self.assertTrue(p.stderr)
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            try:
                cmd, env = self.invocation(name, script='trap "" PIPE; "$@"; '
                                           'rc=$?; printf "status=%s" "$rc" >&2')
                p = subprocess.run(cmd, env=env, stdout=write_fd, stderr=subprocess.PIPE,
                                   timeout=10)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(b'status=1', p.stderr)
            finally:
                os.close(write_fd)
        with open('/dev/full', 'wb', buffering=0) as full:
            host = subprocess.run([HOST, '-Txterm'], env=self.env, stdout=full,
                                  stderr=subprocess.PIPE, timeout=10)
        print(f'Host clear /dev/full status: {host.returncode}; bashclear requires 1')

    def pty_run(self, command, env):
        master, slave = pty.openpty()
        try:
            tty.setraw(slave)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            before = termios.tcgetattr(slave)
            p = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                               stdout=slave, stderr=subprocess.PIPE, timeout=10)
            data = b''
            while select.select([master], [], [], 0.05)[0]:
                data += os.read(master, 65536)
                self.assertLess(len(data), 65536)
            self.assertEqual(termios.tcgetattr(slave), before)
            return p.returncode, data, p.stderr
        finally:
            os.close(master)
            os.close(slave)

    def test_private_ptys(self):
        for term in ('xterm', 'xterm-kitty', 'screen', 'tmux-256color', 'linux',
                     'vt100', 'vt102', 'ansi', 'dumb'):
            for opts in ([], ['-x']):
                host = self.pty_run([HOST, *opts], dict(self.env, TERM=term))
                if host[0] and term not in REQUIRED_HOST | {'dumb'}:
                    self.missing_host.add(term)
                    continue
                for name in COMMANDS:
                    with self.subTest(name=name, term=term, options=opts):
                        command, env = self.invocation(name, opts, term=term)
                        actual = self.pty_run(command, env)
                        if term in ('vt100', 'vt102'):
                            self.assertEqual((host[0], host[1].rstrip(b'\0'), host[2]), actual)
                            self.padding[term] = len(host[1]) - len(actual[1])
                        else:
                            self.assertEqual(actual, host)
                        type(self).pty_comparisons += 1


unittest.main(argv=['clear-check'], verbosity=2)
