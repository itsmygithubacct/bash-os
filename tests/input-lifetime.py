#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the corrected input readers together, including through a QEMU wrapper.

This is a small cross-libc integration check. The dedicated command suites
cover the wider native option/regex/locale contracts.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
environment = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
commands = [
    ['head', '-n', '1'], ['sed', 's/alpha/OMEGA/g'], ['fold', '-w', '7'],
    ['expand', '-t', '4'], ['nl', '-ba'], ['pr', '-t'], ['tac'], ['bc'],
]
checks = 0


def run(argv, data=None):
    return subprocess.run(argv, input=data, capture_output=True,
                          env=environment, timeout=60)


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    left = root / 'left'
    left.write_bytes(b'first\nleftover\n' + b'padding\n' * 1000)
    empty = root / 'empty'
    empty.touch()
    fixtures = [b'', b'alpha\nbeta\n', b'alpha\nbeta', b'a\x00b\n',
                b'alpha\tbeta\n' * 8000]
    for command in commands:
        probe = run([binary, '-c', 'type -t "$1"', '_', command[0]])
        assert (probe.returncode, probe.stdout) == (0, b'builtin\n'), command
        # bc intentionally evaluates an unterminated final statement whereas
        # GNU bc diagnoses it; its dedicated suite tests that contract.
        inputs = [b'1+1\n', b'', b'scale=20; sqrt(2)\n'] if command[0] == 'bc' else fixtures
        for data in inputs:
            target = root / 'target'
            target.write_bytes(data)
            expected = run(['/usr/bin/' + command[0], *command[1:]], data)
            assert expected.returncode == 0, (command, expected.stderr)
            shapes = [
                ('repeat', 'for ((i=0;i<3;i++)); do "${@:4}" < "$1" || exit; done', 3),
                ('after head', 'head -n1 < "$2" >/dev/null || exit; "${@:4}" < "$1"', 1),
                ('after empty', '"${@:4}" < "$3" >/dev/null || exit; "${@:4}" < "$1"', 1),
            ]
            if command[0] != 'bc':
                shapes.append(('file then redirect',
                               '"${@:4}" "$1" || exit; "${@:4}" < "$1"', 2))
            for label, script, copies in shapes:
                got = run([binary, '--noprofile', '--norc', '-c', script, '_',
                           str(target), str(left), str(empty), *command])
                assert (got.returncode, got.stdout) == (0, expected.stdout * copies), (
                    command, label, data[:40], got.returncode, got.stdout[:100],
                    expected.stdout[:100], got.stderr[:200])
                checks += 1
    # An operand can receive descriptor zero after the shell closes stdin.
    # Ownership follows the opened operand even when that number is reused.
    target.write_bytes(b'alpha\nbeta\n')
    for name in ['head', 'sed', 'fold', 'expand', 'nl', 'pr', 'tac']:
        command = next(c for c in commands if c[0] == name)
        got = run([binary, '-c', 'exec 0<&-; "${@:2}" "$1" >/dev/null || exit; '
                   '[[ ! -e /proc/self/fd/0 ]]', '_', str(target), *command])
        assert got.returncode == 0, (command, 'closed stdin', got.stderr)
        checks += 1

print(f'input-lifetime: {checks} mixed-reader and descriptor-ownership checks passed')
