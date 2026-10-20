#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Additional poweroff parser and cross-command state checks; no compilation.

Run alongside sol-halt-check.py. Reuses its closed reboot/sync/accounting
boundary and sanitizer loading, so every production call is intercepted.
"""
import argparse
import errno
import itertools
from pathlib import Path
import runpy
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
helper = runpy.run_path(str(ROOT / 'tests/sol-halt-check.py'))
EMPTY = 'sync=0 reboot=0 accounting=0 cmd=none order=\n'


def trace(name, force=False):
    command = {'poweroff': 'RB_POWER_OFF', 'halt': 'RB_HALT_SYSTEM',
               'reboot': 'RB_AUTOBOOT'}[name]
    return (f'sync={int(not force)} reboot=1 accounting=0 cmd={command} '
            f'order={"R" if force else "SR"}\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--sanitize-dir', type=Path)
    args = parser.parse_args()
    modules = args.sanitize_dir.resolve() if args.sanitize_dir else None
    asan = Path((modules / 'asan-path.txt').read_text().strip()) if modules else None
    shim = args.shim.resolve()
    prefix = helper['setup'](shim, modules)
    env = helper['environment'](shim, asan)
    failures = []
    count = 0

    def check(label, script, expected, diagnostics=()):
        nonlocal count
        count += 1
        result = subprocess.run(
            [str(args.binary.resolve()), '--noprofile', '--norc', '-c', prefix + script],
            env=env, capture_output=True, text=True, timeout=30)
        ok = (result.returncode == 0 and result.stdout == expected and
              (all(d in result.stderr for d in diagnostics) if diagnostics else not result.stderr)
              and 'AddressSanitizer' not in result.stderr and 'runtime error:' not in result.stderr)
        print(('PASS ' if ok else 'FAIL ') + label)
        if not ok:
            failures.append(label)
            print(f'exit={result.returncode} stdout={result.stdout!r} '
                  f'stderr={result.stderr!r} expected={expected!r}')

    # Exhaust every short-option cluster through length five, using the
    # documented flag meanings as the oracle, independently of parser state.
    for length in range(1, 6):
        for flags in itertools.product('fn', repeat=length):
            opts = '-' + ''.join(flags)
            dry = 'n' in flags
            expected = ('poweroff: would poweroff (dry run)\n' if dry else '')
            expected += 'status=0\n' + (EMPTY if dry else trace('poweroff', True))
            check(f'poweroff cluster {opts}',
                  f'poweroff {opts}; printf "status=%s\\n" "$?"; halt_fixture report',
                  expected)

    for argv in [[], ['-n'], ['-f'], ['-fn'], ['--']]:
        for operand in ['', ' ', '\n', '-n', '--help']:
            # An explicit -- makes even option-looking words invalid operands.
            words = [*argv, '--', operand] if argv != ['--'] else [*argv, operand]
            command = shlex.join(['poweroff', *words])
            check(f'reject operand {words!r}', command +
                  '; printf "status=%s\\n" "$?"; halt_fixture report',
                  'status=2\n' + EMPTY, ('usage:',))

    for option in ('-h', '--force', '--no-sync', '--dry-run', '-fnx', '-nqf'):
        check(f'reject unsupported {option}',
              f'poweroff {option}; printf "status=%s\\n" "$?"; halt_fixture report',
              'status=2\n' + EMPTY, ('usage:',))

    # No shell restart between siblings or failure/success paths. Only the
    # interceptor is reset; production getopt, flags and stdio must recover.
    script, expected = [], []
    for _ in range(100):
        for name in ('poweroff', 'halt', 'reboot', 'poweroff'):
            cases = [
                ('-fn', 0, 0, f'{name}: would {name} (dry run)\n', EMPTY),
                ('-n bad', 0, 2, '', EMPTY),
                ('-f', errno.EPERM, 1, '', trace(name, True)),
                ('', 0, 0, '', trace(name)),
                ('-f', 0, 0, '', trace(name, True)),
                ('', errno.EACCES, 1, '', trace(name)),
                ('--help >/dev/null', 0, 2, '', EMPTY),
            ]
            for opts, error, status, output, boundary in cases:
                script.append(f'halt_fixture reset; halt_fixture errno {error}\n'
                              f'{name} {opts} 2>/dev/null; '
                              'printf "status=%s\\n" "$?"; halt_fixture report\n')
                expected.append(output + f'status={status}\n' + boundary)
    # Pass the long script over stdin, avoiding the OS argv length limit.
    with subprocess.Popen(
            [str(args.binary.resolve()), '--noprofile', '--norc'],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True) as process:
        stdout, stderr = process.communicate(prefix + ''.join(script), timeout=30)
        ok = process.returncode == 0 and stdout == ''.join(expected) and not stderr
    count += 1
    print(('PASS ' if ok else 'FAIL ') + '2800 mixed sibling calls with exact per-call boundary traces')
    if not ok:
        failures.append('mixed sibling calls')
        print(f'exit={process.returncode} stderr={stderr!r} '
              f'actual_bytes={len(stdout)} expected_bytes={len("".join(expected))}')
    print(f'{count - len(failures)}/{count} passed')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
