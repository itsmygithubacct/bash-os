#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reboot parser/state contracts behind the existing closed syscall boundary.

No compilation or host mutation. Run together with the halt and poweroff suites.
"""
import argparse
import errno
import itertools
import os
from pathlib import Path
import runpy
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
helper = runpy.run_path(str(ROOT / 'tests/sol-halt-check.py'))
EMPTY = 'sync=0 reboot=0 accounting=0 cmd=none order=\n'
SYNC = 'sync=1 reboot=1 accounting=0 cmd=RB_AUTOBOOT order=SR\n'
FORCE = 'sync=0 reboot=1 accounting=0 cmd=RB_AUTOBOOT order=R\n'
DRY = 'reboot: would reboot (dry run)\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--sanitize-dir', type=Path)
    args = parser.parse_args()
    modules = args.sanitize_dir.resolve() if args.sanitize_dir else None
    required = [args.binary, args.shim]
    if modules:
        required += [modules / 'asan-path.txt'] + [
            modules / (name + '-sanitize.so') for name in ('halt', 'reboot', 'poweroff')]
    for path in required:
        if not path.is_file():
            parser.error(f'required prebuilt artifact missing: {path}')
    asan = Path((modules / 'asan-path.txt').read_text().strip()) if modules else None
    shim = args.shim.resolve()
    prefix = helper['setup'](shim, modules)
    env = helper['environment'](shim, asan)
    failures, count = [], 0

    def check(label, script, expected, diagnostic=None):
        nonlocal count
        count += 1
        result = subprocess.run(
            [str(args.binary.resolve()), '--noprofile', '--norc'],
            input=prefix + script, env=env, capture_output=True, text=True, timeout=30)
        ok = (result.returncode == 0 and result.stdout == expected and
              (diagnostic in result.stderr if diagnostic else not result.stderr) and
              'AddressSanitizer' not in result.stderr and 'runtime error:' not in result.stderr)
        print(('PASS ' if ok else 'FAIL ') + label)
        if not ok:
            failures.append(label)
            print(f'exit={result.returncode} stdout={result.stdout[:4000]!r} '
                  f'stderr={result.stderr!r} expected={expected[:4000]!r}')

    # Every partition of every f/n string through length four: options may be
    # clustered or split across words. The oracle derives only from the flags.
    for length in range(1, 5):
        for flags in itertools.product('fn', repeat=length):
            for splits in itertools.product((False, True), repeat=length - 1):
                words = ['-' + flags[0]]
                for split, flag in zip(splits, flags[1:]):
                    if split:
                        words.append('-' + flag)
                    else:
                        words[-1] += flag
                dry = 'n' in flags
                argv = shlex.join(['reboot', *words, '--'])
                check(argv, argv + '; printf "status=%s\\n" "$?"; halt_fixture report\n',
                      (DRY if dry else '') + 'status=0\n' + (EMPTY if dry else FORCE))

    for words in ([''], [' '], ['\n'], ['now'], ['0'], ['restart'],
                  ['--', '-f'], ['--', '--help'], ['-n', 'now'],
                  ['-f', 'now', '-n'], ['now', '-n'], ['-n', '--', ''],
                  ['-w'], ['-d', '0'], ['-i'], ['-p'], ['-h'], ['--reboot'],
                  ['--force'], ['--no-sync'], ['--dry-run'], ['-nfq'], ['-qnf']):
        argv = shlex.join(['reboot', *words])
        check('invalid ' + repr(words),
              argv + '; printf "status=%s\\n" "$?"; halt_fixture report\n',
              'status=2\n' + EMPTY, 'usage:')

    # Inject errno on alternating default/forced calls and immediately recover
    # in the same shell. This catches stale error/force/dry/getopt state.
    for error in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.EIO,
                  errno.ENOSYS, errno.EBUSY, errno.EINTR):
        for option, boundary in (('', SYNC), ('-f', FORCE)):
            check(f'errno={error} option={option!r} then recovery',
                  f'halt_fixture errno {error}\nreboot {option}\n'
                  'printf "status=%s\\n" "$?"; halt_fixture report\n'
                  'halt_fixture reset\nreboot\n'
                  'printf "status=%s\\n" "$?"; halt_fixture report\n',
                  'status=1\n' + boundary + 'status=0\n' + SYNC, os.strerror(error))

    # A dry run must not consult even an armed failure, nor leave flags for the
    # following call. Assert every boundary trace across a persistent shell.
    script, expected = [], []
    for _ in range(100):
        for opts, error, status, output, boundary in (
                ('-fn', errno.EIO, 0, DRY, EMPTY),
                ('-n invalid', errno.EPERM, 2, '', EMPTY),
                ('--help >/dev/null', errno.EACCES, 2, '', EMPTY),
                ('-f', errno.EPERM, 1, '', FORCE),
                ('--', 0, 0, '', SYNC),
                ('-nf', 0, 0, DRY, EMPTY),
                ('', errno.EINVAL, 1, '', SYNC),
                ('-ff', 0, 0, '', FORCE),
                ('', 0, 0, '', SYNC)):
            script.append(f'halt_fixture reset; halt_fixture errno {error}\n'
                          f'reboot {opts} 2>/dev/null\n'
                          'printf "status=%s\\n" "$?"; halt_fixture report\n')
            expected.append(output + f'status={status}\n' + boundary)
    check('900 calls with exact per-call trace and status', ''.join(script), ''.join(expected))
    print(f'{count - len(failures)}/{count} passed')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
