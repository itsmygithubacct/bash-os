#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""watch -x executes the given words and does not pass them through a shell."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


BINARY = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())


def main():
    with tempfile.TemporaryDirectory(prefix='watch-exec-') as directory:
        root = Path(directory)
        record = root / 'argv'
        helper = root / 'helper'
        helper.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$@" > "$WATCH_ARGV_OUT"\n'
            'exit 1\n')
        helper.chmod(helper.stat().st_mode | stat.S_IEXEC)
        env = {**os.environ, 'LC_ALL': 'C', 'WATCH_ARGV_OUT': str(record)}
        env.pop('BASH_ENV', None)
        env.pop('ENV', None)
        result = subprocess.run(
            [BINARY, '--noprofile', '--norc', '-c',
             'PATH=; watch -n 30 -e -x "$1" "$2" "$3"',
             'watch-exec', str(helper), 'arg1', 'arg;two'],
            env=env, cwd=root, capture_output=True, timeout=20)
        if result.returncode == 0:
            raise SystemExit(f'watch -e did not stop on helper failure: {result.stderr!r}')
        if not record.is_file():
            raise SystemExit(
                'watch -x did not execute the helper\n'
                f'rc={result.returncode} stderr={result.stderr!r} stdout={result.stdout!r}')
        got = record.read_text()
        want = 'arg1\narg;two\n'
        if got != want:
            raise SystemExit(f'watch -x argv mismatch: {got!r} != {want!r}')
    print('watch: -x executed the given words')


if __name__ == '__main__':
    main()
