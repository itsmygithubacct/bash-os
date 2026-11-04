#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only regression: BASH and an actual packaged uv.so are required.

Run in a disposable VM: python3 tests/uv-relative-module-after-cd.py BASH UV_SO
The module must have been built for the candidate Bash. No upstream uv or
network is needed. An unsupported or failed enable is a failure, not a skip.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 3:
    raise SystemExit('usage: uv-relative-module-after-cd.py BASH UV_SO')
bash, module = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])

with tempfile.TemporaryDirectory(prefix='uv-relative-module-') as directory:
    root = Path(directory)
    module_dir = root / 'pkgroot/lib/bash-os/loadables'
    helper = root / 'pkgroot/lib/bash-os/libexec/uv/uv'
    decoy = root / 'elsewhere/pkgroot/lib/bash-os/libexec/uv/uv'
    module_dir.mkdir(parents=True)
    helper.parent.mkdir(parents=True)
    decoy.parent.mkdir(parents=True)
    shutil.copyfile(module, module_dir / 'uv.so')
    helper.write_text('#!/bin/sh\nprintf "correct:%s\\n" "$1"\n')
    decoy.write_text('#!/bin/sh\nprintf "wrong:%s\\n" "$1"\n')
    helper.chmod(0o755)
    decoy.chmod(0o755)
    script = '''
PATH=
enable -f pkgroot/lib/bash-os/loadables/uv.so uv || exit 91
[[ $(type -t uv) == builtin ]] || exit 92
uv before || exit 93
cd elsewhere || exit 94
uv after || exit 95
'''
    result = subprocess.run([str(bash), '--noprofile', '--norc', '-c', script],
                            cwd=root, env={'PATH': '', 'LC_ALL': 'C'},
                            capture_output=True, text=True, timeout=30)
    expected = 'correct:before\ncorrect:after\n'
    if result.returncode != 0 or result.stdout != expected or result.stderr:
        sys.stderr.write(f'FAIL status={result.returncode}\nstdout={result.stdout!r}\n'
                         f'stderr={result.stderr!r}\n')
        raise SystemExit(1)
print('uv-relative-module-after-cd: PASS')
