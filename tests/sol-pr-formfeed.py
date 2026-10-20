#!/usr/bin/env python3
"""Assert every case in the recorded 294-comparison GNU form-feed matrix."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = 'if [[ -n ${PR_MODULE:-} ]]; then enable -f "$PR_MODULE" pr || exit; fi\n'
fixtures = [b'\f', b'a\fb\nc\n', b'a\n\f\nb\nc', b'1\n2\n\f\n3\n4\n',
            b'\f\fX\n', b'x\n'*5+b'\f\n'+b'y\n'*5]
options = [
    ['-t'], ['-T'], ['-t', '-2'], ['-t', '-a', '-2'], ['-T', '-a', '-2'],
    ['-t', '-2', '-n'], ['-t', '-a', '-2', '-n'], ['-t', '-l2'],
    ['-t', '-l2', '-2'], ['-t', '-l2', '-a', '-2'], ['-t', '-l2', '+2:3'],
    ['-t', '-l2', '-2', '+2:3'], ['-T', '-2', '-n'],
]
merge_options = [
    ['-t', '-m'], ['-T', '-m'], ['-t', '-m', '-n'], ['-t', '-l2', '-m'],
    ['-t', '-l2', '-m', '-n'], ['-t', '-m', '-n', '-s,'],
]
checks = failures = 0


def check(opts, data, right=None, cwd=None):
    global checks, failures
    args = opts if right is None else [*opts, 'left', 'right']
    stdin = data if right is None else b''
    got = subprocess.run([binary, '-c', prefix+'pr "$@"', '_', *args], input=stdin,
                         capture_output=True, env=env, cwd=cwd, timeout=30)
    want = subprocess.run(['/usr/bin/pr', *args], input=stdin, capture_output=True,
                          env=env, cwd=cwd, timeout=30)
    checks += 1
    if ((got.returncode, got.stdout) != (want.returncode, want.stdout)
            or b'AddressSanitizer' in got.stderr or b'runtime error:' in got.stderr):
        failures += 1
        print('FAIL', opts, repr(data), repr(right), 'ours', got.returncode,
              repr(got.stdout), repr(got.stderr), 'GNU', want.returncode, repr(want.stdout))


with tempfile.TemporaryDirectory(prefix='pr-formfeed-') as d:
    root = Path(d)
    for data in fixtures:
        for opts in options:
            check(opts, data)
        for right in fixtures:
            (root/'left').write_bytes(data)
            (root/'right').write_bytes(right)
            for opts in merge_options:
                check(opts, data, right, root)
assert checks == 294
print(f'{checks} form-feed comparisons, {failures} differences')
raise SystemExit(bool(failures))
