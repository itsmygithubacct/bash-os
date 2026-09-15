#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the uv builtin with a stand-in program in place of upstream uv.

Usage: python3 tests/uv-builtin.py [BINARY]
Packages uv.so with a shell script at libexec/uv/uv, against out/bash-shell
and the bash tree its build left behind, so ./build.sh --profile shell must
be the latest build. BINARY (default out/bash) installs and loads it with an
empty PATH; the builtin must pass arguments, exported variables and exit
statuses through, keep working after cd, and say how to install uv when the
program is missing.
"""

from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
arch = platform.machine()
PROGRAM = '''#!/bin/sh
printf '%s|' "$@"
printf '\\nVISIBLE=%s HIDDEN=%s\\n' "$VISIBLE" "$HIDDEN"
[ -n "$UV_SIGNAL" ] && kill -"$UV_SIGNAL" $$
exit "${UV_EXIT:-0}"
'''
checks = 0


def check(condition, *detail):
    global checks
    assert condition, detail
    checks += 1


def tool(script, *args):
    result = subprocess.run([sys.executable, str(ROOT / 'config' / script), *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True, timeout=900)
    check(result.returncode == 0, script, args, result.stdout, result.stderr)


with tempfile.TemporaryDirectory(prefix='uv-builtin-') as directory:
    tmp = Path(directory)
    data = tmp / 'data'
    program = data / 'libexec/uv/uv'
    program.parent.mkdir(parents=True)
    program.write_text(PROGRAM)
    program.chmod(0o755)
    tool('build-packages.py', '--version', '1.0', '--data', f'uv={data}', '--out', tmp / 'build', 'uv')
    tool('sign-packages.py', 'keygen', tmp / 'keys', 'publisher')
    tool('sign-packages.py', 'release', '--key', tmp / 'keys/publisher.sec', '--out', tmp / 'release', tmp / 'build')
    trusted = tmp / 'trusted'
    trusted.mkdir()
    shutil.copy(tmp / 'keys/publisher.pub', trusted)
    root = tmp / 'root'
    root.mkdir()
    env = {'LC_ALL': 'C', 'HOME': str(tmp), 'BASHSIGNIFY_TRUSTED_KEYS_DIR': str(trusted),
           'BASHSIGNIFY_REVOKED_KEYS': str(tmp / 'no-revocations')}

    def run(script, status=0, stdout=None, stderr=None):
        result = subprocess.run(
            [binary, '--noprofile', '--norc', '-c',
             'PATH=; pkg load uv --root "$1" > /dev/null || exit 99; ' + script, '_', str(root)],
            capture_output=True, text=True, timeout=60, env=env)
        check(result.returncode == status, script, result.returncode, result.stdout, result.stderr)
        if stdout is not None:
            check(result.stdout == stdout, script, result.stdout, result.stderr)
        if stderr is not None:
            check(stderr in result.stderr, script, result.stderr)

    subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; pkg install "$1" --root "$2" > /dev/null',
                    '_', str(tmp / 'release' / f'uv_1.0_{arch}.pkg'), str(root)], check=True, env=env)
    run('[[ $(type -t uv) == builtin ]] && help -s uv', stdout='uv: uv [UV-ARGS ...]\n')
    run("export VISIBLE=yes; HIDDEN=no; uv pip install 'two words' ''",
        stdout='pip|install|two words||\nVISIBLE=yes HIDDEN=\n')
    run('UV_EXIT=3 uv; echo "status $?"', stdout='|\nVISIBLE= HIDDEN=\nstatus 3\n')
    run('UV_SIGNAL=TERM uv > /dev/null; echo "status $?"', stdout='status 143\n')
    run('cd / && uv after-cd', stdout='after-cd|\nVISIBLE= HIDDEN=\n')
    (root / 'usr/lib/bash-os/libexec/uv/uv').unlink()
    run('uv --version', status=127, stderr='(install it with: pkg install uv)')

print(f'uv-builtin: {checks} checks passed')
