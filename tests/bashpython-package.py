#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check bashpython as a signed pkg package with its standard library.

Usage: python3 tests/bashpython-package.py [BINARY]
Packs out/bashpython.so (from config/build-python-loadable.py) with the
standard library tree from out/python/TARGET/data, against out/bash-shell and
the bash tree its build left behind. BINARY (default out/bash-pkg, a build
with pkg) runs pkg with an empty PATH to install, verify, load and remove it. The installed
module must find its standard library beside itself: no PYTHONHOME is set.
"""

from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash-pkg').resolve())
shell = str(ROOT / 'out/bash-shell')
arch = platform.machine()
target = subprocess.run(['cc', '-dumpmachine'], capture_output=True, text=True, check=True).stdout.strip()
prefix = ROOT / 'out/python' / target
module = ROOT / 'out/bashpython.so'
data = prefix / 'data'
checks = 0


def check(condition, *detail):
    global checks
    assert condition, detail
    checks += 1


def tool(script, *args):
    result = subprocess.run([sys.executable, str(ROOT / 'config' / script), *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True, timeout=1800)
    check(result.returncode == 0, script, args, result.stdout, result.stderr)


# The interpreter itself: bin/ also holds python3.13-config, a shell script.
reference = next(path for path in sorted(prefix.glob('bin/python3.*'))
                 if re.fullmatch(r'python3\.[0-9]+', path.name))
version = subprocess.run([str(reference), '-c', 'import sys; print(sys.version.split()[0])'],
                         capture_output=True, text=True, check=True).stdout
files = sum(1 for path in (data / 'share/bashpython').rglob('*') if path.is_file())

with tempfile.TemporaryDirectory(prefix='bashpython-package-') as directory:
    tmp = Path(directory)
    tool('build-packages.py', '--version', '1.0', '--prebuilt', f'bashpython={module}',
         '--data', f'bashpython={data}', '--out', tmp / 'build', 'bashpython')
    tool('sign-packages.py', 'keygen', tmp / 'keys', 'publisher')
    tool('sign-packages.py', 'release', '--key', tmp / 'keys/publisher.sec', '--out', tmp / 'release',
         tmp / 'build')
    trusted = tmp / 'trusted'
    trusted.mkdir()
    shutil.copy(tmp / 'keys/publisher.pub', trusted)
    root = tmp / 'root'
    root.mkdir()
    env = {'LC_ALL': 'C', 'HOME': str(tmp), 'BASHSIGNIFY_TRUSTED_KEYS_DIR': str(trusted),
           'BASHSIGNIFY_REVOKED_KEYS': str(tmp / 'no-revocations')}

    def run(runner, script, *args, stdout=None):
        result = subprocess.run([runner, '--noprofile', '--norc', '-c', 'PATH=; ' + script, '_',
                                 *map(str, args)], capture_output=True, text=True, timeout=300, env=env)
        check(result.returncode == 0, script, result.returncode, result.stdout, result.stderr[-800:])
        if stdout is not None:
            check(result.stdout == stdout, script, result.stdout, result.stderr[-800:])

    package = tmp / 'release' / f'bashpython_1.0_{arch}.pkg'
    run(binary, 'pkg install "$1" --root "$2" > /dev/null', package, root)
    run(binary, 'pkg verify bashpython --root "$1"', root,
        stdout=f'verify bashpython\tloadable=ok\tdata={files}\n')
    installed = root / 'usr/lib/bash-os/loadables/bashpython.so'
    program = 'import sys, json, sqlite3, ssl, zlib; print(sys.version.split()[0])'
    run(shell, 'enable -f "$1" bashpython && bashpython -c "$2"', installed, program, stdout=version)
    run(binary, 'pkg load bashpython --root "$1" > /dev/null && cd / && bashpython -c "print(6 * 7)"', root,
        stdout='42\n')
    run(binary, 'pkg remove bashpython --root "$1"', root, stdout='removed bashpython\n')
    check(not (root / 'usr/lib/bash-os/share/bashpython').exists() and not installed.exists())

print(f'bashpython-package: {checks} checks passed')
