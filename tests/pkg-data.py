#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check loadable packages that carry libexec/NAME/ and share/NAME/ files.

Usage: python3 tests/pkg-data.py [BINARY]
Builds seq twice, with different data trees, against out/bash-shell and the
bash tree its build left behind, so ./build.sh --profile shell must be the
latest build. BINARY (default out/bash) runs pkg with an empty PATH through
install, load, verify, upgrade and remove, then refuses archives whose data
files disagree with MANIFEST, leaving the installed trees alone.
"""

import copy
import hashlib
import io
import lzma
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
BUILD = ROOT / 'config/build-packages.py'
SIGN = ROOT / 'config/sign-packages.py'
arch = platform.machine()
checks = 0


def check(condition, *detail):
    global checks
    assert condition, detail
    checks += 1


def tool(script, *args):
    result = subprocess.run([sys.executable, str(script), *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True, timeout=900)
    check(result.returncode == 0, script.name, args, result.stdout, result.stderr)


def tree(directory, files):
    for relative, (content, mode) in files.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
    return directory


def members(package):
    with tarfile.open(fileobj=io.BytesIO(lzma.decompress(package.read_bytes()))) as archive:
        return [(info, archive.extractfile(info).read() if info.isfile() else b'')
                for info in archive.getmembers()]


def craft(entries, destination):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for info, content in entries:
            archive.addfile(info, io.BytesIO(content) if info.isfile() else None)
    destination.write_bytes(lzma.compress(buffer.getvalue(), format=lzma.FORMAT_XZ))
    return destination


def replace(entries, name, content=None, mode=None):
    result = []
    for info, body in entries:
        if info.name == name:
            info = tarfile.TarInfo(info.name) if content is not None else info
            if content is not None:
                body = content
            info.size, info.mode = len(body), mode if mode is not None else 0o644
        result.append((info, body))
    return result


def added(entries, name, content=b'', kind=tarfile.REGTYPE, linkname=''):
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.linkname = kind, 0o644, linkname
    info.size = len(content) if kind == tarfile.REGTYPE else 0
    return entries + [(info, content)]


def manifest_edit(entries, old, new):
    result = []
    for info, body in entries:
        if info.name == 'MANIFEST':
            info = copy.copy(info)
            text = body.decode()
            assert old in text, (old, text)
            body = text.replace(old, new).encode()
            info.size = len(body)
        result.append((info, body))
    return result


def digest(content):
    return hashlib.sha256(content).hexdigest()


with tempfile.TemporaryDirectory(prefix='pkg-data-') as directory:
    tmp = Path(directory)
    keys, trusted = tmp / 'keys', tmp / 'trusted'
    tool(SIGN, 'keygen', keys, 'publisher')
    trusted.mkdir()
    shutil.copy(keys / 'publisher.pub', trusted)
    env = {'LC_ALL': 'C', 'HOME': str(tmp), 'BASHSIGNIFY_TRUSTED_KEYS_DIR': str(trusted),
           'BASHSIGNIFY_REVOKED_KEYS': str(tmp / 'no-revocations')}

    def pkg(script, *args, status=0, stdout=None, output=None):
        result = subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; ' + script, '_',
                                 *map(str, args)], capture_output=True, text=True, timeout=120, env=env)
        check(result.returncode == status, script, result.returncode, result.stdout, result.stderr)
        if stdout is not None:
            check(result.stdout == stdout, script, result.stdout, result.stderr)
        if output is not None:
            check(output in result.stdout + result.stderr, script, output, result.stdout, result.stderr)
        return result

    tool_v1 = b'#!/bin/sh\necho tool 1\n'
    blob = bytes(range(256)) * 64
    v1 = tree(tmp / 'v1', {'share/seq/greeting.txt': (b'hello\n', 0o644),
                           'share/seq/nested/deep/data.bin': (blob, 0o644),
                           'libexec/seq/tool': (tool_v1, 0o755)})
    v2 = tree(tmp / 'v2', {'share/seq/greeting.txt': (b'hello again\n', 0o644),
                           'libexec/seq/tool': (b'#!/bin/sh\necho tool 2\n', 0o755)})
    for version, data in (('1.0', v1), ('2.0', v2)):
        tool(BUILD, '--version', version, '--data', f'seq={data}', '--out', tmp / f'build-{version}', 'seq')
        tool(SIGN, 'release', '--key', keys / 'publisher.sec', '--out', tmp / f'release-{version}',
             tmp / f'build-{version}')
    p1 = tmp / 'release-1.0' / f'seq_1.0_{arch}.pkg'
    p2 = tmp / 'release-2.0' / f'seq_2.0_{arch}.pkg'
    check(p1.read_bytes().startswith(b'\xfd7zXZ\x00'))
    manifest = next(body for info, body in members(p1) if info.name == 'MANIFEST').decode()
    check(f'data: share/seq/greeting.txt 0644 {digest(b"hello" + bytes([10]))}\n' in manifest and
          f'data: share/seq/nested/deep/data.bin 0644 {digest(blob)}\n' in manifest and
          f'data: libexec/seq/tool 0755 {digest(tool_v1)}\n' in manifest, manifest)
    pkg('pkg verify "$1"', p1, stdout='verify seq\tpackage=ok\n')

    # Install, run the builtin and its program, and verify.
    root = tmp / 'root'
    root.mkdir()
    lib = root / 'usr/lib/bash-os'
    pkg('pkg install "$1" --root "$2"', p1, root)
    greeting, program = lib / 'share/seq/greeting.txt', lib / 'libexec/seq/tool'
    check(greeting.read_bytes() == b'hello\n' and greeting.stat().st_mode & 0o7777 == 0o644)
    check(program.read_bytes() == tool_v1 and program.stat().st_mode & 0o7777 == 0o755)
    check((lib / 'share/seq/nested/deep/data.bin').read_bytes() == blob)
    pkg('pkg verify seq --root "$1"', root, stdout='verify seq\tloadable=ok\tdata=3\n')
    pkg('pkg load seq --root "$1" > /dev/null && seq -s, 3 && "$2"', root, program,
        stdout='1,2,3\ntool 1\n')

    # Changes to the installed trees are reported.
    greeting.write_bytes(b'changed\n')
    pkg('pkg verify seq --root "$1"', root, status=1, output=f'SHA256-MISMATCH\t{greeting}')
    greeting.write_bytes(b'hello\n')
    greeting.chmod(0o664)
    pkg('pkg verify seq --root "$1"', root, status=1, output=f'MODE-MISMATCH\t{greeting}')
    greeting.chmod(0o644)
    stray = lib / 'share/seq/nested/stray.py'
    stray.write_text('print("not from the package")\n')
    pkg('pkg verify seq --root "$1"', root, status=1, output=f'EXTRA\t{stray}')
    stray.unlink()
    (lib / 'share/seq/nested/deep/data.bin').unlink()
    pkg('pkg verify seq --root "$1"', root, status=1,
        output=f'MISSING\t{lib}/share/seq/nested/deep/data.bin')

    # An upgrade replaces the trees whole and leaves nothing beside them.
    pkg('pkg install "$1" --root "$2"', p2, root)
    check(greeting.read_bytes() == b'hello again\n' and not (lib / 'share/seq/nested').exists())
    check([p.name for p in (lib / 'share').iterdir()] == ['seq'])
    check([p.name for p in (lib / 'libexec').iterdir()] == ['seq'])
    pkg('pkg verify seq --root "$1"', root, stdout='verify seq\tloadable=ok\tdata=2\n')

    # Archives whose data disagrees with MANIFEST are refused before anything
    # is written, and the installed version stays intact.
    base = members(p2)
    tool_line = f'data: libexec/seq/tool 0755 {digest(b"#!/bin/sh\necho tool 2\n")}'
    other = b'other\n'
    cases = [
        ('undeclared', added(base, 'share/seq/extra.txt', b'x\n'),
         'data file share/seq/extra.txt is not declared in MANIFEST'),
        ('missing', [entry for entry in base if entry[0].name != 'libexec/seq/tool'],
         'declared data file libexec/seq/tool is missing'),
        ('content', replace(base, 'share/seq/greeting.txt', b'tampered\n'),
         'data file share/seq/greeting.txt does not match its MANIFEST sha256'),
        ('mode', replace(base, 'libexec/seq/tool', b'#!/bin/sh\necho tool 2\n', 0o644),
         'data file libexec/seq/tool has mode 0644, but MANIFEST declares 0755'),
        ('setuid', manifest_edit(replace(base, 'libexec/seq/tool', b'#!/bin/sh\necho tool 2\n', 0o4755),
                                 tool_line, tool_line.replace(' 0755 ', ' 4755 ')),
         'data: mode for libexec/seq/tool must be permission bits only'),
        ('namespace', manifest_edit(added(base, 'share/other/x.txt', other), tool_line,
                                    f'{tool_line}\ndata: share/other/x.txt 0644 {digest(other)}'),
         'data: share/other/x.txt is not under libexec/seq/ or share/seq/'),
        ('symlink', added(base, 'share/seq/link', kind=tarfile.SYMTYPE, linkname='/etc/passwd'),
         'data member share/seq/link is not a regular file or directory'),
        ('parent', added(base, 'share/seq/../../escape', b'x\n'), 'unsafe tar path'),
    ]
    for label, entries, message in cases:
        bad = craft(entries, tmp / f'bad-{label}.pkg')
        pkg('pkg install -A "$1" --root "$2"', bad, root, status=1, output=message)
        check(not (root / 'escape').exists() and not (lib / 'share/other').exists(), label)
        pkg('pkg verify seq --root "$1"', root, stdout='verify seq\tloadable=ok\tdata=2\n')

    # Remove takes the trees with the loadable.
    pkg('pkg remove seq --root "$1"', root, stdout='removed seq\n')
    check(not any((lib / part).exists() for part in ('share/seq', 'libexec/seq', 'loadables/seq.so')))

print(f'pkg-data: {checks} checks passed')
