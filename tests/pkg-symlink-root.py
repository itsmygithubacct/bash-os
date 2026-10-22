#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A symlink below --root must not be read or written through.

The package file, a local source, and the --root prefix itself may be
reached through a symlink. Those installs succeed.
"""
import hashlib
import io
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import tarfile
import tempfile


BINARY = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())


def shell(root, script, *args):
    env = {**os.environ, 'LC_ALL': 'C', 'HOME': str(root)}
    env.pop('BASH_ENV', None)
    env.pop('ENV', None)
    if module := os.environ.get('PKG_TEST_LOADABLE'):
        script = 'enable -f ' + shlex.quote(module) + ' pkg || exit; ' + script
    if preload := os.environ.get('PKG_TEST_ASAN_LIB'):
        env.update(LD_PRELOAD=preload,
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    result = subprocess.run(
        [BINARY, '--noprofile', '--norc', '-c', 'PATH=; ' + script,
         'pkg-symlink', *map(str, args)],
        env=env, capture_output=True, text=True, timeout=30)
    if 'AddressSanitizer' in result.stderr or 'runtime error:' in result.stderr:
        raise AssertionError(result.stderr)
    return result


def loadable_package(root):
    source, shared = root / 'probe.c', root / 'probe.so'
    source.write_text('int probe(void) { return 0; }\n')
    subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC', '-nostdlib',
                    str(source), '-o', str(shared)], check=True, timeout=30)
    body = shared.read_bytes()
    data = b'package data\n'
    manifest = ('type: loadable\nname: probe\nversion: 1\nbuiltin: probe\n'
                f'abi: bash-5.3\narch: {platform.machine()}\n'
                f'sha256: {hashlib.sha256(body).hexdigest()}\n'
                f'data: share/probe/data 0644 {hashlib.sha256(data).hexdigest()}\n')
    package = root / 'probe.pkg'
    with tarfile.open(package, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content, mode in [('MANIFEST', manifest.encode(), 0o644),
                                    ('loadable/probe.so', body, 0o755),
                                    ('share/probe/data', data, 0o644)]:
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), mode
            archive.addfile(entry, io.BytesIO(content))
    return package


def legacy_package(root):
    payload = b'legacy payload\n'
    manifest = ('name: legacy\nversion: 1\n')
    package = root / 'legacy.pkg'
    with tarfile.open(package, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name, content, mode in [('MANIFEST', manifest.encode(), 0o644),
                                    ('files/escaped/planted', payload, 0o644)]:
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), mode
            archive.addfile(entry, io.BytesIO(content))
    return package


def outside_names(path):
    return sorted(p.name for p in path.iterdir())


def main():
    with tempfile.TemporaryDirectory(prefix='pkg-symlink-') as directory:
        root = Path(directory)
        package = loadable_package(root)
        outside = root / 'outside'
        outside.mkdir()
        (outside / 'SENTINEL').write_bytes(b'sentinel\n')
        target = root / 'target'
        target.mkdir()
        (target / 'usr').symlink_to(outside)
        result = shell(root, 'pkg install -A "$1" --root "$2"', package, target)
        names = outside_names(outside)
        if names != ['SENTINEL'] or (outside / 'SENTINEL').read_bytes() != b'sentinel\n':
            raise SystemExit(
                'install wrote through a symlink component under --root\n'
                f'rc={result.returncode}\noutside={names}\n'
                f'stderr={result.stderr}\nstdout={result.stdout}')
        if not (target / 'usr').is_symlink():
            raise SystemExit('install replaced the symlink component')

        legacy = legacy_package(root)
        outside_legacy = root / 'outside-legacy'
        outside_legacy.mkdir()
        (outside_legacy / 'SENTINEL').write_bytes(b'sentinel\n')
        legacy_root = root / 'legacy-root'
        legacy_root.mkdir()
        (legacy_root / 'escaped').symlink_to(outside_legacy)
        result = shell(root, 'pkg install -A --legacy-rootfs "$1" --root "$2"',
                       legacy, legacy_root)
        names = outside_names(outside_legacy)
        if names != ['SENTINEL'] or (outside_legacy / 'SENTINEL').read_bytes() != b'sentinel\n':
            raise SystemExit(
                'legacy extract wrote through a symlink component\n'
                f'rc={result.returncode}\noutside={names}\n'
                f'stderr={result.stderr}')
        if not (legacy_root / 'escaped').is_symlink():
            raise SystemExit('legacy extract replaced the symlink component')

        read_root = root / 'read-root'
        (read_root / 'var/lib/pkg/installed/probe').mkdir(parents=True)
        secret = b'outside loadable bytes\n'
        digest = hashlib.sha256(secret).hexdigest()
        so_dir = outside / 'lib/bash-os/loadables'
        so_dir.mkdir(parents=True)
        (so_dir / 'probe.so').write_bytes(secret)
        manifest = ('type: loadable\nname: probe\nversion: 1\nbuiltin: probe\n'
                    f'abi: bash-5.3\narch: {platform.machine()}\n'
                    f'sha256: {digest}\n')
        state = read_root / 'var/lib/pkg/installed/probe'
        (state / 'MANIFEST').write_text(manifest)
        (state / 'sha256').write_text(digest + '\n')
        (read_root / 'usr').symlink_to(outside)
        result = shell(root, 'pkg verify probe --root "$1"', read_root)
        if 'loadable=ok' in result.stdout:
            raise SystemExit(
                'verify read the loadable through a symlink component\n'
                f'rc={result.returncode}\nstdout={result.stdout}')
        if (so_dir / 'probe.so').read_bytes() != secret:
            raise SystemExit('verify changed the outside loadable')

        real = root / 'real'
        real.mkdir()
        ordinary = loadable_package(real)
        link = root / 'link'
        link.symlink_to(real)
        cases = (
            ('plain package, plain root', ordinary, root / 'root1'),
            ('package via symlinked dir', link / ordinary.name, root / 'root2'),
            ('root via symlinked prefix', ordinary, link / 'root3'),
        )
        for name, pkgpath, rootpath in cases:
            rootpath.mkdir(parents=True)
            result = shell(root, 'pkg install -A "$1" --root "$2"',
                           pkgpath, rootpath)
            installed = rootpath / 'usr/lib/bash-os/loadables/probe.so'
            data = rootpath / 'usr/lib/bash-os/share/probe/data'
            if result.returncode != 0 or not installed.is_file() or installed.is_symlink():
                raise SystemExit(
                    f'{name} did not install\n'
                    f'rc={result.returncode}\n'
                    f'stderr={result.stderr}\nstdout={result.stdout}')
            if not data.is_file() or data.read_bytes() != b'package data\n':
                raise SystemExit(f'{name} did not install package data')
            if (rootpath / 'usr').is_symlink():
                raise SystemExit(f'{name} left a symlink inside --root')
    print('pkg: symlink components under --root are not read or written')


if __name__ == '__main__':
    main()
