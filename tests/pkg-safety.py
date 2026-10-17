#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package publication and rollback must preserve unrelated filesystem entries."""
import hashlib
import io
import os
from pathlib import Path
import platform
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'out/bash').resolve())


class PackageSafety(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pkg-safety-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        (self.stage / 'MANIFEST').write_text('name: probe\nversion: 1\n')

    def shell(self, script, *args):
        env = {**os.environ, 'LC_ALL': 'C', 'HOME': str(self.root)}
        env.pop('BASH_ENV', None)
        env.pop('ENV', None)
        if module := os.environ.get('PKG_TEST_LOADABLE'):
            script = 'enable -f ' + shlex.quote(module) + ' pkg || exit; ' + script
        if preload := os.environ.get('PKG_TEST_ASAN_LIB'):
            env.update(LD_PRELOAD=preload, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        result = subprocess.run([BINARY, '--noprofile', '--norc', '-c',
                                 'PATH=; ' + script, 'pkg-safety', *map(str, args)],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertNotIn('AddressSanitizer', result.stderr)
        self.assertNotIn('runtime error:', result.stderr)
        return result

    def package(self):
        # A tiny ELF fixture is enough to exercise install; loading a command
        # into Bash is covered by pkg-signify.py and packages.py.
        source, shared = self.root / 'probe.c', self.root / 'probe.so'
        source.write_text('int probe(void) { return 0; }\n')
        subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC', '-nostdlib',
                        str(source), '-o', str(shared)], check=True, timeout=30)
        body = shared.read_bytes()
        data = b'package data\n'
        manifest = ('type: loadable\nname: probe\nversion: 1\nbuiltin: probe\n'
                    f'abi: bash-5.3\narch: {platform.machine()}\n'
                    f'sha256: {hashlib.sha256(body).hexdigest()}\n'
                    f'data: share/probe/data 0644 {hashlib.sha256(data).hexdigest()}\n')
        package = self.root / 'probe.pkg'
        with tarfile.open(package, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name, content, mode in [('MANIFEST', manifest.encode(), 0o644),
                                        ('loadable/probe.so', body, 0o755),
                                        ('share/probe/data', data, 0o644)]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(content), mode
                archive.addfile(entry, io.BytesIO(content))
        return package, body

    def test_pack_preserves_preexisting_temporary_paths(self):
        for kind in ('symlink', 'hardlink', 'file', 'directory'):
            with self.subTest(kind=kind):
                directory = self.root / kind
                directory.mkdir()
                victim, output, record = (directory / name for name in
                                          ('unrelated', 'output.pkg', 'candidate'))
                victim.write_bytes(b'keep these bytes\n')
                result = self.shell('''
                    candidate=$2.tmp.$BASHPID
                    case $5 in
                        symlink) ln -s "$3" "$candidate" ;;
                        hardlink) ln "$3" "$candidate" ;;
                        file) printf 'keep temporary file\n' > "$candidate" ;;
                        directory) mkdir "$candidate" ;;
                    esac || exit
                    printf '%s' "$candidate" > "$4"
                    pkg pack "$1" "$2"
                ''', self.stage, output, victim, record, kind)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(victim.read_bytes(), b'keep these bytes\n')
                self.assertFalse(output.is_symlink())
                candidate = Path(record.read_text())
                self.assertTrue(candidate.exists())
                if kind == 'symlink':
                    self.assertTrue(candidate.is_symlink())
                elif kind == 'hardlink':
                    self.assertEqual(candidate.stat().st_ino, victim.stat().st_ino)
                elif kind == 'file':
                    self.assertEqual(candidate.read_bytes(), b'keep temporary file\n')
                else:
                    self.assertTrue(candidate.is_dir())
                with tarfile.open(output) as archive:
                    self.assertEqual(archive.extractfile('MANIFEST').read(),
                                     (self.stage / 'MANIFEST').read_bytes())
                self.assertEqual(set(directory.iterdir()), {victim, output, record, candidate})

    def test_pack_preserves_umask_and_cleans_up_failed_publication(self):
        for mask, mode in [('022', 0o644), ('077', 0o600)]:
            output = self.root / ('output-' + mask)
            result = self.shell('umask "$3"; pkg pack "$1" "$2" >/dev/null; umask',
                                self.stage, output, mask)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(int(result.stdout, 8), int(mask, 8))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), mode)
        blocked = self.root / 'destination-directory'
        blocked.mkdir()
        (blocked / 'keep').write_bytes(b'keep\n')
        before = set(self.root.iterdir())
        result = self.shell('pkg pack "$1" "$2"', self.stage, blocked)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((blocked / 'keep').read_bytes(), b'keep\n')
        self.assertEqual(set(self.root.iterdir()), before)

    def test_install_preserves_backup_and_staging_collisions(self):
        package, body = self.package()
        target = self.root / 'target'
        library = target / 'usr/lib/bash-os'
        shared = library / 'loadables/probe.so'
        shared.parent.mkdir(parents=True)
        shared.write_bytes(b'old loadable\n')
        installed = target / 'var/lib/pkg/installed/probe'
        installed.mkdir(parents=True)
        (installed / 'MANIFEST').write_text('name: probe\nversion: old\n')
        data = library / 'share/probe'
        data.mkdir(parents=True)
        (data / 'old').write_bytes(b'old data\n')
        record = self.root / 'sentinels'
        result = self.shell('''
            for base in "$3" "$4" "$5"; do
                for suffix in bak new; do
                    path=$base.$suffix.$BASHPID
                    mkdir "$path" || exit
                    printf 'unrelated\n' > "$path/keep"
                    printf '%s\n' "$path" >> "$6"
                done
            done
            pkg install -A "$1" --root "$2"
        ''', package, target, shared, installed, data, record)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(shared.read_bytes(), body)
        self.assertEqual((data / 'data').read_bytes(), b'package data\n')
        self.assertFalse((data / 'old').exists())
        for sentinel in record.read_text().splitlines():
            self.assertEqual((Path(sentinel) / 'keep').read_bytes(), b'unrelated\n')

    def test_failed_install_restores_previous_loadable_and_data(self):
        package, _ = self.package()
        target = self.root / 'target'
        library = target / 'usr/lib/bash-os'
        shared = library / 'loadables/probe.so'
        shared.parent.mkdir(parents=True)
        shared.write_bytes(b'old loadable\n')
        shared.chmod(0o640)
        data = library / 'share/probe'
        data.mkdir(parents=True)
        (data / 'keep').write_bytes(b'old data\n')
        installed = target / 'var/lib/pkg/installed/probe'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(b'not a state directory\n')
        result = self.shell('pkg install -A "$1" --root "$2"', package, target)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(shared.read_bytes(), b'old loadable\n')
        self.assertEqual(stat.S_IMODE(shared.stat().st_mode), 0o640)
        self.assertEqual((data / 'keep').read_bytes(), b'old data\n')
        self.assertEqual(list(data.iterdir()), [data / 'keep'])
        self.assertEqual(installed.read_bytes(), b'not a state directory\n')
        self.assertEqual(list(shared.parent.iterdir()), [shared])
        self.assertEqual(list(data.parent.iterdir()), [data])

    def test_install_refuses_to_replace_a_loadable_directory(self):
        package, _ = self.package()
        target = self.root / 'target'
        shared = target / 'usr/lib/bash-os/loadables/probe.so'
        shared.mkdir(parents=True)
        (shared / 'keep').write_bytes(b'unrelated\n')
        result = self.shell('pkg install -A "$1" --root "$2"', package, target)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((shared / 'keep').read_bytes(), b'unrelated\n')
        self.assertEqual(list(shared.parent.iterdir()), [shared])


if __name__ == '__main__':
    unittest.main()
