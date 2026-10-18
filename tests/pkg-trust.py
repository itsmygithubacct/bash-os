#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unreadable trust files must not turn a signed package into an accepted one."""
import base64
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
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'out/bash').resolve())


class PackageTrust(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix='pkg-trust-elf-')
        cls.addClassCleanup(directory.cleanup)
        source, shared = (Path(directory.name) / name for name in ('probe.c', 'probe.so'))
        source.write_text('int probe(void) { return 0; }\n')
        subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC', '-nostdlib',
                        str(source), '-o', str(shared)], check=True, timeout=30)
        cls.payload = shared.read_bytes()

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='pkg-trust-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.target = self.root / 'installation'
        self.target.mkdir()
        self.trusted = self.root / 'trusted'
        self.trusted.mkdir()
        self.revoked = self.root / 'revoked'
        self.package = self.root / 'probe.pkg'
        self.signature = self.root / 'probe.pkg.sig'
        self.keynum = os.urandom(8)
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (self.trusted / 'test.pub').write_text('untrusted comment: disposable test key\n' +
            base64.b64encode(b'Ed' + self.keynum + public).decode() + '\n')
        manifest = ('type: loadable\nname: probe\nversion: 1\nbuiltin: probe\n'
                    f'abi: bash-5.3\narch: {platform.machine()}\n'
                    f'sha256: {hashlib.sha256(self.payload).hexdigest()}\n')
        with tarfile.open(self.package, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name, body in (('MANIFEST', manifest.encode()), ('loadable/probe.so', self.payload)):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(body), 0o644
                archive.addfile(entry, io.BytesIO(body))
        signature = private.sign(self.package.read_bytes())
        self.signature.write_text('untrusted comment: disposable test signature\n' +
            base64.b64encode(b'Ed' + self.keynum + signature).decode() + '\n')

    def shell(self, script):
        env = {**os.environ, 'LC_ALL': 'C', 'HOME': str(self.root),
               'BASHSIGNIFY_TRUSTED_KEYS_DIR': str(self.trusted),
               'BASHSIGNIFY_REVOKED_KEYS': str(self.revoked)}
        env.pop('BASH_ENV', None)
        env.pop('ENV', None)
        if module := os.environ.get('PKG_TEST_LOADABLE'):
            script = 'enable -f ' + shlex.quote(module) + ' pkg || exit; ' + script
        if preload := os.environ.get('PKG_TEST_ASAN_LIB'):
            env.update(LD_PRELOAD=preload, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        result = subprocess.run([BINARY, '--noprofile', '--norc', '-c', 'PATH=; ' + script,
                                 'pkg-trust', str(self.package), str(self.target)],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertNotIn('AddressSanitizer', result.stderr)
        self.assertNotIn('runtime error:', result.stderr)
        return result

    def assert_refused(self, script):
        result = self.shell(script)
        self.assertEqual(result.returncode, 1, (result.stdout, result.stderr))
        self.assertTrue(result.stderr)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_missing_or_empty_revocation_list_allows_a_trusted_signature(self):
        for contents in (None, '', '# no keys retired\n\n', '0000000000000000 # another key\n'):
            with self.subTest(contents=contents):
                if contents is not None:
                    self.revoked.write_text(contents)
                result = self.shell('pkg verify "$1"')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'verify probe\tpackage=ok\n')

    def test_revoked_key_is_refused_with_or_without_unsigned_override(self):
        self.revoked.write_text(self.keynum.hex().upper() + ' # retired\n')
        self.assert_refused('pkg verify "$1"')
        self.assert_refused('pkg install -A "$1" --root "$2"')

    def test_revocation_read_error_is_refused(self):
        self.revoked.mkdir()  # fopen succeeds; reading fails with EISDIR.
        self.assert_refused('pkg verify "$1"')
        self.assert_refused('pkg install -A "$1" --root "$2"')

    def test_revocation_open_error_is_refused(self):
        self.revoked.symlink_to(self.revoked.name)
        self.assert_refused('pkg verify "$1"')
        self.assert_refused('pkg install -A "$1" --root "$2"')

    @unittest.skipIf(os.geteuid() == 0, 'root can read mode-000 files')
    def test_unreadable_revocations_are_refused(self):
        self.revoked.write_text(self.keynum.hex() + '\n')
        self.revoked.chmod(0)
        self.addCleanup(self.revoked.chmod, 0o600)
        self.assert_refused('pkg verify "$1"')

    def test_missing_signature_still_allows_explicit_unsigned_install(self):
        self.signature.unlink()
        result = self.shell('pkg install -A "$1" --root "$2"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target / 'usr/lib/bash-os/loadables/probe.so').read_bytes(), self.payload)

    def test_signature_lookup_error_is_not_absence(self):
        self.signature.unlink()
        self.signature.symlink_to(self.signature.name)
        self.assert_refused('pkg install -A "$1" --root "$2"')

    @unittest.skipIf(os.geteuid() == 0, 'root can search mode-000 directories')
    def test_unsearchable_signature_target_is_not_absence(self):
        hidden = self.root / 'hidden'
        hidden.mkdir()
        self.signature.rename(hidden / 'signature')
        self.signature.symlink_to(hidden / 'signature')
        hidden.chmod(0)
        self.addCleanup(hidden.chmod, 0o700)
        self.assert_refused('pkg install -A "$1" --root "$2"')

    def test_shell_can_verify_after_a_read_error(self):
        self.revoked.mkdir()
        empty = self.root / 'empty'
        empty.write_bytes(b'')
        result = self.shell('pkg verify "$1"; printf "first=%s\\n" "$?"; '
                            'BASHSIGNIFY_REVOKED_KEYS=$HOME/empty; pkg verify "$1"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'first=1\nverify probe\tpackage=ok\n')


if __name__ == '__main__':
    unittest.main()
