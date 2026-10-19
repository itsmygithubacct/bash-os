#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check every apply pathname before publishing a multi-file patch."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'out/bash').resolve())
GIT = shutil.which('git')


def edit(name):
    return (f'diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n'
            '@@ -1 +1 @@\n-one\n+two\n').encode()


def addition(name):
    return (f'diff --git a/{name} b/{name}\nnew file mode 100644\n'
            f'--- /dev/null\n+++ b/{name}\n@@ -0,0 +1 @@\n+created\n').encode()


def rename(old, new):
    return (f'diff --git a/{old} b/{new}\nsimilarity index 100%\n'
            f'rename from {old}\nrename to {new}\n').encode()


class ApplyPaths(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='git-apply-paths-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.repo = self.root / 'repo'
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'LC_ALL': 'C',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        subprocess.run([GIT, 'init', '-q', '-b', 'main', str(self.repo)],
                        env=self.env, check=True, timeout=15)
        (self.repo / 'first').write_bytes(b'one\n')

    def run_git(self, args, patch=b''):
        result = subprocess.run([BINARY, '--noprofile', '--norc', '-c',
                                 'PATH=; git "$@"', 'apply-test', *args],
                                cwd=self.repo, env=self.env, input=patch,
                                capture_output=True, timeout=15)
        self.assertNotIn(b'AddressSanitizer', result.stderr)
        self.assertNotIn(b'runtime error:', result.stderr)
        return result

    def boundary_directory(self):
        directory = self.repo
        while len(os.fsencode(directory)) < 4090:
            width = min(200, 4090 - len(os.fsencode(directory)) - 1)
            self.assertGreater(width, 0)
            directory /= 'd' * width
            directory.mkdir()
        return directory

    def assert_no_partial_write(self, patch):
        for args in (['apply', '--check'], ['apply']):
            with self.subTest(args=args):
                result = self.run_git(args, edit('first') + patch)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.repo / 'first').read_bytes(), b'one\n')

    def test_long_rename_source_never_reads_or_removes_a_shorter_name(self):
        directory = self.boundary_directory()
        sentinel = directory / 'abcd'
        sentinel.write_bytes(b'keep shortened-name sentinel\n')
        source = (directory / 'abcdefghijklmnop').relative_to(self.repo).as_posix()
        self.assert_no_partial_write(rename(source, 'moved'))
        self.assertEqual(sentinel.read_bytes(), b'keep shortened-name sentinel\n')
        self.assertFalse((self.repo / 'moved').exists())

    def test_long_rename_destination_keeps_the_source_and_shorter_target(self):
        directory = self.boundary_directory()
        sentinel = directory / 'abcd'
        sentinel.write_bytes(b'keep target\n')
        (self.repo / 'source').write_bytes(b'keep source\n')
        target = (directory / 'abcdefghijklmnop').relative_to(self.repo).as_posix()
        self.assert_no_partial_write(rename('source', target))
        self.assertEqual(sentinel.read_bytes(), b'keep target\n')
        self.assertEqual((self.repo / 'source').read_bytes(), b'keep source\n')

    def test_long_deletion_never_removes_a_shorter_name(self):
        directory = self.boundary_directory()
        sentinel = directory / 'abcd'
        sentinel.write_bytes(b'one\n')
        source = (directory / 'abcdefghijklmnop').relative_to(self.repo).as_posix()
        patch = (f'diff --git a/{source} b/{source}\ndeleted file mode 100644\n'
                 f'--- a/{source}\n+++ /dev/null\n@@ -1 +0,0 @@\n-one\n').encode()
        self.assert_no_partial_write(patch)
        self.assertEqual(sentinel.read_bytes(), b'one\n')

    def test_long_addition_is_rejected_before_an_earlier_patch_is_written(self):
        name = '/'.join(['d' * 200] * 22 + ['entry'])
        self.assert_no_partial_write(addition(name))
        self.assertFalse((self.repo / ('d' * 200)).exists())

    def test_index_only_patch_keeps_long_valid_paths(self):
        name = '/'.join(['d' * 200] * 22 + ['entry'])
        result = self.run_git(['apply', '--cached'], addition(name))
        self.assertEqual(result.returncode, 0, result.stderr)
        names = subprocess.check_output([GIT, 'ls-files', '-z'], cwd=self.repo, env=self.env)
        self.assertEqual(names, name.encode() + b'\0')
        self.assertFalse((self.repo / ('d' * 200)).exists())

    def test_valid_boundary_source_can_be_renamed(self):
        directory = self.boundary_directory()
        source = directory / 'abcd'
        source.write_bytes(b'keep contents\n')
        old = source.relative_to(self.repo).as_posix()
        result = self.run_git(['apply'], rename(old, 'moved'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo / 'moved').read_bytes(), b'keep contents\n')
        self.assertFalse(source.exists())

    def test_later_valid_path_does_not_clear_an_earlier_planning_failure(self):
        result = self.run_git(['apply'], edit('missing') + edit('first'))
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo / 'first').read_bytes(), b'one\n')

    def test_long_added_line_is_kept_whole(self):
        body = b'Z' * 9000
        patch = (b'diff --git a/long.txt b/long.txt\nnew file mode 100644\n'
                 b'--- /dev/null\n+++ b/long.txt\n@@ -0,0 +1 @@\n+' + body + b'\n')
        result = self.run_git(['apply'], patch)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo / 'long.txt').read_bytes(), body + b'\n')

    def test_cached_path_longer_than_the_parse_buffer_is_kept(self):
        name = '/'.join(['d' * 200] * 42 + ['entry'])
        self.assertGreater(len('+++ b/' + name), 8191)
        result = self.run_git(['apply', '--cached'], addition(name))
        self.assertEqual(result.returncode, 0, result.stderr)
        names = subprocess.check_output([GIT, 'ls-files', '-z'], cwd=self.repo,
                                         env=self.env)
        self.assertEqual(names, name.encode() + b'\0')
        self.assertFalse((self.repo / ('d' * 200)).exists())

    def test_nested_rename_strip_matches_git(self):
        nested = self.repo / 'a' / 'b'
        nested.mkdir(parents=True)
        (nested / 'file').write_bytes(b'x\n')
        subprocess.run([GIT, 'add', '-A'], cwd=self.repo, env=self.env,
                       check=True, timeout=15)
        subprocess.run([GIT, '-c', 'user.email=t@example', '-c', 'user.name=t',
                        'commit', '-q', '-m', 'nested'],
                       cwd=self.repo, env=self.env, check=True, timeout=15)
        patch = (b'diff --git a/a/b/file b/c/d/other\n'
                 b'similarity index 100%\n'
                 b'rename from a/b/file\nrename to c/d/other\n')

        def names():
            found = []
            for dirpath, dirs, files in os.walk(self.repo):
                dirs[:] = [item for item in dirs if item != '.git']
                for name in files:
                    found.append(Path(dirpath, name).relative_to(self.repo).as_posix())
            return sorted(found)

        def restore():
            subprocess.run([GIT, 'reset', '-q', '--hard'], cwd=self.repo,
                           env=self.env, check=True, timeout=15)
            subprocess.run([GIT, 'clean', '-q', '-fd'], cwd=self.repo,
                           env=self.env, check=True, timeout=15)

        for args in (['apply'], ['apply', '-p0'], ['apply', '-p1'], ['apply', '-p2']):
            with self.subTest(args=args):
                real = subprocess.run([GIT, *args], cwd=self.repo, env=self.env,
                                      input=patch, capture_output=True, timeout=15)
                real_names = names()
                restore()
                bash = self.run_git(args, patch)
                self.assertEqual(bash.returncode, real.returncode, bash.stderr)
                self.assertEqual(bash.stderr, real.stderr)
                self.assertEqual(names(), real_names)
                restore()


if __name__ == '__main__':
    unittest.main()
