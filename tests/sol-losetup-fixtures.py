#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Production losetup with private sysfs/backing files and intercepted ioctls.

No compilation or host loop access. The module is built separately.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

HEADER = f'{"NAME":<14} {"RO":>5} {"OFFSET":>9} {"DIO":>4} BACK-FILE\n'
AUDIT = 'audit live=0 dirs=0 bad=0\nloop0 foreign 0 0 0\n'


def row(device, ro, off, dio, back):
    return f'/dev/{device:<9} {ro:>5} {off:>9} {dio:>4} {back}\n'


def fixture(root):
    (root / 'sys').mkdir()
    (root / 'dev').mkdir()
    for name in ['loop-control'] + [f'loop{i}' for i in range(8)]:
        (root / 'dev' / name).touch()
    image = root / 'image'
    image.write_bytes(bytes(range(256)) * 256)
    (root / 'alias').symlink_to(image)
    for device, back, off, ro, dio in [('loop7', str(image), '4096', '1', '1'),
                                       ('loop2', '/foreign/backing', '0', '0', '0'),
                                       ('loop3', '', '0', '0', '0'),
                                       ('loop1p1', str(image), '0', '0', '0')]:
        p = root / 'sys' / device
        (p / 'loop').mkdir(parents=True)
        for field, value in [('backing_file', back), ('offset', off), ('dio', dio)]:
            (p / 'loop' / field).write_text(value + '\n')
        (p / 'ro').write_text(ro + '\n')
    return image


def environment(preload=None):
    env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
    env.pop('BASH_ENV', None)
    if preload:
        env.update(LD_PRELOAD=str(preload), ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def setup(module, root):
    return (f'enable -f {shlex.quote(str(module))} losetup losetup_fixture || exit 90\n'
            f'losetup_fixture reset {shlex.quote(str(root))} || exit 91\n')


def invoke(binary, script, root, preload=None):
    return subprocess.run([str(binary), '--noprofile', '--norc', '-c', script],
                          cwd=root, env=environment(preload), capture_output=True,
                          text=True, timeout=30)


class LosetupFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sol-losetup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = fixture(self.root)
        self.before = hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.prefix = setup(ARGS.module, self.root)

    def tearDown(self):
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), self.before)

    def run_case(self, script, expected, status=0, error=None):
        r = invoke(ARGS.binary, self.prefix + script, self.root, ARGS.preload)
        self.assertEqual(r.returncode, status, r.stderr)
        self.assertEqual(r.stdout, expected)
        if error:
            self.assertIn(error, r.stderr)
        else:
            self.assertEqual(r.stderr, '')
        self.assertNotIn('AddressSanitizer', r.stderr)
        self.assertNotIn('runtime error:', r.stderr)
        return r

    def test_native_build_cli(self):
        r = invoke(ARGS.binary, 'test "$(type -t losetup)" = builtin || exit; '
                   'losetup --help || exit; losetup --help', self.root, ARGS.preload)
        self.assertEqual(r.returncode, 0, r.stderr)
        halves = r.stdout.split('Set up and control loop devices.')[1:]
        self.assertEqual(len(halves), 2)
        self.assertEqual(halves[0], halves[1])
        self.assertEqual(r.stderr, '')
        for args in ['--bad', '-o -1 --list', '-d', '-f --show', '-f a b', '-d /dev/loop0 extra']:
            r = invoke(ARGS.binary, f'losetup {args}', self.root, ARGS.preload)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertEqual(r.stdout, '')
        r = invoke(ARGS.binary, 'losetup --help >/dev/full; s=$?; losetup --help || exit; exit "$s"',
                   self.root, ARGS.preload)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('write error', r.stderr)
        self.assertEqual(r.stdout, 'Set up and control loop devices.' + halves[0])

    def test_listing_and_association_repeated(self):
        for flag in ['', '-a', '-l', '--all', '--list']:
            r = invoke(ARGS.binary, self.prefix + f'losetup {flag}; losetup_fixture state', self.root, ARGS.preload)
            self.assertEqual(r.returncode, 0, r.stderr)
            expected = (HEADER + row('loop7', 1, 4096, 1, self.image) +
                        row('loop2', 0, 0, 0, '/foreign/backing') + AUDIT)
            self.assertEqual(sorted(r.stdout.splitlines()), sorted(expected.splitlines()))
            self.assertEqual(r.stderr, '')
        for path in [self.image, self.root / 'alias']:
            self.run_case(f'losetup -j {shlex.quote(str(path))}; '
                          f'losetup --list --associated {shlex.quote(str(path))}; losetup_fixture state',
                          (HEADER + row('loop7', 1, 4096, 1, self.image)) * 2 + AUDIT)
        self.run_case('losetup -j /absent; losetup_fixture state', HEADER + AUDIT)

    def test_long_backing_path_and_alias(self):
        # A pathname can exceed the old 512-byte reporting buffer without any
        # individual component exceeding NAME_MAX. Both the literal name and
        # an inode-equivalent alias must find the complete association.
        parent = self.root
        for i in range(4):
            parent = parent / (str(i) + 'x' * 170)
            parent.mkdir()
        backing = parent / 'image'
        backing.write_bytes(b'private long-path fixture')
        alias = self.root / 'long-alias'
        alias.symlink_to(backing)
        (self.root / 'sys/loop7/loop/backing_file').write_text(str(backing) + '\n')
        for path in (backing, alias):
            self.run_case(f'losetup -j {shlex.quote(str(path))}; losetup_fixture state',
                          HEADER + row('loop7', 1, 4096, 1, backing) + AUDIT)

    def test_missing_sysfs(self):
        import shutil
        shutil.rmtree(self.root / 'sys')
        self.run_case('losetup; losetup_fixture state', HEADER + AUDIT)
        (self.root / 'sys').touch()
        self.run_case('losetup; s=$?; losetup_fixture state; exit "$s"', HEADER + AUDIT, 1, 'Not a directory')

    def test_find_and_selected_attach(self):
        q = shlex.quote(str(self.image))
        self.run_case(f'losetup -f; losetup --find; losetup -f --show -r -P -o 0x1000 --sizelimit 8192 {q} || exit; '
                      f'losetup -f; losetup_fixture state',
                      '/dev/loop1\n/dev/loop1\n/dev/loop1\n/dev/loop2\n' + AUDIT +
                      f'loop1 {self.image} 4096 8192 9\n')
        self.run_case(f'losetup /dev/loop2 -r --partscan --offset 17 --sizelimit 31 --show {q} || exit; '
                      'losetup_fixture state',
                      '/dev/loop2\n' + AUDIT + f'loop2 {self.image} 17 31 9\n')
        self.run_case(f'losetup --find {q} || exit; losetup_fixture state',
                      AUDIT + f'loop1 {self.image} 0 0 0\n')

    def test_independent_flags_and_detach_alias(self):
        q = shlex.quote(str(self.image))
        body, expected = '', ''
        for flag, value in [('--read-only', 1), ('--partscan', 8), ('', 0)]:
            body += (f'losetup {flag} /dev/loop2 {q} || exit; losetup_fixture state; '
                     'losetup --detach /dev/loop2 || exit; ')
            expected += AUDIT + f'loop2 {self.image} 0 0 {value}\n'
        self.run_case(body + 'losetup_fixture state', expected + AUDIT)

    def test_no_free_device(self):
        q = shlex.quote(str(self.image))
        body = ''.join(f'losetup /dev/loop{i} {q} || exit; ' for i in range(1, 8))
        self.run_case(body + 'losetup -f; s=$?; losetup_fixture state; exit "$s"',
                      AUDIT + ''.join(f'loop{i} {self.image} 0 0 0\n' for i in range(1, 8)),
                      1, 'No space left on device')

    def test_missing_optional_sysfs_fields(self):
        for path in ['loop7/loop/offset', 'loop7/loop/dio', 'loop7/ro']:
            (self.root / 'sys' / path).unlink()
        self.run_case(f'losetup -j {self.image}; losetup_fixture state',
                      HEADER + row('loop7', 0, 0, 0, self.image) + AUDIT)

    def test_repeated_attach_detach_and_no_fd_leak(self):
        q = shlex.quote(str(self.image))
        self.run_case('for ((i=0;i<100;i++)); do '
                      f'losetup -f -P -o 512 --sizelimit 2048 {q} || exit; '
                      f'losetup_fixture expect 1 512 2048 8 {q} || exit; '
                      'losetup -d /dev/loop1 || exit; losetup_fixture assert || exit; done; '
                      'losetup_fixture counts; losetup_fixture state',
                      'counts 400 400 400\n' + AUDIT)

    def test_readonly_fallback(self):
        q = shlex.quote(str(self.image))
        for error in [errno.EACCES, errno.EROFS]:
            self.run_case(f'losetup_fixture fail 2 {error}; losetup -f --show {q} || exit; '
                          'losetup_fixture trace; losetup_fixture state',
                          '/dev/loop1\n' +
                          'open /dev/loop-control rw\nGET_FREE\nclose /dev/loop-control\n' +
                          f'open {self.image} rw\nopen {self.image} ro\nopen /dev/loop1 ro\n' +
                          f'SET_FD loop1\nSET_STATUS loop1 offset=0 size=0 flags=1 name={str(self.image)[:63]}\n' +
                          f'close /dev/loop1\nclose {self.image}\n' + AUDIT + f'loop1 {self.image} 0 0 1\n')
        self.run_case(f'losetup_fixture fail 2 {errno.EIO}; losetup -f {q}; s=$?; '
                      'losetup_fixture counts; losetup_fixture state; exit "$s"',
                      'counts 2 1 1\n' + AUDIT, 1, 'Input/output error')

    def test_failure_boundaries_and_rollback(self):
        q = shlex.quote(str(self.image))
        for slot, counts, error in [(0, '1 0 0', 'loop-control'), (1, '1 1 1', 'GET_FREE'),
                                    (2, '2 1 1', str(self.image)), (4, '3 2 1', '/dev/loop1'),
                                    (5, '3 3 2', 'SET_FD'), (6, '3 3 4', 'SET_STATUS64')]:
            with self.subTest(slot=slot):
                r = self.run_case(f'losetup_fixture fail {slot} {errno.EIO}; losetup -f {q}; s=$?; '
                              'losetup_fixture counts; losetup_fixture state; exit "$s"',
                              f'counts {counts}\n' + AUDIT, 1, error)
                self.assertIn('Input/output error', r.stderr)
        self.run_case(f'losetup_fixture fail 3 {errno.EACCES}; losetup -r /dev/loop2 {q}; s=$?; '
                      'losetup_fixture state; exit "$s"', AUDIT, 1, 'Permission denied')
        self.run_case(f'losetup_fixture fail 6 {errno.EINVAL}; losetup_fixture fail 7 {errno.EIO}; '
                      f'losetup /dev/loop2 {q}; s=$?; losetup_fixture state; exit "$s"',
                      AUDIT + f'loop2 {self.image} 0 0 0\n', 1, 'rollback LOOP_CLR_FD')

    def test_foreign_ownership_and_detach_failures(self):
        q = shlex.quote(str(self.image))
        r = self.run_case(f'losetup /dev/loop0 {q}; s=$?; losetup_fixture trace; '
                          'losetup_fixture state; exit "$s"',
                          f'open {self.image} rw\nopen /dev/loop0 rw\nSET_FD loop0\n'
                          f'close /dev/loop0\nclose {self.image}\n' + AUDIT, 1, 'Device or resource busy')
        self.assertNotIn('CLR_FD', r.stdout)
        for body, counts, error in [('losetup -d /dev/loop2', '1 1 1', 'No such device'),
                                     ('losetup_fixture fail 4 13; losetup -d /dev/loop2', '1 0 0', 'Permission denied'),
                                     ('losetup_fixture fail 7 5; losetup -d /dev/loop2', '1 1 1', 'Input/output error')]:
            self.run_case(body + '; s=$?; losetup_fixture counts; losetup_fixture state; exit "$s"',
                          'counts ' + counts + '\n' + AUDIT, 1, error)

    def test_invalid_input_does_not_touch_devices(self):
        invalid = ['-d', '-f --show', '--unknown', '-o', '--sizelimit', '-j',
                   '-f -l', '-d -f /dev/loop2', '--show', '-l /dev/loop2',
                   '-f a b', '/dev/loop2 a extra', '-d /dev/loop2 extra',
                   '-j a -f', '--show -d /dev/loop2', '-d /dev/loop2 -o 0',
                   '-d /dev/loop2 --sizelimit 0']
        for flag in ['-o', '--offset', '--sizelimit']:
            for value in ['', ' ', '-1', '18446744073709551616', '1junk', '2K']:
                invalid.append(f'{flag} {shlex.quote(value)} --list')
        for args in invalid:
            with self.subTest(args=args):
                self.run_case(f'losetup {args}; s=$?; losetup_fixture counts; losetup_fixture state; exit "$s"',
                              'counts 0 0 0\n' + AUDIT, 2, 'losetup')

    def test_double_dash_numeric_limits_and_name_truncation(self):
        long = self.root / ('x' * 100)
        long.write_bytes(b'private')
        self.run_case(f'losetup -r -P --offset 18446744073709551615 --sizelimit 0 --show -- /dev/loop2 {long} || exit; '
                      'losetup_fixture trace; losetup_fixture state',
                      '/dev/loop2\n' + f'open {long} ro\nopen /dev/loop2 ro\nSET_FD loop2\n' +
                      f'SET_STATUS loop2 offset=18446744073709551615 size=0 flags=9 name={str(long)[:63]}\n' +
                      f'close /dev/loop2\nclose {long}\n' + AUDIT + f'loop2 {long} 18446744073709551615 0 9\n')
        self.run_case('losetup -- /dev/unknown /outside; s=$?; losetup_fixture state; exit "$s"',
                      AUDIT, 1, 'No such file')

    def test_output_failure_and_recovery(self):
        self.run_case('losetup -f >/dev/full; s=$?; '
                      'losetup -f || exit; losetup_fixture state; exit "$s"',
                      '/dev/loop1\n' + AUDIT, 1, 'write error')
        self.run_case(f'losetup -f --show {self.image} >/dev/full; s=$?; '
                      'losetup_fixture state; exit "$s"',
                      AUDIT + f'loop1 {self.image} 0 0 0\n', 1, 'write error')
        self.run_case('losetup --list >/dev/full; s=$?; '
                      'losetup -j /absent || exit; losetup_fixture state; exit "$s"',
                      HEADER + AUDIT, 1, 'write error')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--preload', type=Path)
    ARGS, rest = parser.parse_known_args()
    ARGS.binary, ARGS.module = ARGS.binary.resolve(), ARGS.module.resolve()
    unittest.main(argv=[__file__, *rest], verbosity=2)
