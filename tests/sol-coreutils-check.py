#!/usr/bin/env python3
"""Dispatcher regression checks. Usage: sol-coreutils-check.py BINARY.

COREUTILS_TEST_LOAD may name a Bash startup file loading instrumented modules.
All mutation fixtures are private; GNU and standalone tac are required oracles.
"""
import collections
import os
from pathlib import Path
import random
import stat
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'out/bash').resolve())
ENV = {k: v for k, v in os.environ.items()
       if k not in ('BASH_ENV', 'ENV', 'OMP_NUM_THREADS', 'OMP_THREAD_LIMIT')}
ENV.update(LC_ALL='C', TZ='UTC', PATH='')
if os.environ.get('COREUTILS_TEST_LOAD'):
    ENV['BASH_ENV'] = os.environ['COREUTILS_TEST_LOAD']
if os.environ.get('COREUTILS_TEST_ASAN'):
    ENV['LD_PRELOAD'] = os.environ['COREUTILS_TEST_ASAN']


def run(args=(), data=b'', script='"$@"', extra=None, affinity=None, **kw):
    return subprocess.run([BINARY, '--noprofile', '--norc', '-c', script, '_', *map(str, args)],
                          input=data, capture_output=True, timeout=20,
                          env={**ENV, **(extra or {})},
                          preexec_fn=(lambda: os.sched_setaffinity(0, affinity)) if affinity else None, **kw)


def reverse(data, sep=b'\n'):
    """Independent bytes oracle: consume the rightmost nonoverlapping separator."""
    end = search = len(data)
    records = []
    while True:
        found = data.rfind(sep, 0, search)
        if found < 0:
            return b''.join(records) + data[:end]
        boundary = found + len(sep)
        records.append(data[boundary:end])
        end, search = boundary, found


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sol-coreutils-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def good(self, p, expected=None):
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(b'AddressSanitizer', p.stderr)
        self.assertNotIn(b'runtime error:', p.stderr)
        if expected is not None:
            self.assertEqual(p.stdout, expected)

    def test_native(self):
        self.good(run(['type', '-t', 'coreutils', 'tac']), b'builtin\nbuiltin\n')

    def test_tac_bytes(self):
        rng = random.Random(20261019)
        cases = [b'', b'x', b'a\nb\nlast', b'\n\n', b'\0\xff\na\0\nlast',
                 bytes(range(256))*1025, b'x'*131073+b'\nlast', b'aaa', b'abababa']
        cases += [bytes(rng.choices([0, 10, 97, 98, 255], k=n)) for n in range(0, 150, 7)]
        for sep in [b'\n', b'\0', b'ab', b'aa', b'xyz']:
            option = ['-s', sep.decode() if sep != b'\0' else '']
            for data in cases:
                with self.subTest(separator=sep, size=len(data)):
                    expected = reverse(data, sep)
                    self.root.joinpath('input').write_bytes(data)
                    for cmd in [['coreutils', 'tac'], ['tac']]:
                        self.good(run([*cmd, *option], data=data), expected)
                        self.good(run([*cmd, *option, self.root/'input']), expected)
                    p = subprocess.run(['/usr/bin/tac', *option], input=data, capture_output=True, env=ENV)
                    self.good(p, expected)

    def test_tac_multiple_repeated_and_errors(self):
        a, b = self.root/'a', self.root/'b'
        a.write_bytes(b'a\0\nb\nlast'); b.write_bytes(b'\xff\nq')
        expected = reverse(a.read_bytes()) + reverse(b.read_bytes())
        for cmd in [['coreutils', 'tac'], ['tac'], ['/usr/bin/tac']]:
            self.good(run([*cmd, a, b, a]), expected + reverse(a.read_bytes()))
            self.good(run([*cmd, a, '-', b, '-'], data=b'in\nlast'), reverse(a.read_bytes())+reverse(b'in\nlast')+reverse(b.read_bytes()))
            self.good(run([*cmd, '--', a]), reverse(a.read_bytes()))
            self.good(run([*cmd, a, b], script='for i in {1..20}; do "$@" || exit; done'), expected*20)
            self.good(run([*cmd, a], script='for i in {1..20}; do "${@:1:$#-1}" < "${!#}" || exit; done'), reverse(a.read_bytes())*20)
            p = run([*cmd, self.root/'missing', b])
            self.assertNotEqual(p.returncode, 0); self.assertTrue(p.stderr)
            self.assertEqual(p.stdout, reverse(b.read_bytes()))
            p = run([*cmd, '-s']); self.assertNotEqual(p.returncode, 0); self.assertTrue(p.stderr)
            p = run([*cmd, '--invalid']); self.assertNotEqual(p.returncode, 0); self.assertTrue(p.stderr)
            p = run([*cmd, a], script='"$@" > /dev/full; r=$?; printf recovered; exit "$r"')
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b'recovered')
        p = run(['coreutils','tac',self.root]); self.assertNotEqual(p.returncode,0); self.assertTrue(p.stderr)
        self.good(run([a],script='printf before; coreutils tac "$1"; printf after'), b'before'+reverse(a.read_bytes())+b'after')
        # Persistent input EOF/error and output-error state must not poison the next call.
        self.good(run([a], script='coreutils tac < "$1"; coreutils tac < "$1"; printf tail'), reverse(a.read_bytes())*2+b'tail')
        self.good(run([a], script='coreutils tac "$1" >/dev/full; coreutils tac "$1"'), reverse(a.read_bytes()))
        self.good(run([a], script='before=(/proc/$$/fd/*); for i in {1..100}; do coreutils tac "$1" >/dev/null || exit; done; after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]'))

    def test_nproc(self):
        masks = [None, {min(os.sched_getaffinity(0))}]
        if len(os.sched_getaffinity(0)) > 1:
            masks.append(set(sorted(os.sched_getaffinity(0))[:2]))
        values = [None, '', '0', '1', '3', '100000', ' 4 \t', '2,8', '2,garbage',
                  '+2', '-1', '2x', 'x', '18446744073709551615', '18446744073709551616']
        environments = [{'OMP_NUM_THREADS': v} for v in values if v is not None]
        environments += [{'OMP_THREAD_LIMIT': v} for v in values if v is not None]
        environments += [{}, {'OMP_NUM_THREADS':'9', 'OMP_THREAD_LIMIT':'2'},
                         {'OMP_NUM_THREADS':'2', 'OMP_THREAD_LIMIT':'9'}]
        for mask in masks:
            for extra in environments:
                for args in [[], ['--all'], ['--ignore=1'], ['--ignore', '100000'], ['--all', '--ignore=1']]:
                    with self.subTest(mask=mask, env=extra, args=args):
                        g = subprocess.run(['/usr/bin/nproc', *args], capture_output=True,
                                           env={**ENV, **extra}, preexec_fn=(lambda: os.sched_setaffinity(0, mask)) if mask else None)
                        self.good(g)
                        self.good(run(['coreutils', 'nproc', *args], extra=extra, affinity=mask), g.stdout)
        for arg in ['', '-1', '1x', '18446744073709551616x']:
            p = run(['coreutils', 'nproc', '--ignore='+arg])
            self.assertNotEqual(p.returncode, 0); self.assertTrue(p.stderr)
        self.good(run(script='export OMP_NUM_THREADS=3; coreutils nproc; export OMP_NUM_THREADS=7 OMP_THREAD_LIMIT=2; coreutils nproc; unset OMP_NUM_THREADS OMP_THREAD_LIMIT; coreutils nproc --ignore=18446744073709551615'), b'3\n2\n1\n')
        p = run(['coreutils','nproc'], script='"$@" >/dev/full'); self.assertNotEqual(p.returncode,0)

    def test_output_failures_and_invalid_inputs(self):
        text = self.root/'text'; text.write_bytes(b'alpha beta\n')
        chain = self.root/'chain'; chain.write_bytes(b'a b\nb c\n')
        commands = [['factor','97'], ['fmt',text], ['tsort',chain],
                    ['nproc'], ['numfmt','--to=iec','1024'], ['groups'],
                    ['shuf','-e','a'], ['yes','fixture']]
        for args in commands:
            with self.subTest(args=args):
                p = run(['coreutils',*args], script='"$@" >/dev/full; r=$?; printf recovered; exit "$r"')
                self.assertNotEqual(p.returncode,0); self.assertTrue(p.stderr)
                self.assertEqual(p.stdout,b'recovered')
        for args in [[], ['unknown'], ['factor','x'], ['fmt','-w','x'],
                     ['shuf','-i','2-1'], ['shred','-n','-1',text],
                     ['install',self.root/'missing',self.root/'dest'],
                     ['mknod',self.root/'invalid','unknown']]:
            with self.subTest(args=args):
                p = run(['coreutils',*args]); self.assertNotEqual(p.returncode,0); self.assertTrue(p.stderr)

    def test_random_invariants(self):
        seed = self.root/'seed'; seed.write_bytes(bytes(range(1, 9)))
        source = '--random-source='+str(seed)
        for args, population, count in [(['-i','1-100'], [str(i).encode() for i in range(1,101)], 100),
                                         (['-n','7','-i','1-100'], [str(i).encode() for i in range(1,101)], 7),
                                         (['-n','0','-i','1-100'], [], 0),
                                         (['-e','a','b','a','c'], [b'a',b'b',b'a',b'c'], 4)]:
            outputs = []
            for i in range(3):
                p = run(['coreutils','shuf',source,*args]); self.good(p)
                lines = p.stdout.splitlines(); self.assertEqual(len(lines),count)
                self.assertFalse(collections.Counter(lines) - collections.Counter(population))
                outputs.append(p.stdout)
            self.assertEqual(len(set(outputs)),1)
        self.good(run(['coreutils','shuf',source,'-i','1-10']), b'10\n8\n2\n5\n9\n6\n4\n7\n3\n1\n')
        for _ in range(3):
            p = run(['coreutils','shuf'], data=b'a\nb\na\nlast')
            self.good(p)
            self.assertEqual(collections.Counter(p.stdout.splitlines()), collections.Counter([b'a',b'b',b'a',b'last']))
        for payload in [b'\0'*8, b'\x01', b'']:
            seed.write_bytes(payload)
            p = run(['coreutils','shuf',source,'-i','1-30'], script='for i in {1..3}; do "$@" || exit; done')
            self.good(p); lines=p.stdout.splitlines()
            self.assertEqual(lines[:30],lines[30:60]); self.assertEqual(lines[:30],lines[60:])
        p = run(['coreutils','shuf','--random-source='+str(self.root/'missing'),'-i','1-10'])
        self.assertNotEqual(p.returncode,0); self.assertTrue(p.stderr)
        target = self.root/'shred'
        for size in [0,1,8193,65537]:
            target.write_bytes(b'x'*size); target.chmod(0o600)
            self.good(run(['coreutils','shred','-n','1',target]))
            self.assertEqual(target.stat().st_size,size)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            self.good(run(['coreutils','shred','-n','0','-z',target]))
            self.assertEqual(target.read_bytes(),b'\0'*size)
        self.good(run(['coreutils','shred','-n','0','-z','-u',target])); self.assertFalse(target.exists())
        target.symlink_to('/dev/full')
        p = run(['coreutils','shred','-n','0','-z','-u','-s','8192',target])
        self.assertNotEqual(p.returncode, 0); self.assertTrue(p.stderr)
        self.assertTrue(target.is_symlink())


if __name__ == '__main__':
    unittest.main()
