#!/usr/bin/env python3
"""Behavioral tests using production blockdev.c behind closed syscall shims.

No compilation occurs here. Build modules separately with sol-blockdev-build.sh.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/sol-blockdev-fixtures.json'
DEVICES = json.loads(FIXTURE.read_text())['devices']
REQUESTS = {'--getsz': 'BLKGETSIZE64', '--getsize64': 'BLKGETSIZE64',
            '--getsize': 'BLKGETSIZE', '--getss': 'BLKSSZGET',
            '--getbsz': 'BLKBSZGET', '--getro': 'BLKROGET',
            '--setro': 'BLKROSET 1', '--setrw': 'BLKROSET 0',
            '--flushbufs': 'BLKFLSBUF', '--rereadpt': 'BLKRRPART'}
QUERIES = list(REQUESTS)[:6]


def setup(module):
    lines = [f'enable -f {shlex.quote(str(module))} blockdev blockdev_fixture || exit 90',
             'PATH=', 'blockdev_fixture reset || exit 91']
    for d in DEVICES:
        fields = [d[k] for k in ('name', 'bytes', 'sectors', 'ss', 'bsz', 'ro')]
        lines.append('blockdev_fixture device ' + shlex.join(map(str, fields)) + ' v1 || exit 92')
    return '\n'.join(lines) + '\n'


def environment(preload=None):
    env = dict(os.environ, LC_ALL='C')
    env.pop('BASH_ENV', None)
    if preload:
        env.update(LD_PRELOAD=str(preload), ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def invoke(binary, script, preload=None):
    return subprocess.run([str(binary), '--noprofile', '--norc', '-c', script],
                          env=environment(preload), capture_output=True, text=True)


def values(actions, devices):
    output = []
    for initial in devices:
        d = dict(initial)
        for action in actions:
            value = {'--getsz': d['bytes'] // 512, '--getsize64': d['bytes'],
                     '--getsize': d['sectors'], '--getss': d['ss'],
                     '--getbsz': d['bsz'], '--getro': int(bool(d['ro']))}.get(action)
            if value is not None:
                output.append(str(value))
            if action in ('--setro', '--setrw'):
                d['ro'] = int(action == '--setro')
    return ''.join(x + '\n' for x in output)


def trace(actions, devices):
    return ''.join('open ' + d['name'] + ' ro\n' +
                   ''.join('ioctl ' + d['name'] + ' ' + REQUESTS[a] + '\n' for a in actions) +
                   'close ' + d['name'] + '\n' for d in devices)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--preload', type=Path)
    args = p.parse_args()
    binary, module = args.binary.resolve(), args.module.resolve()
    prefix = setup(module)
    passed = failed = 0

    def check(name, body, expected, status=0, diagnostic=None, production=False):
        nonlocal passed, failed
        r = invoke(binary, ('' if production else prefix) + body, args.preload)
        good = (r.returncode == status and r.stdout == expected and
                (diagnostic in r.stderr if diagnostic else not r.stderr))
        if good:
            passed += 1
            print('PASS', name)
        else:
            failed += 1
            print('FAIL', name, 'status', r.returncode, 'expected', status,
                  '\nstdout', repr(r.stdout), '\nexpected', repr(expected), '\nstderr', repr(r.stderr))

    for a in QUERIES:
        command = shlex.join(['blockdev', a] + [d['name'] for d in DEVICES])
        check(a + ' metadata and exact request', command + '\nblockdev_fixture trace',
              values([a], DEVICES) + trace([a], DEVICES))
    actions = list(REQUESTS)
    for name, acts, devices in [
            ('all advertised actions, two devices', actions, DEVICES),
            ('state and ordering', ['--getro', '--setro', '--getro', '--setrw', '--getro', '--flushbufs', '--rereadpt'], DEVICES),
            ('more than 32 actions', ['--getss'] * 32 + ['--setro', '--getro', '--setrw', '--getro'], DEVICES[:1])]:
        command = shlex.join(['blockdev'] + acts + [d['name'] for d in devices])
        check(name, command + '\nrc=$?; blockdev_fixture trace; exit "$rc"',
              values(acts, devices) + trace(acts, devices))
    for badargs in [[], ['/fixture/a'], ['--'], ['--getro'], ['--getro', '--'],
                    ['--nonsense', '/fixture/a'], ['-x', '/fixture/a'],
                    ['--getss=4096', '/fixture/a']]:
        check('malformed ' + repr(badargs), shlex.join(['blockdev'] + badargs) +
              '\nrc=$?; blockdev_fixture trace; exit "$rc"', '', 2, 'blockdev:')
    check('explicit option terminator', 'blockdev --getss -- /fixture/a\nblockdev_fixture trace',
          '4096\n' + trace(['--getss'], DEVICES[:1]))
    dash = dict(DEVICES[1], name='-fixture')
    check('dash-prefixed device after terminator',
          'blockdev_fixture device ' + shlex.join(str(dash[k]) for k in
              ('name', 'bytes', 'sectors', 'ss', 'bsz', 'ro')) + ' v1\n'
          'blockdev --getsz -- -fixture\nblockdev_fixture trace',
          values(['--getsz'], [dash]) + trace(['--getsz'], [dash]))
    check('empty operand and later success', "blockdev --getss '' /fixture/b\nrc=$?; blockdev_fixture trace; exit \"$rc\"",
          '512\nopen  ro\n' + trace(['--getss'], DEVICES[1:]), 1, 'No such file')
    check('option after device is operand', 'blockdev --getss /fixture/a --setro\nrc=$?; blockdev_fixture trace; exit "$rc"',
          '4096\n' + trace(['--getss'], DEVICES[:1]) + 'open --setro ro\n', 1, '--setro:')
    for code in (errno.ENOENT, errno.EPERM, errno.EMFILE):
        check('open failure ' + str(code), f'blockdev_fixture fail /fixture/a open {code}\n'
              'blockdev --getss /fixture/a /fixture/b\nrc=$?; blockdev_fixture trace; exit "$rc"',
              '512\nopen /fixture/a ro\n' + trace(['--getss'], DEVICES[1:]), 1, '/fixture/a:')
    check('EACCES retries O_RDWR', f'blockdev_fixture fail /fixture/a open {errno.EACCES}\n'
          'blockdev --getss /fixture/a\nblockdev_fixture trace',
          '4096\nopen /fixture/a ro\nopen /fixture/a rw\nioctl /fixture/a BLKSSZGET\nclose /fixture/a\n')
    check('EACCES retry also fails and next device succeeds',
          f'blockdev_fixture fail /fixture/missing open {errno.EACCES}\n'
          'blockdev --getss /fixture/missing /fixture/b\nrc=$?; blockdev_fixture trace; exit "$rc"',
          '512\nopen /fixture/missing ro\nopen /fixture/missing rw\n' +
          trace(['--getss'], DEVICES[1:]), 1, '/fixture/missing:')
    for a, request in REQUESTS.items():
        # Include a query after the failed action and a second device to prove continuation.
        acts = [a, '--getbsz']
        for code in (errno.EIO, errno.ENOTTY, errno.EPERM):
            out = values(acts, DEVICES[1:])
            expected = '8192\n' + out + trace(acts, DEVICES)
            check(f'{a} failure {code} continues and closes',
                  f'blockdev_fixture fail /fixture/a {request.split()[0]} {code}\n' +
                  shlex.join(['blockdev'] + acts + [d['name'] for d in DEVICES]) +
                  '\nrc=$?; blockdev_fixture trace; exit "$rc"',
                  # If the trailing query has the same request, it also fails.
                  expected if a != '--getbsz' else out + trace(acts, DEVICES), 1, '/fixture/a: ioctl:')
    check('close error continues', 'blockdev_fixture fail /fixture/a close 5\n'
          'blockdev --getss /fixture/a /fixture/b\nrc=$?; blockdev_fixture stats; exit "$rc"',
          '4096\n512\nstats 2 2 2 0 0\nro /fixture/a 0\nro /fixture/b 7\n', 1, '/fixture/a: close:')
    check('state persists across separate calls',
          'blockdev --setro /fixture/a || exit 98\nblockdev --getro /fixture/a || exit 98\n'
          'blockdev --setrw /fixture/a || exit 98\nblockdev --getro /fixture/a || exit 98\n'
          'blockdev_fixture stats',
          '1\n0\nstats 4 4 4 0 0\nro /fixture/a 0\nro /fixture/b 7\n')
    for option in ('--getss /fixture/a', '--help', '--version'):
        check('output failure and recovery ' + option,
              f'blockdev {option} >/dev/full\nrc=$?\nblockdev --getss /fixture/a || exit 93\nexit "$rc"',
              '4096\n', 1, 'write error')
    check('200 repeated calls in one shell and cleanup',
          'blockdev_fixture quiet\nfor ((i=0;i<200;i++)); do\n'
          'blockdev --setro --getro --setrw --getro /fixture/a || exit 94\ndone\nblockdev_fixture stats',
          '1\n0\n' * 200 + 'stats 200 200 800 0 0\nro /fixture/a 0\nro /fixture/b 7\n')
    check('100 repeated ioctl failures and cleanup',
          'blockdev_fixture quiet\nblockdev_fixture fail /fixture/a BLKGETSIZE64 5\n'
          'for ((i=0;i<100;i++)); do\n'
          'blockdev --getsize64 --getss /fixture/a /fixture/b >/dev/null 2>/dev/null\n'
          '[[ $? == 1 ]] || exit 99\ndone\nblockdev_fixture stats',
          'stats 200 200 400 0 0\nro /fixture/a 0\nro /fixture/b 7\n')
    for option, needle in [('--help', '--getsize '), ('--version', 'blockdev 1.0')]:
        r = invoke(binary, prefix + f'blockdev {option}', args.preload)
        if r.returncode == 0 and needle in r.stdout and not r.stderr:
            passed += 1; print('PASS', option)
        else:
            failed += 1; print('FAIL', option, repr(r.stdout), repr(r.stderr))
    # Exercise the actual native open/ioctl path only on a private regular file.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='blockdev-check-') as tmp:
        regular = Path(tmp) / 'regular'; regular.write_bytes(b'fixture')
        check('native read-only ENOTTY and real fd cleanup',
              'PATH=\nbefore=(/proc/$$/fd/*)\nfor ((i=0;i<100;i++)); do\n'
              f'blockdev --getss {shlex.quote(str(regular))} 2>/dev/null && exit 95\n'
              'done\nafter=(/proc/$$/fd/*)\n[[ ${#before[@]} == ${#after[@]} ]]', '', production=True)
    print(f'blockdev: {passed} passed, {failed} failed')
    return int(failed != 0)


if __name__ == '__main__':
    sys.exit(main())
