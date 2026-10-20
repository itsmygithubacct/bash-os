#!/usr/bin/env python3
"""GNU head bytes/status parity, descriptor offsets, and persistent-shell state."""
import itertools
import os
from pathlib import Path
import random
import select
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = 'if [[ -n ${SOL_HEAD_MODULE:-} ]]; then enable -f "$SOL_HEAD_MODULE" head || exit; fi\n'
checks = 0


def run(args, data=b'', script='"$@"', **kwargs):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        'head-test', 'head', *map(str, args)], input=data,
                       capture_output=True, env=env, timeout=20, **kwargs)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def parity(args, data=b''):
    global checks
    actual = run(args, data)
    reference = subprocess.run(['/usr/bin/head', *map(str, args)], input=data,
                               capture_output=True, env=env, timeout=20)
    assert (actual.returncode, actual.stdout) == (reference.returncode, reference.stdout), (
        args, len(data), actual.returncode, reference.returncode,
        actual.stdout[:200], reference.stdout[:200], actual.stderr)
    checks += 1


with tempfile.TemporaryDirectory(prefix='sol-head-') as directory:
    root = Path(directory)
    a, b, empty = (root / name for name in ('a', 'b', 'empty'))
    empty.touch()
    rng = random.Random(59031)
    data_sets = [b'', b'x', b'\n', b'\0', b'a\nb\nc\n', b'a\nb\nc',
                 b'a\0b\0c\0', b'a\0b\nc\0d', bytes(range(256)) * 9,
                 b'x' * 65535 + b'\n' + b'y' * 65536 + b'\nend',
                 b'x' * 200000 + b'\0tail',
                 bytes(rng.randrange(16) for _ in range(140003))]
    for data in data_sets:
        a.write_bytes(data)
        for mode, count, delimiter in itertools.product(
                ('-n', '-c'), ('0', '1', '2', '10', '65536', '-0', '-1', '-2', '-10', '-65536'), ([], ['-z'])):
            args = [*delimiter, mode, count]
            parity(args, data)
            parity([*args, a])
    a.write_bytes(b'a\nb\nc\n'); b.write_bytes(b'Z\nY\nX')
    for mode, count in itertools.product(('-n', '-c'),
            ('+0', '+2', '01', '1b', '1K', '1kB', '1KB', '1KiB', '1M', '1MB',
             '0Q', '1Q', '1QiB', '18446744073709551615',
             '18446744073709551616', '-999999999999999999999999999999', ' K', 'K', 'kB', '-M', '-+1', '- 1', ' 1', '\t2')):
        parity([mode, count], b'ab\n' * 2000)
    for suffix in ('b', 'k', 'm', 'c', 'l', 'q', 'v', 'z', 'cq', 'kv', 'lc', 'cl', 'bc', 'cb', 'bk', 'kb'):
        parity(['-2' + suffix], b'0123\nabc\0tail\n')
    for flags in ([], ['-q'], ['-v'], ['-qv'], ['-vq'], ['--quiet'], ['--silent'], ['--verbose']):
        for files in ([a], [a, b], [a, '-', b], [root/'missing', a],
                      [empty, b], [root/'missing', empty, root/'also-missing', b]):
            parity([*flags, '-n1', *files], b'stdin\nmore\n')
    # GNU line-mode head discards pipe read-ahead between repeated '-' operands.
    # This builtin deliberately preserves the next reader's bytes. Byte mode
    # has an equivalent GNU work unit, while line mode needs an explicit oracle.
    parity(['-c6', '-', '-'], b'stdin\nmore\n')
    p = run(['-n1', '-', '-'], b'stdin\nmore\n')
    assert (p.returncode, p.stdout) == (0, b'==> standard input <==\nstdin\n\n==> standard input <==\nmore\n'), p.stderr
    checks += 1
    for args in (['--bytes=2'], ['--lines=-1'], ['--by', '2'], ['--li=1'],
                 ['--zero-terminated', '-n1'], [a, '-n1', b], ['-qvc2'],
                 ['--', a], ['-n1', '--', a, '-'], ['-n1', '-c2'], ['-n-1', '-c2'], ['-c-1', '-n1'], ['-n-1', '-n0']):
        parity(args, b'ab\0cd\nef\n')
    for args in (['-n'], ['-c'], ['--bytes'], ['--lines='], ['--quiet=yes'],
                 ['--ver'], ['--unknown'], ['-x'], ['-H'], ['-V'], ['-2n'], ['-n', '++1'],
                 ['-n', '--1'], ['-n', '1junk'], ['-c', '1B'], ['-n', '1Ki'],
                 ['-c', '1kk'], ['-n', ' 1'], ['-c', '+'], ['-n', '-']):
        parity(args, b'a\nb\n')
    # Binary early-stop boundaries: the parent's pipe remains readable, and a
    # shared regular-file offset must equal the independent GNU offset.
    fixture = b'a\0b\nc\nd\0e\n' + b'padding\n' * 12000
    a.write_bytes(fixture)
    for args, consumed in ((['-n0'], 0), (['-c0'], 0), (['-n1'], 4),
                           (['-c1'], 1), (['-c5'], 5), (['-zn1'], 2),
                           (['-c65536'], 65536)):
        with a.open('rb', buffering=0) as source:
            p = subprocess.run([binary, '-c', prefix+'head "$@"', '_', *args],
                               stdin=source, capture_output=True, env=env, timeout=20)
            assert (p.returncode, p.stdout, source.tell()) == (0, fixture[:consumed], consumed), (args, p.stderr, source.tell())
            checks += 1
        # Keep the writer open: a first-N call must not wait for EOF.
        read_fd, write_fd = os.pipe()
        os.write(write_fd, fixture[:100])
        try:
            if consumed <= 100:
                p = subprocess.run([binary, '-c', prefix+'head "$@"', '_', *args],
                                   stdin=read_fd, capture_output=True, env=env, timeout=5)
                os.close(write_fd); write_fd = -1
                remaining = os.read(read_fd, 1000)
                assert (p.returncode, p.stdout, remaining) == (0, fixture[:consumed], fixture[consumed:100]), (args, p.stderr)
                checks += 1
        finally:
            os.close(read_fd)
            if write_fd >= 0: os.close(write_fd)
    for args in (['-n', '-1'], ['-c', '-2'], ['-n', '-9999999'], ['-c', '-9999999'], ['-n', '-0']):
        for offset in (0, 3, len(fixture), len(fixture)+5):
            results = []
            for command in ([binary, '-c', prefix+'head "$@"', '_'], ['/usr/bin/head']):
                with a.open('rb', buffering=0) as source:
                    source.seek(offset)
                    p = subprocess.run([*command, *args], stdin=source, capture_output=True, env=env, timeout=20)
                    results.append((p.returncode, p.stdout, source.tell()))
            assert results[0][:2] == results[1][:2], (args, offset, results[0][::2], results[1][::2])
            # GNU can leave a read-ahead block consumed when a large negative
            # count emits nothing. Our persistent-shell contract is stronger:
            # all of the excluded suffix remains available to the next reader.
            assert results[0][2] == offset + len(results[0][1]), (args, offset, results[0][2])
            checks += 1
    p = run([], script='''shopt -s lastpipe
for ((i=0;i<30;i++)); do
  printf 'a\\nb\\nc\\n' | head -c2 || exit
  printf 'a\\nb\\nc\\n' | head -n-1 || exit
done''')
    assert (p.returncode, p.stdout) == (0, b'a\na\nb\n'*30), p.stderr
    checks += 1
    for mode in ('-n0', '-c0', '-n-0', '-c-0'):
        parity([mode, root/'missing', b], b'')
    # Each failure preserves fd ownership, stdout recovery and later options.
    for mode in ('-n1', '-c2', '-n-1', '-c-2', '-zn1'):
        for redirect in ('<&-', '< "$bad"', '> /dev/full', '>&-'):
            script = '''bad=$2; good=$3; mode=$4
ulimit -n 32
for ((j=0;j<40;j++)); do
  rc=0; head "$mode" < "$good" REDIRECT 2>/dev/null || rc=$?
  [[ $rc != 0 ]] || exit 41
  head -c2 < "$good" || exit
done
printf recovered'''.replace('REDIRECT', redirect)
            p = run([root, a, mode], b'a\nb\nc\n', script)
            assert (p.returncode, p.stdout) == (0, b'a\0'*40 + b'recovered'), (mode, redirect, p.stderr)
            checks += 1
        p = run([a, mode], script='''good=$2; mode=$3
exec 0<&-
head "$mode" "$good" >/dev/null || exit
[[ ! -e /proc/self/fd/0 ]]''')
        assert p.returncode == 0, (mode, 'ownership', p.stderr)
        checks += 1
    # Mixed modes in one shell prove no option, buffer, EOF or header state leaks.
    p = run([a], script='''for ((i=0;i<100;i++)); do
head -q -c2 < "$2" || exit
head -v -n0 < "$2" || exit
head -c-9999999 < "$2" || exit
head -n0 < /dev/null || exit
done''')
    assert (p.returncode, p.stdout) == (0, (b'a\0==> standard input <==\n')*100), p.stderr
    checks += 1
    # Ignored SIGPIPE must return an error without killing the shell.
    read_fd, write_fd = os.pipe(); os.close(read_fd)
    try:
        p = subprocess.run([binary, '-c', prefix+'''trap '' PIPE
rc=0; head -c2 <<< ab 2>/dev/null || rc=$?; [[ $rc != 0 ]]'''],
                           stdout=write_fd, stderr=subprocess.PIPE, env=env, timeout=20)
        assert p.returncode == 0, p.stderr
        checks += 1
    finally:
        os.close(write_fd)
    for option in ('--help', '--version'):
        p = run([option])
        assert p.returncode == 0 and p.stdout, (option, p.stderr)
        checks += 1
print(f'sol-head: {checks} GNU byte/status, boundary and persistent-state checks passed')
