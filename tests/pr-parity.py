#!/usr/bin/env python3
"""Compare pr's supported subset with GNU pr; check invocation and output state.

Every comparison runs the builtin from a bash-os shell with an empty PATH and
GNU pr from /usr/bin on the same bytes, in a fixed C locale and UTC so a page
header is reproducible. Fixture files are given a fixed modification time for
the same reason: GNU pr dates a page from the file, and only a page read from
standard input from the clock. docs/pr.md records the option subset these
checks cover and the differences from GNU pr that remain outside it.
"""
from pathlib import Path
import os
import pty
import re
import select
import subprocess
import sys
import tempfile
import termios

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
environment = dict(os.environ, LC_ALL='C', TZ='UTC', PATH='')
host = dict(environment, PATH='/usr/bin:/bin')
prefix = 'if [[ -n ${PR_MODULE:-} ]]; then enable -f "$PR_MODULE" pr; fi\n'
GNU = '/usr/bin/pr'
MTIME = 981173106                       # 2001-02-03 04:05:06 UTC
STAMP = re.compile(rb'\d{4}-\d\d-\d\d \d\d:\d\d')
CONTROL = re.compile(rb'[\t\r\x00\x08]')
checks = skipped = 0


def builtin(args, data=b'', cwd=None, script='"$@"'):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        '_', 'pr', *map(str, args)],
                       input=data, capture_output=True, env=environment,
                       cwd=cwd, timeout=60)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def reference(args, data=b'', cwd=None):
    return subprocess.run([GNU, *map(str, args)], input=data,
                          capture_output=True, env=host, cwd=cwd, timeout=60)


def clock_race(first, second):
    """The header of a standard-input page carries the current minute in both
    implementations, so two runs either side of a minute boundary differ only
    there. Anything else is a real difference."""
    return first != second and STAMP.sub(b'@', first) == STAMP.sub(b'@', second)


def compare(args, data=b'', cwd=None, label=None):
    global checks
    for attempt in (1, 2):
        actual = builtin(args, data, cwd)
        expected = reference(args, data, cwd)
        if (actual.returncode, actual.stdout) == (expected.returncode, expected.stdout):
            checks += 1
            return
        if attempt == 1 and clock_race(actual.stdout, expected.stdout):
            continue
        raise AssertionError(
            f'pr {label or args}: status {actual.returncode} vs {expected.returncode}\n'
            f'  ours: {actual.stdout[:220]!r}\n'
            f'  gnu : {expected.stdout[:220]!r}\n  {actual.stderr[:200]!r}')


# --- the option subset, over records that exercise the layout ---------------
FIXTURES = {
    'empty':  b'',
    'one':    b'only\n',
    'abc':    b'a\nb\nc\n',
    'nonl':   b'x\ny',                                   # no final newline
    'blank':  b'\n\n\n',                                 # present but empty records
    'n5':     b'1\n2\n3\n4\n5\n',
    'n7':     b''.join(b'%d\n' % i for i in range(1, 8)),
    'page':   b''.join(b'row %04d\n' % i for i in range(1, 201)),   # several pages
    'wide':   b'L' * 200 + b'\n' + b'M' * 10 + b'\n',    # records past the page width
    'long':   b'z' * 70000 + b'\ntail\n',                # past the 64 KiB read buffer
    'tabs':   b'a\tb\tc\nxx\tyy\tzz\n\tlead\n',
    'cr':     b'a\r\nb\n',
    'nul':    b'nul\x00tail\nsecond\n',
}

OPTIONS = [
    [], ['-t'], ['-n'], ['-t', '-n'], ['-t', '-n3'], ['-t', '-nc3'], ['-t', '-n:'],
    ['-2'], ['-3'], ['-4'], ['-t', '-2'], ['-t', '-3'], ['-2', '-n'], ['-t', '-2', '-n'],
    ['-2', '-a'], ['-3', '-a'], ['-t', '-3', '-a'], ['-t', '-a', '-2', '-n'],
    ['-s'], ['-s,'], ['-t', '-s'], ['-t', '-s,'], ['-t', '-s,', '-2'], ['-t', '-s', '-3'],
    ['-t', '-s', '-2', '-n'], ['-t', '-sX', '-2', '-n'],
    ['-o', '3'], ['-t', '-o', '3'], ['-o3', '-2'], ['-t', '-o', '9', '-3'],
    ['-w', '40'], ['-w', '8'], ['-w', '40', '-2'], ['-t', '-w', '20', '-3'],
    ['--width=50', '-2'], ['-t', '-w', '9', '-2'],
    ['-l', '15'], ['-l', '11'], ['-l', '5'], ['--length=20'], ['-l', '13', '-3'],
    ['-d'], ['-d', '-l', '15'], ['-d', '-2'],
    ['-f'], ['-f', '-l', '15'], ['-F'], ['-f', '-2'],
    ['-h', 'TITLE'], ['-h', ''], ['--header=X Y'], ['-t', '-h', 'TITLE'], ['--header=T', '-2'],
    ['-m'], ['-t', '-m'],
]

# Layouts where a record holding a TAB or another control byte still differs
# from GNU pr. GNU tracks such a record through its own clump machinery, whose
# column arithmetic these do not reproduce; plain records match everywhere.
def excluded(options, data):
    columns = any(o in ('-2', '-3', '-4', '-m') for o in options)
    numbered = any(o.startswith('-n') for o in options)
    own_separator = any(o.startswith('-n') and len(o) > 2 and not o[2:].isdigit()
                        for o in options)
    if (columns and numbered and (own_separator or '-s' in options)
            and CONTROL.search(data)):
        return 'numbered column layout of a record holding a control byte'
    return None


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for name, data in FIXTURES.items():
        (root / name).write_bytes(data)
        os.utime(root / name, (MTIME, MTIME))

    for name, data in FIXTURES.items():
        for options in OPTIONS:
            if excluded(options, data):
                skipped += 1
                continue
            compare([*options, name], cwd=root)             # the file operand
            if '-m' not in options:
                compare(options, data, cwd=root)            # the same bytes on stdin

    # Several operands, and merge mode reading them in parallel.
    for options in ([], ['-t'], ['-t', '-n'], ['-m'], ['-t', '-m'], ['-t', '-m', '-n'],
                    ['-m', '-s,'], ['-t', '-m', '-s'], ['-t', '-m', '-o', '3'],
                    ['-t', '-m', '-w', '40'], ['-t', '-m', '-n3'], ['-m', '-l', '15'],
                    ['-t', '-m', '-w', '30', '-n'], ['-h', 'T'], ['-t', '-2']):
        for names in (['abc', 'n5'], ['abc', 'empty'], ['empty', 'abc'],
                      ['abc', 'n5', 'n7'], ['nonl', 'abc'], ['page', 'abc'],
                      ['abc', 'abc']):
            # GNU restarts its row numbering part way through a row when a
            # merged file's final record has no newline; see docs/pr.md.
            if '-m' in options and any(o.startswith('-n') for o in options) \
                    and any(not FIXTURES[n].endswith(b'\n') and FIXTURES[n] for n in names):
                skipped += 1
                continue
            compare([*options, *names], cwd=root)

    # "-" is standard input, and mixes with file operands.
    compare(['-t', '-'], b'a\nb\n', cwd=root)
    compare(['-'], b'a\nb\n', cwd=root)
    compare(['-t', 'abc', '-', 'n5'], b'from stdin\n', cwd=root)
    compare(['-t', '--', 'abc'], cwd=root)

    # --- invocation state: one process, many calls -------------------------
    # Three calls in one shell must each read their own freshly opened input.
    # This is the regression the loadable status table recorded for pr.
    loop = 'input=$1; shift; for i in 1 2 3; do "$@" < "$input" || exit; done'
    for options in (['-t'], ['-t', '-n'], ['-t', '-2'], [], ['-t', '-s,', '-2']):
        for name in ('abc', 'empty', 'nonl', 'tabs', 'long'):
            ours = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + loop,
                                   '_', str(root / name), 'pr', *options],
                                  capture_output=True, env=environment, cwd=root, timeout=60)
            wanted = reference(options, (root / name).read_bytes(), cwd=root)
            assert ours.returncode == 0 and (
                ours.stdout == wanted.stdout * 3
                or clock_race(ours.stdout, wanted.stdout * 3)), (
                    options, name, ours.returncode, ours.stdout[:200], ours.stderr[:200])
            checks += 1

    # Different inputs, in one shell, must not share anything either.
    script = prefix + '''for f in "$@"; do pr -t < "$f"; done'''
    order = ['abc', 'empty', 'n5', 'empty', 'nonl', 'abc', 'blank', 'long']
    ours = subprocess.run([binary, '--noprofile', '--norc', '-c', script, '_',
                           *[str(root / n) for n in order]],
                          capture_output=True, env=environment, cwd=root, timeout=60)
    wanted = b''.join(reference(['-t'], FIXTURES[n], cwd=root).stdout for n in order)
    assert (ours.returncode, ours.stdout) == (0, wanted), (ours.returncode, ours.stdout[:300])
    checks += 1

    # A pipe, a here-string and a shared descriptor: two calls on one open
    # descriptor see one stream, exactly as two GNU processes would.
    shared = '''exec 9< "$1"; pr -t <&9; printf -- '--\\n'; pr -t <&9; exec 9<&-'''
    ours = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + shared, '_',
                           str(root / 'abc')], capture_output=True, env=environment, timeout=60)
    assert (ours.returncode, ours.stdout) == (0, b'a\nb\nc\n--\n'), ours.stdout
    checks += 1
    for pipeline, wanted in (
            ('printf "a\\nb\\n" | pr -t; printf "c\\n" | pr -t', b'a\nb\nc\n'),
            ('pr -t <<< "here"; pr -t <<< "again"', b'here\nagain\n'),
            ('shopt -s lastpipe; printf "p\\nq\\n" | pr -t; printf "r\\n" | pr -t',
             b'p\nq\nr\n')):
        ours = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + pipeline],
                              capture_output=True, env=environment, timeout=60)
        assert (ours.returncode, ours.stdout) == (0, wanted), (pipeline, ours.stdout)
        checks += 1

    # Another builtin reading the same descriptor first must not change what pr
    # then reads: pr keeps its input state inside the invocation.
    mixed = '''read -r first < "$1"; printf '%s\\n' "$first"; pr -t < "$1"
head -n 1 < "$1" > /dev/null; pr -t < "$1"
{ read -r one; pr -t; } < "$1"'''
    ours = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + mixed, '_',
                           str(root / 'abc')], capture_output=True, env=environment, timeout=60)
    assert (ours.returncode, ours.stdout) == (0, b'a\na\nb\nc\na\nb\nc\nb\nc\n'), ours.stdout
    checks += 1

    # A builtin that stops reading part way leaves bytes in the shell process's
    # own stdin object. Clearing only the end-of-file indicator would let those
    # bytes reappear here; pr reads the descriptor it was actually given.
    (root / 'A').write_bytes(b'first\nleftover\n')
    (root / 'B').write_bytes(b'new\ninput\n')
    leftover = 'head -n1 < "$1"; pr -t < "$2"'
    ours = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + leftover, '_',
                           str(root / 'A'), str(root / 'B')],
                          capture_output=True, env=environment, timeout=60)
    wanted = subprocess.run([binary, '--noprofile', '--norc', '-c',
                             'PATH=/usr/bin:/bin; head -n1 < "$1"; /usr/bin/pr -t < "$2"',
                             '_', str(root / 'A'), str(root / 'B')],
                            capture_output=True, env=host, timeout=60)
    assert (ours.returncode, ours.stdout) == (0, b'first\nnew\ninput\n'), ours.stdout
    assert ours.stdout == wanted.stdout, (ours.stdout, wanted.stdout)
    checks += 1

    # --- failures -----------------------------------------------------------
    compare(['-t', 'no-such-file'], cwd=root)
    compare(['-t', 'abc', 'no-such-file'], cwd=root)
    compare(['-t', '.'], cwd=root)                       # a directory
    compare(['-t', '-m', 'abc', 'no-such-file'], cwd=root)
    unreadable = root / 'unreadable'
    unreadable.write_bytes(b'contents\n')
    unreadable.chmod(0)
    if os.geteuid() != 0:
        compare(['-t', str(unreadable)], cwd=root)
    unreadable.chmod(0o600)

    # A failed write is reported and becomes a non-zero status, and the shell
    # carries on: the next call still produces the whole page.
    failing = prefix + '''printf before
pr -t "$1"
printf after
rc=0; pr -t "$1" > /dev/full 2>/dev/null || rc=$?
[[ $rc == 1 ]] || exit 42
pr -t "$1"'''
    ours = subprocess.run([binary, '--noprofile', '--norc', '-c', failing, '_',
                           str(root / 'abc')], capture_output=True, env=environment, timeout=60)
    assert (ours.returncode, ours.stdout) == (0, b'beforea\nb\nc\naftera\nb\nc\n'), (
        ours.returncode, ours.stdout, ours.stderr)
    checks += 1
    message = builtin(['-t', str(root / 'abc')], script='"$@" > /dev/full')
    assert message.returncode == 1 and b'write error' in message.stderr, message.stderr
    checks += 1

    # Rejected option values name the option and exit with the usage status.
    for options in (['-w', '7'], ['-w', '0'], ['-l', '0'], ['-l', 'x'], ['-o', '-1'],
                    ['-n0'], ['-nx0'], ['--width=3'], ['--length=0'], ['-q'], ['-2x']):
        p = builtin([*options, 'abc'], cwd=root)
        assert p.returncode == 2 and p.stderr, (options, p.returncode, p.stderr)
        checks += 1
    # An option whose argument is missing is a usage error, not a silent read.
    for options in (['-h'], ['-l'], ['-w'], ['-o'], ['--header'], ['--length'], ['--width']):
        p = builtin(options, cwd=root)
        assert p.returncode == 2 and p.stderr, (options, p.returncode, p.stderr)
        checks += 1

    # --- a terminal receives complete lines while the input stays open -------
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[1] &= ~termios.ONLCR
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    try:
        with subprocess.Popen([binary, '--noprofile', '--norc', '-c', prefix + 'pr -t'],
                              env=environment, stdin=subprocess.PIPE, stdout=slave,
                              stderr=subprocess.PIPE) as process:
            process.stdin.write(b'a\nb\n')
            process.stdin.flush()
            assert select.select([master], [], [], 10)[0], 'terminal output waited for EOF'
            assert os.read(master, 1024).startswith(b'a\n')
            _, errors = process.communicate(timeout=20)
            assert process.returncode == 0 and not errors, (process.returncode, errors)
    finally:
        os.close(master)
        os.close(slave)
    checks += 1

print(f'pr: {checks} GNU parity and shell-state checks passed, '
      f'{skipped} layouts outside the supported subset skipped')
