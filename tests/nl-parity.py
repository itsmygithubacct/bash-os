#!/usr/bin/env python3
"""Compare nl with GNU nl and BusyBox nl; check repeated input and output state.

Every case runs the builtin inside a bash-os shell and the reference program
as a separate process, then compares exit status and stdout byte for byte.
The repeated-input cases run three invocations in one shell, which is where a
builtin that keeps stdio state across calls stops reading.
"""
from pathlib import Path
import os
import pty
import random
import select
import shutil
import subprocess
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
gnu = [str(Path(os.environ.get('NL_REFERENCE', '/usr/bin/nl')).resolve())]
found = shutil.which('busybox', path='/usr/bin:/bin')
busybox = [found, 'nl'] if found else None
environment = dict(os.environ, LC_ALL='C', PATH='')
# The sanitizer harness supplies a shared object; a plain run uses the builtin.
prefix = 'if [[ -n ${NL_MODULE:-} ]]; then enable -f "$NL_MODULE" nl; fi\n'
checks = 0
failures = []
zero_group_contracts = 0


def builtin(args, data=b'', script='"$@"'):
    return subprocess.run([binary, '-c', prefix + script, '_', 'nl', *map(str, args)],
                          input=data, capture_output=True, env=environment, timeout=60)


def reference(program, args, data=b''):
    return subprocess.run([*program, *map(str, args)], input=data,
                          capture_output=True, env=environment, timeout=60)


def compare(args, data=b'', program=gnu, note='', reference_args=None):
    global checks
    actual = builtin(args, data)
    assert b'AddressSanitizer' not in actual.stderr and b'runtime error:' not in actual.stderr, actual.stderr
    expected = reference(program, args if reference_args is None else reference_args, data)
    checks += 1
    if (actual.returncode, actual.stdout) != (expected.returncode, expected.stdout):
        failures.append((note or Path(program[-1]).name, list(map(str, args)), data[:60],
                         actual.returncode, expected.returncode,
                         actual.stdout[:120], expected.stdout[:120], actual.stderr[:120]))


# GNU 9.4 rejects -l 0; GNU 9.7 accepts it with the same behavior as -l 1.
# Keep testing the builtin's zero-grouping contract even on the older oracle.
zero_probe = reference(gnu, ['-ba', '-l', '0'], b'\n\n')
gnu_zero_grouping = zero_probe.returncode == 0
if not gnu_zero_grouping:
    assert zero_probe.returncode == 1 and not zero_probe.stdout, zero_probe
    assert b'number of blank lines' in zero_probe.stderr, zero_probe.stderr


DOCUMENT = (b'first\n\\:\\:\\:\nH1\nH2\n\\:\\:\nB1\n\n\nB2\n\\:\nF1\nF2\n')
DATA = {
    'empty': b'',
    'plain': b'a\nb\nc\n',
    'blanks': b'a\n\n\n\nz\n',
    'only-newlines': b'\n\n\n',
    'unterminated': b'a\nb',
    'no-newline-at-all': b'x',
    'sections': DOCUMENT,
    'bare-delimiter': b'\\:\\:',
    'crlf-delimiter': b'p\n\\:\\:\r\nq\n',
    'nul-bytes': b'a\x00b\nc\x00\n\x00\n',
    'long-records': b'x' * 100000 + b'\n' + b'y' * 70003 + b'\nshort\n',
}
rng = random.Random(20260908)
DATA['mixed'] = b''.join(rng.choice([b'\n', b'word\n', b'\\:\\:\n', b'\\:\n',
                                     b'\\:\\:\\:\n', b'  spaced \n', b'B1\n'])
                         for _ in range(400))

STYLES = [[], ['-ba'], ['-bt'], ['-bn'], ['-bary'], ['-bpB'], ['-bp'], ['-bp^$'],
          ['-ba', '-ha', '-fa'], ['-ba', '-ht', '-ft'], ['-ba', '-hpH', '-fpF'],
          ['-ba', '-p'], ['-ba', '-ha', '-fa', '-p'], ['-pba']]
NUMBERS = [['-ba', '-w', '1'], ['-ba', '-w', '12'], ['-ba', '-n', 'ln'],
           ['-ba', '-n', 'rz'], ['-ba', '-n', 'rn'], ['-ba', '-s', ''],
           ['-ba', '-s', '::'], ['-ba', '-s', ' | '], ['-ba', '-v', '-3'],
           ['-ba', '-v', '0'], ['-ba', '-i', '2'], ['-ba', '-i', '-1'],
           ['-ba', '-i', '0'], ['-ba', '-w', '3', '-n', 'rz', '-v', '-2'],
           ['-ba', '-v', '9223372036854775807'],
           ['-ba', '-v', '9223372036854775806', '-i', '1']]
BLANKS = [['-ba', '-l', '0'], ['-ba', '-l', '1'], ['-ba', '-l', '2'],
          ['-ba', '-l', '3'], ['-ba', '-l', '2', '-ha', '-fa']]
DELIMS = [['-ba', '-d', '::'], ['-ba', '-d', 'Q'], ['-ba', '-d', ''],
          ['-ba', '-d', 'abc'], ['-ba', '-d', '\\:'], ['-ba', '-ha', '-fa', '-d', ':']]
LONGOPTS = [['--body-numbering=a'], ['--body-numbering', 'a'], ['--number-w=3'],
            ['--starting-line-number', '7', '--body-numbering', 'a'],
            ['--no-renumber', '-ba'], ['--join-blank-lines=2', '-ba'],
            ['--number-format=rz', '-ba'], ['--section-delimiter=@@', '-ba'],
            ['--number-separator', '..', '-ba'], ['--line-increment=3', '-ba']]
ERRORS = [['-w', '0'], ['-w', '-1'], ['-w', 'abc'], ['-w', '3000000000'],
          ['-l', '-1'], ['-l', 'zz'], ['-n', 'zz'], ['-n', 'l'], ['-b', 'x'],
          ['-h', 'x'], ['-f', 'x'], ['-v', 'x'], ['-i', 'x'], ['-Z'], ['-w'],
          ['--nosuch'], ['--n'], ['--num'], ['-bp['],
          ['-v', '99999999999999999999']]
BUSYBOX = [['-ba'], ['-bt'], ['-bn'], ['-ba', '-w', '3'], ['-ba', '-s', ':'],
           ['-ba', '-v', '5'], ['-ba', '-i', '2'], ['-ba', '-w', '2', '-s', '', '-v', '1']]
# BusyBox nl rejects a negative -v, so that GNU-only case stays out of its set.
# BusyBox nl has no logical pages and stops a line at a NUL, so it is compared
# only on inputs where the two references agree by construction.
BUSYBOX_DATA = ['empty', 'plain', 'blanks', 'only-newlines', 'unterminated',
                'no-newline-at-all', 'long-records']

with tempfile.TemporaryDirectory() as directory:
    d = Path(directory)
    paths = {}
    for name, value in DATA.items():
        paths[name] = d / name
        paths[name].write_bytes(value)

    for name, value in DATA.items():
        matrix = STYLES + NUMBERS + BLANKS + DELIMS + LONGOPTS
        if name in ('long-records', 'mixed'):
            matrix = STYLES[:6] + NUMBERS[:4] + BLANKS[:3] + DELIMS[:3]
        for options in matrix:
            reference_options = options
            note = ''
            if options == ['-ba', '-l', '0'] and not gnu_zero_grouping:
                reference_options = ['-ba', '-l', '1']
                note = 'zero-grouping contract (reference -l 1)'
                zero_group_contracts += 2
            compare(options, value, note=note, reference_args=reference_options)
            compare(options + [str(paths[name])], note=note,
                    reference_args=reference_options + [str(paths[name])])
        if name in BUSYBOX_DATA and busybox:
            for options in BUSYBOX:
                compare(options, value, program=busybox, note='busybox')

    for options in ERRORS:
        compare(options, DATA['plain'])
        compare(options + [str(paths['plain'])])

    # Operand handling: several files share one line number, one section and
    # one blank-line run, as nl(1)'s own process-wide state does.
    missing, adir = d / 'missing', d / 'adir'
    adir.mkdir()
    operands = [
        ['-ba', paths['plain'], paths['blanks']],
        ['-ba', paths['sections'], paths['plain']],
        ['-ba', '-l', '2', paths['blanks'], paths['blanks']],
        ['-ba', paths['unterminated'], paths['plain']],
        ['-ba', paths['empty'], paths['plain'], paths['empty']],
        ['-ba', paths['plain'], missing],
        ['-ba', missing, paths['plain']],
        ['-ba', adir],
        ['-ba', adir, paths['plain']],
        ['-ba', '--', paths['plain']],
        [paths['blanks'], '-ba'],
        ['-w', '3', paths['blanks'], '-ba'],
        ['-ba', paths['plain'], paths['plain'], paths['plain']],
    ]
    for options in operands:
        compare(options)
    for options in (['-ba', '-'], ['-ba', '-', '-'], ['-ba', '-', paths['plain']],
                    ['-ba', paths['plain'], '-']):
        compare(options, DATA['plain'])

    # Repeated invocations in one shell. A builtin that leaves stdio at
    # end-of-file numbers the first call only.
    loops = {
        'fresh redirect': 'for i in 1 2 3; do "$@" < "$0"; done',
        'shared redirect': '{ "$@"; "$@"; "$@"; } < "$0"',
        'pipe each time': 'for i in 1 2 3; do cat "$0" | "$@"; done',
        'here-string': 'for i in 1 2 3; do "$@" <<< "a b"; done',
        'file operand': 'for i in 1 2 3; do "$@" "$0"; done',
        'mixed with read': 'for i in 1 2 3; do "$@" < "$0"; read -r l < "$0"; echo "$l"; done',
    }
    for name, value in DATA.items():
        for label, body in loops.items():
            got = subprocess.run([binary, '-c', prefix + body, str(paths[name]), 'nl', '-ba'],
                                 capture_output=True, env=environment, timeout=60)
            want = subprocess.run([binary, '-c', body, str(paths[name]), *gnu, '-ba'],
                                  capture_output=True, env=environment, timeout=60)
            checks += 1
            if (got.returncode, got.stdout) != (want.returncode, want.stdout):
                failures.append((f'repeat/{label}', [name], value[:60], got.returncode,
                                 want.returncode, got.stdout[:120], want.stdout[:120],
                                 got.stderr[:120]))

    # Another builtin's stdio read-ahead must not reach nl. Bash's `stdin`
    # stream belongs to the process, so a builtin that buffers more than it
    # prints leaves those bytes in it, and the next redirection installs a new
    # descriptor without clearing them. Reading the descriptor is what makes nl
    # see its own input only. Here the prefetcher reads a different file and
    # its own output is discarded, so only nl's behaviour is under test.
    leftover = d / 'prefetch-source'
    leftover.write_bytes(b'first\nleftover\n' + b'padding line\n' * 500)
    prefetchers = []
    for tool, options in (('head', ['-n', '1']), ('sed', ['-n', '1p']), ('cat', []),
                          ('wc', ['-l']), ('tac', []), ('nl', ['-ba'])):
        probe = subprocess.run([binary, '-c', prefix + 'type -t "$1"', '_', tool],
                               capture_output=True, env=environment, timeout=20)
        if probe.stdout.strip() == b'builtin':
            prefetchers.append([tool, *options])
    shapes = {
        'redirect after read-ahead': '"${@:2}" < "$0" > /dev/null; nl OPTS < "$1"',
        'file operand after read-ahead': '"${@:2}" < "$0" > /dev/null; nl OPTS "$1"',
        'twice after read-ahead':
            '"${@:2}" < "$0" > /dev/null; nl OPTS < "$1" > /dev/null; nl OPTS < "$1"',
    }
    for name in ('plain', 'sections', 'blanks', 'nul-bytes', 'long-records'):
        target = paths[name]
        for options in (['-ba'], [], ['-ba', '-l', '2']):
            wanted = reference(gnu, options + [str(target)])
            text = ' '.join("'" + value + "'" for value in options)
            for pre in prefetchers:
                for label, body in shapes.items():
                    got = subprocess.run(
                        [binary, '-c', prefix + body.replace('OPTS', text),
                         str(leftover), str(target), *pre],
                        capture_output=True, env=environment, timeout=60)
                    checks += 1
                    if (got.returncode, got.stdout) != (wanted.returncode, wanted.stdout):
                        failures.append((f'read-ahead/{pre[0]}/{label}', options, name.encode(),
                                         got.returncode, wanted.returncode, got.stdout[:160],
                                         wanted.stdout[:160], got.stderr[:160]))

    # The reported shape with the prefetcher's own output kept: the pair of
    # builtins must produce what the pair of external programs produces.
    paired = dict(environment, LEFT=str(leftover), RIGHT=str(paths['plain']))
    for pre in prefetchers:
        if not Path('/usr/bin/' + pre[0]).exists():
            continue
        for options in (['-ba'], []):
            text = ' '.join("'" + value + "'" for value in options)
            got = subprocess.run(
                [binary, '-c', prefix + f'"$@" < "$LEFT"; nl {text} < "$RIGHT"', '_', *pre],
                capture_output=True, env=paired, timeout=60)
            want = subprocess.run(
                [binary, '-c', f'"$@" < "$LEFT"; /usr/bin/nl {text} < "$RIGHT"', '_',
                 '/usr/bin/' + pre[0], *pre[1:]],
                capture_output=True, env=paired, timeout=60)
            checks += 1
            if (got.returncode, got.stdout) != (want.returncode, want.stdout):
                failures.append((f'read-ahead pair/{pre[0]}', options, b'plain', got.returncode,
                                 want.returncode, got.stdout[:160], want.stdout[:160],
                                 got.stderr[:160]))

    # Opening an operand can reuse fd 0. It must still be closed on return,
    # leaving the shell's deliberately closed stdin unchanged.
    p = builtin([paths['plain']], script='''exec 0<&-
"$@" >/dev/null || exit
[[ ! -e /proc/self/fd/0 ]]
''')
    checks += 1
    if p.returncode != 0:
        failures.append(('operand fd ownership', [], b'', p.returncode, 0,
                         p.stdout[:160], b'', p.stderr[:160]))

    # Bash's own stdout keeps its order and buffering around the builtin, a
    # failed write is reported, and the next invocation still works.
    script = prefix + '''printf before
nl -ba "$1"
printf middle
rc=0; nl -ba "$1" >/dev/full 2>/dev/null || rc=$?
[[ $rc == 1 ]] || { echo "want status 1, got $rc" >&2; exit 42; }
nl -ba "$1"
printf after
'''
    numbered = reference(gnu, ['-ba', str(paths['plain'])]).stdout
    for destination in (None, d / 'redirected'):
        argv = [binary, '-c', script, '_', str(paths['plain'])]
        if destination:
            with destination.open('wb') as handle:
                p = subprocess.run(argv, stdout=handle, stderr=subprocess.PIPE,
                                   env=environment, timeout=60)
            out = destination.read_bytes()
        else:
            p = subprocess.run(argv, capture_output=True, env=environment, timeout=60)
            out = p.stdout
        checks += 1
        if (p.returncode, out) != (0, b'before' + numbered + b'middle' + numbered + b'after'):
            failures.append(('stdout state', [str(destination)], b'', p.returncode, 0,
                             out[:160], b'before' + numbered + b'...', p.stderr[:160]))

    # A terminal receives complete lines while the input stream is still open.
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[1] &= ~termios.ONLCR
    termios.tcsetattr(slave, termios.TCSANOW, settings)
    try:
        with subprocess.Popen([binary, '-c', prefix + '"$@"', '_', 'nl', '-ba'],
                              env=environment, stdin=subprocess.PIPE, stdout=slave,
                              stderr=subprocess.PIPE) as proc:
            proc.stdin.write(b'a\nb\n')
            proc.stdin.flush()
            checks += 1
            got = b''
            deadline = time.monotonic() + 10
            while b'\n' not in got:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([master], [], [], remaining)[0]:
                    break
                chunk = os.read(master, 1024)
                if not chunk:
                    break
                got += chunk
            if not got.startswith(b'     1\ta\n'):
                failures.append(('terminal', [], b'', -1, 0, got[:80], b'     1\ta\n', b''))
            _, errors = proc.communicate(timeout=10)
            checks += 1
            if proc.returncode != 0 or errors:
                failures.append(('terminal exit', [], b'', proc.returncode, 0, b'', b'', errors[:120]))
    finally:
        os.close(master)
        os.close(slave)

for note, options, data, got_rc, want_rc, got, want, errors in failures[:int(os.environ.get('NL_SHOW', 20))]:
    print(f'DIFF {note} {options} input={data!r}\n  status {got_rc} vs {want_rc}'
          f'\n  actual   {got!r}\n  expected {want!r}\n  stderr   {errors!r}')
version = reference(gnu, ['--version']).stdout.decode().splitlines()[0]
label = version + ('' if not busybox else ' and BusyBox nl')
if zero_group_contracts:
    print(f'nl: {zero_group_contracts} -l 0 contracts use the equivalent -l 1 reference; '
          'this GNU version rejects zero grouping')
print(f'nl-parity: {checks - len(failures)}/{checks} reference and contract checks pass with {label}')
sys.exit(1 if failures else 0)
