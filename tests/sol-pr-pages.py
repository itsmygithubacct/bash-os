#!/usr/bin/env python3
"""GNU page-state regression matrix, including shared stdin and natural breaks."""
import itertools
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = 'if [[ -n ${PR_MODULE:-} ]]; then enable -f "$PR_MODULE" pr || exit; fi\n'
checks = failures = 0


def check(opts, data=b'', files=()):
    global checks, failures
    args = [*opts, *files]
    got = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix+'pr "$@"', '_', *args],
                         input=data, capture_output=True, env=env, timeout=30)
    want = subprocess.run(['/usr/bin/pr', *args], input=data, capture_output=True, env=env, timeout=30)
    checks += 1
    if ((got.returncode, got.stdout) != (want.returncode, want.stdout)
            or b'AddressSanitizer' in got.stderr or b'runtime error:' in got.stderr):
        failures += 1
        print('FAIL', args, repr(data), {f: Path(f).read_bytes() for f in files if f != '-'}, 'got', got.returncode, repr(got.stdout), repr(got.stderr),
              'GNU', want.returncode, repr(want.stdout), flush=True)


with tempfile.TemporaryDirectory(prefix='pr-pages-') as d:
    left, right = [str(Path(d)/s) for s in ('left', 'right')]
    # Put breaks before, on and after natural page ends and column starts.
    for length, columns in itertools.product((1, 2, 3, 12), (2, 3)):
        for pos in range(length * columns + 2):
            for breaker in (b'\f', b'\f\n', b'\f\f', b'X\f'):
                data = b'a\n'*pos + breaker + b'b\nc\nd'
                for mode in ([], ['-a']):
                    check(['-t', f'-l{length}', f'-{columns}', '-n:2', *mode], data)
        data = b'a\nb\f\nc\nd\ne\f\ff\n' * 3
        for extra in (['-T'], ['-d'], ['-f'], ['+2:3'], ['-d', '+2:3', '-N20'], ['+3:4'], ['-d', '-f']):
            for mode in ([], ['-a']):
                check(['-D', 'STAMP', '-hTITLE', f'-l{length}', f'-{columns}', '-n', *mode, *extra], data)
    rng = random.Random(947)
    for case in range(150):
        data = b''.join(rng.choice((b'a\n', b'\f', b'\f\n', b'b\f', b'\n', b'\0\tX\bZ\n')) for _ in range(rng.randrange(1, 24)))
        other = b''.join(rng.choice((b'Y\n', b'\f', b'\f\n', b'Z\f', b'\n')) for _ in range(rng.randrange(1, 24)))
        Path(left).write_bytes(data); Path(right).write_bytes(other)
        opts = ['-D', 'STAMP', '-hTITLE', '-l'+str(rng.choice((1, 2, 3, 11, 12, 13, 16))),
                *rng.choice(([], ['-t'], ['-T'], ['-d'], ['-f'], ['-t', '-d'])),
                *rng.choice(([], ['-n'], ['-n:2', '-s,'], ['-S::']))]
        check([*opts, '-m'], files=(left, right))
        check([*opts, '-m'], data, ('-', '-'))
        check([*opts, '-m'], data, ('-', right, '-'))
        check(opts, data, ('-', '-'))
        check([*opts, '-2'], data, ('-', '-'))
        check([*opts, '-a', '-3'], data, ('-', '-'))
    for data, other in itertools.product((b'a', b'a\f', b'a\n'), (b'', b'\f', b'b')):
        Path(left).write_bytes(data); Path(right).write_bytes(other)
        for opts in (['-n'], ['-n:2', '-s,'], ['-d', '-n'], []):
            check(['-t', '-m', *opts], files=(left, right))
    for data, other in itertools.product((b'a\fb\nc\nd\fE\n', b'\f\fX\n', b'a'),
                                         (b'1\n2\n\f\n3\n4\n5\n', b'\f\fY\n')):
        Path(left).write_bytes(data); Path(right).write_bytes(other)
        for pages in ('+2:2', '+2:3', '+3:4'):
            for extra in ([], ['-N20']):
                check(['-t', '-l2', '-m', '-n', pages, *extra], files=(left, right))
                check(['-t', '-l2', '-m', '-n', pages, *extra], data, ('-', right, '-'))
    for length, order in itertools.product((10, 11, 66), (['-T', '-t'], ['-t', '-T'])):
        for mode in ([], ['-2'], ['-a', '-3'], ['-m', '-', '-']):
            check([*order, f'-l{length}', *mode], b'1\n2\n\f3\f\f4\n')
    # Each form-feed is shared input data, but hold and boundary flags belong
    # to the operand column. Cover repeated '-' without random sampling too.
    for data in (b'\f', b'\f\fX\n', b'a\fb\nc\n', b'1\n2\n\f\n3\n4\n',
                 b'x\n'*5+b'\f\n'+b'y\n'*5):
        for opts in (['-t'], ['-T'], ['-t', '-l2'], ['-t', '-l2', '-n'], ['-t', '-s,']):
            check([*opts, '-m'], data, ('-', '-', '-'))
            check(opts, data, ('-', '-'))
            check([*opts, '-2'], data, ('-', '-'))
            check([*opts, '-2', '-a'], data, ('-', '-'))
    for data in (b'1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n',
                 b'a\fb\nc\fd\ne\nf\fg\n', b'\f\fX\n' * 4):
        for mode in ([], ['-2'], ['-a', '-2']):
            for pages in ('+1:1', '+2:2', '+1:2'):
                check(['-t', '-l2', *mode, pages], data, ('-', '-', '-'))
    # Many calls in one shell must release page buffers, borrowed stdin and
    # held-column state, including after a failed output write.
    data = b'a\fb\nc\n\f\n' * 20
    Path(left).write_bytes(data)
    for mode in (['-2'], ['-a', '-3'], ['-m', '-', '-']):
        opts = ['-t', '-l2', '-n', *mode]
        want = subprocess.run(['/usr/bin/pr', *opts], input=data, capture_output=True,
                              env=env, check=True).stdout
        script = prefix + """input=$1; shift
before=(/proc/self/fd/*)
for ((i=0;i<25;i++)); do pr "$@" < "$input" || exit; done
pr "$@" < "$input" > /dev/full 2>/dev/null; [[ $? == 1 ]] || exit 42
pr "$@" < "$input" || exit
after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 43
"""
        got = subprocess.run([binary, '-c', script, '_', left, *opts], capture_output=True,
                             env=env, timeout=30)
        checks += 1
        if (got.returncode, got.stdout, got.stderr) != (0, want * 26, b''):
            failures += 1
            print('FAIL persistent/recovery', opts, got.returncode, repr(got.stderr), flush=True)
print(f'pr-pages: {checks} comparisons, {failures} differences')
raise SystemExit(bool(failures))
