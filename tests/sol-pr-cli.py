#!/usr/bin/env python3
"""Focused GNU byte oracles for newly implemented pr CLI/format surfaces."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
checks = 0
prefix = 'if [[ -n ${PR_MODULE:-} ]]; then enable -f "$PR_MODULE" pr; fi\n'


def check(args, data=b'', cwd=None):
    global checks
    got = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix+'"$@"', '_', 'pr', *args], input=data, capture_output=True, env=env, cwd=cwd, timeout=30)
    want = subprocess.run(['/usr/bin/pr', *args], input=data, capture_output=True, env=env, cwd=cwd, timeout=30)
    assert b'AddressSanitizer' not in got.stderr and b'runtime error:' not in got.stderr, got.stderr
    assert (got.returncode, got.stdout) == (want.returncode, want.stdout), (args, data[:80], got.returncode, want.returncode, got.stdout[:250], want.stdout[:250], got.stderr)
    checks += 1


with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    data = b'a\tb\nc\rd\nx\0z\n\bb\n'+b'word space\n'*40
    for name, content in [('a', data), ('b', b'one\ntwo\nthree'), ('c', b'1\n2\n3\n4\n'), ('-t', b'dash\n')]:
        (root/name).write_bytes(content)
        os.utime(root/name, (981173106, 981173106))
    for options in [
        ['-tn:3', '-2'], ['-tan:3', '-3'], ['-t', '-12'], ['-t', '--columns=12'],
        ['-t', '-10', '-s::'], ['-t', '-3', '-S::'], ['-t', '-3', '--sep-string= | '],
        ['-t', '-3', '-S'], ['-t', '-3', '-S '], ['-t', '-3', '-S\t'],
        ['-t', '-3', '-J'], ['-t', '-3', '-J', '-S::'], ['-t', '-J', '-W1'],
        ['-t', '-3', '-w12', '-s,'], ['-t', '-3', '-w12', '-s'],
        ['-t', '-3', '-W12', '-s::'], ['-t', '-W4'], ['-t', '-W4', '-n:2'],
        ['-t', '-e'], ['-t', '-e4'], ['-t', '-eX3'], ['-t', '-i'], ['-t', '-iX4'],
        ['-t', '-c'], ['-t', '-v'], ['-t', '-c', '-v'], ['-t', '-e4', '-i4'],
        ['-t', '-2', '-e4', '-iX4', '-n:'], ['-t', '--number-lines=:3', '--indent=2'],
        ['-t', '-m', '-w1'], ['-t', '--first-line-number=0', '-n'], ['-t', '-N-2', '-n:'],
        ['-t', '-l3', '+2:3'], ['-t', '-l3', '--pages=2:3', '-n'],
        ['-t', '-l3', '+2:3', '-n', '-N20'], ['-t', '-l3', '+2:3', '-2', '-n'],
        ['-t', '-l3', '+2:3', '-2', '-n', '-N20'],
        ['--date-format=%Y', '-hTITLE', '-l15'],
        ['-D', '', '-h', '', '-l15'], ['-D%Y', '-iX4', '-o9', '-l15'], ['--omit-header'],
        ['--omit-pagination'], ['--merge', '--no-file-warnings'],
    ]:
        check([*options, 'a'], cwd=root)
    for opts in [['-t', '-m', '-n', '-w1'], ['-t', '-m', '-n', '-W1']]:
        check(opts, b'abc\n')
    for width in range(1, 13):
        for opts in [[], ['-2'], ['-3'], ['-2', '-n'], ['-2', '-s,']]:
            check(['-t', f'-w{width}', *opts], b'abcdef\nghijkl\n')
    for form_data in [b'a\fb\n', b'a\n\f\nb\n', b'\f\fX\n',
                      b'1\n2\n\f\n3\n4\n', b'a\b\bb\n', b'\0\bb\n']:
        for opts in [['-t'], ['-T'], ['-t', '-2'], ['-T', '-2'],
                     ['-t', '-2', '-n'], ['-t', '-l2'], ['-t', '-l2', '-n']]:
            check(opts, form_data)
    # Per-buffer control summaries must survive record and read boundaries.
    for length in [65535, 65536, 65537]:
        for opts in [['-t'], ['-t', '-W8'], ['-t', '-2', '-n']]:
            check(opts, b'x'*length + b'\b\bY\n\0\bZ\n' + b'clean\n'*10000)
        for opts in [['-t'], ['-T'], ['-t', '-2']]:
            check(opts, b'Q'*length + b'\f\nnext\n')
    # Every byte except newline/formfeed: transformations, input tab stops,
    # output tab compression, and control bytes in numbered columns.
    controls = bytes(x for x in range(256) if x not in (10, 12))+b'\n'
    for opts in [['-t','-c'], ['-t','-v'], ['-t','-e'], ['-t','-i'], ['-t','-2','-n:3']]:
        check(opts, controls*3)
    for options in [['-t'], ['-t', '-2'], ['-t', '-S::', '-3']]:
        check(['a', *options], cwd=root)
    check(['--', '-t'], cwd=root)
    for names in [['a', 'b'], ['b', 'a'], ['b', 'b', 'c']]:
        for options in [['-t', '-m', '-n'], ['-t', '-m', '-n:', '-s,'], ['-t', '-m', '-d']]:
            check([*options, *names], cwd=root)
    for tail in [b'x ', b'x\t', b'\0x', b'x\r', b'x\b']:
        (root/'tail').write_bytes(tail)
        for opts in [['-t', '-m', '-n'], ['-t', '-m', '-n:', '-s,'], ['-t', '-m', '-n', '-s']]:
            check([*opts, 'tail', 'c'], cwd=root)
    for opts in [['-t', '-', '-'], ['-t', '-m', '-', '-'], ['-t', '-m', '-n', '-', '-', '-']]:
        check(opts, b'a\nb\nc\nd\ne\n')
    cleanup = prefix + """before=(/proc/self/fd/*)
for ((i=0;i<100;i++)); do pr -t a >/dev/null || exit; pr -r missing 2>/dev/null; done
after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 42
exec 0<&-; pr -t a >/dev/null || exit; [[ ! -e /proc/self/fd/0 ]]"""
    got = subprocess.run([binary, '-c', cleanup], capture_output=True, env=env, cwd=root)
    assert (got.returncode, got.stdout, got.stderr) == (0, b'', b''), got
    checks += 1
    for opts in [['--columns=0'], ['--columns=2147483648'], ['--pages=0'], ['--pages=4:2'], ['-t', '-m', '-2'], ['-t', '-m', '-a']]:
        got = subprocess.run([binary, '-c', prefix+'pr "$@"', '_', *opts], capture_output=True, env=env)
        assert got.returncode and got.stderr, (opts, got)
        checks += 1
    for opts in [['-t', '-3', '-n:3'], ['-t', '-3', '-S::'], ['-t', '-W4']]:
        want = subprocess.run(['/usr/bin/pr', *opts, 'a'], capture_output=True, env=env, cwd=root, check=True).stdout
        script = prefix + 'pr "$@" > /dev/full 2>/dev/null; [[ $? == 1 ]] || exit 42; pr "$@"'
        got = subprocess.run([binary, '-c', script, '_', *opts, 'a'], capture_output=True, env=env, cwd=root)
        assert (got.returncode, got.stdout, got.stderr) == (0, want, b''), (opts, got)
        checks += 1
    # Page selection must finish after its last page while a pipe stays open.
    proc = subprocess.Popen([binary, '-c', prefix+'pr -t -l2 +1:1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        proc.stdin.write(b'one\ntwo\n'); proc.stdin.flush()
        assert proc.wait(timeout=10) == 0
        assert proc.stdout.read() == b'one\ntwo\n' and not proc.stderr.read()
    finally:
        proc.stdin.close()
        if proc.poll() is None: proc.kill(); proc.wait()
    checks += 1
    check(['-r', '-t', 'missing', 'a'], cwd=root)
    got = subprocess.run([binary, '-c', prefix+'pr -r -t missing'], capture_output=True, env=env, cwd=root)
    assert got.returncode == 1 and not got.stderr
    checks += 1
print(f'sol-pr-cli: {checks} GNU byte/status and invalid-input checks passed')
