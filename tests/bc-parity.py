#!/usr/bin/env python3
"""Compare bc with GNU bc, concentrating on repeated calls in one shell.

A builtin stays in the shell's process, so anything it leaves behind — buffered
bytes, an end-of-file indicator, arithmetic settings — is still there when the
next command runs. These checks call bc several times per shell with freshly
redirected input and compare against the same number of external bc runs.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
external = '/usr/bin/bc'
environment = dict(os.environ, LC_ALL='C', TZ='UTC', PATH='')
host_environment = dict(os.environ, LC_ALL='C', TZ='UTC')
# bc-sanitize.sh replaces the compiled-in builtin with an instrumented module.
prefix = 'if [[ -n ${BC_MODULE:-} ]]; then enable -f "$BC_MODULE" bc; fi\nPATH=\n'
checks = 0

if not os.access(external, os.X_OK):
    sys.exit(f'missing comparison program: {external}')


def bashos(script, *args, data=None):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script, '_',
                        *map(str, args)], input=data, capture_output=True,
                       env=environment, timeout=60)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def gnu(program, options=(), count=1):
    """Run the external bc COUNT times, as separate processes."""
    out, err, rc = b'', b'', 0
    for _ in range(count):
        p = subprocess.run([external, *options], input=program, capture_output=True,
                           env=host_environment, timeout=60)
        out += p.stdout
        err += p.stderr
        rc = p.returncode or rc
    return out, err, rc


def repeated(directory, program, count=3, options=(), name='program'):
    """COUNT invocations in one shell, each with its own redirection of a file."""
    global checks
    source = directory / name
    source.write_bytes(program)
    script = 'for ((i=0;i<$2;i++)); do bc "${@:3}" < "$1" || exit; done'
    actual = bashos(script, source, count, *options)
    expected, _, rc = gnu(program, options, count)
    assert (actual.returncode, actual.stdout) == (rc, expected), (
        program, options, count, actual.returncode, rc,
        actual.stdout[:400], expected[:400], actual.stderr[:400])
    checks += 1


# Programs both implementations agree on. Every one ends with a newline: an
# unterminated final line is a documented divergence, checked separately.
PROGRAMS = [
    b'1+1\n',
    b'scale=20; sqrt(2)\n',                       # the benchmark fixture
    b'2^100\n',
    b'12345678901234567890+98765432109876543210\n',
    b'scale=12\n22/7\n',
    b'17%5\n',
    b'a=12\na*3\na-5\n',
    b'length(123456); scale(1.250)\n',
    b'scale=4\n8/3\n-3*-4\n(2+3)*4\n',
    b'ibase=16\nFF+1\n',
    b'\n\n1+1\n\n\n2+2\n\n',                      # blank lines between statements
    b'x=0\nx=x+7\nx\nx*x\n',
]

with tempfile.TemporaryDirectory(prefix='bash-os-bc-') as tmp:
    d = Path(tmp)

    # 1. The reported failure: three calls, each with a fresh redirection.
    for program in PROGRAMS:
        for count in (1, 3, 5):
            repeated(d, program, count)
    repeated(d, b'scale=8; s(1); c(0); a(1)\n', 3, options=('-l',))
    repeated(d, b'4*a(1)\n', 3, options=('-l',))
    # A batch the size the benchmark harness times.
    repeated(d, b'scale=20; sqrt(2)\n', 25)

    # 2. Different input files between calls, in one shell.
    (d/'first').write_bytes(b'1+1\n')
    (d/'second').write_bytes(b'scale=20; sqrt(2)\n')
    (d/'third').write_bytes(b'2^10\n')
    p = bashos('bc < "$1"; bc < "$2"; bc < "$3"; bc < "$1"', d/'first', d/'second', d/'third')
    wanted = b''.join(gnu(x)[0] for x in (b'1+1\n', b'scale=20; sqrt(2)\n', b'2^10\n', b'1+1\n'))
    assert (p.returncode, p.stdout) == (0, wanted), (p.returncode, p.stdout, p.stderr)
    checks += 1

    # 3. Empty input before, between and after real input.
    (d/'empty').write_bytes(b'')
    p = bashos('bc < "$2"; bc < "$1"; bc < "$2"; echo "rc=$?"; bc < "$1"', d/'first', d/'empty')
    assert (p.returncode, p.stdout) == (0, b'2\nrc=0\n2\n'), (p.returncode, p.stdout, p.stderr)
    checks += 1

    # 4. Pipes and here-documents, repeated in one shell.
    p = bashos('for ((i=0;i<3;i++)); do printf "6*7\\n" | bc; done')
    assert (p.returncode, p.stdout) == (0, b'42\n' * 3), (p.returncode, p.stdout, p.stderr)
    checks += 1
    p = bashos('for ((i=0;i<3;i++)); do bc <<< "6*7"; done')
    assert (p.returncode, p.stdout) == (0, b'42\n' * 3), (p.returncode, p.stdout, p.stderr)
    checks += 1
    p = bashos('for ((i=0;i<3;i++)); do bc <<EOF\nscale=3\n1/8\nEOF\ndone')
    assert (p.returncode, p.stdout) == (0, b'.125\n' * 3), (p.returncode, p.stdout, p.stderr)
    checks += 1
    # Input the shell supplies on the process's own standard input.
    p = bashos('bc', data=b'11*11\n')
    assert (p.returncode, p.stdout) == (0, b'121\n'), (p.returncode, p.stdout, p.stderr)
    checks += 1

    # 5. Multiline programs, sizes around and beyond one read block.
    lines = b''.join(b'%d+%d\n' % (i, i) for i in range(1000))          # ~9 KB
    repeated(d, lines, 3, name='many')
    repeated(d, b'+'.join([b'1'] * 5000) + b'\n', 3, name='long')       # one 10 KB line
    boundary = b'1+1\n' * 1023 + b'2+2\n'                               # last line at 4092
    repeated(d, boundary, 3, name='boundary')
    repeated(d, b'0' * 4090 + b'+1\n1+1\n', 3, name='straddle')
    checks += 1

    # 6. Arithmetic state does not survive an invocation.
    (d/'scaled').write_bytes(b'scale=10\n1/3\n')
    (d/'plain').write_bytes(b'1/3\n')
    (d/'base').write_bytes(b'ibase=16\n10\n')
    (d/'ten').write_bytes(b'10\n')
    (d/'assign').write_bytes(b'a=99\na\n')
    (d/'use').write_bytes(b'a\n')
    p = bashos('bc < "$1"; bc < "$2"; bc < "$3"; bc < "$4"; bc < "$5"; bc < "$6"',
               d/'scaled', d/'plain', d/'base', d/'ten', d/'assign', d/'use')
    assert (p.returncode, p.stdout) == (0, b'.3333333333\n0\n16\n10\n99\n0\n'), (
        p.returncode, p.stdout, p.stderr)
    checks += 1
    # -l applies to the invocation that asked for it, and to no other.
    p = bashos('bc -l < "$1"; bc < "$1"', d/'plain')
    assert p.stdout == b'.33333333333333333333\n0\n', (p.stdout, p.stderr)
    checks += 1

    # 7. Diagnostics, and the invocation after a failure.
    (d/'broken').write_bytes(b'1+\n2+2\n')
    p = bashos('bc < "$1"; echo "rc=$?"; bc < "$2"; echo "rc=$?"; bc < "$1"; echo "rc=$?"',
               d/'broken', d/'first')
    assert p.stdout == b'4\nrc=1\n2\nrc=0\n4\nrc=1\n', (p.stdout, p.stderr)
    assert p.stderr.count(b'syntax error') == 2, p.stderr
    checks += 1
    # A message names the offending text and goes to standard error only.
    p = bashos('bc <<< "@" 2>/dev/null; echo "rc=$?"')
    assert p.stdout == b'rc=1\n' and p.stderr == b'', (p.stdout, p.stderr)
    checks += 1
    # A directory as standard input fails, and the next call still works.
    p = bashos('bc < "$1" 2>/dev/null; echo "rc=$?"; bc < "$2"', d, d/'first')
    assert p.stdout.endswith(b'2\n') and b'rc=' in p.stdout, (p.stdout, p.stderr)
    checks += 1
    # A runtime error is reported, and leaves nothing behind for the next call.
    p = bashos('bc <<< "1/0"; echo "rc=$?"; bc <<< "scale=2; 1/4"', )
    assert p.stdout == b'rc=1\n.25\n', (p.stdout, p.stderr)
    assert b'divide by zero' in p.stderr, p.stderr
    checks += 1

    # 8. bc reads its input to the end, so a second call on the same open
    #    descriptor sees none of it — what separate bc processes also do.
    (d/'pair').write_bytes(b'1+1\n2+2\n')
    p = bashos('{ bc; bc; } < "$1"', d/'pair')
    reference = subprocess.run(['/bin/sh', '-c', f'{{ {external}; {external}; }} < "{d/"pair"}"'],
                               capture_output=True, env=host_environment, timeout=60)
    assert (p.returncode, p.stdout) == (reference.returncode, reference.stdout), (
        p.returncode, p.stdout, reference.returncode, reference.stdout)
    checks += 1

    # 9. read() takes one line per call, repeatedly, in one shell.
    (d/'values').write_bytes(b'5\n9\n')
    p = bashos('for ((i=0;i<3;i++)); do bc "read()+read()" < "$1"; done', d/'values')
    assert (p.returncode, p.stdout) == (0, b'14\n' * 3), (p.returncode, p.stdout, p.stderr)
    checks += 1
    # read() inside a program on standard input takes the following line.
    # This is the builtin's own contract: GNU bc's read() blocks on a pipe it
    # has already buffered, so there is nothing to compare it with.
    p = bashos('for ((i=0;i<3;i++)); do printf "x=read()\\n21\\nx*2\\n" | bc; done')
    assert (p.returncode, p.stdout) == (0, b'42\n' * 3), (p.returncode, p.stdout, p.stderr)
    checks += 1

    # 10. Expression arguments need no input at all, and repeat cleanly.
    p = bashos('for ((i=0;i<3;i++)); do bc "3*(4+5)"; done < /dev/null')
    assert (p.returncode, p.stdout) == (0, b'27\n' * 3), (p.returncode, p.stdout, p.stderr)
    checks += 1

    # 11. The shell's own input is unaffected by a redirected bc.
    p = bashos('while read -r line; do bc <<< "$line"; done', data=b'1+1\n2+2\n3+3\n')
    assert (p.returncode, p.stdout) == (0, b'2\n4\n6\n'), (p.returncode, p.stdout, p.stderr)
    checks += 1
    # A partial read leaves the shared descriptor where a separate bc would.
    p = bashos('exec 0< "$1"; bc "read()"; read -r rest; echo "rest=[$rest]"', d/'values')
    assert p.stdout == b'5\nrest=[]\n', (p.stdout, p.stderr)
    checks += 1

    # 12. A final line with no newline: bash-os evaluates it; GNU bc reports a
    #     syntax error. Recorded here so the divergence stays deliberate.
    (d/'unterminated').write_bytes(b'7*6')
    p = bashos('bc < "$1"; bc < "$1"', d/'unterminated')
    assert (p.returncode, p.stdout) == (0, b'42\n42\n'), (p.returncode, p.stdout, p.stderr)
    reference = subprocess.run([external], input=b'7*6', capture_output=True,
                               env=host_environment, timeout=60)
    assert b'syntax error' in reference.stderr, reference.stderr
    checks += 1

print(f'bc: {checks} GNU parity and repeated-input checks passed')
