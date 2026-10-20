#!/usr/bin/env python3
"""Focused nl binary BRE, logical-page, stream and descriptor contracts.

Runs without external commands on the builtin PATH. NL_MODULE optionally
selects the exact production source compiled as a loadable (also fallback).
"""
import os
from pathlib import Path
import random
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
reference = str(Path(os.environ.get('NL_REFERENCE', '/usr/bin/nl')).resolve())
env = dict(os.environ, PATH='', LC_ALL='C')
prefix = 'if [[ -n ${NL_MODULE:-} ]]; then enable -f "$NL_MODULE" nl || exit; fi\n'
checks = 0
failures = []


def run(script, args=(), data=b''):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        '_', *(x if isinstance(x, bytes) else str(x) for x in args)], input=data, capture_output=True,
                       env=env, timeout=30)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def compare(options, data=b''):
    global checks
    got = run('nl "$@"', options, data)
    want = subprocess.run([reference, *(x if isinstance(x, bytes) else str(x) for x in options)], input=data,
                          capture_output=True, env=env, timeout=30)
    if (got.returncode, got.stdout) != (want.returncode, want.stdout):
        failures.append((options, data[:70], got.returncode, want.returncode,
                         got.stdout[:200], want.stdout[:200], got.stderr))
    checks += 1
    return got


# Explicit byte oracle: matching after NUL must number the whole record.
p = run('nl -bpTAIL', data=b'prefix\0TAIL\nno\0match\n')
assert (p.returncode, p.stdout) == (0, b'     1\tprefix\0TAIL\n       no\0match\n'), p
checks += 1

# GNU dot excludes NUL; negated classes and backreferences can cross it.
subjects = [b'\0', b'a\0b', b'\0tail', b'head\0', b'\0\0', b'ab\0ab',
            b'ab\0ab\0', b'a\0ba\0c', b'a\0ba\0b', b'a\0a\0', b'aaa', b'', b'a\0b\0c', b'  \0 \t', b'\xff\0tail']
patterns = ['', '.', '^$', 'tail$', '^head$', 'a[^x]b', '[^x]*', '^[^x]*$',
            '^a.b$', '^a.*b$', '^[[:cntrl:]]$', '[[:alpha:]]',
            r'^\(ab[^x]\)\1$', r'\(a*\)b\1', r'a\{1,3\}',
            r'^\([^x]*\)\1$', r'^\(ab\)\{2\}$', r'^\([^x]\{3\}\)\1$', r'a\|b', r'a\+', r'a\?', r'^\(a[^x]\)\1\b$', r'^\(a[^x]\)\1\B$', '[]a]', '[^]a]', '[a-z]']
for pattern in patterns:
    compare(['-bp' + pattern], b'\n'.join(subjects) + b'\n')
    compare(['-hp' + pattern, '-fp' + pattern, '-bn'],
            b'\\:\\:\\:\n' + b'\n'.join(subjects) + b'\n\\:\n' + b'\n'.join(subjects))

# Exhaustive small binary subjects against deterministic compound BREs.
# Captures include NUL and empty strings; GNU supplies the independent oracle.
import itertools
small = b'\n'.join(bytes(x) for n in range(5)
                   for x in itertools.product((0, ord('a'), ord('b')), repeat=n)) + b'\n'
grammar = random.Random(7319)
atoms = ['a', 'b', '.', '[^a]', '[ab]', '[^ab]', '[[:cntrl:]]',
         r'\(a*[^b]\)\1', r'\([^b]*\)\1']
for _ in range(48):
    pattern = ''.join(grammar.choice(atoms) + grammar.choice(['', '*', r'\{0,2\}'])
                      for _ in range(grammar.randint(1, 3)))
    pattern = grammar.choice(['', '^']) + pattern + grammar.choice(['', '$'])
    compare(['-bp' + pattern], small)

# Input buffer edges, final records, NUL immediately at/beyond read boundaries.
for length in (127, 128, 65534, 65535, 65536, 65537, 131072, 1048576):
    data = b'x' * length + b'\0TAIL\n\0\nlast\0TAIL'
    for options in (['-ba'], ['-bpTAIL$'], ['-bp^x[^q]*TAIL$']):
        compare(options, data)

# Section repetitions, adjacent/skipped/repeated sections, blank groups and
# overflow reset all interact. A fixed seed gives reproducible page sequences.
rng = random.Random(19231)
for delimiter in ('\\:', '@@', 'abc', 'Q:', ''):
    unit = delimiter.encode()
    data = b''.join(rng.choice([b'\n', b'H\n', b'B\n', b'F\n', b'\0H\n'] +
                              [unit * n + b'\n' for n in range(1, 5)]) for _ in range(100))
    for opts in (['-ba', '-ha', '-fa', '-l3'], ['-bpB', '-hpH', '-fpF'],
                 ['-ba', '-ha', '-fa', '-p', '-v-9', '-i-2', '-nrz', '-w4']):
        compare([*opts, '-d', delimiter], data)
for options in (['-v9223372036854775807'], ['-v-9223372036854775808', '-i-1']):
    for data in (b'a\n', b'a\n\n', b'a\n\\:\\:\nnext\n', b'a\n\\:\\:\nnext\nagain\n'):
        compare(['-ba', *options], data)

for options in (['-bp^yes', '-v9223372036854775807'],
                ['-bp^yes', '-v-9223372036854775808', '-i-1']):
    for data in (b'yes\nno\n', b'yes\nno\nyes\n', b'yes\n\\:\\:\nyes\n'):
        compare(options, data)
for options in (['-ba', '-hn', '-fa', '-l2'], ['-ba', '-hpH', '-fa', '-l3']):
    compare(options, b'\n\\:\\:\\:\n\nH\n\\:\n\n\n\\:\\:\n\n')
compare(['-ba', '-ha', '-fa'], b'\\:\\:\0\n\\:\\:\\:\0\n\\:\\:\\:\\:\n')

# Valid multibyte characters remain characters rather than encoded bytes.
# C.UTF-8 is required for this suite, so unavailable locale support is a failure.
import locale
locale.setlocale(locale.LC_CTYPE, 'C.UTF-8')
env['LC_ALL'] = 'C.UTF-8'
for pattern in ('^é[^x]*é$', r'^\(é[^x]\)\1$', '^[[:alpha:]]*$', r'^.\{2\}$'):
    compare(['-bp' + pattern], 'éé\né\0é\né\0é\0\né\0éX\n漢字\n'.encode())
for pattern in ('TAIL$', '^.*TAIL$', '^[^x]*TAIL$', '[[:cntrl:]]', b'\xff', b'^[\xff]$', b'[^\xff]'):
    arg = b'-bp' + pattern if isinstance(pattern, bytes) else '-bp' + pattern
    compare([arg], b'\xff\n\xff\0TAIL\na\xffTAIL\n\xff\0\xff\n')
compare([b'-bp^\\(\xffa\\)\\1\\b$'], b'\xffa\xffa\n\xffa\xffb\n')
env['LC_ALL'] = 'C'
locale.setlocale(locale.LC_CTYPE, 'C')
# Byte-valued patterns are legal in a single-byte locale too.
compare([b'-bp\xff'], b'\xff\0x\nx\0\xff\n')

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    left, right, missing = (root / n for n in ('left', 'right', 'missing'))
    left.write_bytes(b'\n\\:\\:\\:\nH\0tail\n')
    right.write_bytes(b'\n\\:\\:\nB\n\\:\nF\0tail')
    for opts in (['-ba', '-ha', '-fa', '-l2'], ['-bpB', '-hpH', '-fpF', '-p']):
        compare([*opts, left, right])
        compare([*opts, left, missing, right])
    # -- ends parsing even for names which look like options.
    dash = root / '-ba'
    dash.write_bytes(b'operand\n')
    compare(['--', dash])
    for option in ('--help=x', '--version=x', '--no-renumber=x', '--=a',
                   '--number', '--header-numbering', '-bp[', '-hp[', '-fp['):
        compare([option], b'x\n')
    for options in (['-bpfirst', '-bpsecond'], ['-bp[ab]', '-bn', '-ba'],
                    ['--body-numbering=a', '--body-numbering=pB']):
        compare(options, b'first\nsecond\nA\nB\n')

    # One shell: failure paths, repeated recompilation and state reset, fd
    # ownership, including read errors and named operands reusing fd zero.
    good = root / 'good'
    good.write_bytes(b'a\nb\n')
    script = '''
[[ $(type -t nl) == builtin ]] || exit 40
exec 7< "$1"
before=(/proc/$$/fd/*)
for ((j=0;j<100;j++)); do
  nl -bp'a*' -bp'b' "$1" > /dev/null || exit 41
  nl -bp'[' "$1" > /dev/null 2>/dev/null; [[ $? == 1 ]] || exit 42
  nl "$2" "$1" > /dev/null 2>/dev/null; [[ $? == 1 ]] || exit 43
  nl "$3" > /dev/null 2>/dev/null; [[ $? == 1 ]] || exit 44
  nl -ba "$1" > /dev/full 2>/dev/null; [[ $? == 1 ]] || exit 45
  nl -ba <&7 > /dev/null || exit 46
  [[ -e /proc/$$/fd/7 ]] || exit 47
  nl -ba <&- > /dev/null 2>/dev/null; [[ $? == 1 ]] || exit 48
 done
after=(/proc/$$/fd/*)
[[ ${before[*]} == "${after[*]}" ]] || exit 49
for flag in --help --version; do
  nl "$flag" > /dev/full 2>/dev/null; [[ $? == 1 ]] || exit 51
 done
nl -ba "$1" || exit
exec 0<&-
nl -ba "$1" >/dev/null || exit
[[ ! -e /proc/$$/fd/0 ]] || exit 50
exec 1>&-
nl -ba "$1" 2>/dev/null; [[ $? == 1 ]] || exit 52
[[ ! -e /proc/$$/fd/0 && ! -e /proc/$$/fd/1 ]] || exit 53
'''
    got = run(script, [good, missing, root])
    assert (got.returncode, got.stdout) == (0, b'     1\ta\n     2\tb\n'), got
    checks += 1

    # Ignored SIGPIPE must become an ordinary write failure, and the next
    # invocation in the same shell must still succeed on a fresh descriptor.
    pipe_r, pipe_w = os.pipe()
    os.close(pipe_r)
    try:
        got = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix +
                              'trap "" PIPE; nl -ba "$1"; rc=$?; '
                              '[[ $rc == 1 ]] || exit 54; nl -ba "$1" >&2',
                              '_', str(good)], stdout=pipe_w, stderr=subprocess.PIPE,
                             env=env, timeout=30)
        assert got.returncode == 0 and b'write error:' in got.stderr, got
        assert got.stderr.endswith(b'     1\ta\n     2\tb\n'), got
        checks += 1
    finally:
        os.close(pipe_w)

    # Named FIFO and chunked pipe exercise actual nonseekable descriptor paths.
    fifo = root / 'fifo'
    os.mkfifo(fifo)
    data = b'a\0TAIL\n' + b'x' * 70000 + b'\nlast\0TAIL'
    want = subprocess.run([reference, '-bpTAIL$'], input=data, capture_output=True, env=env)
    for use_fifo in (False, True):
        cmd = [binary, '--noprofile', '--norc', '-c', prefix + 'nl -bpTAIL$ "$@"', '_']
        if use_fifo:
            cmd.append(str(fifo))
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if not use_fifo else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        # Concurrent collector avoids blocking the writer on long output.
        import threading
        result = []
        reader = threading.Thread(target=lambda: result.append((proc.stdout.read(), proc.stderr.read())))
        reader.start()
        with (fifo.open('wb', buffering=0) if use_fifo else proc.stdin) as writer:
            for off in range(0, len(data), 997):
                writer.write(data[off:off + 997])
                writer.flush()
        proc.wait(timeout=30)
        reader.join(timeout=30)
        assert not reader.is_alive()
        assert (proc.returncode, result[0][0]) == (want.returncode, want.stdout), (use_fifo, result)
        assert not result[0][1], result
        checks += 1

for failure in failures:
    print('DIFF', repr(failure))
print(f'sol-nl: {checks - len(failures)}/{checks} binary BRE, page, option, stream and lifetime checks passed')
sys.exit(1 if failures else 0)
