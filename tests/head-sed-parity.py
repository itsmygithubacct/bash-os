#!/usr/bin/env python3
"""Byte parity and persistent-shell input contracts for head and sed."""
from pathlib import Path
import os
import select
import shutil
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash-core').resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = '''if [[ -n ${HEAD_SED_MODULE:-} ]]; then
  enable -f "$HEAD_SED_MODULE" head || exit
  enable -f "$HEAD_SED_MODULE" sed || exit
fi
'''
refs = {name: {'gnu': ['/usr/bin/' + name]} for name in ('head', 'sed')}
busybox = shutil.which('busybox')
if busybox:
    for name in refs:
        refs[name]['busybox'] = [busybox, name]
else:
    print('SKIP BusyBox: executable unavailable')
checks = 0


def shell(script, args=(), data=b''):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix + script,
                        'test', *map(str, args)], input=data, capture_output=True,
                       env=env, timeout=20)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def expect(label, script, args=(), data=b'', output=b'', status=0):
    global checks
    p = shell(script, args, data)
    assert (p.returncode, p.stdout) == (status, output), (label, p.returncode, p.stdout[:300], p.stderr)
    checks += 1


def parity(tool, args, data=b'', references=None):
    global checks
    actual = shell('"$@"', [tool, *args], data)
    for label, command in refs[tool].items():
        if references and label not in references:
            continue
        expected = subprocess.run([*command, *map(str, args)], input=data,
                                  capture_output=True, env=env, timeout=20)
        assert (actual.returncode, actual.stdout) == (expected.returncode, expected.stdout), (
            tool, args, label, actual.returncode, expected.returncode,
            actual.stdout[:200], expected.stdout[:200], actual.stderr)
        checks += 1


with tempfile.TemporaryDirectory(prefix='head-sed-test-') as directory:
    d = Path(directory)
    first, second, empty = d/'first', d/'second', d/'empty'
    empty.write_bytes(b'')
    datasets = [b'', b'a', b'\n', b'a\nb\nc\n', b'alpha\nbeta\na',
                b'a\r\nb\r', b'a'*4095+b'\n'+b'b'*4096+b'\n'+b'c'*4097,
                b'a'*65535+b'\n'+b'b'*65536+b'\nend']
    for data in datasets:
        first.write_bytes(data)
        for args in ([], ['-n', '1'], ['-n', '2'], ['-n', '100'], ['-2']):
            parity('head', args, data)
            parity('head', [*args, first])
        # These scripts cover output paths whose framing must follow input.
        for script in ('', 's/a/A/g', 'p', 's/a/A/p', 'P', 'n', 'N', 'N;P',
                       '$p', '1,$s/a/A/g', '2d', 'h;g', 'H;g', 'x', 'G',
                       'i inserted', 'a appended', 'c changed', 'N;D', 's/a//;p'):
            parity('sed', ['-e', script], data)
            parity('sed', ['-e', script, first])
        for script in ('p', 's/a/A/gp', '$p', 'n;p', 'N;P'):
            # BusyBox 1.37 appends a newline for explicit -n printing.
            parity('sed', ['-n', '-e', script], data, references=['gnu']
                   if data and not data.endswith(b'\n') else None)
        # GNU q adds a newline here; BusyBox preserves the unterminated line.
        parity('sed', ['q'], data, references=['busybox'])
        for script in ('Q', 'q 7', 'Q 7', 'l', 'N;W /dev/stdout'):
            if script == 'l' and len(data) > 60:  # existing wrap-width difference
                continue
            if script.startswith('q') and data and not data.endswith(b'\n') and b'\n' not in data:
                continue
            parity('sed', ['-e', script], data, references=['gnu'])
    # Embedded NULs are byte data for head; sed's regex engine remains text based.
    parity('head', ['-n', '2'], b'a\0b\nc\0d\nend')
    first.write_bytes(b'a\nb\nc\n'); second.write_bytes(b'z\ny\nx\n')
    parity('head', ['-n', '1', first, second])
    parity('sed', ['s/a/A/g', first, second])
    parity('sed', ['s/a/A/g', '-'], b'a\nb\nc')

    for tool, opts, transformed, other in (
            ('head', ['-n', '1'], b'a\n', b'z\n'),
            ('sed', ['s/a/A/g'], b'A\nb\nc\n', b'z\ny\nx\n')):
        argv = [first, second, empty, tool, *opts]
        expect(tool+' repeated stdin', '''f=$1; shift 3
for ((i=0;i<3;i++)); do "$@" < "$f" || exit; done''', argv, output=transformed*3)
        expect(tool+' alternating and empty', '''a=$1 b=$2 e=$3; shift 3
for f in "$a" "$b" "$e" "$a" "$e" "$b"; do "$@" < "$f" || exit; done''',
               argv, output=(transformed+other)*2)
        expect(tool+' changing same file', '''f=$1; shift 3
for value in a z a; do printf '%s\nb\nc\n' "$value" > "$f"; "$@" < "$f" || exit; done''',
               argv, output=(b'a\nz\na\n' if tool == 'head' else b'A\nb\nc\nz\nb\nc\nA\nb\nc\n'))
        expect(tool+' subsequent restored stdin', '''f=$1; shift 3
"$@" < "$f" || exit
IFS= read -r line || exit; printf 'read:%s\n' "$line"''', argv,
               data=b'shell input\n', output=transformed+b'read:shell input\n')
        expect(tool+' shell reads before command', '''IFS= read -r line || exit
printf 'read:%s\n' "$line"
"$@"''', [tool, *opts], data=b'prefix\na\nb\nc\n',
               output=b'read:prefix\n'+transformed)
        expect(tool+' eof reset', '''f=$1; shift 3
"$@" < /dev/null || exit
"$@" < "$f"''', argv, output=transformed)
        expect(tool+' descriptor lifetime', """f=$1; shift 3
ulimit -n 32
for ((i=0;i<128;i++)); do "$@" < "$f" >/dev/null || exit; done
printf ok""", argv, output=b'ok')
        # A failure must be reported, and fd 0/stdout must still work afterwards.
        for redirect in ('<&-', '< "$1"', '> /dev/full', '>&-'):
            expect(tool+' I/O failure '+redirect, '''bad=$1; good=$2; shift 2
rc=0; "$@" '''+redirect.replace('$1', '$bad')+''' 2>/dev/null || rc=$?
[[ $rc != 0 ]] || exit 41
"$@" < "$good" || exit
printf '%s\n' recovered''', [d, first, tool, *opts],
                   data=b'a\nb\nc\n', output=transformed+b'recovered\n')
        expect(tool+' open failure', '''bad=$1; good=$2; shift 2
rc=0; "$@" "$bad" "$good" >/dev/null 2>/dev/null || rc=$?
[[ $rc != 0 ]] || exit 42
"$@" < "$good"''', [d/'missing', first, tool, *opts], output=transformed)
        # Fresh pipe redirections in the same shell, with lastpipe avoiding children.
        expect(tool+' repeated lastpipe', '''shopt -s lastpipe
for ((i=0;i<3;i++)); do printf 'a\nb\nc\n' | "$@" || exit; done''',
               [tool, *opts], output=transformed*3)
        # Closed output pipe, ignored SIGPIPE: report EPIPE, then recover.
        read_fd, write_fd = os.pipe(); os.close(read_fd)
        try:
            p = subprocess.run([binary, '-c', prefix+'''trap '' PIPE
rc=0; "$@" <<< a 2>/dev/null || rc=$?
[[ $rc != 0 ]]''', 'test', tool, *opts], stdout=write_fd,
                               stderr=subprocess.PIPE, env=env, timeout=20)
            assert p.returncode == 0, (tool, 'EPIPE', p.returncode, p.stderr)
            checks += 1
        finally:
            os.close(write_fd)

    for command, expected in [(['head', '-n', '1'], b'a\nread:b\nc\n'),
                              (['sed', '1q'], b'a\nread:b\nc\n'),
                              (['sed', '-n', '1p;1q'], b'a\nread:b\nc\n'),
                              (['sed', 'n;q'], b'a\nb\nread:c\n'),
                              (['sed', 'N;q'], b'a\nb\nread:c\n')]:
        script = '''"$@" || exit
IFS= read -r line || exit; printf 'read:%s\n' "$line"
while IFS= read -r line; do printf '%s\n' "$line"; done'''
        expect('partial pipe '+str(command), script, command, b'a\nb\nc\n', expected)
        expect('partial file '+str(command), 'f=$1; shift; {\n'+script+'\n} < "$f"',
               [first, *command], output=expected)
    # $ may peek; its lookahead must be returned to a seekable shared descriptor.
    expect('seekable dollar lookahead', '''{ sed '$!q'; IFS= read -r line; printf '%s\n' "$line"; } < "$1"''',
           [first], output=b'a\nb\n')
    expect('repeated partial sed', '''for ((i=0;i<3;i++)); do sed 1q < "$1"; done''',
           [first], output=b'a\n'*3)
    expect('sed explicit quit code', 'sed "q 7" < "$1"', [first], output=b'a\n', status=7)
    expect('sed error beats quit code', 'sed "q 0" < "$1" >/dev/full 2>/dev/null', [first], status=1)

    # A producer remains open: head and ordinary sed q must return immediately.
    for command in (['head', '-n', '1'], ['sed', '1q'], ['sed', '1q;$p']):
        with subprocess.Popen([binary, '-c', prefix+'"$@"', 'test', *command],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env) as proc:
            proc.stdin.write(b'a\n'); proc.stdin.flush()
            assert select.select([proc.stdout], [], [], 5)[0], (command, 'waited for more input')
            proc.wait(timeout=5)
            assert proc.stdout.read() == b'a\n' and proc.returncode == 0
            assert not proc.stderr.read()
            checks += 1

    # Shell commands themselves may come from stdin after a redirected builtin.
    program = b"head -n 1 < \"$1\"\nsed s/a/A/g < \"$1\"\nprintf '%s\\n' done\n"
    p = subprocess.run([binary, '--noprofile', '--norc', '-s', '--', str(first)],
                       input=prefix.encode()+program, capture_output=True, env=env, timeout=20)
    assert p.returncode == 0 and p.stdout == b'a\nA\nb\nc\ndone\n', (p.returncode, p.stdout, p.stderr)
    checks += 1

    # Check exact newline preservation through in-place and write-file paths.
    for data in (b'a', b'a\nb', b'a\nb\n'):
        for script in ('s/a/A/g', 'p', 'h;G'):
            first.write_bytes(data); second.write_bytes(data)
            expected = subprocess.run(['/usr/bin/sed', '-i.bak', script, str(second)], capture_output=True)
            actual = shell('sed -i.bak "$1" "$2"', [script, first])
            assert expected.returncode == actual.returncode == 0
            assert first.read_bytes() == second.read_bytes()
            assert Path(str(first)+'.bak').read_bytes() == data
            checks += 1
        for script in ('w ', 's/a/A/w ', 'W '):
            expected = subprocess.run(['/usr/bin/sed', '-n', script+str(second)], input=data, capture_output=True)
            actual = shell('sed -n "$1"', [script+str(first)], data)
            assert actual.returncode == expected.returncode == 0 and first.read_bytes() == second.read_bytes()
            checks += 1
    expect('sed w error', 'sed -n "w /dev/full"', data=b'a', status=1)
    expect('sed w open error', 'sed -n "w $1/missing/file"', [d], b'a', status=1)

print(f'head-sed: {checks} byte-parity and shell-state checks passed')
