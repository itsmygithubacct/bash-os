#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check rev's byte-per-line contract, batching, and live-stream delivery."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = dict(os.environ, PATH='', LC_ALL='C.UTF-8')
checks = 0


def reverse(payload):
    return b'\n'.join(part[::-1] for part in payload.split(b'\n'))


def run(script, *args, data=b'', expected=b''):
    global checks
    result = subprocess.run([binary, '--noprofile', '--norc', '-c', script, 'check',
                             *map(str, args)], input=data, capture_output=True,
                            env=env, timeout=20)
    assert result.returncode == 0, (script, result.returncode, result.stderr)
    assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr, result.stderr
    assert result.stdout == expected, (script, args, result.stdout[:160], expected[:160])
    checks += 1


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream:
            stream.close()


def expect_live(process, expected):
    global checks
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ)
        assert ready.select(timeout=5), 'rev waited for the input producer to close'
    assert os.read(process.stdout.fileno(), 4096) == expected
    assert process.poll() is None
    checks += 1


with tempfile.TemporaryDirectory(prefix='rev-streams-') as directory:
    os.chdir(directory)
    payloads = [b'', b'\n\n', b'one\ntwo\nlast', b'one\ntwo\n',
                b'a\x00b\nlast\xff\x00', 'café\n界'.encode(),
                bytes(range(256)) * 257, b'ab\x00cd\xff\n' * 17000]
    for length in (65535, 65536, 65537, 131073):
        line = (b'ab\x00CD\xff' * ((length + 5) // 6))[:length - 1]
        payloads.append(b'prefix\n' + line + b'\nlast')
    # Two records exactly fill the output block; the following one forces a flush.
    payloads.append((b'a' * 32766 + b'Z\n') * 2 + b'after\n')
    for index, payload in enumerate(payloads):
        Path('input').write_bytes(payload)
        expected = reverse(payload)
        run('rev "$1"', 'input', expected=expected)
        run('rev', data=payload, expected=expected)
        run('rev -', data=payload, expected=expected)
        run('rev < "$1"', 'input', expected=expected)

    first = b'first\x00record\nunterminated'
    second = b'SECOND\xff\nlast\n'
    Path('first').write_bytes(first)
    Path('second').write_bytes(second)
    Path('empty').write_bytes(b'')
    run('rev first empty second', expected=reverse(first) + reverse(second))
    run('rev first - second', data=b'pipe\x00bytes',
        expected=reverse(first) + reverse(b'pipe\x00bytes') + reverse(second))
    run('rev < first; rev < empty; rev < second; rev < first',
        expected=reverse(first) + reverse(second) + reverse(first))
    run('shopt -s lastpipe; printf "first\\n" | rev; printf "second\\n" | rev',
        expected=b'tsrif\ndnoces\n')
    run('printf "<before>"; rev first; printf "<between>"; rev second; printf "<after>"',
        expected=b'<before>' + reverse(first) + b'<between>' + reverse(second) + b'<after>')
    run('rev first > reversed; printf "<saved>"; rev reversed', expected=b'<saved>' + first)
    run('exec 0< first; IFS= read -r prefix; rev', expected=reverse(b'unterminated'))

    Path('sink').write_bytes(b'')
    for fifo in (False, True):
        writer = None
        if fifo:
            os.mkfifo('input.fifo')
            writer = os.open('input.fifo', os.O_RDWR | os.O_NONBLOCK)
        try:
            for fail_output in (False, True):
                with open('sink', 'rb') as sink:
                    process = subprocess.Popen(
                        [binary, '--noprofile', '--norc', '-c', 'rev "$@"', 'check',
                         *(['input.fifo'] if fifo else [])],
                        stdin=subprocess.DEVNULL if fifo else subprocess.PIPE,
                        stdout=sink if fail_output else subprocess.PIPE,
                        stderr=subprocess.PIPE, env=env, bufsize=0)
                    try:
                        for payload in (b'live\x00one\n', b'second\xff\n'):
                            if fifo:
                                os.write(writer, payload)
                            else:
                                process.stdin.write(payload)
                            if fail_output:
                                assert process.wait(timeout=5) != 0
                                errors = process.stderr.read()
                                assert b'write error' in errors
                                assert b'AddressSanitizer' not in errors and b'runtime error:' not in errors
                                checks += 1
                                break
                            expect_live(process, reverse(payload))
                    finally:
                        stop(process)
        finally:
            if writer is not None:
                os.close(writer)
                os.unlink('input.fifo')

    # Final unterminated regular-file bytes are flushed before the next FIFO waits.
    Path('first').write_bytes(b'no newline')
    os.mkfifo('input.fifo')
    writer = os.open('input.fifo', os.O_RDWR | os.O_NONBLOCK)
    process = subprocess.Popen([binary, '-c', 'rev first input.fifo'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, bufsize=0)
    try:
        expect_live(process, reverse(b'no newline'))
        os.write(writer, b'live last\n')
        expect_live(process, reverse(b'live last\n'))
    finally:
        stop(process)
        os.close(writer)
        os.unlink('input.fifo')
print(f'rev-streams: {checks} checks passed')
