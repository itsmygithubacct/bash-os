#!/usr/bin/env python3
"""Keep an interactive shell usable after interrupting a private FIFO input."""
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
if not Path('/proc/self/fd').is_dir():
    print('pager-interrupts: skipped (requires Linux descriptor inspection)')
    raise SystemExit(0)


def descriptors(pid, target):
    matches = []
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            if os.readlink(fd) == str(target):
                matches.append(fd.name)
        except FileNotFoundError:
            pass
    return matches


with tempfile.TemporaryDirectory(prefix='pager-interrupts-') as temporary:
    directory = Path(temporary)
    fifo = directory / 'input'
    os.mkfifo(fifo)
    producer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    env = {**os.environ, 'PS1': '', 'PS2': '', 'LC_ALL': 'C'}
    process = subprocess.Popen([binary, '--noprofile', '--norc', '-i'], env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    errors = bytearray()

    def command(text):
        process.stdin.write(text.encode() + b'\n')
        process.stdin.flush()

    def receive(marker):
        output = bytearray()
        deadline = time.monotonic() + 5
        while marker not in output:
            assert time.monotonic() < deadline, (marker, output, errors)
            for stream in select.select([process.stdout, process.stderr], [], [], 0.1)[0]:
                data = os.read(stream.fileno(), 65536)
                assert data, (process.poll(), marker, output, errors)
                (output if stream == process.stdout else errors).extend(data)
        assert b'AddressSanitizer' not in errors and b'runtime error:' not in errors, errors

    try:
        # Interactive shells ignore BASH_ENV; load instrumented modules
        # explicitly when the caller requests the same validation setup.
        loader = os.environ.get('PAGER_LOAD_ENV')
        if loader:
            command('. ' + shlex.quote(loader))
        command("printf 'PAGER-READY\\n'")
        receive(b'PAGER-READY\n')
        for borrowed in (False, True):
            source = '< ' + shlex.quote(str(fifo)) if borrowed else shlex.quote(str(fifo))
            command('less ' + source + ' > ' + shlex.quote(str(directory / 'output')))
            deadline = time.monotonic() + 5
            while not descriptors(process.pid, fifo):
                assert time.monotonic() < deadline, errors
                time.sleep(0.01)
            # A short record cannot fill the block read; the held-open
            # producer keeps the command inside that read until SIGINT.
            os.write(producer, b'ordinary record\n')
            time.sleep(0.02)
            os.kill(process.pid, signal.SIGINT)
            command("printf 'PAGER-AFTER\\n'")
            receive(b'PAGER-AFTER\n')
            assert not descriptors(process.pid, fifo), (borrowed, descriptors(process.pid, fifo))
        command('exit')
        assert process.wait(timeout=5) == 0, errors
    finally:
        os.close(producer)
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
print('pager-interrupts: 2 checks passed (owned input closed, borrowed stdin restored)')
