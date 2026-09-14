#!/usr/bin/env python3
"""Check pcre line delivery and write errors while its producer stays open."""
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
load = os.environ.get('PATTERN_LOAD_ENV', '')
setup = '. ' + shlex.quote(load) + '; ' if load else ''
env = dict(os.environ, LC_ALL='C.UTF-8')
checks = 0


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream:
            stream.close()


def start(fifo, output=subprocess.PIPE):
    command = 'pcre grep match' + (' input.fifo' if fifo else '')
    process = subprocess.Popen([binary, '-c', setup + command],
                               stdin=subprocess.DEVNULL if fifo else subprocess.PIPE,
                               stdout=output, stderr=subprocess.PIPE, env=env, bufsize=0)
    return process


with tempfile.TemporaryDirectory() as directory:
    os.chdir(directory)
    Path('sink').write_bytes(b'')
    for fifo in (False, True):
        writer = None
        if fifo:
            os.mkfifo('input.fifo')
            # Our private RDWR descriptor keeps a writer present, avoiding a
            # blocking open if a test assertion fails before the child starts.
            writer = os.open('input.fifo', os.O_RDWR | os.O_NONBLOCK)
        try:
            process = start(fifo)
            try:
                if fifo:
                    os.write(writer, b'match live\n')
                else:
                    process.stdin.write(b'match live\n')
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    assert ready.select(timeout=5), 'matching line was buffered with producer open'
                assert os.read(process.stdout.fileno(), 4096) == b'match live\n'
                assert process.poll() is None, 'input producer should still be open'
                checks += 1
            finally:
                stop(process)
            # A normal private file opened read-only supplies a deterministic
            # EBADF output failure. Keep the input producer open after a line.
            with open('sink', 'rb') as sink:
                process = start(fifo, sink)
                try:
                    if fifo:
                        os.write(writer, b'match live\n')
                    else:
                        process.stdin.write(b'match live\n')
                    assert process.wait(timeout=5) != 0, 'write failure returned success'
                    assert b'write error' in process.stderr.read()
                    checks += 1
                finally:
                    stop(process)
        finally:
            if writer is not None:
                os.close(writer)
                os.unlink('input.fifo')
    # A completed regular file must be delivered before the following FIFO
    # produces data, and the FIFO must then retain immediate line delivery.
    Path('first').write_bytes(b'match saved\n')
    os.mkfifo('input.fifo')
    writer = os.open('input.fifo', os.O_RDWR | os.O_NONBLOCK)
    process = subprocess.Popen([binary, '-c', setup + 'pcre grep match first input.fifo'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, bufsize=0)
    try:
        for expected, send in ((b'first:match saved\n', False),
                               (b'input.fifo:match live\n', True)):
            if send:
                os.write(writer, b'match live\n')
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=5), 'file-boundary output was buffered'
            assert os.read(process.stdout.fileno(), 4096) == expected
            assert process.poll() is None
            checks += 1
    finally:
        stop(process)
        os.close(writer)
        os.unlink('input.fifo')
print(f'pcre-streams: {checks} checks passed')
