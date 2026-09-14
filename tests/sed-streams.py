#!/usr/bin/env python3
"""Check sed output delivery around live input and auxiliary streams."""
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = dict(os.environ, LC_ALL='C.UTF-8')
checks = 0


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
        assert ready.select(timeout=5), 'line delivery waited for an open producer'
    assert os.read(process.stdout.fileno(), 4096) == expected
    assert process.poll() is None
    checks += 1


with tempfile.TemporaryDirectory() as directory:
    os.chdir(directory)
    Path('first').write_bytes(b'match saved\n')
    Path('sink').write_bytes(b'')
    for fifo in (False, True):
        writer = None
        if fifo:
            os.mkfifo('input.fifo')
            writer = os.open('input.fifo', os.O_RDWR | os.O_NONBLOCK)
        try:
            for script, fail_output in (('s/match/NEW/g', False), ('s/match/NEW/g;q', True)):
                with open('sink', 'rb') as sink:
                    process = subprocess.Popen(
                        [binary, '-c', 'sed "$@"', 'check', script,
                         *(['input.fifo'] if fifo else [])],
                        stdin=subprocess.DEVNULL if fifo else subprocess.PIPE,
                        stdout=sink if fail_output else subprocess.PIPE,
                        stderr=subprocess.PIPE, env=env, bufsize=0)
                    try:
                        if fifo:
                            os.write(writer, b'match live\n')
                        else:
                            process.stdin.write(b'match live\n')
                        if fail_output:
                            assert process.wait(timeout=5) != 0
                            assert b'write error' in process.stderr.read()
                            checks += 1
                        else:
                            expect_live(process, b'NEW live\n')
                    finally:
                        stop(process)
        finally:
            if writer is not None:
                os.close(writer)
                os.unlink('input.fifo')

    os.mkfifo('input.fifo')
    writer = os.open('input.fifo', os.O_RDWR | os.O_NONBLOCK)
    process = subprocess.Popen([binary, '-c', 'sed s/match/NEW/g first input.fifo'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, bufsize=0)
    try:
        expect_live(process, b'NEW saved\n')
        os.write(writer, b'match live\n')
        expect_live(process, b'NEW live\n')
    finally:
        stop(process)
        os.close(writer)
        os.unlink('input.fifo')

    # A regular primary input does not justify buffering when the script
    # itself can block reading an auxiliary stream after printing a line.
    os.mkfifo('auxiliary.fifo')
    writer = os.open('auxiliary.fifo', os.O_RDWR | os.O_NONBLOCK)
    process = subprocess.Popen([binary, '-c', "sed -n 'p;R auxiliary.fifo' first"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, bufsize=0)
    try:
        expect_live(process, b'match saved\n')
        os.write(writer, b'auxiliary line\n')
        assert process.wait(timeout=5) == 0
        assert process.stdout.read() == b'auxiliary line\n'
        checks += 1
    finally:
        stop(process)
        os.close(writer)
        os.unlink('auxiliary.fifo')
print(f'sed-streams: {checks} checks passed')
