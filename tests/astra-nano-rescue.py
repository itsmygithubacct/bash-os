#!/usr/bin/env python3
"""Capture the rescue diagnostic separately from terminal rendering.

Only private files and an owned PTY child are used. Control bytes in the
filename are isolated characters, never terminal commands. Raw output is
not printed. Usage: astra-nano-rescue.py BASH-OS
"""
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import stat
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1]).resolve())
for sig in (signal.SIGHUP, signal.SIGTERM):
    with tempfile.TemporaryDirectory(prefix='nano-rescue-check-') as tmp:
        root = Path(tmp)
        name = 'note-\x1b-\x01-\x7f-\u009b-é.txt'
        path = root / name
        path.write_bytes(b'original\n')
        diag = root / 'stderr'
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(root)
            env = dict(os.environ, TERM='xterm', LANG='C.UTF-8', HOME=tmp, PATH='')
            script = 'trap : HUP TERM; nano ' + shlex.quote(name) + ' 2>stderr; printf DONE'
            os.execve(binary, [binary, '--norc', '--noprofile', '-c', script], env)
        original_tio = termios.tcgetattr(fd)
        output = bytearray()
        reaped = False
        def until(predicate):
            end = time.monotonic() + 15
            while not predicate():
                if time.monotonic() >= end:
                    raise AssertionError('timed out waiting for owned editor')
                if select.select([fd], [], [], .05)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        chunk = b''
                    if not chunk:
                        raise AssertionError('editor ended before expected output')
                    output.extend(chunk)
        try:
            until(lambda: b'\x1b[?25h' in output)
            frames = output.count(b'\x1b[?25h')
            os.write(fd, b'X')
            until(lambda: output.count(b'\x1b[?25h') > frames)
            os.kill(pid, sig)
            until(lambda: b'DONE' in output)
            assert termios.tcgetattr(fd) == original_tio, 'termios not restored'
            assert b'\x1b[?1049l' in output, 'alternate screen not restored'
            _, status = os.waitpid(pid, 0)
            reaped = True
            assert os.waitstatus_to_exitcode(status) == 0
            saved = root / (name + '.save')
            assert saved.read_bytes() == b'Xoriginal\n'
            assert stat.S_IMODE(saved.stat().st_mode) == 0o600
            assert path.read_bytes() == b'original\n'
            expected = 'nano: buffer written to note-^[-^A-^?-^{-é.txt.save\n'.encode()
            actual = diag.read_bytes()
            # C1 U+009B maps to ^{ in the editor's display encoder.
            assert actual == expected, 'rescue diagnostic was not safely display-encoded'
            print('ok rescue diagnostic, saved data and terminal restoration:', sig.name)
        finally:
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                except (ProcessLookupError, ChildProcessError):
                    pass
            os.close(fd)
