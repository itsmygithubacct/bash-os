#!/usr/bin/python3
"""VM-only PTY check for external signals during the Pong live loop."""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

shell, signame = sys.argv[1:]
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 42, 82, 0, 0))
before = termios.tcgetattr(slave)
proc = subprocess.Popen([shell, '--noprofile', '--norc', '-c',
                         'termpixel_pong --two-player --seed 1 --fps 20'],
                        stdin=slave, stdout=slave, stderr=slave, close_fds=True)
try:
    deadline = time.monotonic() + 8
    rendered = False
    while time.monotonic() < deadline and proc.poll() is None:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            rendered |= bool(os.read(master, 65536))
        flags = termios.tcgetattr(slave)[3]
        if rendered and not flags & (termios.ICANON | termios.ECHO | termios.ISIG):
            break
    else:
        raise RuntimeError('Pong did not render in raw mode')
    os.kill(proc.pid, getattr(signal, signame))
    deadline = time.monotonic() + 5
    while proc.poll() is None and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            os.read(master, 65536)
    if proc.poll() is None:
        raise RuntimeError('Pong did not exit after ' + signame)
    if proc.returncode != 0:
        raise RuntimeError('unexpected status %s' % proc.returncode)
    if termios.tcgetattr(slave) != before:
        raise RuntimeError('terminal attributes were not restored')
    print('signal-restoration=ok')
finally:
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)
    os.close(master)
    os.close(slave)
