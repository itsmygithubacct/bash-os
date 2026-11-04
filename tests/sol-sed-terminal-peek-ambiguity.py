#!/usr/bin/env python3
"""Show the Linux canonical-tty lookahead ambiguity in a disposable VM.

Run independently of sed: the first observable byte count and poll state are
identical, but a consuming read distinguishes the two queues. This is a
kernel diagnostic, not a substitute for the strict sed/GNU comparison.
"""
import array
import fcntl
import os
import pty
import select
import termios
import time


def observe(eof):
    master, slave = pty.openpty()
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] |= termios.ICANON
        attrs[3] &= ~termios.ECHO
        attrs[6][termios.VEOF] = b'\x04'
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        os.write(master, b'a\n' + (b'\x04' if eof else b'') + b'b\n')
        assert os.read(slave, 2) == b'a\n'
        # Allow the line discipline to finish processing the complete write.
        deadline = time.monotonic() + 5
        while True:
            count = array.array('i', [0])
            fcntl.ioctl(slave, termios.FIONREAD, count, True)
            if count[0] == 2:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(('queued byte count', eof, count[0]))
            time.sleep(0.01)
        poller = select.poll()
        poller.register(slave, select.POLLIN)
        ready = bool(poller.poll(0))
        first_read = os.read(slave, 1)
        return count[0], ready, first_read
    finally:
        os.close(master)
        os.close(slave)


with_eof = observe(True)
without_eof = observe(False)
print('EOF then b:', repr(with_eof))
print('b only:', repr(without_eof))
assert with_eof[:2] == without_eof[:2] == (2, True)
assert with_eof[2] == b'' and without_eof[2] == b'b'
print('sed-terminal-peek-ambiguity: demonstrated')
