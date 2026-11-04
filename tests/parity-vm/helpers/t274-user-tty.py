#!/usr/bin/env python3
"""Guest-only PTY and utmp selection regression; use a disposable VM."""
import os
import select
import struct
import subprocess
import sys
import tempfile


def record(user, line):
    return struct.pack('<hxxi32s4s32s256shhiii4i20s', 7, 42,
                       line.encode(), b'p1', user.encode(), b'',
                       0, 0, 0, 1, 0, 0, 0, 0, 0, b'')


def drain(fd):
    result = b''
    while select.select([fd], [], [], 0.2)[0]:
        result += os.read(fd, 4096)
    return result


def main():
    pairs = [os.openpty(), os.openpty()]
    try:
        lines = [os.ttyname(s)[5:] for _, s in pairs]
        for _, s in pairs:
            os.fchmod(s, 0o620)
        with tempfile.TemporaryDirectory() as work:
            utmp = os.path.join(work, 'utmp')
            with open(utmp, 'wb') as f:
                f.write(record('alice_t274', lines[0]))
                f.write(record('alice_t274', lines[1]))
                f.write(record('evil_t274', '../outside'))
            env = dict(os.environ, BASHWALL_UTMP=utmp, BASHWALL_DEV_DIR='/dev',
                       BASHWALL_FORCE_MESG='1', BASHWALL_NOBANNER='1', LC_ALL='C')
            def run(*args):
                return subprocess.run([sys.argv[1], '--noprofile', '--norc', '-c',
                                       '[[ $(type -t write) == builtin ]] || exit 99; write "$@"',
                                       't274', *args], input=b't274-marker\n',
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=env, timeout=10)
            r = run('alice_t274', lines[1])
            assert r.returncode == 0, (r.returncode, r.stderr)
            assert b't274-marker' not in drain(pairs[0][0])
            assert b't274-marker' in drain(pairs[1][0])
            print('explicit-tty=ok')
            r = run('alice_t274', 'pts/nonexistent')
            assert r.returncode != 0 and b't274-marker' not in drain(pairs[0][0])
            assert b't274-marker' not in drain(pairs[1][0])
            print('invalid-tty=ok')
            r = run('evil_t274')
            assert r.returncode != 0 and b't274-marker' not in drain(pairs[0][0])
            assert b't274-marker' not in drain(pairs[1][0])
            print('unsafe-utmp=ok')
    finally:
        for pair in pairs:
            for fd in pair:
                os.close(fd)


if __name__ == '__main__':
    main()
