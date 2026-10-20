#!/usr/bin/env python3
"""Byte oracles and private controlling-terminal checks for the more builtin."""
import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

ENV = {'PATH': '', 'LC_ALL': 'C', 'TERM': 'dumb', 'PS1': '', 'PS2': '',
       **{k: v for k, v in os.environ.items()
          if k in ('LD_PRELOAD', 'ASAN_OPTIONS', 'UBSAN_OPTIONS', 'BASH_ENV')}}
PROMPT = b'--More--'
ERASE = b'\r' + b' ' * 50 + b'\r'


class Terminal:
    def __init__(self, binary, rows=8):
        self.master, self.slave = pty.openpty()
        self.size(rows)
        self.saved = termios.tcgetattr(self.slave)
        self.pending = bytearray()
        self.transcript = bytearray()

        def attach():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen([binary, '--noprofile', '--norc', '-i'],
                                     stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                     env=ENV, preexec_fn=attach)
        self.send("PATH=; PS1=; PS2=; printf '__READY__\\n'\n")
        self.until(b'__READY__\r\n')

    def size(self, rows):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, 80, 0, 0))

    def send(self, data):
        os.write(self.master, data.encode() if isinstance(data, str) else data)

    def until(self, marker, timeout=5):
        deadline = time.monotonic() + timeout
        while marker not in self.pending:
            assert time.monotonic() < deadline, (marker, bytes(self.pending), self.proc.poll())
            if select.select([self.master], [], [], min(.1, max(0, deadline-time.monotonic())))[0]:
                try:
                    data = os.read(self.master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        raise AssertionError(('terminal closed', self.proc.poll(), self.pending)) from exc
                    raise
                assert data, ('terminal EOF', self.proc.poll())
                self.pending.extend(data)
                self.transcript.extend(data)
        end = self.pending.index(marker) + len(marker)
        result = bytes(self.pending[:end])
        del self.pending[:end]
        assert b'AddressSanitizer' not in result and b'runtime error:' not in result, result
        return result

    def start(self, command):
        # read leaves the shell waiting in canonical mode so Python can check
        # the terminal before readline establishes its own editing mode.
        self.send(command + "; printf '__DONE__:%s\\n' \"$?\"; IFS= read -r reply\n")

    def done(self, status=0):
        result = self.until(f'__DONE__:{status}\r\n'.encode())
        attrs = termios.tcgetattr(self.slave)
        assert attrs == self.saved, ('termios not restored', attrs, self.saved)
        return result

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
    checks = 0
    failures = []

    def check(name, fn):
        nonlocal checks
        try:
            fn()
            checks += 1
            print('PASS', name, flush=True)
        except Exception as exc:
            failures.append(name)
            print('FAIL', name, repr(exc), flush=True)

    with tempfile.TemporaryDirectory(prefix='sol-more-') as temporary:
        root = Path(temporary)

        def run(script, data=b'', rc=0):
            p = subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; ' + script],
                               input=data, capture_output=True, env=ENV, cwd=root, timeout=10)
            assert p.returncode == rc, (p.returncode, rc, p.stderr)
            assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
            return p

        payloads = [b'', b'one\ntwo\nthree\n', b'unterminated', bytes(range(256))*1025,
                    b'x'*200000+b'\nlast\x00tail', b'\n'*20000]
        for index, data in enumerate(payloads):
            (root/'a').write_bytes(data)
            check(f'bytes regular/stdin/pipe {index}', lambda data=data: (
                require(run('more -n 100 a').stdout == data),
                require(run('more < a').stdout == data),
                require(run('more', data=data).stdout == data)))
        (root/'a').write_bytes(b'AAAA\x00first\n')
        (root/'b').write_bytes(b'BBBB\x00second')
        check('repeated input and stdout ordering', lambda: require(
            run("printf before; more < a; more < b; more < a; printf after").stdout ==
            b'beforeAAAA\x00first\nBBBB\x00secondAAAA\x00first\nafter'))
        headers = b'::::::::::::::\na\n::::::::::::::\nAAAA\x00first\n::::::::::::::\nb\n::::::::::::::\nBBBB\x00second'
        check('multiple-file byte parity', lambda: (
            require(run('more a b').stdout == headers),
            require(subprocess.run(['/usr/bin/more', 'a', 'b'], cwd=root,
                                   capture_output=True, check=True).stdout == headers)))
        for args in ('-n', '-n bad', '-n -1', '-n 99999999999999999999999', '-n2147483648', '-z'):
            check('invalid '+args, lambda args=args: run('more '+args, rc=2))
        check('missing input', lambda: run('more absent', rc=1))
        check('read failure', lambda: run('more .', rc=1))
        check('closed stdin', lambda: run('more <&-', rc=1))
        for command in ('more a', 'more a b', 'more < a'):
            check('write failure and recovery '+command, lambda command=command: require(
                run(f'{command} > /dev/full; rc=$?; more b; exit "$rc"', rc=1).stdout == b'BBBB\x00second'))

        def broken_output():
            read_fd, write_fd = os.pipe()
            os.close(read_fd)
            try:
                p = subprocess.run([binary, '--noprofile', '--norc', '-c',
                                    "PATH=; trap '' PIPE; more a"], stdout=write_fd,
                                   stderr=subprocess.PIPE, cwd=root, env=ENV, timeout=5)
                require(p.returncode == 1 and b'write error' in p.stderr)
            finally:
                os.close(write_fd)
        check('broken pipe reports failure with inherited ignored SIGPIPE', broken_output)

        lines = [f'line-{i:04d}\n'.encode() for i in range(1, 81)]
        (root/'pages').write_bytes(b''.join(lines))
        source = shlex.quote(str(root/'pages'))

        def terminal_test(body):
            t = Terminal(binary)
            try:
                body(t)
            finally:
                t.close()

        def page(t):
            t.start('more -n 3 '+source)
            require(t.until(PROMPT).endswith(b''.join(lines[:3]).replace(b'\n', b'\r\n')+PROMPT))
            for key, start, count in [(b'\n', 3, 1), (b'j', 4, 1), (b'\x1b[B', 5, 1),
                                      (b' ', 6, 3), (b'\x1b[6~', 9, 3), (b'f', 12, 3)]:
                t.send(key)
                require(t.until(PROMPT) == ERASE+b''.join(lines[start:start+count]).replace(b'\n', b'\r\n')+PROMPT)
            t.send(b'q')
            t.done()
        check('PTY page/enter/j/down/PgDn/f/quit restoration', lambda: terminal_test(page))

        def hint(t):
            t.start('more -d -n 3 '+source)
            require(b'line-0003\r\n' in t.until(b'(space=page, enter=line, q=quit)'))
            t.send(b'Q')
            t.done()
        check('PTY -d hint and Q restoration', lambda: terminal_test(hint))

        def ignored(t):
            t.start('more -n 3 '+source)
            t.until(PROMPT)
            t.send(b'\x1b[A\x1b[5~\x1b[H\x1b[D\x1b[Cq')
            require(b'line-0004' not in t.done())
        check('PTY unsupported backward keys stay on page', lambda: terminal_test(ignored))

        def quit_files(t):
            t.start('more -n 3 '+source+' '+source)
            t.until(PROMPT)
            t.send(b'q')
            require(PROMPT not in t.done())
        check('PTY quit stops the full operand list', lambda: terminal_test(quit_files))

        def help_search(t):
            t.start('more -n 3 '+source)
            t.until(PROMPT)
            t.send(b'h')
            out = t.until(PROMPT)
            require(b'help:' in out and b'line-0004' not in out)
            t.send(b'/')
            t.until(b'/')
            t.send(b'line-002X\x7f0\n')
            out = t.until(PROMPT)
            require(b'line-0020\r\n' in out and b'line-0019\r\n' not in out)
            t.send(b'q')
            t.done()
        check('PTY help does not advance; search and backspace', lambda: terminal_test(help_search))

        def nul_search(t):
            (root/'nul-search').write_bytes(b'one\ntwo\nthree\nskip\nprefix\x00needle\nlast\n')
            t.start('more -n 3 '+shlex.quote(str(root/'nul-search')))
            t.until(PROMPT)
            t.send(b'/')
            t.until(b'/')
            t.send(b'needle\n')
            out = t.done()
            require(b'prefix\x00needle\r\nlast\r\n' in out and b'skip\r\n' not in out)
        check('PTY literal search after embedded NUL', lambda: terminal_test(nul_search))

        def resize(t):
            t.start('more '+source)
            t.until(PROMPT)
            t.size(5)
            os.kill(t.proc.pid, signal.SIGWINCH)
            t.send(b' ')
            require(t.until(PROMPT) == ERASE+b''.join(lines[7:11]).replace(b'\n', b'\r\n')+PROMPT)
            t.send(b'q')
            t.done()
        check('PTY resize changes next page', lambda: terminal_test(resize))

        def resize_input(t):
            fifo = root/'resize-fifo'
            os.mkfifo(fifo)
            producer = None
            try:
                # RDWR allows opening the private fixture without waiting for
                # the pager; closing it below delivers real EOF to the reader.
                producer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
                t.start('more '+shlex.quote(str(fifo)))
                os.write(producer, b'before-resize\n')
                t.until(b'before-resize\r\n')
                t.size(20)
                os.kill(t.proc.pid, signal.SIGWINCH)
                os.write(producer, b'after-resize\n')
                os.close(producer)
                producer = None
                require(b'after-resize\r\n' in t.done())
            finally:
                if producer is not None:
                    os.close(producer)
        check('PTY resize during blocked pipe read retains all bytes', lambda: terminal_test(resize_input))

        def eof(t):
            (root/'short').write_bytes(b'one\ntwo\ntail')
            t.start('more -n 10 '+shlex.quote(str(root/'short')))
            out = t.done()
            require(b'one\r\ntwo\r\ntail' in out and PROMPT not in out)
        check('PTY EOF and terminal restoration', lambda: terminal_test(eof))

        def redirected(t):
            t.start('more '+source+' > '+shlex.quote(str(root/'redirected')))
            require(PROMPT not in t.done())
            require((root/'redirected').read_bytes() == b''.join(lines))
        check('PTY redirected stdout drains without key input', lambda: terminal_test(redirected))

        def repeated(t):
            for invocation in range(8):
                if invocation:
                    t.send(b'continue\n')
                t.start('more -n 3 < '+source)
                require(t.until(PROMPT).endswith(b''.join(lines[:3]).replace(b'\n', b'\r\n')+PROMPT))
                t.send(b'\x1bq')  # The shared decoder pushes q back after ESC.
                t.done()
            t.send(b'continue\n')
            t.start('more < '+shlex.quote(str(root/'b')))
            require(b'BBBB\x00second' in t.done())
        check('PTY repeated quit, ESC pushback, and distinct redirected stdin', lambda: terminal_test(repeated))

        def interrupt(t, searching=False, borrowed=False, redirected=False):
            fifo = root/'fifo'
            if not fifo.exists():
                os.mkfifo(fifo)
            producer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                command = 'more -n 3 '+source
                if borrowed:
                    command = 'more '+('< ' if borrowed is True else '')+shlex.quote(str(fifo))
                if redirected:
                    (root/'raw-copy').unlink(missing_ok=True)
                    command += ' > '+shlex.quote(str(root/'raw-copy'))
                # Spell the prompt with octal escapes so echoed command text
                # cannot satisfy the subsequent shell-readiness oracle.
                t.send("PS1=$'\\123\\117\\114\\055\\111\\104\\114\\105\\076'; "
                       "trap 'printf WINCH-TRAP\\\\n' WINCH\n")
                t.until(b'SOL-IDLE>')
                t.start(command)
                if borrowed:
                    os.write(producer, b'stream-line\n')
                    if redirected:
                        deadline = time.monotonic()+5
                        while (not (root/'raw-copy').exists() or
                               (root/'raw-copy').read_bytes() != b'stream-line\n'):
                            require(time.monotonic() < deadline)
                            time.sleep(.01)
                    else:
                        t.until(b'stream-line\r\n')
                else:
                    t.until(PROMPT)
                    if searching:
                        t.send(b'/')
                        t.until(b'/')
                os.kill(t.proc.pid, signal.SIGINT)
                # SIGINT must release the pager without a subsequent command
                # waking its reader (and potentially losing that command's
                # first byte). Inspect only this owned child's descriptors.
                deadline = time.monotonic()+5
                while True:
                    targets = []
                    for fd in Path(f'/proc/{t.proc.pid}/fd').iterdir():
                        try:
                            targets.append(os.readlink(fd))
                        except FileNotFoundError:
                            pass
                    if str(fifo) not in targets and str(root/'pages') not in targets:
                        break
                    require(time.monotonic() < deadline)
                    time.sleep(.01)
                t.until(b'SOL-IDLE>')
                # An interactive interrupt aborts the current compound command.
                t.send("printf '__INTERRUPTED__\\n'; IFS= read -r reply\n")
                t.until(b'__INTERRUPTED__\r\n')
                require(termios.tcgetattr(t.slave) == t.saved)
                fds = list(Path(f'/proc/{t.proc.pid}/fd').iterdir())
                targets = []
                for fd in fds:
                    try:
                        targets.append(os.readlink(fd))
                    except FileNotFoundError:
                        pass
                require(str(fifo) not in targets and str(root/'pages') not in targets)
                t.send(b'continue\n')
                t.send("kill -WINCH $$; printf '__RESTORED__\\n'; IFS= read -r reply\n")
                out = t.until(b'__RESTORED__\r\n')
                require(b'WINCH-TRAP\r\n' in out)
            finally:
                os.close(producer)
        for searching, borrowed in ((False, False), (True, False), (False, True), (False, 'owned')):
            check(f'PTY interrupt cleanup search={searching} stdin={borrowed}',
                  lambda searching=searching, borrowed=borrowed: terminal_test(
                      lambda t: interrupt(t, searching, borrowed)))
        for borrowed in (True, 'owned'):
            check(f'PTY interrupt nonterminal copy stdin={borrowed}',
                  lambda borrowed=borrowed: terminal_test(
                      lambda t: interrupt(t, borrowed=borrowed, redirected=True)))

        def blocked_output(t):
            (root/'blocked-input').write_bytes(b'x'*1048576)
            fifo = root/'blocked-output'
            os.mkfifo(fifo)
            held_reader = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                t.send("PS1=$'\\123\\117\\114\\055\\111\\104\\114\\105\\076'\n")
                t.until(b'SOL-IDLE>')
                t.start('more '+shlex.quote(str(root/'blocked-input'))+' > '+shlex.quote(str(fifo)))
                deadline = time.monotonic()+5
                while True:
                    channel = Path(f'/proc/{t.proc.pid}/wchan').read_text()
                    full = not select.select([], [held_reader], [], 0)[1]
                    if full and ('pipe_write' in channel or 'poll' in channel):
                        break
                    require(time.monotonic() < deadline)
                    time.sleep(.01)
                os.kill(t.proc.pid, signal.SIGINT)
                t.until(b'SOL-IDLE>')
                t.start(':')
                t.done()
                targets = [os.readlink(fd) for fd in Path(f'/proc/{t.proc.pid}/fd').iterdir()]
                require(str(fifo) not in targets and str(root/'blocked-input') not in targets)
            finally:
                os.close(held_reader)
        check('PTY interrupt blocked output without draining pipe', lambda: terminal_test(blocked_output))

        def live_pipe():
            p = subprocess.Popen([binary, '--noprofile', '--norc', '-c', 'PATH=; more'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=ENV, start_new_session=True)
            try:
                p.stdin.write(b'visible before EOF\n')
                p.stdin.flush()
                require(bool(select.select([p.stdout], [], [], 3)[0]))
                require(os.read(p.stdout.fileno(), 1000) == b'visible before EOF\n')
                p.stdin.close()
                require(p.wait(timeout=3) == 0)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
        check('held-open pipe emits line before EOF', live_pipe)
    print(f'sol-more: {checks} passed, {len(failures)} failed')
    return bool(failures)


def require(condition):
    assert condition


if __name__ == '__main__':
    raise SystemExit(main())
