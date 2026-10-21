#!/usr/bin/env python3
"""Private-PTY tui API checks. No compiler or timing benchmark is run here."""
import errno
import fcntl
import os
from pathlib import Path
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time


class Terminal:
    def __init__(self, binary, rows=6, cols=20):
        self.master, self.slave = os.openpty()
        self.resize(rows, cols)
        self.saved = termios.tcgetattr(self.slave)
        slave = self.slave
        def attach():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.close(slave)
        self.proc = subprocess.Popen([str(Path(binary).resolve()), '--noprofile', '--norc'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(slave,), preexec_fn=attach,
            env={**os.environ, 'PATH': '', 'TERM': 'xterm-256color', 'COLORTERM': 'truecolor', 'LC_ALL': 'C.UTF-8'})
        self.pending = b''
        self.decoder = Decoder(rows, cols)

    def resize(self, rows, cols):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

    def start(self, script):
        self.proc.stdin.write(('eval '+shlex.quote(script)+'; printf "__DONE__:%s\\n" "$?"\n').encode())
        self.proc.stdin.flush()

    def drain(self):
        output = b''
        while select.select([self.master], [], [], 0)[0]:
            try:
                chunk = os.read(self.master, 65536)
            except OSError as e:
                if e.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output += chunk
        return output

    def done(self, rc=0):
        deadline = time.monotonic()+10
        while b'__DONE__:' not in self.pending or not self.pending.endswith(b'\n'):
            assert time.monotonic() < deadline, ('command timed out', self.pending)
            ready = select.select([self.master, self.proc.stdout], [], [], .1)[0]
            if self.master in ready:
                self._traffic += self.drain()
            if self.proc.stdout in ready:
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                assert chunk, ('child exited', self.proc.poll(), self.proc.stderr.read())
                self.pending += chunk
        output, status = self.pending.rsplit(b'__DONE__:', 1)
        self.pending = b''
        assert int(status) == rc, (int(status), rc, output)
        traffic = self._traffic + self.drain()
        self._traffic = b''
        self.completion_ns = time.perf_counter_ns()
        self.decoder.feed(traffic)
        return output, traffic

    def command(self, script, rc=0, keys=None):
        self._traffic = b''
        self.start(script)
        if keys is not None:
            os.write(self.master, keys)
        return self.done(rc)

    def tty_fd(self):
        target = os.ttyname(self.slave)
        fds = Path('/proc')/str(self.proc.pid)/'fd'
        # This child owns the private PTY as its controlling terminal. The
        # screen helper opens /dev/tty because stdin carries test commands.
        matches = [int(p.name) for p in fds.iterdir()
                   if os.readlink(p) in (target, '/dev/tty')]
        assert len(matches) == 1, ('expected one owned tty descriptor', matches)
        return matches[0]

    def close(self, expected=0):
        if self.proc.poll() is None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
            assert self.proc.returncode == expected, self.proc.returncode
            traffic = self.drain()
            stderr = self.proc.stderr.read()
            assert b'AddressSanitizer' not in stderr and b'runtime error:' not in stderr, stderr
            assert termios.tcgetattr(self.slave) == self.saved, 'terminal modes not restored'
            return traffic, stderr
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            os.close(self.master)
            os.close(self.slave)


class Decoder:
    """Independent ECMA-48 subset oracle; rejects unexpected terminal output."""
    def __init__(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.cells = [[(' ', 0, None, None) for _ in range(cols)] for _ in range(rows)]
        self.y = self.x = 0
        self.attr, self.fg, self.bg = 0, None, None
        self.alt = False
        self.visible = True
        self.printed = 0

    def feed(self, data):
        text = data.decode('utf-8')
        i = 0
        while i < len(text):
            c = text[i]
            if c == '\x1b':
                m = re.match(r'\x1b\[([?0-9;]*)([A-Za-z])', text[i:])
                assert m, repr(text[i:])
                params, op = m.groups()
                i += len(m[0])
                if params.startswith('?'):
                    assert op in 'hl' and params in ('?25', '?1049'), m[0]
                    if params == '?25': self.visible = op == 'h'
                    else: self.alt = op == 'h'
                    continue
                p = [int(v or 0) for v in params.split(';')] if params else [0]
                if op == 'H':
                    self.y = (p[0] or 1)-1
                    self.x = (p[1] or 1)-1 if len(p)>1 else 0
                elif op == 'J':
                    assert p == [2]
                    self.cells = [[(' ', self.attr, self.fg, self.bg) for _ in range(self.cols)] for _ in range(self.rows)]
                elif op == 'K':
                    assert p == [0]
                    for x in range(self.x, self.cols): self.cells[self.y][x] = (' ', self.attr, self.fg, self.bg)
                elif op == 'm':
                    j = 0
                    while j < len(p):
                        v = p[j]
                        if v == 0: self.attr, self.fg, self.bg = 0, None, None
                        elif v in (1,2,3,4,5,7): self.attr |= {1:1,2:2,3:4,4:8,5:16,7:32}[v]
                        elif v == 39: self.fg = None
                        elif v == 49: self.bg = None
                        elif 30 <= v <= 37: self.fg = v-30
                        elif 40 <= v <= 47: self.bg = v-40
                        elif 90 <= v <= 97: self.fg = v-90+8
                        elif 100 <= v <= 107: self.bg = v-100+8
                        elif v in (38,48):
                            if p[j+1] == 5: color = p[j+2]; j += 2
                            else:
                                assert p[j+1] == 2
                                color = tuple(p[j+2:j+5]); j += 4
                            if v == 38: self.fg = color
                            else: self.bg = color
                        else: raise AssertionError(('SGR', p))
                        j += 1
                else: raise AssertionError(m[0])
                continue
            if c == '\r': self.x = 0
            else:
                assert ord(c) >= 32, repr(c)
                # Delayed wrap: a following CUP cancels it; actual text wraps.
                if self.x == self.cols: self.x = 0; self.y += 1
                assert 0 <= self.y < self.rows and 0 <= self.x < self.cols, (self.y, self.x)
                self.cells[self.y][self.x] = (c, self.attr, self.fg, self.bg)
                self.x += 1
                self.printed += 1
            i += 1

    def lines(self):
        return [''.join(c[0] for c in row) for row in self.cells]


def check(binary):
    t = Terminal(binary)
    try:
        assert t.command('type -t tui; type -t top; type -t more')[0] == b'builtin\nbuiltin\nbuiltin\n'
        t.command('tui nonsense', 2)
        t.command('tui refresh', 1)
        t.command('tui init')
        assert t.decoder.alt and not t.decoder.visible
        raw = termios.tcgetattr(t.slave)
        assert not raw[3] & (termios.ECHO | termios.ICANON | termios.ISIG)
        assert t.command('tui lines; tui cols')[0] == b'6\n20\n'
        assert t.command('tui init')[1] == b''
        t.command('tui move 1 2; tui addstr abc; tui addstr def; tui refresh')
        assert t.decoder.lines()[1] == '  abcdef            '
        assert t.command('tui refresh')[1] == b''
        t.command('tui move -1 0; tui addstr hidden; tui move 0 -2; tui addstr ABCD; tui move 5 19; tui addstr XYZ; tui refresh')
        assert t.decoder.lines()[0].startswith('CD')
        assert t.decoder.lines()[5][-1] == 'X'
        t.command('tui erase; tui move 1 1; tui fg "#123456"; tui bg 1,2,3; tui attr bold dim italic underline blink reverse; tui addstr Z; tui refresh')
        assert t.decoder.cells[1][1] == ('Z', 63, (18,52,86), (1,2,3))
        t.command('tui move 2 1; tui fg red; tui bg 200; tui attr normal; tui addstr P; tui refresh')
        assert t.decoder.cells[2][1] == ('P', 0, 1, 200)
        for mode, color in [('16',9), ('256',196), ('truecolor',(255,0,0))]:
            t.command(f'tui colormode {mode}; tui move 3 1; tui fg "#ff0000"; tui bg default; tui addstr R; tui refresh')
            assert t.decoder.cells[3][1] == ('R',0,color,None)
        t.command('tui colormode 16; tui move 4 0; tui fg 196; tui addstr P; tui refresh')
        assert t.decoder.cells[4][0] == ('P',0,9,None)
        t.command('tui colormode truecolor')
        t.command("tui erase; tui addansi $'A\\e[1;31mB\\e[0mC\\e[2J\\tD\\001\\177'; tui refresh")
        assert t.decoder.lines()[0].startswith('ABC     D^A^?')
        assert t.decoder.cells[0][1] == ('B',1,1,None)
        t.command("tui move 1 0; tui addansi $'\\e[38;5;123;48;2;4;5;6mX\\e[39;49mY'; tui refresh")
        assert t.decoder.cells[1][0] == ('X',0,123,(4,5,6))
        assert t.decoder.cells[1][1] == ('Y',0,None,None)
        t.command("tui move 2 0; tui addansi $'\\e[999999999999999999999999999mQ\\e[?25lR'; tui refresh")
        assert t.decoder.lines()[2].startswith('QR')
        t.command('tui erase; tui fg default; tui bg default; tui attr normal; tui box; tui move 2 2; tui hline é 3; tui move 1 10; tui vline 3; tui refresh')
        assert t.decoder.lines()[0] == '┌'+'─'*18+'┐'
        assert t.decoder.lines()[2][2:5] == 'ééé'
        assert all(t.decoder.lines()[y][10] == '│' for y in (1,2,3))
        t.command('tui move 2 2; tui clrtoeol; tui refresh')
        assert t.decoder.lines()[2][2:] == ' '*18
        t.command('tui move 3 1; tui clrtobot; tui refresh')
        assert t.decoder.lines()[3][1:] == ' '*19
        assert t.decoder.lines()[4:] == [' '*20]*2
        # Invalid calls must neither silently truncate arguments nor mutate cells.
        bad = ['init extra','end extra','refresh extra','move x 0','move 0', 'move 0 0 extra',
               'move 99999999999999999999999 0', 'timeout junk','timeout -2','fg nope','fg "#zz00ff"',
               'fg 256','bg 256,0,0','fg 1,2,3junk','attr bogus','hline -1','hline xy 3',
               'hline "" 2','vline 2 extra extra','addstr','addstr -y x hi','addstr -x',
               'addstr hi extra','getstr a b','getkey extra','colormode 8','colormode 16 extra',
               'attr normal normal normal normal normal normal normal normal bogus']
        snapshot = [row[:] for row in t.decoder.cells]
        for command in bad: t.command('tui '+command,2)
        t.command('tui refresh')
        assert t.decoder.cells == snapshot
        # Numeric stdout failures must report failure and clear on the next call.
        t.command('tui lines >/dev/full',1)
        assert t.command('tui lines')[0] == b'6\n'
        # Inject failure into the actual tty descriptor, then restore and retry.
        fd = t.tty_fd()
        t.command(f'exec {{saved_tty}}<&{fd}; exec {fd}>/dev/full; tui move 0 0; tui addstr retry; tui refresh',1)
        t.command(f'exec {fd}<&$saved_tty; exec {{saved_tty}}<&-; tui refresh')
        assert t.decoder.lines()[0].startswith('retry')
        t.command('tui timeout 0')
        assert t.command('tui getkey',2)[0] == b''
        t.command('tui timeout 15')
        assert t.command('tui getkey',2)[0] == b''
        t.command('tui timeout -1')
        for key, token in [(b'q',b'q'),(b'\x1b[A',b'UP'),(b'\x1bOB',b'DOWN'),(b'\x1b[6~',b'PGDN'),
                           (b'\x1bOP',b'F1'),(b'\x7f',b'BS'),(b'\t',b'TAB'),(b'\r',b'RET'),(b'\x01',b'C-A'),(b'\x1b',b'ESC')]:
            assert t.command('tui getkey',keys=key)[0] == token+b'\n'
        assert t.command('tui getkey; tui getkey',keys=b'\x1bz')[0] == b'ESC\nz\n'
        assert t.command('tui getkey',keys=b'\x1bz')[0] == b'ESC\n'
        t.command('tui end; tui init; tui timeout 0')
        t.command('tui getkey',2)  # Re-init discards the previous session's pushback.
        t.command('tui timeout -1')
        assert t.command('tui getstr -y 4 -x 0 prompt:',keys=b'ab\x7fc\r')[0] == b'ac\n'
        t.command('tui getstr cancel:',1,keys=b'\x1b')
        fd = t.tty_fd()
        t.command(f'exec {{saved_tty}}<&{fd}; exec {fd}</dev/null; tui getkey',1)
        t.command(f'exec {fd}<&$saved_tty; exec {{saved_tty}}<&-')
        # Query-before-refresh must apply the resize rather than losing SIGWINCH.
        t.command('tui erase; tui move 1 1; tui addstr keep; tui refresh')
        t.resize(8,24)
        os.kill(t.proc.pid, signal.SIGWINCH)
        assert t.command('tui resized')[0] == b'1\n'
        assert t.command('tui lines; tui cols')[0] == b'8\n24\n'
        t.decoder = Decoder(8,24)
        t.command('tui refresh')
        assert t.decoder.lines()[1][1:5] == 'keep'
        assert t.command('tui resized',1)[0] == b'0\n'
        t.resize(3,10)
        os.kill(t.proc.pid, signal.SIGWINCH)
        t.decoder = Decoder(3,10)
        t.command('tui refresh')
        assert t.command('tui lines; tui cols')[0] == b'3\n10\n'
        assert t.command('tui resized')[0] == b'1\n'
        assert t.decoder.lines()[1][1:5] == 'keep'
        t.resize(8,24)
        os.kill(t.proc.pid, signal.SIGWINCH)
        t.decoder = Decoder(8,24)
        t.command('tui refresh')
        t.command('tui erase; tui move 0 0; tui addstr '+('A'*192)+'; tui move 0 0; tui refresh')
        printed = t.decoder.printed
        assert t.command('tui move 0 0; tui addstr '+('A'*192)+'; tui move 0 0; tui refresh')[1] == b''
        traffic = t.command('tui move 2 3; tui addstr B; tui move 2 20; tui addstr B; tui move 0 0; tui refresh')[1]
        assert traffic == b'\x1b[3;4HB\x1b[3;21HB\x1b[1;1H', traffic
        assert t.decoder.printed-printed == 2
        assert t.decoder.lines()[2] == 'AAA'+'B'+'A'*16+'B'+'A'*3
        printed = t.decoder.printed
        traffic = t.command('tui move 0 0; tui addstr '+('C'*192)+'; tui move 0 0; tui refresh')[1]
        expected = b'C'*24+b''.join(f'\x1b[{y};1H'.encode()+b'C'*24 for y in range(2,9))+b'\x1b[1;1H'
        assert traffic == expected
        assert t.decoder.printed-printed == 192
        assert t.decoder.lines() == ['C'*24]*8
        t.command('tui end; tui end')
        assert termios.tcgetattr(t.slave) == t.saved
        assert not t.decoder.alt and t.decoder.visible
        t.command('tui init; tui refresh')
        assert t.decoder.lines() == [' '*24]*8
        # Subshell query must not tear down the parent's active terminal.
        assert t.command('value=$(tui cols); printf "%s\\n" "$value"')[0] == b'24\n'
        assert not termios.tcgetattr(t.slave)[3] & termios.ICANON
        fdcount = len(list((Path('/proc')/str(t.proc.pid)/'fd').iterdir()))
        for _ in range(10): t.command('tui end; tui init')
        assert len(list((Path('/proc')/str(t.proc.pid)/'fd').iterdir())) == fdcount
        t.command('tui end')
        assert t.command("trap 'printf restored' WINCH; tui init; tui end; kill -WINCH $$")[0] == b'restored'
    finally:
        t.close()
    # Automatic process-exit restoration, and signal restoration, in owned PTYs.
    for sig in (None, signal.SIGTERM, signal.SIGHUP):
        t = Terminal(binary)
        t.command('tui init; tui addstr exit; tui refresh')
        if sig: os.kill(t.proc.pid,sig)
        traffic, _ = t.close(-sig if sig else 0)
        assert b'\x1b[?1049l' in traffic and b'\x1b[?25h' in traffic
    p = subprocess.run([str(Path(binary).resolve()), '-c', 'PATH=; tui init'],
                       stdin=subprocess.DEVNULL, capture_output=True, start_new_session=True)
    assert p.returncode == 1, (p.returncode,p.stderr)
    print('sol-tui: persistent cells, clipping, rendition, ANSI, keys, resize, arguments and lifecycle passed')


if __name__ == '__main__':
    check(sys.argv[1] if len(sys.argv)>1 else 'out/bash-sol-tui')
