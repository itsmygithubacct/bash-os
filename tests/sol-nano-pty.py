#!/usr/bin/env python3
"""Second-pass PTY checks for the nano builtin.

Every session runs the builtin with an empty PATH on a private PTY and
types through the real terminal input path.  Groups:

  burst      keys that arrive in one write (arrows, Alt keys, UTF-8, editing)
             are framed one key at a time; seeded random bursts must give the
             same file as GNU nano given the same bytes
  movement   up/down keep the screen column across short lines, tabs and
             wide characters, compared with GNU nano
  display    tabs expand, and control sequences inside a file or a file
             name never reach the terminal
  signals    SIGTERM/SIGHUP and a closed terminal restore the terminal,
             write FILE.save without overwriting anything, then let the
             shell's own disposition act; ignored signals stay ignored
  justify    widths and relative fill against GNU nano, undo/redo round trip
  spell      replace/skip/cancel through the prompt, a helper failure, and a
             hung helper stopped by SIGTERM
  complete   UTF-8 fragment, cycling, wrap and undo
  selection  the marked text survives edits before it, undo and redo
  highlight  syntax colours follow an edit and its undo, also deep in a 1 MiB script
  restore    termios and the alternate screen after normal exit

GNU nano (/usr/bin/nano) is the oracle where one is used.  Without it those
comparisons are reported as SKIPPED and the run exits 3, never as passed.

Usage: tests/sol-nano-pty.py BASH-OS-BINARY [GROUP...]
"""
import fcntl
import os
import pty
import random
import select
import shutil
import signal
import stat
import struct
import sys
import tempfile
import termios
import time
from pathlib import Path

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
GNU = shutil.which("nano", path="/usr/bin:/bin")
checks = 0
skips = []

ESC = b"\x1b"
UP, DOWN, RIGHT, LEFT = b"\x1b[A", b"\x1b[B", b"\x1b[C", b"\x1b[D"
BS, ENTER = b"\x7f", b"\r"
C = {c: bytes([ord(c) & 0x1f]) for c in "abdefghijklnopqrstuvwxyz"}
SAVE, EXIT, UNDO = C["s"], C["x"], C["z"]
JUSTIFY, SPELL, COMPLETE = b"\x0a", b"\x14", b"\x1d"
FRAME = b"\x1b[?25h"


def check(cond, what):
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1
    print(f"ok {checks} - {what}", flush=True)


def skip(what):
    skips.append(what)
    print(f"# SKIP {what}", flush=True)


def pass_env():
    env = {}
    for name in ("BASH_ENV", "LD_PRELOAD", "ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


class Session:
    def __init__(self, script, cwd, gnu=False, rows=24, cols=80, env=None):
        self.out = b""
        child_env = {"TERM": "xterm", "LANG": "C.UTF-8", "HOME": str(cwd), "PATH": ""}
        if not gnu:
            child_env.update(pass_env())
        child_env.update(env or {})
        pid, fd = pty.fork()
        if pid == 0:
            try:
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                os.chdir(cwd)
                os.execve(binary, [binary, "--norc", "--noprofile", "-c", script], child_env)
            finally:
                os._exit(127)
        self.pid, self.fd, self.status = pid, fd, None

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while (left := end - time.monotonic()) > 0:
            r, _, _ = select.select([self.fd], [], [], min(left, 0.05))
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                self.out += data
        return True

    def wait_for(self, needle, timeout=8.0, start=0):
        end = time.monotonic() + timeout
        while needle not in self.out[start:]:
            if time.monotonic() > end:
                raise AssertionError(f"timed out waiting for {needle!r}; tail {self.out[-300:]!r}")
            if not self.pump(0.05) and needle not in self.out[start:]:
                raise AssertionError(f"session ended before {needle!r}; tail {self.out[-300:]!r}")

    def frames(self):
        return self.out.count(FRAME)

    def key(self, data, frame=True):
        before = self.frames()
        os.write(self.fd, data)
        if frame:
            end = time.monotonic() + 8
            while self.frames() <= before:
                if time.monotonic() > end:
                    raise AssertionError(f"no frame after {data!r}; tail {self.out[-300:]!r}")
                if not self.pump(0.02):
                    break

    def keys(self, *seq):
        for k in seq:
            self.key(k)

    def settle(self, quiet=0.3, timeout=8.0):
        """Wait until output has been quiet for QUIET seconds (GNU nano draws
        without a fixed end-of-frame marker)."""
        end = time.monotonic() + timeout
        last = len(self.out)
        mark = time.monotonic()
        while time.monotonic() < end:
            if not self.pump(0.05):
                return
            if len(self.out) != last:
                last, mark = len(self.out), time.monotonic()
            elif time.monotonic() - mark >= quiet:
                return

    def finish(self, timeout=12.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.pump(0.05)
            pid, st = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.pump(0.1)
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.status = os.waitstatus_to_exitcode(st)
                return self.status
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        os.close(self.fd)
        raise AssertionError(f"session did not exit; tail {self.out[-300:]!r}")


def q(p):
    return "'" + str(p).replace("'", "'\\''") + "'"


def ours_session(d, script, **kw):
    s = Session(script, d, **kw)
    s.wait_for(FRAME)
    return s


def gnu_edit(d, name, args, body):
    """Run GNU nano on NAME with BODY(session) and return the saved bytes."""
    s = Session(f"exec {q(GNU)} --ignorercfiles {args} {q(name)}", d, gnu=True)
    s.settle(0.4)
    body(s)
    s.finish()
    return (d / name).read_bytes()


# ---- burst framing --------------------------------------------------------

def burst(d):
    src = b"0123456789\nsecond line here\n\xe4\xb8\xad\xe6\x96\x87 wide\n"

    def ours(name, payload):
        (d / name).write_bytes(src)
        s = ours_session(d, f"nano {name}")
        os.write(s.fd, payload)
        s.pump(0.6)
        s.keys(SAVE)
        s.key(EXIT, frame=False)
        return s.finish(), (d / name).read_bytes(), s

    st, got, s = ours("b0.txt", RIGHT + RIGHT + b"ab" + LEFT + b"c")
    check(st == 0 and got.startswith(b"01acb23456789\n"),
          "arrows and text sent in one write are framed one key at a time")
    frames = s.frames()
    check(frames < 8, f"a burst draws few frames ({frames}) instead of one per key")

    st, got, _ = ours("b1.txt", ESC + b"a" + RIGHT + RIGHT + RIGHT + ESC + b"^" + C["e"] + C["u"])
    check(st == 0 and got.startswith(b"0123456789012\n"),
          "Alt keys inside a burst (M-A mark, M-^ copy) are not swallowed")

    st, got, _ = ours("b2.txt", DOWN + DOWN + "é".encode() + ESC + ESC + b"[C" + b"\xc3" + b"Z")
    # ESC alone does nothing, ESC [ C moves over 中, the lone 0xc3 is
    # dropped, and Z is typed.
    check(st == 0 and got.split(b"\n")[2] == "é中Z文 wide".encode(),
          "ESC ESC [ C and a broken UTF-8 lead keep the following keys")

    if not GNU:
        skip("GNU nano not installed: random burst oracle")
        return
    rng = random.Random(4242)
    keyset = [RIGHT, LEFT, UP, DOWN, BS, ENTER, C["a"], C["e"], C["d"], b"\t",
              b"x", b"y", b"z", b" ", "é".encode(), "中".encode(), "ü".encode()]
    differing = 0
    for case in range(16):
        text = b"".join(rng.choice([b"alpha beta\n", "中文字 x\n".encode(), b"\tindent\n",
                                    b"short\n", "wörld é\n".encode(), b"\n"]) for _ in range(6))
        payload = b"".join(rng.choice(keyset) for _ in range(rng.randint(20, 60)))
        name = f"o{case}.txt"
        (d / name).write_bytes(text)
        s = ours_session(d, f"nano {name}")
        os.write(s.fd, payload)
        s.pump(0.5)
        s.keys(SAVE)
        s.key(EXIT, frame=False)
        check(s.finish() == 0, f"burst oracle {case + 1}: bash-os session exits 0")
        mine = (d / name).read_bytes()

        (d / name).write_bytes(text)

        def body(g):
            os.write(g.fd, payload)
            g.settle(0.4)
            os.write(g.fd, SAVE)
            g.settle(0.3)
            os.write(g.fd, EXIT)
        # By default GNU nano keeps an empty "magic line" at the end and adds
        # a final newline; this builtin saves exactly the typed text, which
        # is GNU nano's --nonewlines model, so the oracle runs with -L.
        theirs = gnu_edit(d, name, "-L", body)
        check(mine == theirs, f"burst oracle {case + 1}: {len(payload)}-byte burst gives GNU nano's file"
              + ("" if mine == theirs else f" ours={mine!r} gnu={theirs!r}"))
        differing += mine != text
    check(differing >= 12, f"burst oracle changed {differing}/16 files (at least 12 required)")


# ---- vertical movement ----------------------------------------------------

def movement(d):
    text = "abcdefghij\nab\n中文中文中文\n\tx\nmixed é中a\n".encode()
    seqs = [
        [RIGHT] * 6 + [DOWN, DOWN, b"X", LEFT, DOWN, DOWN, b"Y"],
        [RIGHT] * 7 + [DOWN, DOWN, b"P", UP, UP, b"Q"],
        [DOWN, DOWN, RIGHT, RIGHT, RIGHT, DOWN, b"T", DOWN, b"U", UP, UP, UP, UP, b"V"],
        [C["e"], DOWN, DOWN, DOWN, DOWN, b"E", UP, UP, b"F"],
        [DOWN, DOWN, DOWN, RIGHT, RIGHT, UP, b"G", C["n"], C["n"], b"H"],
    ]
    for i, seq in enumerate(seqs):
        name = f"m{i}.txt"
        (d / name).write_bytes(text)
        s = ours_session(d, f"nano {name}")
        s.keys(*seq, SAVE)
        s.key(EXIT, frame=False)
        check(s.finish() == 0, f"movement {i + 1}: session exits 0")
        mine = (d / name).read_bytes()
        if not GNU:
            skip(f"GNU nano not installed: movement oracle {i + 1}")
            continue
        (d / name).write_bytes(text)

        def body(g):
            for k in seq:
                os.write(g.fd, k)
                g.settle(0.08, timeout=2)
            os.write(g.fd, SAVE)
            g.settle(0.3)
            os.write(g.fd, EXIT)
        theirs = gnu_edit(d, name, "-L", body)
        check(mine == theirs and mine != text,
              f"movement {i + 1}: up/down land on GNU nano's screen columns"
              + ("" if mine == theirs else f" ours={mine!r} gnu={theirs!r}"))


# ---- display safety -------------------------------------------------------

def display(d):
    evil = b"a\x1b]0;PWNED\x07b\x1b[2J\x1b[31mred\xc2\x9b31m\x80\tz\n"
    (d / "evil.txt").write_bytes(evil)
    s = ours_session(d, "nano evil.txt")
    s.keys(C["e"])
    s.key(EXIT, frame=False)
    st = s.finish()
    body = s.out
    check(st == 0 and b"\x1b]" not in body and b"\x07" not in body and b"\x1b[31m" not in body
          and b"\x1b[2J" not in body and b"\xc2\x9b" not in body,
          "OSC, BEL, SGR, clear-screen and C1 bytes from a file never reach the terminal")
    check("a^[]0;PWNED^Gb^[[2J^[[31mred^{31m\ufffd      z".encode() in body,
          "the same bytes are shown in caret form, with U+FFFD and an expanded tab")
    # columns: a1 ^[2 ]0;PWNED8 ^G2 b1 ^[2 [2J3 ^[2 [31mred7 ^{2 31m3 U+FFFD1 = 34, tab to 40, z 41
    check(b"\x1b[2;42H" in body, "the cursor after ^E sits at screen column 42, matching the drawn text")

    odd = d / "x\x1b[2Jname.txt"
    odd.write_bytes(b"x\n")
    s = ours_session(d, "nano " + q(odd.name))
    s.key(EXIT, frame=False)
    st = s.finish()
    check(st == 0 and b"x^[[2Jname.txt" in s.out and b"\x1b[2J" not in s.out,
          "a file name with an escape sequence is shown in caret form")

    s = ours_session(d, "nano evil.txt", cols=40)
    s.keys(C["g"])
    st_out = s.out
    s.key(EXIT, frame=False)
    s.finish()
    last = st_out[st_out.rfind(b"\x1b[7m "):]
    shown = last[len(b"\x1b[7m "):last.find(b" \x1b[K")]
    check(0 < len(shown) <= 37 and shown.startswith(b"^O/^S Save"),
          f"^G help on a 40-column terminal is cut to {len(shown)} cells instead of wrapping")


# ---- termination signals --------------------------------------------------

def signals(d):
    stty = shutil.which("stty", path="/usr/bin:/bin")
    (d / "t.txt").write_bytes(b"original\n")
    script = (f"trap '{stty} -g > after.txt; echo TRAPPED; exit 7' TERM; "
              f"{stty} -g > before.txt; nano t.txt; echo NOT-REACHED")
    s = ours_session(d, script)
    s.keys(b"X", b"Y")
    os.kill(s.pid, signal.SIGTERM)
    s.wait_for(b"TRAPPED")
    st = s.finish()
    saved = d / "t.txt.save"
    check(st == 7 and b"NOT-REACHED" not in s.out,
          "SIGTERM ends the session and the shell's TERM trap then runs (exit 7)")
    check((d / "before.txt").read_text() == (d / "after.txt").read_text(),
          "termios is restored exactly before the trap runs")
    check(s.out.rfind(b"\x1b[?1049l") > s.out.rfind(FRAME), "the alternate screen is left after the last frame")
    check(saved.read_bytes() == b"XYoriginal\n" and stat.S_IMODE(saved.stat().st_mode) == 0o600
          and (d / "t.txt").read_bytes() == b"original\n",
          "the modified buffer is rescued to t.txt.save (0600); t.txt is untouched")
    check(b"nano: buffer written to t.txt.save" in s.out, "the rescue file is reported on stderr")

    # A second rescue does not overwrite the first; the session is killed by
    # SIGHUP's default action once the terminal is restored.
    s = Session("printf 'READY\\n'; read -r go; nano t.txt", d)
    s.wait_for(b"READY")
    s.pump(0.2)
    cooked = termios.tcgetattr(s.fd)
    s.key(b"go\r")
    s.wait_for(b"nano  t.txt")
    s.keys(b"Z")
    os.kill(s.pid, signal.SIGHUP)
    st = s.finish()
    check(st == -signal.SIGHUP, f"SIGHUP with the default disposition still kills the shell ({st})")
    check(saved.read_bytes() == b"XYoriginal\n" and (d / "t.txt.save.1").read_bytes() == b"Zoriginal\n",
          "a second rescue goes to t.txt.save.1 and leaves t.txt.save alone")

    # The terminal disappears: closing the master hangs up the session.
    s = Session("printf 'READY\\n'; read -r go; nano t.txt", d)
    s.wait_for(b"READY")
    s.key(b"go\r")
    s.wait_for(b"nano  t.txt")
    s.keys(b"H")
    os.close(s.fd)
    end = time.monotonic() + 10
    while time.monotonic() < end:
        pid, st = os.waitpid(s.pid, os.WNOHANG)
        if pid:
            break
        time.sleep(0.05)
    else:
        os.kill(s.pid, signal.SIGKILL)
        os.waitpid(s.pid, 0)
        raise AssertionError("session survived its terminal")
    check((d / "t.txt.save.2").read_bytes() == b"Horiginal\n",
          "closing the terminal (hangup) rescues the buffer to t.txt.save.2")

    # An unmodified buffer writes nothing; termios is restored even though
    # the shell is then killed.
    s = Session("printf 'READY\\n'; read -r go; nano t.txt", d)
    s.wait_for(b"READY")
    s.pump(0.2)
    cooked = termios.tcgetattr(s.fd)
    s.key(b"go\r")
    s.wait_for(b"nano  t.txt")
    s.keys(RIGHT)
    raw = termios.tcgetattr(s.fd)
    os.kill(s.pid, signal.SIGTERM)
    s.pump(0.5)
    after = termios.tcgetattr(s.fd)
    st = s.finish()
    check(raw != cooked and after == cooked and st == -signal.SIGTERM,
          "SIGTERM restores the cooked termios before the default action kills the shell")
    check(not (d / "t.txt.save.3").exists(), "an unmodified buffer is not rescued")

    # A signal the shell ignores stays ignored; later calls work normally.
    s = ours_session(d, "trap '' TERM; nano t.txt; echo FIRST=$?; nano t.txt; echo SECOND=$?")
    s.keys(b"I")
    os.kill(s.pid, signal.SIGTERM)
    s.pump(0.4)
    s.keys(b"J", SAVE)
    s.key(EXIT, frame=False)
    s.wait_for(b"FIRST=0")
    s.wait_for(FRAME, start=s.out.find(b"FIRST=0"))
    s.key(EXIT, frame=False)
    st = s.finish()
    check(st == 0 and b"SECOND=0" in s.out and (d / "t.txt").read_bytes() == b"IJoriginal\n"
          and not (d / "t.txt.save.3").exists(),
          "with TERM ignored the editor keeps running, and the next call is unaffected")

    # A trapped signal ends only the current call: the next call in the same
    # shell installs fresh handlers and starts clean.  The status is read
    # with || so the check also holds under set -e (the sanitizer loader).
    (d / "u.txt").write_bytes(b"u\n")
    s = ours_session(d, "trap 'echo CAUGHT' TERM; nano u.txt || echo FIRST=$?; nano u.txt; echo SECOND=$?")
    s.keys(b"1")
    os.kill(s.pid, signal.SIGTERM)
    s.wait_for(b"CAUGHT")
    s.wait_for(b"FIRST=143")
    s.wait_for(FRAME, start=s.out.find(b"FIRST=143"))
    s.keys(b"2", SAVE)
    s.key(EXIT, frame=False)
    st = s.finish()
    check(st == 0 and b"SECOND=0" in s.out and (d / "u.txt").read_bytes() == b"2u\n"
          and (d / "u.txt.save").read_bytes() == b"1u\n",
          "after a trapped SIGTERM (status 143) the next call edits and saves normally")


# ---- justify --------------------------------------------------------------

def justify(d):
    para = (b"The quick brown fox jumps over the lazy dog while   the cat  watches.  "
            b"Then it naps.\n  indented second line keeps going with more words here\n"
            b"\n> quoted text that runs on and on past the fill width for sure\n> more quoted\n")
    for opts, cols in (("--fill=30", 80), ("-r 45 -M", 80), ("--fill=-20", 60), ("-r 0", 50)):
        name = f"j{opts.replace(' ', '').replace('=', '').replace('-', '_')}.txt"
        (d / name).write_bytes(para)
        s = ours_session(d, f"nano {opts} {name}", cols=cols)
        s.keys(ESC + b"j", SAVE)
        once = (d / name).read_bytes()
        s.keys(UNDO, SAVE)
        undone = (d / name).read_bytes()
        s.keys(ESC + b"e", SAVE)
        redone = (d / name).read_bytes()
        s.key(EXIT, frame=False)
        check(s.finish() == 0 and once != para and undone == para and redone == once,
              f"M-J {opts} at {cols} columns, one undo restores the text and redo re-applies it")
        if not GNU:
            skip(f"GNU nano not installed: justify {opts}")
            continue
        (d / name).write_bytes(para)

        def body(g):
            os.write(g.fd, ESC + b"j")
            g.settle(0.3)
            os.write(g.fd, SAVE)
            g.settle(0.3)
            os.write(g.fd, EXIT)
        s2 = Session(f"exec {q(GNU)} --ignorercfiles {opts} {q(name)}", d, gnu=True, cols=cols)
        s2.settle(0.4)
        body(s2)
        s2.finish()
        theirs = (d / name).read_bytes()
        check(once == theirs, f"M-J {opts} at {cols} columns equals GNU nano"
              + ("" if once == theirs else f" ours={once!r} gnu={theirs!r}"))

    # ^J on one paragraph, then the next: the cursor walks the file.
    (d / "jj.txt").write_bytes(b"aaa bbb ccc ddd eee\n\nfff ggg hhh iii jjj\n")
    s = ours_session(d, "nano --fill=10 jj.txt")
    s.keys(JUSTIFY)
    s.wait_for(b"Justified paragraph")
    s.keys(JUSTIFY, SAVE)
    s.key(EXIT, frame=False)
    check(s.finish() == 0 and (d / "jj.txt").read_bytes()
          == b"aaa bbb \nccc ddd \neee\n\nfff ggg \nhhh iii \njjj\n",
          "repeated ^J justifies one paragraph after another")


# ---- spell ----------------------------------------------------------------

def spell(d):
    helper = d / "speller.sh"
    helper.write_text("read -r -d '' text || :; printf '%s\\n' teh wrold\n")
    cmd = f"{binary} --norc {helper}"
    (d / "s.txt").write_bytes(b"teh wrold is teh best wrold\n")
    s = ours_session(d, f"nano --speller={q(cmd)} s.txt")
    s.keys(SPELL)
    s.wait_for(b"Edit a replacement: teh")
    s.keys(BS, BS, b"he", ENTER)
    s.wait_for(b"Edit a replacement: wrold")
    s.keys(ENTER)                       # unchanged: skip
    s.wait_for(b"Finished checking spelling (2 replaced)")
    s.keys(SAVE)
    replaced = (d / "s.txt").read_bytes()
    s.keys(UNDO, SAVE)
    undone = (d / "s.txt").read_bytes()
    s.key(EXIT, frame=False)
    check(s.finish() == 0 and replaced == b"the wrold is the best wrold\n"
          and undone == b"teh wrold is teh best wrold\n",
          "spell: a replacement edits every whole word once, Enter unchanged skips, one ^Z undoes it")

    s = ours_session(d, f"nano --speller={q(cmd)} s.txt")
    s.keys(SPELL)
    s.wait_for(b"Edit a replacement: teh")
    s.keys(ESC)
    s.wait_for(b"Spell check cancelled (0 replaced)")
    s.key(EXIT, frame=False)
    check(s.finish() == 0 and (d / "s.txt").read_bytes() == b"teh wrold is teh best wrold\n",
          "spell: Esc cancels and leaves the buffer unmodified (^X exits without a prompt)")

    bad = d / "bad.sh"
    bad.write_text("echo nope >&2; exit 4\n")
    s = ours_session(d, f"nano --speller={q(f'{binary} --norc {bad}')} s.txt")
    s.keys(SPELL)
    s.wait_for(b"Spell helper failed (exit 4)")
    s.key(EXIT, frame=False)
    check(s.finish() == 0 and b"nope" not in s.out, "spell: a failing helper is reported; its stderr stays off the screen")

    hang = d / "hang.sh"
    pidfile = d / "hang.pid"
    hang.write_text(f"echo $$ > {q(pidfile)}; while :; do :; done\n")
    s = ours_session(d, f"trap 'echo GOT-TERM' TERM; nano --speller={q(f'{binary} --norc {hang}')} s.txt || echo RC=$?")
    os.write(s.fd, SPELL)
    end = time.monotonic() + 5
    while not pidfile.exists() and time.monotonic() < end:
        time.sleep(0.05)
    t0 = time.monotonic()
    os.kill(s.pid, signal.SIGTERM)
    s.wait_for(b"RC=143", timeout=8)
    elapsed = time.monotonic() - t0
    st = s.finish()
    hpid = int(pidfile.read_text())
    alive = Path(f"/proc/{hpid}").exists()
    if alive:                           # never leave a spinning helper behind
        os.kill(hpid, signal.SIGKILL)
    check(st == 0 and elapsed < 3 and not alive and b"GOT-TERM" in s.out,
          f"SIGTERM during a hung helper stops it within {elapsed:.2f}s and kills only that helper")


# ---- completion -----------------------------------------------------------

def completion(d):
    (d / "c.txt").write_bytes("über übel üppig\n".encode())
    s = ours_session(d, "nano c.txt")
    s.keys(DOWN)
    s.keys("ü".encode(), COMPLETE)
    s.wait_for(b"Completion 1 of 3")
    s.keys(COMPLETE)
    s.wait_for(b"Completion 2 of 3")
    s.keys(SAVE)
    two = (d / "c.txt").read_bytes()
    s.keys(COMPLETE, COMPLETE)
    s.wait_for(b"No further matches")
    s.keys(SAVE)
    wrapped = (d / "c.txt").read_bytes()
    s.keys(COMPLETE, SAVE)
    again = (d / "c.txt").read_bytes()
    s.keys(UNDO, SAVE)
    undone = (d / "c.txt").read_bytes()
    s.key(EXIT, frame=False)
    base = "über übel üppig\n".encode()
    check(s.finish() == 0 and two == base + "übel".encode() and wrapped == base + "ü".encode()
          and again == base + "über".encode() and undone == base + "ü".encode(),
          "completion: a UTF-8 fragment cycles über, übel, üppig, back to the fragment, then restarts; ^Z steps back")


# ---- selection ------------------------------------------------------------

def selection(d):
    (d / "sel.txt").write_bytes("one two 中文 three\n".encode())
    s = ours_session(d, "nano sel.txt")
    s.keys(*[RIGHT] * 4, ESC + b"a", *[RIGHT] * 6)        # mark "two 中文"
    s.keys(C["a"], b"<<")                                 # edit before the anchor (cursor moves)
    s.keys(UNDO, ESC + b"e")                              # undo and redo the edit
    s.keys(C["e"], LEFT, LEFT, LEFT, LEFT, LEFT, LEFT)    # cursor back to the end of the region
    s.keys(ESC + b"^", C["e"], b" [", C["u"], b"]", SAVE)
    s.key(EXIT, frame=False)
    got = (d / "sel.txt").read_bytes()
    check(s.finish() == 0 and got == "<<one two 中文 three [two 中文]\n".encode(),
          "the mark follows its text through an edit before it, undo and redo; M-^ copies the same clusters")


# ---- syntax colours follow edits -----------------------------------------

def highlight(d):
    (d / "h.sh").write_bytes(b"echo hi # note\nls -l\n")
    s = ours_session(d, "nano h.sh")
    first = s.out
    s.keys(b"#")
    commented = s.out[len(first):]
    mark = len(s.out)
    s.keys(UNDO)
    undone = s.out[mark:]
    s.key(EXIT, frame=False)
    check(s.finish() == 0 and b"\x1b[36mecho" in first and b"\x1b[90m# note" in first
          and b"\x1b[90m#echo hi # note" in commented and b"\x1b[36mecho" in undone,
          "typing # recolours the line as a comment and ^Z restores the command colour")

    lines = [f'echo "item {i:07d}" | grep -q item  # c\n'.encode() for i in range(24000)]
    (d / "big.sh").write_bytes(b"".join(lines))
    s = ours_session(d, "nano big.sh")
    s.keys(b"\x1f", *[bytes([c]) for c in b"12000"], ENTER)
    s.wait_for(b"L 12000/")
    # The first parse runs in frame-budget slices while input is idle;
    # wait for the coloured window around line 12000.
    s.wait_for(b'\x1b[36mecho\x1b[0m \x1b[32m"item 0011999"', timeout=60, start=s.out.find(b"L 12000/"))
    mark = len(s.out)
    s.keys(b"#")
    first = s.out[mark:]
    # The keystroke's frame may come from the edited old tree; the settled
    # frame that follows must colour the line as a comment.
    s.wait_for(b'\x1b[90m#echo "item 0011999"', timeout=60, start=mark)
    frame = s.out[mark:]
    settled_line = b'\x1b[90m#echo "item 0011999"'
    # From the edited old tree: the typed "#" uncoloured, the command still coloured.
    stale_line = b'\x1b[K#\x1b[36mecho\x1b[0m \x1b[32m"item 0011999"'
    stale = stale_line in first
    print(f"# keystroke frame {'drawn from the edited old tree' if stale else 'already settled'}")
    s.keys(SAVE)
    s.key(EXIT, frame=False)
    got = (d / "big.sh").read_bytes().split(b"\n")
    check(s.finish() == 0 and (stale or settled_line in first)
          and b'\x1b[36mecho\x1b[0m' in frame and got[11999].startswith(b"#echo"),
          "in a 1 MiB script the edited line 12000 is recoloured once its reparse settles; neighbours keep theirs")


# ---- terminal restoration on normal exit ----------------------------------

def restore(d):
    stty = shutil.which("stty", path="/usr/bin:/bin")
    s = ours_session(d, f"{stty} -g > b.txt; nano r.txt; {stty} -g > a.txt; nano r.txt; {stty} -g > c.txt")
    s.keys(b"q")
    s.key(EXIT, frame=False)
    s.wait_for(b"Save modified buffer?")
    s.key(b"y", frame=False)
    s.wait_for(b"\x1b[?1049l")
    s.wait_for(FRAME, start=s.out.find(b"\x1b[?1049l"))
    s.key(EXIT, frame=False)
    st = s.finish()
    b, a, c = ((d / n).read_text() for n in ("b.txt", "a.txt", "c.txt"))
    check(st == 0 and b == a == c and b.strip() and (d / "r.txt").read_bytes() == b"q",
          "termios is identical before, between and after two calls; ^X Y saves a new file")
    check(s.out.count(b"\x1b[?1049h") == 2 and s.out.count(b"\x1b[?1049l") == 2,
          "each call enters and leaves the alternate screen once")


with tempfile.TemporaryDirectory(prefix="sol-nano-pty.") as tmp:
    root = Path(tmp)
    groups = (burst, movement, display, signals, justify, spell, completion, selection, highlight, restore)
    wanted = sys.argv[2:] or [g.__name__ for g in groups]
    unknown = set(wanted) - {g.__name__ for g in groups}
    if unknown:
        sys.exit(f"unknown group(s): {' '.join(sorted(unknown))}")
    for group in groups:
        if group.__name__ not in wanted:
            continue
        d = root / group.__name__
        d.mkdir()
        group(d)

print(f"1..{checks}")
for s in skips:
    print(f"# SKIPPED (not counted as passed): {s}")
sys.exit(3 if skips else 0)
