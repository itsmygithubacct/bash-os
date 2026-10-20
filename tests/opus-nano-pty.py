#!/usr/bin/env python3
"""Drive the nano builtin through private PTYs, as a user would.

Covers justify (width, quoting, undo), spell (replacement, cancel, helper
failure, helper selection), word completion (candidates and cycling), UTF-8
grapheme movement with a visible selection, the save prompts, atomic save,
undo/redo, terminal restoration, repeated calls in one shell, invalid
invocations and descriptor cleanup.  Every session runs with an empty PATH,
so the builtin is what runs.  When GNU nano is installed, a seeded set of
paragraphs is justified by both editors with the same keys and options and
the saved files must be identical; without it that comparison is reported
as skipped, not passed.

Usage: tests/opus-nano-pty.py BASH-OS-BINARY
"""
import os
import pty
import random
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import fcntl
import time
from pathlib import Path

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
checks = 0
skips = []

CTRL = {c: bytes([ord(c) & 0x1f]) for c in "abcdefghijklnopqrstuvwxyz"}
ESC = b"\x1b"
RIGHT, LEFT, DOWN = b"\x1b[C", b"\x1b[D", b"\x1b[B"
DEL, ENTER = b"\x7f", b"\r"
JUSTIFY, SPELL, COMPLETE = b"\x0a", b"\x14", b"\x1d"
SAVE, EXIT, UNDO, WRITEOUT = CTRL["s"], CTRL["x"], CTRL["z"], CTRL["o"]
RENDER_END = b"\x1b[?25h"


def check(cond, what):
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1
    print(f"ok {checks} - {what}", flush=True)


class Session:
    """One shell on a private PTY running a script that calls nano."""

    def __init__(self, script, cwd, argv0=None, env=None, rows=24, cols=80):
        self.out = b""
        child_env = {"TERM": "xterm", "LANG": "C.UTF-8", "HOME": str(cwd), "PATH": ""}
        if argv0 is None:
            # tests/opus-nano-sanitize.sh loads instrumented builtins this way.
            for name in ("BASH_ENV", "LD_PRELOAD", "ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"):
                if os.environ.get(name):
                    child_env[name] = os.environ[name]
        child_env.update(env or {})
        argv = argv0 or [binary, "--norc", "--noprofile", "-c", script]
        pid, fd = pty.fork()
        if pid == 0:
            try:
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                os.chdir(cwd)
                os.execve(argv[0] if os.path.isabs(argv[0]) else shutil.which(argv[0]), argv, child_env)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.status = None

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return True
            r, _, _ = select.select([self.fd], [], [], min(left, 0.05))
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                self.out += data

    def wait_for(self, needle, timeout=5.0, start=0):
        end = time.monotonic() + timeout
        while needle not in self.out[start:]:
            if time.monotonic() > end:
                raise AssertionError(f"timed out waiting for {needle!r}; tail {self.out[-400:]!r}")
            if not self.pump(0.05):
                if needle not in self.out[start:]:
                    raise AssertionError(f"session ended before {needle!r}; tail {self.out[-400:]!r}")

    def renders(self):
        return self.out.count(RENDER_END)

    def key(self, data, render=True):
        """Send one key and wait for the frame it causes."""
        before = self.renders()
        os.write(self.fd, data)
        if render:
            end = time.monotonic() + 5
            while self.renders() <= before:
                if time.monotonic() > end:
                    raise AssertionError(f"no frame after {data!r}; tail {self.out[-300:]!r}")
                if not self.pump(0.02):
                    break

    def keys(self, *seq):
        for k in seq:
            self.key(k)

    def text(self, s):
        for ch in s:
            self.key(ch.encode())

    def finish(self, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.pump(0.05)
            pid, st = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.pump(0.1)
                os.close(self.fd)
                self.status = os.waitstatus_to_exitcode(st)
                return self.status
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        os.close(self.fd)
        raise AssertionError(f"session did not exit; tail {self.out[-400:]!r}")


def edit(d, name, content, script, actions, env=None, rows=24, cols=80):
    """Write NAME, run SCRIPT, perform ACTIONS(session), return (status, session)."""
    path = d / name
    if content is not None:
        path.write_bytes(content)
    s = Session(script, d, env=env, rows=rows, cols=cols)
    s.wait_for(RENDER_END)
    actions(s)
    return s.finish(), s


def quote(p):
    return "'" + str(p).replace("'", "'\\''") + "'"


# Expected outputs produced by GNU nano 8.4 with the same options (LANG=C.UTF-8).
GNU_CASES = [
    (b"aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk\n", ["--fill=20"],
     b"aaaa bbbb cccc dddd \neeee ffff gggg hhhh \niiii jjjj kkkk\n"),
    (b"aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk\n", ["--fill=20", "-M"],
     b"aaaa bbbb cccc dddd\neeee ffff gggg hhhh\niiii jjjj kkkk\n"),
    (b"One.  Two!   Three?) four   five.\tsix seven eight nine ten\n", ["-r", "20", "--trimblanks"],
     b"One.  Two!  Three?)\nfour five. six seven\neight nine ten\n"),
    (b"> quoted text that is long enough to wrap\n> more quoted\n", ["-r20"],
     b"> quoted text that \n> is long enough to \n> wrap more quoted\n"),
    ("héllo wörld 中文中文 café naïve résumé über\n".encode(),
     ["--fill=12"],
     "héllo wörld \n中文中文 \ncafé naïve \nrésumé über\n".encode()),
]


def justify_cases(d):
    for i, (src, opts, want) in enumerate(GNU_CASES):
        st, _ = edit(d, "j.txt", src, "nano " + " ".join(opts) + " j.txt",
                     lambda s: s.keys(JUSTIFY, SAVE) or s.key(EXIT, render=False))
        check(st == 0 and (d / "j.txt").read_bytes() == want,
              f"PTY justify matches GNU nano case {i + 1} ({' '.join(opts)})")
    # Default fill is COLS - 8: a 28-column terminal wraps at 20.
    st, _ = edit(d, "j.txt", GNU_CASES[0][0], "nano j.txt",
                 lambda s: s.keys(JUSTIFY, SAVE) or s.key(EXIT, render=False), cols=28)
    check(st == 0 and (d / "j.txt").read_bytes() == GNU_CASES[0][2],
          "default fill follows the terminal width (COLS - 8)")


def justify_undo(d):
    src = GNU_CASES[0][0]

    def act(s):
        s.keys(JUSTIFY)
        s.wait_for(b"Justified paragraph")
        s.keys(UNDO, SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "u.txt", src, "nano --fill=20 u.txt", act)
    check(st == 0 and (d / "u.txt").read_bytes() == src, "one ^Z undoes a justification")

    def act2(s):
        s.keys(JUSTIFY, ESC + b"u", ESC + b"e", SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "u.txt", src, "nano --fill=20 u.txt", act2)
    check(st == 0 and (d / "u.txt").read_bytes() == GNU_CASES[0][2],
          "M-U then M-E redoes the justification")


def gnu_oracle(d):
    gnu = shutil.which("nano", path="/usr/bin:/bin:/usr/local/bin")
    if not gnu:
        skips.append("GNU nano not installed: random justify oracle comparison skipped")
        print("# SKIP " + skips[-1])
        return
    version = subprocess.run([gnu, "--version"], capture_output=True, text=True).stdout.split("\n")[0]
    rng = random.Random(20261019)
    words = ["a", "be", "sea", "deed", "eerie", "fluffy", "gargantuan", "hi.", "ok!", "why?)",
             "naïve", "中文", "café", "x" * 14, "end."]
    compared = 0
    changed = 0
    for case in range(24):
        lines = []
        for _ in range(rng.randint(1, 3)):
            indent = rng.choice(["", "", "  ", "\t", "> "])
            n = rng.randint(1, 12)
            sep = lambda: rng.choice([" ", " ", "  ", "\t"])
            # GNU nano measures a paragraph's first line from the byte offset
            # of the *second* line's lead; when that offset splits a UTF-8
            # character it wraps early (see docs/opus-nano.md).  Starting each
            # line with an ASCII word keeps the comparison to cases where that
            # offset is harmless; the deviation itself is pinned in
            # nano selftest-justify.
            first = rng.choice([w for w in words if w.isascii() and len(w) >= 2])
            body = (first + sep() + "".join(rng.choice(words) + sep() for _ in range(n - 1))).rstrip()
            lines.append(indent + body)
            if rng.random() < 0.3:
                lines.append("")
        src = ("\n".join(lines) + "\n").encode()
        fill = rng.choice([8, 12, 20, 33])
        opts = [f"--fill={fill}"] + (["-M"] if rng.random() < 0.5 else [])
        key = ESC + b"j"        # full justify: every paragraph in the file
        ours_path, gnu_path = d / "ours.txt", d / "gnu.txt"
        ours_path.write_bytes(src)
        gnu_path.write_bytes(src)
        s = Session("nano " + " ".join(opts) + " ours.txt", d)
        s.wait_for(RENDER_END)
        s.keys(key, SAVE)
        s.key(EXIT, render=False)
        check(s.finish() == 0, f"oracle case {case + 1}: bash-os nano session exits 0")
        g = Session(None, d, argv0=[gnu, "--ignorercfiles", *opts, "gnu.txt"],
                    env={"PATH": "/usr/bin:/bin"})
        g.pump(0.4)
        for k in (key, SAVE, EXIT):
            os.write(g.fd, k)
            g.pump(0.15)
        check(g.finish() == 0, f"oracle case {case + 1}: GNU nano session exits 0")
        ours, theirs = ours_path.read_bytes(), gnu_path.read_bytes()
        check(ours == theirs, f"oracle case {case + 1}: M-J with {' '.join(opts)} equals {version}"
              + ("" if ours == theirs else f" (ours {ours!r} gnu {theirs!r} src {src!r})"))
        changed += theirs != src
        compared += 1
    check(changed >= 12, f"GNU oracle changed {changed}/{compared} input files (at least 12 required)")


def spell(d):
    helper = d / "speller.sh"
    helper.write_text(
        "while IFS= read -r line || [[ -n $line ]]; do\n"
        "  for w in $line; do\n"
        "    case $w in teh|wrold) printf '%s\\n' \"$w\";; esac\n"
        "  done\n"
        "done\n")
    (d / "fail.sh").write_text("exit 3\n")
    speller = f"{binary} {helper}"
    src = b"teh cat saw teh wrold\n"

    def act(s):
        s.keys(SPELL)
        s.wait_for(b"Edit a replacement: teh")
        s.keys(DEL, DEL, DEL)
        s.text("the")
        s.keys(ENTER)
        s.wait_for(b"Edit a replacement: wrold")
        s.keys(ESC)
        s.wait_for(b"Spell check cancelled (2 replaced)")
        s.keys(SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "s.txt", src, f"nano --speller={quote(speller)} s.txt", act)
    check(st == 0 and (d / "s.txt").read_bytes() == b"the cat saw the wrold\n",
          "spell: replacement applies to every occurrence, Esc cancels the rest")

    def act_env(s):
        s.keys(SPELL)
        s.wait_for(b"Edit a replacement: teh")
        s.keys(ENTER)
        s.wait_for(b"Edit a replacement: wrold")
        s.keys(DEL, DEL, DEL, DEL, DEL)
        s.text("world")
        s.keys(ENTER)
        s.wait_for(b"Finished checking spelling (1 replaced)")
        s.keys(SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "s.txt", src, f"export NANO_SPELLER={quote(speller)}; nano s.txt", act_env)
    check(st == 0 and (d / "s.txt").read_bytes() == b"teh cat saw teh world\n",
          "spell: exported NANO_SPELLER selects the helper; Enter skips a word")

    def act_fail(s):
        s.keys(SPELL)
        s.wait_for(b"Spell helper failed (exit 3)")
        s.key(EXIT, render=False)
    st, _ = edit(d, "s.txt", src,
                 f"export NANO_SPELLER=/nonexistent; nano --speller={quote(f'{binary} {d}/fail.sh')} s.txt",
                 act_fail)
    check(st == 0 and (d / "s.txt").read_bytes() == src,
          "spell: --speller overrides the environment; helper failure leaves the buffer clean")

    def act_missing(s):
        s.keys(SPELL)
        s.wait_for(b"Spell helper not found: spell")
        s.key(EXIT, render=False)
    st, _ = edit(d, "s.txt", src, "nano s.txt", act_missing)
    check(st == 0 and (d / "s.txt").read_bytes() == src,
          "spell: with an empty PATH the default helper is reported missing")

    # Descriptors of the shell are unchanged by a helper run.
    def act_fd(s):
        s.keys(SPELL)
        s.wait_for(b"Edit a replacement: teh")
        s.keys(ESC)
        s.key(EXIT, render=False)
    st, sess = edit(d, "s.txt", src,
                    'a=(/proc/$$/fd/*); nano --speller=' + quote(speller) + ' s.txt; '
                    'b=(/proc/$$/fd/*); echo "fds ${#a[@]} ${#b[@]}"', act_fd)
    tail = sess.out.rsplit(b"fds ", 1)[-1].split()[:2]
    check(st == 0 and len(tail) == 2 and tail[0] == tail[1],
          f"spell: shell descriptor count unchanged after helper run ({tail})")


def helper_isolation(d):
    helper = d / "helper.py"
    helper.write_text("""import os
try:
    fd = os.open('/dev/tty', os.O_RDWR)
except OSError:
    pass
else:
    os.close(fd)
    raise SystemExit(3)
# Probe inherited extra /dev/null descriptors, including the former leak.
for fd in range(3, 128):
    try:
        target = os.readlink('/proc/self/fd/' + str(fd))
    except OSError:
        continue
    if target == '/dev/null':
        raise SystemExit(4)
""")
    def act(s):
        s.keys(SPELL)
        s.wait_for(b"Finished checking spelling (0 replaced)")
        s.key(EXIT, render=False)
    cmd = str(Path(sys.executable).resolve()) + " " + str(helper)
    st, _ = edit(d, "isolation.txt", b"teh\n", f"nano --speller={quote(cmd)} isolation.txt", act)
    check(st == 0 and (d / "isolation.txt").read_bytes() == b"teh\n",
          "spell helper has no controlling terminal or leaked /dev/null descriptor")


def highlighted_selection(d):
    def act(s):
        s.keys(RIGHT, ESC + b"a", RIGHT, RIGHT, RIGHT)
        mark = len(s.out)
        s.keys(CTRL["l"])
        s.wait_for(b'\x1b[7m\x1b[1;36m"k"', start=mark)
        s.keys(CTRL["e"])
        s.text(" ")
        s.keys(SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "highlight.json", b'{"k":1}\n', "nano highlight.json", act)
    check(st == 0 and (d / "highlight.json").read_bytes() == b'{"k":1} \n',
          "combined ts JSON key colour survives selection and an edit")


def completion(d):
    def act(s):
        s.keys(DOWN, DOWN)
        s.text("ap")
        s.keys(COMPLETE)
        s.wait_for(b"Completion 1 of 2")
        s.keys(COMPLETE)
        s.wait_for(b"Completion 2 of 2")
        s.keys(SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "c.txt", b"apple\napricot\n", "nano c.txt", act)
    check(st == 0 and (d / "c.txt").read_bytes() == b"apple\napricot\napricot",
          "completion: ^] inserts and cycles candidates")

    def act_wrap(s):
        s.keys(DOWN, DOWN)
        s.text("ap")
        s.keys(COMPLETE, COMPLETE, COMPLETE)
        s.wait_for(b"No further matches")
        s.text("e")
        s.keys(SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "c.txt", b"apple\napricot\n", "nano c.txt", act_wrap)
    check(st == 0 and (d / "c.txt").read_bytes() == b"apple\napricot\nape",
          "completion: after the last candidate the fragment returns")


def burst(d):
    typed = ("burst typing " * 25).encode()          # 325 bytes in one write

    def act(s):
        os.write(s.fd, typed)
        s.wait_for(b"L 1/2 C 326")
        s.keys(SAVE)
        s.key(EXIT, render=False)
    st, sess = edit(d, "b.txt", b"tail\n", "nano b.txt", act)
    frames = sess.renders()
    check(st == 0 and (d / "b.txt").read_bytes() == typed + b"tail\n",
          f"a 325-byte burst is applied in order ({frames} frames drawn)")


def utf8_selection(d):
    line = "a\U0001F44D\U0001F3FDé中\n".encode()

    def act(s):
        s.keys(ESC + b"a", RIGHT, RIGHT, RIGHT)
        mark = len(s.out)
        s.keys(CTRL["l"])           # full redraw to capture the selection
        s.wait_for(b"\x1b[7ma\xf0\x9f\x91\x8d\xf0\x9f\x8f\xbde\xcc\x81\x1b[0m\xe4\xb8\xad", start=mark)
        s.keys(ESC + b"^", CTRL["e"], CTRL["u"], SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "g.txt", line, "nano g.txt", act)
    want = "a\U0001F44D\U0001F3FDé中a\U0001F44D\U0001F3FDé\n".encode()
    check(st == 0 and (d / "g.txt").read_bytes() == want,
          "UTF-8: arrows step by grapheme; the selection is drawn and copies whole clusters")

    def act_bs(s):
        s.keys(RIGHT, RIGHT, DEL, SAVE)
        s.key(EXIT, render=False)
    st, _ = edit(d, "g.txt", line, "nano g.txt", act_bs)
    check(st == 0 and (d / "g.txt").read_bytes() == "aé中\n".encode(),
          "UTF-8: backspace removes an emoji with its modifier as one cluster")


def save_paths(d):
    target = d / "keep.txt"
    target.write_bytes(b"one\n")
    target.chmod(0o640)

    def act(s):
        s.text("x")
        s.keys(SAVE)
        s.wait_for(b"Wrote 2 lines")
        s.key(EXIT, render=False)
    st, _ = edit(d, "keep.txt", None, "nano keep.txt", act)
    leftovers = [p.name for p in d.iterdir() if ".tmp" in p.name]
    check(st == 0 and target.read_bytes() == b"xone\n" and stat.S_IMODE(target.stat().st_mode) == 0o640
          and not leftovers, "atomic save keeps the mode and leaves no temporary file")

    def act_writeout(s):
        s.keys(WRITEOUT)
        s.wait_for(b"File Name to Write: keep.txt")
        s.text("2")
        s.keys(ENTER)
        s.wait_for(b"Wrote")
        s.key(EXIT, render=False)
    st, _ = edit(d, "keep.txt", None, "nano keep.txt", act_writeout)
    check(st == 0 and (d / "keep.txt2").read_bytes() == b"xone\n", "^O prompt prefilled with the path writes the edited name")

    def act_guard(s):
        s.text("y")
        s.keys(EXIT)
        s.wait_for(b"Save modified buffer?")
        s.keys(ESC)
        s.wait_for(b"Exit cancelled")
        s.keys(EXIT)
        s.key(b"y", render=False)
    st, _ = edit(d, "keep.txt", None, "nano keep.txt", act_guard)
    check(st == 0 and target.read_bytes() == b"yxone\n", "^X guard: Esc stays, Y saves and exits")

    def act_discard(s):
        s.text("z")
        s.keys(EXIT)
        s.wait_for(b"Save modified buffer?")
        s.key(b"n", render=False)
    st, _ = edit(d, "keep.txt", None, "nano keep.txt", act_discard)
    check(st == 0 and target.read_bytes() == b"yxone\n", "^X guard: N discards")


def terminal_restore(d):
    stty = shutil.which("stty", path="/usr/bin:/bin")
    if not stty:
        skips.append("stty unavailable: termios comparison skipped")
        print("# SKIP " + skips[-1])
        return
    script = (f"{stty} -g > before.txt; nano t.txt; {stty} -g > after.txt")
    st, s = edit(d, "t.txt", b"text\n", script, lambda s: s.key(EXIT, render=False))
    before, after = (d / "before.txt").read_text(), (d / "after.txt").read_text()
    enter = s.out.find(b"\x1b[?1049h")
    leave = s.out.find(b"\x1b[?1049l")
    check(st == 0 and before == after and before.strip(), "termios restored exactly after exit")
    check(0 <= enter < leave, "alternate screen entered and left")


def repeated_calls(d):
    src = GNU_CASES[0][0]
    (d / "r1.txt").write_bytes(src)
    (d / "r2.txt").write_bytes(src)
    s = Session("nano -M --fill=20 r1.txt; nano --fill=20 r2.txt; nano r2.txt", d)
    s.wait_for(RENDER_END)
    s.keys(JUSTIFY, SAVE)
    s.key(EXIT, render=False)
    mark = len(s.out)
    s.wait_for(b"r2.txt", start=mark)
    s.wait_for(RENDER_END, start=mark)
    s.keys(JUSTIFY, SAVE)
    s.key(EXIT, render=False)
    mark = len(s.out)
    s.wait_for(b"r2.txt", start=mark)
    s.wait_for(RENDER_END, start=mark)
    s.keys(SPELL)
    s.wait_for(b"Spell helper not found: spell", start=mark)
    s.key(EXIT, render=False)
    st = s.finish()
    check(st == 0 and (d / "r1.txt").read_bytes() == GNU_CASES[1][2]
          and (d / "r2.txt").read_bytes() == GNU_CASES[0][2],
          "repeated calls in one shell: -M does not leak into the next call")


def invalid(d):
    env = {"PATH": "", "LANG": "C.UTF-8"}
    for name in ("BASH_ENV", "LD_PRELOAD", "ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    for args, rc, msg in ((["--bogus"], 2, b"invalid option"), (["-r", "x", "f"], 2, b"invalid fill width"),
                          (["--fill=12a"], 2, b"invalid fill width"), (["a", "b"], 2, b"only one file"),
                          (["-r"], 2, b"usage"), (["f"], 1, b"needs a tty")):
        p = subprocess.run([binary, "-c", 'nano "$@"', "_", *args], capture_output=True,
                           stdin=subprocess.DEVNULL, env=env, cwd=d, timeout=10)
        check(p.returncode == rc and msg in p.stderr.lower(),
              f"nano {' '.join(args)} exits {rc} with '{msg.decode()}'")


with tempfile.TemporaryDirectory(prefix="opus-nano-pty.") as tmp:
    d = Path(tmp)
    for group in (justify_cases, justify_undo, spell, helper_isolation, completion, burst, utf8_selection, save_paths,
                  terminal_restore, repeated_calls, invalid, gnu_oracle):
        group(d)
    if os.environ.get("NANO_REQUIRE_RESOLVED_TS") == "1":
        highlighted_selection(d)

print(f"1..{checks}")
for s in skips:
    print(f"# SKIPPED (not counted as passed): {s}")
