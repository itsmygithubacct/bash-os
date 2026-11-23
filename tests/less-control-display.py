#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""G79: less on a terminal shows control characters as GNU less 668 does.

Without -r or -R, ESC is "ESC" and other control characters are ^X in
standout, bytes that are not characters are <XX>, a CR before the newline is
hidden and backspace overstrike is bold or underline. -R passes colour (SGR)
and OSC 8 sequences and ends each line with ESC[m (closing a hyperlink
after OSC 8); -r passes control
characters. Output that is not a terminal is copied unchanged.

Each case runs `less -F FILE` from the bash-os binary on a pseudo-terminal
(TERM=xterm, C.UTF-8) and compares the bytes with the expected rendering.
When GNU less 668 is installed, its output (less the screen set-up it adds:
a leading CR, the closing CR ESC[K, and tabs it expands) is compared too.

Usage: python3 tests/less-control-display.py [BASH]"""

import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
SO, SE = b"\033[7m", b"\033[27m"

CASES = [
    # (name, file bytes, options, expected terminal bytes)
    ("escape-default", b"\033[31mr\033[0m\n", "-F",
     SO + b"ESC" + SE + b"[31mr" + SO + b"ESC" + SE + b"[0m\r\n"),
    ("escape-R", b"\033[31mr\033[0m\n", "-FR",
     b"\033[31mr\033[0m\033[m\r\n"),
    ("escape-r", b"\033[31mr\033[0m\n", "-Fr",
     b"\033[31mr\033[0m\r\n"),
    ("carets", b"\000a\001b\037c\177d\n", "-F",
     SO + b"^@" + SE + b"a" + SO + b"^A" + SE + b"b" + SO + b"^_" + SE
     + b"c" + SO + b"^?" + SE + b"d\r\n"),
    ("carets-R", b"a\001\002b\n", "-FR",
     b"a" + SO + b"^A^B" + SE + b"b\033[m\r\n"),
    ("carets-r", b"a\001\002b\n", "-Fr", b"a\001\002b\r\n"),
    ("bytes-utf8", b"\200\303\251\302\205e\n", "-F",
     SO + b"<80>" + SE + b"\303\251" + SO + b"<U+0085>" + SE + b"e\r\n"),
    ("bytes-r", b"\200\303\251e\n", "-Fr",
     SO + b"<80>" + SE + b"\303\251e\r\n"),
    ("carriage-return", b"a\rb\r\n", "-F",
     b"a" + SO + b"^M" + SE + b"b\r\n"),
    ("overstrike", b"a\bab _\bc d\be|c\bcd\bde\b_\n", "-F",
     b"\033[1ma\033[0mb \033[4mc\033[24m e|\033[1mcd\033[0m\033[4me\033[24m\r\n"),
    ("overstrike-r", b"c\bcd\bd\n", "-Fr", b"\033[1mcd\033[0m\r\n"),
    ("R-drops-other-csi", b"\033[1;32mg\033[Kk\n", "-FR",
     b"\033[1;32mgk\033[m\r\n"),
    ("R-osc8-hyperlink", b"\033]8;;http://x\033\\L\033]8;;\033\\|\n", "-FR",
     b"\033]8;;http://x\033\\L\033]8;;\033\\|\033[m\033]8;;\033\\\r\n"),
    ("plain-R", b"hello\n", "-FR", b"hello\033[m\r\n"),
    ("LESS-R", b"\033[32mg\033[m\n", "-F",
     b"\033[32mg\033[m\033[m\r\n"),
]


def on_terminal(argv, cwd, env):
    """Run ARGV with a pseudo-terminal as stdin/stdout/stderr; its output."""
    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=slave,
                                   stdout=slave, stderr=slave, start_new_session=True)
    finally:
        os.close(slave)
    output = bytearray()
    try:
        while True:
            ready = select.select([master], [], [], 10)[0]
            if not ready:
                process.kill()
                raise AssertionError(f"timed out: {argv}: {bytes(output)!r}")
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            output.extend(data)
    finally:
        os.close(master)
        process.wait(timeout=10)
    return bytes(output)


def gnu_screen(raw):
    """GNU less's bytes without its screen set-up and end-of-screen line."""
    if raw.startswith(b"\r"):
        raw = raw[1:]
    if raw.endswith(b"\r\033[K"):
        raw = raw[:-4]
    return raw


class LessDisplay(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="bash-os-less-display-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.env = {"PATH": "", "TERM": "xterm", "LC_ALL": "C.UTF-8", "HOME": str(self.root)}

    def test_terminal_display(self):
        gnu = shutil.which("less")
        gnu_ok = False
        if gnu:
            version = subprocess.run([gnu, "--version"], capture_output=True, text=True)
            gnu_ok = version.stdout.startswith("less 668")
        for name, data, options, expected in CASES:
            with self.subTest(name=name):
                (self.root / "f").write_bytes(data)
                env = dict(self.env)
                if name == "LESS-R":
                    env["LESS"] = "R"
                got = on_terminal([BINARY, "--noprofile", "--norc", "-c",
                                   f"less {options} f"], self.root, env)
                self.assertEqual(got, expected)
                if gnu_ok and b"\t" not in data:
                    genv = {**env, "PATH": "/usr/bin:/bin", "LESSHISTFILE": "-"}
                    ref = gnu_screen(on_terminal([gnu, *options.split(), "f"], self.root, genv))
                    self.assertEqual(got, ref, "GNU less 668 differs")

    def test_redirected_output_is_unchanged(self):
        data = b"\033[31mr\033[0m\001\b\r\n\200\n"
        (self.root / "f").write_bytes(data)
        for options in ("", "-R", "-r"):
            with self.subTest(options=options):
                result = subprocess.run([BINARY, "--noprofile", "--norc", "-c",
                                         f"less {options} f"], cwd=self.root,
                                        env=self.env, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, data)


if __name__ == "__main__":
    unittest.main()
