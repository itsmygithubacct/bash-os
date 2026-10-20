#!/usr/bin/env python3
"""FIFO contract tests; all operations execute the production builtin, PATH empty.

Optional FIFO_TEST_LOADABLE / FIFO_TEST_ASAN_LIB load an instrumented module.
No compilation or timing is performed by this test.
"""
import os
from pathlib import Path
import random
import re
import shlex
import subprocess
import sys
import tempfile


binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash-sol-fifo").resolve())
env = dict(os.environ, PATH="", LC_ALL="C")
for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
    env.pop(key, None)
prelude = ""
if env.get("FIFO_TEST_LOADABLE"):
    prelude = "enable -f " + shlex.quote(env["FIFO_TEST_LOADABLE"]) + " fifo || exit 99\n"
if env.get("FIFO_TEST_ASAN_LIB"):
    env.update(LD_PRELOAD=env["FIFO_TEST_ASAN_LIB"],
               ASAN_OPTIONS="detect_leaks=0:abort_on_error=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
env.update(FIFO_CHILD_BINARY=binary, FIFO_CHILD_STARTUP=prelude)


def run(script, expected, label, errors=False):
    p = subprocess.run([binary, "--noprofile", "--norc", "-s"],
                       input=(prelude + script).encode(), env=env,
                       capture_output=True, timeout=90)
    assert p.returncode == 0, (label, p.returncode, p.stdout[-1000:], p.stderr[-3000:])
    actual = p.stdout.decode()
    if actual != expected:
        a, b = actual.splitlines(), expected.splitlines()
        at = next((i for i, pair in enumerate(zip(a, b)) if pair[0] != pair[1]), min(len(a), len(b)))
        raise AssertionError((label, "line", at + 1, "actual", a[max(0, at-3):at+4],
                              "expected", b[max(0, at-3):at+4], p.stderr[-1500:]))
    assert errors or not p.stderr, (label, p.stderr)
    assert b"Sanitizer" not in p.stderr and b"runtime error:" not in p.stderr, p.stderr
    print(f"PASS {label}")


class Model:
    """List and integer cursor oracle, independent of ring indices."""
    def __init__(self):
        self.queue = []
        self.cursor = 0
        self.script = ["type -t fifo\n"]
        self.expected = ["builtin\n"]
        self.calls = 0

    def call(self, *args):
        self.calls += 1
        status, output = 0, ""
        verb = args[0] if args else ""
        words = args[1:]
        if verb in ("push", "unget"):
            if (not words or len(self.queue) + len(words) > 64 or
                any(not re.fullmatch(r"[+-]?[0-9]+", str(w)) or
                    not -2147483648 <= int(w) <= 2147483647 for w in words)):
                status = 2
            else:
                values = list(map(int, words))
                if verb == "push":
                    self.queue.extend(values)
                else:
                    self.queue[0:0] = values
                self.cursor = 0
        elif verb in ("pull", "peek", "depth", "clear"):
            if words:
                status = 2
            elif verb == "depth":
                output = f"{len(self.queue)}\n"
            elif verb == "clear":
                self.queue.clear()
                self.cursor = 0
            elif verb == "pull":
                if self.queue:
                    output = f"{self.queue.pop(0)}\n"
                    self.cursor = 0
                else:
                    status = 1
            elif self.cursor < len(self.queue):
                output = f"{self.queue[self.cursor]}\n"
                self.cursor += 1
            else:
                status = 1
        else:
            status = 2
        self.script.append(shlex.join(["fifo", *map(str, args)]) +
                           f"; printf '@{self.calls}:%s\\n' \"$?\"\n")
        self.expected.append(output + f"@{self.calls}:{status}\n")

    def check(self, label):
        self.script.append("exit 0\n")
        run("".join(self.script), "".join(self.expected), f"{label} ({self.calls} calls)", errors=True)


m = Model()
# Retain the original terminal-smoke sequence and its explicit values.
for args in (("clear",), ("push", 10, 20), ("unget", 5), ("pull",), ("pull",), ("depth",)):
    m.call(*args)
m.call("clear")
for verb in ("pull", "peek", "peek", "depth"):
    m.call(verb)
m.call("push", -2147483648, 2147483647, "+0001", "-0", "010")
for _ in range(7):
    m.call("peek")
m.call("depth")  # depth does not rewind an exhausted cursor
m.call("peek")
m.call("push", 90)  # append rewinds even after peek exhaustion
m.call("peek")
m.call("pull")
m.call("peek")  # pull rewinds to the new head
m.call("unget", 4, 5, 6)
for _ in range(3):
    m.call("peek")
for bad in ("", "+", "-", "1x", "0x10", "1.0", " 1", "1 ", "\t2", "2\n",
            "2147483648", "-2147483649", "9" * 120, "1_0"):
    for verb in ("push", "unget"):
        m.call(verb, 123, bad, 456)
        m.call("peek")  # invalid operation must preserve the cursor too
        m.call("depth")
for verb in ("push", "unget", "pull", "peek", "depth", "clear", "unknown", "--help", "-h"):
    if verb in ("push", "unget"):
        m.call(verb)
    else:
        m.call(verb, "unexpected")
m.call()
for _ in range(len(m.queue) + 1):
    m.call("pull")
m.call("push", *range(65))  # oversize batch also fails on an empty queue
m.call("unget", *range(65))
m.call("push", *range(63))
m.call("peek")
m.call("push", 100, 101)  # one slot left: neither value may be inserted
m.call("peek")
m.call("unget", 100, 101)
m.call("peek")
m.call("push", 63)  # exactly fills the last slot and resets peek
m.call("peek")
m.call("clear")

# Every possible physical head offset, full/empty distinction and head/tail wrap.
for offset in range(64):
    m.call("clear")
    m.call("push", *range(64))
    m.call("push", 64)
    m.call("unget", -1)
    for _ in range(offset):
        m.call("pull")
    if offset:
        m.call("push", *range(64, 64 + offset))
    for _ in range(65):
        m.call("peek")
    m.call("push", *range(65))
    m.call("unget", *range(65))
    for _ in range(64):
        m.call("pull")
    m.call("pull")
    m.call("unget", *range(-64, 0))
    for _ in range(64):
        m.call("pull")
    m.call("depth")
m.check("ordering, bounds, atomic rejection, all ring offsets")

m = Model()
rng = random.Random(20261019)
for _ in range(4000):
    verb = rng.choices(["push", "unget", "pull", "peek", "depth", "clear"], [22, 18, 25, 24, 9, 2])[0]
    args = [rng.randint(-2147483648, 2147483647) for _ in range(rng.randint(1, 12))] if verb in ("push", "unget") else []
    if args and rng.randrange(11) == 0:
        args[-1] = "invalid"
    m.call(verb, *args)
for _ in range(len(m.queue) + 1):
    m.call("pull")
m.check("seeded mixed-operation list oracle")

run("""set -e
fifo depth
fifo push 10 20 30
"$FIFO_CHILD_BINARY" --noprofile --norc -c "${FIFO_CHILD_STARTUP}fifo depth"
fifo depth
fifo peek
fifo --help > /dev/null
fifo -h > /dev/null
( fifo peek; fifo pull; fifo unget 99; fifo pull; fifo clear; fifo depth )
fifo peek
x=$(fifo pull); [[ $x == 10 ]]
fifo peek
fifo pull | { read -r x; [[ $x == 10 ]]; }
fifo depth
f() { fifo pull; }
f; f; fifo pull
fifo depth
""", "0\n0\n3\n10\n20\n10\n99\n0\n20\n30\n3\n10\n20\n30\n0\n", "fresh exec, functions, subshell, command substitution and pipeline isolation")
run("fifo depth\nfifo pull; printf 'status:%s\\n' \"$?\"\n", "0\nstatus:1\n", "independent shell starts empty")

# Same process, failing output then successful output: no lost event/cursor.
with tempfile.TemporaryDirectory(prefix="sol-fifo-") as tmp:
    target = shlex.quote(str(Path(tmp) / "values"))
    run(f"""fifo push 41 42
fifo peek
fifo pull > /dev/full; printf 'pull:%s\\n' "$?"
fifo depth
fifo pull >&-; printf 'closed:%s\\n' "$?"
fifo peek > /dev/full; printf 'peek:%s\\n' "$?"
fifo depth > /dev/full; printf 'depth:%s\\n' "$?"
fifo --help > /dev/full; printf 'help:%s\\n' "$?"
fifo -h >&-; printf 'help-closed:%s\\n' "$?"
fifo peek
fifo peek; printf 'exhausted:%s\\n' "$?"
fifo pull > {target}
read -r v < {target}; printf 'file:%s\\n' "$v"
fifo peek
fifo pull
fifo depth
""", "41\npull:1\n2\nclosed:1\npeek:1\ndepth:1\nhelp:1\nhelp-closed:1\n42\nexhausted:1\nfile:41\n42\n42\n0\n",
        "output failures preserve queue and peek, stdout recovers", errors=True)
for flag in ("--help", "-h"):
    p = subprocess.run([binary, "--noprofile", "--norc", "-s"],
                       input=(prelude + f"fifo {flag}\n").encode(), env=env,
                       capture_output=True, timeout=15)
    assert p.returncode == 0 and b"64-entry" in p.stdout and not p.stderr, p
print("PASS help flags")
print("sol-fifo-check: all checks passed")
