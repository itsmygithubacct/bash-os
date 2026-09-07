#!/usr/bin/env python3
"""Exercise terminal and editing primitives without changing a live terminal."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
checks = 0

def run(*args, data=None, rc=0, env=None):
    global checks
    child_env = {**os.environ, **(env or {})}
    if os.environ.get("TERMINAL_LOAD_ENV"):
        child_env["BASH_ENV"] = os.environ["TERMINAL_LOAD_ENV"]
        child_env["LD_PRELOAD"] = os.environ["TERMINAL_ASAN_LIB"]
        child_env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        child_env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    p = subprocess.run([binary, "-e", "-o", "pipefail", "-c", 'PATH=; "$@"', "_", *map(str, args)],
                       input=data, capture_output=True, timeout=15, env=child_env)
    assert p.returncode == rc, (args, p.returncode, p.stdout, p.stderr)
    checks += 1
    return p.stdout

with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    names = "pty expect termpixel termpixel_pong escdelay fifo kgetch wgetch wget_wch mouse script buf undo clip nano2 watch wall write"
    for name in names.split(): assert run("type", "-t", name) == b"builtin\n"
    run("termpixel", "selftest")
    run("termpixel_pong", "--selftest")
    run("termpixel_pong", "--dump-frame", "--seed", "1")
    run("nano2", "selftest")
    assert run("kgetch", "decode", "1b5b41") == b"key_up 257\n"
    assert run("wget_wch", "decode", "c3a9") == b"wch U+00E9 bytes=2\n"
    assert b"x=1 y=1" in run("mouse", "decode", "1b5b3c303b313b314d")
    run("eval", 'escdelay set 75; [[ $(escdelay get) == 75 ]]')
    assert run("eval", 'fifo clear; fifo push 10 20; fifo unget 5; '
               'fifo pull; fifo pull; fifo depth') == b"5\n10\n1\n"
    assert run("eval", 'wgetch open 0 fixture; wgetch unget 1 257; '
               'wgetch peek 1; wgetch read 1; wgetch close 1') == b"1\nkey_up 257\nkey_up 257\n"
    run("eval", 'pty spawn fd pid printf "hello\\n"; read -r -u "$fd" value; '
        'pty waitpid "$pid" code; pty close "$fd"; [[ $value == $\'hello\\r\' && $code == 0 ]]')
    run("eval", '''expect log_user off
expect spawn eval 'printf ready; read -r answer; printf "reply:%s\\n" "$answer"' -h fd -h pid
expect expect "$fd" ready -t 2
expect sendline "$fd" hello
expect expect "$fd" reply:hello -t 2
expect eof "$fd" -t 2
expect close "$fd" "$pid"
''')
    run("watch", "-e", "-x", "false", rc=1)
    run("watch", "-e", "false", rc=1)
    run("script", "record", "-c", "printf recorded", "-O", d / "record", "-T", d / "timing", "-A", d / "cast", data=b"")
    assert b"recorded" in (d / "record").read_bytes()
    cast = [json.loads(line) for line in (d / "cast").read_text().splitlines()]
    assert cast[0]["version"] == 2
    assert any("recorded" in event[2] for event in cast[1:] if event[1] == "o")
    run("script", "replay", d / "timing", d / "record", "-d", "1000", data=b"")
    (d / "original").write_bytes(b"a\x00b\nlast")
    env = {"TEST_DIR": str(d)}
    run("eval", 'buf new -h b; buf load "$b" "$TEST_DIR/original"; '
        'buf save "$b" "$TEST_DIR/copy"; buf free "$b"', env=env)
    assert (d / "copy").read_bytes() == (d / "original").read_bytes()
    run("eval", '''buf new -h b
undo new -h u -B "$b"
buf insert-line "$b" 0 alpha
undo record "$u" I 0 alpha
undo undo "$u"
[[ $(buf lines "$b") == 0 ]]
undo redo "$u"
[[ $(buf line "$b" 0) == alpha ]]
undo begin-group "$u"
buf insert-line "$b" 1 ""
undo record "$u" I 1 ""
buf insert-line "$b" 2 beta
undo record "$u" I 2 beta
undo end-group "$u"
undo undo "$u"
[[ $(buf lines "$b") == 1 ]]
undo redo "$u"
[[ $(buf lines "$b") == 3 ]]
clip new -h c
clip copy-line "$c" "$b" 0
clip paste "$c" "$b" 3
[[ $(buf line "$b" 3) == alpha ]]
clip free "$c"
undo free "$u"
buf free "$b"
''')
    # Empty private utmp: exercises parsing without sending a terminal message.
    (d / "utmp").write_bytes(b"")
    run("wall", "fixture", env={"BASHWALL_UTMP": str(d / "utmp")})
    run("write", "missing-fixture-user", data=b"fixture\n", rc=1,
        env={"BASHWALL_UTMP": str(d / "utmp")})

print(f"terminal-smoke: {checks} checks passed")
