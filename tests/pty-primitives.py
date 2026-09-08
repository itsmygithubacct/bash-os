#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression checks for PTY statuses and native signal/readiness ownership.

Usage: tests/pty-primitives.py [BASH_BINARY] [--load-dir SHARED_LOADABLE_DIR]
All subprocesses and PTYs belong to these fixtures; no live terminal is used.
"""

import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", nargs="?", default="out/bash")
parser.add_argument("--load-dir", type=Path)
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
env = {k: v for k, v in os.environ.items() if k not in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")}
env["FIXTURE_PYTHON"] = sys.executable
if args.load_dir:
    env["PRIMITIVES_LOAD_DIR"] = str(args.load_dir.resolve())
else:
    env.pop("PRIMITIVES_LOAD_DIR", None)

prelude = r'''
if [[ -n ${PRIMITIVES_LOAD_DIR-} ]]; then
    enable -f "$PRIMITIVES_LOAD_DIR/pty.so" pty || exit 98
    enable -f "$PRIMITIVES_LOAD_DIR/bashpoll.so" bashpoll || exit 98
fi
FIXTURE_SHELL_PID=$BASHPID
mask() {
    local field rest
    while read -r field rest; do
        if [[ $field == SigBlk: ]]; then printf '%s\n' "$rest"; return; fi
    done < "/proc/$FIXTURE_SHELL_PID/status"
}
'''
checks = []


def run(name, script, *, extra=None, preexec_fn=None):
    result = subprocess.run(
        [binary, "--noprofile", "--norc", "-c", prelude + script],
        env={**env, **(extra or {})}, text=True, capture_output=True,
        timeout=15, preexec_fn=preexec_fn,
    )
    assert result.returncode == 0, (name, result.returncode, result.stdout, result.stderr)
    checks.append(name)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="pty-primitives-") as tmp:
    env["FIXTURE_DIR"] = tmp
    run("concurrent statuses in reverse order", r'''
before=(/proc/$BASHPID/fd/*)
for ((i=0; i<16; i++)); do
    pty spawn fd pid eval "exit $((i+7))" || exit 1
    fds[i]=$fd; pids[i]=$pid
done
for ((i=15; i>=0; i--)); do
    unset code
    pty waitpid "${pids[i]}" code; rc=$?
    [[ $rc == $((i+7)) && $code == "$rc" ]] || exit 2
    pty close "${fds[i]}" || exit 3
    if pty waitpid "${pids[i]}"; then exit 4; fi
done
after=(/proc/$BASHPID/fd/*)
[[ ${#before[@]} == ${#after[@]} ]] || exit 5
''')
    run("builtin dispatch with no executable PATH", r'''
PATH=
pty spawn fd pid printf 'builtin-ok\n' || exit 1
read -r -u "$fd" value || exit 2
pty waitpid "$pid" code || exit 3
pty close "$fd" || exit 4
[[ $value == $'builtin-ok\r' && $code == 0 ]] || exit 5
''')
    run("invalid bindings cannot execute command or leak descriptors", r'''
before=(/proc/$BASHPID/fd/*)
readonly locked=original
declare -n alias=locked
declare -n one=shared two=shared
for fdvar in locked alias 'bad-name' 'a[$(touch "$FIXTURE_DIR/injected")]'; do
    if pty spawn "$fdvar" pid "$FIXTURE_PYTHON" -c 'import pathlib,os;pathlib.Path(os.environ["FIXTURE_DIR"],"started").touch()'; then exit 1; fi
done
if pty spawn fd locked "$FIXTURE_PYTHON" -c 'raise RuntimeError("must not run")'; then exit 2; fi
if pty spawn one two printf unwanted; then exit 3; fi
after=(/proc/$BASHPID/fd/*)
[[ ${#before[@]} == ${#after[@]} && $locked == original && ! -e $FIXTURE_DIR/started && ! -e $FIXTURE_DIR/injected ]] || exit 4
''')
    run("nameref outputs and invalid wait binding preserve status", r'''
declare -n outfd=fd outpid=pid outcode=code
pty spawn outfd outpid eval 'exit 19' || exit 1
readonly locked=unchanged
if pty waitpid "$pid" locked; then exit 2; fi
pty waitpid "$pid" outcode; rc=$?
pty close "$fd" || exit 3
[[ $rc == 19 && $code == 19 && $locked == unchanged ]] || exit 4
''')
    run("subshell cannot consume parent status", r'''
pty spawn fd pid eval 'exit 21' || exit 1
if (pty waitpid "$pid" code); then exit 2; fi
(
    pty spawn childfd childpid eval 'exit 3' || exit 3
    pty waitpid "$childpid" code; rc=$?
    pty close "$childfd"
    [[ $rc == 3 && $code == 3 ]]
) || exit 4
pty waitpid "$pid" code; rc=$?
pty close "$fd"
[[ $rc == 21 && $code == 21 ]] || exit 5
''')

    interrupted = prelude + r'''
trap 'seen=yes' USR1
pty spawn fd pid "$FIXTURE_PYTHON" -c 'import time; time.sleep(.7); raise SystemExit(23)' || exit 1
printf 'ready\n'
pty waitpid "$pid" code; interrupted=$?
[[ $interrupted == 138 && ${seen-} == yes && ! -v code ]] || exit 2
pty waitpid "$pid" code; rc=$?
pty close "$fd"
[[ $rc == 23 && $code == 23 ]] || exit 3
'''
    child = subprocess.Popen([binary, "--noprofile", "--norc", "-c", interrupted],
                             env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert child.stdout.readline() == "ready\n"
        time.sleep(.08)
        child.send_signal(signal.SIGUSR1)
        stdout, stderr = child.communicate(timeout=10)
        assert child.returncode == 0, ("interrupted wait", child.returncode, stdout, stderr)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    checks.append("interrupted wait preserves status for retry")

    hup_fixture = Path(tmp, "hup.py")
    hup_fixture.write_text('''import os, signal, sys, time
def done(sig, frame):
    with open(sys.argv[1], "w") as out: out.write("hup")
    os._exit(17)
signal.signal(signal.SIGHUP, done)
print("ready", flush=True)
time.sleep(10)
''')
    run("later spawn does not retain earlier PTY master", r'''
pty spawn fd1 pid1 "$FIXTURE_PYTHON" "$FIXTURE_DIR/hup.py" "$FIXTURE_DIR/hup" || exit 1
read -r -u "$fd1" ready || exit 2
pty spawn fd2 pid2 "$FIXTURE_PYTHON" -c 'import time; time.sleep(2)' || exit 3
pty close "$fd1" || exit 4
"$FIXTURE_PYTHON" -c 'import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); until=time.monotonic()+.8
while not p.exists() and time.monotonic()<until: time.sleep(.01)
raise SystemExit(0 if p.exists() else 1)' "$FIXTURE_DIR/hup"
observed=$?
kill -TERM "$pid2"
pty waitpid "$pid2"; second=$?
pty close "$fd2"
pty waitpid "$pid1" code; first=$?
[[ $observed == 0 && $first == 17 && $code == 17 && $second == 143 ]] || exit 5
''')
    run("overlapping signalfd masks close independently", r'''
before=$(mask)
bashpoll signalfd SIGUSR1 a || exit 1
bashpoll signalfd USR1 USR2 b || exit 2
both=$(mask)
bashpoll close "$a" || exit 3
after_one=$(mask)
[[ $after_one == "$both" && $both != "$before" ]] || exit 4
bashpoll close "$b" || exit 5
[[ $(mask) == "$before" ]] || exit 6
''')
    run("preexisting blocked signal remains blocked", r'''
before=$(mask)
(( (16#$before & (1 << 9)) != 0 )) || exit 1
bashpoll signalfd SIGUSR1 SIGUSR2 fd || exit 2
bashpoll close "$fd" || exit 3
[[ $(mask) == "$before" ]] || exit 4
''', preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1}))
    run("signalfd failures restore masks and descriptor count", r'''
before=$(mask); fds_before=(/proc/$BASHPID/fd/*)
readonly locked=old
for var in locked 'bad-name'; do
    if bashpoll signalfd SIGUSR1 "$var"; then exit 1; fi
done
for sig in SIGKILL SIGSTOP 0 9999; do
    if bashpoll signalfd "$sig" fd; then exit 2; fi
done
soft=$(ulimit -Sn)
exec 3</dev/null 4</dev/null
ulimit -Sn 5 || exit 3
bashpoll signalfd SIGUSR1 fd; failed=$?
ulimit -Sn "$soft"
exec 3<&- 4<&-
fds_after=(/proc/$BASHPID/fd/*)
[[ $failed != 0 && $(mask) == "$before" && ${#fds_before[@]} == ${#fds_after[@]} ]] || exit 4
''')
    run("subshell signalfd close changes only child mask", r'''
before=$(mask)
bashpoll signalfd SIGUSR1 a || exit 1
blocked=$(mask)
( FIXTURE_SHELL_PID=$BASHPID; bashpoll close "$a"; [[ $(mask) == "$before" ]] ) || exit 2
[[ $(mask) == "$blocked" ]] || exit 3
bashpoll close "$a" || exit 4
[[ $(mask) == "$before" ]] || exit 5
''')
    if args.load_dir:
        run("unloading signalfd loadable restores masks", r'''
before=$(mask)
bashpoll signalfd SIGUSR1 a || exit 1
bashpoll signalfd SIGUSR1 SIGUSR2 b || exit 2
enable -d bashpoll || exit 3
[[ $(mask) == "$before" ]] || exit 4
''')

    # Independent sockets make writability and read readiness deterministic.
    left, right = socket.socketpair()
    try:
        script = prelude + r'''
[[ -z $(bashpoll wait -t 0 "$READY_FD") ]] || exit 1
[[ $(bashpoll wait -t 0 "$READY_FD:write") == "$READY_FD writable" ]] || exit 2
[[ $(bashpoll wait -t 0 "$READY_FD:read,write") == "$READY_FD writable" ]] || exit 3
printf 'ready\n'
read -r ready
[[ $(bashpoll wait -t 0 "$READY_FD") == "$READY_FD readable" ]] || exit 4
[[ $(bashpoll wait -t 0 "$READY_FD:read,write") == "$READY_FD readable,writable" ]] || exit 5
if bashpoll wait -t 0 "$READY_FD:invalid"; then exit 6; fi
if bashpoll wait -t nope "$READY_FD"; then exit 7; fi
'''
        child = subprocess.Popen([binary, "--noprofile", "--norc", "-c", script],
                                 env={**env, "READY_FD": str(left.fileno())},
                                 pass_fds=(left.fileno(),), text=True,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert child.stdout.readline() == "ready\n"
        right.sendall(b"data")
        stdout, stderr = child.communicate("continue\n", timeout=10)
        assert child.returncode == 0, ("readiness interests", child.returncode, stdout, stderr)
        checks.append("read defaults and explicit write interests")
    finally:
        left.close()
        right.close()
        if child.poll() is None:
            child.kill()
            child.wait()

print(f"pty-primitives: {len(checks)} checks passed")
for name in checks:
    print(f"  {name}")
