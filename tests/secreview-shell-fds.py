#!/usr/bin/env python3
"""Descriptor check: 40 open/close cycles must leave /proc/$$/fd unchanged.

Same shape as the dmsetup shell test: compare the two glob arrays, with
no ls or wc. PATH is empty inside the shell. dmsetup's own 40-cycle check
stays in tests/opus-dmsetup-ioctl.py.
"""
import os
import shlex
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
ONLY = sys.argv[2] if len(sys.argv) > 2 else ""
if BINARY is None or not BINARY.is_file():
    sys.exit("usage: secreview-shell-fds.py BASH [lpr|pkg|ptybroker|ssh]")

LOOP = r"""
before=(/proc/$$/fd/*)
i=0
while [ "$i" -lt 40 ]; do
  __BODY__
  i=$((i + 1))
done
after=(/proc/$$/fd/*)
if [[ ${before[*]} == "${after[*]}" ]]; then
  printf 'fds-same\n'
else
  printf 'fds-differ\n'
  printf 'before=%s\n' "${before[*]}"
  printf 'after=%s\n' "${after[*]}"
  exit 93
fi
"""


def run(script, env, timeout):
    module = os.environ.get("SECREVIEW_LOADABLE")
    name = os.environ.get("SECREVIEW_BUILTIN")
    if module and name:
        script = f"enable -f {shlex.quote(module)} {name} || exit 99\n" + script
    env = dict(env)
    if lib := os.environ.get("SECREVIEW_ASAN_LIB"):
        env["LD_PRELOAD"] = lib
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    proc = subprocess.run(
        [str(BINARY), "--noprofile", "--norc", "-c", script],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0 or b"fds-same\n" not in proc.stdout or b"fds-differ" in proc.stdout:
        sys.exit(
            f"FAIL rc={proc.returncode}\nout={proc.stdout!r}\nerr={proc.stderr!r}"
        )
    print("PASS", proc.stdout.decode().strip())


def test_lpr():
    with tempfile.TemporaryDirectory(prefix="sr-lpr-fd-") as temporary:
        spool = Path(temporary) / "spool"
        spool.mkdir(mode=0o700)
        body = "lpr list >/dev/null || exit 9"
        script = "PATH=\n" + LOOP.replace("__BODY__", body)
        env = {"PATH": "/usr/bin:/bin", "BASHLPR_SPOOL": str(spool), "HOME": temporary}
        run(script, env, 20)
        print("lpr")


def test_pkg():
    with tempfile.TemporaryDirectory(prefix="sr-pkg-fd-") as temporary:
        root = Path(temporary) / "root"
        installed = root / "var" / "lib" / "pkg" / "installed"
        installed.mkdir(parents=True, mode=0o700)
        body = f'pkg list --root {root} >/dev/null || exit 9'
        script = "PATH=\n" + LOOP.replace("__BODY__", body)
        env = {"PATH": "/usr/bin:/bin", "HOME": temporary}
        run(script, env, 30)
        print("pkg")


def test_ptybroker():
    with tempfile.TemporaryDirectory(prefix="pb", dir="/tmp") as temporary:
        root = Path(temporary)
        # pb_check_root requires an absolute private directory, mode 0700,
        # at most 90 bytes, with no trailing slash.
        if len(str(root)) > 90 or (root.stat().st_mode & 0o777) != 0o700:
            sys.exit(f"ptybroker root is not usable: {root}")
        # A sibling session's SIGCHLD must not abort create. Spam only
        # during create: receive and terminate still have to surface EINTR
        # so a caller trap can interrupt them. Stop the spam before
        # terminate, or that call fails for the same reason on purpose.
        script = f'''PATH=
spam() {{ while true; do kill -CHLD $$; done; }}
before=(/proc/$$/fd/*)
i=0
while [ "$i" -lt 40 ]; do
  id=$(printf "s%02d" "$i")
  spam &
  spam_pid=$!
  ptybroker create {root} "$id" -- /bin/true >/dev/null
  create_rc=$?
  kill "$spam_pid"
  wait "$spam_pid" || true
  [ "$create_rc" -eq 0 ] || exit 9
  ptybroker terminate {root} "$id" >/dev/null || exit 9
  i=$((i + 1))
done
after=(/proc/$$/fd/*)
if [[ ${{before[*]}} == "${{after[*]}}" ]]; then
  printf 'fds-same\\n'
else
  printf 'fds-differ\\n'
  printf 'before=%s\\n' "${{before[*]}}"
  printf 'after=%s\\n' "${{after[*]}}"
  exit 93
fi
'''
        env = {"PATH": "/usr/bin:/bin", "HOME": temporary}
        run(script, env, 180)
        print("ptybroker")


def test_ssh():
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    holder.close()
    body = f"ssh run 127.0.0.1 true -p {port} >/dev/null 2>&1 && exit 8"
    script = "PATH=\n" + LOOP.replace("__BODY__", body)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "SSH_AUTH_SOCK": ""}
    run(script, env, 40)
    print("ssh")


def main():
    selected = {
        "lpr": test_lpr,
        "pkg": test_pkg,
        "ptybroker": test_ptybroker,
        "ssh": test_ssh,
    }
    names = (ONLY,) if ONLY else ("lpr", "pkg", "ptybroker", "ssh")
    if ONLY and ONLY not in selected:
        sys.exit(f"unknown builtin {ONLY}")
    for name in names:
        selected[name]()


if __name__ == "__main__":
    main()
