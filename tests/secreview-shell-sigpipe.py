#!/usr/bin/env python3
"""Shell-lifetime SIGPIPE fixtures for the frozen bash-os review.

Each case runs one builtin under three caller dispositions (default,
trap 'printf unexpected-PIPE' PIPE, and trap '' PIPE). The shell must
keep running, trap -p PIPE and the SigIgn/SigCgt masks must match the
values from before the call, and the trap text must not appear. PATH is
empty inside the shell. Nothing here contacts an external network.

The target cases also read the started program's own masks. Default and
a caught signal must not ignore the signal. trap '' must ignore it.
"""
import os
import select
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
ONLY = sys.argv[2] if len(sys.argv) > 2 else ""
if BINARY is None or not BINARY.is_file():
    sys.exit(
        "usage: secreview-shell-sigpipe.py BASH "
        "[git|nc|mail|ssh|pty|pty-target|sv-target|git-target|targets]"
    )

CASES = (
    ("default", ""),
    ("trapped", "trap 'printf unexpected-PIPE' PIPE; "),
    ("ignored", "trap '' PIPE; "),
)
HUP_CASES = (
    ("default", ""),
    ("trapped", "trap 'printf unexpected-HUP' HUP; "),
    ("ignored", "trap '' HUP; "),
)
PIPE_BIT = 1 << 12
HUP_BIT = 1 << 0

MASK = r"""
sigmask() {
  key=$1
  while IFS= read -r line; do
    case $line in
      "$key:"*)
        bits=${line#"$key:"}
        bits=${bits//[[:space:]]/}
        printf '%s' "$bits"
        return 0
        ;;
    esac
  done < /proc/$$/status
  return 1
}
"""


def bash_env(extra=None):
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if extra:
        env.update(extra)
    if lib := os.environ.get("SECREVIEW_ASAN_LIB"):
        env["LD_PRELOAD"] = lib
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def load_prefix():
    module = os.environ.get("SECREVIEW_LOADABLE")
    name = os.environ.get("SECREVIEW_BUILTIN")
    if not module or not name:
        return ""
    return f"enable -f {shlex.quote(module)} {name} || exit 99\n"


def run_bash(script, env, timeout, stdin=subprocess.DEVNULL, pass_fds=()):
    proc = subprocess.Popen(
        [str(BINARY), "--noprofile", "--norc", "-c", script],
        env=env,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, err = proc.communicate()
        proc.timeout = True
        return proc, out, err
    proc.timeout = False
    return proc, out, err


def finish(name, proc, out, err, require_text):
    text = out + b"\n" + err
    needed = require_text if isinstance(require_text, tuple) else (require_text,)
    bad = []
    if getattr(proc, "timeout", False):
        bad.append("timeout")
    if proc.returncode != 0:
        bad.append(f"shell rc={proc.returncode}")
    if b"survived status=" not in out:
        bad.append("shell did not return")
    if b"unexpected-PIPE" in text:
        bad.append("unexpected-PIPE")
    if b"trap-changed" in out:
        bad.append("trap-changed")
    if b"mask-changed" in out:
        bad.append("mask-changed")
    for item in needed:
        if item and item not in text:
            bad.append(f"missing {item!r}")
    if bad:
        sys.exit(
            f"FAIL {name}: {', '.join(bad)}\n"
            f"out={out!r}\nerr={err!r}"
        )
    status = out.split(b"survived status=", 1)[1].split(b"\n", 1)[0]
    print(f"PASS {name} status={status.decode()}")


def wrapper(setup, body):
    return (
        load_prefix()
        + MASK
        + "PATH=\n"
        + setup
        + "before=$(trap -p PIPE); ign1=$(sigmask SigIgn); cgt1=$(sigmask SigCgt)\n"
        + body
        + "rc=$?\n"
        + "ign2=$(sigmask SigIgn); cgt2=$(sigmask SigCgt); after=$(trap -p PIPE)\n"
        + '[[ "$after" == "$before" ]] || { printf "trap-changed\\n%s\\n%s\\n" "$before" "$after"; exit 91; }\n'
        + '[[ "$ign1" == "$ign2" && "$cgt1" == "$cgt2" ]] || '
        + '{ printf "mask-changed ign %s -> %s cgt %s -> %s\\n" "$ign1" "$ign2" "$cgt1" "$cgt2"; exit 92; }\n'
        + 'printf "survived status=%s\\n" "$rc"\n'
    )


def test_git():
    for disposition, setup in CASES:
        with tempfile.TemporaryDirectory(prefix="sr-git-") as temporary:
            script = wrapper(
                setup,
                'GIT_SSH_COMMAND="exit 0" git ls-remote ssh://127.0.0.1/fixture-repo\n',
            )
            env = bash_env()
            env["HOME"] = temporary
            proc, out, err = run_bash(script, env, 8)
            # git's own fatal is printed by the forked command child.
            finish(f"git {disposition}", proc, out, err, (b"fatal:", b"survived status=128\n"))


def test_nc():
    for disposition, setup in CASES:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(6)
        port = srv.getsockname()[1]
        out_r, out_w = os.pipe()
        if out_w <= 2:
            sys.exit("nc fixture needed a free descriptor above 2")
        accepted = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def peer():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            accepted.set()
            if not release.wait(6):
                conn.close()
                return
            try:
                conn.sendall(b"payload-for-stdout\n")
            except OSError:
                pass
            finished.wait(8)
            conn.close()

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        script = wrapper(setup, f"nc connect 127.0.0.1 {port} >&{out_w}\n")
        proc = subprocess.Popen(
            [str(BINARY), "--noprofile", "--norc", "-c", script],
            env=bash_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(out_w,),
            start_new_session=True,
        )
        os.close(out_w)
        try:
            if not accepted.wait(6):
                os.killpg(proc.pid, signal.SIGKILL)
                out, err = proc.communicate()
                sys.exit(f"FAIL nc {disposition}: connect did not arrive out={out!r} err={err!r}")
            os.close(out_r)
            out_r = -1
            release.set()
            try:
                out, err = proc.communicate(timeout=6)
                proc.timeout = False
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                out, err = proc.communicate()
                proc.timeout = True
            finish(f"nc {disposition}", proc, out, err,
                   (b"write stdout:", b"survived status=1\n"))
        finally:
            finished.set()
            if out_r >= 0:
                os.close(out_r)
            srv.close()
            thread.join(timeout=2)


def test_mail():
    for verb in ("serve", "smtpd"):
        for disposition, setup in CASES:
            with tempfile.TemporaryDirectory(prefix="sr-mail-", dir="/tmp") as temporary:
                root = Path(temporary)
                queue = root / "q"
                queue.mkdir(mode=0o700)
                if verb == "serve":
                    endpoint = root / "sock"
                    command = f'mail serve --socket {endpoint} --queue {queue}\n'
                    ready = b"mail: serving"
                else:
                    holder = socket.socket()
                    holder.bind(("127.0.0.1", 0))
                    port = holder.getsockname()[1]
                    holder.close()
                    command = f"mail smtpd --bind 127.0.0.1:{port} --queue {queue}\n"
                    ready = b"mail: smtpd listening"
                script = wrapper(setup, command)
                proc = subprocess.Popen(
                    [str(BINARY), "--noprofile", "--norc", "-c", script],
                    env=bash_env({"HOME": temporary}),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                collected = b""
                deadline = time.monotonic() + 6
                try:
                    while ready not in collected and time.monotonic() < deadline:
                        readable, _, _ = select.select([proc.stdout], [], [], 0.2)
                        if proc.poll() is not None and not readable:
                            break
                        if readable:
                            chunk = os.read(proc.stdout.fileno(), 4096)
                            if not chunk:
                                break
                            collected += chunk
                    if ready not in collected:
                        os.killpg(proc.pid, signal.SIGKILL)
                        rest, err = proc.communicate()
                        sys.exit(
                            f"FAIL mail {verb} {disposition}: did not become ready "
                            f"out={collected + rest!r} err={err!r}"
                        )
                    os.kill(proc.pid, signal.SIGTERM)
                    try:
                        rest, err = proc.communicate(timeout=6)
                        proc.timeout = False
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        rest, err = proc.communicate()
                        proc.timeout = True
                    finish(f"mail {verb} {disposition}", proc, collected + rest, err,
                           (ready, b"survived status=0\n"))
                finally:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.communicate()


def test_ssh():
    for disposition, setup in CASES:
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        holder.close()
        script = wrapper(setup, f"ssh run 127.0.0.1 true -p {port}\n")
        proc, out, err = run_bash(script, bash_env(), 8)
        # A refused local port must surface ssh's own error. No session is opened.
        finish(f"ssh {disposition}", proc, out, err, (b"ssh:", b"survived status=1\n"))


def test_pty():
    for disposition, setup in CASES:
        script = wrapper(setup, "pty spawn SRFD SRPID true\n")
        proc, out, err = run_bash(script, bash_env(), 8)
        finish(f"pty {disposition}", proc, out, err, b"survived status=0")


def mask_value(text, key):
    for line in text.splitlines():
        if line.startswith(key + ":"):
            return int(line.split(":", 1)[1].strip(), 16)
    sys.exit(f"missing {key} in {text!r}")


def require_target(name, path, bit, want_ignored, out, err):
    if not path.is_file() or path.stat().st_size == 0:
        sys.exit(f"FAIL {name}: target wrote no status\nout={out!r}\nerr={err!r}")
    text = path.read_text()
    ign = mask_value(text, "SigIgn")
    cgt = mask_value(text, "SigCgt")
    ignored = bool(ign & bit)
    caught = bool(cgt & bit)
    if want_ignored:
        ok = ignored and not caught
        expected = "ignored"
    else:
        ok = not ignored and not caught
        expected = "default"
    if not ok:
        sys.exit(
            f"FAIL {name}: expected {expected}\n{text}\nout={out!r}\nerr={err!r}"
        )
    return text


def write_reader(path, output):
    path.write_text(
        "#!/bin/bash\n"
        "while IFS= read -r line; do\n"
        "  case $line in\n"
        "    SigIgn:*|SigCgt:*) printf '%s\\n' \"$line\" ;;\n"
        "  esac\n"
        "done < /proc/self/status > "
        + shlex.quote(str(output))
        + "\n"
    )
    path.chmod(0o755)


def test_pty_target():
    for disposition, setup in CASES:
        with tempfile.TemporaryDirectory(prefix="sr-pty-target-") as temporary:
            root = Path(temporary)
            output = root / "status"
            reader = root / "reader"
            write_reader(reader, output)
            body = (
                f"pty spawn SRFD SRPID /bin/bash {shlex.quote(str(reader))}\n"
                f"for _ in {{1..50}}; do [[ -s {shlex.quote(str(output))} ]] && break; "
                "/bin/sleep 0.05; done\n"
                f"[[ -s {shlex.quote(str(output))} ]]\n"
            )
            proc, out, err = run_bash(wrapper(setup, body), bash_env(), 8)
            require_target(
                f"pty target {disposition}",
                output,
                PIPE_BIT,
                disposition == "ignored",
                out,
                err,
            )
            finish(f"pty target {disposition}", proc, out, err, b"survived status=0")


def test_sv_target():
    for disposition, setup in HUP_CASES:
        with tempfile.TemporaryDirectory(prefix="sr-sv-target-") as temporary:
            root = Path(temporary)
            output = root / "status"
            services = root / "services" / "probe"
            services.mkdir(parents=True)
            run = services / "run"
            run.write_text(
                "#!/bin/bash\n"
                "# type: oneshot\n"
                "while IFS= read -r line; do\n"
                "  case $line in\n"
                "    SigIgn:*|SigCgt:*) printf '%s\\n' \"$line\" ;;\n"
                "  esac\n"
                "done < /proc/self/status > "
                + shlex.quote(str(output))
                + "\n"
            )
            run.chmod(0o755)
            (root / "run").mkdir()
            (root / "logs").mkdir()
            body = (
                "sv up probe\n"
                f"for _ in {{1..50}}; do [[ -s {shlex.quote(str(output))} ]] && break; "
                "/bin/sleep 0.05; done\n"
                "sv down probe >/dev/null 2>&1 || true\n"
                f"[[ -s {shlex.quote(str(output))} ]]\n"
            )
            env = bash_env({
                "BASHSV_DIR": str(services.parent),
                "BASHSV_RUNDIR": str(root / "run"),
                "BASHSV_LOGDIR": str(root / "logs"),
            })
            proc, out, err = run_bash(wrapper(setup, body), env, 12)
            text = out + b"\n" + err
            if b"unexpected-HUP" in text:
                sys.exit(f"FAIL sv target {disposition}: unexpected-HUP\n{text!r}")
            require_target(
                f"sv target {disposition}",
                output,
                HUP_BIT,
                disposition == "ignored",
                out,
                err,
            )
            finish(f"sv target {disposition}", proc, out, err, b"survived status=0")


def test_git_target():
    for disposition, setup in CASES:
        with tempfile.TemporaryDirectory(prefix="sr-git-target-") as temporary:
            root = Path(temporary)
            output = root / "status"
            dump = root / "dump"
            dump.write_text(
                "while IFS= read -r line; do\n"
                "  case $line in\n"
                "    SigIgn:*|SigCgt:*) printf '%s\\n' \"$line\" ;;\n"
                "  esac\n"
                "done < /proc/self/status > "
                + shlex.quote(str(output))
                + "\n"
            )
            command = f". {dump}"
            body = (
                f"GIT_SSH_COMMAND={shlex.quote(command)} "
                "git ls-remote ssh://127.0.0.1/fixture-repo\n"
                f"[[ -s {shlex.quote(str(output))} ]]\n"
            )
            env = bash_env()
            env["HOME"] = str(root)
            proc, out, err = run_bash(wrapper(setup, body), env, 8)
            require_target(
                f"git target {disposition}",
                output,
                PIPE_BIT,
                disposition == "ignored",
                out,
                err,
            )
            finish(
                f"git target {disposition}",
                proc,
                out,
                err,
                b"survived status=0",
            )


def main():
    selected = {
        "git": test_git,
        "nc": test_nc,
        "mail": test_mail,
        "ssh": test_ssh,
        "pty": test_pty,
        "pty-target": test_pty_target,
        "sv-target": test_sv_target,
        "git-target": test_git_target,
    }
    if ONLY == "targets":
        test_pty_target()
        test_sv_target()
        test_git_target()
        return
    if ONLY:
        if ONLY not in selected:
            sys.exit(f"unknown builtin {ONLY}")
        selected[ONLY]()
        return
    for name in ("git", "nc", "mail", "ssh", "pty", "pty-target", "sv-target", "git-target"):
        selected[name]()


if __name__ == "__main__":
    main()
