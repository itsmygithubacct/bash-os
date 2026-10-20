#!/usr/bin/env python3
"""Cancel must survive a reader closing before the control-FIFO write.

The shell's SIGPIPE disposition (default, trapped, ignored) is restored,
and the default disposition must not kill the caller before EPIPE is
reported as "already finished".
"""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

if len(sys.argv) != 4:
    sys.exit("usage: opus-lpr-cancel-sigpipe.py BASH LPR_SO PRELOAD_SO")
binary, module, shim = (Path(a).resolve() for a in sys.argv[1:])
prefix = "enable -f " + shlex.quote(str(module)) + " lpr || exit 99; "
cases = (
    ("default", ""),
    ("trapped", "trap 'printf unexpected-PIPE' PIPE; "),
    ("ignored", "trap '' PIPE; "),
)
for disposition, setup in cases:
    with tempfile.TemporaryDirectory(prefix="lpr-cancel-sigpipe-") as temporary:
        root = Path(temporary)
        spool = root / "spool"
        spool.mkdir(mode=0o700)
        job = "0123456789abcdef"
        (spool / (job + ".lpr")).write_bytes(b"owned fixture")
        fifo = spool / (job + ".ctl")
        os.mkfifo(fifo, 0o600)
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        ready, go = root / "ready", root / "go"
        env = dict(os.environ)
        env.update(
            BASHLPR_SPOOL=str(spool),
            LD_PRELOAD=str(shim),
            LPR_REVIEW_CTL=fifo.name,
            LPR_REVIEW_READY=str(ready),
            LPR_REVIEW_GO=str(go),
        )
        env.pop("BASH_ENV", None)
        script = (
            prefix + "PATH=; " + setup
            + 'before=$(trap -p PIPE); lpr cancel ' + job + '; rc=$?; '
            + '[[ $(trap -p PIPE) == "$before" ]] || exit 91; '
            + 'printf "survived status=%s\\n" "$rc"'
        )
        proc = subprocess.Popen(
            [str(binary), "--noprofile", "--norc", "-c", script],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            end = time.monotonic() + 12
            while not ready.exists() and proc.poll() is None and time.monotonic() < end:
                time.sleep(0.005)
            if not ready.exists():
                sys.exit(f"{disposition}: cancel never opened the owned live FIFO")
            os.close(reader)
            reader = -1
            go.touch()
            out, err = proc.communicate(timeout=5)
        finally:
            if reader >= 0:
                os.close(reader)
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        if proc.returncode != 0 or b"already finished" not in out or not out.endswith(
            b"survived status=0\n"
        ) or b"unexpected-PIPE" in out or err:
            sys.exit(
                f"{disposition}: rc={proc.returncode} out={out!r} err={err!r}"
            )
        print("PASS", disposition, "SIGPIPE disposition preserved; cancel survived reader close")
