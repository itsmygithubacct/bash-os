#!/usr/bin/env python3
"""Version output failures must reach every shared-dispatch caller."""
import os
from pathlib import Path
import subprocess
import sys

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH="", LC_ALL="C")
env.pop("BASH_ENV", None)
env.pop("ENV", None)
for name in ("pgrep", "pkill", "killall", "killall5"):
    for prefix in ("", "-9 " if name != "pgrep" else "-f "):
        for redirect in (">/dev/full", ">&-"):
            script = (
                f"{name} {prefix}--version {redirect}; rc=$?; "
                '[[ $rc == 1 ]] || exit 90; '
                f"{name} --version >/dev/null || exit 91; "
                'printf "recovered\\n"'
            )
            result = subprocess.run(
                [binary, "--noprofile", "--norc", "-c", script],
                env=env, capture_output=True, timeout=10,
            )
            assert (result.returncode, result.stdout) == (0, b"recovered\n"), (
                name, prefix, redirect, result
            )
            assert b"write error" in result.stderr, result
print("16 shared version output failure/recovery cases passed")
