#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Common guard and evidence writer for disposable-guest qualification only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def guard(root=False):
    if os.environ.get("BASHOS_QUALIFICATION_GUEST") != "1":
        raise RuntimeError("requires an explicitly authorized disposable guest")
    uuid.UUID(Path("/etc/bashos-parity-vm").read_text().strip())
    if Path("/sys/class/dmi/id/sys_vendor").read_text().strip() != "QEMU":
        raise RuntimeError("not the disposable qualification guest")
    if root and os.geteuid() != 0:
        raise RuntimeError("this control requires guest root")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def clean_env():
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/parity-home",
            "BASHOS_QUALIFICATION_GUEST": "1"}


def run(argv, data=b"", timeout=20, env=None, cwd=None, start_new_session=False):
    try:
        p = subprocess.run(list(map(str, argv)), input=data, capture_output=True,
                           timeout=timeout, env=env or clean_env(), cwd=cwd,
                           start_new_session=start_new_session)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": list(map(str, argv)), "status": 125, "error": str(exc),
                "stdout_hex": (getattr(exc,"stdout",None) or b"").hex(),
                "stderr_hex": (getattr(exc,"stderr",None) or b"").hex(),
                "stdin_sha256": hashlib.sha256(data).hexdigest()}
    return {"argv": list(map(str, argv)), "status": p.returncode,
            "stdin_sha256": hashlib.sha256(data).hexdigest(),
            "stdout_hex": p.stdout.hex(), "stderr_hex": p.stderr.hex(),
            "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(p.stderr).hexdigest()}


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def require_bash_5320(shell):
    """Guest-only version prerequisite; not proof of source/build provenance."""
    guard()
    observed = run([shell, '--noprofile', '--norc', '-c',
                    'printf "%s.%s.%s\\n" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}" "${BASH_VERSINFO[2]}"'])
    if (observed['status'] != 0 or observed['stderr_hex'] or
            bytes.fromhex(observed['stdout_hex']) != b'5.3.20\n'):
        raise RuntimeError('Bash 5.3.20 prerequisite failed: ' + json.dumps(observed))
    observed['shell_sha256'] = digest(shell)
    return observed


def entrypoint(main):
    try:
        status = main()
    except Exception as exc:
        print(json.dumps({"result":"ERROR", "error":str(exc)}), file=sys.stderr)
        status = 125
    raise SystemExit(status)
