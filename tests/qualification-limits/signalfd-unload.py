#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Observe a separately built module's unload in its still-running shell."""
import argparse
import ctypes
import os
from pathlib import Path
import select
import signal
import subprocess
from guest import clean_env, digest, entrypoint, guard, require_bash_5320, save

SCRIPT = r'''
set -eu
mark() { printf '%s %s %s %s\n' "$1" "${a:--}" "${b:--}" "$keep"; IFS= read -r go; }
[[ $(type -t bashpoll || :) != builtin ]] || exit 125
exec {keep}</dev/null
enable -f "$1" bashpoll
mark baseline
bashpoll signalfd USR1 SIGUSR2 a
bashpoll signalfd USR1 b
mark created
enable -n bashpoll
mark disabled
enable -d bashpoll
mark unloaded
if [[ $2 == positive ]]; then
  enable -f "$1" bashpoll
  bashpoll signalfd USR1 a
  mark reloaded
  enable -d bashpoll
  mark final
fi
'''


def bit(sig): return 1 << (sig - 1)


def snapshot(pid):
    base = Path("/proc") / str(pid)
    fields = dict(line.split(":",1) for line in (base / "status").read_text().splitlines() if ":" in line)
    fds = {}
    for path in (base / "fd").iterdir():
        fds[path.name] = os.readlink(path)
    return {"blocked": int(fields["SigBlk"].strip(),16), "fds": fds}


def inherited_mask():
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR1})
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})


def raw_control():
    """Kernel closes a signalfd without restoring the signal mask."""
    before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    fd = None
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR1})
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        expected = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
        c = ctypes.CDLL(None, use_errno=True)
        mask = ctypes.create_string_buffer(128)
        c.sigemptyset.argtypes = [ctypes.c_void_p]
        c.sigaddset.argtypes = [ctypes.c_void_p,ctypes.c_int]
        c.signalfd.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_int]
        if c.sigemptyset(mask) or c.sigaddset(mask,signal.SIGUSR1): raise OSError(ctypes.get_errno())
        fd = c.signalfd(-1,mask,os.O_CLOEXEC)
        if fd < 0: raise OSError(ctypes.get_errno())
        os.close(fd); fd = None
        after_close = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR1})
        restored = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        ok = after_close == expected | {signal.SIGUSR1} and restored == expected
        return dict(ok=ok, before=sorted(expected), close_only=sorted(after_close), explicit_restore=sorted(restored))
    finally:
        if fd is not None: os.close(fd)
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def lifecycle(shell, module, mode):
    p = subprocess.Popen([shell,"--noprofile","--norc","-c",SCRIPT,"qualification",module,mode],
                         stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         env=clean_env(), preexec_fn=inherited_mask, bufsize=0)
    states = {}
    expected = ["baseline","created","disabled","unloaded"] + (["reloaded","final"] if mode == "positive" else [])
    try:
        for name in expected:
            if not select.select([p.stdout],[],[],5)[0]: raise RuntimeError("missing lifecycle marker: " + name)
            line = p.stdout.readline().decode("ascii").split()
            if len(line) != 4 or line[0] != name: raise RuntimeError("invalid marker: " + repr(line))
            observed = snapshot(p.pid)
            observed.update(a=line[1],b=line[2],keep=line[3])
            states[name] = observed
            p.stdin.write(b"continue\n"); p.stdin.flush()
        out, err = p.communicate(timeout=5)
        return dict(status=p.returncode,stdout_hex=out.hex(),stderr_hex=err.hex(),states=states)
    finally:
        if p.poll() is None: p.kill(); p.wait(timeout=5)


def checks(observed):
    s = observed["states"]; base = s["baseline"]; created = s["created"]
    a,b,keep = created["a"],created["b"],base["keep"]
    owned = bit(signal.SIGUSR1); preblocked = bit(signal.SIGUSR2)
    ready = (not base["blocked"] & owned and base["blocked"] & preblocked and a != b and
             created["fds"].get(a) == created["fds"].get(b) == "anon_inode:[signalfd]" and
             all(v["fds"].get(keep) == "/dev/null" for v in s.values()))
    created_ok = created["blocked"] == base["blocked"] | owned
    disable_only = (s["disabled"]["blocked"] == created["blocked"] and
                    all(s["disabled"]["fds"].get(fd) == "anon_inode:[signalfd]" for fd in (a,b)))
    unload_restores = s["unloaded"]["blocked"] == base["blocked"]
    unload_closes = a not in s["unloaded"]["fds"] and b not in s["unloaded"]["fds"]
    reload = True
    if "reloaded" in s:
        again = s["reloaded"]
        reload = (again["blocked"] == base["blocked"] | owned and
                  again["fds"].get(again["a"]) == "anon_inode:[signalfd]" and
                  s["final"]["blocked"] == base["blocked"] and again["a"] not in s["final"]["fds"])
    return dict(ready=bool(ready),created=created_ok,disable_only=disable_only,
                unload_restores=unload_restores,unload_closes=unload_closes,reload=reload)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("stock_shell"); p.add_argument("module"); p.add_argument("omitted_hook_control"); p.add_argument("output")
    a = p.parse_args(); guard()
    bash_version = require_bash_5320(a.stock_shell)
    control = raw_control()
    good = lifecycle(a.stock_shell,a.module,"positive")
    bad = lifecycle(a.stock_shell,a.omitted_hook_control,"negative")
    g,b = checks(good),checks(bad)
    controls = (control["ok"] and all(b[k] for k in ("ready","created","disable_only")) and
                not b["unload_restores"] and not b["unload_closes"])
    setup = controls and all(g[k] for k in ("ready","created","disable_only")) and all(
        r["status"] == 0 and not r["stdout_hex"] and not r["stderr_hex"] for r in (good,bad))
    result = "ERROR" if not setup else ("PASS" if all(g.values()) else "FAIL")
    save(a.output,dict(scope="separate dynamic bashpoll module; not either release binary",
                       bash_version=bash_version,
                       result=result,binaries={x:digest(x) for x in (a.stock_shell,a.module,a.omitted_hook_control)},
                       raw_kernel_control=control,positive=good,negative=bad,checks=g,negative_checks=b))
    return {"PASS":0,"FAIL":1,"ERROR":125}[result]


if __name__ == "__main__": entrypoint(main)
