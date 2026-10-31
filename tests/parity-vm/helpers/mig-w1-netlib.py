#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Shared guest-side helpers for the w1 network fixtures.

Runs inside a mapped user namespace (unshare --user --map-root-user --net ...).
Provides: running a callable in a throw-away network namespace, running the
candidate shell and the reference tools, and check bookkeeping that prints one
`ok NAME` / `FAIL NAME: detail` line per assertion.
"""
import json
import os
import subprocess
import sys
import difflib

CAND = "/opt/bashos-parity/candidate"
IPR = "/usr/bin/ip"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/tmp/parity-home",
       "TZ": "UTC"}

_results = []


def check(name, cond, detail=""):
    """Per-check lines go to stderr (retained raw evidence); stdout carries only the verdict."""
    if cond:
        _results.append((name, True, ""))
        print("ok " + name, file=sys.stderr, flush=True)
    else:
        _results.append((name, False, detail))
        print("FAIL " + name + (": " + str(detail)[:1500] if detail else ""), file=sys.stderr, flush=True)
    return bool(cond)


def finish(scenario):
    bad = [n for n, ok, _ in _results if not ok]
    print("checks=%d failed=%d" % (len(_results), len(bad)), file=sys.stderr, flush=True)
    if not _results:
        print("scenario %s: NO CHECKS RAN" % scenario)
    elif bad:
        print("scenario %s: FAIL %s" % (scenario, "; ".join(bad[:12])))
    else:
        print("scenario %s: all checks ok" % scenario)
    return 0


def run(argv, input=None, env=None, timeout=20):
    p = subprocess.run(argv, input=input, capture_output=True, text=True,
                       env=env or ENV, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def cand(script, *args, input=None, env=None, timeout=20):
    """Run SCRIPT in the candidate shell; positional args become $1.."""
    e = dict(ENV)
    if env:
        e.update(env)
    return run([CAND, "--noprofile", "--norc", "-c", script, "cand"] + list(args),
               input=input, env=e, timeout=timeout)


def cand_ip(args, input=None):
    return cand('ip "$@"', *args, input=input)


def ref_ip(args, input=None):
    return run([IPR] + list(args), input=input)


def in_netns(fn):
    """Run fn() in a forked child inside a fresh network namespace; return its JSON result."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            os.unshare(os.CLONE_NEWNET)
            out = fn()
            data = json.dumps(out).encode()
        except BaseException as exc:  # noqa: BLE001
            data = json.dumps({"__error__": repr(exc)}).encode()
        with os.fdopen(w, "wb") as f:
            f.write(data)
        os._exit(0)
    os.close(w)
    with os.fdopen(r, "rb") as f:
        raw = f.read()
    os.waitpid(pid, 0)
    return json.loads(raw)


def jq(args, tool=None):
    rc, out, err = run([IPR, "-j"] + args)
    try:
        return json.loads(out) if out.strip() else []
    except ValueError:
        return {"unparsed": out, "stderr": err}


def seed(cmds):
    for c in cmds:
        rc, out, err = ref_ip(c)
        if rc != 0:
            raise RuntimeError("seed failed: ip %s: %s" % (" ".join(c), err))


def json_diff(a, b):
    x = json.dumps(a, indent=1, sort_keys=True).splitlines()
    y = json.dumps(b, indent=1, sort_keys=True).splitlines()
    return "\n".join(list(difflib.unified_diff(x, y, "candidate", "iproute2", lineterm=""))[:60])


def load_helper(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"),
                                                  os.path.join(os.path.dirname(os.path.abspath(__file__)), name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
