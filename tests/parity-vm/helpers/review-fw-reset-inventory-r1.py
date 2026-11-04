#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only reset checks in the suite's disposable network namespace."""
import os
import subprocess
import sys
import tempfile

TOOLS = ("/usr/sbin/iptables", "/usr/sbin/ip6tables")
CAND = "/opt/bashos-parity/candidate"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/tmp/parity-home"}


def run(argv, env=ENV):
    p = subprocess.run(argv, text=True, capture_output=True, env=env, timeout=15)
    return p.returncode, p.stdout, p.stderr


def must(argv):
    result = run(argv)
    if result[0] != 0:
        raise RuntimeError("setup failed: %r: %r" % (argv, result))
    return result[1]


def fw(env=ENV, backend="iptables"):
    return run([CAND, "--noprofile", "--norc", "-c",
                '[[ $(type -t fw) == builtin ]] || exit 97; fw -B "$1" reset',
                'fw-test', backend], env)


def inventories():
    return [must([tool, "-S"]) for tool in TOOLS]


def require(cond, detail):
    if not cond:
        raise AssertionError(detail)


try:
    for tool in TOOLS:
        must([tool, "-N", "OTHER"])
        must([tool, "-A", "OTHER", "-j", "ACCEPT"])
        must([tool, "-A", "INPUT", "-j", "OTHER"])
    rc, out, err = fw()
    require(rc == 0, ("initial reset", rc, out, err))
    for tool in TOOLS:
        must([tool, "-A", "BASHFW_IN", "-j", "DROP"])
        must([tool, "-A", "BASHFW_OUT", "-j", "DROP"])
    for iteration in range(2):
        rc, out, err = fw()
        require(rc == 0, ("repeated reset", iteration, rc, out, err))
        for text in inventories():
            lines = text.splitlines()
            require(lines.count("-A INPUT -j BASHFW_IN") == 1, lines)
            require(lines.count("-A OUTPUT -j BASHFW_OUT") == 1, lines)
            require("-A INPUT -j OTHER" in lines and "-A OTHER -j ACCEPT" in lines, lines)
            require(not any(line.startswith("-A BASHFW_IN ") or line.startswith("-A BASHFW_OUT ") for line in lines), lines)
    before = inventories()
    with tempfile.TemporaryDirectory(prefix="fw-reset-inventory-", dir="/tmp/parity-home") as temp:
        os.symlink(TOOLS[0], os.path.join(temp, "iptables"))
        wrapper = os.path.join(temp, "ip6tables")
        with open(wrapper, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nif [ \"$1\" = -S ]; then echo injected-inventory-error >&2; exit 1; fi\nexec /usr/sbin/ip6tables \"$@\"\n")
        os.chmod(wrapper, 0o755)
        env = dict(ENV, PATH=temp + ":" + ENV["PATH"])
        rc, out, err = fw(env)
        require(rc != 0 and "injected-inventory-error" in err, ("injected error", rc, out, err))
        require(inventories() == before, "inventory failure changed the rules")
        with open(wrapper, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' '-P INPUT ACCEPT' '-P OUTPUT ACCEPT' 'MALFORMED'\n")
        rc, out, err = fw(env)
        require(rc != 0 and "malformed" in err, ("malformed inventory", rc, out, err))
        require(inventories() == before, "malformed inventory changed the rules")
        log = os.path.join(temp, "nft-calls")
        nft = os.path.join(temp, "nft")
        with open(nft, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$REVIEW_NFT_LOG\"\n"
                    "if [ \"$1\" = list ]; then printf '%s\\n' 'table inet fw'; exit 0; fi\n"
                    "if [ \"$1\" = delete ]; then echo injected-nft-delete >&2; exit 79; fi\n"
                    "exit 0\n")
        os.chmod(nft, 0o755)
        nenv = dict(env, REVIEW_NFT_LOG=log)
        rc, out, err = fw(nenv, "nft")
        with open(log, encoding="utf-8") as f:
            calls = f.read().splitlines()
        require(rc != 0 and "injected-nft-delete" in err, ("nft delete failure", rc, out, err))
        require(calls == ["list tables", "delete table inet fw"], ("unexpected nft calls", calls))
    print("reset inventory checks passed")
except (AssertionError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
    print("FAIL: %s" % (exc,), file=sys.stderr)
    sys.exit(1)
