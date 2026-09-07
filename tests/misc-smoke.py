#!/usr/bin/env python3
"""Small-tool contracts using temporary data and an empty command PATH."""
import os
from pathlib import Path
import random
import re
import socket
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve())
checks = 0

def run(*args, data=None, rc=0, env=None):
    global checks
    p = subprocess.run([binary, "-c", 'PATH=; "$@"', "_", *map(str, args)],
                       input=data, capture_output=True, timeout=15, env=env)
    assert p.returncode == rc, (args, p.returncode, p.stdout, p.stderr)
    checks += 1
    return p.stdout

with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    names = "asort totp scrub bignum tz locale scm notify cluster at batch crontab payload fsck mkfs lpr opt cal man apropos whatis file"
    for name in names.split(): assert run("type", "-t", name) == b"builtin\n"
    run("eval", 'a=(three one two); asort a; [[ ${a[*]} == "one three two" ]]')
    rng = random.Random(196)
    for _ in range(12):
        a, b = rng.randrange(-2**256, 2**256), rng.randrange(1, 2**128)
        for op, expected in (("add", a+b), ("sub", a-b), ("mul", a*b)):
            assert int(run("bignum", op, a, b)) == expected
        q = (abs(a)//b) * (-1 if a < 0 else 1)
        assert list(map(int, run("bignum", "divmod", a, b).split())) == [q, a-q*b]
    assert int(run("bignum", "modexp", 1234, 567, 891)) == pow(1234, 567, 891)
    run("bignum", "divmod", 1, 0, rc=1)
    assert run("tz", "convert", 0, "-z", "UTC") == b"1970-01-01 00:00:00 UTC +0000\n"
    run("locale", "validate", "C.UTF-8")
    run("locale", "validate", "invalid", rc=1)
    uri = run("totp", "uri", "-k", "JBSWY3DPEHPK3PXP", "-l", "test", "-i", "fixture").decode().strip()
    assert uri.startswith("otpauth://totp/")
    run("totp", "parse-uri", uri)
    run("totp", "parse-uri", "invalid", rc=1)
    run("eval", 'scrub clear-patterns; scrub add-pattern blocked; '
        'scrub scrub-line allowed && ! scrub scrub-line blocked')
    (d / "text").write_text("passed\n")
    run("eval", 'scm pair -h left -h right; exec {source}< "$TEST_FILE"; '
        'scm send-fd "$left" "$source" tag; scm recv-fd "$right" -h received -V message; '
        'read -r -u "$received" value; [[ $value == passed && $message == tag ]]',
        env={**os.environ, "TEST_FILE": str(d / "text")})
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        receiver.bind(str(d / "notify")); receiver.settimeout(2)
        run("notify", "send", d / "notify", "READY=1")
        assert receiver.recv(1024) == b"READY=1"
    run("cluster", "--version")
    env = {**os.environ, "BASHCRON_SPOOL_DIR": str(d / "cron"), "USER": "fixture"}
    run("at", "@2000000000", data=b"echo scheduled\n", env=env)
    jobs = list((d / "cron/atjobs").glob("*")); assert jobs
    run("at", "-l", env=env)
    run("batch", data=b"echo batch\n", env=env)
    assert len(list((d / "cron/atjobs").glob("*"))) > len(jobs)
    (d / "crontab").write_text("* * * * * echo cron\n")
    run("crontab", d / "crontab", env=env)
    assert run("crontab", "-l", env=env) == (d / "crontab").read_bytes()
    run("eval", 'before=(/proc/self/fd/*); for ((i=0;i<10;i++)); do '
        'crontab "$BAD_INPUT" || :; done; after=(/proc/self/fd/*); '
        '[[ ${#before[@]} == ${#after[@]} ]]', env={**env, "BAD_INPUT": str(d)})
    run("crontab", "-r", env=env)
    image = d / "disk.img"
    with image.open("wb") as f: f.truncate(8*1024*1024)
    run("mkfs", image, "-L", "fixture")
    run("fsck", "-n", image)
    assert image.read_bytes()[1080:1082] == b"\x53\xef"
    run("lpr", "list", env={**os.environ, "BASHLPR_SPOOL": str(d / "print")})
    run("payload", "help")
    for args in (("-o", "ab:", "--", "-a", "-b", "two words", "tail"),
                 ("-o", "", "-l", "name:", "--", "--name", "it's quoted")):
        expected = subprocess.run(["/usr/bin/getopt", *args], capture_output=True, check=True).stdout
        assert run("opt", *args) == expected
    feb = run("cal", "2", "2024").decode().splitlines()[2:]
    assert list(map(int, re.findall(r"\d+", "\n".join(feb)))) == list(range(1,30))
    man = d / "man"; (man / "man1").mkdir(parents=True)
    (man / "man1/task.1").write_text('.TH TASK 1\n.SH NAME\ntask - fixture command\n')
    (man / "whatis").write_text("task (1) - fixture command\n")
    env = {**os.environ, "MANPATH": str(man), "BASHMAN_STALE_QUIET": "1"}
    assert b"fixture command" in run("man", "task", env=env)
    assert b"fixture command" in run("apropos", "fixture", env=env)
    assert b"fixture command" in run("whatis", "task", env=env)
    prefix = "-----" + "BEGIN "
    for kind, expected in (("RSA", "PEM RSA private key"), ("EC", "PEM EC private key"),
                           ("DSA", "PEM DSA private key"), ("OPENSSH", "OpenSSH private key"),
                           ("PGP", "PGP private key block")):
        marker = prefix + kind + " PRIVATE " + "KEY" + (" BLOCK" if kind == "PGP" else "") + "-----\n"
        (d / "magic").write_text(marker)
        assert run("file", "-b", d / "magic").decode().strip() == expected
    (d / "magic").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))
    assert b"PNG" in run("file", "-b", d / "magic")

print(f"misc-smoke: {checks} checks passed")
