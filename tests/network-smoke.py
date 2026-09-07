#!/usr/bin/env python3
"""Exercise imported network helpers with files and loopback sockets."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

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
    for name in "nc pkt http pcap dhcp6 dhcpd6 sftp scp audit fail2ban".split():
        assert run("type", "-t", name) == b"builtin\n"
    run("pcap", "selftest")
    run("fail2ban", "selftest")
    assert run("pkt", "encode", "hello") == b"0009hello"
    assert run("pkt", "decode", "0009hello") == b"hello"
    run("pkt", "decode", "000fshort", rc=1)
    (d / "packet").write_bytes(b"0009\x01data0000")
    run("pkt", "sideband", d / "packet", "-o", d / "pack")
    assert (d / "pack").read_bytes() == b"data"
    assert run("http", "parse-url", "https://example.test:8443/path") == (
        b"scheme=https host=example.test port=8443 path=/path\n")
    request = run("http", "request", "http://example.test/path", "-d", "abc")
    assert request.startswith(b"GET /path HTTP/1.1\r\nHost: example.test\r\n")
    assert b"Content-Length: 3\r\n" in request
    (d / "response").write_bytes(b"HTTP/1.1 200 OK\r\n\r\na\x00b")
    run("http", "response-body", d / "response", "-o", d / "body")
    assert (d / "body").read_bytes() == b"a\x00b"
    run("http", "response-body", d / "response", "-o", "/dev/full", rc=1)
    (d / "response").write_bytes(b"HTTP/1.1 200")
    run("http", "response-body", d / "response", "-o", d / "body", rc=1)
    duid = run("dhcp6", "duid-ll", "02:00:00:00:00:01").decode().strip()
    assert duid == "00030001020000000001"
    solicit = run("dhcp6", "build", "solicit", "-d", duid, "-x", "123456").decode().strip()
    assert solicit.startswith("01123456")
    run("dhcp6", "parse", solicit)
    (d / "dhcp.conf").write_text(
        "server-duid 00030001020000000002\npool-start 2001:db8::10\npool-size 4\n")
    reply = run("dhcpd6", "respond", solicit, "-c", d / "dhcp.conf", "-l", d / "leases").decode().strip()
    assert reply.startswith("02123456"), reply
    run("dhcp6", "parse", reply)
    run("dhcp6", "parse", "01", rc=1)
    assert run("audit", "typenum", "SYSCALL") == b"1300\n"
    assert run("audit", "typename", "1300") == b"SYSCALL\n"
    run("audit", "decode-text", "1300", "audit(1.000:2): syscall=1 success=yes", "-o", "-")
    for db in (d / "missing", d / "bans"):
        if db.name == "bans": db.write_text("127.0.0.1\ttest\t1\n")
        run("fail2ban", "format-status", db)
        run("fail2ban", "format-status", db, "test")
    run("fail2ban", "validate-jail", "bad/jail", rc=1)

    # Two stdout/stderr pipes must be drained together, even with a large
    # diagnostic emitted before the first stdout byte.
    helper = d / "ssh-fixture"
    helper.write_text(f"#!{sys.executable}\nimport os\nos.write(2, b'x'*200000)\nos.write(1, b'/tmp\\n')\n")
    helper.chmod(0o755)
    (d / "batch").write_text("quit\n")
    env = {**os.environ, "BASHSSH_OPENSSH_BIN": str(helper)}
    assert b"/tmp" in run("sftp", "--openssh", "-b", d / "batch", "example.test", env=env)
    run("eval", 'ulimit -n 7; before=(/proc/self/fd/*); '
        'for ((i=0;i<10;i++)); do sftp --openssh -b "$BASH_TEST_BATCH" example.test || :; done; '
        'after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]]',
        env={**env, "BASH_TEST_BATCH": str(d / "batch")})

    errors = []
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0)); server.listen(); server.settimeout(10)
        port = server.getsockname()[1]
        def echo():
            try:
                with server.accept()[0] as conn:
                    conn.settimeout(10)
                    while data := conn.recv(4096): conn.sendall(data)
            except Exception as e: errors.append(e)
        worker = threading.Thread(target=echo, daemon=True); worker.start()
        assert run("nc", "connect", "127.0.0.1", port, "-w", "5", data=b"loopback\n") == b"loopback\n"
        worker.join(10); assert not worker.is_alive() and not errors, errors

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0)); server.listen(); server.settimeout(10)
        port = server.getsockname()[1]
        def framed():
            try:
                for _ in range(3):
                    with server.accept()[0] as conn:
                        conn.settimeout(10)
                        with conn.makefile("rb") as stream:
                            assert stream.readline() == b"BASHSSH1\n"
                            length = int(stream.readline().split()[1])
                            stdin_length = int(stream.readline().split()[1])
                            assert stream.readline() == b"\n"
                            command = stream.read(length)
                            stream.read(stdin_length)
                            output = b"/tmp\n" if command == b"pwd" else b"file\x00bytes\n"
                            header = f"BASHSSH1-RESP\nrc 0\nstdout-len {len(output)}\nstderr-len 0\n\n".encode()
                            conn.sendall(header + output)
            except Exception as e: errors.append(e)
        worker = threading.Thread(target=framed, daemon=True); worker.start()
        (d / "batch").write_text(f"get remote {d / 'download'}\nquit\n")
        run("sftp", "--native", "-p", port, "-b", d / "batch", "127.0.0.1")
        assert (d / "download").read_bytes() == b"file\x00bytes\n"
        run("scp", "--native", "-P", port, "127.0.0.1:remote", d / "copy")
        assert (d / "copy").read_bytes() == b"file\x00bytes\n"
        worker.join(10); assert not worker.is_alive() and not errors, errors

print(f"network-smoke: {checks} checks passed")
