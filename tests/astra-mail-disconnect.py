#!/usr/bin/env python3
"""A closed SMTP peer must fail the call while preserving its parent shell."""
import importlib.util
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('sol-mail-check.py'))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='mail-disconnect-') as tmp, f.Shell(binary) as shell:
    root = Path(tmp)
    qid = f.submit(shell, root, b'Subject: disconnect\n\nprivate test\n')
    before = f.check_entry(root/'queue', qid, b'Subject: disconnect\n\nprivate test\n')
    client, peer = socket.socketpair()
    try:
        peer.sendall(b'220 fixture ready\r\n')
        peer.shutdown(socket.SHUT_RD)
        script = f.words('mail', 'deliver-fd', '--fd', client.fileno(), '--from', f.FROM,
                         '--qid', qid, '--queue', root/'queue', '--tls', 'off', '--', *f.RCPTS)
        script += '; status=$?; printf "survived:%s\\n" "$status"; [[ $status == 75 ]]'
        env = dict(os.environ, PATH='', LC_ALL='C')
        p = subprocess.run([str(binary), '--noprofile', '--norc', '-c', script],
                           pass_fds=(client.fileno(),), capture_output=True, env=env, timeout=10)
        print('closed peer:', p.returncode, p.stdout, p.stderr, flush=True)
        assert p.returncode == 0 and p.stdout == b'survived:75\n'
    finally:
        client.close(); peer.close()
    assert f.check_entry(root/'queue', qid, b'Subject: disconnect\n\nprivate test\n') == before
print('PASS closed peer returns temporary failure without killing shell or changing queue')
