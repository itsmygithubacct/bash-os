#!/usr/bin/env python3
"""Live page/row delivery, page-range termination and bounded input storage."""
import errno
import hashlib
import os
from pathlib import Path
import pty
import resource
import select
import subprocess
import sys
import tempfile
import termios

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = 'if [[ -n ${PR_MODULE:-} ]]; then enable -f "$PR_MODULE" pr || exit; fi\n'
checks = 0


def live(opts, data, terminal=False, finish=False):
    global checks
    want = subprocess.run(['/usr/bin/pr', *opts], input=data, capture_output=True, env=env, check=True).stdout
    master = slave = None
    if terminal:
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[1] &= ~termios.OPOST
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
    proc = subprocess.Popen([binary, '-c', prefix+'pr "$@"', '_', *opts], stdin=subprocess.PIPE,
                            stdout=slave if terminal else subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if slave is not None: os.close(slave)
    try:
        proc.stdin.write(data); proc.stdin.flush()
        fd = master if terminal else proc.stdout.fileno()
        got = b''
        while len(got) < len(want):
            assert select.select([fd], [], [], 10)[0], (opts, 'delivery waited for EOF', got, want)
            chunk = os.read(fd, 65536)
            assert chunk, (opts, 'early EOF', got, want)
            got += chunk
        assert got == want, (opts, got, want)
        if finish: assert proc.wait(timeout=10) == 0
        else: assert proc.poll() is None, (opts, 'exited before input closed')
        proc.stdin.close(); proc.stdin = None
        assert proc.wait(timeout=10) == 0
        assert not proc.stderr.read()
        if terminal:
            try:
                tail = os.read(master, 65536)
            except OSError as error:
                assert error.errno == errno.EIO, error
                tail = b''
        else:
            tail = proc.stdout.read()
        assert not tail, (opts, 'extra output after EOF', tail)
        checks += 1
    finally:
        if proc.stdin: proc.stdin.close()
        if proc.poll() is None: proc.kill(); proc.wait()
        proc.stderr.close()
        if proc.stdout: proc.stdout.close()
        if master is not None: os.close(master)


# Complete pages must arrive through pipes without waiting for another byte.
for mode in ([], ['-a']):
    live(['-t', '-l2', '-2', *mode], b'a\nb\nc\nd\n')
    live(['-t', '-l2', '-2', *mode, '+1:1'], b'a\nb\nc\nd\n', finish=True)
    live(['-t', '-l2', '-2', *mode, '+2:2'], b'a\nb\nc\nd\ne\nf\ng\nh\n', finish=True)
    live(['-t', '-l2', '-2', *mode], b'a\fb\f')
# Across mode can deliver a row to a terminal before a whole page exists.
live(['-t', '-l20', '-a', '-2'], b'a\nb\n', terminal=True)
live(['-t', '-l2', '-m', '-', '-'], b'a\nb\nc\nd\n')
live(['-t', '-l2', '-m', '-', '-', '+1:1'], b'a\nb\nc\nd\n', finish=True)
live(['-t', '-m', '-', '-'], b'a\fb\f')

# A deterministic address-space ceiling rejects whole-input accumulation.
# ASan reserves a huge virtual shadow; run this native-only assertion separately.
if not os.environ.get('PR_SKIP_ADDRESS_LIMIT'):
    with tempfile.TemporaryDirectory(prefix='pr-bounded-') as d:
        root = Path(d); src = root/'input'; src.write_bytes(b'x\n' * 2_000_000)
        def ceiling(): resource.setrlimit(resource.RLIMIT_AS, (64*1024**2, 64*1024**2))
        def digest(path):
            with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
        for mode in ([], ['-a']):
            opts = ['-t', '-3', '-s,', *mode, str(src)]
            with (root/'gnu').open('wb') as out:
                subprocess.run(['/usr/bin/pr', *opts], stdout=out, stderr=subprocess.PIPE, env=env, check=True)
            with (root/'actual').open('wb') as out:
                got = subprocess.run([binary, '-c', prefix+'pr "$@"', '_', *opts], stdout=out,
                                     stderr=subprocess.PIPE, env=env, preexec_fn=ceiling, timeout=90)
            assert got.returncode == 0 and not got.stderr, (opts, got.returncode, got.stderr)
            assert digest(root/'actual') == digest(root/'gnu'), opts
            checks += 1
label = 'live-delivery/range' if os.environ.get('PR_SKIP_ADDRESS_LIMIT') else 'live-delivery/range/storage'
print(f'pr-stream: {checks} {label} checks passed')
if os.environ.get('PR_SKIP_ADDRESS_LIMIT'):
    print('Address-space ceiling is qualified by the separate native run, not this sanitizer run.')
