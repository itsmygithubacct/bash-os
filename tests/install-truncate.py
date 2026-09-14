#!/usr/bin/env python3
"""Check install's final file length, inode identity and partial-copy cleanup."""
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
import threading


binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = {**os.environ, 'LC_ALL': 'C'}
if env.get('COREUTILS_LOAD_ENV'):
    env['BASH_ENV'] = env['COREUTILS_LOAD_ENV']
checks = 0


def run(src, dst, *, limit=None, expected_status=0):
    global checks

    def set_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    p = subprocess.run(
        [binary, '-c', 'trap "" XFSZ; coreutils install -m 751 "$1" "$2"',
         '_', str(src), str(dst)], env=env, capture_output=True, timeout=20,
        preexec_fn=set_limit if limit is not None else None)
    assert p.returncode == expected_status, (src, dst, p.returncode, p.stderr)
    assert not p.stdout, p.stdout
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    checks += 1
    return p


def check_directory(root):
    src, dst = root / 'source', root / 'destination'
    old = b'previous destination\n' * 4096
    for length in [0, 1, 1023, len(old), len(old) + 1, 262147]:
        data = (bytes(range(256)) * ((length + 255) // 256))[:length]
        src.write_bytes(data)
        dst.write_bytes(old)
        dst.chmod(0o640)
        before = dst.stat()
        run(src, dst)
        after = dst.stat()
        assert dst.read_bytes() == data
        assert (after.st_dev, after.st_ino, after.st_uid, after.st_gid) == (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid)
        assert stat.S_IMODE(after.st_mode) == 0o751

    # Both kinds of destination alias continue to refer to the same inode.
    linked, symbolic = root / 'hardlink', root / 'symlink'
    os.link(dst, linked)
    symbolic.symlink_to(dst)
    for target in [linked, symbolic]:
        dst.write_bytes(old)
        src.write_bytes(b'short replacement\0\xff\n')
        before = dst.stat()
        run(src, target)
        assert symbolic.is_symlink()
        assert dst.stat().st_ino == linked.stat().st_ino == before.st_ino
        assert dst.read_bytes() == linked.read_bytes() == src.read_bytes()

    # Same-inode operands are refused before the destination is opened, so
    # the only copy of the data survives, whether spelled directly or reached
    # through either alias.
    for source in [dst, linked, symbolic]:
        dst.write_bytes(old)
        dst.chmod(0o640)
        p = run(source, dst, expected_status=1)
        assert b'are the same file' in p.stderr, p.stderr
        assert dst.read_bytes() == linked.read_bytes() == old
        assert stat.S_IMODE(dst.stat().st_mode) == 0o640

    for data in [b'', bytes(range(256)) * 513 + b'last']:
        src.write_bytes(data)
        dst.unlink()
        run(src, dst)
        assert dst.read_bytes() == data
        assert stat.S_IMODE(dst.stat().st_mode) == 0o751

    # A FIFO destination keeps stream copying and is never length-truncated.
    fifo = root / 'fifo'
    os.mkfifo(fifo)
    received, errors = [], []

    def receive():
        try:
            with fifo.open('rb') as stream:
                received.append(stream.read())
        except BaseException as error:
            errors.append(error)

    reader = threading.Thread(target=receive, daemon=True)
    reader.start()
    run(src, fifo)
    reader.join(timeout=2)
    assert not reader.is_alive() and not errors
    assert received == [src.read_bytes()] and stat.S_ISFIFO(fifo.stat().st_mode)

    # A normal file-size limit makes the copy fail after a successful prefix.
    # The old tail must disappear, and failure must precede chmod/chown.
    src.write_bytes(bytes(range(256)) * 1024)
    for existing in [False, True]:
        dst.unlink()
        if existing:
            dst.write_bytes(old)
            dst.chmod(0o640)
            before = dst.stat()
        p = run(src, dst, limit=1024, expected_status=1)
        assert b'install: write:' in p.stderr, p.stderr
        assert dst.read_bytes() == src.read_bytes()[:1024]
        expected_mode = 0o640 if existing else 0o600
        assert stat.S_IMODE(dst.stat().st_mode) == expected_mode
        if existing:
            assert dst.stat().st_ino == before.st_ino

# Kernel copying and truncation behave differently across filesystems, and the
# default temporary directory is often tmpfs. Repeat the checks beside the
# binary when that is a different filesystem.
filesystems = set()
for place in [Path(tempfile.gettempdir()), Path(binary).parent]:
    device = place.stat().st_dev
    if device in filesystems or not os.access(place, os.W_OK):
        continue
    filesystems.add(device)
    with tempfile.TemporaryDirectory(prefix='install-truncate-', dir=place) as tmp:
        check_directory(Path(tmp))

print(f'install-truncate: {checks} checks passed on {len(filesystems)} filesystems')
