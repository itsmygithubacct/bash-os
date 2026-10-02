#!/usr/bin/env python3
"""Check install's final file length, inode identity and partial-copy cleanup."""
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile


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
        with dst.open('rb') as previous:
            before = os.fstat(previous.fileno())
            run(src, dst)
            after = dst.stat()
            assert after.st_ino != before.st_ino
            assert previous.read() == old
        assert dst.read_bytes() == data
        assert (after.st_dev, after.st_uid, after.st_gid) == (
            before.st_dev, before.st_uid, before.st_gid)
        assert stat.S_IMODE(after.st_mode) == 0o751

    # Installing over either kind of alias replaces only that directory entry.
    linked, symbolic = root / 'hardlink', root / 'symlink'
    def reset_aliases():
        linked.unlink(missing_ok=True)
        symbolic.unlink(missing_ok=True)
        dst.write_bytes(old)
        os.link(dst, linked)
        symbolic.symlink_to(dst)

    for target in [linked, symbolic]:
        reset_aliases()
        src.write_bytes(b'short replacement\0\xff\n')
        run(src, target)
        assert not target.is_symlink()
        assert not os.path.samefile(dst, target)
        assert dst.read_bytes() == old
        assert target.read_bytes() == src.read_bytes()

    # Operands that are one file follow GNU install. The same directory entry,
    # however it is spelled, and a source that is a symbolic link to the
    # destination are refused, and the data survives.
    for source, target in [(dst, dst), (dst, f'{root}/./destination'), (symbolic, dst)]:
        reset_aliases()
        dst.chmod(0o640)
        p = run(source, target, expected_status=1)
        assert b'are the same file' in p.stderr, p.stderr
        assert dst.read_bytes() == linked.read_bytes() == old
        assert stat.S_IMODE(dst.stat().st_mode) == 0o640

    # A destination that is another hard link or a symbolic link to the source
    # is removed and a fresh file takes its name; the source is untouched.
    for alias in [linked, symbolic]:
        reset_aliases()
        dst.chmod(0o640)
        run(dst, alias)
        assert not alias.is_symlink() and alias.stat().st_ino != dst.stat().st_ino
        assert alias.read_bytes() == dst.read_bytes() == old
        assert stat.S_IMODE(alias.stat().st_mode) == 0o751
        assert stat.S_IMODE(dst.stat().st_mode) == 0o640

    for data in [b'', bytes(range(256)) * 513 + b'last']:
        src.write_bytes(data)
        dst.unlink()
        run(src, dst)
        assert dst.read_bytes() == data
        assert stat.S_IMODE(dst.stat().st_mode) == 0o751

    # GNU install replaces a FIFO destination with an ordinary file too.
    fifo = root / 'fifo'
    os.mkfifo(fifo)
    run(src, fifo)
    assert stat.S_ISREG(fifo.stat().st_mode)
    assert fifo.read_bytes() == src.read_bytes()

    # A normal file-size limit makes the copy fail after a successful prefix.
    # The old tail must disappear, and failure must precede chmod/chown.
    src.write_bytes(bytes(range(256)) * 1024)
    for existing in [False, True]:
        dst.unlink()
        if existing:
            dst.write_bytes(old)
            dst.chmod(0o640)
        p = run(src, dst, limit=1024, expected_status=1)
        assert b'install: write:' in p.stderr, p.stderr
        assert dst.read_bytes() == src.read_bytes()[:1024]
        assert stat.S_IMODE(dst.stat().st_mode) == 0o600

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
