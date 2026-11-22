#!/usr/bin/env python3
"""Compare low-level blkid output and status on disposable regular-file images."""
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

shell = str(Path(sys.argv[1]).resolve())
tool_path = '/usr/sbin:/sbin:/usr/bin:/bin'
oracle = shutil.which('blkid', path=tool_path)
mkfs = shutil.which('mkfs.ext4', path=tool_path)
if not oracle or not mkfs:
    sys.exit('blkid-probe needs util-linux blkid and e2fsprogs mkfs.ext4')
env = {**os.environ, 'LC_ALL': 'C', 'PATH': tool_path}
version = subprocess.check_output([oracle, '--version'], env=env, text=True)
major, minor = map(int, re.search(r'(\d+)\.(\d+)', version).groups())
checks = 0


def compare(*args, status=0, exact_error=True):
    global checks
    candidate = [shell, '--noprofile', '--norc', '-c', 'PATH=; builtin blkid "$@"', 'blkid']
    ref, actual = [subprocess.run([*cmd, *args], capture_output=True, cwd=directory,
                                  env=env, timeout=10) for cmd in ([oracle], candidate)]
    assert ref.returncode == status, ('reference', args, ref.returncode, ref.stderr)
    assert actual.returncode == status, (args, actual.returncode, actual.stderr)
    assert actual.stdout == ref.stdout, (args, actual.stdout, ref.stdout)
    if exact_error:
        assert actual.stderr == ref.stderr, (args, actual.stderr, ref.stderr)
    else:
        assert bool(actual.stderr) == bool(ref.stderr), (args, actual.stderr, ref.stderr)
    checks += 1


with tempfile.TemporaryDirectory() as tmp:
    directory = Path(tmp)
    fs = directory/'ext.img'
    size = 8 * 1024 * 1024
    with fs.open('wb') as f:
        f.truncate(size)
    subprocess.run([mkfs, '-qF', '-b', '1024', '-L', 'lab el&x',
                    '-U', '12345678-1234-4abc-8def-123456789012', fs], check=True, env=env)
    with (directory/'blank').open('wb') as f:
        f.truncate(size)
    with (directory/'offset').open('wb') as f, fs.open('rb') as content:
        f.seek(1024 * 1024)
        shutil.copyfileobj(content, f)
    with (directory/'mbr').open('wb') as f:
        f.truncate(size)
        f.seek(440)
        f.write(struct.pack('<I', 0x13572468))
        f.seek(446)
        f.write(struct.pack('<B3xB3xII', 0, 0x83, 2048, 8192))
        f.seek(510)
        f.write(b'\x55\xaa')
    # A primary ISO 9660 descriptor lives at sector 16, outside the ext superblock.
    collision = directory/'collision'
    shutil.copyfile(fs, collision)
    with collision.open('r+b') as f:
        f.seek(16 * 2048)
        descriptor = bytearray(2048)
        descriptor[:7] = b'\x01CD001\x01'
        descriptor[40:72] = b'TEST'.ljust(32)
        descriptor[80:88] = struct.pack('<I', size // 2048) + struct.pack('>I', size // 2048)
        descriptor[128:132] = struct.pack('<H', 2048) + struct.pack('>H', 2048)
        f.write(descriptor)
        f.write(b'\xffCD001\x01')

    # FS size tags were added in util-linux 2.41. Compare older tools on shared tags.
    shared = ('-s', 'TYPE', '-s', 'LABEL', '-s', 'UUID', '-s', 'VERSION', '-s', 'USAGE')
    formats = ['full', 'value', 'export', 'udev', 'device']
    help_output = subprocess.check_output([oracle, '--help'], env=env)
    if b'json' in help_output:
        formats.append('json')
    for fmt in formats:
        compare('-p', '-o', fmt, *shared, 'ext.img')
        if (major, minor) >= (2, 41):
            compare('--probe', '--output='+fmt, 'ext.img', 'ext.img')
    for args in [('-p', '-d', '-o', 'export', '-s', 'LABEL', 'ext.img'),
                 ('-p', '-s', 'ABSENT', 'ext.img'),
                 ('ext.img', '--probe', '-ovalue', '-sTYPE'),
                 ('-p', '-o', 'value', '-s', 'TYPE', 'missing', 'ext.img'),
                 ('-p', '-n', 'ext4,xfs', '-sTYPE', 'ext.img'),
                 ('-p', '-u', 'filesystem', '-sUSAGE', 'ext.img'),
                 ('-p', '-u', 'noraid,crypto', '-sTYPE', 'ext.img'),
                 ('-p', '-O1MiB', '-S8MiB', '-sTYPE', 'offset'),
                 ('-p', '-O', '1048576', '-sUUID', 'offset'),
                 ('-pD', '-o', 'export', 'mbr'),
                 ('-p', '-n', 'iso9660', '-sTYPE', 'collision'),
                 ('-p', '-n', 'ext4', '-sTYPE', 'collision')]:
        compare(*args)
    for args in [('-p', 'blank'), ('-p', 'missing'), ('-p', 'blank', 'ext.img'),
                 ('-p', '-n', 'noext4', 'ext.img'), ('-p', '-u', 'raid', 'ext.img'),
                 ('-p', '-O1MiB', '-S512', 'offset')]:
        compare(*args, status=2)
    # Several util-linux releases turn the internal ambiguous result into a
    # generic probe failure. Check the documented exit independently on those.
    for opts, expected in [((), b''), (('-o', 'udev'), b'ID_FS_AMBIVALENT=filesystem:ext4:1.0 filesystem:iso9660\n')]:
        args = ['-p', *opts, 'collision']
        ref = subprocess.run([oracle, *args], capture_output=True, env=env, cwd=directory)
        if ref.returncode == 8:
            compare(*args, status=8)
        else:
            assert ref.returncode == 2 and not ref.stdout and not ref.stderr, (args, ref)
            result = subprocess.run([shell, '-c', 'PATH=; builtin blkid "$@"', 'blkid', *args],
                                    capture_output=True, env=env, cwd=directory, timeout=10)
            assert result.returncode == 8 and result.stdout == expected, (args, result)
            assert (not result.stderr if opts else b'ambivalent result' in result.stderr)
            checks += 1
    for args in [('-p', '--unknown'), ('-p', '-O'), ('-p', '--probe=yes', 'ext.img')]:
        compare(*args, status=1, exact_error=False)
    for args in [('-p',), ('-p', '-o', 'list', 'ext.img'), ('-p', '-O', 'bad', 'ext.img')]:
        compare(*args, status=4, exact_error=False)

    conflict = ['-p', '-n', 'ext4', '-u', 'filesystem', 'ext.img']
    if (major, minor) >= (2, 41):
        compare(*conflict, status=4, exact_error=False)
    else:
        # Older util-linux CLIs can abort within their diagnostic formatter.
        result = subprocess.run([shell, '-c', 'PATH=; builtin blkid "$@"', 'blkid', *conflict],
                                capture_output=True, env=env, cwd=directory, timeout=10)
        assert result.returncode == 4 and not result.stdout and result.stderr, result
        checks += 1

print(f'blkid-probe: {checks} comparisons passed against {version.splitlines()[0]}')
