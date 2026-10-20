#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Streaming/atomic-output regression tests; requires a built zstd,zstdcat shell.
No compilation or timing. The large case exceeds both former size caps under
an address-space limit; the fixture is sparse and all created files are private.
"""
import hashlib
import os
from pathlib import Path
import random
import resource
import shutil
import struct
import subprocess
import sys
import tempfile
import time

BINARY = str(Path(sys.argv[1]).resolve(strict=True))
REF = shutil.which('zstd')
assert REF, 'host zstd required (no skipped assertions)'
ENV = dict(PATH='', LC_ALL='C', TZ='UTC')
SCRIPT = 'PATH=; "$@"'
passed = 0


def check(condition, label):
    global passed
    assert condition, label
    passed += 1
    print('PASS', label, flush=True)


def run(*args, data=None, expected=0, **kwargs):
    p = subprocess.run([BINARY, '--noprofile', '--norc', '-c', SCRIPT, '_', 'zstd', *args],
                       input=data, capture_output=True, env=ENV, **kwargs)
    assert p.returncode == expected, (args, p.returncode, p.stderr)
    return p.stdout


def host(data, *args):
    p = subprocess.run([REF, '-q', *args], input=data, capture_output=True, check=True)
    return p.stdout


def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024**2), b''):
            h.update(b)
    return h.hexdigest()


def main():
    with tempfile.TemporaryDirectory(prefix='sol-zstd-check-') as directory:
        os.chdir(directory)
        data = random.Random(19).randbytes(400000)
        Path('input').write_bytes(data)
        unknown = host(data, '--no-content-size', '-c', '-')
        check(unknown[4] & 0xC0 == 0 and not unknown[4] & 0x20, 'reference fixture has unknown content size')
        Path('unknown.zst').write_bytes(unknown)
        skip = struct.pack('<II', 0x184D2A50, 7) + b'skipped'
        stream = host(b'', '-c', '-') + skip + unknown + unknown + skip
        check(run('-dc', '-', data=stream) == data * 2, 'concatenated unknown-size, empty, and skippable frames')
        check(run('-dc', '-', data=skip) == b'', 'skippable-only stream')
        for size in [131071, 131072, 131073, 262144]:
            edge = (b'chunk boundary\n' * (size // 15 + 1))[:size]
            frame = host(edge, '--no-content-size', '-c', '-')
            check(run('-dc', '-', data=frame) == edge and host(run('-c', '-', data=edge), '-dc', '-') == edge, f'input/output boundary {size} bytes')
        # A valid one-byte raw frame advertising a 256 MiB window. The host
        # explicitly permits it; the builtin must reject it within its bound.
        oversized = bytes.fromhex('28b52ffd0090090000') + b'A'
        check(host(oversized, '--long=28', '-dc', '-') == b'A', 'host validates oversized-window fixture')
        run('-dc', '-', data=oversized, expected=1)
        check(True, 'decoder enforces the 128 MiB window bound')
        Path('dest').write_bytes(b'keep existing')
        for broken in [b'', unknown[:1], unknown[:-1], unknown+unknown[:-1], unknown+b'junk', skip[:-1]]:
            Path('broken.zst').write_bytes(broken)
            run('-df', '--rm', '-o', 'dest', 'broken.zst', expected=1)
            check(Path('broken.zst').read_bytes() == broken and Path('dest').read_bytes() == b'keep existing'
                  and not list(Path('.').glob('*.tmp.*')), 'truncation/garbage keeps old target and source')
            run('-d', '-o', 'absent', 'broken.zst', expected=1)
            check(not Path('absent').exists() and not list(Path('.').glob('*.tmp.*')), 'failed decode never publishes a new target')
        run('-o', 'stdin.zst', '-', data=data)
        check(host(Path('stdin.zst').read_bytes(), '-dc', '-') == data, 'stdin supports a named destination')
        check(host(run('-o', '-', 'input'), '-dc', '-') == data, '-o - writes stdout')
        os.link('input', 'alias')
        run('-f', '--rm', '-o', 'alias', 'input', expected=1)
        check(Path('alias').read_bytes() == data and Path('input').exists(), 'same-inode destination rejected before --rm')
        os.symlink('dest', 'symlink')
        run('-f', '-o', 'symlink', 'input', expected=1)
        check(Path('symlink').is_symlink() and Path('dest').read_bytes() == b'keep existing', 'forced symlink target is refused safely')
        with open('/dev/full', 'wb') as full:
            p = subprocess.run([BINARY, '-c', 'PATH=; zstd --rm -c input; rc=$?; [[ -f input ]] || exit 9; exit "$rc"'], env=ENV, stdout=full, stderr=subprocess.PIPE)
        check(p.returncode == 1 and b'write' in p.stderr, 'stdout ENOSPC reports failure and keeps --rm input')
        script = 'PATH=; for ((i=0;i<30;i++)); do zstd -f -o repeat.zst input || exit; zstd -df -o repeat.back repeat.zst || exit; zstd -dc broken.zst >/dev/null 2>/dev/null; rc=$?; [[ $rc == 1 ]] || exit 9; done'
        p = subprocess.run([BINARY, '-c', script], env=ENV, capture_output=True)
        check(p.returncode == 0 and Path('repeat.back').read_bytes() == data, '30 repeated success/error calls in one empty-PATH shell')
        # Prove output starts before EOF and named publication waits for EOF.
        noise = random.Random(21).randbytes(2 * 1024**2)
        p = subprocess.Popen([BINARY, '-c', 'PATH=; zstd -1 -c -'], env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Drain stdout concurrently while feeding input, keeping the input open.
        import threading
        chunks = []
        def drain():
            while True:
                b = p.stdout.read(65536)
                if not b:
                    break
                chunks.append(b)
        reader = threading.Thread(target=drain)
        reader.start()
        p.stdin.write(noise); p.stdin.flush()
        deadline = time.monotonic() + 10
        while not chunks and time.monotonic() < deadline:
            time.sleep(.01)
        check(bool(chunks) and p.poll() is None, 'compression emits bytes before input EOF')
        p.stdin.close(); p.wait(timeout=20); reader.join(timeout=20)
        check(p.returncode == 0 and host(b''.join(chunks), '-dc', '-') == noise, 'incremental stdout frame round-trips')
        p = subprocess.Popen([BINARY, '-c', 'PATH=; zstd -1 -f -o dest -'], env=ENV, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdin.write(noise); p.stdin.flush()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            temps = list(Path('.').glob('dest.tmp.*'))
            if temps and temps[0].stat().st_size:
                break
            time.sleep(.01)
        check(bool(temps) and temps[0].stat().st_size > 0 and p.poll() is None and Path('dest').read_bytes() == b'keep existing', 'old destination remains visible during incremental writes')
        p.stdin.close(); p.wait(timeout=20)
        check(p.returncode == 0 and host(Path('dest').read_bytes(), '-dc', '-') == noise and not list(Path('.').glob('*.tmp.*')), 'EOF commits a complete frame and removes temporary')
        # 1 GiB + 123 bytes crosses both the old 256 MiB input and 1 GiB output caps.
        size = 1024**3 + 123
        with open('large', 'wb') as f:
            f.truncate(size)
        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (192 * 1024**2, 192 * 1024**2))
        run('-1', '-o', 'large.zst', 'large', preexec_fn=limit, timeout=90)
        run('-d', '-o', 'large.back', 'large.zst', preexec_fn=limit, timeout=90)
        check(Path('large.back').stat().st_size == size and hash_file('large') == hash_file('large.back'), 'named >1 GiB round-trip under 192 MiB address-space limit')
        # Host independently validates the large frame without materializing its output.
        with open(os.devnull, 'wb') as null:
            p = subprocess.run([REF, '-q', '-dc', 'large.zst'], stdout=null, stderr=subprocess.PIPE)
        check(p.returncode == 0, 'host decodes the large streaming frame')
        with open('large', 'rb') as source, open('large-stdin.zst', 'wb') as output:
            p = subprocess.run([BINARY, '-c', 'PATH=; zstd -1 -c -'], env=ENV, stdin=source, stdout=output, stderr=subprocess.PIPE, preexec_fn=limit, timeout=90)
        check(p.returncode == 0, 'stdin >1 GiB compresses under 192 MiB address-space limit')
        Path('large.back').unlink()
        run('-d', '--rm', '-o', 'large.back', 'large-stdin.zst', preexec_fn=limit, timeout=90)
        check(not Path('large-stdin.zst').exists() and hash_file('large.back') == hash_file('large'), 'large streaming decode publishes then removes source')
        print(f'sol-zstd-check: {passed} passed, no skips')


if __name__ == '__main__':
    main()
