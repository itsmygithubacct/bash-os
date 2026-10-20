#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strict UTF-8 oracle and incremental delivery checks; no compiler required."""
import argparse
import os
from pathlib import Path
import pty
import random
import select
import subprocess
import tempfile
import termios
import unicodedata


def oracle(data, width=40, mode='columns', spaces=False, loc='C.UTF-8'):
    # Python's strict UTF-8 codec with surrogateescape preserves each rejected
    # byte separately. This is independent of the production decoder.
    text = ''.join(map(chr, data)) if mode == 'bytes' else data.decode('utf-8', 'surrogateescape')

    def advance(column, last, char):
        if mode == 'bytes':
            return column + 1, 1
        if char == '\b':
            return max(0, column - last), last
        if char == '\r':
            return 0, last
        if char == '\t':
            return (column // 8 + 1) * 8, last
        if mode == 'characters':
            size = 1
        elif char == '\0':
            size = 0
        elif loc == 'C' or 0xDC80 <= ord(char) <= 0xDCFF:
            size = 1
        elif unicodedata.category(char) in ('Mn', 'Me', 'Cf'):
            size = 0
        elif unicodedata.category(char).startswith('C'):
            size = 1
        else:
            size = 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
        return column + size, size

    output, pending = [], []
    column, last = 0, 1
    for char in text:
        if char == '\n':
            output.extend(pending + ['\n'])
            pending, column, last = [], 0, 1
            continue
        new_column, new_last = advance(column, last, char)
        while pending and new_column > width:
            cut = len(pending)
            if spaces:
                blanks = [i + 1 for i, c in enumerate(pending) if c in ' \t']
                if blanks:
                    cut = blanks[-1]
            output.extend(pending[:cut] + ['\n'])
            pending = pending[cut:]
            column, last = 0, 1
            for old in pending:
                column, last = advance(column, last, old)
            new_column, new_last = advance(column, last, char)
        pending.append(char)
        column, last = new_column, new_last
    output.extend(pending)
    text = ''.join(output)
    return bytes(map(ord, text)) if mode == 'bytes' else text.encode('utf-8', 'surrogateescape')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--only', choices=['oracle', 'stream', 'all'], default='all')
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    env = dict(os.environ, PATH='', LC_ALL='C.UTF-8')
    for key in ('BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS'):
        env.pop(key, None)
    prefix = 'if [[ -n ${FOLD_MODULE:-} ]]; then enable -f "$FOLD_MODULE" fold || exit; fi; '
    checks = 0
    if args.only != 'stream':
        rng = random.Random(20261019)
        malformed = [b'\xc0\x80', b'\xc0\x88', b'\xc0\x89', b'\xc0\x8a', b'\xc0\x8d',
                     b'\xc0\xa0', b'\xc1\xbf', b'\xe0\x80\x80', b'\xed\xa0\x80',
                     b'\xed\xbf\xbf', b'\xf0\x80\x80\x80', b'\xf4\x90\x80\x80',
                     b'\xf5\x80\x80\x80', b'\xf7\xbf\xbf\xbf', b'\xff', b'\x80',
                     b'\xc2', b'\xe2\x82', b'\xf0\x9f\x98', b'\xe2X\x82']
        valid = ['é', '界', '\u0301', '😀', '\u0080', '\u07ff', '\u0800', '\ud7ff',
                 '\ue000', '\uffff', '\U00010000', '\U0010ffff']
        fixtures = [b'A' + part + b'B\n' for part in malformed]
        fixtures += [(v + 'e\u0301界\bZ\tQ\rX\0\n').encode() for v in valid]
        fixtures += ['界\u0301Z\n'.encode(), 'e\u0301\bXYZ\n'.encode(), 'ab\u00a0cd ef\n'.encode()]
        alphabet = [b'a', b' ', b'\t', b'\b', b'\r', b'\n', b'\0',
                    'é'.encode(), '界'.encode(), '\u0301'.encode(), '😀'.encode(), *malformed]
        fixtures += [b''.join(rng.choice(alphabet) for _ in range(150)) for _ in range(24)]
        fixtures += [bytes(range(256)) * 3]
        # Every position near the 8 KiB boundary, including malformed prefixes.
        fixtures += [b'a' * n + part + b'Z\n' for n in range(8188, 8194)
                     for part in [b'\xf0\x9f\x98\x80', b'\xe2\x82\xac', b'\xed\xa0\x80', b'\xe2X']]
        with tempfile.TemporaryDirectory(prefix='sol-fold-') as tmp:
            source = Path(tmp) / 'in'
            for loc in ['C', 'C.UTF-8']:
                for mode, flag in [('bytes', '-b'), ('characters', '-c'), ('columns', '')]:
                    for spaces in [False, True]:
                        for width in [1, 3, 8, 40]:
                            # Batch all fixtures in one shell, exercising state reset
                            # on distinct redirected inputs as well as one-off decoding.
                            paths, expected = [], []
                            for i, data in enumerate(fixtures):
                                path = source.with_name(str(i))
                                path.write_bytes(data)
                                paths.append(str(path))
                                expected.append(oracle(data, width, mode, spaces, loc))
                            flags = [flag] if flag else []
                            flags += ['-s'] if spaces else []
                            command = ['fold', *flags, '-w', str(width)]
                            body = 'for file; do ' + ' '.join(command) + ' < "$file" || exit; done'
                            proc = subprocess.run([binary, '-c', prefix + body, '_', *paths],
                                                  env=dict(env, LC_ALL=loc), capture_output=True, timeout=30)
                            assert proc.returncode == 0 and not proc.stderr, (loc, command, proc.stderr)
                            assert proc.stdout == b''.join(expected), (loc, command, 'oracle mismatch')
                            checks += len(fixtures)
        pairs = b''.join(bytes([a, b]) + b'X\n' for a in range(256) for b in range(256))
        for loc in ['C', 'C.UTF-8']:
            proc = subprocess.run([binary, '-c', prefix + 'fold -c -w1'], input=pairs,
                                  env=dict(env, LC_ALL=loc), capture_output=True, timeout=30)
            assert proc.returncode == 0 and not proc.stderr, proc.stderr
            assert proc.stdout == oracle(pairs, 1, 'characters', loc=loc), (loc, 'two-byte matrix')
            checks += 65536
        # Canonical encodings of every non-ASCII Unicode scalar: strictness
        # must not accidentally reject valid encodings. Expected unit breaks
        # come directly from scalar enumeration, independently of decoding.
        scalars = [chr(cp).encode() for cp in range(0x80, 0x110000)
                   if not 0xD800 <= cp <= 0xDFFF]
        data, expected = b''.join(scalars), b'\n'.join(scalars)
        for loc in ['C', 'C.UTF-8']:
            proc = subprocess.run([binary, '-c', prefix + 'fold -c -w1'], input=data,
                                  env=dict(env, LC_ALL=loc), capture_output=True, timeout=30)
            assert proc.returncode == 0 and not proc.stderr, proc.stderr
            assert proc.stdout == expected, (loc, 'canonical scalar enumeration')
            checks += 1
    if args.only != 'oracle':
        # These are correctness deadlines, not latency measurements. Keep the
        # producer open until each complete result arrives; no extra padding.
        for terminal in [False, True]:
            for flag in ['', '-b', '-c', '-s', '-bs', '-cs']:
                master, slave = pty.openpty() if terminal else (None, None)
                if terminal:
                    settings = termios.tcgetattr(slave)
                    settings[1] &= ~termios.ONLCR
                    termios.tcsetattr(slave, termios.TCSANOW, settings)
                proc = subprocess.Popen([binary, '-c', prefix + f'fold {flag} -w3'],
                                        env=env, stdin=subprocess.PIPE,
                                        stdout=slave if terminal else subprocess.PIPE, stderr=subprocess.PIPE)
                fd = master if terminal else proc.stdout.fileno()

                def receive(expected):
                    data = b''
                    while len(data) < len(expected):
                        assert select.select([fd], [], [], 3)[0], (terminal, flag, 'waited for unrelated input', data, expected)
                        chunk = os.read(fd, len(expected) - len(data))
                        assert chunk, ('early EOF', data)
                        data += chunk
                    assert data == expected, (terminal, flag, data, expected)

                try:
                    for payload in [b'a\n', b'\n', b'ab\n', b'abcde\n', b'\xff\n',
                                    b'\xe0\x80\x80\n', b'\xed\xa0\x80\n', b'\xe2X\n']:
                        proc.stdin.write(payload); proc.stdin.flush()
                        mode = 'bytes' if 'b' in flag else 'characters' if 'c' in flag else 'columns'
                        receive(oracle(payload, 3, mode, 's' in flag))
                        checks += 1
                    proc.stdin.write(b'abcd'); proc.stdin.flush()
                    receive(b'abc\n')
                    proc.stdin.write(b'\n'); proc.stdin.flush()
                    receive(b'd\n')
                    checks += 1
                    # A genuine split sequence must wait only for its own
                    # continuation bytes, then deliver the complete line.
                    for char in ['é', '界', '😀', '\u0301']:
                        encoded = char.encode()
                        for split in range(1, len(encoded)):
                            proc.stdin.write(b'A\n' + encoded[:split]); proc.stdin.flush()
                            receive(b'A\n')
                            proc.stdin.write(encoded[split:] + b'Z\n'); proc.stdin.flush()
                            receive(oracle(encoded + b'Z\n', 3, mode, 's' in flag))
                            checks += 1
                    proc.stdin.write(b'\xe2\x82'); proc.stdin.flush()
                    proc.stdin.close()
                    receive(b'\xe2\x82')
                    assert proc.wait(timeout=3) == 0 and not proc.stderr.read()
                    checks += 1
                finally:
                    if proc.poll() is None:
                        proc.kill(); proc.wait()
                    if terminal:
                        os.close(master); os.close(slave)
        # Canonical terminal input must deliver a short line too. The private
        # PTY belongs to this test; VEOF terminates the open input cleanly.
        master, slave = pty.openpty()
        proc = subprocess.Popen([binary, '-c', prefix + 'fold -w3'], env=env,
                                stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            os.write(master, b'a\n')
            assert select.select([proc.stdout], [], [], 3)[0], 'short terminal input blocked'
            assert os.read(proc.stdout.fileno(), 2) == b'a\n'
            os.write(master, b'\x04')
            assert proc.wait(timeout=3) == 0 and not proc.stderr.read()
            checks += 1
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait()
            os.close(master); os.close(slave)
    print(f'sol-fold: {checks} independent-oracle cases and open-producer checks passed')


if __name__ == '__main__':
    main()
