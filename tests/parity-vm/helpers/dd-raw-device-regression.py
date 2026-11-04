#!/usr/bin/env python3
"""Disposable root VM only: private loop-device dd regression, one side per run.

Usage: python3 dd-raw-device-regression.py candidate /path/to/bash
       python3 dd-raw-device-regression.py reference /usr/bin/dd
The caller must provide a guest with loop-control, free loop devices, and
util-linux losetup. Missing prerequisites are errors, never passes.
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def run(argv, **kw):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('candidate', 'reference'):
        raise SystemExit(__doc__)
    side, executable = sys.argv[1:]
    if os.geteuid() != 0:
        raise RuntimeError('root disposable VM required')
    with tempfile.TemporaryDirectory(prefix='dd-raw-' + side + '-') as tmp:
        root = Path(tmp)
        image = root / 'image'
        seed = bytes((i * 37 + 11) % 256 for i in range(3072))
        image.write_bytes(seed)
        attach = run(['losetup', '--find', '--show', '--nooverlap', str(image)])
        if attach.returncode:
            raise RuntimeError('loop setup failed: ' + attach.stderr.decode(errors='replace'))
        device = attach.stdout.decode().strip()
        if not re.fullmatch(r'/dev/loop[0-9]+', device):
            raise RuntimeError('unexpected loop device: ' + repr(device))
        try:
            def dd(*args):
                if side == 'candidate':
                    command = [executable, '--noprofile', '--norc', '-c',
                               '[[ $(type -t dd) == builtin ]] || exit 99; dd "$@"',
                               'dd-test', *args]
                else:
                    command = [executable, *args]
                return run(command, env={**os.environ, 'LC_ALL': 'C'})

            def records(result, expected, code):
                assert result.returncode == code, (result.returncode, result.stderr)
                lines = result.stderr.decode(errors='replace').splitlines()
                actual = [line for line in lines if re.fullmatch(r'\d+\+\d+ records (in|out)', line)]
                assert actual == expected, (actual, result.stderr)

            out = root / 'read'
            result = dd('if=' + device, 'of=' + str(out), 'bs=512', 'skip=1',
                        'count=3', 'status=noxfer')
            records(result, ['3+0 records in', '3+0 records out'], 0)
            assert out.read_bytes() == seed[512:2048]

            payload = bytes((255 - i) % 256 for i in range(1024))
            source = root / 'source'
            source.write_bytes(payload)
            result = dd('if=' + str(source), 'of=' + device, 'bs=512', 'seek=2',
                        'count=2', 'conv=notrunc', 'status=noxfer')
            records(result, ['2+0 records in', '2+0 records out'], 0)
            expected = seed[:1024] + payload + seed[2048:]
            assert image.read_bytes() == expected

            source.write_bytes(b'Z' * 2048)
            result = dd('if=' + str(source), 'of=' + device, 'bs=2048', 'seek=1',
                        'conv=notrunc')
            records(result, ['1+0 records in', '0+1 records out'], 1)
            assert b'No space left on device' in result.stderr, result.stderr
            assert re.search(rb'\b1024 bytes \(', result.stderr), result.stderr
            expected = expected[:2048] + b'Z' * 1024
            assert image.read_bytes() == expected

            result = dd('if=' + device, 'of=' + str(out), 'bs=1024', 'skip=2',
                        'count=2', 'status=noxfer')
            records(result, ['1+0 records in', '1+0 records out'], 0)
            assert out.read_bytes() == expected[2048:]
        finally:
            detached = run(['losetup', '--detach', device])
            if detached.returncode:
                raise RuntimeError('loop detach failed: ' + detached.stderr.decode(errors='replace'))
            # Query by backing file; no association may survive cleanup.
            check = run(['losetup', '--associated', str(image), '--noheadings'])
            if check.returncode or check.stdout.strip():
                raise RuntimeError('loop association remains or cannot be checked: ' + repr(check.stdout + check.stderr))
    print('PASS dd-raw-device-regression ' + side)


if __name__ == '__main__':
    main()
