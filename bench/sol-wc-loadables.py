#!/usr/bin/env python3
"""Run unchanged loadables.py with an independent oracle on every timed wc pass.

All regular loadables.py arguments are forwarded. --wc-source pins provenance.
The adapter captures short count rows instead of discarding timed stdout, and
checks ASCII C-locale fixtures before returning to the shared harness's timer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--wc-source', type=Path, default=root/'loadables/wc.c')
    args, forwarded = parser.parse_known_args()
    output = Path(forwarded[forwarded.index('--output')+1])
    original = subprocess.run
    audit = []
    oracles = {}

    def checked(argv, *positional, **kwargs):
        if (not isinstance(argv, list) or len(argv) < 10 or argv[5] != 'bench'
                or not argv[4].startswith('input=$1;')):
            return original(argv, *positional, **kwargs)
        command = argv[8:]
        if Path(command[0]).name == 'busybox':
            command = command[1:]
        assert Path(command[0]).name == 'wc', command
        opt = command[1]
        key = (str(kwargs['cwd']), argv[6], opt)
        if key not in oracles:
            # Initial captured validation runs populate this immutable-fixture
            # cache before any timed probe/sample; avoid timing Python's scan.
            data = (Path(kwargs['cwd'])/argv[6]).read_bytes()
            assert data.isascii() and opt in ('-m', '-lwc', '-L')
            assert b'\t' not in data and b'\r' not in data and b'\f' not in data
            values = dict(l=data.count(b'\n'), w=len(data.split()), c=len(data), m=len(data),
                          L=max(map(len, data.split(b'\n')), default=0))
            oracles[key] = (len(data), hashlib.sha256(data).hexdigest(), [values[c] for c in 'lwmcL' if c in opt])
        size, fixture_sha, expected = oracles[key]
        if kwargs.get('stdout') != subprocess.DEVNULL:
            return original(argv, *positional, **kwargs)
        count = int(argv[7])
        kwargs['stdout'] = subprocess.PIPE
        proc = original(argv, *positional, **kwargs)
        valid = False
        if proc.returncode == 0:
            try:
                actual = [[int(v) for v in line.split()] for line in proc.stdout.splitlines()]
                valid = actual == [expected]*count
            except ValueError:
                pass
            if not valid:
                proc.returncode = 97
                proc.stderr += b'wc adapter: timed output failed independent oracle\n'
        audit.append(dict(command=argv[8:], passes=count, options=opt, exit_code=proc.returncode,
                          validated=valid, bytes_per_pass=size, expected=expected,
                          fixture_sha256=fixture_sha,
                          output_sha256=hashlib.sha256(proc.stdout).hexdigest()))
        return proc

    subprocess.run = checked
    try:
        sys.argv = [str(root/'bench/loadables.py'), *forwarded]
        runpy.run_path(str(root/'bench/loadables.py'), run_name='__main__')
    finally:
        subprocess.run = original
    report = json.loads(output.read_text())
    report['wc_validation_adapter'] = dict(source_sha256=hashlib.sha256(args.wc_source.read_bytes()).hexdigest(),
                                          adapter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                          method='Timed stdout captured; every pass independently validated in C locale; validation overhead included in sample time.',
                                          calls=audit)
    output.write_text(json.dumps(report, indent=2)+'\n')
    assert audit and all(row['validated'] and row['exit_code'] == 0 for row in audit)
    assert all(c['results']['bashos']['status'] == 'ok' for c in report['cases'])


if __name__ == '__main__':
    main()
