#!/usr/bin/python3
"""Controlled /proc/swaps contract; execute only in the disposable parity VM."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HEADER = b'Filename\tType\tSize\tUsed\tPriority\n'
CASES = [
    ('header-only', HEADER, 0, [], []),
    ('missing-header', b'', 1, ['/proc/swaps: missing header'], []),
    ('invalid-header', b'Bogus header\n/tmp/x file 100 0 -2\n', 1, ['/proc/swaps: invalid header'], []),
    ('escapes', HEADER + b'/tmp/a\\040b file 100 0 -2\n/tmp/t\\011ab file 100 0 -3\n/tmp/n\\012l file 100 0 -4\n/tmp/bs\\134x file 100 0 -5\n/tmp/u\\777k file 100 0 -6\n', 1,
     ['/proc/swaps: malformed row 6'], ['/tmp/a b', '/tmp/t\tab', '/tmp/n\nl', '/tmp/bs\\x']),
    ('duplicates', HEADER + b'/tmp/d1 file 100 0 -2\n/tmp/d2 file 100 0 -3\n/tmp/d1 file 100 0 -4\n', 1, [], ['/tmp/d1', '/tmp/d2']),
    ('malformed', HEADER + b'/tmp/m1 file 100\n/tmp/m2 bogus 100 0 -2\n/tmp/m3 file x 0 -2\n/tmp/m4 file 100 200 -2\n/tmp/ok file 100 0 -2\n', 1,
     ['/proc/swaps: malformed row 2', '/proc/swaps: malformed row 3', '/proc/swaps: malformed row 4', '/proc/swaps: malformed row 5'], ['/tmp/ok']),
    ('decoded-duplicate', HEADER + b'/tmp/a\\040b file 100 0 -2\n/tmp/a\\040b partition 100 0 -3\n/tmp/other file 1 0 0\n', 1, [], ['/tmp/a b', '/tmp/other']),
]


def main():
    shell, seccomp = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='swapoff-table-') as tmp:
        fixture, log = Path(tmp) / 'swaps', Path(tmp) / 'requests'
        fixture.write_bytes(b'')
        subprocess.run(['/usr/bin/mount', '--bind', str(fixture), '/proc/swaps'], check=True)
        try:
            for name, data, status, diagnostics, expected in CASES:
                fixture.write_bytes(data)
                log.write_text('')
                cmd = ['/usr/bin/python3', seccomp, '--notify', 'swapoff', '--reply', 'swapoff=EINVAL',
                       '--errno', 'swapon:EPERM', '--log-string', 'swapoff=0', '--log', str(log),
                       '--', shell, '--noprofile', '--norc', '-c', 'swapoff -a']
                result = subprocess.run(cmd, capture_output=True, env={**os.environ, 'LC_ALL': 'C'}, timeout=15)
                records = [json.loads(line) for line in log.read_text().splitlines()]
                paths = [entry.get('string0') for entry in records]
                stderr = result.stderr.decode('utf-8', errors='replace')
                # Every EINVAL request produces its own diagnostic, including paths containing newlines.
                if (result.returncode != status or result.stdout or paths != expected or
                    any(d not in stderr for d in diagnostics) or
                    stderr.count('Invalid argument') != len(expected) or
                    stderr.count('/proc/swaps: malformed row ') != len([d for d in diagnostics if 'malformed row' in d]) or
                    (not diagnostics and not expected and stderr)):
                    raise AssertionError(f'{name}: status={result.returncode}, stdout={result.stdout!r}, stderr={stderr!r}, requests={paths!r}')
        finally:
            subprocess.run(['/usr/bin/umount', '/proc/swaps'], check=True)
    print('swapoff-all-table=ok')


if __name__ == '__main__':
    main()
