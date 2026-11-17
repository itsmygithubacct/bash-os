#!/usr/bin/python3
"""swapoff -a over controlled /proc/swaps tables, compared with util-linux; execute only in the disposable parity VM."""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

HEADER = b'Filename\tType\tSize\tUsed\tPriority\n'
CASES = [
    ('header-only', HEADER),
    ('missing-header', b''),
    ('invalid-header', b'Bogus header\n/tmp/x file 100 0 -2\n'),
    ('escapes', HEADER + b'/tmp/a\\040b file 100 0 -2\n/tmp/t\\011ab file 100 0 -3\n/tmp/n\\012l file 100 0 -4\n/tmp/bs\\134x file 100 0 -5\n/tmp/u\\777k file 100 0 -6\n'),
    ('duplicates', HEADER + b'/tmp/d1 file 100 0 -2\n/tmp/d2 file 100 0 -3\n/tmp/d1 file 100 0 -4\n'),
    ('malformed', HEADER + b'/tmp/m1 file 100\n/tmp/m2 bogus 100 0 -2\n/tmp/m3 file x 0 -2\n/tmp/m4 file 100 200 -2\n/tmp/ok file 100 0 -2\n'),
    ('decoded-duplicate', HEADER + b'/tmp/a\\040b file 100 0 -2\n/tmp/a\\040b partition 100 0 -3\n/tmp/other file 1 0 0\n'),
]
REFERENCE = '/usr/sbin/swapoff'


def observe(seccomp, log, argv):
    """Status, stdout, diagnostics and ordered swapoff requests of one run.

    Every swapoff request is answered EINVAL by the notifier and never reaches
    the kernel."""
    log.write_text('')
    cmd = ['/usr/bin/python3', seccomp, '--notify', 'swapoff', '--reply', 'swapoff=EINVAL',
           '--errno', 'swapon:EPERM', '--log-string', 'swapoff=0', '--log', str(log), '--'] + argv
    result = subprocess.run(cmd, capture_output=True, env={**os.environ, 'LC_ALL': 'C'}, timeout=15)
    paths = [json.loads(line).get('string0') for line in log.read_text().splitlines()]
    stderr = result.stderr.decode('utf-8', errors='replace')
    # A builtin's diagnostic carries the shell's "NAME: line N: " prefix.
    stderr = re.sub(r'(?m)^[^\n:]*: line \d+: ', '', stderr)
    return {'status': result.returncode, 'stdout': result.stdout, 'stderr': stderr, 'requests': paths}


def main():
    shell, seccomp = sys.argv[1:]
    failed = 0
    with tempfile.TemporaryDirectory(prefix='swapoff-table-') as tmp:
        fixture, log = Path(tmp) / 'swaps', Path(tmp) / 'requests'
        fixture.write_bytes(b'')
        subprocess.run(['/usr/bin/mount', '--bind', str(fixture), '/proc/swaps'], check=True)
        try:
            for name, data in CASES:
                fixture.write_bytes(data)
                want = observe(seccomp, log, [REFERENCE, '-a'])
                got = observe(seccomp, log, [shell, '--noprofile', '--norc', '-c',
                                             '[[ $(type -t swapoff) == builtin ]] || exit 97; swapoff -a'])
                if got != want:
                    failed = 1
                    print(f'{name}: differs\n  util-linux {want!r}\n  candidate  {got!r}', file=sys.stderr)
                else:
                    print(f'{name}: same as util-linux, {len(want["requests"])} requests, status {want["status"]}')
        finally:
            subprocess.run(['/usr/bin/umount', '/proc/swaps'], check=True)
    sys.exit(failed)


if __name__ == '__main__':
    main()
