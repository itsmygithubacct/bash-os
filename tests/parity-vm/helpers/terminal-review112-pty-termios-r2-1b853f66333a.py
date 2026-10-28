#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only raw termios samples on the fixture's own controlling PTY."""
import json
import os
from pathlib import Path
import sys
import termios
import uuid


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture uid or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires disposable QEMU uid2000 fixture scratch') from exc


def sample(mode):
    attrs = termios.tcgetattr(0)
    names = ('ECHO', 'ECHOE', 'ECHOK', 'ECHONL')
    values = {name: bool(attrs[3] & getattr(termios, name)) for name in names}
    cc = [value if isinstance(value, int) else value[0] for value in attrs[6]]
    record = {'sample': mode, 'pid': os.getpid(), 'fd': 0, 'tty_name': os.ttyname(0),
              'iflag': attrs[0], 'oflag': attrs[1], 'cflag': attrs[2], 'lflag': attrs[3],
              'ispeed': attrs[4], 'ospeed': attrs[5], 'cc': cc,
              'flags': values, 'flag_masks': {name: getattr(termios, name) for name in names}}
    Path(os.environ['HOME'], 'tty-echo-' + mode + '.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n')
    return all(value == (mode == 'on') for value in values.values())


if __name__ == '__main__':
    require_guest()
    if len(sys.argv) != 2 or sys.argv[1] not in ('off', 'on'):
        raise SystemExit('invalid fixture arguments')
    raise SystemExit(0 if sample(sys.argv[1]) else 1)
