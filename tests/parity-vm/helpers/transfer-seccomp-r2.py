#!/usr/bin/python3
"""Disposable-guest gate for the pinned shared seccomp supervisor."""
import os
from pathlib import Path
import sys
import uuid


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        case, home = Path('/tmp/parity-case'), Path('/tmp/parity-home')
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(home)
                or Path.cwd().resolve() != case or case.stat().st_uid != 2000
                or home.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


if __name__ == '__main__':
    require_guest()
    supervisor = '/opt/bashos-parity/harness/helpers/system-seccomp.py'
    os.execv('/usr/bin/python3', ['/usr/bin/python3', supervisor, *sys.argv[1:]])
