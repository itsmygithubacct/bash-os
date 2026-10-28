#!/usr/bin/python3
"""Disposable-guest-only recording userdb provider and trace checker."""
import base64
import json
import os
from pathlib import Path
import sys
import time
import uuid


def require_guest():
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        uuid.UUID(marker)
        case, home = Path('/tmp/parity-case'), Path('/tmp/parity-home')
        if (str(uuid.UUID(marker)) != marker.lower()
                or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.getuid() != 2000 or os.geteuid() != 2000 or os.environ.get('HOME') != str(home)
                or Path.cwd().resolve() != case or case.stat().st_uid != 2000
                or home.stat().st_uid != 2000):
            raise ValueError('guest identity or owned scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def b64(data):
    return base64.b64encode(data).decode('ascii')


def main():
    require_guest()
    home = Path('/tmp/parity-home')
    if len(sys.argv) == 2 and sys.argv[1] == '--check-lookup':
        events = [json.loads(line) for line in (home / 'provider.events').read_text().splitlines()]
        expected = [(tag, user) for user in ('external', 'baduid', 'badgid', 'extra', 'oversize', 'nul', 'error', 'missing') for tag in ('first', 'second')]
        valid = [(e['tag'], e['user']) for e in events] == expected
        valid &= all(e['op'] == 'lookup' and e['argv'] == [str(home / 'provider'), e['tag'], 'lookup', e['user']] for e in events)
        print('trace=' + ('ok' if valid else 'BAD'))
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == '--check-timeout':
        events = [json.loads(line) for line in (home / 'provider.events').read_text().splitlines()]
        valid = len(events) == 1 and events[0]['tag'] == 'first' and events[0]['op'] == 'lookup' and events[0]['user'] == 'timeout'
        print('timeout-trace=' + ('ok' if valid else 'BAD'))
        return 0
    if len(sys.argv) != 4:
        raise SystemExit('provider invocation needs TAG OP USER')
    _, tag, op, user = sys.argv
    if tag not in ('first', 'second') or op != 'lookup':
        raise SystemExit('unexpected fixture invocation')
    out, err, rc = b'', b'', 1
    if tag == 'second' and user != 'missing':
        out, rc = b'7101:7102:Remote User:/srv/remote:/bin/sh\n', 0
    elif tag == 'first':
        vals = {'baduid': b'abc:7102:bad:/tmp:/bin/sh\n',
                'badgid': b'7101:-2:bad:/tmp:/bin/sh\n',
                'extra': b'7101:7102:bad:/tmp:/bin/sh:extra\n',
                'oversize': b'7' * 4200 + b':2:x:/tmp:/bin/sh\n',
                'nul': b'7101:7102:x\0tail:/tmp:/bin/sh\n'}
        if user in vals:
            out, rc = vals[user], 0
        elif user == 'error':
            err, rc = b'synthetic provider failure\n', 7
    event = {'tag':tag, 'op':op, 'user':user, 'argv':sys.argv,
             'pid':os.getpid(), 'pgid':os.getpgrp(),
             'stdout_base64':b64(out), 'stderr_base64':b64(err), 'planned_status':rc,
             'monotonic':time.monotonic()}
    with (home / 'provider.events').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(event, sort_keys=True) + '\n')
        stream.flush()
    if user == 'timeout' and tag == 'first':
        time.sleep(8)
    os.write(1, out)
    os.write(2, err)
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
