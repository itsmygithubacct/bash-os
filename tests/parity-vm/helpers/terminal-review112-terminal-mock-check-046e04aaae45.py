#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only control/verification for top's mocked mutation syscalls.

The target is INT_MAX, above Linux pid_max's maximum; even a broken filter
cannot signal or change a real process. The pinned seccomp notifier must reply
synthetically to every kill/getpriority/setpriority, and the log is reviewed.
"""
import json
import os
import sys
import uuid
from pathlib import Path

try:
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
except (OSError, ValueError):
    raise SystemExit('requires the disposable parity VM marker')
if os.getuid() not in (0, 2000):
    raise SystemExit('requires the fixture UID or its user-namespace mapping')

PID = 2147483647
UNKNOWN = 2147483646
mode = sys.argv[1]
if mode == 'probe':
    os.kill(PID, 15)
    current = os.getpriority(os.PRIO_PROCESS, PID)
    if current != 5:
        raise SystemExit('mock getpriority did not return nice 5')
    os.setpriority(os.PRIO_PROCESS, PID, 8)
    print('MOCK-PROBE=PASS')
    raise SystemExit(0)
if mode == 'probe-esrch':
    import errno
    try:
        os.kill(UNKNOWN, 15)
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise
    else:
        raise SystemExit('mock kill did not return ESRCH')
    print('MOCK-ESRCH=PASS')
    raise SystemExit(0)

path = Path(sys.argv[2])
records = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
def item(name, args, reply):
    return {'syscall': name, **{'arg%d' % i: value for i, value in enumerate(args)}, 'reply': reply}

expected = {
    'control': [item('kill', (PID, 15), 'value:0'),
                item('getpriority', (0, PID), 'value:15'),
                item('setpriority', (0, PID, 8), 'value:0')],
    'control-esrch': [item('kill', (UNKNOWN, 15), 'errno:3')],
    'none': [],
    'kill': [item('kill', (PID, 15), 'value:0')],
    'unknown-kill': [item('kill', (UNKNOWN, 15), 'errno:3')],
    'renice': [item('getpriority', (0, PID), 'value:15'),
               item('setpriority', (0, PID, 8), 'value:0')],
    'unknown-renice': [item('getpriority', (0, UNKNOWN), 'errno:3')],
}
if mode not in expected:
    raise SystemExit('unknown mock verification mode')
# Ignore no fields: these are the exact synthetic replies and argument tuples.
ok = records == expected[mode]
print('MOCK-LOG=' + ('PASS' if ok else 'FAIL'))
if mode.startswith('control') and not ok:
    raise SystemExit(1)
