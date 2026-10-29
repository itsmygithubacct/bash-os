#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only semantic assertions over bounded top fixture captures.

The expected proc fields and ordering come from the fixture ABI values and
original requirements, not from candidate output. It never launches top.
"""
import json
import os
import re
import sys
import uuid
from pathlib import Path

# The root evaluator has verified the exact VM UUID before dropping privileges.
# The readable marker is checked only for UUID format here; sys_vendor is
# unprivileged-readable, unlike the DMI product UUID.
def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() not in (0, 2000)
                or os.geteuid() != os.getuid()
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, fixture UID, or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires the disposable QEMU parity guest and fixture scratch') from exc


require_guest()
root = Path(os.environ['HOME'])
mode, status = sys.argv[1], int(sys.argv[2])
(root / 'top-status.json').write_text(json.dumps({'mode': mode, 'status': status},
                                                indent=2) + '\n')
raw = (root / 'top.raw').read_bytes() if (root / 'top.raw').exists() else b''
err = (root / 'top.err').read_bytes() if (root / 'top.err').exists() else b''
text = raw.decode('utf-8', 'replace')
pattern = re.compile(r'^\s*(\d+)\s+\S+\s+(\d+\.\d+)\s+(\d+)\s+([A-Za-z])\s+(.+)$', re.M)
rows = [(int(m.group(1)), float(m.group(2)), int(m.group(3)), m.group(4), m.group(5))
        for m in pattern.finditer(text)]


def emit(label, ok):
    print(label + '=' + ('PASS' if ok else 'FAIL'))


if mode == 'header':
    emit('status', status == 0)
    emit('load', bool(re.search(r'load.*0\.25.*0\.50.*1\.00', text, re.I)))
    emit('tasks', bool(re.search(r'\bprocs\s+3\b|\btasks:\s*3\b', text, re.I)))
    emit('memory', bool(re.search(r'Mem[^\n]*1024[^\n]*768[^\n]*256', text, re.I)))
    emit('swap', bool(re.search(r'Swap[^\n]*512[^\n]*384[^\n]*128', text, re.I)))
    emit('uptime', bool(re.search(r'(?:\bup\b|\buptime\b)[^\n]*(?:2 days|48:00|2d)', text, re.I)))
    emit('cpu-header', bool(re.search(r'%?Cpu\(s\)|\bCPU\s*:', text, re.I)))
elif mode in ('cpu', 'memory'):
    emit('status', status == 0)
    wanted = [303, 202, 101] if mode == 'cpu' else [101, 303, 202]
    emit('rows-and-order', [r[0] for r in rows] == wanted)
    emit('zero-static-cpu', len(rows) == 3 and all(r[1] == 0 for r in rows))
    emit('rss', {r[0]: r[2] for r in rows} == {101: 120, 202: 80, 303: 80})
elif mode == 'cap':
    emit('status', status == 0)
    emit('two-rows', len(rows) == 2)
    emit('first-two-pids', [r[0] for r in rows] == [303, 202])
elif mode == 'malformed':
    emit('status', status == 0)
    emit('valid-only', [r[0] for r in rows] == [303, 202, 101])
    emit('rejected-malformed', all(r[0] not in (404, 505) for r in rows))
elif mode == 'empty':
    emit('status', status == 0)
    emit('zero-tasks', bool(re.search(r'\bprocs\s+0\b|\btasks:\s*0\b', text, re.I)))
    emit('no-rows', not rows)
elif mode == 'missing':
    emit('failure-status', status == 1)
    emit('diagnostic', bool(err.strip()))
elif mode == 'full':
    emit('failure-status', status == 1)
    emit('enospc-diagnostic', b'No space left on device' in err)
else:
    raise SystemExit('unknown observation mode')
