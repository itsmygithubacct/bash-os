#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only PID/starttime observations and identity-safe owned-process cleanup."""
import json
import os
from pathlib import Path
import signal
import sys
import time
import uuid


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case')
                or Path.home() != Path('/tmp/parity-home')):
            raise ValueError('guest identity, uid or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires disposable QEMU uid2000 fixture scratch') from exc


def observe(pid):
    path = Path('/proc') / str(pid)
    try:
        raw = (path / 'stat').read_text().strip()
        fields = raw[raw.rindex(')') + 2:].split()
        return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
                'pgrp': int(fields[2]), 'sid': int(fields[3]),
                'starttime': int(fields[19]), 'uid': path.stat().st_uid, 'stat': raw}
    except (FileNotFoundError, ProcessLookupError):
        return {'pid': pid, 'absent': True}
    except (OSError, ValueError, IndexError) as exc:
        return {'pid': pid, 'error': '%s: %s' % (type(exc).__name__, exc)}


def snapshot(path, pairs, require_live):
    if len(pairs) % 2 or not pairs:
        raise ValueError('snapshot needs label/pid pairs')
    records = {}
    for label, pidtext in zip(pairs[::2], pairs[1::2]):
        if not label.isidentifier() or not pidtext.isdigit() or int(pidtext) <= 1 or label in records:
            raise ValueError('invalid owned process label or pid')
        records[label] = observe(int(pidtext))
    result = {'monotonic_ns': time.monotonic_ns(), 'records': records}
    Path(path).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return (not require_live or all(r.get('uid') == os.getuid() and 'starttime' in r
                                   and r.get('state') != 'Z' for r in records.values()))


def gone(initial, current):
    return bool(current.get('absent') or ('starttime' in current and
                current['starttime'] != initial['starttime']))


def wait_gone(source, output, labels):
    saved = json.loads(Path(source).read_text())['records']
    selected = {}
    for label in labels:
        rec = saved[label]
        if rec.get('uid') != os.getuid() or 'starttime' not in rec or rec.get('state') == 'Z':
            raise ValueError('initial process is not a live owned identity: ' + label)
        selected[label] = rec
    observations = []
    seen = {}
    deadline = time.monotonic() + 4
    while True:
        current = {name: observe(rec['pid']) for name, rec in selected.items()}
        # Save changes and a final raw state, not thousands of identical samples.
        key = json.dumps(current, sort_keys=True)
        if key != seen.get('key'):
            observations.append({'monotonic_ns': time.monotonic_ns(), 'records': current})
            seen['key'] = key
        if all(gone(selected[name], value) for name, value in current.items()):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(.03)
    natural = all(gone(selected[name], value) for name, value in current.items())
    actions = []
    if not natural:
        # Cleanup is only through pidfds acquired for identities independently
        # recorded while live, then rechecked after acquisition. A forced cleanup
        # remains a failed natural-cleanup assertion even if it succeeds.
        for name, initial in selected.items():
            cur = observe(initial['pid'])
            if gone(initial, cur) or cur.get('state') == 'Z':
                continue
            action = {'label': name, 'before': cur, 'signals': []}
            try:
                if cur.get('uid') != os.getuid() or cur.get('starttime') != initial['starttime']:
                    raise ValueError('identity changed before cleanup')
                fd = os.pidfd_open(initial['pid'], 0)
                try:
                    again = observe(initial['pid'])
                    if again.get('uid') != os.getuid() or again.get('starttime') != initial['starttime']:
                        raise ValueError('identity changed after pidfd acquisition')
                    for sig in (signal.SIGTERM, signal.SIGKILL):
                        if gone(initial, observe(initial['pid'])):
                            break
                        signal.pidfd_send_signal(fd, sig)
                        action['signals'].append(sig.name)
                        until = time.monotonic() + 1.5
                        while time.monotonic() < until and not gone(initial, observe(initial['pid'])):
                            time.sleep(.03)
                finally:
                    os.close(fd)
            except (OSError, ValueError, AttributeError) as exc:
                action['error'] = '%s: %s' % (type(exc).__name__, exc)
            action['after'] = observe(initial['pid'])
            actions.append(action)
    final = {name: observe(rec['pid']) for name, rec in selected.items()}
    Path(output).write_text(json.dumps({'initial': selected, 'samples': observations,
        'natural_disappearance': natural, 'forced_actions': actions, 'final': final},
        indent=2, sort_keys=True) + '\n')
    return natural


if __name__ == '__main__':
    require_guest()
    args = sys.argv[1:]
    if len(args) >= 4 and args[0] in ('snapshot', 'snapshot-live'):
        raise SystemExit(0 if snapshot(args[1], args[2:], args[0] == 'snapshot-live') else 1)
    if len(args) >= 4 and args[0] == 'wait-gone':
        raise SystemExit(0 if wait_gone(args[1], args[2], args[3:]) else 1)
    raise SystemExit('invalid fixture arguments')
