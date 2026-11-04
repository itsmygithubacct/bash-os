#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only regression: batch sequence survives a consumer poll and mixes with at jobs."""
import importlib.util
import sys

spec = importlib.util.spec_from_file_location('observer', '/opt/bashos-parity/harness/helpers/cron-lifecycle-observer-bash5320.py')
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
o.require_guest()
if sys.argv[1:] == ['setup']:
    assert o.align()
    print('controls=verified')
    sys.exit(0)

shell = sys.argv[1]
try:
    for attempt in range(1, 7):
        base = o.scenario_dir('batch-sequence-%d' % attempt)
        log = base / 'order.log'
        first = o.spawn_submitter(shell, base, 'first', [o.append(log, 'FIRST')])
        second = o.spawn_submitter(shell, base, 'second', [o.append(log, 'SECOND')])
        o.align()
        a = o.submit(first)
        if a:
            poll = o.consume(shell, base, a[0]['sec'])
        b = o.submit(second)
        if a and b and a[0]['sec'] == b[0]['sec']:
            break
    assert a and b and a[0]['sec'] == b[0]['sec']
    assert poll.returncode == 0 and o.marks(log) == ['FIRST']
    assert b[0]['seq'] > a[0]['seq']
    o.drop_job(base, 'manual-at', o.append(log, 'AT'), b[0]['sec'])
    poll = o.consume(shell, base, b[0]['sec'])
    assert poll.returncode == 0 and o.marks(log) == ['FIRST', 'SECOND', 'AT']
    assert not o.queue(base)
    poll = o.consume(shell, base, b[0]['sec'])
    assert poll.returncode == 0 and o.marks(log) == ['FIRST', 'SECOND', 'AT']
    print('across-poll same-second=yes sequence=increasing mixed-at=executed once=yes queue=empty')
except Exception as exc:
    o.record(kind='error', error=repr(exc))
    print('scenario-error=%s' % type(exc).__name__)
