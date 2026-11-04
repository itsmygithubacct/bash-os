#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only regression for a revisited second and an interrupted reservation."""
import importlib.util
import sys
import time

spec = importlib.util.spec_from_file_location('observer', '/opt/bashos-parity/harness/helpers/cron-lifecycle-observer-bash5320.py')
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
o.require_guest()
shell = sys.argv[1]
for attempt in range(1, 7):
    base = o.scenario_dir('batch-journal-r2-%d' % attempt)
    log = base / 'order.log'
    proc = o.spawn_submitter(shell, base, 'new', [o.append(log, 'NEW')])
    try:
        assert o.align()
        sec = int(time.time())
        directory = base / 'spool' / '.batch-sequence.d'
        directory.mkdir(mode=0o700)
        # The second has already reserved two IDs, then a writer died halfway
        # through the next record. A later-second journal also exists.
        (directory / str(sec)).write_bytes(b'000000\n000001\n000')
        (directory / str(sec + 1)).write_bytes(b'000000\n')
        o.drop_job(base, '%d.99999.000000' % sec, o.append(log, 'OLD'), sec)
        result = o.submit(proc)
        if result and result[0]['sec'] == sec:
            break
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
else:
    raise AssertionError('could not submit within seeded second')
assert result[0]['seq'] == 2, result
assert (directory / str(sec)).read_bytes() == b'000000\n000001\n000002\n'
assert (directory / str(sec + 1)).read_bytes() == b'000000\n'
poll = o.consume(shell, base, sec)
assert poll.returncode == 0 and o.marks(log) == ['OLD', 'NEW'], (poll.returncode, o.marks(log))
assert not o.queued_jobs(base)
poll = o.consume(shell, base, sec)
assert poll.returncode == 0 and o.marks(log) == ['OLD', 'NEW']
print('journal-recovery=ok reserved-order=ok consumed-once=ok')
