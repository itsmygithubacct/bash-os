#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only control: a journal directory symlink must not be followed."""
import importlib.util
import subprocess
import sys

spec = importlib.util.spec_from_file_location('observer', '/opt/bashos-parity/harness/helpers/cron-lifecycle-observer-bash5320.py')
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
o.require_guest()
base = o.scenario_dir('batch-journal-symlink-r3')
target = base / 'outside'
target.mkdir(mode=0o700)
(target / 'marker').write_text('intact\n')
(base / 'spool' / '.batch-sequence.d').symlink_to(target, target_is_directory=True)
result = subprocess.run([sys.argv[1], '--noprofile', '--norc', '-c', 'batch'],
                        input=b'echo forbidden\n', env=o.cron_env(base),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
assert result.returncode != 0, (result.returncode, result.stdout, result.stderr)
assert sorted(p.name for p in target.iterdir()) == ['marker']
assert (target / 'marker').read_text() == 'intact\n'
assert not o.queued_jobs(base)
print('journal-symlink-rejected=ok')
