#!/usr/bin/env python3
"""Revalidate existing key API consumers after the optional callback addition."""
import importlib.util
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location('more_checks', Path(__file__).with_name('sol-more-check.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
binary = str(Path(sys.argv[1]).resolve())
p = subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; top --once -r 3'],
                   capture_output=True, env=checks.ENV, check=True)
assert b'PID' in p.stdout and not p.stderr
for keys, names in [(b'\x1b[B\x1b[6~\n', [b'DOWN', b'PGDN', b'RET']),
                    (b'\x1bq\x1b[A', [b'ESC', b'q', b'UP'])]:
    t = checks.Terminal(binary)
    try:
        t.start("tui init; printf '__KEYS__\\n'; tui getkey; tui getkey; tui getkey; tui end")
        t.until(b'__KEYS__\n')  # _bl_screen disables output newline conversion.
        t.send(keys)
        output = t.done()
        for name in names:
            assert name+b'\n' in output, output
    finally:
        t.close()
# Exercise top's screen lifecycle and existing decoder without signalling any
# process or choosing its kill/renice keys.
t = checks.Terminal(binary, rows=24)
try:
    t.start('top -d 60 -r 3')
    t.until(b'PID')
    t.send(b'\x1b[B\x1b[6~ q')
    t.done()
finally:
    t.close()
print('sol-more-helper: top batch/interactive and tui CSI/Enter/pushback passed')
