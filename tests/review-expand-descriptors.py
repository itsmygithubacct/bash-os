#!/usr/bin/env python3
"""Closed output must fail without modifying read/write stdin."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C')
command = 'expand'
prefix = 'if [[ -n ${REVIEW_MODULE:-} ]]; then enable -f "$REVIEW_MODULE" expand || exit; fi; '
checks = 0
with tempfile.TemporaryDirectory(prefix='expand-descriptors-') as directory:
    fixture = Path(directory) / 'input'
    for data in (b'ab\ncd\n', b'a\t' * 20000 + b'\nend\n'):
        for args in [[], ["-i"], ["-t4"]]:
            fixture.write_bytes(data)
            script = prefix + 'before=(/proc/$$/fd/*)\nfor ((i=0;i<20;i++)); do\n  expand "${@:2}" 0<>"$1" >&- 2>/dev/null\n  [[ $? == 1 ]] || exit 91\ndone\nafter=(/proc/$$/fd/*)\n[[ ${#before[@]} == ${#after[@]} ]] || exit 92\nprintf recovered\n'
            p = subprocess.run([binary, '--noprofile', '--norc', '-c', script,
                                '_', str(fixture), *args], env=env,
                               capture_output=True, timeout=20)
            assert (p.returncode, p.stdout, p.stderr) == (0, b'recovered', b''), (args, p)
            assert fixture.read_bytes() == data, (args, 'input modified')
            checks += 1
print(f'expand-descriptors: {checks} cases, 20 failure/recovery cycles each; input unchanged')
