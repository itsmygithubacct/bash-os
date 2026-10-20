#!/usr/bin/env python3
"""A failed join must not retain stdin bytes across shell redirections."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C')
prefix = 'if [[ -n ${REVIEW_MODULE:-} ]]; then enable -f "$REVIEW_MODULE" join || exit; fi\n'
with tempfile.TemporaryDirectory(prefix='join-streams-') as directory:
    root = Path(directory)
    empty = root / 'empty'
    empty.touch()
    for side in (1, 2):
        operands = '- "$1"' if side == 1 else '"$1" -'
        script = prefix + '''
shopt -s lastpipe
set +m
before=(/proc/$$/fd/*)
for ((i=0;i<40;i++)); do
  printf 'a X\nb Y\nc Z\n' | join -aSIDE OPERANDS >/dev/full 2>/dev/null
  [[ $? == 1 ]] || exit 91
  printf 'd D\n' | join -aSIDE OPERANDS || exit 92
done
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]] || exit 93
'''.replace('SIDE', str(side)).replace('OPERANDS', operands)
        p = subprocess.run([binary, '--noprofile', '--norc', '-c', script,
                            '_', str(empty)], capture_output=True, env=env, timeout=20)
        assert (p.returncode, p.stdout, p.stderr) == (0, b'd D\n' * 40, b''), p
    # Also reserve closed standard descriptors when stdin permits writing.
    data = b'a X\nb Y\nc Z\n'
    source = root / 'source'
    source.write_bytes(data)
    p = subprocess.run([binary, '-c', prefix + '''
join -a1 - "$1" 0<>"$2" >&- 2>/dev/null
[[ $? == 1 ]] || exit 94
printf recovered
''', '_', str(empty), str(source)], capture_output=True, env=env, timeout=20)
    assert (p.returncode, p.stdout, p.stderr) == (0, b'recovered', b''), p
    assert source.read_bytes() == data
print('join-streams: both stdin operands, 80 failure/recovery cycles, stable FDs, closed stdout')
