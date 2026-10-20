#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run with BASH_ENV loading sol-buf-probe; production operations, injected faults."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
checks = 0
child_env = os.environ.copy()
if os.environ.get('BUF_LOAD_ENV'):
    child_env['BASH_ENV'] = os.environ['BUF_LOAD_ENV']
if os.environ.get('BUF_ASAN_LIB'):
    child_env.update(LD_PRELOAD=os.environ['BUF_ASAN_LIB'],
                     ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                     UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
with tempfile.TemporaryDirectory(prefix='sol-buf-faults-') as td:
    d = Path(td)
    src = d/'source'
    data = b'alpha\x00beta\n'*14000+b'end'
    src.write_bytes(data)
    old = d/'old'
    old.write_bytes(b'keep\n')
    dest = d/'dest'
    q = lambda p: shlex.quote(str(p))
    def run(script):
        global checks
        script = 'before=(/proc/$$/fd/*)\n'+script+'\nafter=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]'
        p = subprocess.run([binary, '-e', '-c', 'PATH=; reject() { if "$@"; then printf "unexpected success: %s\\n" "$*" >&2; exit 90; fi; }; '+script], capture_output=True, timeout=30, env=child_env)
        assert p.returncode == 0, (script, p.returncode, p.stdout, p.stderr)
        assert b'Sanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        checks += 1
    # Every allocation site in mapped load and failure after a stream chunk.
    for fault in [f'alloc {n}' for n in range(1, 14)] + ['read 1', 'read 2', 'read 3']:
        run(f'''
buf new -h b; buf load "$b" {q(old)}; buf insert-at "$b" 0 0 X
bufprobe reset; bufprobe {fault}
if buf load "$b" {q(src)}; then
  bufprobe reset
  buf text "$b" > {q(dest)}
else
  bufprobe reset
  [[ $(buf text "$b" -X) == 586b6565700a ]]
  buf dirty "$b"
  buf save "$b"
fi
buf free "$b"
''')
        old.write_bytes(b'keep\n')
        if dest.exists(): assert dest.read_bytes() == data; dest.unlink()
    # Stream allocation failures, including ownership transfer of completed lines.
    for n in (1, 2, 3, 4, 10, 32, 100, 1000):
        run(f'''
buf new -h b; buf load "$b" {q(old)}
bufprobe reset; bufprobe stream; bufprobe alloc {n}
reject buf load "$b" {q(src)}
bufprobe reset
[[ $(buf text "$b" -X) == 6b6565700a ]]
reject buf dirty "$b"; buf free "$b"
''')
    # Save must not replace the old file or retained name on pre-rename failure.
    for fault in ('write 1', 'sync', 'zero', 'alloc 1', 'alloc 2'):
        dest.write_bytes(b'unchanged')
        run(f'''
buf new -h b; buf load "$b" {q(old)}; buf insert-at "$b" 0 0 X
bufprobe reset; bufprobe {fault}
reject buf save "$b" {q(dest)}
bufprobe reset; buf dirty "$b"; buf save "$b"; buf free "$b"
''')
        assert dest.read_bytes() == b'unchanged'
        assert old.read_bytes() == b'Xkeep\n'
        assert not list(d.glob('*.tmp*'))
        old.write_bytes(b'keep\n')
    # The second bounded write fails after the temporary file already has data.
    dest.write_bytes(b'unchanged')
    run(f'''
buf new -h b; buf load "$b" {q(src)}; buf insert-at "$b" 0 0 X
bufprobe reset; bufprobe write 2
reject buf save "$b" {q(dest)}
bufprobe reset; buf dirty "$b"; buf text "$b" > {q(d/'after-failure')}
buf free "$b"
''')
    assert dest.read_bytes() == b'unchanged'
    assert (d/'after-failure').read_bytes() == b'X'+data
    assert not list(d.glob('*.tmp*'))
    for fault in ('short', 'eintr'):
        run(f'''
buf new -h b; buf load "$b" {q(src)}; bufprobe reset; bufprobe {fault}
buf save "$b" {q(dest)}; bufprobe reset; buf free "$b"
''')
        assert dest.read_bytes() == data
    # A failed insertion must not leave a ghost slot, altered bytes, or dirty bit.
    for verb in ('insert-line "$b" 0 extra', 'insert-at "$b" 0 1 extra'):
        for n in range(1, 8):
            run(f'''
buf new -h b; buf load "$b" {q(old)}
bufprobe reset; bufprobe alloc {n}
if buf {verb}; then bufprobe reset; else
  bufprobe reset
  [[ $(buf text "$b" -X) == 6b6565700a ]]
  reject buf dirty "$b"
fi
buf free "$b"
''')
    # set-name allocation failure retains the original default save destination.
    run(f'''
buf new -h b; buf load "$b" {q(old)}
bufprobe reset; bufprobe alloc 1
reject buf set-name "$b" {q(dest)}
bufprobe reset; buf insert-at "$b" 0 0 X; buf save "$b"; buf free "$b"
''')
    assert old.read_bytes() == b'Xkeep\n'
print(f'sol-buf-faults: {checks} checks passed')
