#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Persistent buffer contracts; no compilation, external commands or live terminals."""
import os
from pathlib import Path
import random
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
failures = []


def run(name, script, data=None, expected=b''):
    global checks
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh') as shell:
        shell.write('PATH=; reject() { if "$@"; then printf "unexpected success: %s\\n" "$*" >&2; exit 90; fi; }; '+script); shell.flush()
        p = subprocess.run([binary, '-e', '-o', 'pipefail', shell.name],
                           input=data, capture_output=True, timeout=60, env=child_env)
    checks += 1
    if p.returncode or p.stdout != expected or b'Sanitizer' in p.stderr or b'runtime error:' in p.stderr:
        failures.append(name)
        print(name, 'FAIL', p.returncode, repr(p.stdout[:500]), repr(p.stderr[:1500]))
    return p.returncode == 0


with tempfile.TemporaryDirectory(prefix='sol-buf-check-') as td:
    d = Path(td)
    q = lambda s: shlex.quote(str(s))
    for n, data in enumerate([b'', b'\n', b'\n\n', b'last', b'a\x00b\nlast', b'\r\n\xff\n',
                              b'x'*65535+b'\nY', b'x'*65536+b'\n', b'x'*65537,
                              b'a\n'*1023+b'boundary\n'+b'\x00\n'*1025+b'last']):
        src = d/f'source-{n}'
        src.write_bytes(data)
        lines = data.split(b'\n')
        if not data or data.endswith(b'\n'): lines.pop()
        for stream in (False, True):
            path = '/dev/stdin' if stream else src
            script = [f'buf new -h b; buf load "$b" {q(path)}',
                      f'[[ $(buf lines "$b") == {len(lines)} ]]',
                      f'buf text "$b" > {q(d/"text")}',
                      f'buf text "$b" -X > {q(d/"hex")}',
                      f'buf text "$b" {len(lines)} 0 > {q(d/"empty")}',
                      f'buf save "$b" {q(d/"save")}', 'buf save "$b"', 'reject buf dirty "$b"']
            for i in sorted({0, len(lines)//2, len(lines)-1}):
                if i < 0 or i >= len(lines): continue
                script += [f'[[ $(buf len "$b" {i}) == {len(lines[i])} ]]',
                           f'buf line "$b" {i} -V value -X', f'[[ $value == {q(lines[i].hex())} ]]']
            ranges = [(0, 0), (0, 1), (len(lines), 3)]
            ranges += [(i, 3) for i in (1, 1023, 1024, len(lines)-1) if 0 <= i < len(lines)]
            for j, (start, count) in enumerate(ranges):
                script += [f'buf text "$b" {start} {count} > {q(d/f"range-{j}")}']
            script += ['buf free "$b"', 'reject buf text "$b"', 'reject buf free "$b"']
            if run(f'roundtrip-{n}-stream-{stream}', '; '.join(script), data if stream else None):
                assert (d/'text').read_bytes() == data
                assert (d/'save').read_bytes() == data
                assert (d/'hex').read_bytes() == data.hex().encode()+b'\n'
                assert (d/'empty').read_bytes() == b''
                for j, (start, count) in enumerate(ranges):
                    stop = min(start+count, len(lines))
                    expected = b'\n'.join(lines[start:stop])
                    if stop > start and stop == len(lines) and data.endswith(b'\n'): expected += b'\n'
                    assert (d/f'range-{j}').read_bytes() == expected


    src = d/'original'
    src.write_bytes(b'alpha\nbeta\n')
    run('reload-rollback', f'''
buf new -h b
buf load "$b" {q(src)}
buf insert-at "$b" 0 0 X
reject buf load "$b" {q(d)}
[[ $(buf line "$b" 0) == Xalpha ]]
buf dirty "$b"
reject buf load "$b" {q(d/'missing')}
[[ $(buf text "$b" -X) == 58616c7068610a626574610a ]]
buf save "$b"
buf free "$b"
''')
    src.write_bytes(b'alpha\nbeta\n')
    run('reload-alias-cleanup-fds', f'''
buf new -h b
before=(/proc/$$/fd/*)
for ((i=0; i<100; i++)); do
  buf load "$b" {q(src)}
  buf insert-line "$b" 0 gamma
  buf delete-line "$b" 2
  buf load "$b" {q(src)}
  [[ $(buf line "$b" 0) == alpha ]]
  buf save "$b"
  reject buf dirty "$b"
done
after=(/proc/$$/fd/*)
[[ ${{#before[@]}} == ${{#after[@]}} ]]
buf free "$b"
''')
    assert src.read_bytes() == b'alpha\nbeta\n'
    run('mapping-cleanup', f'''
mapping_count() {{
  local n=0 row
  while IFS= read -r row; do
    case "$row" in *"$1"*) ((n+=1));; esac
  done </proc/$$/maps
  printf '%s' "$n"
}}
buf new -h b
for ((i=0;i<50;i++)); do
  buf load "$b" {q(src)}
  [[ $(mapping_count {q(src)}) == 1 ]]
  reject buf load "$b" {q(d)}
  [[ $(mapping_count {q(src)}) == 1 ]]
done
buf free "$b"
[[ $(mapping_count {q(src)}) == 0 ]]
''')
    run('save-failure-retains-name' , f'''
buf new -h b; buf load "$b" {q(src)}
buf insert-at "$b" 0 0 X
reject buf save "$b" {q(d)}
buf dirty "$b"
buf save "$b"
buf free "$b"
''')
    assert src.read_bytes() == b'Xalpha\nbeta\n'
    assert not list(d.glob('*.tmp*'))

    for token in ('', 'no', '0x0', '0junk', '-1', '999999999999999999999999'):
        run('invalid-handle-'+repr(token), f'buf new -h b; reject buf lines {q(token)}; [[ $(buf lines "$b") == 0 ]]; buf free "$b"')
        run('invalid-index-'+repr(token), f'buf new -h b; buf insert-line "$b" 0 keep; reject buf delete-line "$b" {q(token)}; [[ $(buf line "$b" 0) == keep ]]; reject buf len "$b" {q(token)}; buf free "$b"')
    run('stale-slots', '''for ((i=0;i<32;i++)); do buf new -h b; slots[i]=$b; done
reject buf new -h b
for b in "${slots[@]}"; do buf free "$b"; reject buf lines "$b"; reject buf free "$b"; done
buf new -h b; [[ $b == 0 ]]; buf free "$b"''')
    run('output-errors', '''buf new -h b; buf insert-line "$b" 0 data
reject buf text "$b" >/dev/full
reject buf text "$b" -X >/dev/full
reject buf line "$b" 0 >/dev/full
reject buf len "$b" 0 >/dev/full
reject buf lines "$b" >/dev/full
reject buf text "$b" -F 2147483648
buf text "$b"; buf free "$b"''', expected=b'data')
    run('range-boundaries', '''buf new -h b; buf insert-line "$b" 0 610062 -X
buf insert-line "$b" 1 ''; buf insert-line "$b" 2 ff -X
[[ $(buf text "$b" 0 1 -X) == 610062 ]]
[[ $(buf text "$b" 1 1 -X) == '' ]]
[[ $(buf text "$b" 1 99 -X) == 0aff ]]
reject buf insert-at "$b" 0 4 x
reject buf delete-at "$b" 0 3 1
buf insert-at "$b" 0 3 00 -X
buf delete-at "$b" 0 0 4
[[ $(buf len "$b" 0) == 0 ]]
buf delete-at "$b" 0 0 0
buf free "$b"''')
    # Independent Python byte-array oracle, exercised through both COW and heap paths.
    rng = random.Random(4927)
    model = [b'a\x00b', b'', b'last']
    src.write_bytes(b'\n'.join(model))
    script = [f'buf new -h b; buf load "$b" {q(src)}']
    for step in range(160):
        op = rng.randrange(4) if model else 0
        if op == 0:
            i = rng.randrange(len(model)+1)
            value = bytes(rng.randrange(256) for _ in range(rng.randrange(10)))
            model.insert(i, value)
            script += [f'buf insert-line "$b" {i} {q(value.hex())} -X']
        elif op == 1:
            i = rng.randrange(len(model)); model.pop(i)
            script += [f'buf delete-line "$b" {i}']
        elif op == 2:
            i = rng.randrange(len(model)); col = rng.randrange(len(model[i])+1)
            value = bytes(rng.randrange(256) for _ in range(rng.randrange(10)))
            model[i] = model[i][:col]+value+model[i][col:]
            script += [f'buf insert-at "$b" {i} {col} {q(value.hex())} -X']
        else:
            i = rng.randrange(len(model)); col = rng.randrange(len(model[i])+1)
            count = rng.randrange(len(model[i])-col+1)
            model[i] = model[i][:col]+model[i][col+count:]
            script += [f'buf delete-at "$b" {i} {col} {count}']
        script += [f'[[ $(buf text "$b" -X) == {q(b"\n".join(model).hex())} ]]']
    script += ['buf free "$b"']
    run('random-byte-oracle', '\n'.join(script))
    run('unpublished-handles', '\n'.join([
        'readonly locked=old',
        'for ((i=0;i<40;i++)); do reject buf new -h locked; done',
        'reject buf new >/dev/full',
        'buf new -h b; [[ $b == 0 ]]; buf insert-line "$b" 0 value',
        'reject buf line "$b" 0 -V locked; buf free "$b"']))
    journal = d/'journal'
    run('journal-tuples', f'''buf new -h b; exec 9>{q(journal)}
buf mutate -j 9 -h "$b" -- insert-line 0 6100626364656667 -X
buf mutate -j 9 -h "$b" -- insert-at 0 1 ff -X
buf mutate -j 9 -h "$b" -- delete-at 0 1 2
buf mutate -j 9 -h "$b" -- delete-line 0
exec 9>&-; buf free "$b"
''')
    assert journal.read_bytes() == b'I 0 6100626364656667 -X\nA 0 1 ff -X\nR 0 1 ff00 -X\nD 0 61626364656667 -X\n'
    # Atomic replacement preserves old open descriptions/hardlinks and mode.
    src.write_bytes(b'old\n'); src.chmod(0o640)
    link = d/'hardlink'; os.link(src, link)
    with src.open('rb') as old_reader:
        run('atomic-replace-mode', f'''buf new -h b; buf load "$b" {q(src)}
buf insert-at "$b" 0 0 X; buf save "$b"; buf save "$b"; buf free "$b"''')
        assert old_reader.read() == b'old\n'
    assert link.read_bytes() == b'old\n'
    assert src.read_bytes() == b'Xold\n'
    assert src.stat().st_mode & 0o7777 == 0o640
    run('companions', '''buf new -h b; undo new -h u -B "$b"
buf insert-line "$b" 0 610062 -X; undo record "$u" I 0 610062 -X
undo undo "$u"; [[ $(buf lines "$b") == 0 ]]
undo redo "$u"; [[ $(buf line "$b" 0 -X) == 610062 ]]
clip new -h c; clip copy-line "$c" "$b" 0; clip paste "$c" "$b" 1
[[ $(buf line "$b" 1 -X) == 610062 ]]
clip free "$c"; undo free "$u"; buf free "$b"''')
print(f'sol-buf-check: {checks-len(failures)}/{checks} passed; failures={failures}')
sys.exit(bool(failures))
