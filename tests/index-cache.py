#!/usr/bin/env python3
"""Check repeated index reads and mutations using valid private Git indexes."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
git_binary = shutil.which('git')
move_binary = shutil.which('mv')
assert git_binary and move_binary, 'index-cache requires git and mv'
checks = 0


def quote(value):
    return shlex.quote(str(value))


def git(root, *args, data=None, index=None):
    env = {**os.environ, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull}
    if index is not None:
        env['GIT_INDEX_FILE'] = str(index)
    result = subprocess.run([git_binary, '-C', str(root), '-c', 'index.version=2',
                             '-c', 'core.splitIndex=false', *map(str, args)],
                            input=data, capture_output=True, timeout=40, env=env)
    assert result.returncode == 0, (args, result.stderr[:2000])
    return result.stdout


def make_index(root, path, rows):
    index_info = b''.join(b'\t'.join(row.rsplit(b' ', 1))+b'\n'
                          for row in rows.splitlines())
    git(root, 'update-index', '--index-info', data=index_info, index=path)


def read(index, output, verb='read'):
    return f'index {verb} {quote(index)} > {quote(output)}\n'


def run(root, script, expected):
    global checks
    script = '[ "$(type -t index)" = builtin ]\n'+script
    result = subprocess.run([binary, '--noprofile', '--norc', '-e', '-o',
                             'pipefail', '-c', script], cwd=root,
                            capture_output=True, timeout=50,
                            env={**os.environ, 'LC_ALL': 'C'})
    assert result.returncode == 0, (result.returncode, result.stderr[:4000])
    assert result.stdout == b'', result.stdout[:1000]
    assert b'AddressSanitizer' not in result.stderr, result.stderr[:4000]
    assert b'runtime error:' not in result.stderr, result.stderr[:4000]
    checks += 1
    for path, content in expected.items():
        assert (root/path).read_bytes() == content, path
        checks += 1


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    git(root, 'init', '-q', '--object-format=sha1')
    rows, other_rows, shas = [], [], []
    for i in range(6):
        path = f'entry-{i:05d}'
        body = f'ordinary fixture {i}\n'.encode()
        (root/path).write_bytes(body)
        (root/path).chmod(0o644)
        sha = git(root, 'hash-object', '-w', '--stdin', data=body).strip().decode()
        other = git(root, 'hash-object', '-w', '--stdin', data=body.upper()).strip().decode()
        shas.append(sha)
        rows.append(f'100644 {sha} 0 {path}\n')
        other_rows.append(f'100644 {other} 0 {path}\n')
    data, other_data = ''.join(rows).encode(), ''.join(other_rows).encode()
    a, b, alias = root/'a.index', root/'b.index', root/'alias.index'
    make_index(root, a, data)
    make_index(root, b, other_data)
    assert a.stat().st_size == b.stat().st_size
    shutil.copy2(a, alias)

    script = read(a, 'first')+read(a, 'listed', 'list')
    script += f'index read {quote(alias)} -V entries\n'
    script += 'printf "%s\n" "${entries[@]}" > array\n'
    run(root, script, {'first': data, 'listed': data, 'array': data})

    stamp = 1700000000000000000
    for path in [a, b]:
        os.utime(path, ns=(stamp, stamp))
    for source, name in [(a, 'active'), (b, 'next'), (a, 'last')]:
        shutil.copy2(source, root/name)
    script = read('active', 'before')
    script += f'{quote(move_binary)} -f next active\n'
    script += read('active', 'replaced')+read('active', 'again')
    script += f'{quote(move_binary)} -f last active\n'+read('active', 'restored')
    run(root, script, {'before': data, 'replaced': other_data,
                       'again': other_data, 'restored': data})
    assert (root/'active').stat().st_mtime_ns == stamp
    checks += 1

    shutil.copy2(a, root/'mutating')
    script = read('mutating', 'mutation-before')
    script += 'index remove mutating entry-00001\n'
    script += read('mutating', 'removed')+read('mutating', 'removed-again')
    script += f'index add mutating {shas[1]} entry-00001\n'+read('mutating', 'added')
    script += 'index update-stat mutating entry-00000\n'+read('mutating', 'restatted')
    script += ('if index remove mutating missing-entry; then exit 90; '
               'else status=$?; [ "$status" -eq 1 ]; fi\n')
    script += read('mutating', 'after-failure')
    removed = ''.join(rows[:1]+rows[2:]).encode()
    run(root, script, {'mutation-before': data, 'removed': removed,
                       'removed-again': removed, 'added': data,
                       'restatted': data, 'after-failure': data})

    # The large valid index exceeds the 8 MiB snapshot cap. Repeated parsing
    # and a following small-index read must retain the same public behavior.
    large = root/'large.index'
    large_rows = ''.join(f'100644 {shas[0]} 0 bulk-{i:07d}\n'
                         for i in range(110000)).encode()
    make_index(root, large, large_rows)
    assert large.stat().st_size > 8*1024*1024
    script = read(a, 'small-before')+read(large, 'large-first')
    script += read(large, 'large-again')+read(a, 'small-after')
    run(root, script, {'small-before': data, 'large-first': large_rows,
                       'large-again': large_rows, 'small-after': data})

print(f'index-cache: {checks} checks passed')
