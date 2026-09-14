#!/usr/bin/env python3
"""Exercise buffered grep/pcre output and literal sed substitution contracts."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = dict(os.environ, LC_ALL='C.UTF-8')
load = os.environ.get('PATTERN_LOAD_ENV', '')
setup = '. ' + shlex.quote(load) + '; ' if load else ''
checks = 0


def run(command, data=b'', expected=b'', rc=0, locale='C.UTF-8'):
    global checks
    result = subprocess.run([binary, '-c', setup + command], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=dict(env, LC_ALL=locale), timeout=15)
    assert (result.returncode, result.stdout) == (rc, expected), (
        command, result.returncode, result.stderr, result.stdout[:160], expected[:160])
    checks += 1


with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    # Both buffering thresholds, sparse and adjacent selected records, long
    # records, and a final unterminated record. All inputs are ordinary text.
    records = [b'first match\n']
    for i in range(9000):
        records.append((b'match match ' if i % 7 < 4 else b'other ') +
                       str(i).encode() + b' value\n')
    records += [b'x' * 160000 + b' match\n', b'match final']
    data = b''.join(records)
    wanted = b''.join(line if line.endswith(b'\n') else line + b'\n'
                      for line in records if b'match' in line)
    count = sum(b'match' in line for line in records)
    Path('one').write_bytes(data)
    for locale in ('C', 'C.UTF-8'):
        run('grep match', data, wanted, locale=locale)
        run('grep -c match', data, f'{count}\n'.encode(), locale=locale)
        run('pcre grep match one', expected=wanted, locale=locale)
    Path('two').write_bytes(b'match second')
    run('pcre grep match < one; pcre grep match < two', expected=wanted + b'match second\n')
    run('pcre grep absent < one; pcre grep match < two', expected=b'match second\n')
    run('pcre grep match one two', expected=(
        b''.join(b'one:' + line for line in wanted.splitlines(keepends=True)) + b'two:match second\n'))
    run("pcre grep '(?<=id:)[0-9]+'", b'none\nid:123\nid:abc\n', b'id:123\n')
    run("pcre grep '\\p{L}+'", '123\ncafé\n'.encode(), 'café\n'.encode())
    run('pcre grep match', b'bad\xff match\nvalid match\n', b'valid match\n')
    run('pcre grep match -b', b'bad\xff match\nvalid match\n', b'bad\xff match\nvalid match\n')
    run('pcre grep match -b', b'nul\x00 match\n', b'nul\x00 match\n')
    mixed = b'plain filler\n' * 6000 + b'bad\xff match\n' + 'café match\n'.encode() + b'match end'
    Path('mixed').write_bytes(mixed)
    run('pcre grep match mixed', expected='café match\n'.encode() + b'match end\n')
    Path('nul').write_bytes(b'match\x00record\nlast match')
    run('pcre grep match nul', expected=b'match\x00record\nlast match\n')
    run("pcre grep $'match\\nmatch' one", rc=1)
    run('pcre grep match -i', b'MATCH\nMatch\nnone\n', b'MATCH\nMatch\n')
    run("pcre grep 'm a t c h' -x", b'match\nnone\n', b'match\n')
    # A non-ASCII window falls back without suppressing valid matching lines.
    run('grep match', b'caf\xc3\xa9 match\nplain\nlast match\n', b'caf\xc3\xa9 match\nlast match\n')
    scripts = [
        's/match/NEW/g', 's/match/NEW/2', 's/match/NEW/2g',
        's/match/[&]/g', r's/match/\U&/g', 's/match//g',
        's/match/X/g;s//Y/g', 's/match/X/g;t done;s/.*/miss/;:done',
        's/ma.ch/X/g', 's/match/X/ig',
    ]
    sed_input = b'match match match\nnone\nMATCH\ncaf\xc3\xa9 match\nmatch final'
    for locale in ('C', 'C.UTF-8'):
        for script in scripts:
            reference = subprocess.run(['/usr/bin/sed', script], input=sed_input,
                                       stdout=subprocess.PIPE, check=True,
                                       env=dict(env, LC_ALL=locale)).stdout
            run('sed ' + shlex.quote(script), sed_input, reference, locale=locale)
print(f'pattern-fastpaths: {checks} checks passed')
