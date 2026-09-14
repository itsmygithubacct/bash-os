#!/usr/bin/env python3
"""Check regular-file install copying and reusable fmt paragraph storage."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
env = {**os.environ, 'LC_ALL': 'C'}
if os.environ.get('COREUTILS_LOAD_ENV'):
    env['BASH_ENV'] = os.environ['COREUTILS_LOAD_ENV']
checks=0

def run(args, rc=0, script='coreutils install "$@"'):
    global checks
    p=subprocess.run([binary,'-c',script,'_',*map(str,args)],env=env,capture_output=True,timeout=20)
    assert p.returncode==rc,(args,p.returncode,p.stderr)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr,p.stderr
    checks+=1
    return p

with tempfile.TemporaryDirectory(prefix='coreutils-fastpaths-') as tmp:
    d=Path(tmp);src=d/'source';dst=d/'installed'
    for length in [0,1,8191,8192,8193,65535,65536,131071,131072,131073,1048583]:
        data=(bytes(range(256)) * ((length+255)//256))[:length]
        src.write_bytes(data)
        for mode in [0o600,0o644,0o755]:
            dst.write_bytes(b'existing destination content')
            inode=dst.stat().st_ino
            run(['-m',format(mode,'o'),src,dst])
            assert dst.read_bytes()==data
            assert stat.S_IMODE(dst.stat().st_mode)==mode
            assert dst.stat().st_ino==inode
    src.write_bytes(b'new data\x00\xff\n')
    link=d/'hardlink';os.link(dst,link)
    run(['-m','600',src,dst]);assert link.read_bytes()==src.read_bytes()
    symbolic=d/'symlink';symbolic.symlink_to(dst)
    run(['-m','644',src,symbolic]);assert symbolic.is_symlink() and dst.read_bytes()==src.read_bytes()
    run(['-D','-m','755',src,d/'nested/sub/output']);assert (d/'nested/sub/output').read_bytes()==src.read_bytes()
    run(['-d','-m','700',d/'new/deep']);assert stat.S_IMODE((d/'new/deep').stat().st_mode)==0o700
    run(['-m','644',d/'absent',dst],rc=1)
    run(['-m','644',src,d/'missing/output'],rc=1)
    data=bytes(range(256))*1025+b'last'
    fifo=d/'pipe';os.mkfifo(fifo)
    errors=[]
    def send():
        try:
            with fifo.open('wb') as f:f.write(data)
        except BaseException as e:errors.append(e)
    t=threading.Thread(target=send);t.start()
    run(['-m','640',fifo,dst]);t.join(timeout=2)
    assert not t.is_alive() and not errors and dst.read_bytes()==data
    # Repeated calls reopen the operands and preserve surrounding Bash output.
    p=run([src,dst],script='printf before; coreutils install -m 644 "$1" "$2"; coreutils install -m 644 "$1" "$2"; printf after')
    assert p.stdout==b'beforeafter' and dst.read_bytes()==src.read_bytes()
    install_checks = checks

    def fmt(data, expected, width=5, file_input=False):
        global checks
        src.write_bytes(data)
        command = ['coreutils', 'fmt', '-w', str(width)]
        if file_input:
            command.append(str(src))
        p = subprocess.run([binary, '-c', '"$@"', '_', *command],
                           env=env, input=data, capture_output=True, timeout=20)
        assert (p.returncode, p.stdout) == (0, expected), (
            width, len(data), p.returncode, p.stderr, p.stdout[:80], expected[:80])
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        checks += 1

    # Every word exceeds half the width: these independent expectations force
    # one word per output line without duplicating the optimal-cost algorithm.
    fmt(b'', b'')
    fmt(b'alpha beta gamma', b'alpha\nbeta\ngamma\n')
    fmt(b' \talpha beta\n', b' \talpha\n \tbeta\n')
    for count in [1, 63, 64, 65, 127, 128, 129]:
        fmt(b'abcdef ' * count + b'\n', b'abcdef\n' * count,
            file_input=bool(count % 2))
    fmt(b'x' * 65536 + b' beta\n', b'x' * 65536 + b'\nbeta\n', file_input=True)

    # Paragraphs grow, reuse, shrink and grow the same arrays. Prefix state
    # resets at each blank separator; an empty separator run stays collapsed.
    data = b'  ' + b'abcdef ' * 129 + b'\n\n\n' + b'zulu\n\n' + b'\t' + b'ghijkl ' * 65
    expected = b'  abcdef\n' * 129 + b'\n' + b'zulu\n\n' + b'\tghijkl\n' * 65
    fmt(data, expected)
    fmt(data, expected, file_input=True)
    src.write_bytes(b'alpha beta\n')
    p = run([src], script='printf before; coreutils fmt -w 5 "$1" "$1"; coreutils fmt -w 5 "$1"; printf after')
    assert p.stdout == b'before' + b'alpha\nbeta\n' * 3 + b'after'

print(f'coreutils-fastpaths: {checks} checks passed ({install_checks} install, {checks-install_checks} fmt)')
