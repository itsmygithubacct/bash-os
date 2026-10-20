#!/usr/bin/env python3
"""Strict GNU oracle for canonical EOF before already queued terminal data.

Keep this check strict even where the kernel has no nonconsuming terminal
peek API. Failure is a qualification limit, not a skipped or passing case.
"""
import os
from pathlib import Path
import pty
import subprocess
import sys
import termios

binary=str(Path(sys.argv[1]).resolve())
results=[]
for cmd in ([binary,'-c',"sed -n '$p;1q'"], ['/usr/bin/sed','-n','$p;1q']):
    m,s=pty.openpty()
    attrs=termios.tcgetattr(s);attrs[3]&=~termios.ECHO
    termios.tcsetattr(s,termios.TCSANOW,attrs)
    try:
        os.write(m,b'a\n\x04b\n')
        p=subprocess.run(cmd,stdin=s,capture_output=True,timeout=5,
                         env=dict(os.environ,PATH='',LC_ALL='C'))
        results.append((p.returncode,p.stdout))
    finally:
        os.close(m);os.close(s)
print('canonical EOF followed by queued data:',repr(results),flush=True)
assert results[0]==results[1], 'terminal readiness/byte count cannot expose the EOF marker before queued data'
