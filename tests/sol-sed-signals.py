#!/usr/bin/env python3
"""Signal responsiveness of owned sed processes; no unrelated PID is signalled."""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C')
checks = failures = 0
for script,data in [('p',b''), ('$p',b'a\n'), (':loop;b loop',b'a\n')]:
    for sig in (signal.SIGINT,signal.SIGTERM):
        p=subprocess.Popen([binary,'-c','printf "ready\\n"; sed "$1"','_',script],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:
            assert select.select([p.stdout],[],[],5)[0], 'shell did not start'
            assert p.stdout.readline()==b'ready\n'
            p.stdin.write(data);p.stdin.flush()
            # Allow entry into the blocking read/lookahead or branch loop. This
            # is a correctness deadline, not a throughput or latency sample.
            time.sleep(.1)
            p.send_signal(sig)
            try:
                p.wait(timeout=5)
                ok=p.returncode in (-sig,128+sig)
            except subprocess.TimeoutExpired:
                ok=False
            checks+=1
            if not ok:
                failures+=1;print('FAIL',script,sig,p.returncode,flush=True)
            if p.poll() is None:p.kill();p.wait()
            err=p.stderr.read()
            assert b'AddressSanitizer' not in err and b'runtime error:' not in err, err
        finally:
            if p.poll() is None:p.kill();p.wait()
            p.stdin.close();p.stdout.close();p.stderr.close()
# A trapped signal must return control to the persistent shell; each owned
# input/write stream must be closed before the trap and the next invocation.
for script,data in [('p',b''), ('$p',b'a\n'), (':loop;b loop',b'a\n')]:
    for sig in (signal.SIGINT,signal.SIGTERM):
        program = """trap 'printf "trapped\\n"' INT TERM
before=(/proc/$$/fd/*)
printf 'ready\\n'
sed "$1"
rc=$?
after=(/proc/$$/fd/*)
[[ ${#before[@]} == ${#after[@]} ]] || exit 90
printf 'status:%s\\n' "$rc"
sed s/a/A/ <<< a
printf 'done\\n'
"""
        p=subprocess.Popen([binary,'-c',program,'_',script],stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:
            assert select.select([p.stdout],[],[],5)[0]
            assert p.stdout.readline()==b'ready\n'
            p.stdin.write(data);p.stdin.flush();time.sleep(.1);p.send_signal(sig)
            try:
                p.wait(timeout=5)
                out=p.stdout.read();err=p.stderr.read()
                expected=f'trapped\nstatus:{128+sig}\nA\ndone\n'.encode()
                ok=p.returncode==0 and out==expected
                assert b'AddressSanitizer' not in err and b'runtime error:' not in err,err
            except subprocess.TimeoutExpired:
                ok=False;out=b'<timeout>'
            checks+=1
            if not ok:
                failures+=1;print('FAIL trapped',script,sig,p.returncode,repr(out),flush=True)
        finally:
            if p.poll() is None:p.kill();p.wait()
            p.stdin.close();p.stdout.close();p.stderr.close()
print(f'sol-sed-signals: {checks} checks, {failures} failures')
raise SystemExit(bool(failures))
