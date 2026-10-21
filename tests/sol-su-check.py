#!/usr/bin/env python3
"""Noncompiling su checks. Build sol-su-fixture.c separately through the gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import resource
import select
import signal
import subprocess
import sys
import tempfile
import termios
import fcntl

p = argparse.ArgumentParser()
p.add_argument('--fixture', type=Path)
p.add_argument('--shell', type=Path)
p.add_argument('--oracle', action='store_true', help='require independent argon2-cffi verification')
a = p.parse_args()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
assert a.fixture or a.shell

def private_pty(argv, expected, env=None, cancel=False):
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    def session():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                            env=env, preexec_fn=session)
    output = b''
    try:
        while b'Password: ' not in output:
            assert select.select([master], [], [], 10)[0], output
            output += os.read(master, 4096)
        assert not termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ICANON)
        if cancel:
            children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
            assert len(children) == 1, children
            os.kill(int(children[0]), signal.SIGTERM)
        else:
            os.write(master, b'fixture-password\n')
        assert proc.wait(timeout=20) == expected
        while select.select([master], [], [], 0)[0]:
            output += os.read(master, 4096)
        assert b'fixture-password' not in output, output
        assert termios.tcgetattr(slave) == original, (original, termios.tcgetattr(slave))
        return output
    finally:
        if proc.poll() is None:
            proc.kill(); proc.wait()
        os.close(master); os.close(slave)

if a.fixture:
    fixture = a.fixture.resolve()
    proc = subprocess.run([str(fixture)], capture_output=True, timeout=60)
    print(proc.stdout.decode(), proc.stderr.decode(), flush=True)
    assert proc.returncode == 0, proc.returncode
    phc = subprocess.check_output([str(fixture), '--phc'], text=True).strip()
    if a.oracle:
        oracle_path = os.environ.get('SOL_SU_ORACLE_PATH')
        if oracle_path:
            sys.path.insert(0, oracle_path)
        from argon2.low_level import hash_secret_raw, Type
        from importlib.metadata import version
        expected = hash_secret_raw(b'fixture-password', b'fixture-salt', 1, 1024, 1, 32, Type.ID).hex()
        assert phc == '$argon2id$v=19$m=1024,t=1,p=1$'+b'fixture-salt'.hex()+'$'+expected
        print('independent libargon2 PHC oracle passed; argon2-cffi', version('argon2-cffi'))
    output = private_pty([str(fixture), '--pty'], 0)
    assert b'pty passed' in output, output
    print('owned PTY password: echo disabled, real read, PHC verified, terminal restored, secret wiped')
    output = private_pty([str(fixture), '--pty-cancel'], 0, cancel=True)
    assert b'pty passed' in output, output
    print('owned PTY cancellation: child SIGTERM status 143, parent restores echo and terminal settings')

if a.shell:
    shell = str(a.shell.resolve())
    with tempfile.TemporaryDirectory(prefix='sol-su-native-') as tmp:
        tmp = Path(tmp)
        (tmp/'passwd').write_text('fixture:x:4242:4343:Fixture:'+str(tmp)+':/bin/sh\n')
        (tmp/'shadow').write_text('fixture:!:20000:0:99999:7:::\n')
        env = {**os.environ, 'PHCLIB_PASSWD':str(tmp/'passwd'), 'PHCLIB_SHADOW':str(tmp/'shadow'),
               'BPW_LOCK_DIR':str(tmp/'locks'), 'LC_ALL':'C', 'SOL_SU_TRAP_FILE':str(tmp/'trap')}
        def run(script, rc=0):
            q = subprocess.run([shell, '--noprofile', '--norc', '-c', 'PATH=; '+script],
                               capture_output=True, env=env, timeout=60)
            assert q.returncode == rc, (script, q.returncode, q.stdout, q.stderr)
            return q
        for args in ['--invalid', '-c', '../bad', '-- fixture extra', 'fixture extra']:
            run('su '+args, 2)
        run('su --help >/dev/full', 1)
        assert b'Switch user' in run('su --help >/dev/full; su --help').stdout
        if os.getuid() != 0:
            run('su fixture', 2)
            # Fast owned child failures, preserving unrelated jobs, fd, trap, cwd.
            script = '''exec 200</dev/null
trap ':' CHLD
trap -p CHLD > "$SOL_SU_TRAP_FILE"
read -r saved < "$SOL_SU_TRAP_FILE"; old=$PWD
for ((i=0;i<200;i++)); do
  (exit 41) & bg=$!
  su fixture 2>/dev/null; [[ $? == 2 ]] || exit 90
  wait "$bg"; [[ $? == 41 ]] || exit 91
  trap -p CHLD > "$SOL_SU_TRAP_FILE"
  read -r current < "$SOL_SU_TRAP_FILE"
  [[ $current == "$saved" && $PWD == "$old" && -r /proc/$$/fd/200 ]] || exit 92
done
'''
            run(script)
            print('200 repeated native child failures preserve parent FD, directory, CHLD trap and job status')
            if a.fixture and not Path('/dev/bashos-auth').exists():
                (tmp/'shadow').write_text('fixture:'+phc+':20000:0:99999:7:::\n')
                output = private_pty([shell, '--noprofile', '--norc', '-c', 'PATH=; su --no-login -c "exit 37" fixture'], 1, env)
                assert b'kernel auth:' in output and b'/dev/bashos-auth' in output, output
                print('native successful password verification reaches missing-authority denial through owned PTY')
                private_pty([shell, '--noprofile', '--norc', '-c', 'PATH=; su fixture'], 143, env, cancel=True)
                print('native canceled password child returns 143 and parent restores terminal')
        print('native parsing, empty PATH and repeated help/output-failure checks passed')
print('GAP: live /dev/bashos-auth mint/consume and privileged target transition remain unqualified')
