#!/usr/bin/env python3
"""Native sudo listing through private files and an injected authority only."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
p = argparse.ArgumentParser()
p.add_argument('--shell', type=Path, required=True)
p.add_argument('--preload', type=Path, required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='astra-sudo-list-') as tmp:
    d = Path(tmp)
    policy = d/'policy'
    passwd = d/'passwd'
    passwd.write_text(f'reviewcaller:x:{os.getuid()}:{os.getgid()}:Review:{d}:/bin/sh\n')
    valid = 'User_Alias OPS = reviewcaller\nCmnd_Alias CMDS = /bin/true, /bin/echo\nOPS ALL = (root) NOPASSWD: CMDS\nother ALL = (root) /private/other-only\n'
    policy.write_text(valid)
    policy.chmod(0o644)
    env = {**os.environ, 'LD_PRELOAD':str(a.preload.resolve()),
           'SUDO_LIST_TEST_POLICY':str(policy), 'SUDO_LIST_TEST_PASSWD':str(passwd),
           'BASHSUDO_EXTERNAL':'', 'BASHDOAS_EXTERNAL':'', 'LC_ALL':'C'}
    def run(script, rc=0, extra=None):
        q = subprocess.run([str(a.shell.resolve()), '--noprofile', '--norc', '-c', 'PATH=; '+script],
                           env={**env, **(extra or {})}, capture_output=True, timeout=20)
        assert q.returncode == rc, (script,q.returncode,q.stdout,q.stderr)
        return q
    for opt in ['-l','--list','-nl','-ll']:
        q = run('sudo '+opt)
        assert b'not an execution approval' in q.stdout and b'other-only' not in q.stdout
        assert (b'summary entries=2' if opt=='-ll' else b'summary entries=1') in q.stdout
        assert b'user=reviewcaller' in q.stdout and not q.stderr
    for fault in ['digest','drift']:
        q = run('sudo -l',1,{'SUDO_LIST_TEST_FAULT':fault}); assert not q.stdout
    for text in ['invalid policy\n', 'other ALL = (root) /bin/true\n', '']:
        policy.write_text(text)
        q = run('sudo -l',1)
        assert b'list user=' not in q.stdout and b'entry user=' not in q.stdout
    policy.write_bytes(b'ALL ALL = (root) /bin/true\x00hidden\n')
    q = run('sudo -l', 1); assert not q.stdout
    policy.write_text(valid)
    saved_policy = d/'saved-policy'
    policy.rename(saved_policy); policy.symlink_to(saved_policy)
    q = run('sudo -l', 1); assert not q.stdout
    policy.unlink(); saved_policy.rename(policy)
    for args in ['-l -u root','-l /bin/true','-kl','-l A=1']:
        run('sudo '+args,2)
    policy.chmod(0o666); q=run('sudo -l',1); assert not q.stdout
    policy.chmod(0o644)
    q=run('sudo -l >/dev/full; a=$?; sudo -l >/dev/null; b=$?; printf "%s %s" "$a" "$b"')
    assert q.stdout==b'1 0',q
    q=run('before=(/proc/$$/fd/*); for ((i=0;i<50;i++)); do sudo -l >/dev/null || exit; done; after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]')
print('native listing: private metadata, real parser/dispatcher, formats, filtering, failures and repeated FD cleanup passed; no authentication')
