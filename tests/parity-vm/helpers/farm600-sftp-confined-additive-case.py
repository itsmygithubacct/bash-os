#!/usr/bin/python3
"""Guest-only setup and observation utilities for confined SFTP cases."""
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import runpy
import stat
import subprocess
import sys
import time

CASE = Path('/tmp/parity-case'); HOME = Path('/tmp/parity-home')
GUARD = Path('/opt/bashos-parity/harness/helpers/ns_guest_identity_r1.py')
GUARD_SHA = 'a74d97058d313388948010d1033f50dde7151c2d204d221ed3aeb4da3e9e1762'
SERVER = '/opt/bashos-parity/harness/helpers/farm600-sftp-confined-additive-server.py'
LIFEPATH = '/opt/bashos-parity/harness/helpers/farm600-sftp-confined-additive-lifecycle.py'
PAYLOAD = bytes(range(256))


def guard():
    if hashlib.sha256(GUARD.read_bytes()).hexdigest() != GUARD_SHA: raise ValueError('guard digest')
    runpy.run_path(str(GUARD))['verify']()
    if os.getuid() != 2000 or os.geteuid() != 2000: raise ValueError('uid')
    for p in (CASE, HOME):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 2000 or s.st_mode & 0o022: raise ValueError('scratch')


def b64(data): return base64.b64encode(data).decode('ascii')


def current_umask():
    previous = os.umask(0o077); os.umask(previous)
    return format(previous, '04o')


def metadata(path):
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 2000 or st.st_nlink != 1 or st.st_size > 65536:
            return {'invalid': True, 'mode': st.st_mode, 'size': st.st_size}
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            def fingerprint(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if fingerprint(st) != fingerprint(before):
                return {'invalid': True, 'reason': 'file changed before read'}
            data = bytearray()
            while len(data) <= 65536:
                part = os.read(fd, 65537 - len(data))
                if not part: break
                data.extend(part)
            after = os.fstat(fd)
            if fingerprint(before) != fingerprint(after) or len(data) != before.st_size:
                return {'invalid': True, 'reason': 'file changed or read incomplete'}
        finally: os.close(fd)
        return {'base64': b64(bytes(data)), 'mode': stat.S_IMODE(before.st_mode), 'dev': before.st_dev,
                'ino': before.st_ino, 'nlink': before.st_nlink, 'size': before.st_size}
    except FileNotFoundError: return {'missing': True}


def save(name, data):
    (HOME / ('sftp-confined-' + name + '.json')).write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')


def setup(op, form):
    if op not in ('put', 'get') or form not in ('quoted', 'escaped'): raise ValueError('case')
    root = CASE / 'sftp-confined-remote'; root.mkdir(mode=0o700)
    (root / 'remote get.bin').write_bytes(PAYLOAD)
    (CASE / 'local payload.bin').write_bytes(PAYLOAD)
    if form == 'quoted':
        line = 'put "local payload.bin" "remote put.bin"' if op == 'put' else 'get "remote get.bin" "local result.bin"'
    else:
        line = r'put local\ payload.bin remote\ put.bin' if op == 'put' else r'get remote\ get.bin local\ result.bin'
    (CASE / 'sftp-confined.batch').write_text(line + '\nbye\n')
    adapter = CASE / 'sftp-confined-adapter'
    adapter.write_text('#!/bin/sh\nexec /usr/bin/python3 -I ' + SERVER + ' sftp "$@"\n')
    adapter.chmod(0o700)
    save('setup', {'op': op, 'form': form, 'identity': identity(), 'umask': current_umask(), 'remote_root': 'sftp-confined-remote',
                   'batch_base64': b64((CASE / 'sftp-confined.batch').read_bytes()),
                   'adapter_sha256': hashlib.sha256(adapter.read_bytes()).hexdigest(),
                   'sentinel': metadata(CASE / 'sftp-confined-external' / 'sentinel'),
                   'payload_base64': b64(PAYLOAD)})


def identity():
    return {'token': Path('/etc/bashos-parity-vm').read_text().strip(), 'uid': os.getuid(),
            'euid': os.geteuid(), 'cwd': os.getcwd(), 'home': os.environ.get('HOME')}


def snapshot(side, stage, status):
    if side not in ('candidate', 'reference') or stage not in ('before', 'after'): raise ValueError('snapshot')
    root = CASE / 'sftp-confined-remote'
    names = sorted(p.name for p in root.iterdir())
    local_names = sorted(p.name for p in CASE.iterdir())
    if len(names) > 64 or len(local_names) > 128: raise ValueError('directory entry limit')
    observation = {'status': status, 'identity': identity(), 'umask': current_umask(), 'remote_root': 'sftp-confined-remote',
        'remote_entries': {name: metadata(root / name) for name in names}, 'case_entries': local_names,
        'batch': metadata(CASE / 'sftp-confined.batch'),
        'local_input': metadata(CASE / 'local payload.bin'),
        'local_result': metadata(CASE / 'local result.bin'),
        'remote_get': metadata(root / 'remote get.bin'), 'remote_put': metadata(root / 'remote put.bin'),
        'sentinel': metadata(CASE / 'sftp-confined-external' / 'sentinel')}
    if stage == 'after':
        # Saved before the candidate waits for the peer. These records are
        # point-in-time observations, not proof of final writer quiescence.
        observation['client_stdout'] = metadata(HOME / 'sftp-confined-client.stdout')
        observation['client_stderr'] = metadata(HOME / 'sftp-confined-client.stderr')
        if side == 'candidate':
            observation['builtin_status'] = metadata(HOME / 'sftp-confined-client.status')
    save(side + '-' + stage, observation)


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    os.umask(0o077)


def reference():
    snapshot('reference', 'before', 'not-started')
    life = runpy.run_path(LIFEPATH); life['prepare'](); life['before_spawn']()
    env = dict(os.environ, SFTP_CONFINED_ROOT='remote', SFTP_CONFINED_LOG='reference', PATH='/usr/bin:/bin')
    outpath = HOME / 'sftp-confined-client.stdout'; errpath = HOME / 'sftp-confined-client.stderr'
    started = time.monotonic_ns(); lifecycle = {'started_ns': started}
    with outpath.open('wb') as out, errpath.open('wb') as err:
        p = life['spawn'](['/usr/bin/sftp', '-b', 'sftp-confined.batch', '-S', str(CASE / 'sftp-confined-adapter'), 'fixture'],
                             stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env,
                             start_new_session=True, preexec_fn=child_limits)
        lifecycle['pid'] = p.pid
        lifecycle['observation'] = life['finish'](p, timeout=12)
        lifecycle['status'] = lifecycle['observation']['rc']
    lifecycle['finished_ns'] = time.monotonic_ns()
    save('reference-process', lifecycle)
    snapshot('reference', 'after', lifecycle['status'])
    print('status=%s' % lifecycle['status'])
    if not lifecycle['observation']['complete'] or lifecycle['observation']['forced']: raise SystemExit(125)


def main():
    guard()
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == 'setup': setup(args[1], args[2])
    elif len(args) == 4 and args[0] == 'snapshot': snapshot(args[1], args[2], int(args[3]))
    elif args == ['reference']: reference()
    elif args == ['guard']: pass
    else: raise ValueError('arguments')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('confined case: ' + repr(exc), file=sys.stderr); sys.exit(125)
