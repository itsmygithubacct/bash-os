#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Bounded guest-only framed SFTP observer and listing checks."""
import base64
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import uuid

C = Path('/tmp/parity-case')
H = Path('/tmp/parity-home')
ROOT = C / 'remote'
CAP = 4096
COMMANDS = [b'pwd', b"cd '/fixture' && cd 'space dir' && pwd",
            b"cd '/fixture/space dir' && ls -la"]


def protected(path):
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError('identity parent is not protected')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444 or info.st_size != 37):
            raise ValueError('identity file metadata differs')
        raw = os.read(fd, 38)
    finally:
        os.close(fd)
    if len(raw) != 37 or raw[-1:] != b'\n': raise ValueError('identity length differs')
    token = raw[:-1].decode('ascii')
    if str(uuid.UUID(token)) != token: raise ValueError('identity is not canonical')
    return token


def guard():
    token = protected(Path('/etc/bashos-parity-vm'))
    if protected(Path('/run/bashos-parity-vm-identity')) != token:
        raise ValueError('controller identity mismatch')
    if (os.getuid() != 2000 or os.geteuid() != 2000 or Path.cwd().resolve() != C
            or os.environ.get('HOME') != str(H)):
        raise ValueError('guest credentials or scratch context differs')
    for p in (C, H):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 2000 or s.st_mode & 0o022:
            raise ValueError('scratch ownership differs')
    return {'token': token, 'uid': os.getuid(), 'euid': os.geteuid(), 'cwd': str(C), 'home': str(H)}


def save(name, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(data) > 262144: raise ValueError('record limit')
    (H / name).write_bytes(data)


def exact(sock, n, captured):
    while n:
        piece = sock.recv(min(n, CAP))
        if not piece: return False
        captured.extend(piece)
        n -= len(piece)
    return True


def event(label, **record):
    with (H / ('peer-' + label + '.jsonl')).open('a', encoding='utf-8') as f:
        f.write(json.dumps(record, sort_keys=True) + '\n')


def peer(label, count):
    identity = guard()
    for p in (ROOT, ROOT / 'space dir', ROOT / 'other'):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 2000: raise ValueError('invalid fixture tree')
    event(label, event='identity', identity=identity)
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0)); server.listen(4); server.settimeout(12)
        fd, tmp = tempfile.mkstemp(prefix='.sftp-ready-', dir=H)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({'pid': os.getpid(), 'address': '127.0.0.1', 'port': server.getsockname()[1]}, f)
                f.write('\n'); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, H / ('ready-' + label + '.json'))
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        for index in range(count):
            conn, addr = server.accept()
            with conn:
                conn.settimeout(4)
                raw = bytearray(); header = bytearray(); complete = False; trailing = bytearray()
                try:
                    while not header.endswith(b'\n\n'):
                        part = conn.recv(1)
                        if not part: break
                        header.extend(part); raw.extend(part)
                        if len(header) > 512: raise ValueError('header limit')
                    if not header.endswith(b'\n\n'):
                        event(label, event='request', index=index, raw=base64.b64encode(raw).decode(),
                              complete=False, reason='short-header', peer=list(addr)); continue
                    lines = bytes(header[:-2]).split(b'\n')
                    if len(lines) != 3 or lines[0] != b'BASHSSH1' or not lines[1].startswith(b'cmd-len ') or not lines[2].startswith(b'stdin-len '):
                        raise ValueError('bad frame header')
                    cmdlen = int(lines[1][8:]); inlen = int(lines[2][10:])
                    if not 0 <= cmdlen <= 512 or not 0 <= inlen <= CAP: raise ValueError('frame length limit')
                    body = bytearray()
                    try:
                        body_complete = exact(conn, cmdlen + inlen, body)
                    finally:
                        raw.extend(body)
                    if not body_complete:
                        event(label, event='request', index=index, raw=base64.b64encode(raw).decode(),
                              complete=False, reason='short-body', peer=list(addr)); continue
                    cmd = bytes(body[:cmdlen]); data = bytes(body[cmdlen:])
                    rc = 0; err = b''
                    if data: rc, out, err = 127, b'', b'unexpected stdin\n'
                    elif cmd == COMMANDS[0]: out = b'/fixture\n'
                    elif cmd == COMMANDS[1]: out = b'/fixture/space dir\n'
                    elif cmd == COMMANDS[2]:
                        entries = sorted(ROOT.joinpath('space dir').iterdir())
                        if any(not stat.S_ISREG(x.lstat().st_mode) for x in entries): raise ValueError('bad listing tree')
                        out = b''.join(x.name.encode('utf-8') + b'\n' for x in entries)
                    else: rc, out, err = 127, b'', b'unsupported command\n'
                    reply = b'BASHSSH1-RESP\nrc %d\nstdout-len %d\nstderr-len %d\n\n' % (rc, len(out), len(err)) + out + err
                    conn.sendall(reply)
                    while True:
                        part = conn.recv(CAP + 1 - len(trailing))
                        if not part: complete = True; break
                        trailing.extend(part)
                        if len(trailing) > CAP: raise ValueError('trailing bytes limit')
                    raw.extend(trailing)
                    event(label, event='request', index=index, raw=base64.b64encode(raw).decode(),
                          header=base64.b64encode(header).decode(), command=base64.b64encode(cmd).decode(),
                          stdin=base64.b64encode(data).decode(), trailing=base64.b64encode(trailing).decode(),
                          response=base64.b64encode(reply).decode(), rc=rc, complete=complete, peer=list(addr))
                except (OSError, ValueError) as exc:
                    event(label, event='peer-error', index=index, error=repr(exc),
                          raw=base64.b64encode(raw + trailing).decode(), complete=False)
                    raise
    event(label, event='finished', requests=count)


def listing(kind, data):
    if len(data) > 131072: raise ValueError('client output limit')
    if kind == 'candidate':
        prefix = b'Remote working directory: /fixture\n'
        return data == prefix + b'selected-needle\n'
    elif kind == 'reference':
        marker = b'sftp> ls\n'
        if data.count(marker) != 1: return False
        section = data.split(marker, 1)[1]
        if b'sftp> bye' not in section: return False
        section = section.split(b'sftp> bye', 1)[0]
    else: raise ValueError('invalid listing kind')
    return section.endswith(b'\n') and len(section.splitlines()) == 1 and section.strip() == b'selected-needle'


def listing_selftest():
    positive = [('candidate', b'Remote working directory: /fixture\nselected-needle\n'),
                ('reference', b'sftp> cd "space dir"\nsftp> ls\nselected-needle  \nsftp> bye\n')]
    negative = [('candidate', b'Remote working directory: /fixture\nnot-selected-needle\n'),
                ('candidate', b'Remote working directory: /fixture\nselected-needle-corrupt\n'),
                ('candidate', b'Remote working directory: /fixture\nselected-needle'),
                ('reference', b'selected-needle\nsftp> ls\nnot-selected-needle\nsftp> bye\n'),
                ('reference', b'sftp> ls\nselected-needle-corrupt\nsftp> bye\n')]
    if not all(listing(k, x) for k, x in positive) or any(listing(k, x) for k, x in negative):
        raise ValueError('listing control failed')
    return {'positive': [{'kind': k, 'base64': base64.b64encode(x).decode(), 'result': listing(k, x)} for k, x in positive],
            'negative': [{'kind': k, 'base64': base64.b64encode(x).decode(), 'result': listing(k, x)} for k, x in negative],
            'passed': True}


def controls():
    result = {'identity': guard(), 'listing_selftest': listing_selftest(), 'peers': {}}
    for label, count in (('valid', 3), ('extra', 1), ('short', 1)):
        rows = [json.loads(x) for x in (H / ('peer-' + label + '.jsonl')).read_text().splitlines()]
        ready = json.loads((H / ('ready-' + label + '.json')).read_text())
        requests = [x for x in rows if x.get('event') == 'request']
        pid = int((H / ('control-' + label + '.pid')).read_text())
        stdout = (H / ('control-' + label + '.out')).read_bytes()
        stderr = (H / ('control-' + label + '.err')).read_bytes()
        peer_stdout = (H / ('peer-' + label + '.stdout')).read_bytes()
        peer_stderr = (H / ('peer-' + label + '.stderr')).read_bytes()
        if peer_stdout or peer_stderr: raise ValueError('peer control diagnostics differ')
        if ready.get('pid') != pid or ready.get('address') != '127.0.0.1' or stdout != ('control=' + label + ' complete\n').encode() or stderr:
            raise ValueError('control client or ready identity differs')
        if (len(requests) != count or rows[0].get('event') != 'identity'
                or rows[-1] != {'event': 'finished', 'requests': count}
                or any(x.get('event') == 'peer-error' for x in rows)):
            raise ValueError('incomplete peer control ' + label)
        if label == 'valid':
            for index, r in enumerate(requests):
                if (not r.get('complete') or base64.b64decode(r['command'], validate=True) != COMMANDS[index]
                        or r['stdin'] or r['trailing'] or r['rc'] != 0): raise ValueError('valid control differs')
        elif label == 'extra':
            if not requests[0].get('complete') or base64.b64decode(requests[0]['trailing'], validate=True) != b'extra':
                raise ValueError('extra-byte control differs')
        elif requests[0].get('complete') is not False or requests[0].get('reason') != 'short-body':
            raise ValueError('short-frame control differs')
        result['peers'][label] = {'ready': ready, 'pid': pid, 'events': rows,
                                  'client_stdout': base64.b64encode(stdout).decode(),
                                  'client_stderr': base64.b64encode(stderr).decode(),
                                  'peer_stdout': base64.b64encode(peer_stdout).decode(),
                                  'peer_stderr': base64.b64encode(peer_stderr).decode()}
    save('native-controls.json', result)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'guard' and sys.argv[2] in ('setup', 'candidate', 'reference'):
        save('guard-' + sys.argv[2] + '.json', guard()); return
    if len(sys.argv) == 4 and sys.argv[1] == 'peer' and sys.argv[2] in ('valid', 'extra', 'short', 'case'):
        peer(sys.argv[2], int(sys.argv[3])); return
    if sys.argv[1:] == ['controls']:
        controls(); return
    if len(sys.argv) == 3 and sys.argv[1] == 'listing' and sys.argv[2] in ('candidate', 'reference', 'control'):
        guard(); kind = 'reference' if sys.argv[2] == 'control' else sys.argv[2]
        path = H / ('nav-control.out' if sys.argv[2] == 'control' else 'client.stdout')
        print('listing=%d' % listing(kind, path.read_bytes())); return
    raise ValueError('invalid invocation')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, UnicodeError, KeyError) as exc:
        print('SFTP fixture: ' + repr(exc), file=sys.stderr); sys.exit(125)
