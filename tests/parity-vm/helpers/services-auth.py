#!/usr/bin/python3
"""Guest-only LDAP-provider recorder and bounded owned-descendant observer."""
import base64
import json
import os
from pathlib import Path
import signal
import sys
import time
import uuid


def require_guest():
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        case, home = Path('/tmp/parity-case'), Path('/tmp/parity-home')
        if (str(uuid.UUID(marker)) != marker.lower()
                or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.getuid() != 2000 or os.geteuid() != 2000
                or os.environ.get('HOME') != str(home) or Path.cwd().resolve() != case
                or case.stat().st_uid != 2000 or home.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('requires disposable parity guest: ' + str(exc))


def proc(pid):
    try:
        p = Path('/proc') / str(pid)
        st = p.stat()
        f = (p / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid':pid, 'uid':st.st_uid, 'state':f[0], 'ppid':int(f[1]),
                'pgid':int(f[2]), 'starttime':int(f[19])}
    except (OSError, ValueError, IndexError):
        return None


def read_events(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def check(kind):
    home = Path('/tmp/parity-home')
    events = read_events(home/'ldap.events')
    ok = len(events) == 1
    e = events[0] if events else {}
    expected_user = {'normal':'external','oversize':'oversize','timeout':'timeout','complete':'complete'}[kind]
    ok &= e.get('argv') == [str(home/'ldap-provider'), 'verify', expected_user]
    ok &= e.get('fd_env') == '3' and e.get('fd_read_base64') == base64.b64encode(b'fixture-password\n').decode()
    ok &= e.get('pid') == e.get('pgid') and 'fixture-password' not in e.get('argv', [])
    if kind == 'oversize':
        ok &= e.get('response_base64') == base64.b64encode(b'X'*5000).decode()
    if kind in ('timeout','complete'):
        child = e.get('child') or {}
        seen = None
        for _ in range(20):
            seen = proc(child.get('pid', -1))
            if seen is None or seen['state'] == 'Z' or seen['starttime'] != child.get('starttime'):
                break
            time.sleep(.05)
        live = bool(seen and seen['state'] != 'Z' and seen['starttime'] == child.get('starttime'))
        parent_seen = proc(e.get('pid', -1))
        parent_live = bool(parent_seen and parent_seen['state'] != 'Z' and parent_seen['starttime'] == e.get('provider_starttime'))
        observation = {'recorded_provider_pid':e.get('pid'), 'recorded_provider_starttime':e.get('provider_starttime'),
                       'observed_provider':parent_seen, 'provider_live':parent_live,
                       'recorded_child':child, 'observed_child':seen, 'live_before_cleanup':live,
                       'cleanup_attempted':False}
        ok &= not live and not parent_live
        if live and seen['uid'] == 2000 and seen['pgid'] == e.get('pgid'):
            # The saved PID, start time, uid and fixture-owned process group must all match.
            try:
                os.kill(seen['pid'], signal.SIGKILL)
                observation['cleanup_attempted'] = True
                for _ in range(40):
                    current = proc(seen['pid'])
                    if current is None or current['state'] == 'Z' or current['starttime'] != seen['starttime']:
                        break
                    time.sleep(.05)
                observation['after_cleanup'] = proc(seen['pid'])
            except ProcessLookupError:
                pass
        (home/'child-observation.json').write_text(json.dumps(observation, indent=2)+'\n')
    print('provider-observation=' + ('ok' if ok else 'BAD'))


def provider():
    home=Path('/tmp/parity-home')
    if len(sys.argv) != 3 or sys.argv[1] != 'verify':
        raise SystemExit('unexpected provider arguments')
    user=sys.argv[2]
    if user not in ('external','oversize','timeout','complete','control'):
        raise SystemExit('unexpected provider user')
    try:
        pieces=[]
        while sum(map(len,pieces)) < 4096:
            data=os.read(3, 4096)
            if not data: break
            pieces.append(data)
        pw=b''.join(pieces); error=''
    except OSError as exc:
        pw=b''; error=str(exc)
    child=None
    if user in ('timeout','complete'):
        r,w=os.pipe()
        pid=os.fork()
        if pid == 0:
            os.close(r); os.write(w,b'R'); os.close(w)
            time.sleep(20)
            os._exit(0)
        os.close(w); os.read(r,1); os.close(r)
        child=proc(pid)
    response=b'X'*5000 if user == 'oversize' else b''
    event={'argv':sys.argv,'pid':os.getpid(),'pgid':os.getpgrp(),'fd_env':os.environ.get('BASHUSERDB_VERIFY_FD'),
           'fd_read_base64':base64.b64encode(pw).decode(), 'read_error':error, 'child':child,
           'response_base64':base64.b64encode(response).decode(), 'time_monotonic':time.monotonic(),
           'provider_starttime':proc(os.getpid())['starttime']}
    with (home/'ldap.events').open('a') as f: f.write(json.dumps(event,sort_keys=True)+'\n')
    if user == 'timeout': time.sleep(20)
    if response: os.write(1,response)
    return 0 if not error else 2


if __name__ == '__main__':
    require_guest()
    if len(sys.argv)==2 and sys.argv[1].startswith('--check-'):
        check(sys.argv[1][8:])
    else:
        raise SystemExit(provider())
