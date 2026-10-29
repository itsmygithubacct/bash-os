#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""VM-only observer and fallback for the screen fixture's private brokers."""
import base64
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

HOME = Path('/tmp/parity-home')


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        vendor = Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
        if (vendor != 'QEMU' or os.getuid() != 2000 or os.geteuid() != 2000
                or Path.cwd() != Path('/tmp/parity-case') or Path.home() != HOME):
            raise ValueError('guest identity, fixture uid or scratch mismatch')
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit('requires disposable QEMU uid2000 fixture scratch') from exc


def process(pid):
    path = Path('/proc') / str(pid)
    try:
        text = (path / 'stat').read_text().strip()
        fields = text[text.rindex(')') + 2:].split()
        return {'pid': pid, 'uid': path.stat().st_uid, 'state': fields[0],
                'ppid': int(fields[1]), 'starttime': int(fields[19]), 'stat': text,
                'monotonic_ns': time.monotonic_ns()}
    except FileNotFoundError:
        return {'pid': pid, 'absent': True, 'monotonic_ns': time.monotonic_ns()}
    except (OSError, ValueError, IndexError) as exc:
        return {'pid': pid, 'error': '%s: %s' % (type(exc).__name__, exc),
                'monotonic_ns': time.monotonic_ns()}


def same_live(before, after):
    return (after.get('uid') == os.getuid() and after.get('state') not in ('Z', 'X')
            and after.get('starttime') == before.get('starttime')
            and 'starttime' in before)


def command(shell, text, *args):
    try:
        result = subprocess.run([shell, '--noprofile', '--norc', '-c', text, 'fixture', *args],
                                capture_output=True, timeout=6)
        return {'status': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode(),
                'stderr_base64': base64.b64encode(result.stderr).decode(),
                'monotonic_ns': time.monotonic_ns()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'error': '%s: %s' % (type(exc).__name__, exc), 'monotonic_ns': time.monotonic_ns()}


def state_paths(state, session):
    state = Path(state)
    if state not in (HOME / 'screen-state', HOME / 'trace-state') or session != 'live':
        raise ValueError('not the fixture private state path')
    for path in (state, state / session, state / session / 'brokers'):
        if path.exists():
            s = path.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
                raise ValueError('unexpected state directory ownership or mode: ' + str(path))
    return state / session, state / session / 'brokers'


def status(shell, root, name):
    result = command(shell, 'ptybroker status "$1" "$2"', str(root), name)
    output = base64.b64decode(result.get('stdout_base64', ''))
    match = re.search(rb'\bbroker_pid=([0-9]+)\s+child_pid=([0-9]+)\b', output)
    if result.get('status') == 0 and match:
        result['broker_pid'], result['child_pid'] = map(int, match.groups())
    return result


def snapshot(shell, state, session, output, minimum):
    record = {'state': state, 'session': session, 'minimum': minimum,
              'monotonic_ns': time.monotonic_ns(), 'brokers': [], 'errors': []}
    try:
        _, root = state_paths(state, session)
        for entry in sorted(root.iterdir()) if root.is_dir() else []:
            if not re.fullmatch(r'w[0-9]+-p[0-9]+', entry.name):
                raise ValueError('unexpected broker id: ' + entry.name)
            s = entry.lstat()
            sock = (entry / 'control.sock').lstat()
            if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid()
                    or not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != os.getuid()):
                raise ValueError('unexpected broker directory or socket')
            info = status(shell, root, entry.name)
            item = {'id': entry.name, 'socket_device': sock.st_dev, 'socket_inode': sock.st_ino,
                    'status': info}
            if 'broker_pid' not in info or info['broker_pid'] <= 1 or info['child_pid'] <= 1:
                raise ValueError('cannot identify broker and child: ' + entry.name)
            item['broker'] = process(info['broker_pid'])
            item['child'] = process(info['child_pid'])
            if any(p.get('uid') != os.getuid() or 'starttime' not in p for p in
                   (item['broker'], item['child'])):
                raise ValueError('broker or child is not a live fixture-owned identity')
            record['brokers'].append(item)
        if len(record['brokers']) < minimum:
            raise ValueError('fewer observed brokers than expected')
    except (OSError, ValueError) as exc:
        record['errors'].append('%s: %s' % (type(exc).__name__, exc))
    Path(output).write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return not record['errors']


def finish(shell, state, session, baseline, output):
    record = {'state': state, 'session': session, 'monotonic_ns': time.monotonic_ns(),
              'actions': [], 'observations': [], 'errors': []}
    try:
        session_path, root = state_paths(state, session)
        before = json.loads(Path(baseline).read_text())
        if before.get('state') != state or before.get('session') != session or before.get('errors'):
            raise ValueError('invalid ownership baseline')
        entries = before['brokers']
        # Give a successful tested kill time to finish before intervening.
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if not any(same_live(item['broker'], process(item['broker']['pid'])) for item in entries):
                break
            time.sleep(.05)
        for item in entries:
            original = item['broker']
            now = process(original['pid'])
            record['observations'].append({'id': item['id'], 'phase': 'before-fallback', 'process': now})
            if not same_live(original, now):
                continue
            try:
                sock = (root / item['id'] / 'control.sock').lstat()
                if (not stat.S_ISSOCK(sock.st_mode) or sock.st_uid != os.getuid()
                        or (sock.st_dev, sock.st_ino) != (item['socket_device'], item['socket_inode'])):
                    raise ValueError('socket identity changed')
                info = status(shell, root, item['id'])
                if info.get('broker_pid') != original['pid'] or not same_live(original, process(original['pid'])):
                    raise ValueError('status does not identify baseline broker')
                result = command(shell, 'ptybroker terminate "$1" "$2"', str(root), item['id'])
                record['actions'].append({'id': item['id'], 'action': 'protocol-terminate',
                                          'status_before': info, 'result': result})
            except (OSError, ValueError) as exc:
                record['errors'].append('%s: %s' % (type(exc).__name__, exc))
        if session_path.exists():
            result = command(shell, 'screen kill live')
            record['actions'].append({'action': 'fresh-shell-screen-kill', 'result': result})
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not any(same_live(item['broker'], process(item['broker']['pid'])) for item in entries):
                break
            time.sleep(.05)
        for item in entries:
            for kind in ('broker', 'child'):
                original = item[kind]
                now = process(original['pid'])
                record['observations'].append({'id': item['id'], 'kind': kind, 'phase': 'after-fallback', 'process': now})
                if same_live(original, now):
                    # A pidfd binds the signal to this exact, rechecked process.
                    try:
                        pidfd = os.pidfd_open(original['pid'])
                        try:
                            if not same_live(original, process(original['pid'])):
                                raise ValueError('process identity changed before pidfd signal')
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        finally:
                            os.close(pidfd)
                        record['actions'].append({'id': item['id'], 'kind': kind, 'action': 'pidfd-sigkill'})
                    except (OSError, ValueError, AttributeError) as exc:
                        record['errors'].append('%s: %s' % (type(exc).__name__, exc))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if not any(same_live(item[kind], process(item[kind]['pid']))
                       for item in entries for kind in ('broker', 'child')):
                break
            time.sleep(.05)
        for item in entries:
            for kind in ('broker', 'child'):
                original = item[kind]
                now = process(original['pid'])
                record['observations'].append({'id': item['id'], 'kind': kind, 'phase': 'final', 'process': now})
                if same_live(original, now) or 'error' in now:
                    record['errors'].append('fixture process not verified gone: %s %s' % (item['id'], kind))
        record['session_remaining'] = session_path.exists()
        record['no_intervention'] = not record['actions']
        record['cleanup_completed'] = not record['errors'] and not record['session_remaining']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        record['errors'].append('%s: %s' % (type(exc).__name__, exc))
        record['cleanup_completed'] = False
    Path(output).write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    # An intervention may make the guest safe, but cannot substantiate a
    # successful, self-contained candidate kill.
    return record['cleanup_completed'] and record.get('no_intervention', False)


def finish_extra(baseline, output):
    record = {'monotonic_ns': time.monotonic_ns(), 'observations': [], 'actions': [], 'errors': []}
    try:
        original = json.loads(Path(baseline).read_text())['records']['grandchild']
        if original.get('uid') != os.getuid() or original.get('pid', 0) <= 1 or 'starttime' not in original:
            raise ValueError('invalid live fixture-grandchild baseline')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            now = process(original['pid'])
            if not same_live(original, now):
                break
            time.sleep(.05)
        record['observations'].append({'phase': 'before-fallback', 'process': now})
        if same_live(original, now):
            pidfd = os.pidfd_open(original['pid'])
            try:
                if not same_live(original, process(original['pid'])):
                    raise ValueError('grandchild identity changed before signal')
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            finally:
                os.close(pidfd)
            record['actions'].append('pidfd-sigkill')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            now = process(original['pid'])
            if not same_live(original, now):
                break
            time.sleep(.05)
        record['observations'].append({'phase': 'final', 'process': now})
        if same_live(original, now) or 'error' in now:
            record['errors'].append('grandchild not verified gone')
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        record['errors'].append('%s: %s' % (type(exc).__name__, exc))
    Path(output).write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return not record['actions'] and not record['errors']


if __name__ == '__main__':
    require_guest()
    args = sys.argv[1:]
    if len(args) == 6 and args[0] == 'snapshot':
        raise SystemExit(0 if snapshot(*args[1:5], int(args[5])) else 1)
    if len(args) == 6 and args[0] == 'finish':
        raise SystemExit(0 if finish(*args[1:]) else 1)
    if len(args) == 3 and args[0] == 'finish-extra':
        raise SystemExit(0 if finish_extra(*args[1:]) else 1)
    raise SystemExit('invalid fixture arguments')
