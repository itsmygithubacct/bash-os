#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only fixture and independent dry-run selected-set assertions."""
import base64
import errno
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

HOME = Path('/tmp/parity-home')
ROOT = Path('/tmp/parity-case/proc-fixture')
ELIGIBLE = [1900000101, 1900000102, 1900000103, 1900000104]
SAME = [1900000201, 1900000202]
KERNEL, BAD, MISSING, GONE, DENIED = range(1900000301, 1900000306)
MODES = {'baseline', 'comma', 'repeat', 'none', 'unreadable', 'race'}


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    # The root guest evaluator already verifies marker/product UUID equality.
    # The DMI product UUID need not be readable after dropping to uid 2000.
    if str(uuid.UUID(marker)) != marker.lower():
        raise RuntimeError('noncanonical guest marker')
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME) or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
            Path('/tmp/parity-case').stat().st_uid != 2000 or HOME.stat().st_uid != 2000 or
            os.uname().machine != 'x86_64'):
        raise RuntimeError('requires the isolated uid-2000 x86_64 QEMU guest')


def save(name, obj):
    (HOME / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def parse_output(data):
    if data == b'':
        return set()
    if len(data) > 4096 or not re.fullmatch(rb'[1-9][0-9]*\n(?:[1-9][0-9]*\n)*', data):
        raise ValueError('noncanonical or oversized PID list')
    values = [int(x) for x in data.splitlines()]
    if len(values) != len(set(values)) or any(x > 2147483647 for x in values):
        raise ValueError('duplicate or out-of-range PID')
    return set(values)


def setup():
    record = {'stage': 'parser-start', 'complete': False}
    save('setup.json', record)
    try:
        setup_checked(record)
    except BaseException as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            record['timeout'] = {'stdout_base64': base64.b64encode(exc.stdout or b'').decode(),
                                 'stderr_base64': base64.b64encode(exc.stderr or b'').decode()}
        record['error'] = repr(exc)
        save('setup.json', record)
        raise


def setup_checked(record):
    positive = [(b'', set()), (b'4\n21\n', {4, 21}), (b'21\n4\n', {4, 21})]
    negative = [b'4', b'4\n4\n', b'04\n', b'0\n', b'4 5\n', b'4\nnoise\n',
                b'2147483648\n', b'4\n' * 2100, b'\xff\n']
    for raw, expected in positive:
        if parse_output(raw) != expected:
            raise RuntimeError('PID parser positive control')
    for raw in negative:
        try:
            parse_output(raw)
        except ValueError:
            continue
        raise RuntimeError('PID parser accepted negative control')
    record.update(stage='parser-complete', parser={'positive': len(positive), 'negative': len(negative), 'ok': True})
    save('setup.json', record)
    source = '/opt/bashos-parity/harness/helpers/killall5-dry-run-reviewed.c'
    record['stage'] = 'compile-start'; save('setup.json', record)
    build = subprocess.run(['/usr/bin/cc', '-O2', '-Wall', '-Wextra', '-o', 'guard', source],
                           capture_output=True, timeout=15)
    record['compile'] = raw_result(build); record['stage'] = 'compile-complete'; save('setup.json', record)
    if build.returncode != 0:
        raise RuntimeError('guard compilation unavailable')
    record['stage'] = 'guard-control-start'; save('setup.json', record)
    result = subprocess.run(['./guard', '--check'], capture_output=True, timeout=6)
    record['guard_control'] = raw_result(result); record['stage'] = 'guard-control-complete'; save('setup.json', record)
    if result.returncode != 0 or result.stderr or len(result.stdout.splitlines()) != 6:
        raise RuntimeError('signal guard control unavailable')
    record['stage'] = 'scope-control-start'; save('setup.json', record)
    scope = subprocess.run(['./guard', '--check-scope'], capture_output=True, timeout=6)
    record['scope_control'] = raw_result(scope); record['stage'] = 'scope-control-complete'; save('setup.json', record)
    if scope.returncode != 0 or scope.stderr or len(scope.stdout.splitlines()) != 7:
        raise RuntimeError('proc confinement control unavailable')
    record['stage'] = 'guard-exec-start'; save('setup.json', record)
    allowed = subprocess.run(['./guard', '/usr/bin/true'], capture_output=True, timeout=6)
    record['guard_exec'] = raw_result(allowed); record['stage'] = 'guard-exec-complete'; save('setup.json', record)
    if allowed.returncode != 0 or allowed.stdout or allowed.stderr:
        raise RuntimeError('guarded exec control unavailable')
    record['stage'] = 'namespace-control-start'; save('setup.json', record)
    outer = os.readlink('/proc/self/ns/pid')
    control = subprocess.run(['/usr/bin/unshare', '--user', '--map-user=2000', '--map-group=2000',
                              '--mount', '--pid', '--fork', '--mount-proc',
                              '/usr/bin/python3', '/opt/bashos-parity/harness/helpers/killall5-dry-run-reviewed.py',
                              'namespace-check', outer, 'setup'], capture_output=True, timeout=8)
    record['namespace_control'] = raw_result(control); record['stage'] = 'namespace-control-complete'; save('setup.json', record)
    if control.returncode != 0 or control.stderr:
        raise RuntimeError('private PID/proc namespace unavailable')
    observed = json.loads(control.stdout)
    if observed.get('ok') is not True or observed.get('mode') != 'setup':
        raise RuntimeError('private PID/proc namespace control failed')
    record['stage'] = 'session-control-start'; save('setup.json', record)
    session = subprocess.run(['/usr/bin/unshare', '--user', '--map-user=2000', '--map-group=2000',
                              '--mount', '--pid', '--fork', '--mount-proc', '/usr/bin/setsid', '--wait',
                              '/usr/bin/python3', '/opt/bashos-parity/harness/helpers/killall5-dry-run-reviewed.py',
                              'session-check', outer], capture_output=True, timeout=8)
    record['session_control'] = raw_result(session); record['stage'] = 'session-control-complete'; save('setup.json', record)
    if session.returncode != 0 or session.stderr:
        raise RuntimeError('visible session control unavailable')
    control_session = json.loads(session.stdout)
    if control_session.get('ok') is not True or control_session.get('sid', 0) <= 0 or control_session.get('sid') != control_session.get('pid'):
        raise RuntimeError('visible session control failed')
    record.update(stage='complete', complete=True); save('setup.json', record)


def raw_result(result):
    return {'status': result.returncode, 'stdout_base64': base64.b64encode(result.stdout).decode(),
            'stderr_base64': base64.b64encode(result.stderr).decode()}


def stat_record(pid, sid):
    return f'{pid} (fixture name) S 1 1 {sid} 0 0 0\n'.encode()


def namespace_check(outer, mode):
    if mode not in {'setup', 'candidate'} or not re.fullmatch(r'pid:\[[0-9]+\]', outer):
        raise RuntimeError('invalid outer PID namespace record')
    inner = os.readlink('/proc/self/ns/pid')
    pid, parent = os.getpid(), os.getppid()
    visible = sorted(int(x) for x in os.listdir('/proc') if x.isascii() and x.isdigit())
    expected = [1] if mode == 'setup' else [1, pid]
    if inner == outer or (mode == 'setup' and (pid != 1 or parent != 0)) or \
            (mode == 'candidate' and (pid <= 1 or parent != 1)) or visible != expected:
        raise RuntimeError('PID namespace or private procfs control failed')
    own_stat = Path('/proc/self/stat').read_bytes()
    match = re.match(rb'([0-9]+) \(', own_stat)
    if not match or int(match[1]) != pid:
        raise RuntimeError('procfs does not describe this PID namespace')
    print(json.dumps({'stage':'namespace-ok', 'ok':True, 'mode':mode, 'outer':outer,
                      'inner':inner, 'pid':pid, 'parent':parent, 'uid':os.getuid(),
                      'euid':os.geteuid(), 'visible':visible,
                      'own_stat_hex':own_stat.hex()}, sort_keys=True))


def session_identity(pid):
    sid = os.getsid(pid)
    if sid <= 0 or sid != pid or os.getsid(sid) != sid:
        raise RuntimeError('caller is not a visible positive session leader')
    raw = Path(f'/proc/{sid}/stat').read_bytes()
    match = re.fullmatch(rb'([0-9]+) \(.*\) [^ ]+ ([0-9]+) ([0-9]+) ([0-9]+) .*\n', raw)
    if not match or int(match[1]) != sid or int(match[4]) != sid:
        raise RuntimeError('session leader stat does not match getsid')
    return sid, raw


def session_check(outer):
    if not re.fullmatch(r'pid:\[[0-9]+\]', outer):
        raise RuntimeError('invalid outer PID namespace record')
    inner = os.readlink('/proc/self/ns/pid')
    pid = os.getpid()
    sid, raw = session_identity(pid)
    visible = sorted(int(x) for x in os.listdir('/proc') if x.isascii() and x.isdigit())
    if inner == outer or visible != sorted({1, pid}):
        raise RuntimeError('session control did not enter a private PID/proc namespace')
    print(json.dumps({'ok': True, 'pid': pid, 'sid': sid, 'leader_getsid': os.getsid(sid),
                      'leader_stat_hex': raw.hex(), 'outer': outer, 'inner': inner,
                      'visible': visible, 'uid': os.getuid(), 'euid': os.geteuid()}, sort_keys=True))


def prepare(mode, pid):
    if mode not in MODES or pid <= 1 or pid != os.getppid():
        raise RuntimeError('caller PID mismatch')
    namespace = json.loads((HOME / 'events.jsonl').read_text().splitlines()[0])
    if (namespace.get('stage') != 'namespace-ok' or namespace.get('ok') is not True or
            namespace.get('mode') != 'candidate' or namespace.get('inner') != os.readlink('/proc/self/ns/pid') or
            namespace['inner'] != os.readlink(f'/proc/{pid}/ns/pid')):
        raise RuntimeError('caller PID namespace mismatch')
    sid, raw = session_identity(pid)
    match = re.fullmatch(rb'([0-9]+) \(.*\) [^ ]+ ([0-9]+) ([0-9]+) ([0-9]+) .*\n', raw)
    if not match or int(match[1]) != pid or int(match[4]) != sid:
        raise RuntimeError('real caller SID control failed')
    if pid in ELIGIBLE + SAME + [KERNEL, BAD, MISSING, GONE, DENIED] or sid in ELIGIBLE:
        raise RuntimeError('fixture ID collides with caller')
    outside = 1900000000 if sid != 1900000000 else 1900000001
    ROOT.mkdir()
    entries = {}
    def add(number, session, command=b'fixture\0', stat_data=None):
        directory = ROOT / str(number)
        directory.mkdir()
        record = stat_record(number, session) if stat_data is None else stat_data
        (directory / 'stat').write_bytes(record)
        (directory / 'cmdline').write_bytes(command)
        entries[str(number)] = {'stat_hex': record.hex(), 'cmdline_hex': command.hex()}
    for n in ELIGIBLE:
        add(n, outside)
    for n in SAME:
        add(n, sid)
    add(pid, outside)  # Self has a different synthetic SID so session filtering cannot mask it.
    add(KERNEL, outside, b'')
    add(BAD, outside, stat_data=b'malformed stat\n')
    add(MISSING, outside)
    (ROOT / str(MISSING) / 'cmdline').unlink()
    entries[str(MISSING)]['cmdline_hex'] = None
    add(GONE, outside)
    (ROOT / str(GONE) / 'stat').unlink()
    if mode == 'race':
        os.mkfifo(ROOT / str(GONE) / 'stat', 0o600)
    else:
        (ROOT / str(GONE) / 'stat').symlink_to('vanished-stat')
    entries[str(GONE)]['stat_hex'] = None
    add(DENIED, outside)
    (ROOT / str(DENIED) / 'cmdline').chmod(0)
    (ROOT / '123junk').mkdir()
    omitted = {'baseline': [], 'race': [], 'comma': ELIGIBLE[:2], 'repeat': ELIGIBLE[1:4],
               'none': ELIGIBLE[:], 'unreadable': []}[mode]
    expected = sorted(set(ELIGIBLE) - set(omitted)) if mode != 'unreadable' else []
    for key, entry in entries.items():
        folder = ROOT / key
        if entry['stat_hex'] is None:
            path = folder / 'stat'
            if mode == 'race' and int(key) == GONE:
                if not stat.S_ISFIFO(path.lstat().st_mode): raise RuntimeError('race stat is not FIFO')
            elif not path.is_symlink() or path.exists():
                raise RuntimeError('disappeared stat control failed')
        elif (folder / 'stat').read_bytes().hex() != entry['stat_hex']:
            raise RuntimeError('stat fixture control failed')
        cmd = folder / 'cmdline'
        if entry['cmdline_hex'] is None:
            if cmd.exists(): raise RuntimeError('missing cmdline control failed')
        elif int(key) == DENIED:
            if stat.S_IMODE(cmd.stat().st_mode) != 0:
                raise RuntimeError('denied cmdline mode control failed')
            try:
                cmd.read_bytes()
            except PermissionError:
                pass
            else:
                raise RuntimeError('denied cmdline remains readable')
        elif cmd.read_bytes().hex() != entry['cmdline_hex']:
            raise RuntimeError('cmdline fixture control failed')
    save('fixture.json', {'mode': mode, 'caller_pid': pid, 'caller_sid': sid, 'session_leader_pid': sid,
                          'leader_getsid': os.getsid(sid), 'pid_namespace': namespace['inner'],
                          'real_stat_hex': raw.hex(), 'outside_sid': outside,
                          'root_uid': ROOT.stat().st_uid, 'root_mode': stat.S_IMODE(ROOT.stat().st_mode),
                          'entries': entries, 'omitted': omitted, 'fixture_preconditions': 'verified'})
    save('oracle.json', {'selected': expected, 'status': 1 if mode == 'unreadable' else 0 if expected else 2})


def race_writer():
    record = {'stage': 'start', 'complete': False}
    save('race.json', record)
    try:
        fixture = json.loads((HOME / 'fixture.json').read_text())
        if fixture['mode'] != 'race' or fixture['fixture_preconditions'] != 'verified':
            raise RuntimeError('race fixture was not prepared')
        path = ROOT / str(GONE) / 'stat'
        cmd = ROOT / str(GONE) / 'cmdline'
        if not stat.S_ISFIFO(path.lstat().st_mode) or cmd.read_bytes() != b'fixture\0':
            raise RuntimeError('race record precondition failed')
        deadline = time.monotonic() + 8
        while True:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                break
            except OSError as exc:
                if exc.errno != errno.ENXIO or time.monotonic() >= deadline:
                    raise
                time.sleep(.01)
        try:
            record.update(stage='reader-open', reader_open=True); save('race.json', record)
            cmd.unlink()
            if cmd.exists(): raise RuntimeError('cmdline was not removed')
            record.update(stage='cmdline-removed', cmdline_removed=True); save('race.json', record)
            payload = stat_record(GONE, fixture['outside_sid'])
            count = os.write(fd, payload)
            if count != len(payload): raise RuntimeError('short race stat write')
            record.update(stage='complete', complete=True, stat_hex=payload.hex(), bytes_written=count)
            save('race.json', record)
        finally:
            os.close(fd)
    except BaseException as exc:
        record['error'] = repr(exc)
        save('race.json', record)
        raise


def recheck(mode, pid, observation):
    record = {'mode': mode, 'pid': pid, 'observation': observation, 'ok': False}
    try:
        fixture = json.loads((HOME / 'fixture.json').read_text())
        if (fixture['mode'] != mode or fixture['caller_pid'] != pid or pid != os.getppid() or
                fixture['caller_sid'] <= 0 or fixture['caller_sid'] != pid or
                fixture['session_leader_pid'] != pid or fixture['caller_sid'] != os.getsid(pid) or
                observation not in {'baseline', 'candidate'}):
            raise RuntimeError('caller identity or fixture mismatch')
        sid, raw = session_identity(pid)
        record['caller_sid'] = sid
        record['session_leader_pid'] = sid
        record['leader_getsid'] = os.getsid(sid)
        m = re.fullmatch(rb'([0-9]+) \(.*\) [^ ]+ ([0-9]+) ([0-9]+) ([0-9]+) .*\n', raw)
        if not m or int(m[1]) != pid or int(m[4]) != fixture['caller_sid']:
            raise RuntimeError('caller stat or session changed')
        record['real_stat_hex'] = raw.hex()
        record['pid_namespace'] = os.readlink('/proc/self/ns/pid')
        if (record['pid_namespace'] != fixture['pid_namespace'] or
                record['pid_namespace'] != os.readlink(f'/proc/{pid}/ns/pid')):
            raise RuntimeError('caller PID namespace changed')
        record['root_uid'] = ROOT.stat().st_uid
        record['root_mode'] = stat.S_IMODE(ROOT.stat().st_mode)
        target_unreadable = mode == 'unreadable' and observation == 'candidate'
        expected_mode = 0 if target_unreadable else fixture['root_mode']
        if record['root_uid'] != 2000 or record['root_mode'] != expected_mode:
            raise RuntimeError('fixture root ownership or mode changed')
        if target_unreadable:
            if stat.S_IMODE(ROOT.stat().st_mode) != 0: raise RuntimeError('root mode changed')
            try: list(ROOT.iterdir())
            except PermissionError as exc:
                if exc.errno != errno.EACCES: raise
                record['root_open_errno'] = exc.errno
            else: raise RuntimeError('root became readable')
        else:
            if {p.name for p in ROOT.iterdir()} != set(fixture['entries']) | {'123junk'}:
                raise RuntimeError('fixture entries changed')
            for key, entry in fixture['entries'].items():
                folder = ROOT / key
                path = folder / 'stat'
                if entry['stat_hex'] is None:
                    if mode == 'race' and int(key) == GONE:
                        if not stat.S_ISFIFO(path.lstat().st_mode): raise RuntimeError('race FIFO missing')
                    elif not path.is_symlink() or path.exists(): raise RuntimeError('vanished stat changed')
                elif path.read_bytes().hex() != entry['stat_hex']:
                    raise RuntimeError('stat changed')
                cmd = folder / 'cmdline'
                if entry['cmdline_hex'] is None:
                    if cmd.exists(): raise RuntimeError('missing cmdline appeared')
                elif int(key) == DENIED:
                    if stat.S_IMODE(cmd.stat().st_mode) != 0: raise RuntimeError('denied mode changed')
                    try: cmd.read_bytes()
                    except PermissionError: pass
                    else: raise RuntimeError('denied cmdline readable')
                elif cmd.read_bytes().hex() != entry['cmdline_hex']:
                    raise RuntimeError('cmdline changed')
        record['ok'] = True
    except BaseException as exc:
        record['error'] = repr(exc)
        raise
    finally:
        with (HOME / 'rechecks.jsonl').open('a') as f:
            f.write(json.dumps(record, sort_keys=True) + '\n')


def seal_unreadable(pid):
    record = {'mode': 'unreadable', 'pid': pid, 'observation': 'seal', 'ok': False}
    try:
        fixture = json.loads((HOME / 'fixture.json').read_text())
        if (fixture['mode'] != 'unreadable' or fixture['caller_pid'] != pid or
                pid != os.getppid() or session_identity(pid)[0] != fixture['caller_sid'] or
                ROOT.stat().st_uid != 2000 or stat.S_IMODE(ROOT.stat().st_mode) != fixture['root_mode']):
            raise RuntimeError('root transition identity or mode mismatch')
        ROOT.chmod(0)
        try: list(ROOT.iterdir())
        except PermissionError as exc:
            if exc.errno != errno.EACCES: raise
            record.update(root_mode=stat.S_IMODE(ROOT.stat().st_mode), root_uid=ROOT.stat().st_uid,
                          root_open_errno=exc.errno, ok=True)
        else: raise RuntimeError('root remained readable')
    except BaseException as exc:
        record['error'] = repr(exc)
        raise
    finally:
        with (HOME / 'rechecks.jsonl').open('a') as f:
            f.write(json.dumps(record, sort_keys=True) + '\n')


def verify(mode):
    fixture = json.loads((HOME / 'fixture.json').read_text())
    oracle = json.loads((HOME / 'oracle.json').read_text())
    if fixture['mode'] != mode or fixture['fixture_preconditions'] != 'verified':
        raise RuntimeError('fixture preconditions missing')
    out = (HOME / 'candidate.out').read_bytes()
    err = (HOME / 'candidate.err').read_bytes()
    status_raw = (HOME / 'candidate.status').read_bytes()
    failures = []
    infrastructure_errors = []
    if mode == 'race':
        race = json.loads((HOME / 'race.json').read_text())
        if (race.get('complete') is not True or race.get('stage') != 'complete' or
                race.get('reader_open') is not True or race.get('cmdline_removed') is not True or
                race.get('stat_hex') != stat_record(GONE, fixture['outside_sid']).hex() or
                race.get('bytes_written') != len(stat_record(GONE, fixture['outside_sid'])) or
                (HOME / 'race.status').read_bytes() != b'0\n' or
                (HOME / 'race.err').read_bytes()):
            infrastructure_errors.append('race control incomplete')
    baseline = None
    if mode in {'none', 'unreadable'}:
        base_out = (HOME / 'baseline.out').read_bytes()
        base_err = (HOME / 'baseline.err').read_bytes()
        base_status = (HOME / 'baseline.status').read_bytes()
        try:
            baseline = sorted(parse_output(base_out))
        except ValueError as exc:
            failures.append('baseline: ' + str(exc))
        if baseline != ELIGIBLE: failures.append('baseline selected set mismatch')
        if base_status != b'0\n': failures.append('baseline status mismatch')
        if base_err: failures.append('baseline unexpected stderr')
    try:
        actual = sorted(parse_output(out))
    except ValueError as exc:
        actual = None
        failures.append(str(exc))
    if actual != oracle['selected']: failures.append('selected set mismatch')
    if status_raw != f"{oracle['status']}\n".encode(): failures.append('status mismatch')
    if mode == 'unreadable':
        if b'opendir /tmp/parity-case/proc-fixture: Permission denied' not in err:
            failures.append('diagnostic lacks intended root and EACCES')
    elif err:
        failures.append('unexpected candidate stderr')
    save('assertions.json', {'mode': mode, 'baseline_selected': baseline, 'selected': actual, 'expected': oracle['selected'],
                             'status_raw_hex': status_raw.hex(), 'stderr_hex': err.hex(), 'failures': failures,
                             'infrastructure_errors': infrastructure_errors})
    if infrastructure_errors:
        print('fixture incomplete: ' + '; '.join(infrastructure_errors), file=sys.stderr)
        return 90
    if failures:
        print('candidate mismatch: ' + '; '.join(failures), file=sys.stderr)
        return 1
    print('dry-run-ok')
    return 0


def main():
    require_guest()
    if sys.argv[1:] == ['setup']:
        setup(); return 0
    if len(sys.argv) == 4 and sys.argv[1] == 'prepare':
        prepare(sys.argv[2], int(sys.argv[3])); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'verify' and sys.argv[2] in MODES:
        return verify(sys.argv[2])
    if len(sys.argv) == 5 and sys.argv[1] == 'recheck':
        recheck(sys.argv[2], int(sys.argv[3]), sys.argv[4]); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'seal':
        seal_unreadable(int(sys.argv[2])); return 0
    if sys.argv[1:] == ['race-writer']:
        race_writer(); return 0
    if len(sys.argv) == 4 and sys.argv[1] == 'namespace-check':
        namespace_check(sys.argv[2], sys.argv[3]); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'session-check':
        session_check(sys.argv[2]); return 0
    raise ValueError('invalid helper arguments')


if __name__ == '__main__':
    raise SystemExit(main())
