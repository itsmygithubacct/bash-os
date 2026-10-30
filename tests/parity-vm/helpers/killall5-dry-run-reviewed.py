#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only fixture and independent dry-run selected-set assertions."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

HOME = Path('/tmp/parity-home')
ROOT = Path('/tmp/parity-case/proc-fixture')
ELIGIBLE = [1900000101, 1900000102, 1900000103, 1900000104]
SAME = [1900000201, 1900000202]
KERNEL, BAD, MISSING, GONE, DENIED = range(1900000301, 1900000306)
MODES = {'baseline', 'comma', 'repeat', 'none', 'unreadable'}


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    actual = Path('/sys/class/dmi/id/product_uuid').read_text().strip()
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME) or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
            uuid.UUID(marker) != uuid.UUID(actual) or os.uname().machine != 'x86_64'):
        raise RuntimeError('requires the isolated uid-2000 x86_64 QEMU guest')


def save(name, obj):
    (HOME / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def parse_output(data):
    if data == b'':
        return set()
    if len(data) > 4096 or not re.fullmatch(rb'[1-9][0-9]*\n(?:[1-9][0-9]*\n)*', data):
        raise ValueError('malformed or truncated PID list')
    values = [int(x) for x in data.splitlines()]
    if len(values) != len(set(values)) or any(x > 2147483647 for x in values):
        raise ValueError('duplicate or out-of-range PID')
    return set(values)


def setup():
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
    save('parser-controls.json', {'positive': len(positive), 'negative': len(negative), 'ok': True})
    source = '/opt/bashos-parity/harness/helpers/killall5-dry-run-reviewed.c'
    build = subprocess.run(['/usr/bin/cc', '-O2', '-Wall', '-Wextra', '-o', 'guard', source],
                           capture_output=True, timeout=20)
    (HOME / 'cc.out').write_bytes(build.stdout)
    (HOME / 'cc.err').write_bytes(build.stderr)
    (HOME / 'cc.status').write_text(str(build.returncode) + '\n')
    if build.returncode != 0:
        raise RuntimeError('guard compilation unavailable')
    result = subprocess.run(['./guard', '--check'], capture_output=True, timeout=10)
    (HOME / 'guard-control.out').write_bytes(result.stdout)
    (HOME / 'guard-control.err').write_bytes(result.stderr)
    (HOME / 'guard-control.status').write_text(str(result.returncode) + '\n')
    if result.returncode != 0 or result.stderr or len(result.stdout.splitlines()) != 6:
        raise RuntimeError('signal guard control unavailable')
    allowed = subprocess.run(['./guard', '/usr/bin/true'], capture_output=True, timeout=10)
    save('guard-exec.json', {'status': allowed.returncode, 'stdout_hex': allowed.stdout.hex(),
                             'stderr_hex': allowed.stderr.hex()})
    if allowed.returncode != 0 or allowed.stdout or allowed.stderr:
        raise RuntimeError('guarded exec control unavailable')


def stat_record(pid, sid):
    return f'{pid} (fixture name) S 1 1 {sid} 0 0 0\n'.encode()


def prepare(mode, pid):
    if mode not in MODES or pid <= 1 or pid != os.getppid():
        raise RuntimeError('caller PID mismatch')
    sid = os.getsid(pid)
    raw = Path(f'/proc/{pid}/stat').read_bytes()
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
    (ROOT / str(GONE) / 'stat').symlink_to('vanished-stat')
    entries[str(GONE)]['stat_hex'] = None
    add(DENIED, outside)
    (ROOT / str(DENIED) / 'cmdline').chmod(0)
    (ROOT / '123junk').mkdir()
    omitted = {'baseline': [], 'comma': ELIGIBLE[:2], 'repeat': ELIGIBLE[1:4],
               'none': ELIGIBLE[:], 'unreadable': []}[mode]
    expected = sorted(set(ELIGIBLE) - set(omitted)) if mode != 'unreadable' else []
    if mode == 'unreadable':
        ROOT.chmod(0)
        try:
            list(ROOT.iterdir())
        except PermissionError:
            pass
        else:
            raise RuntimeError('proc root is not unreadable')
    else:
        for key, entry in entries.items():
            folder = ROOT / key
            if entry['stat_hex'] is None:
                if not (folder / 'stat').is_symlink() or (folder / 'stat').exists():
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
    save('fixture.json', {'mode': mode, 'caller_pid': pid, 'caller_sid': sid,
                          'real_stat_hex': raw.hex(), 'outside_sid': outside,
                          'entries': entries, 'omitted': omitted, 'fixture_preconditions': 'verified'})
    save('oracle.json', {'selected': expected, 'status': 1 if mode == 'unreadable' else 0 if expected else 2})


def verify(mode):
    fixture = json.loads((HOME / 'fixture.json').read_text())
    oracle = json.loads((HOME / 'oracle.json').read_text())
    if fixture['mode'] != mode or fixture['fixture_preconditions'] != 'verified':
        raise RuntimeError('fixture preconditions missing')
    out = (HOME / 'candidate.out').read_bytes()
    err = (HOME / 'candidate.err').read_bytes()
    status_raw = (HOME / 'candidate.status').read_bytes()
    failures = []
    try:
        actual = sorted(parse_output(out))
    except ValueError as exc:
        actual = None
        failures.append(str(exc))
    if actual != oracle['selected']: failures.append('selected set mismatch')
    if status_raw != f"{oracle['status']}\n".encode(): failures.append('status mismatch')
    if mode == 'unreadable':
        if not err or b'opendir' not in err: failures.append('missing unreadable-root diagnostic')
    elif err:
        failures.append('unexpected candidate stderr')
    save('assertions.json', {'mode': mode, 'selected': actual, 'expected': oracle['selected'],
                             'status_raw_hex': status_raw.hex(), 'stderr_hex': err.hex(), 'failures': failures})
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
    raise ValueError('invalid helper arguments')


if __name__ == '__main__':
    raise SystemExit(main())
