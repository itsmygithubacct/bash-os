#!/usr/bin/python3
"""Guest-only owned-process and visible-root lsof selection observation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time
import uuid

ROOT = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
RAW = HOME / 'lsof-other-uid-observations.json'


def capture(args):
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=6)
    limit = 128*1024
    return {'argv': args, 'status': p.returncode,
            'stdout_base64': base64.b64encode(p.stdout[:limit]).decode(),
            'stderr_base64': base64.b64encode(p.stderr[:limit]).decode(),
            'stdout_bytes': len(p.stdout), 'stderr_bytes': len(p.stderr),
            'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(p.stderr).hexdigest(),
            'truncated': len(p.stdout) > limit or len(p.stderr) > limit}


def data(record):
    return base64.b64decode(record['stdout_base64'])


def save(record):
    tmp = RAW.with_name(RAW.name + '.tmp')
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    os.replace(tmp, RAW)


def identity(pid):
    p = Path('/proc') / str(pid)
    return {'status': (p / 'status').read_text(), 'stat': (p / 'stat').read_text()}


def birth(rec):
    return rec['stat'].rsplit(')', 1)[1].split()[19]


def candidate_rows(rec):
    lines = data(rec).decode('utf-8', 'strict').splitlines()
    if not lines or lines[0].split() != ['COMMAND', 'PID', 'USER', 'FD', 'TYPE', 'PATH']:
        raise ValueError('unexpected candidate header')
    rows = []
    for line in lines[1:]:
        f = line.split(None, 5)
        if len(f) != 6 or not f[1].isdigit() or not f[3].isdigit():
            raise ValueError('unparseable candidate row')
        rows.append({'pid': int(f[1]), 'fd': int(f[3]), 'path': f[5], 'user': f[2]})
    return rows


def native_pids(rec):
    result = set()
    for line in data(rec).splitlines():
        if line.startswith(b'p') and line[1:].isdigit():
            result.add(int(line[1:]))
    return sorted(result)


def main():
    if len(sys.argv) != 2 or os.geteuid() != 2000 or Path.cwd() != ROOT or Path(os.environ['HOME']) != HOME:
        raise RuntimeError('guest uid, paths or arguments invalid')
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
        raise RuntimeError('guest vendor invalid')
    vm_uuid = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    if pwd.getpwuid(0).pw_name != 'root':
        raise RuntimeError('guest root account mapping differs')
    root_pid = None
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            rec = identity(int(entry.name))
            m = re.search(r'^Uid:\s+(\d+)', rec['status'], re.M)
            if m and int(m.group(1)) == 0:
                root_pid = int(entry.name)
                break
        except (OSError, ProcessLookupError):
            pass
    if root_pid is None:
        raise RuntimeError('no visible root-owned process')
    root_before = identity(root_pid)
    witness_path = ROOT / 'lsof-owned-witness'
    witness_path.write_text('owned descriptor witness\n')
    # Inherited open regular fd belongs to a process held by its own stdin pipe.
    child_script = 'import os,sys; f=open(sys.argv[1],"rb"); print(str(os.getpid())+" "+str(f.fileno()),flush=True); sys.stdin.readline()'
    child = subprocess.Popen(['/usr/bin/python3', '-c', child_script, str(witness_path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    record = {'guest_uuid': vm_uuid, 'root_pid': root_pid, 'root_before': root_before,
              'uid': os.geteuid(), 'own_user': pwd.getpwuid(os.geteuid()).pw_name}
    try:
        import select
        ready, _, _ = select.select([child.stdout], [], [], 5)
        if not ready:
            raise RuntimeError('owned witness startup timeout')
        pid, fd = map(int, child.stdout.readline().split())
        if pid != child.pid:
            raise RuntimeError('witness identity mismatch')
        record['witness_pid'] = pid
        record['witness_fd'] = fd
        record['witness_before'] = identity(pid)
        record['witness_fd_target'] = os.readlink('/proc/%d/fd/%d' % (pid, fd))
        if record['witness_fd_target'] != str(witness_path):
            raise RuntimeError('witness fd target mismatch')
        save(record)
        candidate = sys.argv[1]
        # Positional parameters preserve argument boundaries; no shell interpolation.
        def run_candidate(*args):
            return capture([candidate, '--noprofile', '--norc', '-c',
                            'type -t lsof >&2; lsof "$@"', 'fixture', *args])
        def probe(key, fn):
            record.setdefault('probe_windows', {})[key] = {'before': {'witness': identity(pid), 'root': identity(root_pid)}, 'start_ns': time.monotonic_ns()}
            save(record)
            try:
                outcome = fn()
            except subprocess.TimeoutExpired as exc:
                def encoded(v):
                    if v is None: return None
                    if isinstance(v, str): v = v.encode()
                    return {'prefix_base64': base64.b64encode(v[:128*1024]).decode(), 'bytes': len(v), 'sha256': hashlib.sha256(v).hexdigest(), 'truncated': len(v) > 128*1024}
                record.setdefault('infrastructure_errors', {})[key] = {'kind': 'timeout', 'stdout': encoded(exc.stdout), 'stderr': encoded(exc.stderr)}
                save(record)
                raise
            except Exception as exc:
                record.setdefault('infrastructure_errors', {})[key] = {'kind': type(exc).__name__, 'detail': str(exc)[:500]}
                save(record)
                raise
            record[key] = outcome
            record['probe_windows'][key]['result_ns'] = time.monotonic_ns()
            save(record)  # Persist reached behavior before any later identity or probe can fail.
            if outcome['truncated']:
                record.setdefault('infrastructure_errors', {})[key] = {'kind': 'output-limit'}
                save(record)
                raise RuntimeError('probe output bound exceeded')
            try:
                record['probe_windows'][key]['after'] = {'witness': identity(pid), 'root': identity(root_pid)}
            except OSError as exc:
                record['probe_windows'][key]['after_error'] = str(exc)
                save(record)
                raise
            record['probe_windows'][key]['end_ns'] = time.monotonic_ns()
            save(record)
        probe('candidate_unfiltered', lambda: run_candidate('-p', str(pid)))
        probe('native_unfiltered', lambda: capture(['/usr/bin/lsof', '-nP', '-F', 'pfn', '-p', str(pid)]))
        probe('candidate_name', lambda: run_candidate('-u', 'root'))
        probe('candidate_numeric', lambda: run_candidate('-u', '0'))
        probe('native_name', lambda: capture(['/usr/bin/lsof', '-nP', '-F', 'pfn', '-u', 'root']))
        probe('native_numeric', lambda: capture(['/usr/bin/lsof', '-nP', '-F', 'pfn', '-u', '0']))
        record['witness_after'] = identity(pid)
        record['root_after'] = identity(root_pid)
        record['witness_alive_at_end'] = child.poll() is None
        save(record)
        if not record['witness_alive_at_end'] or birth(record['witness_before']) != birth(record['witness_after']) or birth(root_before) != birth(record['root_after']):
            raise RuntimeError('process identity changed during observations')
        witness_uid = re.search(r'^Uid:\s+(\d+)', record['witness_before']['status'], re.M)
        if not witness_uid or int(witness_uid.group(1)) != 2000:
            raise RuntimeError('owned witness uid invalid')
        native_control = record['native_unfiltered']
        if native_control['status'] != 0 or pid not in native_pids(native_control) or str(witness_path).encode() not in data(native_control):
            raise RuntimeError('native descriptor positive control incomplete')
        for key in ('native_name', 'native_numeric'):
            if record[key]['status'] not in (0, 1) or base64.b64decode(record[key]['stderr_base64']) or pid in native_pids(record[key]):
                raise RuntimeError('native other-uid selection control failed')
        for key in ('candidate_unfiltered', 'candidate_name', 'candidate_numeric'):
            if not base64.b64decode(record[key]['stderr_base64']).startswith(b'builtin\n'):
                raise RuntimeError('candidate builtin identity or diagnostic incomplete')
        unfiltered = candidate_rows(record['candidate_unfiltered'])
        positive = record['candidate_unfiltered']['status'] == 0 and any(r['pid'] == pid and r['fd'] == fd and r['path'] == str(witness_path) for r in unfiltered)
        if not positive:
            raise RuntimeError('candidate positive witness absent; filtering is not attributable')
        selected = []
        for key in ('candidate_name', 'candidate_numeric'):
            if record[key]['status'] != 0:
                selected.append(False)
                continue
            rows = candidate_rows(record[key])
            selected.append(all(r['pid'] != pid for r in rows))
        print('other_uid_excluded=' + ('yes' if all(selected) else 'no'))
    finally:
        forced = False
        if child.poll() is None:
            try:
                child.stdin.write('done\n'); child.stdin.flush()
                child.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                forced = True
                child.kill(); child.wait(timeout=3)
        record['fixture_cleanup'] = {'child_status': child.returncode, 'forced': forced}
        save(record)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('CONTROL-INCOMPLETE: ' + repr(exc), file=sys.stderr)
        sys.exit(97)
