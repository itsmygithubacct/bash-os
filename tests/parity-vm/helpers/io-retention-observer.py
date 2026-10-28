#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disposable-VM controls and same-child observations for atomic save failures.

This helper never substitutes a successful syscall result. EIO is answered once
and subsequent calls continue in the kernel. A refused close leaves its actual
kernel descriptor open: snapshots retain that state through recovery, and the
fixture closes any remaining descriptor only after the recovery observations.
"""
import base64
import ctypes
import errno
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import uuid


ROOT = Path('/opt/bashos-parity/harness/helpers')
SELF = ROOT / 'io-retention-observer.py'
SEQUENCE = ROOT / 'system-sequence.py'
OLD = b'old target\n'


def require_guest():
    # The root evaluator separately verifies the marker against the DMI UUID.
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'QEMU'
    assert os.geteuid() == 2000 and Path.cwd() == Path('/tmp/parity-case')


def initial(mode):
    return (b'0' * 3000 + b'\n') if mode == 'efbig' else b'one\ntwo\n'


def wanted(mode):
    return b'zero\n' + initial(mode)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def trace_rules(mode, log, inject=True):
    args = ['/usr/bin/python3', str(SEQUENCE),
            '--notify', 'write', '--log-args', 'write=0,2', '--log-mem', 'write=1:64',
            '--notify', 'openat', '--log-string', 'openat=1',
            '--notify', 'fdatasync', '--log-args', 'fdatasync=0',
            '--notify', 'close:0=11', '--log-args', 'close=0']
    for name, index in [('rename', 0), ('renameat', 1), ('renameat2', 1)]:
        args += ['--notify', name, '--log-string', '%s=%d' % (name, index)]
    if inject and mode == 'fdatasync':
        args += ['--reply-seq', 'fdatasync=EIO,continue']
    if inject and mode == 'close':
        args += ['--reply-seq', 'close=EIO,continue']
    if inject and mode == 'rename':
        for name in ['rename', 'renameat', 'renameat2']:
            args += ['--reply-seq', name + '=EIO,continue']
    return args + ['--log', str(log), '--']


def records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def expect_errno(number, call):
    try:
        call()
    except OSError as exc:
        assert exc.errno == number, (exc.errno, number)
    else:
        raise AssertionError('control did not fail with the requested errno')


def direct_control(mode):
    """Independent controls; assertions here are setup failures, not DUT results."""
    if mode == 'efbig':
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        fd = os.open('control-file', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, hard))
            assert os.write(fd, b'x' * 3006) == 1024
            expect_errno(errno.EFBIG, lambda: os.write(fd, b'x'))
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        assert resource.getrlimit(resource.RLIMIT_FSIZE) == (soft, hard)
        os.write(fd, b'recovered')
        assert os.fstat(fd).st_size == 1033
        os.close(fd)
        Path('control-file').unlink()
    elif mode == 'fdatasync':
        fd = os.open('control-file', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.write(fd, b'control data\n')
        expect_errno(errno.EIO, lambda: os.fdatasync(fd))
        os.fdatasync(fd)
        os.close(fd)
        assert Path('control-file').read_bytes() == b'control data\n'
        Path('control-file').unlink()
    elif mode == 'close':
        fd = os.open('control-file', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        if fd != 11:
            os.dup2(fd, 11)
            os.close(fd)
        os.write(11, b'control data\n')
        expect_errno(errno.EIO, lambda: os.close(11))
        assert os.fstat(11).st_size == 13
        os.close(11)
        expect_errno(errno.EBADF, lambda: os.fstat(11))
        Path('control-file').unlink()
    elif mode == 'rename':
        assert os.uname().machine == 'x86_64'  # syscall 316 is renameat2 on this sealed guest.
        lib = ctypes.CDLL(None, use_errno=True)
        a, b = b'control-a', b'control-b'
        calls = [lambda: lib.rename(a, b),
                 lambda: lib.renameat(-100, a, -100, b),
                 lambda: lib.syscall(316, -100, a, -100, b, 0)]
        for call in calls:
            Path('control-a').write_bytes(b'control data\n')
            ctypes.set_errno(0)
            assert call() == -1 and ctypes.get_errno() == errno.EIO
            assert Path('control-a').read_bytes() == b'control data\n'
            assert not Path('control-b').exists()
            assert call() == 0
            assert not Path('control-a').exists()
            assert Path('control-b').read_bytes() == b'control data\n'
            Path('control-b').unlink()
    else:
        raise ValueError(mode)
    print('independent-control=%s-fault-and-recovery' % mode)


def setup(mode):
    command = ['/usr/bin/python3', str(SELF), 'control', mode]
    log = Path.home() / 'control.jsonl'
    if mode != 'efbig':
        command = trace_rules(mode, log) + command
    proc = subprocess.run(command, capture_output=True, timeout=10)
    (Path.home() / 'control.stdout').write_bytes(proc.stdout)
    (Path.home() / 'control.stderr').write_bytes(proc.stderr)
    assert proc.returncode == 0 and not proc.stderr, (proc.returncode, proc.stderr)
    assert proc.stdout == ('independent-control=%s-fault-and-recovery\n' % mode).encode()
    if mode != 'efbig':
        names = ['rename', 'renameat', 'renameat2'] if mode == 'rename' else [mode]
        rows = records(log)
        for name in names:
            selected = [r for r in rows if r['syscall'] == name]
            assert [r['reply'] for r in selected] == ['errno:5', 'continue'], selected
    print('independent-control=%s-fault-and-recovery' % mode)


def snapshot(stage, mode, owner):
    """Called by the live failed shell, before and after its recovery save."""
    fd = Path('/proc/%d/fd/11' % owner)
    result = {'owner': owner, 'mode': mode,
              'original_base64': base64.b64encode(Path('original.txt').read_bytes()).decode(),
              'target_base64': base64.b64encode(Path('w/target').read_bytes()).decode(),
              'temp_residue': sorted([str(p) for p in Path('w').glob('target.tmp*')] +
                                     [str(p) for p in Path('.').glob('original.txt.tmp*')]),
              'soft_hard_bytes': list(resource.prlimit(owner, resource.RLIMIT_FSIZE))}
    try:
        result['fd11'] = {'link': os.readlink(fd), 'size': fd.stat().st_size}
    except FileNotFoundError:
        result['fd11'] = None
    write_json(Path.home() / ('snapshot-' + stage + '.json'), result)


def trace_identity(rows, mode, expected, injected=True):
    """Report only actual trace facts; failures remain visible in case output."""
    error = next((i for i, r in enumerate(rows) if r['reply'] == 'errno:5'), None)
    end = error if error is not None else len(rows)
    prefix = rows[:end]
    writes = [r for r in prefix if r['syscall'] == 'write' and r.get('arg0') == 11]
    data_ok = bool(writes) and writes[0]['arg2'] == len(expected)
    if writes:
        captured = bytes.fromhex(writes[0]['memory1'].get('hex', ''))[:min(len(expected), 64)]
        data_ok &= captured == expected[:64]
    first_write = next((i for i, r in enumerate(prefix)
                        if r['syscall'] == 'write' and r.get('arg0') == 11), len(rows))
    sync = any(i > first_write and r['syscall'] == 'fdatasync' and r.get('arg0') == 11
               for i, r in enumerate(prefix))
    through_fault = rows[:error + 1] if error is not None else rows
    close_after_sync = any(r['syscall'] == 'close' and r.get('arg0') == 11 and
                           any(j > first_write and previous['syscall'] == 'fdatasync' and
                               previous.get('arg0') == 11
                               for j, previous in enumerate(through_fault[:i]))
                           for i, r in enumerate(through_fault))
    opens = [r.get('string1', '') for r in prefix if r['syscall'] == 'openat']
    temp_ok = any(str(x).startswith('w/target.tmp') or str(x).startswith('w/witness.tmp') for x in opens)
    hit_ok = True
    if mode == 'efbig':
        # A second request smaller by exactly the soft limit witnesses the
        # short first write. The independent control proves kernel EFBIG.
        hit_ok = len(writes) >= 2 and writes[1]['arg2'] == len(expected) - 1024
    elif injected:
        hit_ok = error is not None
        if hit_ok:
            hit = rows[error]
            if mode in ('fdatasync', 'close'):
                hit_ok &= hit['syscall'] == mode and hit.get('arg0') == 11
            else:
                hit_ok &= hit['syscall'] in ('rename', 'renameat', 'renameat2')
                hit_ok &= any(str(v).startswith('w/target.tmp') for k, v in hit.items() if k.startswith('string'))
            hit_ok &= sum(r['reply'] == 'errno:5' for r in rows) == 1
    if mode in ('close', 'rename'):
        hit_ok &= sync
    return {'temporary_open_observed': temp_ok, 'saved_bytes_on_fd11': bool(data_ok),
            'intended_fault_observed': bool(hit_ok), 'fdatasync_before_fault': sync,
            'close_after_data_and_sync': close_after_sync}


def buffer(shell, mode):
    inherited_limits = resource.getrlimit(resource.RLIMIT_FSIZE)
    Path('w').mkdir()
    Path('original.txt').write_bytes(initial(mode))
    Path('w/target').write_bytes(OLD)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    witness_ok = True
    if mode == 'close':
        witness = subprocess.run(trace_rules(mode, Path.home() / 'witness.jsonl', False) +
                                 [shell, '--noprofile', '--norc', 'failed-buffer.sh', mode, 'witness'],
                                 capture_output=True, env=env, timeout=10)
        (Path.home() / 'witness.stdout').write_bytes(witness.stdout)
        (Path.home() / 'witness.stderr').write_bytes(witness.stderr)
        fact = trace_identity(records(Path.home() / 'witness.jsonl'), mode, wanted(mode), False)
        witness_ok = (witness.returncode == 0 and not witness.stderr and
                      all(fact.values()) and Path('w/witness').read_bytes() == wanted(mode))
        write_json(Path.home() / 'witness-observations.json', fact)
        Path('w/witness').unlink(missing_ok=True)
    log = Path.home() / 'fault.jsonl'
    command = trace_rules(mode, log, mode != 'efbig') + [shell, '--noprofile', '--norc', 'failed-buffer.sh', mode, 'fault']
    proc = subprocess.run(command, capture_output=True, env=env, timeout=15)
    (Path.home() / 'child.stdout').write_bytes(proc.stdout)
    (Path.home() / 'child.stderr').write_bytes(proc.stderr)
    state = dict(line.split('=', 1) for line in proc.stdout.decode().splitlines() if '=' in line)
    before = json.loads((Path.home() / 'snapshot-fault.json').read_text())
    after = json.loads((Path.home() / 'snapshot-recovered.json').read_text())
    facts = trace_identity(records(log), mode, wanted(mode))
    yes = lambda value: 'yes' if value else 'no'
    print('fault=%s child-status=%d save-status=%s diagnostic=%s' %
          (mode, proc.returncode, state.get('fault-status', 'missing'),
           yes(os.strerror(errno.EFBIG if mode == 'efbig' else errno.EIO).encode() in proc.stderr)))
    print('same-child=%s same-handle=%s dirty-before-recovery=%s' %
          (yes(str(before['owner']) == str(after['owner']) == state.get('owner-before') == state.get('owner-after')),
           yes(bool(state.get('handle-before')) and state.get('handle-before') == state.get('handle-after')),
           yes(state.get('dirty-status') == '0')))
    print('rollback original-unchanged=%s target-unchanged=%s temp-residue=%d' %
          (yes(base64.b64decode(before['original_base64']) == initial(mode)),
           yes(base64.b64decode(before['target_base64']) == OLD), len(before['temp_residue'])))
    print('recovery save-without-path=%s clean=%s original-exact=%s failed-target-unchanged=%s temp-residue=%d' %
          (state.get('recovery-status', 'missing'), yes(state.get('clean-status') == '1'),
           yes(base64.b64decode(after['original_base64']) == wanted(mode)),
           yes(base64.b64decode(after['target_base64']) == OLD), len(after['temp_residue'])))
    print('fault-control intended-temp=%s fd11-bytes=%s intended-fault=%s' %
          (yes(facts['temporary_open_observed']), yes(facts['saved_bytes_on_fd11']), yes(facts['intended_fault_observed'])))
    if mode == 'close':
        # Do not credit a synthetic EIO with closing a real kernel fd. These
        # snapshots expose whether the candidate retried/retained it. Cleanup
        # occurs only after the successful same-buffer recovery observations.
        prior_fd, later_fd = before['fd11'], after['fd11']
        artifact_ok = (prior_fd is None or
                       ('/w/target.tmp' in prior_fd['link'] and
                        prior_fd['link'].endswith(' (deleted)') and prior_fd['size'] == len(wanted(mode))))
        artifact_ok &= (later_fd is None or prior_fd is not None and later_fd == prior_fd)
        print('close-witness=%s mock-close-fd-state=%s fixture-cleanup-after-recovery=%s' %
              (yes(witness_ok), 'recorded' if artifact_ok else 'invalid',
               yes(state.get('cleanup-after-snapshot') == 'yes')))
    if mode == 'efbig':
        hard_ok = (state.get('hard-before') == state.get('hard-during') == state.get('hard-after') and
                   before['soft_hard_bytes'][1] == after['soft_hard_bytes'][1] == inherited_limits[1] and
                   state.get('limited-hard-bytes') == str(inherited_limits[1]))
        soft_ok = (state.get('soft-before') == state.get('soft-after') and
                   before['soft_hard_bytes'][0] == after['soft_hard_bytes'][0] == inherited_limits[0])
        print('soft-limit-restored=%s inherited-hard-limit-unchanged=%s limited-bytes=%s' %
              (yes(soft_ok), yes(hard_ok),
               state.get('limited-bytes', 'missing')))
    write_json(Path.home() / 'observations.json', {'state': state, 'before': before, 'after': after,
                                                'trace': facts, 'close_witness_ok': witness_ok})


def diagnostic(path):
    data = Path(path).read_bytes()
    print('errno-eio=' + ('yes' if os.strerror(errno.EIO).encode() in data else 'no'))


if __name__ == '__main__':
    require_guest()
    verb, args = sys.argv[1], sys.argv[2:]
    if verb == 'setup':
        setup(args[0])
    elif verb == 'control':
        direct_control(args[0])
    elif verb == 'snapshot':
        snapshot(args[0], args[1], int(args[2]))
    elif verb == 'limits':
        print(*resource.prlimit(int(args[0]), resource.RLIMIT_FSIZE))
    elif verb == 'buffer':
        buffer(args[0], args[1])
    elif verb == 'diagnostic':
        diagnostic(args[0])
    else:
        raise ValueError(verb)
