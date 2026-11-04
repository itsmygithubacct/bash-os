#!/usr/bin/python3
"""Versioned private system-file contract, with upstream System query bytes."""
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clamp_r2_guard import verify
from clamp_r2_support import atomic, checkpoint, require_program_status


def main():
    verify()
    if sys.argv[1:] != ['/opt/bashos-parity/candidate'] or os.geteuid() != 2000:
        raise RuntimeError('invalid private model invocation')
    root = Path('/tmp/parity-case/private-proc/sys/kernel')
    files = [root / ('sched_util_clamp_' + suffix) for suffix in ('min', 'max')]
    read = lambda: [path.read_bytes() for path in files]
    if read() != [b'32\n', b'512\n']:
        raise RuntimeError('private model initial state differs')
    report = {'control_valid': True, 'candidate_checks': {}, 'events': [],
              'oracle_revision': '0.1.4 System capitalization; frozen lowercase oracle retained'}
    env = dict(os.environ, BASHOS_PROC_ROOT='private-proc')
    for index, (options, expected, query) in enumerate([
        ([], [32, 512], True), (['-m', '64', '-M', '768'], [64, 768], False),
        ([], [64, 768], True), (['-m', '-1', '-M', '900'], [64, 900], False),
        ([], [64, 900], True)]):
        result = subprocess.run([sys.argv[1], '--noprofile', '--norc', '-c',
                                 'uclampset --system "$@"', 'private-model', *options],
                                env=env, capture_output=True, timeout=5)
        after = read()
        wanted = ('System util_clamp: min: %d max: %d\n' % tuple(expected)).encode() if query else b''
        report['events'].append({'options': options, 'status': result.returncode,
                                 'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex(),
                                 'after_hex': [x.hex() for x in after]})
        atomic('/tmp/parity-home/private-model-report-r2.json', report)
        require_program_status(result.returncode, 'private-model-' + str(index))
        checks = {'status': result.returncode == 0, 'stdout': result.stdout == wanted,
                  'stderr': result.stderr == b'', 'file_values': after == [(str(x) + '\n').encode() for x in expected]}
        report['candidate_checks'][str(index)] = checks
        atomic('/tmp/parity-home/private-model-report-r2.json', report)
        checkpoint(report, 'private-model')
        sys.stdout.buffer.write(result.stdout); sys.stdout.buffer.flush()
        sys.stderr.buffer.write(result.stderr); sys.stderr.buffer.flush()
    return 0 if all(all(checks.values()) for checks in report['candidate_checks'].values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
