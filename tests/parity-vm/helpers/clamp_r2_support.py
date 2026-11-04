#!/usr/bin/python3
"""Receipt I/O for guest-only clamp r2 observers. Importing does not run fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clamp_r2_model import notification_valid, qualified_checks, program_result_usable

HOME = Path('/tmp/parity-home')
RECORD = HOME / 'clamp-observations-r2.json'


def atomic(path, data):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(data, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def checkpoint(report, source):
    state = json.loads(RECORD.read_text()) if RECORD.exists() else {
        'schema': 'clamp-observations-r2', 'checks': {}, 'complete': False, 'incomplete': []}
    # Monotonic: later cleanup or a repeated successful observation cannot erase a FAIL.
    for name, value in qualified_checks(report).items():
        key = source + ':' + name
        state['checks'][key] = state['checks'].get(key, True) and value
    if report.get('incomplete'):
        message = source + ': ' + str(report['incomplete'])
        if message not in state['incomplete']:
            state['incomplete'].append(message)
    atomic(RECORD, state)


def finish(status, error=None):
    checkpoint({'incomplete': error} if error else {}, 'driver')
    state = json.loads(RECORD.read_text())
    state['helper_status'] = status
    state['complete'] = status in (0, 1) and not error and not state['incomplete']
    atomic(RECORD, state)
    return state


def require_program_status(status, source, encoding='subprocess'):
    if not program_result_usable(status, encoding):
        message = 'interrupted or invalid program result: %r (%s)' % (status, encoding)
        checkpoint({'incomplete': message}, source)
        raise RuntimeError(source + ': ' + message)


def observed(argv, log, timeout=25):
    """Separate observer errors from the actual program's wait status."""
    p = subprocess.run(argv, capture_output=True, timeout=timeout)
    log = Path(log)
    trace = [json.loads(line) for line in log.read_text().splitlines()]
    outcome = json.loads(Path(str(log) + '.outcome.json').read_text())
    result = {'argv': argv, 'status': p.returncode,
              'stdout': p.stdout.decode('utf8', 'backslashreplace'),
              'stderr': p.stderr.decode('utf8', 'backslashreplace'),
              'trace': trace, 'observer_outcome': outcome}
    if not notification_valid(outcome, trace, p.returncode):
        actual = outcome.get('program_status')
        # A completed candidate observation is independent of later cleanup.
        # Native controls must be entirely clean before they can qualify a case.
        if (outcome.get('program', [None])[0] == '/opt/bashos-parity/candidate'
                and outcome.get('cleanup_complete') is False and p.returncode == 125
                and notification_valid(outcome, trace, actual, require_cleanup=False)):
            result['status'] = actual
            checkpoint({'incomplete': 'notification descendant cleanup failed: ' + log.name}, 'observer')
        else:
            raise RuntimeError('notification observer incomplete: ' + str(log.name))
    status = -outcome['signal'] if outcome['termination'] == 'signal' else outcome['program_status']
    require_program_status(status, 'notification:' + log.name)
    return result


def verify_outcome(log):
    log = Path(log)
    receipt = json.loads(Path(str(log) + '.outcome.json').read_text())
    trace = [json.loads(line) for line in log.read_text().splitlines()]
    if not notification_valid(receipt, trace, receipt.get('program_status')):
        raise RuntimeError('incomplete syscall observation')
    status = -receipt['signal'] if receipt['termination'] == 'signal' else receipt['program_status']
    require_program_status(status, 'notification:' + log.name)


def cleanup_task(process, close_input=False):
    forced = False
    try:
        if process.poll() is None:
            if close_input:
                process.stdin.close()
            else:
                process.stdin.write(b'exit\n')
                process.stdin.flush()
            process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        forced = True
        process.kill()
        process.wait(timeout=5)
    if forced or process.returncode != 0:
        raise RuntimeError('owned child cleanup incomplete: pid=%d status=%s forced=%s' %
                           (process.pid, process.returncode, forced))


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == '--verify-outcome':
            verify_outcome(sys.argv[2])
        else:
            raise RuntimeError('invalid receipt operation')
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(125)
