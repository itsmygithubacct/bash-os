#!/usr/bin/python3
"""Real guest sysctl controls, candidate observations, and verified restoration."""
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

H = Path('/tmp/parity-home')
SOURCE = Path(__file__).with_name('clamp-profile-control-r1.py')
spec = importlib.util.spec_from_file_location('clamp_control', SOURCE)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
PATHS = [Path('/proc/sys/kernel') / name for name in control.NAMES]


def read():
    return [int(path.read_text()) for path in PATHS]


def write(index, value):
    data = (str(value) + '\n').encode()
    fd = os.open(PATHS[index], os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if os.write(fd, data) != len(data):
            raise RuntimeError('short real sysctl write')
    finally:
        os.close(fd)


def pair(values):
    if not 0 <= values[0] <= values[1] <= 1024:
        raise RuntimeError('invalid restoration target')
    current = read()
    order = (1, 0) if values[0] > current[1] else (0, 1)
    for index in order:
        if read()[index] != values[index]:
            write(index, values[index])
    if read() != values:
        raise RuntimeError('sysctl pair readback differs')


def run(argv):
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = child.communicate(timeout=5)
    except BaseException:
        # No child may remain able to write after restoration.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate(timeout=3)
        raise
    return {'argv': argv, 'status': child.returncode,
            'stdout': out.decode('utf8', 'backslashreplace'),
            'stderr': err.decode('utf8', 'backslashreplace')}


def main():
    args = sys.argv[1:]
    if args != ['--preflight'] and args != ['--candidate', '/opt/bashos-parity/candidate']:
        raise SystemExit(125)
    filename = 'clamp-live-control.json' if args == ['--preflight'] else 'clamp-live-report.json'
    report = {'schema': 1, 'scope': 'real guest-global sysctls', 'control_valid': False,
              'events': [], 'candidate_checks': {}, 'restored': False}
    original = None
    lock = None
    code = 125

    def save():
        (H / filename).write_text(json.dumps(report, indent=2) + '\n')

    def interrupted(signum, frame):
        raise TimeoutError('live sysctl fixture interrupted: ' + str(signum))

    try:
        report['profile'] = control.guard(0)
        lock = os.open('/run/bashos-clamp-sysctl.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = read()
        report['original'] = original
        save()
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            signal.signal(sig, interrupted)
        # Leave time for child termination and restoration before the outer 60s bound.
        signal.alarm(40)
        pair([256, 768])
        # These writes bypass both CLIs and exercise the real kernel handler.
        for index, value in ((0, 900), (1, 255), (0, 1025), (1, 1025)):
            before = read()
            error = 0
            try:
                write(index, value)
            except OSError as exc:
                error = exc.errno
            event = {'direct_write': {'index': index, 'value': value}, 'errno': error,
                     'before': before, 'after': read()}
            report['events'].append(event)
            save()
            if error != errno.EINVAL or event['after'] != before:
                raise RuntimeError('kernel EINVAL/no-mutation control differs')

        requests = [(['-m', '600', '-M', '900'], [600, 900], False),
                    (['-m', '64', '-M', '512'], [64, 512], False),
                    (['-m', '900', '-M', '100'], [256, 768], True),
                    (['-M', '1025'], [256, 768], True)]
        natives = []
        for options, wanted, rejected in requests:
            pair([256, 768])
            operation = run(['/usr/bin/uclampset', '--system', *options])
            after = read()
            query = run(['/usr/bin/uclampset', '--system'])
            event = {'native': operation, 'after': after, 'query': query}
            natives.append(event)
            report['events'].append(event)
            save()
            expected_query = f'System util_clamp: min: {wanted[0]} max: {wanted[1]}\n'
            if (after != wanted or query['status'] != 0 or query['stderr'] or query['stdout'] != expected_query or
                    (operation['status'] == 0) == rejected or
                    (rejected and not operation['stderr'])):
                raise RuntimeError('util-linux live system control failed')
        report['control_valid'] = True
        save()
        if args == ['--preflight']:
            code = 0
        else:
            shell = args[1]
            for index, ((options, wanted, rejected), native) in enumerate(zip(requests, natives)):
                pair([256, 768])
                operation = run([shell, '--noprofile', '--norc', '-c',
                                 '[[ $(type -t uclampset) == builtin ]] || exit 125; uclampset --system "$@"',
                                 'live-sysctl', *options])
                event = {'candidate': operation, 'after': read()}
                report['events'].append(event)
                save()
                if operation['status'] == 125:
                    raise RuntimeError('candidate invocation precondition failed')
                checks = {'status': operation['status'] == native['native']['status'],
                          'real_readback': event['after'] == wanted,
                          'diagnostic': bool(operation['stderr']) if rejected else operation['stderr'] == ''}
                report['candidate_checks'][str(index)] = checks
                save()
                query = run([shell, '--noprofile', '--norc', '-c', 'uclampset --system'])
                event['query'] = query
                checks.update(query_status=query['status'] == 0,
                              query_bytes=query['stdout'] == native['query']['stdout'],
                              query_stderr=query['stderr'] == '')
                save()
            code = 0 if all(all(v.values()) for v in report['candidate_checks'].values()) else 1
    except Exception as error:
        report['incomplete'] = type(error).__name__ + ': ' + str(error)
        code = 1 if any(False in checks.values() for checks in report['candidate_checks'].values()) else 125
    finally:
        signal.alarm(0)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            signal.signal(sig, signal.SIG_IGN)
        if original is not None:
            try:
                pair(original)
                report['restored_values'] = read()
                report['restored'] = report['restored_values'] == original
            except Exception as error:
                report['restoration_error'] = type(error).__name__ + ': ' + str(error)
            if not report['restored']:
                # Retain reached mismatches in diagnostics, but quarantine this guest.
                code = 125
        if lock is not None:
            os.close(lock)
        save()
    if code == 0 and args[0] == '--candidate':
        print('live uclamp sysctl checks ok')
    raise SystemExit(code)


if __name__ == '__main__':
    main()
