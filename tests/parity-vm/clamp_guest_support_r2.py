#!/usr/bin/python3
"""Trusted outer-controller cleanup for guest-global clamp state, r2."""
import base64
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).parent / 'helpers'))
from clamp_r2_guard import attest_side
from clamp_r2_model import classify

PATHS = [Path('/proc/sys/kernel') / ('sched_util_clamp_' + name) for name in ('min', 'max')]


def snapshot():
    return [int(path.read_text()) for path in PATHS]


def restore(values):
    if len(values) != 2 or not 0 <= values[0] <= values[1] <= 1024:
        raise RuntimeError('invalid saved system clamps')
    current = snapshot()
    for index in ((1, 0) if values[0] > current[1] else (0, 1)):
        if snapshot()[index] != values[index]:
            data = (str(values[index]) + '\n').encode()
            fd = os.open(PATHS[index], os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.write(fd, data) != len(data):
                    raise RuntimeError('short outer restoration write')
            finally:
                os.close(fd)
    if snapshot() != values:
        raise RuntimeError('outer restoration readback differs')


def protected_root(run, terminal):
    if os.geteuid() != 0 or os.getpid() != 1:
        raise RuntimeError('outer clamp cleanup requires isolated root PID 1')
    before = snapshot()
    cleanup = {'original': before, 'restored': False, 'writers_gone': False}
    result = None
    try:
        result = run()
    except BaseException as error:
        result = {'status': None, 'error': str(error), 'harness_error': str(error),
                  'stdout_base64': '', 'stderr_base64': '', 'tree': {}}
    finally:
        try:
            killed = terminal.cleanup(-1)
            remaining = terminal.owned_processes(-1)
            for _ in range(50):
                if not remaining:
                    break
                terminal.cleanup(-1)
                time.sleep(.02)
                remaining = terminal.owned_processes(-1)
            cleanup.update(killed=killed, remaining=remaining, writers_gone=not remaining)
            if remaining:
                raise RuntimeError('writers remain before restoration')
            cleanup['before_restoration'] = snapshot()
            restore(before)
            cleanup['after_restoration'] = snapshot()
            cleanup['restored'] = cleanup['after_restoration'] == before
            if cleanup['before_restoration'] != before or killed:
                result['harness_error'] = 'inner root observer left state/processes; outer cleanup required'
        except BaseException as error:
            cleanup['error'] = type(error).__name__ + ': ' + str(error)
            result['harness_error'] = 'global clamp cleanup incomplete; discard overlay'
        finally:
            result['clamp_cleanup'] = cleanup
            attest_side(False)
    return result


def observations(result):
    record = result.get('diagnostics', {}).get('clamp-observations-r2.json', {})
    if record.get('truncated') or record.get('error') or 'base64' not in record:
        return None
    try:
        return json.loads(base64.b64decode(record['base64'], validate=True))
    except (ValueError, TypeError):
        return None


def adjudicate(case, result, differences):
    decision = classify(result, observations(result), differences)
    result['clamp_adjudication'] = decision
    return decision
