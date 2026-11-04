#!/usr/bin/python3
"""Pure data rules for clamp r2; no process, filesystem or syscall operations."""


def booleans(value, prefix=''):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from booleans(item, prefix + str(key) + '.')
    elif type(value) is bool:
        yield prefix.rstrip('.'), value


def notification_valid(receipt, trace, status, require_cleanup=True):
    if not isinstance(receipt, dict) or not isinstance(trace, list):
        return False
    if (receipt.get('schema') != 'clamp-notification-r2'
            or receipt.get('observer_status') != 'completed'
            or receipt.get('exec_confirmed') is not True
            or receipt.get('reaped') is not True
            or (require_cleanup and receipt.get('cleanup_complete') is not True)
            or receipt.get('termination') not in ('exit', 'signal')
            or type(receipt.get('program_status')) is not int
            or type(status) is not int or receipt['program_status'] != status):
        return False
    if not 0 <= receipt['program_status'] <= 255:
        return False
    if receipt['termination'] == 'signal' and (type(receipt.get('signal')) is not int
            or not 0 < receipt['signal'] < 65 or receipt['program_status'] != 128 + receipt['signal']):
        return False
    ids = [row.get('id') for row in trace if isinstance(row, dict)]
    ack = receipt.get('acknowledged_ids')
    return (isinstance(ack, list) and all(type(i) is int for i in ack)
            and len(ids) == len(trace) and all(type(i) is int for i in ids)
            and len(set(ids)) == len(ids) and ack == ids)


def program_result_usable(status, encoding='subprocess'):
    """Reject interruption/resource deaths before creating product checks.

    subprocess exposes actual signals as negative values. A shell's 128+signal
    result is ambiguous, so these fixtures conservatively leave interrupt-like
    shell statuses unresolved. Their expected command statuses are 0/7/73/127.
    Actual crashes or an independently witnessed SIGSYS remain behavioral data.
    """
    if type(status) is not int:
        return False
    if encoding == 'subprocess':
        if not -64 <= status <= 255:
            return False
        signal_number = -status if status < 0 else 0
    elif encoding == 'shell':
        if not 0 <= status <= 255:
            return False
        signal_number = status - 128 if status > 128 else 0
    else:
        return False
    return signal_number not in (1, 2, 9, 15, 24, 25)


def qualified_checks(report):
    """Only completed candidate observations; never native/control mismatches."""
    if not isinstance(report, dict) or report.get('control_valid') is not True:
        return {}
    checks = dict(booleans(report.get('candidate_checks', {})))
    for index, run in enumerate(report.get('runs', [])):
        if (isinstance(run, dict) and run.get('kind') == 'candidate'
                and run.get('qualified') is True):
            checks.update({'run.' + str(index) + '.' + k: v
                           for k, v in booleans(run.get('checks', {}))})
    return checks


def classify(raw, observations, differences=()):
    """Keep behavioral failures independently of observation/lifecycle status."""
    valid = (isinstance(observations, dict)
             and observations.get('schema') == 'clamp-observations-r2')
    checks = observations.get('checks', {}) if valid else {}
    failures = sorted(k for k, v in checks.items() if v is False)
    incomplete = []
    if not valid or observations.get('complete') is not True:
        incomplete.append('observer did not complete')
    if valid and observations.get('incomplete'):
        incomplete.extend(observations['incomplete'])
    for key in ('error', 'harness_error'):
        if raw.get(key):
            incomplete.append(str(raw[key]))
    if type(raw.get('status')) is not int or raw['status'] not in (0, 1):
        incomplete.append('outer observer status is not a completed 0/1 outcome')
    if raw.get('status') == 1 and not failures:
        incomplete.append('nonzero observer without qualified candidate mismatch')
    cleanup = raw.get('clamp_cleanup')
    quarantine = cleanup is not None and (cleanup.get('restored') is not True
                                          or cleanup.get('writers_gone') is not True)
    if quarantine:
        incomplete.append('guest-global cleanup unproved; discard overlay')
    product = 'FAIL' if failures else None
    if not incomplete and differences:
        product = 'FAIL'
    status = ('ERROR' if quarantine else 'FAIL' if product == 'FAIL'
              else 'ERROR' if incomplete else 'PASS')
    return {'status': status, 'product_status': product or ('PASS' if status == 'PASS' else None),
            'reached_failures': failures, 'incomplete': incomplete,
            'release_eligible': status == 'PASS' and not incomplete,
            'overlay_must_be_discarded': quarantine}
