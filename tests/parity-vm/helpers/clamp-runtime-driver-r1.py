#!/usr/bin/python3
"""Distinguish recorded candidate mismatches from incomplete ported observers."""
import importlib.util
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).parent
H = Path('/tmp/parity-home')
REPORTS = ('uclamp-check.json', 'query-report.json', 'alltasks-report.json',
           'setter-report.json', 'setter-update-report.json', 'scheduler-mock-report.json')


def false_check(value):
    if isinstance(value, dict):
        return any(false_check(item) for item in value.values())
    return value is False


def reached_failure():
    for name in REPORTS:
        path = H / name
        if not path.exists():
            continue
        record = json.loads(path.read_text())
        if name == 'uclamp-check.json' and record.get('pass') is False:
            return True
        if record.get('control_valid') is True and false_check(record.get('candidate_checks', {})):
            return True
    return False


def main():
    code = 125
    outcome = {'schema': 1, 'helper_status': None, 'incomplete': None}
    try:
        spec = importlib.util.spec_from_file_location('profile', HERE / 'clamp-profile-control-r1.py')
        profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile)
        profile.guard()
        helper = Path(sys.argv[1])
        if helper.parent != HERE or not helper.name.startswith('clamp-runtime-') or helper.name == Path(__file__).name:
            raise RuntimeError('unknown runtime helper')
        if not helper.is_file() or helper.is_symlink():
            raise RuntimeError('runtime helper unavailable')
        sys.argv = sys.argv[1:]
        try:
            runpy.run_path(str(helper), run_name='__main__')
            code = 0
        except SystemExit as result:
            code = result.code if type(result.code) is int else 125
        outcome['helper_status'] = code
        mismatch = reached_failure()
        outcome['reached_candidate_failure'] = mismatch
        # A Python crash, missing observer or exit 125 cannot become product FAIL
        # just because the plain harness expected zero. Preserve already saved FAILs.
        code = 1 if mismatch else (0 if code == 0 else 125)
    except Exception as error:
        outcome['incomplete'] = type(error).__name__ + ': ' + str(error)
        try:
            code = 1 if reached_failure() else 125
        except Exception:
            code = 125
    outcome['status'] = code
    (H / 'clamp-runtime-outcome.json').write_text(json.dumps(outcome, indent=2) + '\n')
    raise SystemExit(code)


if __name__ == '__main__':
    main()
