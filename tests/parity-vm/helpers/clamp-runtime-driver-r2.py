#!/usr/bin/python3
"""Guest r2 observer driver; qualified checks survive interruption and cleanup."""
import importlib.util
from pathlib import Path
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from clamp_r2_support import atomic, finish
from clamp_r2_model import classify


def main():
    code, error = 125, None
    try:
        spec = importlib.util.spec_from_file_location('profile', HERE / 'clamp-profile-control-r2.py')
        profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile)
        profile.guard()
        if sys.argv[1] == '--script':
            script, shell = Path(sys.argv[2]), sys.argv[3]
            if script != Path('/tmp/parity-case/clamp-r2-body.sh') or script.is_symlink() or shell != '/opt/bashos-parity/candidate':
                raise RuntimeError('unrecognized script invocation')
            completed = subprocess.run([shell, '--noprofile', '--norc', str(script)], timeout=45)
            code = completed.returncode
            if not Path('/tmp/parity-home/clamp-body-completed-r2').is_file():
                raise RuntimeError('script observer did not complete')
        else:
            helper = Path(sys.argv[1])
            if (helper.parent != HERE or helper.is_symlink() or not helper.is_file()
                    or not helper.name.startswith('clamp-runtime-') or not helper.name.endswith('-r2.py')
                    or helper == Path(__file__)):
                raise RuntimeError('unknown runtime helper')
            sys.argv = sys.argv[1:]
            try:
                runpy.run_path(str(helper), run_name='__main__')
                code = 0
            except SystemExit as result:
                code = result.code if type(result.code) is int else 125
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    observations = finish(code, error)
    outcome = classify({'status': code, 'error': error}, observations)
    atomic('/tmp/parity-home/clamp-runtime-outcome.json', dict(outcome, helper_status=code))
    return {'PASS': 0, 'FAIL': 1, 'ERROR': 125}[outcome['status']]


if __name__ == '__main__':
    raise SystemExit(main())
