#!/usr/bin/python3
"""Guest-only swapon contract checks; seccomp answers every request with EPERM."""
import json
import os
import subprocess
import sys
import tempfile

helper = '/opt/bashos-parity/harness/helpers/system-seccomp.py'
bash = sys.argv[1]
cases = [
    ('lower', ['-p', '0', 'fixture'], 1, 'fixture', 0x8000),
    ('upper', ['--priority', '32767', 'fixture'], 1, 'fixture', 0xffff),
    ('negative', ['-p', '-1', 'fixture'], 2, None, None),
    ('above', ['-p', '32768', 'fixture'], 2, None, None),
    ('letters', ['-p', 'abc', 'fixture'], 2, None, None),
    ('suffix', ['-p', '5x', 'fixture'], 2, None, None),
    ('empty', ['-p', '', 'fixture'], 2, None, None),
    ('empty-long', ['--priority', '', 'fixture'], 2, None, None),
    ('overflow', ['-p', '999999999999999999999999', 'fixture'], 2, None, None),
    ('missing', ['-p'], 2, None, None),
    ('missing-long', ['--priority'], 2, None, None),
    ('discard', ['-d', 'fixture'], 1, 'fixture', 0x10000),
    ('discard-long', ['--discard', 'fixture'], 1, 'fixture', 0x10000),
    ('terminator', ['--', '-name'], 1, '-name', 0),
    ('unknown', ['-Z', 'fixture'], 2, None, None),
]
with tempfile.TemporaryDirectory(prefix='swapon-options-', dir='/tmp') as directory:
    os.chmod(directory, 0o777)
    for name, args, status, path, flags in cases:
        log = os.path.join(directory, 'requests')
        with open(log, 'w', encoding='utf-8'):
            pass
        os.chmod(log, 0o666)
        cmd = ['/usr/bin/setpriv', '--reuid=2000', '--regid=2000', '--clear-groups', '--',
               '/usr/bin/python3', helper, '--notify', 'swapon', '--reply', 'swapon=EPERM',
               '--log-string', 'swapon=0', '--log-args', 'swapon=1', '--log', log,
               '--', bash, '--noprofile', '--norc', '-c', 'swapon "$@"', 'case'] + args
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with open(log, encoding='utf-8') as stream:
            records = [json.loads(line) for line in stream]
        if result.returncode != status or result.stdout:
            sys.exit(f'{name}: status={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
        if path is None:
            diagnostic = 'usage' if name == 'unknown' else ('requires an argument' if name.startswith('missing') else 'invalid priority')
            if records or diagnostic not in result.stderr or 'fixture:' in result.stderr:
                sys.exit(f'{name}: records={records!r} stderr={result.stderr!r}')
        elif (len(records) != 1 or records[0].get('syscall') != 'swapon'
              or records[0].get('string0') != path or records[0].get('arg1') != flags
              or f'{path}: Operation not permitted' not in result.stderr):
            sys.exit(f'{name}: records={records!r} stderr={result.stderr!r}')
print('PASS')
