#!/usr/bin/python3
"""Guest-only swapon contract checks; seccomp answers every request with EPERM.

Files are real swap areas so the builtin reaches swapon(2). A non-root owner
produces the util-linux warning and the syscall still happens. Priority parse
errors exit 1 before any request. Device failures exit 255.
"""
import json
import os
import subprocess
import sys
import tempfile

helper = '/opt/bashos-parity/harness/helpers/system-seccomp.py'
bash = sys.argv[1]


def make_swap(path):
    subprocess.run(['/usr/bin/dd', 'if=/dev/zero', f'of={path}', 'bs=64k', 'count=16', 'status=none'],
                   check=True)
    subprocess.run(['/usr/sbin/mkswap', '-q', path], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chown(path, 2000, 2000)


with tempfile.TemporaryDirectory(prefix='swapon-options-', dir='/tmp') as directory:
    os.chmod(directory, 0o755)
    os.chdir(directory)
    make_swap('fixture')
    make_swap('-name')
    fixture = os.path.realpath('fixture')
    dash = os.path.realpath('-name')
    cases = [
        ('lower', ['-p', '0', 'fixture'], 255, fixture, 0x8000),
        ('upper', ['--priority', '32767', 'fixture'], 255, fixture, 0xffff),
        ('negative', ['-p', '-1', 'fixture'], 255, fixture, 0),
        ('above', ['-p', '32768', 'fixture'], 1, None, None),
        ('letters', ['-p', 'abc', 'fixture'], 1, None, None),
        ('suffix', ['-p', '5x', 'fixture'], 1, None, None),
        ('empty', ['-p', '', 'fixture'], 1, None, None),
        ('empty-long', ['--priority', '', 'fixture'], 1, None, None),
        ('overflow', ['-p', '999999999999999999999999', 'fixture'], 1, None, None),
        ('missing', ['-p'], 1, None, None),
        ('missing-long', ['--priority'], 1, None, None),
        ('discard', ['-d', 'fixture'], 255, fixture, 0x10000),
        ('discard-long', ['--discard', 'fixture'], 255, fixture, 0x10000),
        ('terminator', ['--', '-name'], 255, dash, 0),
        ('unknown', ['-Z', 'fixture'], 1, None, None),
    ]
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
            if name == 'unknown':
                diagnostic = 'invalid option'
            elif name.startswith('missing'):
                diagnostic = 'requires an argument'
            else:
                diagnostic = 'failed to parse priority'
            if records or diagnostic not in result.stderr or 'fixture:' in result.stderr:
                sys.exit(f'{name}: records={records!r} stderr={result.stderr!r}')
        elif (len(records) != 1 or records[0].get('syscall') != 'swapon'
              or records[0].get('string0') != path or records[0].get('arg1') != flags
              or 'insecure file owner 2000, 0 (root) suggested.' not in result.stderr
              or f'{path}: swapon failed: Operation not permitted' not in result.stderr):
            sys.exit(f'{name}: records={records!r} stderr={result.stderr!r}')
print('PASS')
