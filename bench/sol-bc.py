#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the bc workload harness with independent oracles and source provenance.

Accepts bench/opus-bc.py options plus required --before-source/--after-source.
Build binaries and the optional allocation shim separately before running.
"""
import argparse
import decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expected(name):
    if name == 'arithmetic':
        with decimal.localcontext() as ctx:
            ctx.prec = 60
            return (format(decimal.Decimal(2).sqrt(), 'f')[:22] + '\n').encode()
    if name == 'assign-lines':
        return b''
    if name == 'print-lines':
        return ''.join(f'{i}\n' for i in range(1, 100001)).encode()
    if name == 'add-lines':
        return b'777777\n' * 100000
    if name == 'big-output':
        sys.set_int_max_str_digits(0)
        return (str(2**30000) + '\n').encode() * 300
    if name == 'for-loop':
        return f'{sum(range(200000))}\n'.encode()
    if name == 'loop-print':
        return ''.join(f'{i}\n' for i in range(100000)).encode()
    if name == 'recursion':
        a, b = 0, 1
        for _ in range(22):
            a, b = b, a + b
        return f'{a}\n'.encode()
    if name == 'obase-output':
        return (format(2**10000, 'X') + '\n').encode() * 10
    raise ValueError(name)


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--before-source', required=True, type=Path)
    parser.add_argument('--after-source', required=True, type=Path)
    args, rest = parser.parse_known_args()
    spec = importlib.util.spec_from_file_location(
        'bc_workloads', Path(__file__).with_name('opus-bc.py'))
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    external = rest[rest.index('--external') + 1] if '--external' in rest else '/usr/bin/bc'
    env = dict(os.environ, LC_ALL='C', BC_LINE_LENGTH='0')
    env.pop('BC_ENV_ARGS', None)
    env.pop('POSIXLY_CORRECT', None)
    os.environ.pop('POSIXLY_CORRECT', None)
    only = set(rest[rest.index('--only') + 1].split(',')) if '--only' in rest else None
    oracles = {}
    for name, _, _, program, _, batch in harness.workloads():
        if only and name not in only:
            continue
        oracle = expected(name)
        p = subprocess.run([external], input=program, capture_output=True,
                           env=env, timeout=600)
        assert (p.returncode, p.stdout, p.stderr) == (0, oracle, b''), name
        oracles[name] = dict(single_pass_sha256=digest(oracle),
                             batch_sha256=digest(oracle * batch))
    sys.argv = [str(Path(__file__)), *rest]
    harness.main()
    output = Path(rest[rest.index('--output') + 1])
    report = json.loads(output.read_text())
    report['adapter'] = dict(path='bench/sol-bc.py',
                             sha256=digest(Path(__file__).read_bytes()))
    report['source_sha256'] = {
        'before': digest(args.before_source.read_bytes()),
        'after': digest(args.after_source.read_bytes()),
    }
    report['oracles'] = oracles
    report['reset'] = 'Fresh interpreter and fresh fixture redirection per invocation; same shell per batch.'
    report['order'] = 'Implementation order reverses on alternate warm-up/timed rounds.'
    for name in ('before', 'after'):
        binary = report['binaries'].get(name)
        if binary:
            binary['version'] = subprocess.check_output(
                [binary['path'], '--version']).splitlines()[0].decode()
            manifest = Path(binary['path'] + '.manifest.json')
            if manifest.exists():
                binary['build_manifest'] = json.loads(manifest.read_text())
    output.write_text(json.dumps(report, indent=2) + '\n')
    for workload in report['workloads']:
        assert workload['expected_sha256'] == oracles[workload['name']]['batch_sha256']
        for name, result in workload['results'].items():
            assert result['result'] == 'ok', (workload['name'], name, result)
    print('All workload statuses and independent expected-output hashes verified.')


if __name__ == '__main__':
    main()
