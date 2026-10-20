#!/usr/bin/env python3
"""Validated inventory and helper-boundary timings. Run through the bench gate.

No build, live repository, real installer, or external timing ratio is used.
Every warm-up/sample has an independent exact-output and exit-status oracle;
transaction samples also validate every argv and the final empty state.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fake_source():
    tree = ast.parse((REPO / 'tests/opus-payload-installer.py').read_text())
    return next(ast.literal_eval(node.value) for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'FAKE' for t in node.targets))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--source', type=Path, default=REPO / 'loadables/payload.c')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--passes', type=int, default=40)
    parser.add_argument('--txns', type=int, default=20)
    args = parser.parse_args()
    if args.runs < 7 or args.passes < 1 or args.txns < 1:
        parser.error('at least seven samples and positive work counts required')
    cpu = args.cpu if args.cpu is not None else max(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {cpu})
    binary = str(args.binary.resolve())
    report = {
        'kind': 'self', 'binary': binary,
        'binary_sha256': digest(Path(binary).read_bytes()),
        'source_sha256': digest(args.source.read_bytes()),
        'harness_sha256': digest(Path(__file__).read_bytes()),
        'fake_helper_sha256': digest(fake_source().encode()),
        'cpu_affinity': sorted(os.sched_getaffinity(0)),
        'kernel': platform.release(), 'machine': platform.machine(),
        'cpu_model': next((line.split(':', 1)[1].strip() for line in
                           Path('/proc/cpuinfo').read_text().splitlines()
                           if line.startswith('model name')), 'unknown'),
        'python': sys.version, 'libc': platform.libc_ver(),
        'bash_version': subprocess.check_output([binary, '--version'], text=True).splitlines()[0],
        'compiler_version': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
        'options': {'runs': args.runs, 'passes': args.passes, 'txns': args.txns},
        'load_average_start': os.getloadavg(),
        'timing': 'wall milliseconds including shell startup and captured output; validation outside timer',
        'cases': [],
    }
    with tempfile.TemporaryDirectory(prefix='sol-payload-bench-') as tmp:
        top = Path(tmp)
        for mode, count, passes in [('inventory', 20000, args.passes),
                                    ('transactions', 2000, args.txns)]:
            work = top / mode
            repo, root, log = work / 'payloadrepo', work / 'payloadroot', work / 'log'
            state = root / 'var/lib/bl-pkg/installed'
            for directory in (repo, state, log):
                directory.mkdir(parents=True)
            lines = ['# bashy.box payload index (fixture)']
            rows = []
            state_hash = hashlib.sha256()
            for i in range(count):
                name, version = f'pl-{i:05d}', f'1.{i % 53}.0'
                lines.append(f'blpkg-v1 name={name} version={version} arch=x86_64 type=payload provides=bin/{name}')
                installed = mode == 'inventory' and i % 8 == 0
                if installed:
                    body = f'txn=txn-{i:05d}\nversion={version}\n'
                    (state / name).write_text(body)
                    state_hash.update(name.encode() + b'\0' + body.encode())
                rows.append('  %-10s  %-18s  %-12s  %s\n' %
                            ('installed' if installed else 'available', name, version, 'bin/' + name))
            index = ('\n'.join(lines) + '\n').encode()
            (repo / 'INDEX').write_bytes(index)
            helper = work / 'bl-pkg.sh'
            helper.write_text(fake_source())
            helper.chmod(0o644)
            env = {'LC_ALL': 'C', 'PATH': '', 'HOME': str(work),
                   'PAYLOAD_REPO': 'payloadrepo', 'PAYLOAD_ROOT': 'payloadroot',
                   'PAYLOAD_INSTALLER': str(helper), 'FAKE_LOG': str(log)}
            if mode == 'inventory':
                command = 'payload list'
                expected_once = ('payload: repo payloadrepo\n\n' +
                                 '  %-10s  %-18s  %-12s  %s\n' % ('STATUS', 'NAME', 'VERSION', 'PROVIDES') +
                                 ''.join(rows) + '\npayload: 20000 available, 2500 installed\n')
                expected = (expected_once * passes).encode()
                want = []
                unit = f'{passes} passes x {count} parsed INDEX records, 2500 installed hits and 20005 output lines per pass'
            else:
                target = f'pl-{count - 1:05d}'
                command = f'payload install {target} && payload remove {target}'
                expected = ''.join(f'helper: installed {target}\nhelper: rolled back txn-{target}-{2*i}\n'
                                   f'payload: removed {target}\n' for i in range(passes)).encode()
                base = [binary, str(helper), '--internal', '--root', 'payloadroot']
                want = []
                for i in range(passes):
                    want += [base + ['--repo', 'payloadrepo', '--allow-unsigned', 'install', target],
                             base + ['rollback', f'txn-{target}-{2*i}']]
                unit = f'{passes} install/remove pairs, {2*passes} helper executions, {passes} full {count}-record INDEX scans and transaction lookups'
            script = f'for ((i=0;i<{passes};i++)); do {command} || exit $?; done'
            case = {'workload': 'payload-list' if mode == 'inventory' else 'payload-helper-transactions',
                    'kind': 'self', 'work_unit': unit, 'index_bytes': len(index),
                    'index_sha256': digest(index), 'initial_state_sha256': state_hash.hexdigest(),
                    'expected_stdout_sha256': digest(expected), 'expected_stdout_bytes': len(expected),
                    'environment': env, 'script': script, 'checks': [],
                    'reset': 'inventory immutable; transaction state must be empty after every sample; logs deleted before each sample'}
            samples = []
            for iteration in range(args.runs + 1):
                for path in log.iterdir():
                    path.unlink()
                if mode == 'transactions':
                    assert not any(state.iterdir()), 'previous transaction left state behind'
                start = time.perf_counter_ns()
                result = subprocess.run([binary, '--noprofile', '--norc', '-c', script],
                                        cwd=work, env=env, capture_output=True, timeout=300)
                elapsed = (time.perf_counter_ns() - start) / 1e6
                calls = sorted(log.glob('call.*'), key=lambda p: int(p.suffix[1:]))
                got = [[s.decode() for s in path.read_bytes().split(b'\0')[:-1]] for path in calls]
                valid = (result.returncode == 0 and result.stdout == expected and not result.stderr
                         and got == want and (mode == 'inventory' or not any(state.iterdir())))
                case['checks'].append({'warmup': iteration == 0, 'valid': valid,
                                       'exit_code': result.returncode,
                                       'stdout_sha256': digest(result.stdout),
                                       'helper_calls': len(got), 'stderr': result.stderr.decode(errors='replace')})
                if not valid:
                    break
                if iteration:
                    samples.append(elapsed)
            case['valid_every_pass'] = len(samples) == args.runs and all(c['valid'] for c in case['checks'])
            case['samples_ms'] = samples if case['valid_every_pass'] else []
            if case['valid_every_pass']:
                case.update(median_ms=statistics.median(samples), min_ms=min(samples), max_ms=max(samples),
                            stdev_ms=statistics.stdev(samples))
            report['cases'].append(case)
            print(json.dumps({k: case[k] for k in ('workload', 'valid_every_pass', 'samples_ms')}), flush=True)
    report['load_average_end'] = os.getloadavg()
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if all(c['valid_every_pass'] for c in report['cases']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
