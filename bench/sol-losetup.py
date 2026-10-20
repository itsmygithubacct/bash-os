#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixture discovery and syscall-shim request batches; no external ratios.

Run through the bench gate after compiling the fixture module separately.
Every warm-up/sample validates output, exit status, FD audit, request counts,
and independently specified resulting state. No host loop devices are used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('losetup_fixture', ROOT / 'tests/sol-losetup-fixtures.py')
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture_hash(root):
    digest = hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.is_dir():
            continue
        digest.update(str(p.relative_to(root)).encode() + b'\0')
        data = str(p.readlink()).encode() if p.is_symlink() else p.read_bytes()
        digest.update(data.replace(str(root).encode(), b'/FIXTURE') + b'\0')
    return digest.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--runs', type=int, default=7)
    p.add_argument('--discovery-passes', type=int, default=100)
    p.add_argument('--request-passes', type=int, default=1000)
    a = p.parse_args()
    if not __debug__:
        p.error('validation requires Python assertions enabled')
    if a.runs < 7 or min(a.discovery_passes, a.request_passes) < 1:
        p.error('at least seven samples and positive pass counts required')
    a.binary, a.module = a.binary.resolve(), a.module.resolve()
    affinity = sorted(os.sched_getaffinity(0))
    if len(affinity) != 1:
        p.error('run with fixed single-CPU affinity (campaign bench gate provides it)')
    report = dict(kind='syscall-shim', comparison=None, cpu_affinity=affinity,
                  environment=dict(platform=platform.platform(), machine=platform.machine(),
                                   python=platform.python_version(), libc=platform.libc_ver(),
                                   path='', locale='C', timezone='UTC'),
                  binary=str(a.binary), binary_sha256=sha(a.binary),
                  module=str(a.module), module_sha256=sha(a.module),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_state='Working tree; exact source hashes identify measured implementation.',
                  sources={str(x): sha(ROOT / x) for x in ['loadables/losetup.c', 'tests/sol-losetup-shim.c',
                                                            'tests/sol-losetup-fixtures.py', 'tests/sol-losetup-build.sh', 'bench/sol-losetup.py']},
                  versions=dict(shell=subprocess.check_output([str(a.binary), '--version'], text=True).splitlines()[0],
                                compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]),
                  runs=a.runs, warmups=1, cases=[],
                  limits=['Private regular files replace sysfs and device nodes; all loop ioctls intercepted.',
                          'Includes shell startup, module loading, loop overhead and output capture.',
                          'No external reference or real-loop performance/qualification; no speedup claim.'])
    with tempfile.TemporaryDirectory(prefix='sol-losetup-bench-') as d:
        root = Path(d)
        image = fx.fixture(root)
        shutil.rmtree(root / 'sys')
        (root / 'sys').mkdir()
        expected_rows = []
        for i in range(128):
            target = root / 'sys' / f'loop{i}'
            (target / 'loop').mkdir(parents=True)
            off, ro, dio = i * 512, i % 2, (i // 2) % 2
            for field, value in [('backing_file', image), ('offset', off), ('dio', dio)]:
                (target / 'loop' / field).write_text(str(value) + '\n')
            (target / 'ro').write_text(str(ro) + '\n')
            expected_rows.append(fx.row(f'loop{i}', ro, off, dio, image).rstrip('\n'))
        fixture_digest, image_digest = fixture_hash(root), sha(image)
        prefix = fx.setup(a.module, root) + 'losetup_fixture quiet || exit 92\n'
        n, m = a.discovery_passes, a.request_passes
        discovery = (prefix + f'for ((i=0;i<{n};i++)); do losetup --list || exit 93; '
                     'losetup_fixture assert || exit 94; done\nlosetup_fixture counts\nlosetup_fixture state\n')
        requests = (prefix + f'for ((i=0;i<{m};i++)); do '
                    f'losetup -f --show -r -P -o 4096 --sizelimit 8192 {shlex.quote(str(image))} || exit 93; '
                    f'losetup_fixture expect 1 4096 8192 9 {shlex.quote(str(image))} || exit 97; '
                    'losetup --detach /dev/loop1 || exit 94; losetup_fixture assert || exit 95; done\n'
                    f'losetup /dev/loop2 -o 65536 --sizelimit 32768 {shlex.quote(str(image))} || exit 96\n'
                    'losetup_fixture counts\nlosetup_fixture state\n')

        def validate_discovery(r):
            lines = r.stdout.splitlines()
            expected_tail = f'counts {512*n} {512*n} 0\n' + fx.AUDIT
            assert len(lines) == 129*n + len(expected_tail.splitlines()), 'discovery row count'
            for i in range(n):
                batch = lines[129*i:129*(i+1)]
                assert batch[0] == fx.HEADER.rstrip('\n'), 'discovery header'
                assert sorted(batch[1:]) == sorted(expected_rows), f'discovery pass {i}'
            assert '\n'.join(lines[129*n:]) + '\n' == expected_tail, 'discovery resulting state'

        def validate_requests(r):
            expected = ('/dev/loop1\n' * m + f'counts {4*m+2} {4*m+2} {4*m+2}\n' +
                        fx.AUDIT + f'loop2 {image} 65536 32768 0\n')
            assert r.stdout == expected, 'request outputs/counts/resulting state'

        for name, script, validator, work in [
            ('discovery', discovery, validate_discovery,
             dict(passes=n, devices_per_pass=128, sysfs_reads_per_pass=512, rows=n*128)),
            ('requests', requests, validate_requests,
             dict(cycles=m, attach=m+1, detach=m, get_free=m, ioctls=4*m+2))]:
            case = dict(name=name, status='pending', work=work, samples_seconds=[],
                        options=script.replace(str(root), '/FIXTURE').replace(str(a.module), '/MODULE'),
                        fixture_sha256=fixture_digest, image_sha256=image_digest, sample_validation=[],
                        reset='Fresh shell, empty in-memory state except foreign loop0; same files on every sample.')
            report['cases'].append(case)
            try:
                for sample in range(a.runs + 1):
                    start = time.perf_counter()
                    r = fx.invoke(a.binary, script, root)
                    elapsed = time.perf_counter() - start
                    assert r.returncode == 0, f'exit {r.returncode}: {r.stderr}'
                    assert not r.stderr, r.stderr
                    validator(r)
                    assert sha(image) == image_digest, 'backing file changed'
                    assert fixture_hash(root) == fixture_digest, 'fixture changed'
                    case['sample_validation'].append(dict(sample=sample, warmup=sample == 0,
                                                          exit_code=r.returncode, validated=True,
                                                          stdout_sha256=hashlib.sha256(r.stdout.encode()).hexdigest()))
                    if sample:
                        case['samples_seconds'].append(elapsed)
                case.update(status='pass', validation='Every pass matched independent output/state/count oracle; no live FDs or directories, no foreign cleanup.',
                            median_seconds=statistics.median(case['samples_seconds']),
                            min_seconds=min(case['samples_seconds']), max_seconds=max(case['samples_seconds']))
            except Exception as e:
                case.update(status='fail', error=str(e))
            a.output.write_text(json.dumps(report, indent=2) + '\n')
            print(name, case['status'], case.get('median_seconds', case.get('error')))
    if any(c['status'] != 'pass' for c in report['cases']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
