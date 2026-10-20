#!/usr/bin/env python3
"""Fixed selection and intercepted signal delivery. Run through the bench gate.
The separately built shim never calls real kill. No external ratio is claimed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import statistics
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture(root):
    """Fixed records with PIDs outside the kernel's allocation range."""
    assert int(Path('/proc/sys/kernel/pid_max').read_text()) < 2000000000
    for i in range(512):
        pid = 2000000000 + i
        name = 'kthreadd' if i == 511 else f'worker{i:03d}'
        directory = root / str(pid)
        directory.mkdir()
        (directory / 'comm').write_text(name + '\n')
        (directory / 'cmdline').write_bytes(f'/usr/bin/{name}\0--task\0{i}\0'.encode())
        euid = 2001 + i % 2
        gid = 3001 + (i % 3 != 0)
        (directory / 'status').write_text(
            f'Name:\t{name}\nUid:\t1001\t{euid}\t{euid}\t{euid}\n'
            f'Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n')
        fields = [77, 88, 99] + [0] * 15 + [1000 + i, 4096000, 20] + [0] * 29
        (directory / 'stat').write_text(f'{pid} ({name}) S ' + ' '.join(map(str, fields)) + '\n')
    h = hashlib.sha256()
    for file in sorted(root.rglob('*')):
        if file.is_file():
            h.update(str(file.relative_to(root)).encode() + b'\0' + file.read_bytes())
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--shim', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--passes', type=int, default=34)
    ap.add_argument('--runs', type=int, default=7)
    args = ap.parse_args()
    assert args.runs >= 7 and args.passes >= 3
    binary = str(args.binary.resolve(strict=True))
    shim = str(args.shim.resolve(strict=True))
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 1, 'Use the bench gate to pin CPU affinity'
    sources = ['loadables/pgrep.c', 'loadables/pkill.c', 'tests/sol-pkill-intercept.c',
               'bench/sol-pkill.py']
    report = dict(
        kind='syscall-shim', source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        working_tree=subprocess.check_output(['git', 'status', '--short'], text=True).splitlines(),
        source_sha256={p: digest(p) for p in sources}, binary=binary, binary_sha256=digest(binary),
        shim_sha256=digest(shim), cpus=cpus, kernel=platform.release(), machine=platform.machine(),
        kernel_pid_max=int(Path('/proc/sys/kernel/pid_max').read_text()),
        cpu_model=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines()
                       if x.startswith('model name')),
        versions=dict(python=platform.python_version(),
                      shell=subprocess.check_output([binary, '--version'], text=True).splitlines()[0],
                      compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0]),
        environment=dict(PATH='', LC_ALL='C', TZ='UTC'), passes=args.passes, runs=args.runs, warmups=1,
        method='Wall time includes shell startup, 512-entry proc scans, regex/selector evaluation, '
               'and synchronous intercepted signal request logging. Every pass count/status and '
               'every requested PID/signal/result are checked against fixture arithmetic.',
        reset='Read-only fixture; truncate signal log before every batch. No process state is mutated.',
        limitations=['No real kernel delivery cost or external performance ratio.',
                     'No paired speedup claim; baseline has no historical measurement.'],
        load_average_start=os.getloadavg(), cases=[])
    with tempfile.TemporaryDirectory(prefix='sol-pkill-bench-') as tmp:
        root = Path(tmp) / 'proc'
        root.mkdir()
        report['fixture_sha256'] = fixture(root)
        log = Path(tmp) / 'signals'
        env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC', LD_PRELOAD=shim,
                   SOL_PKILL_PROC_ROOT=str(root), SOL_PKILL_LOG=str(log))
        for key in ('BASH_ENV', 'ENV', 'BASHOS_PROC_ROOT', 'SOL_PKILL_FAIL', 'SOL_PKILL_REPEAT'):
            env.pop(key, None)
        cases = [
            ('pkill-regex-select-512',
             ['-USR1', '-c', '-u2001', '-G3001', '-P77', '-s99',
              '^worker(0[0-9][0-9]|1[0-9][0-9])$'],
             [2000000000 + i for i in range(200) if i % 6 == 0], int(signal.SIGUSR1), 0),
            ('pkill-full-select-512', [f'-{signal.SIGUSR2}', '-f', '-c', '-P77', '--', '--task [0-9]+$'],
             list(range(2000000000, 2000000512)), int(signal.SIGUSR2), 0),
            ('pkill-newest-select-512', ['-USR1', '-n', '-c', '-P77', '-x', 'worker[0-9]{3}'],
             [2000000510], int(signal.SIGUSR1), 0),
            ('pkill-invalid-regex', ['-USR1', '['], [], int(signal.SIGUSR1), 2)]
        for label, options, pids, sig, status in cases:
            expected = [(pid, sig, 0) for pid in pids]
            case = dict(id=label, options=options, validation='pending', kind='syscall-shim',
                        work_unit=f'{args.passes} calls; '
                                  f'{512 if status != 2 else 0} process records examined and '
                                  f'{len(pids)} intercepted deliveries per call',
                        delivered_per_pass=len(pids), delivered_per_batch=len(pids) * args.passes,
                        expected_pids=pids, expected_status=status, samples_ms=[])
            report['cases'].append(case)
            def batch():
                log.write_text('')
                command = shlex.join(['pkill', *options])
                script = f'for ((i=0;i<{args.passes};i++)); do {command}; printf "|%d\\n" "$?"; done'
                start = time.perf_counter_ns()
                p = subprocess.run([binary, '--noprofile', '--norc', '-c', script],
                                   env=env, capture_output=True, text=True, timeout=90)
                elapsed = (time.perf_counter_ns() - start) / 1e6
                output = (f'{len(pids)}\n' if status != 2 else '') + f'|{status}\n'
                assert p.returncode == 0 and p.stdout == output * args.passes, (
                    label, p.returncode, p.stdout[:200], p.stderr[:500])
                actual = [tuple(map(int, line.split())) for line in log.read_text().splitlines()]
                assert len(actual) == len(expected) * args.passes, (label, len(actual))
                if expected:
                    for offset in range(0, len(actual), len(expected)):
                        assert sorted(actual[offset:offset + len(expected)]) == expected, (label, offset)
                    assert not p.stderr, p.stderr
                else:
                    assert p.stderr.count('invalid regular expression') == args.passes, p.stderr
                return elapsed
            try:
                case['warmup_ms'] = batch()
                for _ in range(args.runs):
                    case['samples_ms'].append(batch())
                case['validation'] = 'pass: every output, status, PID, signal and delivered count verified'
                values = case['samples_ms']
                case['distribution_ms'] = dict(min=min(values), max=max(values),
                                                median=statistics.median(values),
                                                mean=statistics.mean(values), stdev=statistics.stdev(values))
            except Exception as error:
                case['validation'] = 'FAIL: ' + repr(error)
                raise
            finally:
                report['load_average_end'] = os.getloadavg()
                args.output.write_text(json.dumps(report, indent=2) + '\n')
            print(label, case['distribution_ms'], 'delivered/batch', case['delivered_per_batch'], flush=True)


if __name__ == '__main__':
    main()
