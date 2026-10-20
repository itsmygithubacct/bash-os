#!/usr/bin/env python3
"""Validated fixed key operations through the fixture or an owned kernel child.

No compilation. Invoke with the campaign bench resource gate. Both modes include
shell costs and neither is an external-tool comparison.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('keyctl_checks', ROOT / 'tests/sol-keyctl-check.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--validation', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--cycles', type=int, default=1000)
    p.add_argument('--runs', type=int, default=7)
    p.add_argument('--mode', choices=['shim', 'kernel'], default='shim')
    args = p.parse_args()
    if args.runs < 7 or args.cycles < 1:
        p.error('at least seven runs and one cycle required')
    validation = json.loads(args.validation.read_text())
    assert validation['failed'] == 0 and validation['passed'] >= 100
    binary, module = args.binary.resolve(), args.module.resolve()
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'run through bench gate with fixed CPU affinity'
    payload = bytes(range(256))
    state = b'calls=8 bad=0 joined=1 linked=0 revoked=1 ring=-3\n'
    expected_unit = b'9001\n10001\n10001\n' + payload + state
    expected = expected_unit * args.cycles
    if args.mode == 'kernel':
        assert validation['kernel']['status'] == 'passed', 'qualify the private kernel fixture before timing'
    with tempfile.TemporaryDirectory(prefix='sol-keyctl-bench-') as temp:
        f = Path(temp) / 'payload'
        f.write_bytes(payload)
        script = checks.setup(module) + f'''
[[ $(type -t keyctl) == builtin ]] || exit 92
for ((i=0;i<{args.cycles};i++)); do
    keyctl_fixture reset || exit 93
    keyctl session || exit 94
    keyctl add user bench <{shlex.quote(str(f))} || exit 95
    keyctl search @s user bench || exit 96
    keyctl print 10001 || exit 97
    keyctl revoke 10001 || exit 98
    keyctl clear @s || exit 99
    keyctl clear @s || exit 100
    keyctl_fixture check || exit 101
    keyctl_fixture stats || exit 102
done
'''
        if args.mode == 'kernel':
            base = shlex.quote(temp)
            script = f'''
PATH=
[[ $(type -t keyctl) == builtin ]] || exit 92
keyctl session >{base}/ring || exit 93
read -r ring <{base}/ring
[[ $ring =~ ^[1-9][0-9]*$ ]] || exit 94
trap 'keyctl clear "$ring" >/dev/null; keyctl revoke "$ring" >/dev/null' EXIT
keyctl add user bench <{shlex.quote(str(f))} >{base}/id || exit 95
read -r id <{base}/id
[[ $id =~ ^[1-9][0-9]*$ ]] || exit 96
trap 'keyctl revoke "$id" && keyctl clear "$ring" && keyctl clear "$ring" && keyctl revoke "$ring" || exit 105' EXIT
printf '%s\\n' "$id"
for ((i=0;i<{args.cycles};i++)); do
    keyctl add user bench <{shlex.quote(str(f))} || exit 97
    keyctl search "$ring" user bench || exit 98
    keyctl print "$id" || exit 99
done
keyctl search "$ring" user bench >{base}/found || exit 100
read -r found <{base}/found
[[ $found == "$id" ]] || exit 101
'''

        def valid_output(r):
            if r.returncode or r.stderr:
                return False
            if args.mode == 'shim':
                return r.stdout == expected
            first, sep, rest = r.stdout.partition(b'\n')
            return (bool(sep) and first.isdigit() and 0 < int(first) <= 2147483647
                    and rest == (first + b'\n' + first + b'\n' + payload) * args.cycles)

        results = []
        # Validate a complete batch before warm-up or timed samples.
        preflight = checks.invoke(binary, script)
        assert valid_output(preflight), preflight
        for index in range(args.runs + 1):
            started = time.perf_counter_ns()
            r = checks.invoke(binary, script)
            elapsed = time.perf_counter_ns() - started
            good = valid_output(r)
            row = dict(phase='warmup' if index == 0 else 'sample', status='ok' if good else 'invalid',
                       exit_code=r.returncode, elapsed_ns=elapsed,
                       stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),
                       stderr=r.stderr.decode(errors='replace'))
            results.append(row)
            if not good:
                break
    valid = len(results) == args.runs + 1 and all(r['status'] == 'ok' for r in results)
    samples = [r['elapsed_ns'] / 1e6 for r in results if r['phase'] == 'sample'] if valid else []
    source_files = ['loadables/keyctl.c', 'tests/sol-keyctl-shim.c',
                    'tests/sol-keyctl-check.py', 'tests/sol-keyctl-build.sh', 'bench/sol-keyctl.py']
    report = dict(workload='keyctl-fixed-binary-lifecycle', kind='syscall-shim',
                  status='ok' if valid else 'invalid', external_ratio=None,
                  validation=str(args.validation.resolve()), validation_sha256=sha(args.validation),
                  kernel_coverage=validation['kernel'],
                  work_unit=dict(cycles=args.cycles, builtin_operations=7 * args.cycles,
                                 injected_syscalls=8 * args.cycles, payload_bytes_per_cycle=256,
                                 output_bytes=len(expected)),
                  reset='fixture reset and anonymous session at start of every cycle; clear twice at end',
                  oracle='fixed serials, exact 256-byte binary payload, exact syscall counts and final link/revoke state for EVERY cycle',
                  fixture_sha256=hashlib.sha256(payload).hexdigest(),
                  expected_stdout_sha256=hashlib.sha256(expected).hexdigest(),
                  binary=str(binary), binary_sha256=sha(binary),
                  module=str(module), module_sha256=sha(module),
                  source_sha256={name: sha(ROOT / name) for name in source_files},
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_tree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                  environment=dict(affinity=affinity, kernel=platform.release(), machine=platform.machine(),
                                   platform=platform.platform(), python=platform.python_version(),
                                   bash=subprocess.check_output([str(binary), '--version'], text=True).splitlines()[0],
                                   compiler=(module.parent / 'compiler-version.txt').read_text().splitlines()[0],
                                   cpu_model=next((s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines()
                                                   if s.startswith('model name')), 'unknown'),
                                   LC_ALL='C', PATH='empty inside child'),
                  options=dict(runs=args.runs, cycles=args.cycles, warmups=1),
                  passes=results, samples_ms=samples,
                  distribution_ms=dict(min=min(samples), median=statistics.median(samples), max=max(samples),
                                       mean=statistics.mean(samples), stdev=statistics.stdev(samples)) if valid else None,
                  limitations=['Closed syscall fixture, not kernel latency or keyutils parity.',
                               'Includes shell startup, loops, redirects, output capture and fixture controls.',
                               'Actual permission, quota and concurrent-update behavior is not established by injected responses.'])
    if args.mode == 'kernel':
        report.update(workload='keyctl-kernel-update-search-read', kind='api',
                      work_unit=dict(cycles=args.cycles, builtin_operations=3 * args.cycles,
                                     syscalls=4 * args.cycles, payload_bytes_per_cycle=256,
                                     setup_cleanup_builtin_operations=7, setup_cleanup_syscalls=7),
                      reset='new anonymous session and seeded key in every child; revoke owned key and clear/revoke owned ring at exit',
                      oracle='seed ID must be positive signed-32-bit; every add/search must return that ID; every print must match fixed 256 bytes',
                      expected_stdout_sha256=None,
                      limitations=['Native child-owned anonymous kernel keyring; includes shell/redirect/output capture costs.',
                                   'Times update/search/read; revoke/clear are setup/cleanup, not individually isolated timings.',
                                   'No external keyutils ratio, permission/quota coverage, or concurrent writer in this workload.'])
    report['options']['mode'] = args.mode
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'work_unit', 'distribution_ms', 'environment')}, indent=2))
    return not valid


if __name__ == '__main__':
    raise SystemExit(main())
