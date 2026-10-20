#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated query and controlled mutation timings; compile the shim separately.
Run via the campaign bench gate. Every call records its exact status. Syscall
requests and every fixture write are independently checked after each sample.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = Path('/usr/bin/uclampset')
GETATTR = {'x86_64': 315, 'aarch64': 275, 'riscv64': 275}[platform.machine()]


class Attr(ctypes.Structure):
    _fields_ = [('size', ctypes.c_uint32), ('policy', ctypes.c_uint32),
                ('flags', ctypes.c_uint64), ('nice', ctypes.c_int32),
                ('prio', ctypes.c_uint32), ('runtime', ctypes.c_uint64),
                ('deadline', ctypes.c_uint64), ('period', ctypes.c_uint64),
                ('util_min', ctypes.c_uint32), ('util_max', ctypes.c_uint32)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def version(argv):
    p = subprocess.run(argv, capture_output=True, check=True)
    return p.stdout.decode().splitlines()[0]


def logs(state, kind):
    p = state / 'log'
    return [dict(f.split('=', 1) for f in line.split()[1:])
            for line in p.read_text().splitlines() if line.startswith(kind + ' ')] if p.exists() else []


def run(binary, command, calls, env, directory):
    script = r'''out=$1/out err=$1/err statuses=$1/statuses; shift
: >"$out"; : >"$err"; : >"$statuses"
start=$EPOCHREALTIME
for ((i=0;i<CALLS;i++)); do
  "$@" >>"$out" 2>>"$err"
  printf '%s\n' "$?" >>"$statuses"
done
end=$EPOCHREALTIME
printf '%s %s\n' "$start" "$end"
'''.replace('CALLS', str(calls))
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', script, 'bench', str(directory), *command],
                       env=env, capture_output=True, cwd=directory, timeout=120)
    assert p.returncode == 0 and not p.stderr, (p.returncode, p.stderr)
    start, end = map(float, p.stdout.split())
    return (end - start) * 1000 / calls, (directory / 'out').read_bytes(), (directory / 'err').read_bytes(), (directory / 'statuses').read_bytes()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    ap.add_argument('shim', type=Path)
    ap.add_argument('output', type=Path)
    ap.add_argument('--source', type=Path, help='Exact source snapshot used by a preserved baseline binary')
    ap.add_argument('--source-commit', help='Commit for that source snapshot')
    ap.add_argument('--calls', type=int, default=300)
    ap.add_argument('--samples', type=int, default=9)
    ap.add_argument('--cpu', type=int, default=max(os.sched_getaffinity(0)))
    a = ap.parse_args()
    assert a.calls > 0 and a.samples >= 7
    binary, shim = str(a.binary.resolve()), str(a.shim.resolve())
    os.sched_setaffinity(0, {a.cpu})
    child = subprocess.Popen([sys.executable, '-c', 'import time; print(1, flush=True); time.sleep(3600)'], stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b'1\n'
        pid = child.pid
        oracle = Attr()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        assert libc.syscall(ctypes.c_long(GETATTR), ctypes.c_long(pid), ctypes.byref(oracle), ctypes.c_ulong(56), ctypes.c_ulong(0)) == 0
        comm = Path(f'/proc/{pid}/comm').read_text().strip()
        query = f'{comm} ({pid}) util_clamp: min: {oracle.util_min} max: {oracle.util_max}\n'.encode()
        rows = []
        artifacts = a.output.with_name(a.output.stem + '-raw')
        artifacts.mkdir()
        with tempfile.TemporaryDirectory(prefix='sol-uclampset-bench-') as tmp:
            d = Path(tmp)
            state, proc = d / 'shim', d / 'proc'
            state.mkdir()
            kernel = proc / 'sys/kernel'
            kernel.mkdir(parents=True)
            env = {'PATH': '', 'LC_ALL': 'C'}
            injected = {**env, 'LD_PRELOAD': shim, 'UCLAMP_SHIM_DIR': str(state)}
            configs = [('query', 'builtin', ['uclampset', '-p', str(pid)], env, 'compared'),
                       ('query', 'external', [str(EXTERNAL), '-p', str(pid)], env, 'compared')]
            if not Path('/proc/sys/kernel/sched_util_clamp_min').exists():
                for impl, exe in [('builtin', 'uclampset'), ('external', str(EXTERNAL))]:
                    configs.append(('pid-set-refused', impl, [exe, '-m', '0', '-M', '512', '-p', str(pid)], env, 'compared'))
            configs += [('pid-set-shim', 'builtin', ['uclampset', '-m', '0', '-M', '512', '-p', str(pid)],
                         {**injected, 'UCLAMP_SHIM_SET': 'emulate'}, 'syscall-shim'),
                        ('system-set', 'builtin', ['eval', 'uclampset -m $((i%2 ? 200 : 100)) -s'],
                         {**injected, 'UCLAMP_SHIM_SET': 'real', 'BASHOS_PROC_ROOT': str(proc)}, 'syscall-shim')]
            for wl, impl, cmd, e, kind in configs:
                rows.append(dict(workload=wl, implementation=impl, command=cmd, environment=e, kind=kind, records=[]))
            # Reverse execution order each round to reduce order bias. Round 0 warms every case.
            for sample in range(a.samples + 1):
                for row in rows[::1 if sample % 2 == 0 else -1]:
                    for f in state.iterdir():
                        f.unlink()
                    (kernel / 'sched_util_clamp_min').write_text('0\n')
                    (kernel / 'sched_util_clamp_max').write_text('1024\n')
                    ms, out, err, statuses = run(binary, row['command'], a.calls, row['environment'], d)
                    wl = row['workload']
                    problems = []
                    expected_rc = 1 if wl == 'pid-set-refused' else 0
                    if statuses != f'{expected_rc}\n'.encode() * a.calls:
                        problems.append('exact per-call status mismatch')
                    expected_out = query * a.calls if wl == 'query' else b''
                    expected_err = (f"uclampset: failed to set pid {pid}'s uclamp values: Operation not supported\n".encode() * a.calls if wl == 'pid-set-refused' else b'')
                    if (out, err) != (expected_out, expected_err):
                        problems.append('stdout/stderr mismatch')
                    if wl == 'pid-set-shim':
                        expected = dict(pid=str(pid), size='56', flags='0x78', min='0', max='512', uflags='0', result='0')
                        expected.update({field: str(getattr(oracle, field)) for field in ('policy', 'nice', 'prio', 'runtime', 'deadline', 'period')})
                        sets = logs(state, 'set')
                        if len(sets) != a.calls or any(any(r.get(k) != v for k, v in expected.items()) for r in sets):
                            problems.append('scheduler request mismatch')
                        if (state / f'state-{pid}').read_text() != '0 512\n':
                            problems.append('final clamp state mismatch')
                    if wl == 'system-set':
                        writes = logs(state, 'write')
                        if len(writes) != a.calls or any(r != dict(path='sched_util_clamp_min', value=str(200 if i % 2 else 100), bytes='4', count='4', result='0') for i, r in enumerate(writes)):
                            problems.append('per-call system write mismatch')
                        if (kernel / 'sched_util_clamp_min').read_text() != ('200\n' if a.calls % 2 == 0 else '100\n') or (kernel / 'sched_util_clamp_max').read_text() != '1024\n':
                            problems.append('final system state mismatch')
                    raw = artifacts / f"sample-{sample:02d}-{wl}-{row['implementation']}"
                    raw.mkdir()
                    for name, data in [('stdout', out), ('stderr', err), ('statuses', statuses)]:
                        (raw / name).write_bytes(data)
                    if (state / 'log').exists():
                        (raw / 'syscalls').write_bytes((state / 'log').read_bytes())
                    if wl == 'system-set':
                        for side in ('min', 'max'):
                            (raw / side).write_bytes((kernel / ('sched_util_clamp_' + side)).read_bytes())
                    if wl == 'pid-set-shim':
                        (raw / 'state').write_bytes((state / f'state-{pid}').read_bytes())
                    row['records'].append(dict(warmup=sample == 0, ms_per_call=ms, valid=not problems, problems=problems, artifacts=str(raw),
                                               statuses_sha256=sha(statuses), stdout_sha256=sha(out), stderr_sha256=sha(err),
                                               syscall_log_sha256=sha((state / 'log').read_bytes()) if (state / 'log').exists() else None))
                    print(wl, row['implementation'], sample, not problems, flush=True)
            for row in rows:
                row['valid'] = all(r['valid'] for r in row['records'])
                row['samples_ms_per_call'] = [r['ms_per_call'] for r in row['records'] if not r['warmup']]
                row['median_ms_per_call'] = statistics.median(row['samples_ms_per_call'])
                row['range_ms_per_call'] = [min(row['samples_ms_per_call']), max(row['samples_ms_per_call'])]
            ratios = {}
            for wl in ('query', 'pid-set-refused'):
                pair = [r for r in rows if r['workload'] == wl]
                if len(pair) == 2 and all(r['valid'] for r in pair):
                    ratios[wl] = pair[0]['median_ms_per_call'] / pair[1]['median_ms_per_call']
            report = dict(binary=binary, binary_sha256=sha(Path(binary).read_bytes()),
                          source_sha256=sha((a.source or ROOT / 'loadables/uclampset.c').read_bytes()),
                          source_commit=a.source_commit or version(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']),
                          source_dirty=False if a.source else bool(subprocess.check_output(['git', '-C', str(ROOT), 'diff', '--', 'loadables/uclampset.c'])),
                          shim_sha256=sha(Path(shim).read_bytes()), shim_source_sha256=sha((ROOT / 'tests/opus-uclampset-shim.c').read_bytes()),
                          harness_sha256=sha(Path(__file__).read_bytes()), external_sha256=sha(EXTERNAL.read_bytes()),
                          versions=dict(binary=version([binary, '--version']), external=version([str(EXTERNAL), '-V']), python=sys.version, libc=platform.libc_ver(), compiler=version(['cc', '--version'])),
                          oracle=dict(pid=pid, comm=comm, attributes={name: getattr(oracle, name) for name, _ in Attr._fields_}),
                          artifacts=str(artifacts),
                          kernel=platform.release(), machine=platform.machine(), cpu_affinity=sorted(os.sched_getaffinity(0)),
                          cpu_model=next((s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')), ''),
                          nice=os.getpriority(os.PRIO_PROCESS, 0), load=os.getloadavg(), calls_per_sample=a.calls, samples=a.samples, warmups=1,
                          fixture_initial_sha256={'min': sha(b'0\n'), 'max': sha(b'1024\n'), 'shim_state': sha(b'')},
                          reset='each sample: clear all shim state/log files, reset system fixture to 0/1024; use the same owned idle child',
                          timer='EPOCHREALTIME around N calls including shell loop, output redirections and exact status recording; validation outside timer',
                          rows=rows, ratios=ratios,
                          limitations=['Accepted PID and system setters include interception log/state I/O; no external ratios for these workloads.', 'Live accepted utilization-clamp setter timing unavailable on this kernel.'])
            a.output.write_text(json.dumps(report, indent=2) + '\n')
            for r in rows:
                print(r['workload'], r['implementation'], r['valid'], r['median_ms_per_call'], r['range_ms_per_call'])
            return 0 if all(r['valid'] for r in rows) else 1
    finally:
        child.kill()
        child.wait()
        child.stdout.close()


if __name__ == '__main__':
    sys.exit(main())
