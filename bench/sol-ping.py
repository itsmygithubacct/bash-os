#!/usr/bin/env python3
"""Fixed-count ping measurements. Build separately; run through gated.py bench.
Shim timings measure the production request/reply loop with fake socket/clock
calls. Native timings report loopback RTT and paced command wall time separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--fixtures', required=True)
p.add_argument('--output', required=True)
p.add_argument('--runs', type=int, default=7)
a = p.parse_args()
if a.runs < 7: p.error('at least seven samples are required')
binary = Path(a.binary).resolve()
fixtures = Path(a.fixtures).resolve()
module = fixtures/'fixture.so'
affinity = sorted(os.sched_getaffinity(0))
assert len(affinity) == 1, 'pin a fixed CPU using the campaign bench gate'
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def command(cmd, env):
    start = time.perf_counter_ns()
    q = subprocess.run([str(binary), '--noprofile', '--norc', '-c', cmd],
                       env=env, capture_output=True, text=True, timeout=60)
    elapsed = time.perf_counter_ns()-start
    assert q.returncode == 0, (q.returncode, q.stdout, q.stderr)
    return q, elapsed

base_env = dict(os.environ, PATH='', LC_ALL='C')
for startup_var in ['BASH_ENV', 'ENV']:
    base_env.pop(startup_var, None)
report = dict(schema=1, method='one full warm-up then >=7 validated samples per workload; same fixed CPU',
              affinity=affinity, environment=dict(platform=platform.platform(), machine=platform.machine(),
              python=platform.python_version(), bash=subprocess.check_output([str(binary), '-c', 'printf "%s" "$BASH_VERSION"'], text=True),
              uid=os.getuid(), effective_capabilities=next((s.split(':',1)[1].strip() for s in Path('/proc/self/status').read_text().splitlines() if s.startswith('CapEff:')), None),
              ping_group_range=Path('/proc/sys/net/ipv4/ping_group_range').read_text().strip(),
              compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
              cpu_model=next((s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')), 'unknown')),
              binary_sha256=digest(binary), fixture_binary_sha256=digest(module),
              source_base_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              working_tree_dirty=bool(subprocess.run(['git', 'diff', '--quiet'], cwd=ROOT).returncode),
              source_sha256={s:digest(ROOT/s) for s in ['loadables/ping.c','tests/sol-ping-fixture.c','bench/sol-ping.py']},
              reset='fresh owned Bash per sample; each shim socket resets request counters and virtual time',
              reference='none; no comparison ratio', cases=[])
summary_re = re.compile(r'(\d+) packets transmitted, (\d+) received, (\d+)% packet loss')
rtt_re = re.compile(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms')

def measure(name, family, shim):
    packets, calls = (10000, 20) if shim else (16, 1)
    host = '127.0.0.1' if family == 4 else '::1'
    cmd = f'ping -{family} -c {packets} -i .1 -W 1 {host}'
    if shim:
        cmd = f'enable -f {shlex.quote(str(module))} ping || exit; for ((j=0;j<{calls};j++)); do {cmd} -q || exit; done'
        # Bash options must precede HOST.
        cmd = cmd.replace(f'{host} -q', f'-q {host}')
    env = dict(base_env, SOL_PING_MODE='clean')
    case = dict(name=name, kind='syscall-shim' if shim else 'api', status='pending',
                command=cmd, family=family, calls=calls, packets_per_call=packets,
                packets_per_sample=packets*calls, warmups=1, samples=[],
                fixture_sha256=report['source_sha256']['tests/sol-ping-fixture.c'] if shim else None,
                interpretation='production request/reply processing with fake waits; no network RTT' if shim else
                'real loopback echo RTT; command wall time includes 100ms pacing, startup and output')
    report['cases'].append(case)
    for index in range(-1, a.runs):
        q, elapsed = command(cmd, env)
        summaries = summary_re.findall(q.stdout)
        assert summaries == [(str(packets), str(packets), '0')]*calls, summaries
        rtts = rtt_re.findall(q.stdout)
        assert len(rtts) == calls
        if shim:
            assert q.stderr.count(f'FIXTURE sends={packets} reads={packets}') == calls, q.stderr
            assert all(tuple(map(float, v)) == (.25,.25,.25,0) for v in rtts), rtts
        else:
            seqs = re.findall(r'icmp_seq=(\d+)', q.stdout)
            assert seqs == [str(n) for n in range(1, packets+1)], seqs
            assert not q.stderr, q.stderr
            assert all(0 <= float(v) for row in rtts for v in row)
        sample = dict(wall_ns=elapsed, returncode=q.returncode, summaries=summaries,
                      rtt_min_avg_max_mdev_ms=rtts, stdout=q.stdout, stderr=q.stderr,
                      validation='pass')
        if shim:
            sample.update(processing_ns_per_packet=elapsed/(packets*calls), packets_per_second=packets*calls/(elapsed/1e9))
        if index < 0: case['warmup'] = sample
        else: case['samples'].append(sample)
    walls = [v['wall_ns'] for v in case['samples']]
    case.update(status='pass', wall_ns_distribution=dict(min=min(walls), median=statistics.median(walls), max=max(walls)))
    if shim:
        vals=[v['processing_ns_per_packet'] for v in case['samples']]
        case['processing_ns_per_packet_distribution']=dict(min=min(vals), median=statistics.median(vals), max=max(vals))
    else:
        vals=[float(v['rtt_min_avg_max_mdev_ms'][0][1]) for v in case['samples']]
        case['reported_mean_rtt_ms_distribution']=dict(min=min(vals), median=statistics.median(vals), max=max(vals))
    print(name, 'pass', case.get('processing_ns_per_packet_distribution', case.get('reported_mean_rtt_ms_distribution')), flush=True)

try:
    for family in [4, 6]:
        measure(f'IPv{family} shim processing', family, True)
        measure(f'IPv{family} real loopback RTT', family, False)
finally:
    Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
assert all(c['status']=='pass' for c in report['cases']) and len(report['cases']) == 4
