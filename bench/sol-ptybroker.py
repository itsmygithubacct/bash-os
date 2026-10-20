#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""API timings with independent byte oracles; invoke through the bench gate."""
import argparse
import ctypes
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('streams', ROOT/'tests/sol-ptybroker-streams.py')
work = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(work)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distribution(values):
    ordered = sorted(values)
    return dict(samples=values, minimum=min(values), median=statistics.median(values),
                maximum=max(values), p95=ordered[min(len(values)-1, int(.95*len(values)))])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bash', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--runs', type=int, default=7)
    args = p.parse_args()
    assert args.runs >= 7
    args.bash = args.bash.resolve()
    args.loadable = None
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'pin to one CPU through the bench gate'
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    paths = ['loadables/ptybroker.c', 'loadables/_ptybroker/server.c',
             'loadables/_ptybroker/client.c', 'loadables/_ptybroker/ptybroker.h',
             'loadables/_ptybroker/transport.h', 'tests/sol-ptybroker-streams.py',
             'tests/ptybroker.py', 'tests/fixtures/ptybroker-child.py', 'bench/sol-ptybroker.py']
    report = dict(kind='api', reference=None, ratio=None, passed=False,
                  method='One warmup then >=7 fresh private sessions per workload; exact bytes and offsets on every pass. Timings include Python/Bash orchestration; exclude creation, cleanup, history capture and byte comparison. Same input/options/reset on every pass.',
                  cpu_affinity=affinity, platform=platform.platform(), python=sys.version,
                  started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  environment={k: os.environ.get(k) for k in ('LANG','LC_ALL','MALLOC_ARENA_MAX')},
                  reset='New private root, broker, raw PTY child and subscriber files per pass; warmup uses a separate fresh session.',
                  memory='VmRSS and VmHWM from broker /proc/PID/status only; no child/client/kernel memory; 32 MiB correctness ceiling.',
                  build_manifest=args.bash.with_name(args.bash.name+'.manifest.txt').read_text(),
                  cpu_model=next(line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
                  bash_version=subprocess.check_output([str(args.bash),'--version'],text=True),
                  compiler_version=subprocess.check_output(['cc','--version'],text=True),
                  binary_sha256=sha(args.bash), source_sha256={s:sha(ROOT/s) for s in paths},
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  worktree_diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','HEAD'],cwd=ROOT)).hexdigest(),
                  cases=[])
    cases = [('binary-relay', lambda: work.relay(args, True)),
             ('burst-observers', lambda: work.stream(args,'burst-observers',4*1024**2,16384,250,3,True,True)),
             ('sustained', lambda: work.stream(args,'sustained',8*1024**2,8192,1000,2,False,True)),
             ('roundtrip-256', lambda: work.latency(args,True))]
    try:
        for name, run in cases:
            case = dict(name=name, passed=False, warmup=None, samples=[])
            report['cases'].append(case)
            case['warmup'] = run()
            for sample in range(args.runs):
                value = run()
                assert value['passed']
                assert value['fixture_sha256'] == case['warmup']['fixture_sha256']
                case['samples'].append(value)
                print(f'{name} sample {sample+1}: {value["seconds"]:.6f}s',flush=True)
            case['seconds'] = distribution([v['seconds'] for v in case['samples']])
            if 'bytes_per_second' in case['samples'][0]:
                case['bytes_per_second'] = distribution([v['bytes_per_second'] for v in case['samples']])
            if name == 'roundtrip-256':
                case['latency_seconds'] = distribution([t for v in case['samples'] for t in v['latency_seconds']])
            case['passed'] = True
        report['passed'] = True
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
