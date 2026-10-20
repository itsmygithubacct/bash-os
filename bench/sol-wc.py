#!/usr/bin/env python3
"""Gated wc character benchmarks; no builds. Every pass has an independent oracle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', action='append', required=True, help='LABEL=PATH')
    p.add_argument('--source', action='append', default=[], help='LABEL=wc.c (defaults to current source)')
    p.add_argument('--rusage', type=Path, default=Path(__file__).resolve().parents[1]/'out/sol-wc-rusage', help='Separately built sol-wc-rusage launcher')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--runs', type=int, default=7)
    args = p.parse_args()
    assert args.runs >= 7
    binaries = dict(x.split('=', 1) for x in args.binary)
    binaries = {k: str(Path(v).resolve(strict=True)) for k, v in binaries.items()}
    shell = next(iter(binaries.values()))
    rusage = args.rusage.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    sources = dict(x.split('=', 1) for x in args.source)
    report = dict(method='One warmup then interleaved/reversed batches; every command status and output validated; stdin reopened each pass; warm cache. Separate C fork/wait4 memory probes avoid inherited Python high-water RSS; RSS is maximum for shell/children, not sum. Timed wait4 RSS is retained only as a diagnostic.',
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                  source_sha256=sha(root/'loadables/wc.c'), harness_sha256=sha(__file__),
                  cpus=sorted(os.sched_getaffinity(0)), kernel=platform.release(),
                  architecture=platform.machine(), load_start=os.getloadavg(),
                  cpu_model=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
                  versions={}, binaries={k: dict(path=v, sha256=sha(v)) for k, v in binaries.items()},
                  reference=dict(path='/usr/bin/wc', sha256=sha('/usr/bin/wc')), cases=[])
    report['sources'] = {k: dict(path=sources.get(k, str(root/'loadables/wc.c')),
                               sha256=sha(sources.get(k, root/'loadables/wc.c'))) for k in binaries}
    report['worktree_status'] = subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).splitlines()
    report['rss_launcher'] = dict(path=str(rusage), sha256=sha(rusage), source_sha256=sha(root/'bench/sol-wc-rusage.c'))
    for k, v in {**binaries, 'gnu': '/usr/bin/wc', 'libc': '/usr/bin/ldd'}.items():
        report['versions'][k] = subprocess.check_output([v, '--version'], text=True).splitlines()[0]
    rng = random.Random(20260908)
    text = ''.join(' '.join(rng.choice(['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']) for _ in range(10))+'\n' for _ in range(12000)).encode()[:423000]
    mixed = 'alpha café 界 e\u0301\tomega\n'.encode()
    with tempfile.TemporaryDirectory(prefix='sol-wc-') as d:
        for kind, seed in [('text', text), ('mixed', mixed)]:
            for size in [4096, 423000, 4194304]:
                data = (seed * (size//len(seed)+1))[:size]
                if kind == 'mixed':
                    # Keep valid UTF-8, with the exact byte count recorded below.
                    data = data.decode('utf-8', errors='ignore').encode()
                fixture = Path(d)/'input'
                fixture.write_bytes(data)
                for loc in ['C', 'C.UTF-8', 'en_US.utf8']:
                    expected = len(data) if loc == 'C' else len(data.decode())
                    passes = 42 if size == 4096 else 12 if size == 423000 else 3
                    row = dict(id=f'wc-characters/{kind}/{size}/{loc}', locale=loc, options=['-m'],
                               fixture_sha256=sha(fixture), bytes_per_pass=len(data),
                               characters_per_pass=expected, passes=passes,
                               bytes_per_batch=len(data)*passes, characters_per_batch=expected*passes,
                               results={})
                    report['cases'].append(row)
                    env = {'PATH': '', 'LC_ALL': loc, 'TZ': 'UTC', 'TERM': 'dumb'}
                    def run(label, memory=False):
                        binary = binaries.get(label, shell)
                        command = 'wc' if label != 'gnu' else '/usr/bin/wc'
                        script = 'PATH=; for ((i=0;i<$2;i++)); do '+command+' -m < "$1" || exit; done'
                        argv = [binary, '--noprofile', '--norc', '-c', script, '_', str(fixture), str(passes)]
                        rss_file = Path(d)/'rss'
                        if memory:
                            argv = [str(rusage), str(rss_file), *argv]
                        start = time.perf_counter_ns()
                        proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        _, status, usage = os.wait4(proc.pid, 0)
                        elapsed = (time.perf_counter_ns()-start)/1e6
                        proc.returncode = os.waitstatus_to_exitcode(status)
                        out, err = proc.communicate()
                        assert proc.returncode == 0 and not err, (row['id'], label, proc.returncode, err)
                        assert out.splitlines() == [str(expected).encode()]*passes, (row['id'], label, out)
                        result = dict(wait4_peak_rss_kib=usage.ru_maxrss, user_s=usage.ru_utime, system_s=usage.ru_stime,
                                      validated_passes=passes, exit_code=proc.returncode, output_sha256=hashlib.sha256(out).hexdigest())
                        if memory:
                            result['peak_rss_kib'] = int(rss_file.read_text())
                        else:
                            result['ms'] = elapsed
                        return result
                    labels = [*binaries, 'gnu']
                    for label in labels:
                        row['results'][label] = dict(warmup=run(label), memory_probe=run(label, memory=True), samples=[])
                    for sample in range(args.runs):
                        for label in (labels if sample % 2 == 0 else labels[::-1]):
                            row['results'][label]['samples'].append(run(label))
                    for result in row['results'].values():
                        result['status'] = 'ok'
                        result['median_ms'] = statistics.median(s['ms'] for s in result['samples'])
                        result['range_ms'] = [min(s['ms'] for s in result['samples']), max(s['ms'] for s in result['samples'])]
                        result['peak_rss_kib'] = result['memory_probe']['peak_rss_kib']
                    for label in binaries:
                        row['results'][label]['over_gnu'] = row['results'][label]['median_ms']/row['results']['gnu']['median_ms']
                    print(row['id'], {k: round(v['median_ms'], 3) for k, v in row['results'].items()}, flush=True)
                    args.output.write_text(json.dumps(report, indent=2)+'\n')
    report['load_end'] = os.getloadavg()
    args.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
