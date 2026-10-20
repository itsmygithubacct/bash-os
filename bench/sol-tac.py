#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact GNU bytes on every sample, size scaling and per-process peak RSS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import signal
import statistics
import subprocess
import tempfile
import time


def digest(path):
    h = hashlib.sha256()
    with open(path,'rb') as f:
        while chunk := f.read(1024*1024):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--runs', type=int, default=7)
    p.add_argument('--rusage-tool', type=Path, default=Path(__file__).resolve().parents[1]/'out/sol-tac-rusage')
    a = p.parse_args()
    assert a.runs >= 7
    assert len(os.sched_getaffinity(0)) == 1, 'Use the campaign bench gate'
    binary = str(a.binary.resolve())
    if not a.rusage_tool.is_file():
        p.error('Build bench/sol-tac-rusage.c separately through the build gate before measuring')
    monitor = str(a.rusage_tool.resolve())
    env = dict(PATH='', LC_ALL='C', TZ='UTC', TERM='dumb')
    report = dict(date_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()), binary=binary, binary_sha256=digest(binary), source_sha256=digest(a.source),
                  driver_sha256=digest(__file__), rusage_tool_sha256=digest(monitor),
                  rusage_source_sha256=digest(Path(__file__).with_name('sol-tac-rusage.c')),
                  cpu_affinity=sorted(os.sched_getaffinity(0)),
                  platform=platform.platform(), libc=platform.libc_ver(), python=platform.python_version(),
                  build_manifest=json.loads(Path(binary+'.manifest.json').read_text()),
                  cflags=os.environ.get('CFLAGS','-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2'),
                  source_git_head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                  cpu_model=next(l.split(':',1)[1].strip() for l in
                     Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),
                  load_start=os.getloadavg(), env=env, samples=a.runs, cases=[],
                  method='One warm-up then seven interleaved/reversed samples. Fresh shell and input descriptor each sample; warm filesystem cache. Each repeated pass emits to an owned output file, every byte checked after timing against concatenated GNU output. A small C wait4 launcher excludes the Python fixture generator heap from pre-exec RSS. Peak RSS is the largest process in the waited-for shell process tree, not an aggregate. Wall time includes the launcher, shell startup and output file writes. No hash work timed.',
                  compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                  shell_version=subprocess.check_output([binary,'--version'],text=True).splitlines()[0],
                  gnu_version=subprocess.check_output(['/usr/bin/tac','--version'],text=True).splitlines()[0],
                  reference_sha256=digest('/usr/bin/tac'))
    with tempfile.TemporaryDirectory(prefix='sol-tac-bench-') as d:
        root = Path(d)
        fixture, expected, output, rss = [root/n for n in ['input','expected','output','rss']]
        # Exact historical text generator from bench/loadables.py, without
        # creating unrelated catalog fixtures or invoking their host tools.
        rng = random.Random(20260908)
        words = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'the', 'and', 'of']
        original = ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n'
                           for _ in range(12000)).encode()[:423000]
        cases = [('reviewed-text-63', original, [], 'redirect',63),
                 ('historical-text-26', original, [], 'redirect',26)]
        for size in [1024*1024,4*1024*1024,16*1024*1024]:
            # Correct truncation independent of the period length.
            unit = b'alpha 0123456789\nbeta 9876543210\n'
            text = (unit*(size//len(unit)+1))[:size]
            huge = b'A'*(size//2)+b'\n'+b'B'*(size-size//2-1)
            unit = b'alpha,beta::gamma,tail\n'
            regex = (unit*(size//len(unit)+1))[:size]
            for shape in ['file','pipe']:
                cases += [(f'literal-{size}-{shape}',text,[],shape,1),
                          (f'huge-record-{size}-{shape}',huge,[],shape,1),
                          (f'regex-{size}-{shape}',regex,['-r','-s','[,:]+'],shape,1)]
            cases += [(f'regex-general-{size}',huge,['-r','-s','BEGIN.*END'],'file',1)]
        probes = {}
        for name,data,options,shape,passes in cases:
            fixture.write_bytes(data)
            with expected.open('wb') as f:
                subprocess.run(['/usr/bin/tac',*options,str(fixture)],env=env,stdout=f,check=True)
            expected_hash = digest(expected)
            expected_size = expected.stat().st_size
            # Stream the concatenated oracle into a digest without allocating
            # passes * input size in the measurement driver.
            h = hashlib.sha256()
            for _ in range(passes):
                with expected.open('rb') as f:
                    while chunk := f.read(1024*1024): h.update(chunk)
            batch_hash = h.hexdigest()
            row = dict(id=name, bytes=len(data), options=options, input_kind=shape, passes=passes,
                       fixture_sha256=hashlib.sha256(data).hexdigest(), expected_sha256=expected_hash,
                       expected_batch_sha256=batch_hash, results={})
            tools = {'builtin':['tac',*options], 'gnu':['/usr/bin/tac',*options]}
            if shape == 'file':
                script = 'input=$1; passes=$2; shift 2; for ((i=0;i<passes;i++)); do "$@" "$input" || exit; done'
            elif shape == 'redirect':
                script = 'input=$1; passes=$2; shift 2; for ((i=0;i<passes;i++)); do "$@" < "$input" || exit; done'
            else:
                # One owned /bin/cat process per call for both implementations.
                # pipefail ensures the producer's status is validated as well.
                script = 'set -o pipefail; input=$1; passes=$2; shift 2; for ((i=0;i<passes;i++)); do /bin/cat "$input" | "$@" || exit; done'

            def sample(label):
                rss.unlink(missing_ok=True)
                with output.open('wb') as out:
                    start = time.perf_counter_ns()
                    proc = subprocess.Popen([monitor,str(rss),binary,'--noprofile','--norc','-c',script,
                        '_',str(fixture),str(passes),*tools[label]],
                        env=env,stdout=out,stderr=subprocess.PIPE,process_group=0)
                    timed_out = False
                    try:
                        _, stderr = proc.communicate(timeout=120)
                    except subprocess.TimeoutExpired:
                        # The entire group belongs to this sample, including
                        # producer/consumer children. Never orphan a worker.
                        os.killpg(proc.pid, signal.SIGKILL)
                        _, stderr = proc.communicate()
                        timed_out = True
                    ms = (time.perf_counter_ns()-start)/1e6
                counters = json.loads(rss.read_text()) if rss.exists() else {'peak_rss_kib':0}
                valid = not timed_out and proc.returncode == 0 and output.stat().st_size == expected_size*passes and digest(output)==batch_hash
                return dict(valid=valid,exit_code=124 if timed_out else proc.returncode,ms=ms,**counters,
                            stdout_sha256=digest(output),stderr=stderr.decode(errors='replace'))

            accepted = []
            for label in tools:
                if '-r' in options and label == 'builtin':
                    key = tuple(options)
                    if key not in probes:
                        probe = b'a,b::c\nD\0E\n'
                        ref = subprocess.run(['/usr/bin/tac',*options],input=probe,
                            env=env,capture_output=True,check=True)
                        actual = subprocess.run([binary,'--noprofile','--norc','-c','"$@"',
                            '_','tac',*options],input=probe,env=env,capture_output=True,timeout=10)
                        probes[key] = dict(valid=(actual.returncode,actual.stdout)==(0,ref.stdout),
                            fixture_sha256=hashlib.sha256(probe).hexdigest(),
                            expected_sha256=hashlib.sha256(ref.stdout).hexdigest(),
                            actual_sha256=hashlib.sha256(actual.stdout).hexdigest(),
                            exit_code=actual.returncode)
                    if not probes[key]['valid']:
                        row['results'][label] = dict(status='invalid',samples=[],probe=probes[key],
                            validation_scope='Independent small regex probe failed; full-size timing excluded. No comparison is claimed.')
                        continue
                warmup = sample(label)
                row['results'][label] = dict(status='ok' if warmup['valid'] else 'invalid', warmup=warmup, samples=[])
                if warmup['valid']: accepted.append(label)
            for i in range(a.runs):
                order = accepted[:] if i%2 == 0 else accepted[::-1]
                for label in order:
                    s = sample(label)
                    row['results'][label]['samples'].append(s)
                    if not s['valid']: row['results'][label]['status']='invalid'
            for r in row['results'].values():
                if r['samples']:
                    r['median_ms']=statistics.median(s['ms'] for s in r['samples'])
                    r['min_ms']=min(s['ms'] for s in r['samples'])
                    r['max_ms']=max(s['ms'] for s in r['samples'])
                    r['max_rss_kib']=max(s['peak_rss_kib'] for s in r['samples'])
            report['cases'].append(row)
            report['load_end']=os.getloadavg()
            a.output.write_text(json.dumps(report,indent=2)+'\n')
            print(name, {k: (v['status'],round(v.get('median_ms',0),3),v.get('max_rss_kib')) for k,v in row['results'].items()},flush=True)
    assert all(row['results']['gnu']['status']=='ok' for row in report['cases'])
    # Invalid builtins are retained honestly, including all differing regex
    # cases in the historical implementation. They never receive a ratio.


if __name__ == '__main__': main()
