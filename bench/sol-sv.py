#!/usr/bin/env python3
"""Validated sv tail and supervised capture measurements (run through bench gate)."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location('sv_checks', Path(__file__).resolve().parents[1]/'tests/sol-sv-check.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def framing_profile(args):
    tools = {'before-frame': args.framing_before, 'after-frame': args.framing_after,
             'after-copy': args.framing_after}
    payload = b'a\0b\xff row\n'*131072
    result = dict(kind='api', after_source_sha256=sha('loadables/sv.c'), harness_sha256=sha(__file__), description='production framing in isolation; 16 KiB input chunks; copy is read/write control',
                  affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
                  input_bytes=len(payload), input_sha256=hashlib.sha256(payload).hexdigest(),
                  binaries={k: dict(path=str(Path(v).resolve()),sha256=sha(v)) for k,v in tools.items()},
                  runs=args.runs,warmups=1,cases={})
    with tempfile.TemporaryDirectory(prefix='sol-sv-framing-') as tmp:
        path=Path(tmp)
        (path/'input').write_bytes(payload)
        for key in tools:
            result['cases'][key] = dict(samples_ms=[],cpu_user_ms=[],cpu_sys_ms=[])
        for iteration in range(args.runs+1):
            for key in (list(tools) if iteration%2 else list(tools)[::-1]):
                stats=resource.getrusage(resource.RUSAGE_CHILDREN)
                start=time.perf_counter_ns()
                proc=subprocess.run([str(Path(tools[key]).resolve()),str(path/'input'),str(path/'output'),
                                     'copy' if key.endswith('copy') else 'frame'],capture_output=True,timeout=30)
                elapsed=(time.perf_counter_ns()-start)/1e6
                done=resource.getrusage(resource.RUSAGE_CHILDREN)
                assert proc.returncode == 0 and not proc.stdout and not proc.stderr
                output=(path/'output').read_bytes()
                assert (output if key.endswith('copy') else m.unframe(output)) == payload
                case=result['cases'][key]
                case['output_bytes']=len(output)
                if iteration:
                    case['samples_ms'].append(elapsed)
                    case['cpu_user_ms'].append((done.ru_utime-stats.ru_utime)*1000)
                    case['cpu_sys_ms'].append((done.ru_stime-stats.ru_stime)*1000)
    result['validation']='independent byte oracle, status and empty stderr checked for every warmup/sample'
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--runs', type=int, default=7)
    p.add_argument('--profile', action='store_true')
    p.add_argument('--framing-before')
    p.add_argument('--framing-after')
    args = p.parse_args()
    assert args.runs >= 7
    if args.framing_before or args.framing_after:
        assert args.framing_before and args.framing_after
        return framing_profile(args)
    binary = str(Path(args.binary).resolve())
    out = Path(args.output)
    report = dict(binary=binary, binary_sha256=sha(binary), source_sha256=sha('loadables/sv.c'), harness_sha256=sha(__file__),
                  commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                  source_dirty=subprocess.run(['git','diff','--quiet','--','loadables/sv.c']).returncode == 1,
                  compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                  affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
                  cpu=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
                  bash_version=subprocess.check_output([binary,'--version'],text=True).splitlines()[0],
                  tail_version=subprocess.check_output(['/usr/bin/tail','--version'],text=True).splitlines()[0],
                  runs=args.runs, warmups=1, cases=[])
    out.write_text(json.dumps(report,indent=2))
    with tempfile.TemporaryDirectory(prefix='sol-sv-bench-') as root:
        f = m.Fixture(binary, root)
        try:
            payload = b''.join(('2026-01-01T00:00:%02d fixture[%05d] service log record %05d status=ok\n' % (i%60,i,i)).encode() for i in range(40000))
            (f.root/'logs/fixture').write_bytes(payload)
            expected = b''.join(payload.splitlines(keepends=True)[-200:])
            passes = 29
            scripts = {'sv': 'PATH=; for ((i=0;i<29;i++)); do sv log fixture -n 200 || exit; done',
                       'tail': 'PATH=; for ((i=0;i<29;i++)); do /usr/bin/tail -n 200 "$BASHSV_LOGDIR/fixture" || exit; done'}
            values = {k:[] for k in scripts}
            for iteration in range(args.runs+1):
                for key in (list(scripts) if iteration%2 else list(scripts)[::-1]):
                    start = time.perf_counter_ns()
                    result = f.run(script=scripts[key])
                    elapsed = (time.perf_counter_ns()-start)/1e6
                    assert result.stdout == expected*passes and not result.stderr
                    if iteration:
                        values[key].append(elapsed)
            report['cases'].append(dict(name='sv-log', kind='compared', input_bytes=len(payload), input_sha256=hashlib.sha256(payload).hexdigest(),
                                        output_bytes=len(expected), passes=passes, samples_ms=values,
                                        ratio=statistics.median(values['sv'])/statistics.median(values['tail']), validation='all statuses and output bytes exact on warmup and every pass'))
            print('sv-log', report['cases'][-1],flush=True)
            for name, payload in [('short',b'a\0b\xff row\n'*8192), ('long',b'x'*131071+b'\nlast\0')]:
                f.producer(name,payload)
                samples=[]
                cpu_user=[]
                cpu_sys=[]
                for iteration in range(args.runs+1):
                    (f.root/'logs'/name).unlink(missing_ok=True)
                    (f.root/(name+'.receipt')).unlink(missing_ok=True)
                    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                    start = time.perf_counter_ns()
                    result = f.run('once',name,timeout=60)
                    elapsed = (time.perf_counter_ns()-start)/1e6
                    done = resource.getrusage(resource.RUSAGE_CHILDREN)
                    data=(f.root/'logs'/name).read_bytes()
                    assert m.unframe(data) == payload
                    assert (f.root/(name+'.receipt')).read_text() == str(len(payload))+' '+hashlib.sha256(payload).hexdigest()
                    assert result.stdout == (name+': exited rc=0\n').encode() and not result.stderr
                    if iteration:
                        samples.append(elapsed)
                        cpu_user.append((done.ru_utime-usage.ru_utime)*1000)
                        cpu_sys.append((done.ru_stime-usage.ru_stime)*1000)
                case=dict(name='capture-'+name,kind='self', input_bytes=len(payload), output_bytes=len(data),
                          input_sha256=hashlib.sha256(payload).hexdigest(), samples_ms=samples, cpu_user_ms=cpu_user, cpu_sys_ms=cpu_sys,
                          validation='child receipt bytes/hash and timestamp-stripped log exact on warmup and every sample')
                report['cases'].append(case)
                print(case,flush=True)
                if args.profile:
                    profile=out.with_name(out.stem+'-'+name+'-strace.txt')
                    (f.root/'logs'/name).unlink()
                    cmd=['/usr/bin/strace','-f','-c','-o',str(profile),binary,'-c','PATH=; sv once "$1"','_',name]
                    trace=subprocess.run(cmd,env=f.env,capture_output=True,timeout=60)
                    assert trace.returncode == 0 and m.unframe((f.root/'logs'/name).read_bytes()) == payload
                    case['syscall_profile']=str(profile)
                out.write_text(json.dumps(report,indent=2)+'\n')
        finally:
            f.cleanup()
    out.write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__':
    main()
