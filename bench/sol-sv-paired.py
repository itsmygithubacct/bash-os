#!/usr/bin/env python3
"""Interleave both sv builds to control drift between separate build rounds."""
import argparse
import datetime
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

spec=importlib.util.spec_from_file_location('checks',Path(__file__).resolve().parents[1]/'tests/sol-sv-check.py')
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--before',required=True)
    p.add_argument('--after',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--runs',type=int,default=7)
    args=p.parse_args()
    assert args.runs >= 7
    binaries={k:str(Path(v).resolve()) for k,v in [('before',args.before),('after',args.after)]}
    report=dict(binaries={k:dict(path=v,sha256=sha(v)) for k,v in binaries.items()},
                after_source_sha256=sha('loadables/sv.c'),harness_sha256=sha(__file__),
                platform=platform.platform(),affinity=sorted(os.sched_getaffinity(0)),
                recorded_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                cpu=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
                compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                python=platform.python_version(),runs=args.runs,warmups=1,
                bash_version=subprocess.check_output([binaries['after'],'--version'],text=True).splitlines()[0],
                tail_version=subprocess.check_output(['/usr/bin/tail','--version'],text=True).splitlines()[0],cases=[])
    output=Path(args.output)
    with tempfile.TemporaryDirectory(prefix='sol-sv-paired-') as root:
        f=m.Fixture(binaries['before'],root)
        try:
            data=b''.join(('2026-01-01T00:00:%02d fixture[%05d] service log record %05d status=ok\n' % (i%60,i,i)).encode() for i in range(40000))
            (f.root/'logs/fixture').write_bytes(data)
            expected=b''.join(data.splitlines(keepends=True)[-200:])*29
            samples={k:[] for k in ('before','after','tail')}
            for iteration in range(args.runs+1):
                for key in (list(samples) if iteration%2 else list(samples)[::-1]):
                    f.binary=binaries.get(key,binaries['after'])
                    command='sv log fixture -n 200' if key != 'tail' else '/usr/bin/tail -n 200 "$BASHSV_LOGDIR/fixture"'
                    start=time.perf_counter_ns()
                    result=f.run(script='PATH=; for ((i=0;i<29;i++)); do '+command+' || exit; done')
                    elapsed=(time.perf_counter_ns()-start)/1e6
                    assert result.stdout == expected and not result.stderr
                    if iteration: samples[key].append(elapsed)
            case=dict(name='sv-log',input_bytes=len(data),output_bytes=len(expected)//29,passes=29,
                      input_sha256=hashlib.sha256(data).hexdigest(),samples_ms=samples,
                      validation='every batch status and every output byte match independent input-derived oracle')
            report['cases'].append(case)
            output.write_text(json.dumps(report,indent=2)+'\n')
            print(case,flush=True)
            for name,data in [('short',b'a\0b\xff row\n'*8192),('long',b'x'*131071+b'\nlast\0')]:
                # Both parents launch the identical script, interpreter and Python child.
                f.binary=binaries['before']
                f.producer(name,data)
                samples={k:dict(wall_ms=[],user_ms=[],system_ms=[]) for k in binaries}
                for iteration in range(args.runs+1):
                    for key in (list(binaries) if iteration%2 else list(binaries)[::-1]):
                        f.binary=binaries[key]
                        (f.root/'logs'/name).unlink(missing_ok=True)
                        (f.root/(name+'.receipt')).unlink(missing_ok=True)
                        usage=resource.getrusage(resource.RUSAGE_CHILDREN)
                        start=time.perf_counter_ns()
                        result=f.run('once',name,timeout=60)
                        elapsed=(time.perf_counter_ns()-start)/1e6
                        done=resource.getrusage(resource.RUSAGE_CHILDREN)
                        logged=(f.root/'logs'/name).read_bytes()
                        assert m.unframe(logged) == data
                        assert (f.root/(name+'.receipt')).read_text() == str(len(data))+' '+hashlib.sha256(data).hexdigest()
                        assert result.stdout == (name+': exited rc=0\n').encode() and not result.stderr
                        if iteration:
                            samples[key]['wall_ms'].append(elapsed)
                            samples[key]['user_ms'].append((done.ru_utime-usage.ru_utime)*1000)
                            samples[key]['system_ms'].append((done.ru_stime-usage.ru_stime)*1000)
                case=dict(name='capture-'+name,input_bytes=len(data),output_bytes=len(logged),
                          input_sha256=hashlib.sha256(data).hexdigest(),samples=samples,
                          before_over_after=statistics.median(samples['before']['wall_ms'])/statistics.median(samples['after']['wall_ms']),
                          validation='every child receipt byte count/hash, log payload, prefix grammar, exit status and stdout exact')
                report['cases'].append(case)
                output.write_text(json.dumps(report,indent=2)+'\n')
                print(case,flush=True)
        finally:
            f.cleanup()


if __name__ == '__main__':
    main()
