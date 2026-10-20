#!/usr/bin/env python3
"""Fixed 512-process selection against procps through a read-only path adapter.
Compile bench/sol-pgrep-proc-shim.c separately; invoke this driver under the bench gate.
Every pass is checked against an index-derived oracle, including warm-up/timed batches.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture(root):
    (root/'stat').write_text('cpu  10000 0 1000 50000 0 0 0 0 0 0\nbtime 1700000000\n')
    (root/'uptime').write_text('987654.00 555555.00\n')
    (root/'meminfo').write_text('MemTotal: 1000000 kB\nMemFree: 500000 kB\n')
    for i in range(512):
        pid = 900000+i
        name = 'kthreadd' if i == 511 else f'worker{i:03d}'
        d = root/str(pid)
        d.mkdir()
        (d/'comm').write_text(name+'\n')
        (d/'cmdline').write_bytes(f'/usr/bin/{name}\0--task\0{i}\0'.encode())
        uid = 2001+i%2
        gid = 3001+(i%3 != 0)
        (d/'status').write_text(f'Name:\t{name}\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t77\nTracerPid:\t0\nUid:\t1001\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nThreads:\t1\nVmSize:\t1000 kB\nVmRSS:\t100 kB\n')
        fields=[77,88,99]+[0]*15+[1000+i,4096000,20]+[0]*29
        (d/'stat').write_text(f'{pid} ({name}) S '+' '.join(map(str,fields))+'\n')
    h=hashlib.sha256()
    for file in sorted(root.rglob('*')):
        if file.is_file():
            h.update(str(file.relative_to(root)).encode()+b'\0'+file.read_bytes())
    return h.hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',type=Path,required=True)
    ap.add_argument('--shim',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--regex',action='store_true')
    ap.add_argument('--implementation-source',type=Path,default=Path('loadables/pgrep.c'))
    ap.add_argument('--passes',type=int,default=34)
    ap.add_argument('--runs',type=int,default=7)
    args=ap.parse_args()
    assert args.runs>=7 and args.passes>=3
    binary=str(args.binary.resolve(strict=True))
    shim=str(args.shim.resolve(strict=True))
    affinity=sorted(os.sched_getaffinity(0))
    assert len(affinity)==1, 'Pin the benchmark using the campaign bench gate'
    report=dict(schema=1,source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                binary_sha256=digest(binary),reference_sha256=digest('/usr/bin/pgrep'),
                shim_sha256=digest(shim),source_sha256={str(p):digest(p) for p in [args.implementation_source,Path(__file__),Path('bench/sol-pgrep-proc-shim.c')]},
                cpus=affinity,kernel=platform.release(),machine=platform.machine(),
                load_average_start=os.getloadavg(),binary=binary,reference='/usr/bin/pgrep',
                adapter='LD_PRELOAD read-only /proc path redirection for both command runners',
                cpu_model=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
                versions=dict(reference=subprocess.check_output(['/usr/bin/pgrep','--version'],text=True).strip(),
                              shell=subprocess.check_output([binary,'--version'],text=True).splitlines()[0],
                              compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0]),
                passes=args.passes,runs=args.runs,warmups=1,
                method='Alternating builtin/procps batches in the same Bash executable; elapsed wall time includes shell startup and output capture. Each pass output and status independently verified. No fixture resets or mutations.',
                environment=dict(PATH='',LC_ALL='C',TZ='UTC'),cases=[])
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='sol-pgrep-bench-') as tmp:
        root=Path(tmp)
        report['fixture_sha256']=fixture(root)
        cases=[('pgrep-kthreadd',['-x','kthreadd'],'900511\n',0)]
        if args.regex:
            # Independent arithmetic oracle: worker index 0..199, even and divisible by 3.
            expected=sum(1 for i in range(200) if i%2==0 and i%3==0)
            cases += [('pgrep-select-512',['-c','-u2001','-G3001','-P77','-s99','^worker(0[0-9][0-9]|1[0-9][0-9])$'],f'{expected}\n',0),
                      ('pgrep-cmdline-512',['-f','-c','-P77','--','--task [0-9]+$'],'512\n',0),
                      ('pgrep-oldest-512',['-o','worker[0-9]+'],'900000\n',0),
                      ('pgrep-invalid-regex',['['],'',2)]
        env=dict(os.environ,PATH='',LC_ALL='C',TZ='UTC',BASHOS_PROC_ROOT=str(root))
        # Apply the same adapter to the shell on both sides. The builtin uses
        # BASHOS_PROC_ROOT directly; the unmodified procps binary inherits it.
        env['LD_PRELOAD']=shim
        reference_check=subprocess.run(['/usr/bin/pgrep','-c','.'],env=env,capture_output=True,text=True,timeout=15)
        report['reference_fixture_validation']=dict(status=reference_check.returncode,stdout=reference_check.stdout,stderr=reference_check.stderr)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        assert (reference_check.returncode,reference_check.stdout)==(0,'512\n'), report['reference_fixture_validation']
        for label, options, expected, status in cases:
            case=dict(id=label,options=options,work_unit='512 synthetic process directories scanned per selection; 34 selections per batch' if args.passes==34 else f'512 directories; {args.passes} selections per batch',
                      expected_output=expected,expected_status=status,kind='compared',samples_ms={'builtin':[],'procps':[]},validation='pending')
            if status == 2:
                case['work_unit']=f'{args.passes} invalid-regex validations per batch; zero process records selected'
            report['cases'].append(case)
            def batch(which):
                command=shlex.join((['pgrep'] if which=='builtin' else ['/usr/bin/pgrep'])+options)
                script=f'for ((i=0;i<{args.passes};i++)); do {command}; printf "|%d\\n" "$?"; done'
                start=time.perf_counter_ns()
                p=subprocess.run([binary,'--noprofile','--norc','-c',script],env=env,capture_output=True,text=True,timeout=90)
                elapsed=(time.perf_counter_ns()-start)/1e6
                assert p.returncode==0 and p.stdout==(expected+f'|{status}\n')*args.passes, (label,which,p.returncode,p.stdout[:300],p.stderr[:1000])
                return elapsed
            try:
                for which in ('builtin','procps'): batch(which)
                for index in range(args.runs):
                    for which in (('builtin','procps') if index%2==0 else ('procps','builtin')):
                        case['samples_ms'][which].append(batch(which))
                case['validation']='pass: all warm-up and measured outputs/statuses match the independent fixture oracle'
                case['median_ms']={k:statistics.median(v) for k,v in case['samples_ms'].items()}
                case['builtin_over_procps']=case['median_ms']['builtin']/case['median_ms']['procps']
                case['distribution']={k:dict(min=min(v),max=max(v),median=statistics.median(v)) for k,v in case['samples_ms'].items()}
            except Exception as error:
                case['validation']='FAIL: '+repr(error)
                raise
            finally:
                report['load_average_end']=os.getloadavg()
                args.output.write_text(json.dumps(report,indent=2)+'\n')
            print(label,case['median_ms'],case['validation'],flush=True)


if __name__=='__main__': main()
