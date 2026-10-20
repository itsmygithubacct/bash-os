#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ss live snapshot and fixed-table wall times. Use the campaign bench gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ss_fixture',ROOT/'tests/sol-ss-behavior.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
f=t.f

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(base):
    h=hashlib.sha256()
    for p in sorted(base.rglob('*')):
        if p.is_symlink():data=os.readlink(p).encode()
        elif p.is_file():data=p.read_bytes()
        else:continue
        h.update(str(p.relative_to(base)).encode()+b'\0'+data)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--shim',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--runs',type=int,default=7)
    p.add_argument('--passes',type=int,default=10);p.add_argument('--records',type=int,default=10000)
    a=p.parse_args();assert a.runs>=7 and a.passes>=1 and 1<=a.records<=50000
    a.binary=a.binary.resolve();a.shim=a.shim.resolve()
    cpu=max(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
    report=dict(method='prevalidate both routes, one validated warmup, seven or more wall-clock batch samples; every status and output checked; includes shell startup and captured output',reference=None,
        cpu_affinity=sorted(os.sched_getaffinity(0)),kernel=platform.release(),machine=platform.machine(),python=platform.python_version(),
        binary_sha256=sha(a.binary),shim_sha256=sha(a.shim),source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        sources={p:sha(ROOT/p) for p in ('loadables/ss.c','loadables/netstat.c','tests/sol-ss-shim.c','tests/sol-ss-behavior.py','tests/sol-netstat-behavior.py','bench/sol-ss.py')},
        compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
        bash_version=f.run(a.binary,'printf "%s\\n" "$BASH_VERSION"',f.environment()).stdout.strip(),
        external_ss_version=subprocess.check_output(['/usr/bin/ss','--version'],text=True).strip() if Path('/usr/bin/ss').exists() else None,cases=[])
    def save():a.output.write_text(json.dumps(report,indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='sol-ss-bench-') as tmp, socket.socket(2,2) as udp, socket.socket(10,2) as udp6:
        udp.bind(('127.0.0.1',0));udp6.bind(('::1',0))
        large=f.fixtures(Path(tmp)/'large')
        (large/'proc/net/tcp').write_text('header\n'+''.join(f.proc_row(i,2,1,10000+i,60000,1000+i) for i in range(a.records)))
        (large/'proc/net/tcp6').write_text('header\n')
        messages=[f.inet(2,1,10000+i,60000,1000+i) for i in range(a.records)]
        chunks=[b''.join(messages[i:i+180]) for i in range(0,len(messages),180)]
        chunks[-1]+=f.msg(kind=3)
        for i,chunk in enumerate(chunks):(large/('diag/2-6.bin' if i==0 else f'diag/2-6.{i}.bin')).write_bytes(chunk)
        (large/'diag/10-6.bin').write_bytes(f.msg(kind=3))
        exact=t.HEADER+'\n'+''.join(t.row('tcp',3,5,f'127.0.0.1:{10000+i}','127.0.0.1:60000','ESTAB') for i in range(a.records))
        live_expected=[t.row('udp' if s.family==2 else 'udp6',0,0,f'{s.getsockname()[0]}:{s.getsockname()[1]}','0.0.0.0:*' if s.family==2 else ':::*','UNCONN').strip() for s in (udp,udp6)]
        live_fixture=json.dumps(live_expected).encode()
        workloads=[]
        for name,base,options,expected in [('small-live-udp',None,'-una',None),('large-fixed-tcp',large,'-tna',exact)]:
            for route in ('diag','proc'):
                env=f.environment(a.shim,base,route)
                if route=='diag':env['SOL_SS_NO_PROC']='1'
                else:env['SOL_SS_FORCE_PROC']='1'
                case=dict(name=name+'-'+route,kind='api' if base is None else 'syscall-shim',transport=route,options=options,status='pending',passes=a.passes,runs=a.runs,
                    fixture_sha256=digest(base) if base else hashlib.sha256(live_fixture).hexdigest(),
                    fixture_input_bytes=sum(p.stat().st_size for p in (base/('diag' if route=='diag' else 'proc/net')).iterdir() if p.name.startswith('2-6') or p.name.startswith('10-6') or p.name in ('tcp','tcp6')) if base else None,
                    expected_sha256=hashlib.sha256(expected.encode()).hexdigest() if expected else None,
                    owned_records=2 if base is None else a.records,
                    reset='immutable sockets/tables retained for all passes; fresh shell per batch, repeated calls within each shell',
                    validation='every byte of every row' if expected else 'exact owned endpoint/state/queue records; host rows counted but not an oracle',
                    limitations=[] if expected else ['Host UDP rows may vary; total socket counts and output bytes recorded for each pass. No external ratio.'],
                    environment={k:v for k,v in env.items() if k in ('PATH','LC_ALL','SOL_SS_NO_PROC','SOL_SS_FORCE_PROC','SOL_NETSTAT_TRANSPORT')},samples_seconds=[],work_per_batch=[])
                report['cases'].append(case)
                script=f'for ((i=0;i<{a.passes};i++)); do ss {options} || exit $?; printf "<END>\\n"; done'
                def validate(r,expected=expected):
                    assert r.returncode==0,(r.returncode,r.stderr)
                    assert not r.stderr,r.stderr
                    outputs=r.stdout.split('<END>\n');assert outputs.pop()=='' and len(outputs)==a.passes
                    work=[]
                    for out in outputs:
                        assert out.startswith(t.HEADER+'\n')
                        if expected is not None:assert out==expected,'fixed output mismatch'
                        else:
                            for line in live_expected:assert out.splitlines().count(line)==1,(line,out)
                        work.append(dict(sockets=len(out.splitlines())-1,bytes=len(out.encode())))
                    return work
                workloads.append((case,script,env,validate))
        # Finish validation of every workload and route before any timing begins.
        for case,script,env,validate in workloads:
            try:case['prevalidation']=validate(f.run(a.binary,script,env));case['status']='validated'
            except Exception as e:case.update(status='fail',error=str(e));save();raise
        for case,script,env,validate in workloads:
            try:
                for index in range(a.runs+1):
                    start=time.perf_counter_ns();r=f.run(a.binary,script,env);seconds=(time.perf_counter_ns()-start)/1e9
                    work=validate(r)
                    if index:case['samples_seconds'].append(seconds);case['work_per_batch'].append(work)
                    else:case['warmup_seconds']=seconds;case['warmup_work']=work
                case.update(status='pass',median_seconds=statistics.median(case['samples_seconds']),min_seconds=min(case['samples_seconds']),max_seconds=max(case['samples_seconds']))
                print(case['name'],case['median_seconds'],flush=True);save()
            except Exception as e:case.update(status='fail',error=str(e));save();raise
    save();assert all(c['status']=='pass' for c in report['cases'])

if __name__=='__main__':main()
