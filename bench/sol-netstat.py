#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validated netstat syscall-fixture timings; run only through the bench gate.

Build the product and test shim separately through the build gate. This driver
never compiles. Each batch runs in one persistent shell with an empty PATH and
validates the status and every byte of every invocation after timing.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('netstat_fixture',ROOT/'tests/sol-netstat-behavior.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fixture_sha(root):
    h=hashlib.sha256()
    for p in sorted(root.rglob('*')):
        if p.is_file():h.update(str(p.relative_to(root)).encode()+b'\0'+p.read_bytes())
        elif p.is_symlink():h.update(str(p.relative_to(root)).encode()+b'\0'+os.readlink(p).encode())
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--shim',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--runs',type=int,default=7)
    p.add_argument('--passes',type=int,default=10)
    p.add_argument('--records',type=int,default=10000)
    a=p.parse_args()
    assert a.runs>=7 and a.passes>=1 and 1<=a.records<=50000
    a.binary=a.binary.resolve();a.shim=a.shim.resolve()
    cpu=max(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpu})
    report=dict(kind='syscall-shim',reference=None,method='one validated warmup, then wall-clock subprocess batches; stdout captured; status checked after every call; exact bytes checked for every repeated pass',
        cpu_affinity=sorted(os.sched_getaffinity(0)),kernel=platform.release(),machine=platform.machine(),python=platform.python_version(),
        binary=str(a.binary),binary_sha256=sha(a.binary),shim_sha256=sha(a.shim),
        sources={str(p):sha(ROOT/p) for p in ('loadables/netstat.c','loadables/ss.c','tests/sol-netstat-shim.c','tests/sol-netstat-behavior.py','bench/sol-netstat.py')},
        source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        source_dirty=bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=ROOT,text=True).strip()),
        source_provenance='source_commit is HEAD at measurement; sources contains exact hashes of the measured working files',
        compiler=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
        cases=[])
    report['bash_version']=f.run(a.binary,'printf "%s\\n" "$BASH_VERSION"',f.environment()).stdout.strip()
    with tempfile.TemporaryDirectory(prefix='sol-netstat-bench-') as tmp:
        small=f.fixtures(Path(tmp)/'snapshot')
        large=f.fixtures(Path(tmp)/'large',large=a.records)
        # All connected IPv4 records: exact count, no zero-port formatting
        # differences between netlink and proc affect this separate workload.
        (large/'proc/net/tcp').write_text('fixture header\n'+''.join(f.proc_row(i,2,1,10000+i,60000,1000+i) for i in range(a.records)))
        snapshot=f.HEADER+'\n'+f.expected_inet()+f.expected_inet('udp')+f.row('u_str',0,0,'/fixture/listener','*','LISTEN')+f.row('u_str',0,0,'/fixture/connected','*','ESTAB')
        owners=f.HEADER+'        PID/Program\n'+f.row('tcp',3,5,'127.0.0.1:41001','0.0.0.0:*','LISTEN',' users:(("fixture",pid=4242,fd=7))')+f.row('tcp',3,5,'127.0.0.1:41002','127.0.0.1:41003','ESTAB')+f.row('tcp6',3,5,'::1:42001',':::*','LISTEN')+f.row('udp',3,5,'127.0.0.1:43001','0.0.0.0:*','UNCONN',' users:(("fixture",pid=4242,fd=8))')+f.row('udp',3,5,'127.0.0.1:43002','127.0.0.1:43003','ESTAB')+f.row('u_str',0,0,'/fixture/listener','*','LISTEN',' users:(("fixture",pid=4242,fd=9))')+f.row('u_str',0,0,'/fixture/connected','*','ESTAB')
        table=f.HEADER+'\n'+''.join(f.row('tcp',3,5,f'127.0.0.1:{10000+i}','127.0.0.1:60000','ESTAB') for i in range(a.records))
        workloads=[('fixed-socket-snapshot',small,'diag','-an',snapshot,7),('fixed-socket-snapshot-owners',small,'diag','-anp',owners,7),('large-connected-table',large,'proc','-tan',table,a.records)]
        for name,base,transport,options,expected,records in workloads:
            case=dict(name=name,status='pending',transport=transport,options=options,records_per_pass=records,passes=a.passes,runs=a.runs,fixture_sha256=fixture_sha(base),
                expected_sha256=hashlib.sha256(expected.encode()).hexdigest(),bytes_per_pass=len(expected.encode()),reset='none; immutable fixture and fresh shell per batch; repeated calls share one shell',samples_seconds=[])
            report['cases'].append(case)
            script=f'for ((i=0;i<{a.passes};i++)); do netstat {options} || exit $?; done'
            env=f.environment(a.shim,base,transport)
            case['environment']={k:env[k] for k in ('PATH','LC_ALL','SOL_NETSTAT_TRANSPORT')}
            try:
                for index in range(a.runs+1):
                    start=time.perf_counter_ns()
                    r=f.run(a.binary,script,env)
                    seconds=(time.perf_counter_ns()-start)/1e9
                    assert r.returncode==0,(r.returncode,r.stderr)
                    assert r.stderr=='',r.stderr
                    assert r.stdout==expected*a.passes,(name,index,'output mismatch',len(r.stdout),len(expected)*a.passes)
                    if index:case['samples_seconds'].append(seconds)
                    else:case['warmup_seconds']=seconds
                case.update(status='pass',median_seconds=statistics.median(case['samples_seconds']),min_seconds=min(case['samples_seconds']),max_seconds=max(case['samples_seconds']))
                print(name,case['status'],case['median_seconds'],flush=True)
            except Exception as e:
                case.update(status='fail',error=str(e))
                a.output.write_text(json.dumps(report,indent=2)+'\n')
                raise
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    assert all(c['status']=='pass' for c in report['cases'])

if __name__=='__main__':main()
