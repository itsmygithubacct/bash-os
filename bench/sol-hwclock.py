#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed validated hwclock shim transactions; no hardware or external speed ratio.
Run only through the campaign bench gate. Build fixtures separately first.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hwclock_check', ROOT/'tests/sol-hwclock-check.py')
check=importlib.util.module_from_spec(spec); spec.loader.exec_module(check)

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',required=True); ap.add_argument('--module',required=True)
    ap.add_argument('--output',required=True); ap.add_argument('--runs',type=int,default=7)
    ap.add_argument('--passes',type=int,default=2000); ap.add_argument('--adjust-passes',type=int,default=200)
    args=ap.parse_args()
    assert args.runs>=7 and args.passes>=1 and args.adjust_passes>=1
    cpu=max(os.sched_getaffinity(0)); os.sched_setaffinity(0,{cpu})
    binary=Path(args.binary).resolve(); module=Path(args.module).resolve()
    vals=(2024,2,29,12,34,56); t=check.epoch(vals); local=(2024,7,1,12,34,56)
    local_t=check.epoch(local,check.ZoneInfo('America/New_York'))
    cases=[dict(name='read-show',options=['-r','-u','--noadjfile'],rtc=vals,now=t,
                counts=[1,1,0,1,0,0],output=check.iso(vals)+'\n',verify=[]),
           dict(name='hctosys-utc',options=['-s','-u','--noadjfile'],rtc=vals,now=t,
                counts=[1,1,0,1,0,1],output='',verify=['verify-sys',str(t)]),
           dict(name='hctosys-local',options=['-s','-l','--noadjfile'],rtc=local,now=local_t,
                counts=[1,1,0,1,0,1],output='',verify=['verify-sys',str(local_t)]),
           dict(name='hctosys-adjtime',options=['-s','-u'],rtc=vals,now=t,
                adj=f'2.5 {t-86400} 0.25\n123\nUTC\n',counts=[1,1,0,1,0,1],output='',verify=['verify-sys',str(t-2)]),
           dict(name='systohc-utc',options=['-w','-u','--noadjfile'],rtc=vals,now=t,
                counts=[1,0,1,1,1,0],output='',verify=['verify-rtc',*map(str,vals)]),
           dict(name='systohc-local',options=['-w','-l','--noadjfile'],rtc=local,now=local_t,
                counts=[1,0,1,1,1,0],output='',verify=['verify-rtc',*map(str,local)]),
           dict(name='systohc-adjtime',options=['-w','-u'],rtc=vals,now=t,
                adj='2.5 1000 0.75\n500\nLOCAL\n',counts=[1,0,1,1,1,0],output='',
                verify=['verify-rtc',*map(str,vals)],reset=True,
                expected_adj=f'2.500000 {t} 0.000000\n{t}\nUTC\n'),
           dict(name='adjust-noop',options=['-a','-u'],rtc=vals,now=t,
                adj=f'0.1 {t-86400} 0.2\n123\nUTC\n',counts=[1,1,0,1,0,0],output='',verify=[]),
           dict(name='adjust-write',options=['-a','-u'],rtc=vals,now=t,
                adj=f'2.5 {t-86400} 0.25\n123\nUTC\n',counts=[2,1,1,2,0,0],output='',
                verify=['verify-rtc',*map(str,check.fields(t-2))],reset=True,
                expected_adj=f'2.500000 {t-2} 0.750000\n123\nUTC\n')]
    env=dict(os.environ,TZ='America/New_York',LC_ALL='C')
    # Add independently computed weekday/yearday expectations to setter checks.
    for case in cases:
        if case['verify'] and case['verify'][0]=='verify-rtc':
            expected=dt.datetime(*map(int,case['verify'][1:]))
            case['verify'] += [str((expected.weekday()+1)%7),str(expected.timetuple().tm_yday-1)]
    results=[]
    with tempfile.TemporaryDirectory(prefix='sol-hwclock-bench-', dir=Path(args.output).resolve().parent) as tmp:
        adj=Path(tmp)/'adjtime'
        for case in cases:
            n=args.adjust_passes if case.get('reset') else args.passes
            fixture_description=dict(rtc=case['rtc'],now=case['now'],adjtime=case.get('adj'),
                                     TZ=env['TZ'],options=case['options'])
            fixture_id=hashlib.sha256(json.dumps(fixture_description,sort_keys=True).encode()).hexdigest()
            options=case['options']+(['--adjfile',str(adj)] if 'adj' in case else [])
            setup=(f'enable -f {shlex.quote(str(module))} hwclock || exit 90\n'
                   f'enable -f {shlex.quote(str(module))} hwclock_fixture || exit 91\n'
                   'PATH=\nhwclock_fixture reset\nhwclock_fixture quiet\n'+
                   shlex.join(['hwclock_fixture','rtc',*map(str,case['rtc'])])+'\n'+
                   shlex.join(['hwclock_fixture','now',str(case['now'])])+'\n')
            reset=''
            if case.get('reset'):
                reset='printf %s '+shlex.quote(case['adj'])+' >'+shlex.quote(str(adj))+' || exit 92\n'
            command=shlex.join(['hwclock','--rtc','/fixture/rtc',*options])+' || exit 93\n'
            verify=(shlex.join(['hwclock_fixture',*case['verify']])+' || exit 94\n') if case['verify'] else ''
            file_verify=''
            if 'adj' in case:
                expected_lines=case.get('expected_adj',case['adj']).splitlines()
                assert len(expected_lines)==3
                file_verify=('{ IFS= read -r adj_first && IFS= read -r adj_second && '
                             'IFS= read -r adj_mode && ! IFS= read -r adj_extra; } <'+
                             shlex.quote(str(adj))+' || exit 96\n'+
                             '[[ $adj_first == '+shlex.quote(expected_lines[0])+
                             ' && $adj_second == '+shlex.quote(expected_lines[1])+
                             ' && $adj_mode == '+shlex.quote(expected_lines[2])+' ]] || exit 97\n')
            counts='hwclock_fixture verify-counts "$i" '+shlex.join(list(map(str,case['counts'])))+' || exit 95\n'
            script=setup+f'for ((i=1;i<={n};i++)); do\n'+reset+command+verify+file_verify+counts+'done\nhwclock_fixture stats\n'
            expected_stats=dict(zip(['open','read','write','close','get','set'],[v*n for v in case['counts']]))
            samples=[]; validations=[]
            for run in range(args.runs+1):
                if 'adj' in case: adj.write_text(case['adj'])
                fixture_hash=digest(adj) if 'adj' in case else None
                start=time.perf_counter_ns()
                p=subprocess.run([str(binary),'--noprofile','--norc'],input=script,text=True,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
                elapsed=time.perf_counter_ns()-start
                assert p.returncode==0 and p.stderr=='',(case['name'],run,p.returncode,p.stdout,p.stderr)
                lines=p.stdout.splitlines(keepends=True)
                statline=lines[-1]
                assert ''.join(lines[:-1])==case['output']*n,(case['name'],run,'output')
                stats=dict(v.split('=',1) for v in statline.split())
                assert all(int(stats[k])==v for k,v in expected_stats.items()),(case['name'],stats)
                assert stats['live']==stats['bad']=='0' and stats['cloexec']=='1',stats
                if case.get('reset'):
                    assert adj.read_text()==case['expected_adj']
                    assert list(Path(tmp).iterdir())==[adj]
                elif 'adj' in case: assert digest(adj)==fixture_hash
                validations.append(dict(run=run,warmup=run==0,status='pass',exit_code=p.returncode,
                                        stdout_sha256=hashlib.sha256(p.stdout.encode()).hexdigest(),
                                        fixture_sha256=fixture_id,adjfile_sha256=fixture_hash,stats=stats))
                if run: samples.append(elapsed/1e6)
            results.append(dict(name=case['name'],status='pass',kind='syscall-shim',passes=n,
                                work_unit='One production hwclock call plus per-call independent value/count validation',
                                options=case['options'],rtc=case['rtc'],now=case['now'],counts_per_call=case['counts'],
                                fixture_sha256=fixture_id,fixture=fixture_description,
                                adjfile_sha256=hashlib.sha256(case.get('adj','').encode()).hexdigest() if 'adj' in case else None,
                                reset='rewrite identical private adjtime before every call' if reset else 'same read-only fixture and fixed shim inputs each call',
                                script_sha256=hashlib.sha256(script.encode()).hexdigest(),script=script,
                                warmups=1,samples_ms=samples,median_ms=statistics.median(samples),
                                min_ms=min(samples),max_ms=max(samples),mean_ms=statistics.mean(samples),
                                stdev_ms=statistics.stdev(samples),validations=validations))
            print(case['name'],f'{statistics.median(samples):.3f} ms / {n} passes',flush=True)
    sources=['loadables/hwclock.c','tests/sol-hwclock-shim.c','tests/sol-hwclock-check.py','bench/sol-hwclock.py']
    report=dict(status='pass',kind='syscall-shim',external_ratio=None,cpu=cpu,affinity=sorted(os.sched_getaffinity(0)),
                created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),platform=platform.platform(),
                cpu_model=next((l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),None),
                libc=platform.libc_ver(),python=platform.python_version(),timer='time.perf_counter_ns',
                timezone_sha256={z:digest(Path('/usr/share/zoneinfo')/z) for z in ['America/New_York','UTC']},env={k:env[k] for k in ['TZ','LC_ALL']},
                binary=str(binary),binary_sha256=digest(binary),module=str(module),module_sha256=digest(module),
                bash_version=subprocess.check_output([str(binary),'--version'],text=True).splitlines()[0],
                compiler_version=(module.parent/'compiler-version.txt').read_text(),
                source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                source_dirty=subprocess.run(['git','diff','--quiet','HEAD','--',*sources],cwd=ROOT).returncode != 0,
                source_sha256={s:digest(ROOT/s) for s in sources},cases=results,
                limitations=['Includes shell startup, loop, fixture, validation, and private file I/O overhead.',
                             'No real RTC access, update-edge synchronization, clock accuracy or hardware latency qualification.',
                             'No util-linux timing ratio: its RTC synchronization and display work differ.'])
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
    return 0
if __name__=='__main__': raise SystemExit(main())
