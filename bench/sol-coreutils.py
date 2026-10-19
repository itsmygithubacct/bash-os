#!/usr/bin/env python3
"""Individually validate and measure dispatcher verbs; run under the bench gate.

Every warm-up and timed batch captures all stdout records and checks status,
bytes/invariants and private mutation artifacts. Includes the eight historical
cases with their original fixture bytes. No aggregate dispatcher timing.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shlex
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--passes', type=int, default=30)
p.add_argument('--samples', type=int, default=7)
p.add_argument('--only')
p.add_argument('--source-snapshot', type=Path, default=ROOT/'loadables/coreutils.c')
a = p.parse_args()
assert a.samples >= 7 and a.passes >= 3
binary = str(a.binary.resolve())
sha = lambda b: hashlib.sha256(b).hexdigest()
env = {'PATH':'', 'LC_ALL':'C', 'TZ':'UTC', 'TERM':'dumb'}
report = dict(date=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()), harness_sha256=sha(Path(__file__).read_bytes()), binary=binary, binary_sha256=sha(Path(binary).read_bytes()),
              source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              source_sha256=sha(a.source_snapshot.read_bytes()), standalone_source_sha256=sha((ROOT/'loadables/tac.c').read_bytes()),
              source_state='Explicit source SHA identifies the compiled working-tree source; source_commit is its parent commit',
              kernel=platform.release(), platform=platform.machine(),
              affinity=sorted(os.sched_getaffinity(0)), environment=env,
              passes=a.passes, samples=a.samples, cases=[],
              method='Warm-up then alternating implementations; batch wall ms including shell startup; stdout captured and validated on EVERY pass; warm cache; no compilation')
report['cpu_model'] = next(x for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name'))
report['versions'] = {x:subprocess.check_output([x,'--version'],env=env,text=True).splitlines()[0] for x in [binary,'/usr/bin/tac','/usr/bin/nproc']}
report['reference_sha256'] = {}
manifest=Path(binary+'.manifest.txt')
report['build_manifest']=manifest.read_text() if manifest.exists() else None
with tempfile.TemporaryDirectory(prefix='sol-coreutils-bench-') as directory:
    d = Path(directory)
    rng=random.Random(20260908)
    words=['alpha','beta','gamma','delta','epsilon','the','and','of']
    fixtures={'empty': b'', 'left': b''.join(f'{i:06d} left\n'.encode() for i in range(10000)),
              'text': ''.join(' '.join(rng.choice(words) for _ in range(10))+'\n' for _ in range(12000)).encode()[:423000],
              'chain':b'a b\nb c\nc d\n', 'seed': bytes(range(1,9))*4096,
              'binary':bytes(range(256))*1025+b'last',
              'dense':b'x\n'*500000}
    for name, data in fixtures.items(): (d/name).write_bytes(data)
    report['fixtures']={k:dict(bytes=len(v),sha256=sha(v)) for k,v in fixtures.items()}
    # (case, args, input, work, post-command, validation kind)
    cases=[('factor',['factor','1234567890','97'],'empty','two integer factorizations','', 'exact'),
           ('factor-big',['factor','111111111111'],'empty','one integer factorization','', 'exact'),
           ('fmt',['fmt','-w','20','left'],'empty','120000 B / 10000 lines, width 20','', 'exact'),
           ('groups',['groups'],'empty','current process supplementary groups','', 'exact'),
           ('install',['install','-m','644','text','installed'],'empty','423000 B copied; mode 0644; readback each pass','; [[ -f installed && $(/usr/bin/stat -c %a installed) == 644 ]] || exit 91; /usr/bin/cat installed','exact'),
           ('numfmt',['numfmt','--to=iec','1024','4096'],'empty','two integer conversions','', 'exact'),
           ('tac',['tac','left'],'empty','120000 B / 10000 lines','', 'exact'),
           ('tsort',['tsort','chain'],'empty','four-node chain / three edges','', 'exact'),
           ('nproc',['nproc'],'empty','one affinity count; OMP unset','', 'exact'),
           ('shuf',['shuf','--random-source=seed','-i','1-100'],'empty','100-element permutation, fixed seed','', 'permutation'),
           ('shred',['shred','-n','0','-z','shredded'],'empty','8192 B private file zero overwrite + fsync + readback per pass','; /usr/bin/cat shredded','zero'),
           ('mknod',['mknod','fifo','p'],'empty','one private FIFO creation + type verification + removal','; [[ -p fifo ]] || exit 92; /usr/bin/rm fifo','exact'),
           ('yes',['yes','fixture'],'empty','4096 output records consumed; pipe-close termination; producer overshoot unspecified','', 'yes'),
           ('tac-stdin',['tac'],'left','120000 B redirected stdin / repeated calls','', 'exact'),
           ('tac-binary',['tac','binary'],'empty','262404 B including NUL/unterminated tail','', 'exact'),
           ('tac-dense',['tac','dense'],'empty','1000000 B / 500000 short records','', 'exact')]
    for name,args,fixture,work,post,kind in cases:
        if a.only and name not in a.only.split(','): continue
        row=dict(id='coreutils-'+name,work_unit=work,fixture=fixture,args=args,post=post,results={})
        report['cases'].append(row)
        reference='/usr/bin/'+args[0]
        report['reference_sha256'][reference]=sha(Path(reference).read_bytes())
        commands={'dispatcher':['coreutils',*args], 'gnu':[reference,*args[1:]]}
        if args[0]=='tac': commands['standalone']=['tac',*args[1:]]
        expected=None
        def batch(label,count):
            (d/'shredded').write_bytes(b'x'*8192)
            if (d/'fifo').exists(): (d/'fifo').unlink()
            command=shlex.join(commands[label])
            body=command+' < '+shlex.quote(fixture)+' || exit'+post
            if kind=='yes':
                body=command+' | /usr/bin/head -n 4096; r=("${PIPESTATUS[@]}"); [[ ${r[1]} == 0 && ${r[0]} != 0 ]] || exit 93'
            script=f'for ((i=0;i<{count};i++)); do {body}; done'
            start=time.perf_counter_ns()
            result=subprocess.run([binary,'--noprofile','--norc','-c',script],cwd=d,env=env,capture_output=True,timeout=60)
            ms=(time.perf_counter_ns()-start)/1e6
            assert result.returncode==0,(label,name,result.returncode,result.stderr)
            assert not result.stderr,(label,name,result.stderr)
            data=result.stdout
            if kind=='permutation':
                lines=data.splitlines(); assert len(lines)==count*100
                for i in range(count): assert collections.Counter(lines[i*100:(i+1)*100])==collections.Counter(str(i).encode() for i in range(1,101))
            elif kind=='yes': assert data==b'fixture\n'*(4096*count)
            elif kind=='zero': assert data==b'\0'*(8192*count)
            else: assert data==expected*count,(label,name,len(data),len(expected)*count)
            return ms
        # Independent GNU result, with exact tac and artifact checks below.
        (d/'shredded').write_bytes(b'x'*8192)
        if kind=='exact':
            command=shlex.join(commands['gnu'])
            g=subprocess.run([binary,'-c',command+' < '+fixture+' || exit'+post],cwd=d,env=env,capture_output=True,timeout=30)
            assert g.returncode==0 and not g.stderr,(name,g)
            expected=g.stdout
            if args[0]=='tac':
                data=fixtures[fixture if len(args)==1 else args[1]]
                records=data.split(b'\n'); oracle=b''
                if records[-1]: oracle=records.pop()
                else: records.pop()
                oracle+=b''.join(x+b'\n' for x in reversed(records))
                assert expected==oracle
            if name=='install': assert expected==fixtures['text']
        row['expected_sha256']=sha(expected) if expected is not None else None
        row['validation']='every batch status + every record bytes' if kind=='exact' else kind+' invariant on every pass'
        row['metric_kind']='self' if kind in ('yes','permutation') else 'compared'
        try:
            for label in commands: batch(label,1)
            for label in commands: row['results'][label]={'status':'ok','samples_ms':[]}
            for sample in range(a.samples):
                order=list(commands)
                if sample%2: order.reverse()
                for label in order: row['results'][label]['samples_ms'].append(batch(label,a.passes))
            for data in row['results'].values(): data['median_ms']=statistics.median(data['samples_ms'])
            if row['metric_kind']=='compared': row['dispatcher_over_gnu']=row['results']['dispatcher']['median_ms']/row['results']['gnu']['median_ms']
            row['status']='ok'
        except AssertionError as e:
            row['status']='invalid'; row['error']=str(e)
        a.output.write_text(json.dumps(report,indent=2)+'\n')
        print(row['id'],row['status'], {k:round(v.get('median_ms',0),3) for k,v in row['results'].items()},flush=True)
assert all(r['status']=='ok' for r in report['cases']), 'invalid case(s), inspect JSON'
