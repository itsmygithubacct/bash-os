#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Interleave before/after tac builds with GNU and BusyBox on fixed inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

import loadables


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error('--runs must be positive')
    before,after = (str(p.resolve(strict=True)) for p in [args.before,args.after])
    if args.cpu is not None:
        os.sched_setaffinity(0,{args.cpu})
    environment = {'PATH':'','LC_ALL':'C','TZ':'UTC','TERM':'dumb'}
    report = {'schema':1,'date':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
              'architecture':platform.machine(),'kernel':platform.release(),
              'cpu_affinity':sorted(os.sched_getaffinity(0)),
              'load_average_start':os.getloadavg(),'samples':args.runs,
              'method':'Warm-cache untraced batch wall time; stdout /dev/null; rotated/reversed order; single and repeated output validation; external commands launched by the before Bash build.',
              'binaries':{k:{'name':Path(p).name,'sha256':hashlib.sha256(Path(p).read_bytes()).hexdigest()}
                          for k,p in [('before',before),('after',after)]},'cases':[]}
    report['reference_versions'] = {
        name: subprocess.check_output(command, stderr=subprocess.STDOUT,
                                      text=True, timeout=5).splitlines()[0]
        for name,command in [('external',['/usr/bin/tac','--version']),
                             ('busybox',['/usr/bin/busybox'])]}
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name'):
            report['cpu_model'] = line.split(':',1)[1].strip(); break
    args.output.parent.mkdir(parents=True,exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report,indent=2)+'\n')

    with tempfile.TemporaryDirectory(prefix='bash-os-tac-bench-') as directory:
        root = Path(directory)
        loadables.fixtures(root)
        text = (root/'text').read_bytes()
        mib = 1024*1024
        fixtures = {'tiny':b'first\nsecond\nthird\nlast',
                    '1m-lines':(text*(mib//len(text)+1))[:mib],
                    '16m-lines':(text*(16*mib//len(text)+1))[:16*mib],
                    'dense-lines':b'x\n'*(mib//2),
                    'long-records':b'a'*mib+b'\n'+b'b'*mib+b'\n'+b'c'*mib,
                    'nul':(b'alpha\0beta\0gamma\0'*(mib//17+1))[:mib],
                    'custom':b'alpha::beta::gamma::'*20000}
        for name,data in fixtures.items(): (root/name).write_bytes(data)
        cases = [('text','text',[],26,True),('tiny','tiny',[],200,True),
                 ('1m-lines','1m-lines',[],10,True),('16m-lines','16m-lines',[],1,True),
                 ('dense-lines','dense-lines',[],2,True),('long-records','long-records',[],3,True),
                 ('nul','nul',['-s',''],6,False),('custom','custom',['-b','-s','::'],10,False),
                 ('before-separator','text',['-b'],26,False)]

        def run(shell,command,fixture,passes,capture=False):
            script = 'input=$1; passes=$2; shift 2; for ((i=0;i<passes;i++)); do "$@" < "$input" || exit; done'
            with tempfile.TemporaryFile() as output:
                start = time.perf_counter_ns()
                p = subprocess.run([shell,'--noprofile','--norc','-c',script,'_',fixture,str(passes),*command],
                                   cwd=root,env=environment,stdout=output if capture else subprocess.DEVNULL,
                                   stderr=subprocess.PIPE,timeout=30)
                ms = (time.perf_counter_ns()-start)/1e6
                output.seek(0)
                return p.returncode,output.read() if capture else b'',ms,p.stderr

        for identifier,fixture,options,passes,has_applet in cases:
            commands = {'before':(before,['tac',*options]),'after':(after,['tac',*options]),
                        'external':(before,['/usr/bin/tac',*options])}
            if has_applet:
                commands['busybox'] = (before,['/usr/bin/busybox','tac',*options])
            content = (root/fixture).read_bytes()
            row = {'id':identifier,'args':options,'passes':passes,'bytes':len(content),
                   'fixture_sha256':hashlib.sha256(content).hexdigest(),'results':{}}
            validation_passes = max(3,passes)
            row['validation_passes'] = validation_passes
            rc,expected,_,err = run(*commands['external'],fixture,1,True)
            if rc: raise RuntimeError(f'GNU reference failed: {err!r}')
            accepted = []
            for label,command in commands.items():
                for count in [1,validation_passes]:
                    rc,actual,_,err = run(*command,fixture,count,True)
                    if rc or actual!=expected*count:
                        row['results'][label] = {'status':'invalid','returncode':rc,
                                                 'validation_passes':count}
                        break
                else:
                    accepted.append(label)
            if not accepted:
                raise RuntimeError(f'{identifier}: no implementation passed validation')
            samples = {name:[] for name in accepted}
            for iteration in range(args.runs):
                order = accepted[iteration%len(accepted):]+accepted[:iteration%len(accepted)]
                if iteration%2: order.reverse()
                for label in order:
                    rc,_,ms,err = run(*commands[label],fixture,passes)
                    if rc: raise RuntimeError(f'{label} failed while timing: {err!r}')
                    samples[label].append(ms)
            for label,values in samples.items():
                row['results'][label] = {'status':'ok','median_ms':round(statistics.median(values),3),
                                         'min_ms':round(min(values),3),'max_ms':round(max(values),3),
                                         'runs_ms':[round(value,3) for value in values]}
            report['cases'].append(row); save()
            print(identifier+': '+', '.join(f"{label}={value.get('median_ms',value['status'])}"
                                           for label,value in row['results'].items()),flush=True)
    report['load_average_end'] = os.getloadavg(); save()


if __name__=='__main__':
    main()
