#!/usr/bin/env python3
"""Validated crypto size/conversion/allocation measurements; run via bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import ssl
import cryptography
from cryptography.hazmat.backends import default_backend
import subprocess
import tempfile
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True, type=Path)
    ap.add_argument('--before', type=Path)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--profile', action='store_true')
    ap.add_argument('--runs', type=int, default=7)
    args = ap.parse_args()
    assert args.runs >= 7
    binaries = {'after' if args.before else 'current': args.binary.resolve()}
    if args.before: binaries = {'before': args.before.resolve(), **binaries}
    env = {**os.environ, 'PATH': '', 'LC_ALL': 'C', 'BASHCRYPTO_NONCE_GUARD': '0'}
    report = dict(affinity=sorted(os.sched_getaffinity(0)), uname=platform.uname()._asdict(),
                  cpu_model=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
                  versions={}, binaries={k:dict(path=str(v), sha256=sha(v)) for k,v in binaries.items()},
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
                  source_sha256={'loadables/crypto.c':sha('loadables/crypto.c'), 'loadables/_mbedtls/sha256.c':sha('loadables/_mbedtls/sha256.c')},
                  python=platform.python_version(), reference_libraries={'hashlib_openssl':ssl.OPENSSL_VERSION,'cryptography':cryptography.__version__,'cryptography_openssl':default_backend().openssl_version_text()}, environment={'PATH':'','LC_ALL':'C','BASHCRYPTO_NONCE_GUARD':'0'},
                  runs=args.runs, warmup_batches=1, cases=[], load_start=os.getloadavg(),
                  method='Same shell per batch; reopen same fixture each pass; capture and independently validate EVERY output and fail-fast exit status, including warmup and timed batches. Rotating implementation order.')
    for name, command in [('sha256sum',['/usr/bin/sha256sum','--version']), ('openssl',['/usr/bin/openssl','version']), ('bash',[str(args.binary.resolve()),'--version'])]:
        p = subprocess.run(command, capture_output=True, text=True, check=True)
        report['versions'][name] = p.stdout.splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='sol-crypto-') as temporary:
        root = Path(temporary)
        cases=[]
        for size, passes in [(0,1000),(64,1000),(8192,200),(1048576,11),(16777216,3)]:
            data=(bytes(range(256))*((size+255)//256))[:size]
            file=root/str(size); file.write_bytes(data)
            cases.append((f'sha256-{size}',file,['crypto','sha256','-x'],hashlib.sha256(data).hexdigest().encode()+b'\n',passes,'sha256sum'))
        file=root/'empty';file.write_bytes(b'')
        cases.append(('shake256-hex-65536',file,['crypto','shake256','-n','65536','-x'],hashlib.shake_256(b'').hexdigest(65536).encode()+b'\n',50,None))
        data=(bytes(range(256))*4096); file=root/'aead';file.write_bytes(data)
        key,nonce=bytes(range(32)),bytes(range(12))
        expected=ChaCha20Poly1305(key).encrypt(nonce,data,None)
        cases.append(('chacha20-poly1305-1048576',file,['crypto','chacha20-poly1305','-e','-k',key.hex(),'-n',nonce.hex()],expected,11,None))
        script='input=$1; count=$2; shift 2; for ((i=0;i<count;i++)); do "$@" < "$input" || exit; done'
        def run(binary,command,file,passes,expected,normalizer=None,prefix=()):
            argv=[str(binary),'--noprofile','--norc','-c',script,'bench',str(file),str(passes),*command]
            started=time.perf_counter_ns()
            p=subprocess.run([*prefix,*argv],capture_output=True,env=env,timeout=120)
            elapsed=(time.perf_counter_ns()-started)/1e6
            assert p.returncode == 0,(command,p.returncode,p.stderr[:2000])
            actual=p.stdout
            if normalizer: actual=b''.join(line.split()[0]+b'\n' for line in actual.splitlines())
            assert actual == expected*passes,(command,len(actual),sha(file))
            return elapsed, p.stderr.decode(errors='replace')
        for name,file,command,expected,passes,reference in cases:
            implementations={k:(v,command,None) for k,v in binaries.items()}
            if reference: implementations['external']=(args.binary.resolve(),['/usr/bin/sha256sum'],'digest')
            row=dict(workload=name, input_bytes=file.stat().st_size,fixture_sha256=sha(file),
                     command=command,passes=passes, work_bytes=file.stat().st_size*passes,
                     expected_record_sha256=hashlib.sha256(expected).hexdigest(),expected_record_bytes=len(expected),
                     oracle='hashlib/OpenSSL SHA-256' if reference else ('hashlib SHAKE-256' if name.startswith('shake') else 'cryptography/OpenSSL ChaCha20Poly1305'),
                     kind='compared' if reference else 'api',results={})
            for binary,cmd,norm in implementations.values(): run(binary,cmd,file,passes,expected,norm)
            samples={k:[] for k in implementations}
            for n in range(args.runs):
                keys=list(implementations);keys=keys[n%len(keys):]+keys[:n%len(keys)]
                if n%2: keys.reverse()
                for k in keys:
                    binary,cmd,norm=implementations[k]
                    ms,_=run(binary,cmd,file,passes,expected,norm)
                    samples[k].append(ms)
            for k,values in samples.items(): row['results'][k]=dict(status='ok',runs_ms=values,median_ms=statistics.median(values),min_ms=min(values),max_ms=max(values))
            report['cases'].append(row)
            args.output.write_text(json.dumps(report,indent=2)+'\n')
            print(name, {k:round(v['median_ms'],3) for k,v in row['results'].items()},flush=True)
            if args.profile and name in ['sha256-1048576','shake256-hex-65536','chacha20-poly1305-1048576']:
                binary=next(iter(binaries.values()))
                profile_file=args.output.with_name(args.output.stem+'-'+name+'.perf')
                try:
                    _,stderr=run(binary,command,file,passes*10,expected,prefix=['/usr/bin/perf','record','-e','cycles:u','-g','-o',str(profile_file),'--'])
                    report.setdefault('profiles',[]).append(dict(workload=name,status='ok',data=str(profile_file),stderr=stderr))
                except AssertionError as error:
                    report.setdefault('profiles',[]).append(dict(workload=name,status='unavailable',error=str(error)))
                # Syscall profile is independently validated too; retain complete stderr.
                _,stderr=run(binary,command,file,passes,expected,prefix=['/usr/bin/strace','-c'])
                tracefile=args.output.with_name(args.output.stem+'-'+name+'.strace.txt')
                tracefile.write_text(stderr)
        report['load_end']=os.getloadavg()
        args.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__ == '__main__': main()
