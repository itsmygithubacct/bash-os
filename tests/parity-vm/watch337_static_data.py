#!/usr/bin/env python3
"""Read only the exact saved watch v3 static data; never import or run fixture code."""
import argparse, base64, hashlib, json, os, stat, tarfile
from pathlib import Path

ARCHIVE='2e7501e86c488e2b14206a4e984d14fd09ab899770b6663224d4fa0887a99b8f'
PROVENANCE='80d6b7c619b201971fc41ba5d85f9bfb632875fd0ca8e90b9af552c436a35a9d'
UNIT='3428154e930e8ad36bab1c5a8532a22f2993adcbd50b16e76a47826aac7bc597'
TEARDOWN='1dda3305eaef7d855793f5b95f7ec13fb72a11c7bd4200b9443c6e12f8ced83d'
CASE='020a87eca1272d787379abf2ba1bc107359fa2464aa0bddf8c7d6b8b71a0aba4'
CANDIDATE='2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab'
IMAGE='9f8841a2a756268f3785232e713e56f5ac91157d116c37b14dbcb1ddcde17457'
GUARD_SHA='dea91736a54538ae758c4b416d0eb48b2fd4a4ba331af789967c2de0ccf769c6'
UUID='449f96f2-2b97-4096-a36b-2aedc13979ea'
GUARD='/opt/bashos-parity/harness/helpers/terminal213_guard.py'
PREFIX='/usr/bin/python3 '+GUARD+' || { printf "TERMINAL213-INFRA\\n" >&2; exit 90; }\n'
SCRIPTS={'entry':PREFIX+'watch --help\nexit 0','flow':PREFIX+"( exit 7 )\nprintf 'W337+'\nexit 1",'lookalike':PREFIX+"( exit 7 )\nprintf '\\033[H\\033[2J'\nexit 1",'guardfail':PREFIX+"watch -e 'exit 7'",'case':PREFIX+"watch -e 'exit 7'"}
ENV={'LC_ALL':'C.UTF-8','LANG':'C.UTF-8','TZ':'UTC','TERM':'xterm-256color','HOME':'/tmp/parity-home','PATH':'/empty','BASH_ENV':'','ENV':'','INPUTRC':'/dev/null','HISTFILE':'/dev/null','PS1':'PARITY> ','PS2':'MORE> ','PROMPT_COMMAND':''}
BASE='results/migration-terminal213-watch-error-key/'

def check(ok,msg):
    if not ok: raise ValueError(msg)
def digest(b):return hashlib.sha256(b).hexdigest()
def unique(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise ValueError('duplicate JSON key')
        d[k]=v
    return d
def parse(b):return json.loads(b,object_pairs_hook=unique)
def read(path,limit,expected=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);check(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=limit,'unsafe file '+str(path))
        chunks=[];remaining=a.st_size
        while remaining:
            b=os.read(fd,min(remaining,1024*1024));check(bool(b),'short read');chunks.append(b);remaining-=len(b)
        b=b''.join(chunks);z=os.fstat(fd)
        check((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),'file changed while reading')
        check(expected is None or digest(b)==expected,'hash mismatch '+str(path));return b
    finally:os.close(fd)
def rows(raw):
    check(0<len(raw)<=768*1024 and raw.endswith(b'\n'),'trace empty/truncated');r=[parse(x) for x in raw.splitlines()]
    check(2<=len(r)<=4096 and all(type(x.get('monotonic_ns')) is int for x in r),'trace record count/time')
    check(all(a['monotonic_ns']<=b['monotonic_ns'] for a,b in zip(r,r[1:])) and not any(x.get('kind')=='error' for x in r),'trace order/error')
    return r
def one(items,condition,description):
    values=[x for x in items if condition(x)];check(len(values)==1,description);return values[0]
def inspect_trace(mode,r,terminal):
    start,end=r[0],r[-1];env=dict(ENV)
    if mode=='guardfail':env['HOME']='/tmp/watch337-intentionally-invalid-home'
    check(start.get('kind')=='begin' and start.get('mode')==mode and start.get('vm_token')==UUID and start.get('canonical_case_sha256')==CASE and start.get('candidate',{}).get('sha256')==CANDIDATE and start.get('entry')==0x5c0b00,'begin binding '+mode)
    check(start.get('argv')==['/opt/bashos-parity/candidate','--noprofile','--norc','-c',SCRIPTS[mode]] and start.get('environment')==env and start.get('cwd')=='/tmp/parity-case' and (start.get('uid'),start.get('gid'),start.get('groups'))==(2000,2000,[]),'execution scope '+mode)
    leader=one(r,lambda x:x.get('kind')=='birth','leader birth')['pid']
    arm=one(r,lambda x:x.get('kind')=='entry_armed' and x.get('pid')==leader,'entry arm')
    check(arm.get('entry')==0x5c0b00 and arm.get('original_word')==int.from_bytes(bytes.fromhex('4157415641554154'),'little') and arm.get('report_descriptor_not_inherited') is True,'entry code identity')
    forks=[x for x in r if x.get('kind')=='fork'];check(len({x['child'] for x in forks})==len(forks),'fork identity reused')
    guard=one(r,lambda x:x.get('kind')=='syscall' and x.get('call')=='execve' and x.get('path')=='/usr/bin/python3' and x.get('argv')==['/usr/bin/python3',GUARD] and x.get('result')==0,'guard exec')['pid']
    expected_guard=1 if mode=='guardfail' else 0
    check(any(x.get('pid')==leader and x.get('child')==guard for x in forks),'guard child binding')
    one(r,lambda x:x.get('kind')=='reaped' and x.get('pid')==guard and x.get('shell_status')==expected_guard,'guard reaped')
    wait=one(r,lambda x:x.get('kind')=='syscall' and x.get('call')=='wait4' and x.get('pid')==leader and x.get('result')==guard and x.get('wait_status')==expected_guard<<8,'guard wait')
    entries=[x for x in r if x.get('kind')=='watch_entry']
    if mode in ('entry','case'):
        check(len(entries)==1 and entries[0].get('pid')==leader and entries[0].get('address')==0x5c0b00 and entries[0]['monotonic_ns']>=wait['monotonic_ns'],'watch entry attribution')
        a=entries[0].get('active_builtin_table',{});check(a.get('table')==0x121a960 and a.get('count')==363 and a.get('function')==0x5c0b00 and a.get('flags')==5 and a.get('name_pointer')==0xe08ec6 and a.get('doc')==0x122a8a0 and a.get('usage')==0xd65920 and type(a.get('index')) is int and 0<=a['index']<363,'active watch builtin table')
    else:check(not entries,'false watch entry '+mode)
    status={'entry':0,'flow':1,'lookalike':1,'guardfail':90,'case':1}[mode]
    check(end.get('kind')=='end' and end.get('complete') is True and end.get('leader_status')==status and terminal.get('status')==status and terminal.get('signal') is None and terminal.get('harness_error') is None and terminal.get('terminal_restored') is True and not terminal.get('stray_processes'),'terminal completion '+mode)
    reaped=one(r,lambda x:x.get('kind')=='reaped' and x.get('pid')==leader and x.get('shell_status')==status,'leader exit')
    if mode in ('flow','lookalike','case'):
        e=one(r,lambda x:x.get('kind')=='reaped' and x.get('shell_status')==7,'exit 7 child')
        child=e['pid'];check(any(x.get('pid')==leader and x.get('child')==child for x in forks),'exit 7 child fork')
        one(r,lambda x:x.get('kind')=='syscall' and x.get('call')=='wait4' and x.get('pid')==leader and x.get('result')==child and x.get('wait_status')==1792,'exit 7 child wait')
        if mode=='case':check(entries[0]['monotonic_ns']<e['monotonic_ns']<reaped['monotonic_ns'],'case entry/child/leader order')
    screen=base64.b64decode(terminal['screen_base64'],validate=True)
    if mode in ('flow','lookalike'):
        expected=b'W337+' if mode=='flow' else b'\x1b[H\x1b[2J'
        one(r,lambda x:x.get('kind')=='syscall' and x.get('call') in ('write','writev') and x.get('pid')==leader and x.get('result')==len(expected) and x.get('written_hex')==expected.hex(),'controlled PTY write')
        check(screen==expected,'control PTY bytes')
    if mode=='guardfail':check(b'TERMINAL213-INFRA\n' in screen.replace(b'\r\n',b'\n'),'guard refusal sentinel')
    return {'mode':mode,'leader_pid':leader,'guard_pid':guard,'trace_records':len(r),'status':status,'watch_entries':len(entries),'leader_exit_ns':reaped['monotonic_ns']}

def main():
    p=argparse.ArgumentParser();p.add_argument('trial',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=a.trial
    archive=read(root/'evidence.tar',512*1024**2,ARCHIVE);prov=parse(read(root/'provenance.json',4*1024**2,PROVENANCE));unit=parse(read(root/'run.log.unit-proof.json',2*1024**2,UNIT));tear=parse(read(root/'vm/teardown.json',2*1024**2,TEARDOWN))
    import io
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as t:
        members=t.getmembers();names=[m.name for m in members];check(len(names)==len(set(names)) and all((m.isfile() or m.isdir()) and not m.name.startswith('/') and '..' not in m.name.split('/') for m in members),'unsafe or duplicate archive member')
        def file(name):
            m=t.getmember(name);check(m.isfile() and 0<=m.size<=8*1024**2,'unsafe record');b=t.extractfile(m).read(m.size+1);check(len(b)==m.size,'short archive record');return b
        controls=[]
        for mode in ('entry','flow','lookalike','guardfail'):
            setup=parse(file(BASE+'watch337-'+mode+'.setup.json'));check(setup.get('status')==0 and setup.get('error') is None and setup.get('stdout_base64')=='' and setup.get('stderr_base64')=='' and setup.get('stray_processes')==[],'control setup')
            terminal=parse(file(BASE+'watch337-'+mode+'.terminal.json'));controls.append(inspect_trace(mode,rows(file(BASE+'watch337-'+mode+'.trace.jsonl')),terminal))
        key=parse(file('results/migration-terminal213-control-key/candidate.json'));check(key.get('status')==0 and key.get('error') is None and key.get('terminal_restored') is True,'local key control')
        c=parse(file(BASE+'candidate.json'));ref=parse(file(BASE+'reference.json'));trace=file(BASE+'watch337-case.trace.jsonl');candidate=inspect_trace('case',rows(trace),c)
        check(c.get('watch337_trace',{}).get('sha256')==digest(trace) and c['watch337_trace'].get('bytes')==len(trace) and c['watch337_trace'].get('diagnostic_only') is True,'case trace binding')
        check(c.get('events')==[] and c.get('terminal181_input_writes')==[] and 'process exited before step 0' in c.get('error','') and base64.b64decode(c['screen_base64'],validate=True)==b'\x1b[H\x1b[2J','candidate prompt/key reachability')
        check(candidate['leader_exit_ns']<=c['terminal213_failure_ns'],'exit precedes failed screen observation')
        ev=ref['events'];screen=base64.b64decode(ref['screen_base64'],validate=True);check(ref.get('status')==8 and ref.get('error') is None and ref.get('terminal_restored') is True,'reference exit/restoration')
        check([(x.get('step'),x.get('action')) for x in ev]==[(0,'screen'),(1,'quiet_ms'),(2,'send-begin'),(2,'send')],'reference steps')
        check(b'command exit with a non-zero status, press a key to exit' in screen[:ev[0]['offset']] and ev[1]['offset']==ev[0]['offset'] and ev[1]['duration_ms']==300 and ev[1]['monotonic_ns']-ev[0]['monotonic_ns']>=300_000_000,'reference prompt and quiet')
        writes=ref['terminal181_input_writes'];check(len(writes)==1 and writes[0]['hex']=='78' and ev[2]['requested_hex']=='78' and ev[3]['bytes_hex']=='78' and ev[1]['monotonic_ns']<=ev[2]['monotonic_ns']<=writes[0]['monotonic_ns']<=ev[3]['monotonic_ns'],'reference key sequence')
    check(prov.get('watch337_diagnostic_only') is True and prov.get('guest_summary_state')=='validated-diagnostic-only' and prov.get('evidence_validation',{}).get('archive_sha256')==ARCHIVE,'diagnostic evidence binding')
    check(prov.get('guest_units_proven_quiescent') is True and prov.get('scope_proven') is True and prov.get('overlay_discarded') is True and prov.get('prepared_unchanged') is True,'teardown and prepared image flags')
    check(unit.get('vm_uuid')==UUID and unit.get('quiescent') is True and unit.get('transport_finished') is True and tear.get('vm_uuid')==UUID and tear.get('proof_durable') is True and tear.get('scope_quiescent') is True and tear.get('cgroup_events',{}).get('removed') is True,'unit or scope proof')
    observed=prov.get('image_identity',{}).get('sha256');check(observed==GUARD_SHA and observed!=IMAGE,'unexpected image identity hash anomaly')
    result={'schema':'watch337-static-v3-independent-data-review-v1','qualification':'diagnostic-only; no retrospective 294 qualification','archive_sha256':ARCHIVE,'provenance_sha256':PROVENANCE,'unit_sha256':UNIT,'teardown_sha256':TEARDOWN,'vm_uuid':UUID,'controls':controls,'candidate':candidate,'candidate_observation':'FAIL: exited status 1 after builtin entry and child exit 7, before prompt or any input','candidate_trace_sha256':digest(trace),'reference_observation':'PASS: error prompt, 300 ms quiet, x, status 8','reference_observed_quiet_ns':ev[1]['monotonic_ns']-ev[0]['monotonic_ns'],'provenance_anomaly':{'field':'image_identity.sha256','recorded':observed,'expected_prepared_image_sha256':IMAGE,'cause':'source reuses digest in helper hash loop; preflight and final prepared image checks independently compare to pinned image'},'limitations':['Raw trace controls are diagnostic; primary independently decides product evidence.','No direct key-read syscall or arbitrary schedule proof required for literal bounded sequence.','The false image_identity digest cannot be treated as a valid image-hash assertion.']}
    raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode();fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    print(json.dumps({'output':str(a.output),'sha256':digest(raw),'candidate':result['candidate_observation'],'reference':result['reference_observation']},sort_keys=True))
if __name__=='__main__':main()
