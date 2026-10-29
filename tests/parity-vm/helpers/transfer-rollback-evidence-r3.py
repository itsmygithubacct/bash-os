#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Disposable-VM-only bounded transaction mock and evidence collector.

The mock is not the image installer. It verifies a fixture signature, snapshots
one pre-existing file, installs one signed payload and two state files, and
rolls back only a matching journal. No other paths or roots are accepted.
"""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import uuid

HOME=Path('/tmp/parity-home')
CASE=Path('/tmp/parity-case')
BASE=HOME/'rollback-fixture'
BACKEND=HOME/'rollback-backend'
LOG=HOME/'rollback-backend.jsonl'
OWNED='etc/fixture/owned'
STATE='var/lib/bl-pkg/installed/probe'
POINTER='var/lib/pkg/installed/probe/pointer'
NEW=b'signed fixture version two\n'
OLD=b'original package version\n'
SENTINEL=b'unrelated content\n'


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text().strip()
        if str(uuid.UUID(marker))!=marker.lower(): raise ValueError('noncanonical marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('unexpected uid')
        if Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME): raise ValueError('scratch mismatch')
        if CASE.stat().st_uid!=2000 or HOME.stat().st_uid!=2000: raise ValueError('scratch owner mismatch')
    except (OSError,ValueError) as exc:
        raise SystemExit('disposable-VM guard refused helper: '+str(exc))


def run(args):
    return subprocess.run(args,capture_output=True,timeout=12)


def digest(data): return hashlib.sha256(data).hexdigest()


def checked_root(text):
    if text not in ('root','control-root'): raise ValueError('unapproved fixture root')
    path=CASE/text
    if path.is_symlink() or path.resolve()!=path or not path.is_dir(): raise ValueError('invalid fixture root')
    return path


def make_root(name):
    r=CASE/name
    for d in ('etc/fixture','var/lib/bl-pkg/installed','var/lib/pkg/installed/probe'):
        (r/d).mkdir(parents=True,exist_ok=True)
    (r/OWNED).write_bytes(OLD); (r/OWNED).chmod(0o640)
    (r/'etc/fixture/unrelated').write_bytes(SENTINEL); (r/'etc/fixture/unrelated').chmod(0o604)
    (r/'var/lib/bl-pkg/installed/other').write_bytes(b'other-state\n')
    (r/'var/lib/bl-pkg/installed/other').chmod(0o600)


def snapshot(name):
    root=checked_root(name); result={}
    for p in sorted(root.rglob('*')):
        rel=p.relative_to(root).as_posix(); info=p.lstat()
        if stat.S_ISLNK(info.st_mode): raise ValueError('symlink in fixture root')
        if stat.S_ISDIR(info.st_mode): result[rel]={'type':'dir','mode':stat.S_IMODE(info.st_mode)}
        elif stat.S_ISREG(info.st_mode):
            body=p.read_bytes()
            if len(body)>65536: raise ValueError('file too large')
            result[rel]={'type':'file','mode':stat.S_IMODE(info.st_mode),
                         'bytes_hex':body.hex(),'sha256':digest(body)}
        else: raise ValueError('unexpected root object')
    return result


def emit_snapshot(name,label):
    data=snapshot(name)
    (HOME/(label+'.json')).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    return data


def prepare():
    BASE.mkdir(mode=0o700)
    archive=BASE/'synthetic.tar'
    entries=[('MANIFEST',b'name: probe\ntype: payload\nversion: 2\n',0o644),
             ('files/'+OWNED,NEW,0o644)]
    with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as tar:
        for name,data,mode in entries:
            info=tarfile.TarInfo(name); info.size=len(data); info.mode=mode; info.mtime=1
            tar.addfile(info,io.BytesIO(data))
    with tarfile.open(archive,'r:') as tar:
        rows=[(m.name,tar.extractfile(m).read(),m.mode) for m in tar]
    if rows!=entries: raise ValueError('archive round trip failed')
    private=BASE/'private.pem'; public=BASE/'public.pem'; signature=BASE/'signature.bin'
    operations=[['/usr/bin/openssl','genpkey','-algorithm','Ed25519','-out',str(private)],
      ['/usr/bin/openssl','pkey','-in',str(private),'-pubout','-out',str(public)],
      ['/usr/bin/openssl','pkeyutl','-sign','-rawin','-inkey',str(private),'-in',str(archive),'-out',str(signature)]]
    for cmd in operations:
        p=run(cmd)
        if p.returncode: raise ValueError('fixture crypto preparation failed: '+repr(p.stderr))
    verify=['/usr/bin/openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(public),
            '-in',str(archive),'-sigfile',str(signature)]
    positive=run(verify)
    changed=BASE/'altered.tar'; raw=archive.read_bytes(); changed.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
    negative=run(verify[:8]+[str(changed)]+verify[9:])
    proof={'archive_base64':base64.b64encode(raw).decode(),'archive_sha256':digest(raw),
           'signature_base64':base64.b64encode(signature.read_bytes()).decode(),
           'public_pem':public.read_text(), 'entries':[{'name':n,'bytes_hex':b.hex(),'mode':m} for n,b,m in entries],
           'positive':{'argv':verify,'status':positive.returncode,'stdout_hex':positive.stdout.hex(),'stderr_hex':positive.stderr.hex()},
           'negative':{'argv':verify[:8]+[str(changed)]+verify[9:],'status':negative.returncode,
                       'stdout_hex':negative.stdout.hex(),'stderr_hex':negative.stderr.hex()}}
    (HOME/'rollback-input-evidence.json').write_text(json.dumps(proof,indent=2)+'\n')
    if positive.returncode!=0 or negative.returncode==0: raise ValueError('signature controls failed')
    make_root('root'); make_root('control-root')
    print('signed-input-controls=ok')


def seed(name):
    root=checked_root(name); archive=BASE/'synthetic.tar'
    cmd=['/usr/bin/openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(BASE/'public.pem'),
         '-in',str(archive),'-sigfile',str(BASE/'signature.bin')]
    verified=run(cmd)
    if verified.returncode: raise ValueError('signed input rejected')
    with tarfile.open(archive,'r:') as tar:
        members=tar.getmembers()
        if [m.name for m in members]!=['MANIFEST','files/'+OWNED] or any(not m.isfile() for m in members):
            raise ValueError('unexpected signed package members')
        if tar.extractfile(members[0]).read()!=b'name: probe\ntype: payload\nversion: 2\n': raise ValueError('unexpected manifest')
        payload=tar.extractfile(members[1]).read()
        if payload!=NEW: raise ValueError('unexpected payload')
    if (root/STATE).exists() or (root/POINTER).exists(): raise ValueError('existing fixture transaction state')
    txn='txn-'+uuid.uuid4().hex
    journal=BASE/txn; journal.mkdir(mode=0o700)
    old=(root/OWNED).read_bytes(); oldmode=stat.S_IMODE((root/OWNED).stat().st_mode)
    (journal/'record.json').write_text(json.dumps({'root':name,'txn':txn,'old_hex':old.hex(),
        'old_mode':oldmode,'input_sha256':digest(archive.read_bytes()),
        'signature_verification':{'argv':cmd,'status':verified.returncode,
                                  'stdout_hex':verified.stdout.hex(),'stderr_hex':verified.stderr.hex()}})+'\n')
    (root/OWNED).write_bytes(payload); (root/OWNED).chmod(0o644)
    (root/STATE).write_text('txn='+txn+'\n')
    (root/POINTER).write_text('type=payload\nbackend=bl-pkg\ntxn='+txn+'\n')
    (HOME/('rollback-txn-'+name)).write_text(txn+'\n')
    return 'installed txn='+txn+'\n'


def rollback(name,txn):
    root=checked_root(name)
    if not re.fullmatch(r'txn-[0-9a-f]{32}',txn): raise ValueError('invalid transaction id')
    journal=BASE/txn/'record.json'
    if not journal.is_file(): raise ValueError('unknown transaction')
    data=json.loads(journal.read_text())
    if data['txn']!=txn or data['root']!=name: raise ValueError('transaction root mismatch')
    if (root/STATE).read_text()!='txn='+txn+'\n': raise ValueError('state does not match transaction')
    if (root/POINTER).read_text()!='type=payload\nbackend=bl-pkg\ntxn='+txn+'\n': raise ValueError('pointer mismatch')
    (root/OWNED).write_bytes(bytes.fromhex(data['old_hex'])); (root/OWNED).chmod(data['old_mode'])
    (root/STATE).unlink(); (root/POINTER).unlink()
    return 'rolled-back txn='+txn+'\n'


def control():
    before=emit_snapshot('control-root','control-before')
    first=run([str(BACKEND),'seed','control-root'])
    if first.returncode: raise ValueError('mock seed control failed')
    txn=(HOME/'rollback-txn-control-root').read_text().strip()
    installed=emit_snapshot('control-root','control-installed')
    invalid=run([str(BACKEND),'--internal','--root','control-root','rollback','txn-'+'0'*32])
    unchanged=snapshot('control-root')
    valid=run([str(BACKEND),'--internal','--root','control-root','rollback',txn])
    after=emit_snapshot('control-root','control-after')
    result={'seed':{'status':first.returncode,'stdout_hex':first.stdout.hex(),'stderr_hex':first.stderr.hex()},
            'unknown':{'status':invalid.returncode,'stdout_hex':invalid.stdout.hex(),'stderr_hex':invalid.stderr.hex()},
            'rollback':{'status':valid.returncode,'stdout_hex':valid.stdout.hex(),'stderr_hex':valid.stderr.hex()},'txn':txn,
            'unknown_unchanged':unchanged==installed,'after_equals_before':after==before}
    (HOME/'rollback-control.json').write_text(json.dumps(result,indent=2)+'\n')
    if not (invalid.returncode!=0 and unchanged==installed and valid.returncode==0 and after==before and
            valid.stdout==('rolled-back txn='+txn+'\n').encode()): raise ValueError('rollback mock controls failed')
    print('transaction-controls=ok')


def assess(txn,rc):
    before=json.loads((HOME/'before.json').read_text()); installed=json.loads((HOME/'installed.json').read_text())
    after=json.loads((HOME/'after.json').read_text())
    unknown_after=json.loads((HOME/'unknown-after.json').read_text())
    unknown_status=(HOME/'unknown-status').read_text().strip()
    entries=[json.loads(line) for line in LOG.read_text().splitlines()]
    calls=[e for e in entries if e['argv'][1:]==['--internal','--root','root','rollback',txn]]
    out=(HOME/'candidate.out').read_bytes(); err=(HOME/'candidate.err').read_bytes()
    conditions={
      'candidate_unknown_failed':unknown_status=='1' and unknown_after==installed and any(e['argv'][1:]==['--internal','--root','root','rollback','txn-'+'0'*32] and e['status']!=0 for e in entries),
      'candidate_status_zero':rc=='0',
      'candidate_output_exact':out==('rolled-back txn='+txn+'\n').encode(),
      'one_matching_mock_call':len(calls)==1 and calls[0]['status']==0 and calls[0]['program']==str(BACKEND) and calls[0]['internal_env']=='1' and calls[0]['program_sha256']==digest(BACKEND.read_bytes()),
      'installed_file_exact':installed.get(OWNED,{}).get('bytes_hex')==NEW.hex() and installed.get(OWNED,{}).get('mode')==0o644,
      'installed_state':installed.get(STATE,{}).get('bytes_hex')==('txn='+txn+'\n').encode().hex(),
      'installed_pointer':installed.get(POINTER,{}).get('bytes_hex')==('type=payload\nbackend=bl-pkg\ntxn='+txn+'\n').encode().hex(),
      'sentinel_unchanged':installed.get('etc/fixture/unrelated')==before.get('etc/fixture/unrelated')==after.get('etc/fixture/unrelated'),
      'unrelated_state_unchanged':installed.get('var/lib/bl-pkg/installed/other')==before.get('var/lib/bl-pkg/installed/other')==after.get('var/lib/bl-pkg/installed/other'),
      'after_equals_baseline':after==before}
    evidence={'txn':txn,'candidate_argv':['pkg','rollback',txn,'--root','root'],'candidate_status':rc,
              'candidate_stdout_hex':out.hex(),'candidate_stderr_hex':err.hex(),'matching_backend_calls':calls,
              'unknown_candidate_status':unknown_status,'unknown_stdout_hex':(HOME/'unknown.out').read_bytes().hex(),
              'unknown_stderr_hex':(HOME/'unknown.err').read_bytes().hex(),
              'conditions':conditions,'scope':'bounded mock transaction; real image installer not exercised'}
    (HOME/'rollback-assessment.json').write_text(json.dumps(evidence,indent=2)+'\n')
    if not all(conditions.values()): raise ValueError('explicit rollback observations differ')
    print('explicit-rollback=ok')


def main():
    args=sys.argv[1:]
    if args==['prepare']: prepare(); return
    if args==['control']: control(); return
    if len(args)==3 and args[0]=='snapshot': emit_snapshot(args[1],args[2]); return
    if len(args)==3 and args[0]=='assess': assess(args[1],args[2]); return
    row={'program':sys.argv[0],'argv':sys.argv[:], 'pid':os.getpid(),'ppid':os.getppid(),
         'uid':os.getuid(),'internal_env':os.environ.get('BASHPKG_INTERNAL'),
         'program_sha256':digest(Path(sys.argv[0]).read_bytes()),'status':1,'stdout_hex':'','stderr_hex':''}
    try:
        if len(args)==2 and args[0]=='seed': output=seed(args[1])
        elif len(args)==5 and args[:2]==['--internal','--root'] and args[3]=='rollback': output=rollback(args[2],args[4])
        else: raise ValueError('unsupported mock invocation')
        row['status']=0; row['stdout_hex']=output.encode().hex(); sys.stdout.write(output)
    except Exception as exc:
        error=type(exc).__name__+': '+str(exc)+'\n'; row['stderr_hex']=error.encode().hex(); sys.stderr.write(error)
    finally:
        with LOG.open('a') as log: log.write(json.dumps(row,sort_keys=True)+'\n')
    raise SystemExit(row['status'])


if __name__=='__main__':
    require_guest()
    main()
