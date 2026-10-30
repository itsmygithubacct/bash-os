#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded setter55 evidence authorized by the pinned primary receipt."""
import json,tarfile,os,stat,hashlib,types
from pathlib import Path
_helper_path=Path(__file__).with_name('primary_controller_evidence.py')
if _helper_path.is_symlink() or not _helper_path.is_file():raise ValueError('reviewed controller utility missing')
_fd=os.open(_helper_path,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(_fd,'rb') as _f:_helper_bytes=_f.read(1024*1024+1)
if len(_helper_bytes)>1024*1024 or hashlib.sha256(_helper_bytes).hexdigest()!='b926b5bf88055c763a4ed5f36d5df56681a34d3cf3c160c434d16999ab8b20c0':raise ValueError('reviewed controller utility digest differs')
_helper=types.ModuleType('pinned_controller_evidence');_helper.__file__=str(_helper_path);exec(compile(_helper_bytes,str(_helper_path),'exec'),_helper.__dict__)
require,sha,file_sha,pinned,canonical,safe_member,tar_members,deny_noncore=(_helper.__dict__[k] for k in ('require','sha','file_sha','pinned','canonical','safe_member','tar_members','deny_noncore'))

IDS = ['uclamp-followup-setter-owned-updates',
 'uclamp-followup-setter-reset',
 'uclamp-followup-setter-policy',
 'uclamp-followup-setter-mock-rt',
 'uclamp-followup-setter-mock-deadline']
CASE_HASHES = {'uclamp-followup-setter-mock-deadline': 'a2f60d80cd76db17dbaa5ea698d3b32e289ece7e190107c0e5d00aae08d98c2a',
 'uclamp-followup-setter-mock-rt': 'd040e921788ee34d508f0b956fa3d8e6df758ed50b5d75a5c923e42d364fe4c1',
 'uclamp-followup-setter-owned-updates': '6a2d61488e99e44a1d5f2feb773be3412ba9a541da65201860d06637d0922811',
 'uclamp-followup-setter-policy': '58d9b1164767ac54f0304f4ed4197a22758d9a54baecd17bb9d49aded379df6e',
 'uclamp-followup-setter-reset': '4c2869bd469688ca5783554fc00584b1e5bb1b058ce631f159b2f86e0426fdcd'}
RUNS = {'dynamic': {'artifacts': {'compat/run.log.unit-proof.json': '3cff88b2d542a7d80f615a71d16a18047d2b6054e16bbb04969d87206211daf9',
                           'device-classification.json': '7da9e74204aa92eeabe2c484de10ba6bbab7bd13097309c46493f1c2e32fbe7b',
                           'evidence-record.json': '1d0b21520f6faa324061a92f437ab9155f4b3ee5e83d7d19d3eeabb1907d71c2',
                           'evidence.tar': '0fdc2fc93dd4433efa58603903ccd93bfe8cf4dbfdbf4ba83712439a537e2041',
                           'guest-summary.json': '46ebe2b6a28562a99c04e41e022d94cfa414a546b06e60e04692c904df3752a2',
                           'payload.tar': '3436a21e0ffa3281dc9ebecced260b6fd079000858609152f0cb898dff33a175',
                           'run.log.unit-proof.json': '3d7034032c23d4376d5e9ae1905f45b7ed33a0b8815432bf63bfe8a50a031274',
                           'vm/teardown.json': '8e1b29229b6d10ed360b3ad04778447f4423b9f6246513595997499f5fe3426a'},
             'candidate': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
             'case_raw': {'uclamp-followup-setter-mock-deadline': '902fe40dafbc628ae22becc34300eaeec8bcb05145be165825e3b81c2a3f1fac',
                          'uclamp-followup-setter-mock-rt': '1bdd2691456544011bd99871073c8511cbc996d9821185a33be876ee179cf58b',
                          'uclamp-followup-setter-owned-updates': '6d50db1333a34f49ab1c0f187acb33cba80227addeab3c2ef9df58f2e6d374da',
                          'uclamp-followup-setter-policy': '7183ec759f8dd5a80e158b5dc0a80131954799bcba4d447e27d334784a253c86',
                          'uclamp-followup-setter-reset': '6b79c4fa8e6bbc385f27d1510ca112ebf64156419cb03fade606d754293a3001'},
             'uuid': '10885c94-6185-47e0-8c8f-685f3c0129cb'},
 'static': {'artifacts': {'compat/run.log.unit-proof.json': '450d23b8010270003135053fa0fe200c4d12f5b371024fcc077c2bd24f6661da',
                          'device-classification.json': '6016573fe52d878b144e84fe57933724aab16582cf32e4e2285b328dae3fc33a',
                          'evidence-record.json': '81e30d49a246172641013565709e67e22e51480728456fa78eb339eee27fc2f7',
                          'evidence.tar': '3103387ad16efec06a20dab3d87b04f4a3dda3c9657eb553c4ccb024ee68d140',
                          'guest-summary.json': '922ed91290e81dfba98f0459896a82d9857178135a33f82eaa97e19180d03447',
                          'payload.tar': 'e2a4025ffc77a98496f4c4bb748aa84f9ede7ab78186e40439b7208b5f9296d9',
                          'run.log.unit-proof.json': '3918730d3cf6383c12821651b8808f34d55e13ea0ce7173cc6342e82cba59b73',
                          'vm/teardown.json': 'ac957d0c307e7ac32b66612c3692ea67866f918807f5cf1286b80801f831c5df'},
            'candidate': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
            'case_raw': {'uclamp-followup-setter-mock-deadline': '73e600f7dc30ec64732fbccb5f1002cccaa810d367b03e4b0bb4a4cda27349a0',
                         'uclamp-followup-setter-mock-rt': '36dbbc3932b9834d246617d3ccda50568c0b53e629e5da6e73ba0659af424e45',
                         'uclamp-followup-setter-owned-updates': 'cd72bf78382b3ea23f88fe4b6d0a4b73d1562d9eb53bc74100a5165f918bdf67',
                         'uclamp-followup-setter-policy': '7183ec759f8dd5a80e158b5dc0a80131954799bcba4d447e27d334784a253c86',
                         'uclamp-followup-setter-reset': '6b79c4fa8e6bbc385f27d1510ca112ebf64156419cb03fade606d754293a3001'},
            'uuid': 'cfef626e-e697-46df-9aac-c1962dc06410'}}
FREEZE = '78769c5e176404f8d4118860b913f31de57761697575ed3f9ed6da13c04c58b4'
ACCEPT = 'cef18e965b93f086a7863b72a70900e9094a34a5eae90acc45cb7adb75492d7a'
AUDIT = 'a9e63124f5fd64733c1de1a7e893b560bb9b05ffa299ec87e8e886c6c8ec2571'
CHECKER = '7b7531183e3ee8e5a26f79d48acfe733549fc026a62b3dad208ca337d5cd5838'
SEMANTICS = '98d1642d74756e2f1a0f968b0071d53bab58c45f245fee9a435bf567ec4719f5'
FORMAT = 'primary-qualified-uclamp-setter55-v1'
LIMITATIONS = ['r1 is bounded child-self readback for the tested one-sided and paired updates.',
 'r2 and r4 use source-owned numeric targets without separately retained birth or pidfd proof.',
 'r5 uses synthetic scheduler replies and request bytes for a passed numeric target, not actual privileged RT or '
 'deadline scheduling.',
 'r3 is separately evidenced and r6 retains historical evidence; preserve all prior observations and failures.']
INVENTORY = {'static':'1b4fb52b33bc58c8928fe1db60332f798da624115411c0ca71f7c8dbc326f460','dynamic':'e7be44069a15c1b2b1c3b0dd3ec23523f13e5f02913cf065781b22a543f97e86'}
CURRENT = {'static':'83bcbfa859b1115b45f7265920d02f82630d8bfd9663936580a953ef335d0498','dynamic':'b7f26c820243ab4a8424ee2c206d9655fb1fe55a0f09bc170ab6741a8e841de3'}
AUTHORIZED_RECEIPTS = frozenset({'f2da2f66e87cb824243d4123387af71196b27b6e057a634c6d8bd957fc08b0e9'})

def decode(data):
 def unique(pairs):
  out={}
  for k,v in pairs:
   require(k not in out,'duplicate JSON key');out[k]=v
  return out
 def reject(_):raise ValueError('nonfinite JSON number')
 return json.loads(data,object_pairs_hook=unique,parse_constant=reject)
def absolute(p):
 p=Path(p);require(p.is_absolute(),'path is not absolute');return p

def ordinary_preflight(root,path,build):
 manifest=decode(pinned(absolute(path),INVENTORY[build],'non-disk inventory'));require(manifest['schema']=='setter55-exact-nondisk-inventory-v2' and manifest['build']==build and set(manifest['excluded_disk_metadata'])=={'vm/seed.iso'},'inventory schema/disk allowlist');require(stat.S_ISDIR(root.lstat().st_mode),'result root is not a directory');actual_files=set();actual_dirs=set();disks=set()
 for current,dirs,files in os.walk(root,followlinks=False):
  parent=Path(current).relative_to(root)
  for name in dirs:
   rel=(parent/name).as_posix();p=Path(current)/name;st=p.lstat();require(stat.S_ISDIR(st.st_mode),'non-directory inventory node');actual_dirs.add(rel)
  for name in files:
   rel=(parent/name).as_posix();p=Path(current)/name;st=p.lstat();require(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'non-regular inventory node')
   if rel in manifest['excluded_disk_metadata']:
    expected=manifest['excluded_disk_metadata'][rel];require({'bytes':st.st_size,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'nlink':st.st_nlink}==expected,'disk metadata');disks.add(rel);continue
   require(p.suffix.lower() not in ('.qcow2','.img','.iso','.rawdisk','.vmdk','.vdi'),'unlisted disk image');actual_files.add(rel)
 require(actual_files==set(manifest['files']) and actual_dirs==set(manifest['dirs']) and disks==set(manifest['excluded_disk_metadata']),'result inventory membership')
 for name,mode in manifest['dirs'].items():require(stat.S_IMODE((root/name).lstat().st_mode)==mode,'ordinary directory mode: '+name)
 for name,entry in manifest['files'].items():
  require(not Path(name).is_absolute() and '..' not in Path(name).parts and str(Path(name))==name and name not in manifest['excluded_disk_metadata'],'invalid ordinary member');st=(root/name).lstat();require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==entry['bytes'] and stat.S_IMODE(st.st_mode)==entry['mode'],'ordinary member metadata: '+name)
 return manifest

def ordinary_hashes(root,manifest):
 for name,entry in manifest['files'].items():require(file_sha(root/name)==entry['sha256'],'ordinary member digest: '+name)

def inspect_pair(spec):
 """Inspect exact previously reviewed records; does not grant product authority."""
 require(spec['raw_audit_sha256']==AUDIT,'audit digest');audit=decode(pinned(absolute(spec['raw_audit_path']),AUDIT,'paired audit'));pinned(absolute(spec['raw_checker_path']),CHECKER,'strict checker');pinned(absolute(spec['raw_semantics_path']),SEMANTICS,'strict semantics');source=decode(pinned(absolute(spec['source_acceptance_path']),ACCEPT,'source acceptance'));pinned(absolute(spec['source_freeze_path']),FREEZE,'source freeze')
 require(source['schema']=='uclamp-setter55-primary-source-acceptance-v1' and source['decision']=='accept-source-and-bounded-vm-plan' and source['freeze_sha256']==FREEZE and source['product_coverage'] is False and source['root_fixtures_allowed'] is False,'source acceptance scope')
 require(audit['schema']=='setter55-strict-paired-raw-review-v1' and audit['source_acceptance_sha256']==ACCEPT and audit['subject_execution'] is False and set(audit['builds'])==set(RUNS) and set(spec['run_paths'])==set(RUNS) and set(spec['inventory_paths'])==set(RUNS) and RUNS['static']['uuid']!=RUNS['dynamic']['uuid'],'paired audit scope')
 roots={};manifests={}
 for build in RUNS:
  root=absolute(spec['run_paths'][build]);require(root.name==build+'-setter-complete','run path');roots[build]=root;manifests[build]=ordinary_preflight(root,spec['inventory_paths'][build],build)
 for build in RUNS:ordinary_hashes(roots[build],manifests[build])
 results={}
 for build,r in RUNS.items():
  root=roots[build];x=audit['builds'][build];require(x['state']=='completed' and x['vm_uuid']==r['uuid'] and x['candidate_sha256']==r['candidate'] and x['record_sha256']==r['artifacts']['evidence-record.json'] and x['selfchecks_pass']==13 and x['status_counts']=={'BOUNDED_PASS':5,'REACHED_FAIL':0,'INCOMPLETE':0} and x['artifact_hashes']==r['artifacts'] and set(x['case_results'])==set(IDS),'audit run')
  for n,h in r['artifacts'].items():require(file_sha(root/n)==h,'artifact '+n)
  rec=decode(pinned(root/'evidence-record.json',r['artifacts']['evidence-record.json'],'evidence record'));require(rec['vm_uuid']==r['uuid'] and rec['candidate_sha256']==r['candidate'] and rec['status']=='completed' and rec['qualification']=='framework-complete-device-adjudication-required' and rec['product_acceptance'] is False and rec['root_fixtures_allowed'] is False and rec['selected_case_ids']==IDS and rec['scope_proven'] is rec['guest_units_quiescent'] is rec['overlay_discarded'] is True and not (root/'overlay.qcow2').exists(),'record scope/lifecycle')
  require(file_sha(root/'candidate.snapshot')==r['candidate'],'candidate snapshot');summary=decode(pinned(root/'guest-summary.json',r['artifacts']['guest-summary.json'],'summary'));rows=summary['cases'];by={v['id']:v for v in rows};require(len(rows)==len(by)==18 and summary['binary_sha256']==r['candidate'] and summary['vm_uuid']==r['uuid'] and len([v for v in rows if v['group']=='selfcheck' and v['status']=='PASS'])==13,'summary identity/controls')
  with tarfile.open(root/'payload.tar','r:') as t:
   tar_members(t);require(sha(safe_member(t,'candidate'))==r['candidate'],'payload candidate');defs=decode(safe_member(t,'harness/suites/optional-frozen.json'))['cases'];require([c['id'] for c in defs]==IDS and all(canonical(c)==CASE_HASHES[c['id']] for c in defs),'payload definitions')
  with tarfile.open(root/'evidence.tar','r:') as t:
   tar_members(t);require(safe_member(t,'results/summary.json')==(root/'guest-summary.json').read_bytes(),'summary archive')
   for cid in IDS:
    a=x['case_results'][cid];blob=safe_member(t,'results/'+cid+'/candidate.json');raw=decode(blob);require(sha(blob)==r['case_raw'][cid]==a['raw_sha256'] and raw==a['raw_record'] and by[cid]==a['framework_row'] and by[cid]['status']==a['framework_status']=='PASS' and by[cid]['group']=='shell' and a['classification']=='BOUNDED_PASS' and a['controls_verified'] is True and a['candidate_reached'] is True and a['candidate_mismatches']==[] and raw['status']==0 and raw.get('error') is None and raw.get('harness_error') is None,'case raw attribution '+cid)
  results[build]={'root':root,'summary':by,'definitions':{c['id']:c for c in defs}}
 return results

def current(path,pin,build,root):
 r=RUNS[build];require(pin==CURRENT[build],'current proof pin');td=decode(pinned(absolute(root)/'vm/teardown.json',r['artifacts']['vm/teardown.json'],'saved teardown'));q=decode(pinned(absolute(path),pin,'current quiescence'));scope='parity-vm-'+r['uuid']+'.scope';need={'stdout':'ControlGroup=\nId='+scope+'\nLoadState=not-found\nActiveState=inactive\n','stderr':'','returncode':0};group='/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/'+scope
 expected=[('bashos-evaluation-'+r['uuid'][:8]+'.service','run.log.unit-proof.json'),('bashos-optional-'+r['uuid'][:8]+'-reference.service','compat/run.log.unit-proof.json')];proofs=q['strict_unit_proofs'];require(len(proofs)==2 and all(proofs[i]['unit']==n and proofs[i]['proof_sha256']==r['artifacts'][f] and proofs[i]['transport_returncode']==0 and proofs[i]['stop_returncode']==decode((absolute(root)/f).read_bytes())['stop']['returncode'] for i,(n,f) in enumerate(expected)),'current unit proofs')
 require(q['schema']=='primary-exact-owned-current-and-unit-review-v1' and q['vm_uuid']==r['uuid'] and q['record_sha256']==r['artifacts']['evidence-record.json'] and q['scope_raw']==need and q['wrapper_pid']==td['wrapper_pid'] and Path(q['result_path']).name==build+'-setter-complete' and Path(q['overlay']).name=='overlay.qcow2' and q['cgroup']==group and q['poweroff_request']==0 and q['strict_unit_helper_sha256']=='b926b5bf88055c763a4ed5f36d5df56681a34d3cf3c160c434d16999ab8b20c0' and q['exact_uuid_qemu_matches']==[] and q['product_coverage'] is False and q['cgroup_absent'] is q['wrapper_absent'] is q['overlay_absent'] is True,'current quiescence identity')

def load_qualified_uclamp_setter55(spec,expected_binary,expected_build):
 require(expected_build in RUNS and expected_binary==RUNS[expected_build]['candidate'] and spec.get('evidence_format')==FORMAT,'build/format');deny_noncore(spec,'setter selection');require(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==IDS and spec.get('receipt_run')==expected_build and spec.get('name')=='uclamp-setter55-'+expected_build and not spec.get('exclude_ids'),'selection')
 pin=spec.get('primary_receipt');require(isinstance(pin,dict) and set(pin)=={'path','sha256'} and pin['sha256'] in AUTHORIZED_RECEIPTS,'primary setter receipt not source authorized');r=decode(pinned(absolute(pin['path']),pin['sha256'],'primary receipt'));require(set(r)=={'schema','decision','ledger_scope','core_ledger_eligible','subject_execution_on_host','utc','primary_reviewer','source_acceptance_sha256','source_freeze_sha256','audit_sha256','checker_sha256','semantics_sha256','runs','limitations'} and r['schema']=='bashos-uclamp-setter55-primary-receipt-v1' and r['decision']=='accept-bounded-uclamp-setter55-case-evidence' and r['ledger_scope']=='core' and r['core_ledger_eligible'] is True and r['subject_execution_on_host'] is False and isinstance(r['utc'],str) and r['utc'] and isinstance(r['primary_reviewer'],str) and r['primary_reviewer'] and r['source_acceptance_sha256']==ACCEPT and r['source_freeze_sha256']==FREEZE and r['audit_sha256']==AUDIT and r['checker_sha256']==CHECKER and r['semantics_sha256']==SEMANTICS and r['limitations']==LIMITATIONS and set(r['runs'])==set(RUNS),'receipt scope')
 data=inspect_pair(spec)
 for b,v in RUNS.items():
  x=r['runs'][b];require(set(x)=={'uuid','candidate','artifacts','case_raw','current_proof_sha256'} and {k:x[k] for k in ('uuid','candidate','artifacts','case_raw')}==v,'receipt run binding');current(spec['quiescence_paths'][b],x['current_proof_sha256'],b,spec['run_paths'][b])
 root=absolute(spec['path']);core=absolute(spec['core_binary_path']);approved=Path.home()/'projects/bash-os/out'/('bash-static' if expected_build=='static' else 'bash');require(root.resolve()==data[expected_build]['root'].resolve() and core==approved and core.resolve(strict=True)==approved,'selected result/core path');core_stat=core.lstat();require(stat.S_ISREG(core_stat.st_mode) and core_stat.st_nlink==1,'main core is not an ordinary file');require(file_sha(core)==expected_binary,'selected core digest');d=data[expected_build];selected=[{'record':d['summary'][cid],'definition':d['definitions'][cid],'sources':{},'run':spec['name']} for cid in IDS]
 return selected,{'name':spec['name'],'groups':['shell'],'selected_records':5,'evidence_format':FORMAT,'primary_receipt_sha256':pin['sha256'],'candidate_sha256':expected_binary,'vm_uuid':RUNS[expected_build]['uuid'],'limitations':LIMITATIONS}
