#!/usr/bin/env python3
"""Receipt-gated, exact paired setter45 r3 saved-data evidence; no execution."""
import datetime,hashlib,json,math,os,re,stat
from pathlib import Path,PurePosixPath
import setter45_saved_logic as logic
from setter45_inventory import ORDINARY_FILES, EXCLUDED_DISK
from primary_controller_evidence import CHECKS,deny_noncore
AUTHORIZED_RECEIPTS=frozenset({'d41a5fd2f88d164c0ee73295908f946144fb8a009d5fcba2dd096d2d4f5df53a'})
FORMAT='primary-qualified-uclamp-setter45-r3-v1'
SOURCE='2aa3af9a0b81cd244f6b08df3cf738a2e4968e907403cab38b232b7b857f7608'
FREEZE='f2d521b0c7b7e78be5662581d78f722ac7754efb7e35040a79d36e0ba0a51a97'
INDEX='5e0c25a9db4be0a3ef1629af2bd7574d2ae5ff1cba0a906599c2d0d946b9b9d8'
MANIFEST='cad0f523c86ca5eb43699d93ba0eff244990eda01654bc81f891b6657b9b0871'
AUDIT='83d982f94680f5767d1d17febcc991f772e0ff3b25677fa02b50c4fed19da745'
CHECKER='0138a0116a18e3caa27b14b6408b5fe731d86449aea646d4e5e357977c7b3b5e'
IMAGE='b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6'
CASE='uclamp-followup-setter-fork-direct-r2';CASE_SHA='221c51d5d65fdba71c0878d20e115e4b670d1cd5925f90c1ce4a913656877d3b'
RUNS={'static':('b4b866a4-4013-4970-9cae-f3dff95256d7','a2da5864919002481ca9e212dfb022c39d776cbb8181084b4151924dfe0d7cef','425d0449caaa103e327a1090a7af9c445545e0f5910b07cc308ccff168f6c3c6'),'dynamic':('be0434e8-a415-46eb-bf01-8b41b062f0bf','c8f73ab30ca0e6a869a6aa8152e983459f38524ca75ec5b91359fdb8a758a93a','5d25b7e2ac154db78c24b104b6c403529906f0683e5871b7c9a9edc06e20f689')}
LIMITS=['Only setter reset-on-fork r3; remaining setter requirements require separate evidence.','Child wait status and post-fork parent liveness are not separately saved.','Preserve earlier incomplete setter observations and any prior reached failures.','This fixed paired PASS reader does not classify incomplete future runs.','Historical audit contains seed ISO hashes; current reader never opens or hashes ISO disk bytes.']
def need(x,message):
 if not x:raise ValueError(message)
def strict(data):
 def obj(pairs):
  out={}
  for k,v in pairs:
   need(k not in out,'duplicate JSON key');out[k]=v
  return out
 def finite(x):
  y=float(x);need(math.isfinite(y),'nonfinite JSON');return y
 return json.loads(data,object_pairs_hook=obj,parse_float=finite,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def hashfile(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def under(root,name):
 need(type(name) is str and name and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts and str(PurePosixPath(name))==name,'unsafe relative path');p=(root/name).resolve(strict=True);need(p.is_relative_to(root),'path escapes root');return p
def pin(p,h):
 need(p.is_file() and not p.is_symlink(),'pinned file invalid');b=p.read_bytes();need(hashlib.sha256(b).hexdigest()==h,'pinned file mismatch');return strict(b)
def inventory(root,manifest):
 entries=manifest['entries'];actual={p.relative_to(root).as_posix() for p in root.rglob('*')};need(actual==set(entries),'staged source membership differs')
 for name,e in entries.items():
  p=root/name;st=p.lstat();need(stat.S_IMODE(st.st_mode)==e['mode'],'source mode differs')
  if e['type']=='directory':need(stat.S_ISDIR(st.st_mode),'source directory differs')
  elif e['type']=='file':need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==e['size'] and hashfile(p)==e['sha256'],'source file differs')
  else:raise ValueError('source type differs')
def verify_membership(path,build,audit):
 ordinary=ORDINARY_FILES[build];need(type(ordinary) is list and len(ordinary)==len(set(ordinary)) and EXCLUDED_DISK not in ordinary,'invalid fixed inventory');need(set(audit['artifact_hashes'])==set(ordinary)|{EXCLUDED_DISK},'historical audit inventory differs');expected_dirs={str(parent) for name in ordinary+[EXCLUDED_DISK] for parent in PurePosixPath(name).parents if str(parent)!='.'};found_files=set();found_dirs=set()
 def walk(directory,prefix=''):
  with os.scandir(directory) as entries:
   for entry in entries:
    name=prefix+entry.name;info=entry.stat(follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
     need(name in expected_dirs,'unexpected result directory '+name);found_dirs.add(name);walk(entry.path,name+'/')
    elif stat.S_ISREG(info.st_mode):
     need(info.st_nlink==1 and name in set(ordinary)|{EXCLUDED_DISK},'unexpected result file '+name);found_files.add(name)
    else:raise ValueError('unexpected result member '+name)
 walk(path);need(found_dirs==expected_dirs and found_files==set(ordinary)|{EXCLUDED_DISK},'result membership differs')
def compare_nondisk(result,audit):
 expected=dict(audit);hashes=dict(expected['artifact_hashes']);need(EXCLUDED_DISK in hashes,'audit disk absent');del hashes[EXCLUDED_DISK];expected['artifact_hashes']=hashes;need(result==expected,'actual non-disk result differs from pinned paired audit')
def verify_disk_provenance(path,build,audit):
 vm=pin(path/'vm/vm.json',audit['artifact_hashes']['vm/vm.json']);td=pin(path/'vm/teardown.json',audit['artifact_hashes']['vm/teardown.json']);token=RUNS[build][0];need(vm['uuid']==td['vm_uuid']==token,'disk ownership VM differs');argv=vm['argv'];drives=[argv[i+1] for i,x in enumerate(argv[:-1]) if x=='-drive'];suffix='primary-uclamp-setter45-001/results/'+build+'-setter-fork/';seed=[d for d in drives if d.startswith('file=') and d.endswith('/'+suffix+'vm/seed.iso,format=raw,media=cdrom,readonly=on')];overlay=[d for d in drives if d.startswith('file=') and d.endswith('/'+suffix+'overlay.qcow2,format=qcow2,if=virtio,cache=writeback')];need(len(drives)==2 and len(seed)==len(overlay)==1 and td['disk'].endswith('/'+suffix+'overlay.qcow2'),'owned disk metadata differs')
def load_qualified_setter45(spec,expected_binary,expected_build):
 need(type(spec) is dict and expected_build in RUNS and expected_binary==logic.CORES[expected_build] and spec.get('evidence_format')==FORMAT,'format/build differs');deny_noncore(spec,'setter45 selection');need(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==[CASE] and not spec.get('exclude_ids'),'selection differs')
 rp=spec.get('primary_receipt');need(type(rp) is dict and set(rp)=={'path','sha256'} and rp['sha256'] in AUTHORIZED_RECEIPTS,'receipt not source-authorized');receipt_path=Path(rp['path']);need(receipt_path.is_absolute(),'receipt path not absolute');receipt=pin(receipt_path,rp['sha256']);deny_noncore(receipt,'setter45 receipt')
 fields={'schema','decision','ledger_scope','core_ledger_eligible','subject_execution_on_host','primary_reviewer','utc','source_acceptance_sha256','source_freeze_sha256','case_index_sha256','staged_manifest_sha256','image_receipt_sha256','checker_sha256','paired_audit_sha256','case_sha256','limitations','runs'};need(set(receipt)==fields and receipt['schema']=='bashos-setter45-r3-primary-receipt-v1' and receipt['decision']=='accept-reviewed-core-case-evidence' and receipt['ledger_scope']=='core' and receipt['core_ledger_eligible'] is True and receipt['subject_execution_on_host'] is False and type(receipt['primary_reviewer']) is str and bool(receipt['primary_reviewer'].strip()) and receipt['source_acceptance_sha256']==SOURCE and receipt['source_freeze_sha256']==FREEZE and receipt['case_index_sha256']==INDEX and receipt['staged_manifest_sha256']==MANIFEST and receipt['image_receipt_sha256']==IMAGE and receipt['checker_sha256']==CHECKER and receipt['paired_audit_sha256']==AUDIT and receipt['case_sha256']==CASE_SHA and receipt['limitations']==LIMITS,'receipt scope differs');need(type(receipt['utc']) is str and receipt['utc'].endswith('Z'),'invalid UTC');datetime.datetime.fromisoformat(receipt['utc'][:-1]+'+00:00')
 need(set(receipt['runs'])==set(RUNS),'paired builds absent')
 for build,(vm,record,raw) in RUNS.items():
  r=receipt['runs'][build];need(set(r)=={'name','vm_uuid','record_sha256','candidate_sha256','raw_sha256','current_scope_raw','wrapper_absent','cgroup_absent','overlay_absent'} and r['name']=='uclamp-setter45-'+build+'-setter-fork' and r['vm_uuid']==vm and r['record_sha256']==record and r['raw_sha256']==raw and r['candidate_sha256']==logic.CORES[build] and r['current_scope_raw']=='ControlGroup=\nId=parity-vm-'+vm+'.scope\nLoadState=not-found\nActiveState=inactive\n' and r['wrapper_absent'] is r['cgroup_absent'] is r['overlay_absent'] is True,'receipt run differs')
 cfg=spec['artifacts'];need(type(cfg) is dict and set(cfg)=={'root','run_root','packet','source_acceptance','image_receipt','paired_audit','primary_checker'},'artifact configuration differs');root=Path(cfg['root']);need(root.is_absolute(),'root not absolute');root=root.resolve(strict=True);runroot=under(root,cfg['run_root']);packet=under(root,cfg['packet']);need(runroot.is_dir() and packet.is_dir(),'source roots missing')
 accepted=pin(under(root,cfg['source_acceptance']),SOURCE);need(accepted['schema']=='uclamp-setter45-primary-source-acceptance-v1' and accepted['decision']=='accept-source-and-bounded-vm-plan' and accepted['product_coverage'] is False and accepted['root_fixtures_allowed'] is False and accepted['freeze_sha256']==FREEZE and accepted['index_sha256']==INDEX and accepted['staged_manifest_sha256']==MANIFEST,'source acceptance differs')
 image_path=under(root,cfg['image_receipt']);need(image_path==under(root,'primary-kernel-route12-001/primary-image-acceptance.json'),'image path differs');image=pin(image_path,IMAGE);need(image['decision']=='accept-image-qualification' and image['product_coverage'] is False,'image receipt differs');audit=pin(under(root,cfg['paired_audit']),AUDIT);checker=under(root,cfg['primary_checker']);need(hashfile(checker)==CHECKER,'primary checker differs')
 freeze=pin(packet/'freeze-inventory.json',FREEZE);idx=pin(packet/'device-index.json',INDEX);manifest=pin(runroot/'staged-source-manifest.json',MANIFEST);inventory(runroot/'control',manifest)
 for name,item in freeze['files'].items():
  if 'path' in item:
   original=item['path'];marker='/resume-20261029/';need(marker in original,'frozen external path differs');p=under(root,original.split(marker,1)[1])
  else:p=under(packet,name)
  need(p.stat().st_size==item['bytes'] and hashfile(p)==item['sha256'],'frozen source differs')
 suite=under(packet,'uclamp-fork-direct-r2.json');cases=strict(suite.read_bytes())['cases'];need(len(cases)==1 and cases[0]['id']==CASE and idx['cases'][CASE]==CASE_SHA and idx['batches']['setter-fork']==[CASE] and logic.sha(json.dumps(cases[0],sort_keys=True,separators=(',',':')).encode())==CASE_SHA,'case pin differs')
 need(audit['schema']=='primary-setter45-saved-raw-review-v1' and set(audit['builds'])==set(RUNS),'paired audit scope differs');logic.C=root;logic.R=runroot;logic.PACK=packet
 for build,(vm,record,raw) in RUNS.items():
  a=audit['builds'][build];need(a['state']=='completed' and a['vm_uuid']==vm and a['record_sha256']==record and a['case_results'][CASE]['raw_sha256']==raw and a['case_results'][CASE]['classification']=='BOUNDED_PASS' and a['status_counts']=={'BOUNDED_PASS':1,'REACHED_FAIL':0,'INCOMPLETE':0},'paired audit run differs')
 run=receipt['runs'][expected_build];path=under(runroot,'results/'+expected_build+'-setter-fork');need(Path(spec['path']).resolve(strict=True)==path and spec.get('name')==run['name'],'run path/name differs')
 # Inspect membership and types of both result trees before opening any result file.
 paths={build:under(runroot,'results/'+build+'-setter-fork') for build in RUNS}
 for build in RUNS:verify_membership(paths[build],build,audit['builds'][build])
 for build in RUNS:verify_disk_provenance(paths[build],build,audit['builds'][build])
 logic.SAFE_FILES=ORDINARY_FILES
 for build in RUNS:
  result=logic.inspect(build,cases,idx,freeze);compare_nondisk(result,audit['builds'][build])
 summary=pin(path/'guest-summary.json',audit['builds'][expected_build]['guest_summary_sha256']);rows=summary['cases'];controls=[x for x in rows if x.get('group')=='selfcheck'];need(len(controls)==13 and {x['id'] for x in controls}=={'selfcheck-'+x for x in CHECKS} and all(x['status']=='PASS' for x in controls),'exact selfchecks differ');selected=[x for x in rows if x['id']==CASE];need(len(selected)==1 and selected[0]['status']=='PASS','selected case differs')
 return [{'record':selected[0],'definition':cases[0],'sources':{},'run':spec['name']}],{'name':spec['name'],'groups':['shell'],'selected_records':1,'evidence_format':FORMAT,'primary_receipt_sha256':rp['sha256'],'candidate_sha256':expected_binary,'vm_uuid':run['vm_uuid'],'poweroff_request':0,'limitations':LIMITS}
