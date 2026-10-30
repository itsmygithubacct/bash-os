#!/usr/bin/env python3
"""Calendar45 core evidence adapter for the exact primary-issued receipt."""
import stat,tarfile
from pathlib import Path,PurePosixPath
from primary_controller_evidence import canonical,deny_noncore,file_sha,pinned,require,safe_member,sha,tar_members,unit_proof
from primary_calendar_evidence import _inventory,decode_json,CORES,IMAGE_SHA,MANIFEST_SHA

FORMAT='primary-qualified-calendar45-v1'
# Only the exact primary-issued receipt digest is authorized.
AUTHORIZED_RECEIPTS=frozenset({'5cb2884f09e77582e17618ebfd5aa2efac67b0ce4d675f14d5c4a137182cd3df'})
SOURCE_ACCEPT='e13f5fd6561f6d2937e232d4e443ada29c5cf0a833860f36951dd7797074662b'
FREEZE='ef468a0d013a2909b8f2b58bf3266c224aa75cf3d78325b5b41d7bf2966447f6'
STAGED='b8bc8f4a75e84b553b445c50a54b26df53df9c2da4fade97be08ce0f0fcb466f'
INDEX='106e4aa6de528d3f44e26b2fb2e25754076b1b2ab33d3a72f943d68c0b655095'
IMAGE_RECEIPT='b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6'
CHECKER='2e910941fcb1f1c622a1723c7949518bd3d760f62370bf59bda8ccdd6fd0124f'
AUDIT='bee425fcfbe8bd2c13c391f19952fe272efb31e03404ceae549b9118eb1ad9af'
CURRENT='62d3cf066024b6bfe4fcc311286dd45660aeadc80791c0bbdea54c27fc3ddbb5'
INVENTORY='2aa8ee00200c3ed4dbe385b4cd5fa5c094077559ea68ec4359a20cacf00d6281'
IDS=['devices-hwclock-adj-valid-local-r2','devices-hwclock-adj-valid-local-space-r2','devices-hwclock-adj-missing-default-utc-r2','devices-hwclock-adj-missing-default-drift-r2']
CASES={'devices-hwclock-adj-valid-local-r2':'cf50ad19f03de618981e3d4e3523eecdba75ce5835b2c81013488d94568610ec','devices-hwclock-adj-valid-local-space-r2':'addc18c1221f1246a4fb5d77084ca7c862c2fd11fa4b07045db1422bee339df6','devices-hwclock-adj-missing-default-utc-r2':'ebd359a639d46cadf87fab2b201b8190fd90846209a6b1029adc83eef3e21428','devices-hwclock-adj-missing-default-drift-r2':'262f9141c1019244dbfa97eda8acb4dfb5a36be076e8a8f566fbdd48ddabd036'}
RUNS={'static':{'record':'5c241df2aec703c1470b0a1cdc335393197d3732d6e9d9187f0ad0e8743419f2','uuid':'095ccfd0-a41b-42c3-9428-4ff24305ea68'},'dynamic':{'record':'66537a47415daa81477c611263122be223150fb4245e5d0377c9013a7da6e913','uuid':'21ee982b-1b01-4bc7-8244-d9ef1594294a'}}
LIMITS=['RTC and clock calls use synthetic responses; no physical RTC or real clock effect is established.','Whitespace LOCAL remains a reached candidate failure on both builds.','Missing-file UTC selection and post-systohc serialized zero drift are observed; the no-drift default is inferred from pinned source, and post-write remainder does not establish its pre-action value.','Root fixtures remain held; preserve prior evidence and failures.']
def obj(path,digest,label):return decode_json(pinned(path,digest,label))
def checked_sources(spec):
 accept=obj(spec['source_acceptance_path'],SOURCE_ACCEPT,'calendar45 source acceptance');require(accept['schema']=='primary-calendar-followup45-source-acceptance-v1' and accept['decision']=='accept-source-and-bounded-vm-plan' and accept['root_fixtures_allowed'] is False and accept['product_coverage'] is False and accept['freeze_sha256']==FREEZE and accept['staged_source_manifest_sha256']==STAGED and accept['index_sha256']==INDEX and accept['image_acceptance_sha256']==IMAGE_RECEIPT,'source acceptance scope')
 freeze=obj(spec['freeze_path'],FREEZE,'source freeze');source=Path(spec['freeze_path']).parent;external=spec['external_sources'];required={n for n,e in freeze['files'].items() if 'path' in e};require(set(external)==required and freeze['schema']=='calendar-followup-45-source-freeze-v1','source membership')
 for name,e in freeze['files'].items():
  n=PurePosixPath(name);require(not n.is_absolute() and len(n.parts)==1 and str(n)==name,'source name');p=Path(external[name]) if name in required else source/name;require(p.is_absolute(),'source path');st=p.lstat();require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==e['bytes'] and file_sha(p)==e['sha256'],'source mismatch '+name)
 index=obj(source/'device-index.json',INDEX,'case index');require(index['batches']=={'adjtime-gap':IDS} and index['cases']==CASES,'index selection')
 image=obj(spec['image_receipt_path'],IMAGE_RECEIPT,'image receipt');require(image['schema']=='bashos-device-kernel-image-acceptance-v1' and image['decision']=='accept-image-qualification' and image['product_coverage'] is False and image['prepared_sha256']==IMAGE_SHA and image['prepared_manifest_sha256']==MANIFEST_SHA,'image receipt scope')
 manifest=obj(spec['staged_manifest_path'],STAGED,'staged manifest')['entries'];root=Path(spec['control_root']);require(root.is_absolute() and root.is_dir() and not root.is_symlink() and {p.relative_to(root).as_posix() for p in root.rglob('*')}==set(manifest),'control tree membership')
 for name,e in manifest.items():
  n=PurePosixPath(name);require(not n.is_absolute() and '..' not in n.parts and str(n)==name,'control path');q=root/name;st=q.lstat();require(stat.S_IMODE(st.st_mode)==e['mode'],'control mode')
  if e['type']=='directory':require(stat.S_ISDIR(st.st_mode),'control dir')
  else:require(e['type']=='file' and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==e['size'] and file_sha(q)==e['sha256'],'control file '+name)
 pinned(spec['checker_path'],CHECKER,'independent checker')
 return manifest

def validate_receipt(receipt,spec):
 require(set(receipt)=={'schema','decision','ledger_scope','core_ledger_eligible','utc','primary_reviewer','source_acceptance_sha256','checker_sha256','audit_sha256','current_quiescence_sha256','result_inventory_sha256','runs','limitations'} and receipt['schema']=='calendar45-primary-receipt-v1' and receipt['decision']=='accept-calendar45-bounded-core-observations' and receipt['ledger_scope']=='core' and receipt['core_ledger_eligible'] is True and isinstance(receipt['utc'],str) and bool(receipt['utc']) and isinstance(receipt['primary_reviewer'],str) and bool(receipt['primary_reviewer']) and receipt['limitations']==LIMITS,'receipt scope')
 require((receipt['source_acceptance_sha256'],receipt['checker_sha256'],receipt['audit_sha256'],receipt['current_quiescence_sha256'],receipt['result_inventory_sha256'])==(SOURCE_ACCEPT,CHECKER,AUDIT,CURRENT,INVENTORY),'receipt pins')
 control=checked_sources(spec);inventory=obj(spec['result_inventory_path'],INVENTORY,'result inventory');audit=obj(spec['audit_path'],AUDIT,'paired audit');current=obj(spec['current_quiescence_path'],CURRENT,'current quiescence')
 require(inventory['schema']=='calendar45-result-inventory-v1' and set(inventory['runs'])==set(RUNS) and audit['schema']=='calendar45-strict-paired-raw-review-v1' and audit['source_acceptance_sha256']==SOURCE_ACCEPT and audit['subject_execution'] is False and set(audit['builds'])==set(RUNS) and current['schema']=='primary-calendar45-current-quiescence-v1' and set(current['builds'])==set(RUNS) and set(receipt['runs'])==set(RUNS),'paired scope')
 results={}
 for build,info in RUNS.items():
  root=Path(spec['results'][build]);require(root.is_absolute(),'result path');_inventory(root,inventory['runs'][build]);r=obj(root/'evidence-record.json',info['record'],'run record');v=audit['builds'][build];q=current['builds'][build];u=info['uuid'];scope='parity-vm-'+u+'.scope';scope_text='ControlGroup=\nId='+scope+'\nLoadState=not-found\nActiveState=inactive\n'
  require(q['vm_uuid']==u and q['evidence_record_sha256']==info['record'] and q['scope']=={'ControlGroup':'','Id':scope,'LoadState':'not-found','ActiveState':'inactive'} and q['scope_raw']=={'returncode':0,'stdout':scope_text,'stderr':''} and q['cgroup_absent'] is True and q['wrapper_absent'] is True and q['overlay_absent'] is True and q['exact_vm_process_matches']==[] and type(q['wrapper_pid']) is int and q['wrapper_pid']>1,'current scope')
  require(v['state']=='completed' and v['record_sha256']==info['record'] and v['vm_uuid']==u and v['candidate_sha256']==CORES[build] and v['status_counts']=={'BOUNDED_PASS':3,'REACHED_FAIL':1,'INCOMPLETE':0} and set(v['case_results'])==set(IDS),'raw audit')
  require(r['status']=='completed' and r['qualification']=='framework-complete-device-adjudication-required' and r['product_acceptance'] is False and r['root_fixtures_allowed'] is False and r['candidate_sha256']==CORES[build] and r['selected_case_ids']==IDS and r['vm_uuid']==u and r['guest_status']==1 and r['image_sha256']==IMAGE_SHA and r['manifest_sha256']==MANIFEST_SHA and r['index_sha256']==INDEX and r['consumer_sha256']=='2ea16b34264a0c338f9b5fe5ae05fe43388fa5e9afd9406c5edfecdacc95ed6f' and r['device_schema_sha256']=='42f0270961904ee705ce393c050eb6be1fb1b3779ea455b053a572cb34e3639f' and r['image_acceptance_sha256']==IMAGE_RECEIPT,'run scope')
  flags=('scope_proven','guest_units_quiescent','overlay_discarded','candidate_unchanged','candidate_snapshot_unchanged','image_unchanged','manifest_unchanged','inventory_unchanged','consumer_unchanged','classifier_unchanged','staging_source_unchanged','staging_evidence_unchanged','vm_source_unchanged','payload_unchanged','index_unchanged','schema_unchanged','acceptance_unchanged','variant_unchanged','suites_unchanged','helpers_unchanged','compat_source_unchanged','namespace_source_unchanged','evaluation_source_unchanged','selfcheck_sources_unchanged','evidence_unchanged','compat_evidence_unchanged');require(all(r.get(k) is True for k in flags),'run integrity')
  require(file_sha(root/'candidate.snapshot')==CORES[build] and file_sha(root/'payload.tar')==r['payload_sha256'] and file_sha(root/'evidence.tar')==r['evidence_validation']['archive_sha256'] and file_sha(root/'guest-summary.json')==r['guest_summary_sha256'],'run artifacts')
  unit_proof(root/'run.log.unit-proof.json',r['guest_unit_proofs']['run.log.unit-proof.json'],u,'bashos-evaluation-'+u[:8]+'.service',1);unit_proof(root/'compat/run.log.unit-proof.json',r['compatibility']['proof_hashes']['run.log.unit-proof.json'],u,'bashos-optional-'+u[:8]+'-reference.service',0)
  require(receipt['runs'][build]=={'vm_uuid':u,'record_sha256':info['record'],'candidate_sha256':CORES[build],'status_counts':v['status_counts']},'receipt run binding')
  with tarfile.open(root/'payload.tar') as t:
   members=tar_members(t);defs=decode_json(safe_member(t,'harness/suites/optional-frozen.json'))['cases'];require(sha(safe_member(t,'harness/suites/optional-frozen.json'))==r['fixture_sha256'] and [c['id'] for c in defs]==IDS and all(canonical(c)==CASES[c['id']] for c in defs) and sha(safe_member(t,'candidate'))==CORES[build],'payload cases')
   for m in members:
    if m.isdir() or m.name in ('candidate','harness/suites/optional-frozen.json'):continue
    require(m.name.startswith(('harness/','loadable-parity/')),'payload path');name=('tests/parity-vm/'+m.name[len('harness/'):] if m.name.startswith('harness/') else 'tests/'+m.name);require(name in control and control[name]['type']=='file' and sha(safe_member(t,m.name))==control[name]['sha256'],'payload source')
  summary=decode_json((root/'guest-summary.json').read_bytes());rows={x['id']:x for x in summary['cases']};require(len(rows)==len(summary['cases']) and summary['vm_uuid']==u and summary['binary_sha256']==CORES[build],'summary identity')
  with tarfile.open(root/'evidence.tar') as t:
   tar_members(t);require(safe_member(t,'results/summary.json')==(root/'guest-summary.json').read_bytes(),'summary archive');selected=[]
   for c in defs:
    cid=c['id'];raw=safe_member(t,'results/'+cid+'/candidate.json');obs=v['case_results'][cid];row=rows[cid];expected='REACHED_FAIL' if cid==IDS[1] else 'BOUNDED_PASS';status='FAIL' if cid==IDS[1] else 'PASS'
    require(obs['classification']==expected and obs['raw_sha256']==sha(raw) and obs['framework_status']==row['status']==status and obs['controls_verified'] is True and row['group']=='shell','case observation '+cid);selected.append({'record':row,'definition':c,'sources':{},'run':spec['names'][build]})
  results[build]=(selected,{'name':spec['names'][build],'groups':['shell'],'selected_records':4,'evidence_format':FORMAT,'candidate_sha256':CORES[build],'vm_uuid':u,'record_sha256':info['record'],'limitations':LIMITS})
 return results

def load_qualified_calendar45(spec,expected_binary,expected_build):
 require(expected_build in RUNS and expected_binary==CORES[expected_build] and isinstance(spec,dict) and spec.get('evidence_format')==FORMAT and spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==IDS and spec.get('names')=={'static':'calendar45-static','dynamic':'calendar45-dynamic'} and set(spec.get('results',{}))==set(RUNS) and not spec.get('exclude_ids'),'selection')
 deny_noncore(spec,'calendar45 selection');pin=spec.get('primary_receipt');require(isinstance(pin,dict) and set(pin)=={'path','sha256'} and pin['sha256'] in AUTHORIZED_RECEIPTS,'calendar45 receipt not authorized in source')
 receipt=obj(pin['path'],pin['sha256'],'calendar45 primary receipt');results=validate_receipt(receipt,spec);core=Path(spec['core_binary_path']);require(core.is_absolute() and file_sha(core)==expected_binary,'core binary');selected,metadata=results[expected_build];metadata['primary_receipt_sha256']=pin['sha256'];return selected,metadata
