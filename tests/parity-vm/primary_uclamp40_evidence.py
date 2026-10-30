#!/usr/bin/env python3
"""Receipt-gated UCLAMP follow-up reader; saved data only.

The pinned primary receipt binds six independently reviewed runs.
"""
import base64, datetime, hashlib, json, math, re, stat, tarfile, types
from pathlib import Path, PurePosixPath
from primary_controller_evidence import CHECKS, canonical, deny_noncore, file_sha, pinned, require, safe_member, sha, tar_members, unit_proof

FORMAT='primary-qualified-uclamp-followup40-v1'
AUTHORIZED_RECEIPTS=frozenset({'9a7e906fd31fcb655201de6f93f6c64e7ff2bf817a329df19c65c402beedb7a9'})
LIMITATIONS=['No setter case is included; earlier incomplete setter observations remain retained.','A 255 poweroff request is accepted only for the exact primary-disposition static all-task run, remains 255 and has an unobserved SSH failure cause.','Synthetic scheduler replies do not establish privileged policy behavior.','Prior candidate failures and incomplete observations remain retained.']
SOURCE_ACCEPT='908106ca53335fe14696b1229e8ceb23fc2e410c0b4c77b9b6df86f3869b947b'
SOURCE_FREEZE='ca1bab7dac4b8bcbdaa7a50caaf73ab0e8bcd0ffe6d6011cde8bf3e40bf7ec89'
CASE_INDEX='0f370375743f1c63b3afe18e404216705baa1d481a6df7b409ac9c56a14ffccb'
IMAGE_ACCEPT='b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6'
FULL_AUDIT='379ae7af57d982053f88b991f8427a691310e642092ea1fdfbd246b1eadb606a'
PARTIAL_AUDIT='ae49bf2bb93f5fac2bf5914a17df9fe7cc170f304cdd5fbdbff959d84f63613c'
CHECKER='374816d1fd472bbffa5731d47db62cde04b83f10981f66b54eb90d55b818e2fd'
SEMANTICS='d3fb1b566d256eb311afcb65d989120df24065ad921037cad171917684032c8d'
LIFECYCLE='1829936881eb97ac9670352f3ca984bc5b4a75e5444a1edc480f2252680f7f6c'
STATIC_UUID='2e036dbb-6a78-4848-a5c1-abdd2d262b76'
CORES={'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab','dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
CASES={
 'dispatch':{'uclamp-followup-command-dispatch':'9fd1363515b6695b21279f1e9f1b3ddb26fc8d37b04d9aea407fa0a63e4debb2'},
 'query':{'uclamp-followup-query-self':'0cf1251d2688e184604005403ca32458628eacfe1063c3eaa5a5522a14cdbb03','uclamp-followup-query-p0':'987bdfdaf150b2a9663803a5cc10807852e74a4e14be3b0155e1d4c54a2ec6ee','uclamp-followup-query-empty':'82e49db8d5305f567201f4c0b8f00ec75124e3f0dbc8e3c2fec9ed4281f25268','uclamp-followup-query-threads':'0d650e01759d84d3ec67c5053aac4a2530c707f50a820cad5107d8fcc3737249'},
 'alltasks':{'uclamp-followup-alltasks-success':'04ff1bc174ced0d5fdd22df660e3c2c1a4d0778dfbbc88967990b64ac057e4aa','uclamp-followup-alltasks-validation':'20df6aba7d9dfab7173a8a9b2a2d404c80a680a724d84d565e7bfc328098fb72','uclamp-followup-alltasks-readfail':'acffa74e04b72751ad19ff92a5c5b8689bd58a017c79363dbfc3141ab4236ba7'}}
STATIC_ARTIFACTS={'evidence-record.json':'b0deeac18e24988774f78962e94f9978c4a640e844315ee6ad90a3e8cec95bd9','vm/vm.json':'4547ecc209e76c23e6ad1956ddac63bde7e42e296688e1dd09f66aa2cc8eb802','vm/console.log':'14aff240b26761134f978b1aa3af64d1fb9a3e02d67c18d83600ca47bc8cb012','vm/console-limits.json':'50e39b17dcf3790337cb054a827be099d23cac35d5a819be384e787dfd769dc7','vm/teardown.json':'a1bbab77db740f5a4745591b400698ec8989b8c85e3e92720da3113b2c2f488e','run.log.unit-proof.json':'629b03366594a07afb01e684ed867c1ce9b0ab34d68104841578123c7d26dd55','compat/run.log.unit-proof.json':'1588d71e96f2552d7f33406e7253f8ae4c1b94feb5152e88dcb73a6cdebb7c56'}
INSTALL={'tests/parity-vm/suites/migration-uclamp-followup-r1.json':'packet/migration-uclamp-followup-r1.json','tests/parity-vm/helpers/uclamp-query-followup.py':'packet/query-observer.py','tests/parity-vm/helpers/uclamp-setter-followup.py':'packet/setter-observer.py','tests/parity-vm/helpers/uclamp-alltasks-followup.py':'packet/alltasks-observer.py','tests/parity-vm/helpers/uclamp-target-errno-sequence.py':'packet/target-errno-sequence.py','tests/parity-vm/helpers/uclamp-scheduler-mock.py':'packet/scheduler-mock-observer.py','tests/parity-vm/helpers/uclamp-owned-task.py':'packet/owned-task.py','tests/parity-vm/helpers/devices-uclamp-observer-r1.py':'inputs/devices-uclamp-observer-r1.py'}

def strict_json(data):
 def unique(pairs):
  out={}
  for k,v in pairs:
   if k in out:raise ValueError('duplicate JSON key')
   out[k]=v
  return out
 def const(_):raise ValueError('nonfinite JSON number')
 def finite(x):
  value=float(x);require(math.isfinite(value),'nonfinite JSON number');return value
 return json.loads(data,object_pairs_hook=unique,parse_constant=const,parse_float=finite)

def case_semantics():
 """Load exact reviewed case logic with strict diagnostic JSON decoding."""
 path=Path(__file__).resolve().with_name('uclamp40_case_semantics.py');data=pinned(path,SEMANTICS,'reviewed case semantics');module=types.ModuleType('uclamp40_case_semantics');exec(compile(data,str(path),'exec'),module.__dict__);module.json=types.SimpleNamespace(loads=strict_json);return module

def file_under(root,relative):
 require(type(relative) is str and relative and not PurePosixPath(relative).is_absolute() and '..' not in PurePosixPath(relative).parts and str(PurePosixPath(relative))==relative,'invalid artifact path')
 path=(root/relative).resolve(strict=True);require(path.is_relative_to(root) and path.is_file(),'artifact outside root');return path

def inventory(root,items):
 require(root.is_dir() and not root.is_symlink() and isinstance(items,dict) and items,'inventory missing')
 require({p.relative_to(root).as_posix() for p in root.rglob('*')}==set(items),'inventory membership differs')
 for name,v in items.items():
  path=root/name;rel=PurePosixPath(name);require(not rel.is_absolute() and '..' not in rel.parts and str(rel)==name,'inventory path differs');s=path.lstat();require(format(stat.S_IMODE(s.st_mode),'04o')==v['mode'],'inventory mode differs')
  if v['type']=='directory':require(stat.S_ISDIR(s.st_mode),'inventory directory differs')
  elif v['type']=='file':require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==v['bytes'] and file_sha(path)==v['sha256'],'inventory file differs')
  else:raise ValueError('inventory node unsupported')

def verify_staged(root,cfg,accepted,control_manifest):
 packet=file_under(root,cfg['source_freeze']).parent;freeze=strict_json((packet/'freeze-inventory.json').read_bytes());require(type(freeze['files']) is dict and freeze['files'],'empty freeze')
 for name,v in freeze['files'].items():
  rel=PurePosixPath(name);require(not rel.is_absolute() and '..' not in rel.parts and str(rel)==name,'freeze path differs');path=packet/name;info=path.lstat()
  require(path.resolve(strict=True).is_relative_to(packet) and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==v['bytes'] and file_sha(path)==v['sha256'],'freeze member differs')
 cap=(root/cfg['capsule_dir']).resolve(strict=True);require(cap.is_relative_to(root) and cap.is_dir(),'capsule outside root')
 manifest=strict_json(pinned(cap/'checkout-manifest.json',accepted['checkout_manifest_sha256'],'checkout manifest'))['entries'];sums=pinned(cap/'SHA256SUMS',accepted['capsule_sha256s_sha256'],'capsule sums').decode('ascii').splitlines();entries={}
 for line in sums:
  h,sep,name=line.partition('  ');require(sep and re.fullmatch('[0-9a-f]{64}',h) and name not in entries,'capsule sums malformed');entries[name]=h
 expected={}
 for name,v in manifest.items():
  require(v['type'] in ('file','directory'),'unsupported checkout member');q={'type':v['type'],'mode':format(v['mode'],'04o')}
  if v['type']=='file':q.update(bytes=v['size'],sha256=v['sha256'])
  expected[name]=q
 for target,source in INSTALL.items():
  q=file_under(root,cfg['capsule_dir']+'/'+source);require(target not in expected and source in entries and file_sha(q)==entries[source],'staged capsule source differs');expected[target]={'type':'file','mode':'0444','bytes':q.stat().st_size,'sha256':entries[source]}
 require(expected==control_manifest,'staged control inventory differs from accepted source')

def lifecycle(td,record,run,root,config):
 vm=run['vm_uuid'];scope='parity-vm-'+vm+'.scope';group=td['scope_cgroup']
 require(td==record['teardown'] and td['vm_uuid']==vm and td['scope_unit']==scope and td['scope_boot_observation']['state']=={'id':scope,'load':'loaded','active':'active','group':group} and td['scope_after']['load']=='not-found' and td['scope_after']['active']=='inactive' and td['cgroup_events']['removed'] is True and td['clean_poweroff'] is True and td['forced_stop'] is False and td['qemu_exit_status']==0 and td['scope_quiescent'] is True and td['proof_durable'] is True,'lifecycle state differs')
 status=td['poweroff_request'];require(type(status) is int and status==run['poweroff_request'],'poweroff status differs')
 if status==0:return
 require((run['build'],run['batch'],vm,status)==('static','alltasks',STATIC_UUID,255),'unapproved poweroff alternative')
 disposition=strict_json(pinned(file_under(root,config['lifecycle_disposition']),LIFECYCLE,'lifecycle disposition'))
 require(disposition['schema']=='bashos-exact-vm-lifecycle-primary-disposition-v1' and disposition['decision']=='accept-observed-serial-powerdown-and-owned-quiescence-with-unexplained-ssh-255' and disposition['vm_uuid']==vm and disposition['source_acceptance_sha256']==SOURCE_ACCEPT and disposition['artifacts_sha256']==STATIC_ARTIFACTS and disposition['poweroff_request']==255 and disposition['observed_wrapper_exit_status']==0 and disposition['separate_qemu_exit_event_claimed'] is False and disposition['ssh_failure_cause']=='unobserved; stdout and stderr were discarded by pinned controller' and disposition['wrapper_pid']==td['wrapper_pid'] and all(disposition[k] is True for k in ('cgroup_absent','wrapper_absent','overlay_absent')) and disposition['product_coverage'] is False,'exact lifecycle disposition differs')
 require(disposition['current_scope_raw']=='ControlGroup=\nId='+scope+'\nLoadState=not-found\nActiveState=inactive\n','lifecycle scope differs')
 require(disposition['independent_review_sha256']=='d13e9beae6d2f13060577fa7b562538a8f28ec259cb67e3605bc25ce97604e95' and file_sha(file_under(root,config['lifecycle_review']))==disposition['independent_review_sha256'] and disposition['vm_controller_sha256']=='5944d62b34b96768428814b6373462a3e6642cf49561c576f7450ea126959cc5' and file_sha(file_under(root,config['control_tree']+'/tests/parity-vm/vm.py'))==disposition['vm_controller_sha256'],'lifecycle reviewer/controller differs')
 path=file_under(root,config['run_dir']+'/static-alltasks/evidence-record.json').parent
 for name,h in STATIC_ARTIFACTS.items():require(file_sha(file_under(root,config['run_dir']+'/static-alltasks/'+name))==h,'lifecycle artifact differs')
 vmdata=strict_json((path/'vm/vm.json').read_bytes());console=(path/'vm/console.log').read_bytes();limits=strict_json((path/'vm/console-limits.json').read_bytes());require(vmdata['uuid']==vm and '-serial' in vmdata['argv'] and limits=={'bytes':len(console),'truncated':False,'error':None,'reader_alive':False},'serial identity or capture differs')
 sequence=['poweroff.target','All filesystems unmounted.','Powering off.','reboot: Power down'];require(disposition['serial_powerdown_sequence']==sequence,'serial sequence differs');offset=-1
 for marker in sequence:offset=console.find(marker.encode(),offset+1);require(offset>=0,'serial marker absent')

def load_qualified_uclamp40(spec,expected_binary,expected_build):
 """Verify a primary-issued six-run receipt and return only one selected batch."""
 require(type(spec) is dict and expected_build in CORES and expected_binary==CORES[expected_build] and spec.get('evidence_format')==FORMAT,'format/build differs');deny_noncore(spec,'uclamp40 selection')
 batch=spec.get('batch');require(batch in CASES and spec.get('groups')==['shell'] and spec.get('ids')==list(CASES[batch]) and not spec.get('exclude_ids') and spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True,'unsupported selection')
 pin=spec.get('primary_receipt');require(type(pin) is dict and set(pin)=={'path','sha256'} and pin['sha256'] in AUTHORIZED_RECEIPTS,'receipt not source-authorized')
 receipt=strict_json(pinned(pin['path'],pin['sha256'],'primary receipt'));deny_noncore(receipt,'uclamp40 receipt')
 fields={'schema','decision','ledger_scope','core_ledger_eligible','base_commit','subject_execution_on_host','primary_reviewer','utc','source_acceptance_sha256','source_freeze_sha256','case_index_sha256','image_receipt_sha256','checker_sha256','partial_primary_audit_sha256','full_audit_sha256','control_inventory_sha256','setter_excluded','limitations','runs'}
 require(set(receipt)==fields and receipt.get('schema')=='bashos-uclamp-followup40-primary-receipt-v1' and receipt.get('decision')=='accept-reviewed-core-case-evidence' and receipt.get('ledger_scope')=='core' and receipt.get('core_ledger_eligible') is True and receipt.get('base_commit')=='b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf' and receipt.get('subject_execution_on_host') is False and receipt.get('source_acceptance_sha256')==SOURCE_ACCEPT and receipt.get('source_freeze_sha256')==SOURCE_FREEZE and receipt.get('case_index_sha256')==CASE_INDEX and receipt.get('image_receipt_sha256')==IMAGE_ACCEPT and receipt.get('checker_sha256')==CHECKER and receipt.get('partial_primary_audit_sha256')==PARTIAL_AUDIT and receipt.get('full_audit_sha256')==FULL_AUDIT and receipt.get('setter_excluded') is True and type(receipt.get('primary_reviewer')) is str and bool(receipt['primary_reviewer'].strip()) and receipt.get('limitations')==LIMITATIONS,'receipt scope differs')
 require(type(receipt['utc']) is str and receipt['utc'].endswith('Z'),'receipt UTC differs');datetime.datetime.fromisoformat(receipt['utc'][:-1]+'+00:00')
 require(all(type(receipt[k]) is str and re.fullmatch('[0-9a-f]{64}',receipt[k]) for k in ('full_audit_sha256','control_inventory_sha256')) and set(receipt['runs'])=={b+'-'+k for b in CORES for k in CASES},'paired receipt must contain six runs and pins')
 require(len({v['vm_uuid'] for v in receipt['runs'].values()})==6,'receipt VM identity reused')
 for b in CORES:
  for k in CASES:
   v=receipt['runs'][b+'-'+k];require(set(v)=={'name','build','batch','candidate_sha256','selected_ids','vm_uuid','record_sha256','payload_sha256','evidence_sha256','summary_sha256','teardown_sha256','result_inventory','result_inventory_sha256','poweroff_request','current_scope_raw','wrapper_absent','cgroup_absent','cases'} and v['build']==b and v['batch']==k and v['candidate_sha256']==CORES[b] and v['selected_ids']==list(CASES[k]) and set(v['cases'])==set(CASES[k]) and v['wrapper_absent'] is True and v['cgroup_absent'] is True and v['current_scope_raw']=='ControlGroup=\nId=parity-vm-'+v['vm_uuid']+'.scope\nLoadState=not-found\nActiveState=inactive\n' and all(set(v['cases'][cid])=={'case_sha256','raw_sha256','raw_status','status','classification'} and v['cases'][cid]['case_sha256']==h and type(v['cases'][cid]['raw_status']) is int and v['cases'][cid]['status'] in ('PASS','FAIL') and v['cases'][cid]['classification'] in ('BOUNDED_PASS','REACHED_FAIL') for cid,h in CASES[k].items()),'paired receipt run incomplete')
 cfg=spec['artifacts'];require(type(cfg) is dict and set(cfg)=={'root','run_dir','source_acceptance','source_freeze','case_index','capsule_dir','control_tree','control_inventory','image_receipt','checker','partial_audit','full_audit','lifecycle_disposition','lifecycle_review'},'artifact configuration differs')
 root=Path(cfg['root']);require(root.is_absolute(),'artifact root must be absolute');root=root.resolve(strict=True);require(root.is_dir(),'artifact root missing')
 for name,h in [('source_acceptance',SOURCE_ACCEPT),('source_freeze',SOURCE_FREEZE),('case_index',CASE_INDEX),('image_receipt',IMAGE_ACCEPT),('checker',CHECKER),('partial_audit',PARTIAL_AUDIT)]:pinned(file_under(root,cfg[name]),h,name)
 accepted=strict_json((file_under(root,cfg['source_acceptance'])).read_bytes());require(accepted['decision']=='accept-source-and-vm-plan' and accepted['product_coverage'] is False and accepted['root_fixtures_allowed'] is False and accepted['approved_cases']==13 and set(accepted['approved_batches'])=={'dispatch','query','setter','alltasks'} and accepted['packet38_freeze_sha256']==SOURCE_FREEZE and accepted['case_index_sha256']==CASE_INDEX and accepted['image_acceptance_sha256']==IMAGE_ACCEPT,'source acceptance differs')
 image=strict_json(file_under(root,cfg['image_receipt']).read_bytes());require(image['schema']=='bashos-device-kernel-image-acceptance-v1' and image['decision']=='accept-image-qualification' and image['product_coverage'] is False and image['prepared_sha256']=='08442265e7135133c25936899ffc1cc19530b339b216c35a3ad42e072eee668a' and image['prepared_manifest_sha256']=='b7fdb3c8df4f38d9f5d988858731950c6c24229e874eeab18fe5951b40b34569','image acceptance differs')
 idx=strict_json((file_under(root,cfg['case_index'])).read_bytes());require(all(idx['batches'][b]==list(CASES[b]) and all(idx['cases'][k]==v for k,v in CASES[b].items()) for b in CASES),'source case index differs')
 review=strict_json(pinned(file_under(root,cfg['full_audit']),receipt['full_audit_sha256'],'paired primary raw audit'));require(review['schema']=='uclamp-followup40-independent-raw-review-v1' and review['source_acceptance_sha256']==SOURCE_ACCEPT and review['subject_execution'] is False,'full audit scope differs')
 for b in CORES:
  for k in CASES:
   a=review['builds'][b][k];v=receipt['runs'][b+'-'+k];require(a['state']=='completed' and a['vm_uuid']==v['vm_uuid'] and a['record_sha256']==v['record_sha256'] and set(a['case_results'])==set(CASES[k]) and all(a['case_results'][cid]['classification']==v['cases'][cid]['classification'] and a['case_results'][cid]['raw_sha256']==v['cases'][cid]['raw_sha256'] for cid in CASES[k]),'paired raw review incomplete')
 partial=strict_json(file_under(root,cfg['partial_audit']).read_bytes())
 for b,k in (('static','dispatch'),('dynamic','dispatch'),('static','query'),('dynamic','query'),('static','alltasks')):
  before=partial['builds'][b][k];after=review['builds'][b][k];require(before['state']=='completed' and before['record_sha256']==after['record_sha256'] and before['vm_uuid']==after['vm_uuid'] and all(before['case_results'][cid]['raw_sha256']==after['case_results'][cid]['raw_sha256'] and before['case_results'][cid]['classification']==after['case_results'][cid]['classification'] for cid in CASES[k]),'earlier completed raw evidence changed')
 control_manifest=strict_json(pinned(file_under(root,cfg['control_inventory']),receipt['control_inventory_sha256'],'frozen control inventory'));verify_staged(root,cfg,accepted,control_manifest);control=(root/cfg['control_tree']).resolve(strict=True);require(control.is_relative_to(root),'control outside root');inventory(control,control_manifest)
 run=receipt['runs'][expected_build+'-'+batch];require(run['build']==expected_build and run['batch']==batch and run['candidate_sha256']==expected_binary and run['selected_ids']==list(CASES[batch]) and run['name']==spec['name'] and run['wrapper_absent'] is True and run['cgroup_absent'] is True,'run receipt differs')
 uuid=run['vm_uuid'];require(run['current_scope_raw']=='ControlGroup=\nId=parity-vm-'+uuid+'.scope\nLoadState=not-found\nActiveState=inactive\n','scope attestation differs')
 rel=cfg['run_dir']+'/'+expected_build+'-'+batch;record_path=file_under(root,rel+'/evidence-record.json');path=record_path.parent;require(Path(spec['path']).resolve(strict=True)==path and Path(spec['core_binary_path']).is_absolute() and file_sha(spec['core_binary_path'])==expected_binary,'selected path or core differs')
 manifest=strict_json(pinned(file_under(root,run['result_inventory']),run['result_inventory_sha256'],'result inventory'));inventory(path,manifest)
 rec=strict_json(pinned(record_path,run['record_sha256'],'evidence record'));require(rec['schema']=='device-consumer-evidence-v2' and rec['status']=='completed' and rec['guest_summary_state']=='captured-unvalidated' and rec['qualification']=='framework-complete-device-adjudication-required' and rec['product_acceptance'] is False and rec['root_fixtures_allowed'] is False and rec['candidate_sha256']==expected_binary and rec['selected_case_ids']==run['selected_ids'] and rec['vm_uuid']==uuid and rec['consumer_sha256']=='15f0f5e7188bc41d57cb04c35ba5987ae8117c9bca333a220d102a830e670cab' and rec['index_sha256']==CASE_INDEX and rec['image_acceptance_sha256']==IMAGE_ACCEPT and rec['image_sha256']=='08442265e7135133c25936899ffc1cc19530b339b216c35a3ad42e072eee668a' and rec['manifest_sha256']=='b7fdb3c8df4f38d9f5d988858731950c6c24229e874eeab18fe5951b40b34569','evidence record differs')
 flags=('scope_proven','guest_units_quiescent','overlay_discarded','candidate_unchanged','candidate_snapshot_unchanged','acceptance_unchanged','classifier_unchanged','compat_evidence_unchanged','compat_source_unchanged','consumer_unchanged','evaluation_source_unchanged','evidence_unchanged','helpers_unchanged','image_unchanged','index_unchanged','inventory_unchanged','manifest_unchanged','namespace_source_unchanged','payload_unchanged','schema_unchanged','selfcheck_sources_unchanged','staging_evidence_unchanged','staging_source_unchanged','suites_unchanged','variant_unchanged','vm_source_unchanged');require(all(rec.get(k) is True for k in flags) and not (path/'overlay.qcow2').exists() and file_sha(path/'candidate.snapshot')==expected_binary,'integrity/disposal differs')
 require(file_sha(path/'payload.tar')==rec['payload_sha256']==run['payload_sha256'] and file_sha(path/'evidence.tar')==rec['evidence_validation']['archive_sha256']==run['evidence_sha256'],'payload or evidence differs')
 ident=rec['identity'];rb=ident['attestation']['readback'];token=(uuid+'\n').encode().hex();network=rec['network'];require(ident['marker_matches'] is True and ident['product_uuid_matches'] is True and ident['host_shared_mounts']==[] and rb['token']==uuid and rb['marker_hex']==rb['dmi_hex']==rb['attestation_hex']==token and all(rb[k].get('uid')==0 and rb[k].get('gid')==0 and rb[k].get('mode')==0o444 and rb[k].get('nlink')==1 and rb[k].get('type')=='regular' for k in ('marker','attestation')) and network['canary_accepted']==0 and network['host_canary']!='connected' and network['public_tcp']!='connected' and not isinstance(network['dns'],list),'VM identity/network differs')
 ns=strict_json(pinned(path/'namespace-proof-208.json',rec['namespace_proof_sha256'],'namespace'));outer=strict_json(pinned(path/'parent-namespace.json',rec['parent_namespace_sha256'],'parent namespace'));att=strict_json(pinned(path/'namespace-attestation-208.json',rec['namespace_attestation_sha256'],'namespace attestation'));priv=strict_json(pinned(path/'privilege-proof.json',rec['privilege_proof_sha256'],'privilege'));require(ns==rec['namespace_proof']['evaluation'] and outer==rec['namespace_proof']['parent'] and ns['schema']=='bashos-syslog208-namespace-v1' and att['schema']=='bashos-syslog-namespace-attestation-v1' and ns['token']==ns['dmi_uuid']==att['token']==uuid and ns['uid']==ns['euid']==outer['uid']==outer['euid']==0 and ns['pid1_uid']==['0']*4 and ns['attestation']['sha256']==rec['namespace_attestation_sha256'] and all(ns['attestation'].get(k)==v for k,v in {'uid':0,'gid':0,'mode':0o444,'nlink':1}.items()) and ns['namespaces']==att['namespaces'] and ns['outer_namespaces']==att['outer_namespaces'] and ns['proc_interfaces']==ns['sysfs_interfaces']==['lo'] and all(ns['namespaces'][k]!=outer[k] and ns['outer_namespaces'][k]==outer[k] for k in ('pid','net','mnt')),'namespace differs');require(priv==rec['privilege_proof'] and priv['vm_uuid']==uuid and (priv['uid'],priv['euid'],priv['gid'],priv['egid'])==(2000,2000,2000,2000) and priv['groups']==[] and priv['cap_eff']=='0000000000000000' and priv['no_new_privs']=='1','privilege differs')
 strict_json(pinned(path/'run.log.unit-proof.json',rec['guest_unit_proofs']['run.log.unit-proof.json'],'evaluation unit'));unit_proof(path/'run.log.unit-proof.json',rec['guest_unit_proofs']['run.log.unit-proof.json'],uuid,'bashos-evaluation-'+uuid[:8]+'.service',rec['guest_status']);comp=rec['compatibility'];strict_json(pinned(path/'compat/run.log.unit-proof.json',comp['proof_hashes']['run.log.unit-proof.json'],'compat unit'));unit_proof(path/'compat/run.log.unit-proof.json',comp['proof_hashes']['run.log.unit-proof.json'],uuid,'bashos-optional-'+uuid[:8]+'-reference.service',0)
 handoff=strict_json(pinned(path/'compat/handoff.json',comp['handoff_sha256'],'compat handoff'));require((path/'compat/handoff-guest.json').read_bytes()==(path/'compat/handoff.json').read_bytes()==(path/'compat/handoff-after.json').read_bytes() and handoff['vm_uuid']==uuid and handoff['candidate_sha256']==expected_binary and handoff['fixture_sha256']==rec['fixture_sha256'] and handoff['canary_absent'] is True and comp['status']==0 and file_sha(path/'compat/raw.json')==comp['raw_sha256'],'compatibility handoff differs')
 staging=rec['staging'];require(staging['status']==0 and file_sha(path/'staging.stdout')==staging['stdout_sha256'] and file_sha(path/'staging.stderr')==staging['stderr_sha256'] and (path/'staging.stderr').read_bytes()==b'' and file_sha(path/'guest-staging-clean.py')==staging['source_sha256'],'staging differs');stage=[strict_json(line) for line in (path/'staging.stdout').read_bytes().splitlines()];require(len(stage)==3 and [x['schema'] for x in stage]==['device-staging-inventory-v1','device-staging-gates-v1','device-staging-ready-v1'] and all(x['token']==uuid for x in stage) and set(stage[0]['allowed_gates'])==set(stage[0]['output'])==set(stage[1]['gates'])==set(stage[2]['removed_gates'])==set(staging['removed_gates']),'staging gate identity differs')
 td=strict_json(pinned(path/'vm/teardown.json',run['teardown_sha256'],'teardown'));lifecycle(td,rec,run,root,cfg)
 with tarfile.open(path/'payload.tar','r:') as t:
  members=tar_members(t);require(all(x.isfile() for x in members),'payload contains nonfiles');raw=safe_member(t,'harness/suites/optional-frozen.json');defs=strict_json(raw)['cases'];require(sha(raw)==rec['fixture_sha256'] and sha(safe_member(t,'candidate'))==expected_binary and [x['id'] for x in defs]==run['selected_ids'] and all(canonical(x)==CASES[batch][x['id']] and x.get('privilege') is None and not x.get('optional') for x in defs),'payload cases differ')
  for item in members:
   if item.name in ('candidate','harness/suites/optional-frozen.json'):continue
   require(item.name.startswith(('harness/','loadable-parity/')),'payload member scope');name=('tests/parity-vm/'+item.name[8:] if item.name.startswith('harness/') else 'tests/'+item.name);require(name in control_manifest and control_manifest[name]['sha256']==sha(safe_member(t,item.name)),'payload source differs')
 summary=strict_json(pinned(path/'guest-summary.json',run['summary_sha256'],'summary'));rows=summary['cases'];by={x['id']:x for x in rows};checks={'selfcheck-'+x for x in CHECKS};require(summary['vm_uuid']==uuid and summary['binary_sha256']==expected_binary and summary['root_fixtures_allowed'] is False and summary['selected_case_ids']==sorted(run['selected_ids']) and len(rows)==len(by)==len(checks)+len(defs) and set(by)==checks|set(run['selected_ids']) and all(by[x]['status']=='PASS' and by[x]['group']=='selfcheck' for x in checks) and set(rec['evidence_validation']['selfchecks'])==checks,'summary selection or controls differ')
 require(type(rec['guest_status']) is int and rec['guest_status']==int(any(by[c]['status']=='FAIL' for c in run['selected_ids'])),'guest status differs')
 audit=review['builds'][expected_build][batch];require(audit['state']=='completed' and audit['vm_uuid']==uuid and audit['record_sha256']==run['record_sha256'] and set(audit['case_results'])==set(run['selected_ids']),'raw audit selection differs')
 sem=case_semantics()
 selected=[]
 with tarfile.open(path/'evidence.tar','r:') as t:
  tar_members(t);require(safe_member(t,'results/summary.json')==(path/'guest-summary.json').read_bytes(),'archived summary differs')
  for cid in checks:require(strict_json(safe_member(t,'results/selfcheck/'+cid.removeprefix('selfcheck-')+'.json'))=={k:v for k,v in by[cid].items() if k!='kind'},'selfcheck mismatch')
  for case in defs:
   cid=case['id'];raw=safe_member(t,'results/'+cid+'/candidate.json');raw_obj=strict_json(raw);r=run['cases'][cid];observed=sem.independent_case(raw_obj,case);saved=audit['case_results'][cid];require(sha(raw)==r['raw_sha256']==saved['raw_sha256'] and r['case_sha256']==CASES[batch][cid] and r['raw_status']==raw_obj['status'] and r['status']==by[cid]['status']==saved['framework_status'] and by[cid]['group']=='shell' and by[cid]['kind']=='contract' and by[cid]['covers']==case['covers'] and r['status'] in ('PASS','FAIL') and observed['classification']==saved['classification']==r['classification'] and observed['classification'] in ('BOUNDED_PASS','REACHED_FAIL') and observed['control_valid'] is True and observed['candidate_reached'] is True,'raw candidate classification differs')
   if 'seccomp-notify' in case.get('features',[]):require('user_notif' in strict_json(safe_member(t,'results/'+cid+'/feature-checks.json'))['seccomp-notify']['actions_avail'],'seccomp notify unavailable')
   require(not (r['status']=='FAIL' and observed['classification']=='BOUNDED_PASS'),'unexplained framework failure')
   row=dict(by[cid]);row['status']='FAIL' if observed['classification']=='REACHED_FAIL' else row['status'];selected.append({'record':row,'definition':case,'sources':{},'run':spec['name']})
 return selected,{'name':spec['name'],'groups':['shell'],'selected_records':len(selected),'evidence_format':FORMAT,'primary_receipt_sha256':pin['sha256'],'candidate_sha256':expected_binary,'vm_uuid':uuid,'poweroff_request':td['poweroff_request'],'limitations':receipt['limitations']}
