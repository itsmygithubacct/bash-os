#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only device-v8 UCLAMP adapter; accepts only the pinned primary receipt."""
import json,stat,tarfile
from pathlib import Path,PurePosixPath
from primary_controller_evidence import CHECKS,canonical,deny_noncore,file_sha,pinned,require,safe_member,sha,tar_members,unit_proof
from types import ModuleType
_AUDIT_SHA256='46113da7520c20d60f5068dd9d3d4cf87428ed846b1f521d37752f4a8ba87f6a'
_audit_path=Path(__file__).resolve().with_name('device_v8_raw_audit.py')
_audit_data=pinned(_audit_path,_AUDIT_SHA256,'device raw audit source')
raw_audit=ModuleType('device_v8_raw_audit');raw_audit.__file__=str(_audit_path)
exec(compile(_audit_data,str(_audit_path),'exec'),raw_audit.__dict__)
FORMAT='primary-qualified-device-v8-uclamp-v1'
AUTHORIZED_RECEIPT_SHA256=frozenset({'1940fd1da14f62c2c166874ee0b72fcd5ebd0898488954e44b278ad0f16067ae'})  # Exact primary-issued bounded receipt.
RECEIPT_SCHEMA='bashos-device-v8-primary-receipt-v1'
DECISION='accept-reviewed-core-case-evidence'
RAW_REVIEW='9fdc09bcaeb9df5030d9826643d3c4fe9840670bf4a6ee5355b2a412a7252a72'
RESULT_INVENTORY='f9649a189a22d37d427c5ba8c44c40c6c532ccca0783867112e99239728a3134'
CHECKER_SOURCE='cdb64381d1c4acebf276e610f1596d95a663b91ab73f219d17ea73b4f5346d8e'
SOURCE_ACCEPT='9f58c8ab4414ef7278a43a99d1b7f5c18e4563e9eede450fe292e979412601b2'
SOURCE_INVENTORY='b15ec9af6054bad35bc649113c73834149b00d84d4953d3e33269e00e13d620d'
IMAGE_RECEIPT='b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6'
CORES={'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab','dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
IDS=['devices-uclamp-query-r1','devices-uclamp-setter-r1','devices-uclamp-command-r1']

def inventory(root,items):
    require(isinstance(items,dict) and items,'device source-pinned inventory missing')
    actual={x.relative_to(root).as_posix() for x in root.rglob('*')}
    require(actual==set(items),'device artifact inventory membership differs')
    for name,v in items.items():
        rel=PurePosixPath(name);require(not rel.is_absolute() and '..' not in rel.parts and str(rel)==name,'device invalid artifact path')
        p=root/name;s=p.lstat();require(format(stat.S_IMODE(s.st_mode),'04o')==v['mode'],'device artifact mode differs: '+name)
        if v['type']=='directory':require(stat.S_ISDIR(s.st_mode),'device artifact directory differs: '+name)
        elif v['type']=='file':require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==v['bytes'] and file_sha(p)==v['sha256'],'device artifact bytes differ: '+name)
        else:raise ValueError('device unsupported artifact kind')

def load_qualified_device_v8_run(spec,expected_binary,expected_build):
    require(expected_build in CORES and expected_binary==CORES[expected_build] and spec.get('evidence_format')==FORMAT,'device build or format differs')
    deny_noncore(spec,'device selection');require(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==IDS and not spec.get('exclude_ids'),'device selection differs')
    pin=spec['primary_receipt'];digest=pin['sha256'];require(digest in AUTHORIZED_RECEIPT_SHA256,'device primary receipt is not authorized in source')
    receipt=json.loads(pinned(pin['path'],digest,'device primary receipt'));deny_noncore(receipt,'device primary receipt')
    require(receipt.get('schema')==RECEIPT_SCHEMA and receipt.get('decision')==DECISION and receipt.get('ledger_scope')=='core' and receipt.get('core_ledger_eligible') is True and receipt.get('base_commit')=='b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf' and receipt.get('subject_execution_on_host') is False and receipt.get('review_sha256')==RAW_REVIEW and receipt.get('source_acceptance_sha256')==SOURCE_ACCEPT and receipt.get('source_inventory_sha256')==SOURCE_INVENTORY and receipt.get('image_receipt_sha256')==IMAGE_RECEIPT,'device receipt scope differs')
    require(isinstance(receipt.get('limitations'),list) and len(receipt['limitations'])==5 and receipt.get('reviewer_source_sha256')==CHECKER_SOURCE,'device receipt bounds differ')
    review=json.loads(pinned(receipt['review_path'],RAW_REVIEW,'device primary raw review'));require(review['schema']=='paired-uclamp-raw-review-v1' and review['state']=='raw-checks-passed-pending-primary-adjudication','device raw review differs')
    require(spec.get('receipt_run')=='uclamp-'+expected_build,'device receipt selection differs');run=receipt['runs'][spec['receipt_run']];root=Path(spec['path']);require(root.is_absolute() and str(root.resolve(strict=True))==run['source_result'] and spec['name']==run['name'] and run['build']==expected_build and run['candidate_sha256']==expected_binary and run['batch']=='uclamp' and run['groups']==['shell'] and run['selected_ids']==IDS and set(run['cases'])==set(IDS) and run['wrapper_absent'] is True and run['cgroup_absent'] is True,'device receipt run differs')
    # Whole retained result membership, file types, bytes and modes use a separately source-pinned inventory; the receipt does not select that inventory.
    manifests=json.loads(pinned(Path(__file__).resolve().with_name('device-v8-result-inventory.json'),RESULT_INVENTORY,'device independently pinned result inventory'));require(manifests['schema']=='device-v8-result-inventory-v1' and set(manifests['runs'])=={'static','dynamic'},'device result inventory scope differs');inventory(root,manifests['runs'][expected_build])
    record=json.loads(pinned(root/'evidence-record.json',run['record_sha256'],'device evidence record'));u=run['vm_uuid'];require(record['schema']=='device-consumer-evidence-v2' and record['status']=='completed' and record['qualification']=='framework-complete-device-adjudication-required' and record['product_acceptance'] is False and record['root_fixtures_allowed'] is False and record['candidate_sha256']==expected_binary and record['selected_case_ids']==IDS and record['vm_uuid']==u and record['guest_summary_state']=='captured-unvalidated','device record scope differs')
    require(Path(spec['core_binary_path']).is_absolute() and file_sha(spec['core_binary_path'])==expected_binary and file_sha(root/'candidate.snapshot')==expected_binary and record['candidate_unchanged'] is True and record['candidate_snapshot_unchanged'] is True,'device candidate bytes differ')
    require(record['payload_sha256']==run['payload_sha256'] and record['evidence_validation']['archive_sha256']==run['evidence_sha256'] and file_sha(root/'payload.tar')==run['payload_sha256'] and file_sha(root/'evidence.tar')==run['evidence_sha256'],'device archive differs')
    flags=('scope_proven','guest_units_quiescent','overlay_discarded','candidate_unchanged','candidate_snapshot_unchanged','image_unchanged','manifest_unchanged','inventory_unchanged','consumer_unchanged','classifier_unchanged','staging_source_unchanged','staging_evidence_unchanged','vm_source_unchanged','payload_unchanged','index_unchanged','schema_unchanged','acceptance_unchanged','variant_unchanged','suites_unchanged','helpers_unchanged','compat_source_unchanged','namespace_source_unchanged','evaluation_source_unchanged','selfcheck_sources_unchanged','evidence_unchanged','compat_evidence_unchanged')
    require(all(record.get(k) is True for k in flags) and not (root/'overlay.qcow2').exists() and not (root/'prepared.snapshot.qcow2').exists(),'device integrity or disposal differs')
    require(record['guest_status']==0 and record['image_acceptance_sha256']==IMAGE_RECEIPT and record['image_sha256']==raw_audit.IMAGE and record['manifest_sha256']==raw_audit.MAN,'device image or service differs')
    parent=Path(receipt['source_acceptance_path']).parent;source=Path(spec['source_inventory_path']).parent;image_receipt=Path(spec['image_receipt_path']);require(parent.is_absolute() and source.is_absolute() and image_receipt.is_absolute() and root.resolve()==(parent/'results'/(expected_build+'-uclamp')).resolve(),'device source paths differ')
    require(Path(spec['source_inventory_path'])==source/'freeze-inventory.json' and Path(spec['primary_checker_path']).is_absolute() and run['current_scope_raw']=='ControlGroup=\nId=parity-vm-'+u+'.scope\nLoadState=not-found\nActiveState=inactive\n','device source inventory or receipt scope differs')
    require(file_sha(parent/'primary-source-acceptance.json')==SOURCE_ACCEPT and file_sha(source/'freeze-inventory.json')==SOURCE_INVENTORY and file_sha(image_receipt)==IMAGE_RECEIPT and file_sha(spec['primary_checker_path'])==CHECKER_SOURCE,'device source/image acceptance differs')
    source_decision=json.loads(pinned(parent/'primary-source-acceptance.json',SOURCE_ACCEPT,'device source decision')); image_decision=json.loads(pinned(image_receipt,IMAGE_RECEIPT,'device image decision'))
    require(source_decision.get('schema')=='bashos-primary-device-source-acceptance-v1' and source_decision.get('decision')=='accept-device-consumer-v8-for-bounded-nonroot-uclamp-qualification' and source_decision.get('approved_batches')==['uclamp'] and source_decision.get('root_fixtures_allowed') is False and image_decision.get('schema')=='bashos-device-kernel-image-acceptance-v1' and image_decision.get('decision')=='accept-image-qualification' and image_decision.get('product_coverage') is False,'device existing acceptance scope differs')
    require(set(receipt['runs'])=={'uclamp-static','uclamp-dynamic'} and receipt['runs']['uclamp-static']['vm_uuid']!=receipt['runs']['uclamp-dynamic']['vm_uuid'],'device receipt paired VM identity differs')
    # Data-only audit: pinned independently reviewed code rechecks both original runs, all source inventory, raw controls and witnesses.
    actual=raw_audit.audit(parent,source,image_receipt);require(actual==review and actual['builds'][expected_build]['record_sha256']==run['record_sha256'] and actual['builds'][expected_build]['vm_uuid']==u,'device raw review revalidation differs')
    identity=record['identity'];readback=identity['attestation']['readback'];token=(u+'\n').encode().hex();require(identity['marker_matches'] is True and identity['product_uuid_matches'] is True and identity['host_shared_mounts']==[] and readback['token']==u and readback['marker_hex']==readback['dmi_hex']==readback['attestation_hex']==token,'device VM identity differs')
    ns=json.loads(pinned(root/'namespace-proof-208.json',record['namespace_proof_sha256'],'device namespace'));parent_ns=json.loads(pinned(root/'parent-namespace.json',record['parent_namespace_sha256'],'device parent namespace'));at=json.loads(pinned(root/'namespace-attestation-208.json',record['namespace_attestation_sha256'],'device namespace attestation'));priv=json.loads(pinned(root/'privilege-proof.json',record['privilege_proof_sha256'],'device privilege'))
    require(ns==record['namespace_proof']['evaluation'] and parent_ns==record['namespace_proof']['parent'] and ns['token']==ns['dmi_uuid']==at['token']==u and ns['namespaces']==at['namespaces'] and ns['outer_namespaces']==at['outer_namespaces'] and ns['proc_interfaces']==ns['sysfs_interfaces']==['lo'] and all(ns['namespaces'][k]!=parent_ns[k] and ns['outer_namespaces'][k]==parent_ns[k] for k in ('pid','net','mnt')),'device namespace differs')
    require(priv==record['privilege_proof'] and (priv['uid'],priv['euid'],priv['gid'],priv['egid'])==(2000,2000,2000,2000) and priv['groups']==[] and priv['cap_eff']=='0000000000000000' and priv['no_new_privs']=='1','device privilege differs')
    ev=unit_proof(root/'run.log.unit-proof.json',record['guest_unit_proofs']['run.log.unit-proof.json'],u,'bashos-evaluation-'+u[:8]+'.service',0);comp=record['compatibility'];sv=unit_proof(root/'compat/run.log.unit-proof.json',comp['proof_hashes']['run.log.unit-proof.json'],u,'bashos-optional-'+u[:8]+'-reference.service',0)
    td=json.loads(pinned(root/'vm/teardown.json',run['teardown_sha256'],'device teardown'));boot=td['scope_boot_observation']['state'];group=td['scope_cgroup'];require(td==record['teardown'] and td['vm_uuid']==u and td['scope_unit']=='parity-vm-'+u+'.scope' and boot=={'id':td['scope_unit'],'load':'loaded','active':'active','group':group} and td['scope_after']['load']=='not-found' and td['scope_after']['active']=='inactive' and td['cgroup_events']['removed'] is True and td['clean_poweroff'] is True and td['forced_stop'] is False and td['qemu_exit_status']==0 and td['poweroff_request']==0 and td['scope_quiescent'] is True and td['proof_durable'] is True,'device scope or teardown differs')
    with tarfile.open(root/'payload.tar') as t:
        members=tar_members(t);require(all(x.isfile() for x in members),'device payload contains non-files');fixture_raw=safe_member(t,'harness/suites/optional-frozen.json');fixture=json.loads(fixture_raw);defs={x['id']:x for x in fixture['cases']};require(len(defs)==len(fixture['cases'])==3 and set(defs)==set(IDS) and sha(fixture_raw)==record['fixture_sha256'] and sha(safe_member(t,'candidate'))==expected_binary,'device payload fixture differs')
        for cid in IDS:require(canonical(defs[cid])==run['cases'][cid]['case_sha256'] and defs[cid].get('privilege') is None and not defs[cid].get('optional'),'device case definition differs')
        for m in members:
            if m.name in ('candidate','harness/suites/optional-frozen.json'):continue
            require(m.name.startswith(('harness/','loadable-parity/')),'device unexpected payload source')
            path=('tests/parity-vm/'+m.name[len('harness/'):] if m.name.startswith('harness/') else 'tests/'+m.name)
            require(file_sha(parent/'control'/path)==sha(safe_member(t,m.name)),'device payload source differs: '+m.name)
    s=json.loads(pinned(root/'guest-summary.json',record['guest_summary_sha256'],'device summary'));rows=s['cases'];by={x['id']:x for x in rows};checks={'selfcheck-'+x for x in CHECKS};require(s['vm_uuid']==u and s['binary_sha256']==expected_binary and s['selected_case_ids']==sorted(IDS) and sha((root/'guest-summary.json').read_bytes())==run['summary_sha256'] and len(rows)==len(by)==16 and set(by)==checks|set(IDS) and all(by[x]['status']=='PASS' for x in checks),'device summary differs')
    selected=[]
    with tarfile.open(root/'evidence.tar') as t:
        tar_members(t);require(safe_member(t,'results/summary.json')==(root/'guest-summary.json').read_bytes(),'device archived summary differs')
        for x in checks:require(json.loads(safe_member(t,'results/selfcheck/'+x.removeprefix('selfcheck-')+'.json'))=={k:v for k,v in by[x].items() if k!='kind'},'device selfcheck differs')
        for cid in IDS:
            data=safe_member(t,'results/'+cid+'/candidate.json');r=run['cases'][cid];require(sha(data)==r['raw_sha256'] and by[cid]['status']==r['status'] and r['status'] in ('PASS','FAIL') and r['group']=='shell' and json.loads(data)['status']==r['raw_status'],'device case evidence differs');selected.append({'record':by[cid],'definition':defs[cid],'sources':{},'run':spec['name']})
    return selected,{'name':spec['name'],'groups':['shell'],'selected_records':3,'evidence_format':FORMAT,'primary_receipt_sha256':digest,'candidate_sha256':expected_binary,'vm_uuid':u,'record_sha256':run['record_sha256'],'evidence_sha256':run['evidence_sha256'],'units':{'evaluation':ev,'compatibility':sv},'teardown':td,'limitations':receipt['limitations']}
