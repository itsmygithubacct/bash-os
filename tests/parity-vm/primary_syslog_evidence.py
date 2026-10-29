#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the primary-accepted syslog309 observations as inert pinned data.

The pinned review is the authority for the detailed raw temporal and lifecycle
analysis; this reader checks the original retained inputs, isolation, source
and selection bindings, without importing or executing subject code.
"""
import base64
import json
import tarfile
from pathlib import Path
from primary_controller_evidence import CHECKS, canonical, deny_noncore, file_sha, pinned, require, safe_member, sha, tar_members, unit_proof
from primary_clock_evidence import artifact_membership

# Filled only after an actual primary receipt has been supplied and reviewed.
PRIMARY_RECEIPT_SHA256 = '642a045485df4c2c7aa7728e7bb4c9b0aad1255dd6a3e0a50d557b55587ff0af'
FORMAT = 'primary-qualified-syslog309-v1'
FREEZE = '59a4f9c7b08167024904d1e8f7f092d253270477d886c86515ee6a841bff9a51'
SENDER_READY = 'e61f488fca301f0e46fd7efc76e514bbcf82aea913c61cc91559582ccdf16740'
CORES = {'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab', 'dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
CASES = {'hup':'52ba1c642689ff2a382cc92c017b15ccf8aadbf87ee993504ef32545dd868a81', 'periodic':'722b6a690ee44bce0d1418142904562f764aaec9d271cff4dcb5959d6a50789c'}
REVIEWS = {'hup-static':'f15fd6605ff8cf650a443eaf77d703da46c7b1f2a67c6f37ccb00e112f3b66d7','hup-dynamic':'c739c77b2f9a768d24f45644ab92a68e883872f412e0103c81bbd115920c3b86','periodic-static':'7e127b6987deb83a98c1da2efc3da0d656d8729eb462e7da1029efbe2bcf64e0','periodic-dynamic':'53f9e4f578f9f617bc49ed594ec586655ee35fd1edfe73870a91ee2aae93b537'}

def reviewed(ready_path, expected):
    ready_path=Path(ready_path)
    ready=json.loads(pinned(ready_path,expected,'syslog review ready'))
    directory=ready_path.parent
    for filename, key in [('AUDIT.json','audit_sha256'),('REVIEW.md','review_sha256'),('AUDIT-SOURCE.txt','source_snapshot_sha256')]:
        if key in ready:
            pinned(directory/filename,ready[key],'syslog review '+filename)
    return ready, json.loads((directory/'AUDIT.json').read_bytes())

def load_qualified_syslog_run(spec, expected_binary, expected_build):
    require(PRIMARY_RECEIPT_SHA256 is not None, 'syslog primary receipt has not been accepted and pinned')
    require(spec.get('evidence_format')==FORMAT and expected_build in CORES and expected_binary==CORES[expected_build], 'syslog core build mismatch')
    deny_noncore(spec,'syslog selection')
    require(spec.get('core_ledger_eligible') is True and spec.get('ledger_scope')=='core', 'syslog selection not core scoped')
    receipt_spec=spec['primary_receipt']
    require(receipt_spec.get('sha256')==PRIMARY_RECEIPT_SHA256,'syslog receipt pin mismatch')
    receipt=json.loads(pinned(receipt_spec['path'],PRIMARY_RECEIPT_SHA256,'syslog primary receipt'))
    # Receipt schema and accepted fields are checked below after primary supplies it.
    require(receipt.get('schema')=='bashos-syslog309-primary-acceptance-20261029-v1' and receipt.get('decision')=='accept-bounded-syslog309-r4-evidence-for-integration' and receipt.get('core_ledger_eligible') is True and receipt.get('ledger_scope')=='core' and receipt.get('source_freeze_sha256')==FREEZE and receipt.get('sender_basis_ready_sha256')==SENDER_READY and receipt.get('base_commit')=='b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf' and receipt.get('requirement',{}).get('behavior')=='Queued records replay in FIFO order at startup, on SIGHUP and every second once the destination works.' and receipt['requirement'].get('topic')=='bashsyslogd/forwarding_queue_replay' and receipt['requirement'].get('id')=='r4', 'syslog primary receipt authority differs')
    run=spec['receipt_run']; require(run in REVIEWS,'unknown syslog run')
    scenario,build=run.split('-'); cid='migration-system-client-syslog-fifo-'+scenario+'-231-r1'
    require(build==expected_build and spec.get('name')=='syslog309-'+run and spec.get('groups')==['shell'] and spec.get('ids')==[cid] and not spec.get('exclude_ids'), 'syslog run selection differs')
    a=receipt['runs'][run]; deny_noncore(a,'syslog receipt run')
    require(a['case']==cid and a['candidate']==build and a['candidate_sha256']==expected_binary and a['case_sha256']==CASES[scenario] and a['review_ready_sha256']==REVIEWS[run] and a['status']=='PASS' and a['selfchecks_pass']==13 and a['artifact_inventory_verified'] is True and a['payload_source_files_verified']==10, 'syslog accepted run differs')
    directory=Path(spec['path']); require(directory.is_absolute() and str(directory.resolve(strict=True))==a['source_result'],'syslog result path differs')
    core=Path(spec['core_binary_path']); require(core.is_absolute() and file_sha(core)==expected_binary, 'syslog core file mismatch')
    freeze_spec=spec['source_freeze']; require(freeze_spec['sha256']==FREEZE,'syslog freeze pin mismatch')
    freeze=json.loads(pinned(freeze_spec['path'],FREEZE,'syslog freeze'))
    require(freeze['schema']=='bashos-syslog308-primary-source-freeze-v1' and freeze['case_sha256'][cid]==CASES[scenario] and freeze['root_product_fixtures_allowed'] is False,'syslog freeze differs')
    ready,audit=reviewed(a['review_ready_path'],REVIEWS[run]); uuid=a['vm_uuid']
    require(ready['run']==run and ready['vm_uuid']==uuid and ready['candidate_sha256']==expected_binary and ready['case_sha256']==CASES[scenario] and ready['provenance_sha256']==a['provenance_sha256'] and ready['source_freeze_sha256']==FREEZE and ready['subject_execution_on_host'] is False, 'syslog reviewed identity differs')
    require(audit['vm_uuid']==uuid and audit['candidate_sha256']==expected_binary and audit['case_sha256']==CASES[scenario] and audit['provenance_sha256']==a['provenance_sha256'] and audit['recorded_status']=='PASS' and audit['both_units_and_vm_quiescent'] is True and audit['source_freeze_sha256']==FREEZE and audit['setup_control_count']==24 and set(audit['selfchecks'])=={'selfcheck-'+x for x in CHECKS} and all(v=='PASS' for v in audit['selfchecks'].values()) and audit['archive_sha256']==a['evidence_tar_sha256'] and audit['candidate_raw_sha256']==a['raw_case_sha256'] and audit['result_sha256']==a['result_sha256'] and ready['audit_sha256']==a['review_audit_sha256'] and audit['packet_payloads']==a['payloads'], 'syslog raw review differs')
    sender_path=spec['sender_basis_ready_path']; sender,sender_audit=reviewed(sender_path,SENDER_READY)
    require(sender['source_freeze_sha256']==FREEZE and sender['runs'][run]['vm_uuid']==uuid and sender['runs'][run]['provenance_sha256']==a['provenance_sha256'] and sender['audit_sha256']==receipt['sender_basis_audit_sha256'] and sender_audit['source_freeze_sha256']==FREEZE and sender_audit['runs'][run]['vm_uuid']==uuid and sender_audit['runs'][run]['provenance_sha256']==a['provenance_sha256'], 'syslog sender review differs')
    prov=json.loads(pinned(directory/'provenance.json',a['provenance_sha256'],'syslog provenance'))
    require(prov['status']=='completed' and prov['operation']=='syslog259-run' and prov['candidate']==build and prov['scenario']==scenario and prov['candidate_sha256']==expected_binary and prov['vm_uuid']==uuid and prov['selected_case_ids']==[cid] and prov['canonical_case_sha256']==CASES[scenario] and prov['root_fixtures_allowed'] is False and prov['host_mounts']==[] and prov['identity']['marker_matches'] is True and prov['identity']['product_uuid_matches'] is True and not prov['identity']['host_shared_mounts'] and prov['runtime_network']['canary_accepted']==0, 'syslog provenance identity differs')
    require(all(prov.get(k) is True for k in ('candidate_unchanged','candidate_snapshot_unchanged','prepared_unchanged','controller_unchanged','module_unchanged','suite_unchanged','helper_unchanged','guest_units_proven_quiescent','scope_proven','overlay_discarded','evidence_unchanged','compatibility_handoff_unchanged')), 'syslog integrity or lifecycle differs')
    require(prov['workspace_core_before']==prov['workspace_core_after'] and prov['workspace_core_before'].get(str(core))==expected_binary and prov['core_before']==prov['core_after'], 'syslog core binding differs')
    artifact_membership(directory,prov)
    require(file_sha(directory/'candidate.snapshot')==expected_binary and file_sha(directory/'payload.tar')==prov['payload_sha256']==sender_audit['runs'][run]['payload_sha256']==a['payload_sha256'] and file_sha(directory/'evidence.tar')==audit['archive_sha256']==prov['evidence_validation']['archive_sha256'], 'syslog archived evidence differs')
    ns=json.loads(pinned(directory/'namespace-proof-208.json',prov['namespace_proof_sha256'],'syslog namespace proof'))
    require(prov['namespace_proof_sha256']==sender_audit['runs'][run]['namespace_proof_sha256'] and ns==prov['namespace_proof']['evaluation'] and ns['token']==ns['dmi_uuid']==uuid and ns['proc_interfaces']==ns['sysfs_interfaces']==['lo'] and all(ns['namespaces'][k]!=prov['namespace_proof']['parent'][k] for k in ('mnt','net','pid')), 'syslog isolation mismatch')
    priv=json.loads(pinned(directory/'privilege-proof.json',prov['privilege_proof_sha256'],'syslog privilege proof'))
    require(priv==prov['privilege_proof'] and priv['vm_uuid']==uuid and (priv['uid'],priv['euid'],priv['gid'],priv['egid'])==(2000,2000,2000,2000) and priv['groups']==[] and priv['cap_eff']=='0000000000000000' and priv['no_new_privs']=='1','syslog privilege mismatch')
    with tarfile.open(directory/'payload.tar') as archive:
        tar_members(archive)
        for path,digest in sender_audit['source_sha256'].items(): require(sha(safe_member(archive,path))==digest,'syslog source mismatch: '+path)
        fixture_raw=safe_member(archive,'harness/suites/optional-frozen.json'); fixture=json.loads(fixture_raw)
        require(sha(fixture_raw)==prov['frozen_fixture_sha256'] and len(fixture['cases'])==1,'syslog payload fixture mismatch')
        case=fixture['cases'][0]; require(case['id']==cid and case['group']=='shell' and canonical(case)==CASES[scenario] and case['helpers_sha256']['helpers/system-client-syslog-fifo-231.py']==freeze['source_pins']['helper'],'syslog case mismatch')
    summary=json.loads(pinned(directory/'guest-summary.json',prov['guest_summary_sha256'],'syslog guest summary'))
    checks={'selfcheck-'+x for x in CHECKS}; rows=summary['cases']; selected=[x for x in rows if x['id']==cid and x['group']=='shell']
    require(summary['vm_uuid']==uuid and summary['binary_sha256']==expected_binary and summary['selected_case_ids']==[cid] and summary['root_fixtures_allowed'] is False and summary['isolation']['links']==['lo'] and len(rows)==14 and {x['id'] for x in rows}==checks|{cid} and all(x['status']=='PASS' for x in rows) and len(selected)==1 and set(prov['evidence_validation']['selfchecks'])==checks, 'syslog selected result or selfchecks differ')
    with tarfile.open(directory/'evidence.tar') as archive:
        tar_members(archive); raw=safe_member(archive,'results/'+cid+'/candidate.json'); require(sha(raw)==audit['candidate_raw_sha256'],'syslog raw case differs'); record=json.loads(raw)
        require(record['status']==0 and record['error'] is None and not record['stray_processes'] and base64.b64decode(record['stdout_base64'],validate=True)==('fifo169 '+scenario+'=pass\n').encode() and not base64.b64decode(record['stderr_base64'],validate=True),'syslog raw outcome differs')
        setup=base64.b64decode(record['diagnostics']['fifo169-setup.json']['base64'],validate=True); result=base64.b64decode(record['diagnostics']['fifo169-result.json']['base64'],validate=True)
        require(sha(setup)==audit['setup_sha256'] and sha(result)==audit['result_sha256'],'syslog diagnostics differ')
        result=json.loads(result); require(result['token']==uuid and result['classification']=='PASS' and not result['errors'] and [bytes.fromhex(x['hex']).decode() for x in result['udp_packets']]==audit['packet_payloads'], 'syslog raw packets differ')
    comp=prov['compatibility']; handoff=json.loads(pinned(directory/'compat/handoff.json',comp['handoff_sha256'],'syslog compatibility handoff'))
    require(handoff==comp['handoff'] and handoff['vm_uuid']==uuid and handoff['candidate_sha256']==expected_binary and handoff['selected_ids']==[cid] and handoff['fixture_sha256']==sha(fixture_raw) and handoff['status']=='PASS' and handoff['service_exit']==0 and handoff['canary_absent'] is True,'syslog compatibility mismatch')
    unit='bashos-evaluation-'+uuid[:8]+'.service'; compat='bashos-optional-'+uuid[:8]+'-reference.service'
    ep=prov['guest_unit_proofs']['run.log.unit-proof.json']; cp=prov['compatibility_unit_proofs']['run.log.unit-proof.json']
    evaluator=unit_proof(directory/'run.log.unit-proof.json',ep,uuid,unit,prov['guest_exit_status']); service=unit_proof(directory/'compat/run.log.unit-proof.json',cp,uuid,compat,0)
    require(a['unit_proof_checks']=={'evaluator':evaluator,'compatibility':service}, 'syslog unit proof receipt differs')
    teardown=json.loads((directory/'vm/teardown.json').read_bytes()); require(teardown==prov['teardown'] and teardown['vm_uuid']==uuid and teardown['clean_poweroff'] is True and teardown['forced_stop'] is False and teardown['poweroff_request']==0 and teardown['qemu_exit_status']==0 and teardown['scope_quiescent'] is True and teardown['proof_durable'] is True and teardown['cgroup_events']['removed'] is True,'syslog teardown differs')
    return ([{'record':selected[0],'definition':case,'sources':{},'run':spec['name']}], {'name':spec['name'],'groups':['shell'],'selected_records':1,'evidence_format':FORMAT,'primary_receipt_sha256':PRIMARY_RECEIPT_SHA256,'receipt_run':run,'candidate_sha256':expected_binary,'case_definition_sha256':CASES[scenario],'vm_uuid':uuid,'selfcheck_ids':sorted(checks),'requirement':'bashsyslogd/forwarding_queue_replay/r4','independent_review_sha256':REVIEWS[run],'provenance_sha256':a['provenance_sha256'],'evidence_sha256':audit['archive_sha256'],'units':{'evaluator':evaluator,'compatibility':service},'teardown':teardown,'overlay_discarded':True,'sender_attribution':'source-bound inference under pinned isolation'})
