#!/usr/bin/env python3
"""Narrow watch r3 data adapter. No authority exists until primary pins a receipt."""
import contextlib, importlib.util, io, json, sys, tarfile, tempfile
from pathlib import Path
from primary_controller_evidence import CHECKS, artifact_inventory, canonical, deny_noncore, file_sha, pinned, require, safe_member, sha, tar_members, unit_proof
FORMAT='primary-qualified-watch337-r3-v1'
PRIMARY_RECEIPT_SHA256='93207f5cea3dc063a1b98b7a6b8b60bbd5c00d522e5f62d6f8df9de772d4365f'
RECEIPT_SCHEMA='bashos-watch337-r3-primary-acceptance-v1'
DECISION='accept-both-bounded-watch-r3-early-exit-fail'
CASE='migration-terminal213-watch-error-key'; CONTROL='migration-terminal213-control-key'
CASE_HASH='020a87eca1272d787379abf2ba1bc107359fa2464aa0bddf8c7d6b8b71a0aba4'; CONTROL_HASH='a446780ceba49b73bb9c2a5ad3b469d228cc37443d79fb8c35b16ab3c0d57331'
PAIR='c7c0f388fa05e3a52c2fde1cacfe94276550574b019e1dbb2c0e91bd90b0cf1c'
IMAGE='9f8841a2a756268f3785232e713e56f5ac91157d116c37b14dbcb1ddcde17457'
GUARD='dea91736a54538ae758c4b416d0eb48b2fd4a4ba331af789967c2de0ccf769c6'
CORES={'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab','dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
AUDIT={'static':('watch337_static_data.py','0b6979ab07b7c615df24a0374eb39b97235f732ab3ed4da2548dcbd8b8aa7db2'),'dynamic':('watch337_dynamic_data.py','c5e35fc058b78ad8ecb360925b90d23059321155d35e7263b8a11206948ea60e')}

def audit(root,build):
    name,digest=AUDIT[build]; path=Path(__file__).resolve().parent/name
    data=pinned(path,digest,'watch337 reviewed data checker')
    # Exact reviewed data-only source: parses retained data and writes one temporary result.
    module=importlib.util.module_from_spec(importlib.util.spec_from_loader('watch337_data_'+build,loader=None));module.__file__=str(path)
    exec(compile(data,str(path),'exec'),module.__dict__)
    with tempfile.TemporaryDirectory(prefix='watch337-reader-') as temp:
        output=Path(temp)/'review.json'; old=sys.argv
        try:
            sys.argv=[str(path),str(root),'--output',str(output)]
            with contextlib.redirect_stdout(io.StringIO()): module.main()
        finally:sys.argv=old
        return json.loads(output.read_bytes())

def load_qualified_watch337_run(spec,expected_binary,expected_build):
    require(PRIMARY_RECEIPT_SHA256 is not None,'watch337 primary receipt not pinned')
    deny_noncore(spec,'watch337 selection')
    require(spec.get('evidence_format')==FORMAT and expected_build in CORES and expected_binary==CORES[expected_build] and spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['terminal'] and spec.get('ids')==[CASE] and not spec.get('exclude_ids'),'watch337 selection invalid')
    rp=spec['primary_receipt'];require(rp['sha256']==PRIMARY_RECEIPT_SHA256,'watch337 receipt not authorized')
    receipt=json.loads(pinned(rp['path'],PRIMARY_RECEIPT_SHA256,'watch337 primary receipt'));deny_noncore(receipt,'watch337 receipt')
    require(receipt.get('schema')==RECEIPT_SCHEMA and receipt.get('decision')==DECISION and receipt.get('ledger_scope')=='core' and receipt.get('core_ledger_eligible') is True and receipt.get('requirement')=={'topic':'watch/watch-terminal-parity','id':'r3'} and receipt.get('paired_review_sha256')==PAIR and receipt.get('source_diagnostic_classification_unchanged') is True and receipt.get('original_294_qualified') is False and receipt.get('key_handling_reached') is False,'watch337 receipt scope differs')
    pair=json.loads(pinned(receipt['paired_review_path'],PAIR,'watch337 paired review'))
    require(pair.get('decision')=='PROPOSE_R3_BOUNDED_FAIL_PENDING_PRIMARY' and pair.get('source_diagnostic_classification_unchanged') is True and pair.get('original_294_qualified') is False,'watch337 paired review differs')
    a=receipt['runs'][expected_build];root=Path(spec['path']);require(root.is_absolute() and str(root.resolve(strict=True))==a['source_result'] and spec['name']==a['name'] and a['candidate_sha256']==expected_binary and a['case_sha256']==CASE_HASH and a['status']=='FAIL','watch337 receipt run differs')
    require(file_sha(spec['core_binary_path'])==expected_binary and file_sha(root/'candidate.snapshot')==expected_binary,'watch337 candidate bytes differ')
    p=json.loads(pinned(root/'provenance.json',a['provenance_sha256'],'watch337 provenance'));u=a['vm_uuid'];ids=[CONTROL,CASE]
    require((root/'provenance.sha256').read_text().split()[0]==a['provenance_sha256'] and p['operation']=='terminal213-run' and p['status']=='incomplete' and p['qualification']=='not-qualified' and p['error']=='IncompleteEvidence: watch337 tracing is diagnostic-only; no product qualification' and p['watch337_diagnostic_only'] is True and p['guest_summary_state']=='validated-diagnostic-only' and p['batch']=='watch-keywait' and p['candidate']==expected_build and p['candidate_sha256']==expected_binary and p['vm_uuid']==u and p['selected_case_ids']==ids and p['canonical_case_sha256']=={CONTROL:CONTROL_HASH,CASE:CASE_HASH} and p['root_fixtures_allowed'] is False and p['host_mounts']==[],'watch337 diagnostic identity differs')
    require(p['prepared_sha256']==IMAGE and p['image_identity']['sha256']==(GUARD if expected_build=='static' else IMAGE),'watch337 explicit image exception differs')
    flags=('candidate_unchanged','candidate_snapshot_unchanged','prepared_unchanged','prepared_manifest_unchanged','prepared_sidecar_unchanged','image_lock_unchanged','provisioning_unchanged','authentication_receipts_unchanged','controller_unchanged','module_unchanged','namespace_baseline_unchanged','host_schema_unchanged','case_index_unchanged','guest_unchanged','terminal_unchanged','lifecycle167_unchanged','suites_unchanged','helpers_unchanged','guest_units_proven_quiescent','scope_proven','overlay_discarded','evidence_unchanged','compatibility_evidence_unchanged')
    require(all(p.get(k) is True for k in flags) and p['watch337_sources_before']==p['watch337_sources_after'] and file_sha(root/'watch337-sources-before.txt')==p['watch337_sources_before'] and file_sha(root/'watch337-sources-after.txt')==p['watch337_sources_after'],'watch337 integrity differs')
    artifact_inventory(root,p);require(not (root/'overlay.qcow2').exists() and file_sha(root/'payload.tar')==a['payload_sha256']==p['payload_sha256'] and file_sha(root/'evidence.tar')==a['evidence_sha256']==p['evidence_validation']['archive_sha256'],'watch337 archives differ')
    ns=json.loads(pinned(root/'namespace-proof-208.json',p['namespace_proof_sha256'],'watch337 namespace')); parent=json.loads(pinned(root/'parent-namespace.json',p['parent_namespace_sha256'],'watch337 parent namespace'));att=json.loads(pinned(root/'namespace-attestation-208.json',p['namespace_attestation_sha256'],'watch337 attestation'));priv=json.loads(pinned(root/'privilege-proof.json',p['privilege_proof_sha256'],'watch337 privilege'))
    require(ns==p['namespace_proof']['evaluation'] and parent==p['namespace_proof']['parent'] and ns['schema']=='bashos-syslog208-namespace-v1' and att['schema']=='bashos-syslog-namespace-attestation-v1' and ns['token']==ns['dmi_uuid']==att['token']==u and ns['proc_interfaces']==ns['sysfs_interfaces']==['lo'] and ns['namespaces']==att['namespaces'] and ns['outer_namespaces']==att['outer_namespaces'] and all(ns['outer_namespaces'][k]==parent[k] and ns['namespaces'][k]!=parent[k] for k in ('mnt','net','pid')) and ns['attestation']['sha256']==p['namespace_attestation_sha256'],'watch337 namespace differs')
    require(priv==p['privilege_proof'] and priv['vm_uuid']==u and (priv['uid'],priv['euid'],priv['gid'],priv['egid'])==(2000,2000,2000,2000) and priv['groups']==[] and priv['cap_eff']=='0000000000000000' and priv['no_new_privs']=='1' and p['runtime_network']['canary_accepted']==0 and p['identity']['marker_matches'] is True and p['identity']['product_uuid_matches'] is True and p['identity']['host_shared_mounts']==[],'watch337 privilege or identity differs')
    with tarfile.open(root/'payload.tar') as t:
        members=tar_members(t);require(all(m.isfile() for m in members),'watch337 payload membership invalid');fixture_raw=safe_member(t,'harness/suites/optional-frozen.json'); fixture=json.loads(fixture_raw);defs={c['id']:c for c in fixture['cases']}
        require(sha(fixture_raw)==p['frozen_fixture_sha256'] and len(defs)==len(fixture['cases'])==2 and set(defs)==set(ids) and canonical(defs[CASE])==CASE_HASH and canonical(defs[CONTROL])==CONTROL_HASH and sha(safe_member(t,'candidate'))==expected_binary,'watch337 fixture differs')
        source=Path(a['source_control']);require(source.is_absolute() and source.is_dir(),'watch337 source path differs')
        for m in members:
            if m.name in ('candidate','harness/suites/optional-frozen.json'):continue
            require(m.name.startswith(('harness/','loadable-parity/')),'watch337 unexpected payload member')
            rel=('tests/parity-vm/'+m.name[len('harness/'):] if m.name.startswith('harness/') else 'tests/'+m.name)
            require(file_sha(source/rel)==sha(safe_member(t,m.name)),'watch337 payload source differs: '+m.name)
        for c in defs.values():
            for name,h in c['helpers_sha256'].items():require(sha(safe_member(t,'harness/'+name))==h,'watch337 case helper differs')
        for name,h in p['watch337_helper_sha256'].items():require(sha(safe_member(t,'harness/'+name))==h,'watch337 observer source differs')
    s=json.loads(pinned(root/'guest-summary.json',p['guest_summary_sha256'],'watch337 summary'));rows=s['cases'];by={r['id']:r for r in rows};checks={'selfcheck-'+x for x in CHECKS}
    require((root/'summary.json').read_bytes()==(root/'guest-summary.json').read_bytes() and s['vm_uuid']==u and s['binary_sha256']==expected_binary and s['selected_case_ids']==ids and len(rows)==15 and len(by)==15 and set(by)==checks|set(ids) and all(by[k]['status']=='PASS' for k in checks) and by[CONTROL]['status']=='PASS' and by[CASE]['status']=='FAIL' and by[CASE]['reference_problems']==[] and by[CASE]['harness_errors']=={},'watch337 summary differs')
    with tarfile.open(root/'evidence.tar') as archive:
        tar_members(archive)
        require(safe_member(archive,'results/summary.json')==(root/'guest-summary.json').read_bytes(),'watch337 archived summary differs')
        for key in checks:
            rawcheck=json.loads(safe_member(archive,'results/selfcheck/'+key.removeprefix('selfcheck-')+'.json'))
            require(rawcheck=={k:v for k,v in by[key].items() if k!='kind'},'watch337 selfcheck differs')
        for side in ('candidate','reference'):
            raw=json.loads(safe_member(archive,'results/'+CASE+'/'+side+'.json'));setup=raw['setup']
            require(setup['status']==0 and setup['error'] is None and setup['stray_processes']==[] and raw.get('harness_error') is None and raw['terminal_restored'] is True and raw['stray_processes']==[], 'watch337 raw side setup or cleanup differs')
    ev=unit_proof(root/'run.log.unit-proof.json',p['guest_unit_proofs']['run.log.unit-proof.json'],u,'bashos-evaluation-'+u[:8]+'.service',1)
    comp=p['compatibility'];hand=json.loads(pinned(root/'compat/handoff.json',comp['handoff_sha256'],'watch337 handoff'));require(hand==comp['handoff'] and hand['vm_uuid']==u and hand['status']=='PASS' and hand['candidate_sha256']==expected_binary and hand['selected_ids']==ids and hand['fixture_sha256']==p['frozen_fixture_sha256'] and comp['status']==0 and (root/'compat/handoff-after.json').read_bytes()==(root/'compat/handoff.json').read_bytes() and (root/'compat/handoff-guest.json').read_bytes()==(root/'compat/handoff.json').read_bytes(),'watch337 compatibility differs')
    sv=unit_proof(root/'compat/run.log.unit-proof.json',p['compatibility_unit_proofs']['run.log.unit-proof.json'],u,'bashos-optional-'+u[:8]+'-reference.service',0)
    t=json.loads(pinned(root/'vm/teardown.json',a['teardown_sha256'],'watch337 teardown')); group=t['scope_cgroup'];boot=t['scope_boot_observation']['state'];require(t==p['teardown'] and t['vm_uuid']==u and t['scope_unit']=='parity-vm-'+u+'.scope' and boot=={'id':t['scope_unit'],'load':'loaded','active':'active','group':group} and t['scope_after']['load']=='not-found' and t['scope_after']['active']=='inactive' and t['cgroup_events']['removed'] is True and t['clean_poweroff'] is True and t['forced_stop'] is False and t['qemu_exit_status']==0 and t['poweroff_request']==0 and t['scope_quiescent'] is True and t['proof_durable'] is True,'watch337 scope teardown differs')
    review=audit(root,expected_build);require(review==pair[expected_build] and review['provenance_sha256']==a['provenance_sha256'] and review['archive_sha256']==a['evidence_sha256'] and review['vm_uuid']==u and review['candidate']['status']==1 and review['candidate']['watch_entries']==1,'watch337 raw paired adjudication differs')
    return ([{'record':by[CASE],'definition':defs[CASE],'sources':{},'run':spec['name']}],{'name':spec['name'],'groups':['terminal'],'selected_records':1,'evidence_format':FORMAT,'primary_receipt_sha256':PRIMARY_RECEIPT_SHA256,'candidate_sha256':expected_binary,'vm_uuid':u,'requirement':'watch/watch-terminal-parity/r3','source_classification':'incomplete','key_handling_reached':False,'ptrace_timing_caveat':True,'provenance_sha256':a['provenance_sha256'],'evidence_sha256':a['evidence_sha256'],'units':{'evaluator':ev,'compatibility':sv},'teardown':t})
