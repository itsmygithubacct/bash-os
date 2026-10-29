#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""DATA ONLY: read primary-receipted nonroot 293-derived modern VM results.

No subject, archived helper, controller, or external command is executed.
Only hashes placed in AUTHORIZED_RECEIPT_SHA256 by primary integration grant
acceptance. A caller-supplied pin or plausible raw result is not authority.
"""
import base64
import json
import re
import tarfile
from pathlib import Path

from primary_controller_evidence import (CHECKS, artifact_inventory, canonical,
    deny_noncore, file_sha, option, pinned, require, safe_member, sha,
    tar_members, unit_proof)

FORMAT = 'primary-qualified-modern293-v1'
RECEIPT_SCHEMA = 'bashos-modern293-primary-receipt-v1'
AUTHORIZED_RECEIPT_SHA256 = frozenset({
    '151e0abd922f6de27872496d0cb4ec84554ce09ec6c5282fbba89e15a62cbc13',
    '158b6f5bc10655600589fcbba422115bda37c942083560c15517d173d8ffd718',
    '1cd9392df4ac4ed3b54cf0753631fcea0a4e2379b80d116c5767ff36391bd3d5',
    'c9e2da56675cd7be3d03ccac0a4c337957e37ea5a755c1683c84a1cd22e97d16',
    'c1f563eef5f7cb47726afc084f7cf3c2c3f60b7b2997e621721bd2c2d61c2d42',
    '71bc85a71d66b39aa15b8c29c548bc8c6aa3dc1c6409ab20ffff9625fc1af9ce',
    '8ad7316cf0a64c3eac348c4eea1bf3ac182a703a695e9e68aaf59a1d2d8cd107',
})  # Exact primary-issued receipt; no caller-supplied authorities.
CORES = {
    'static': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
    'dynamic': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
}

def obj(path, digest, label):
    return json.loads(pinned(path, digest, label))

def load_qualified_modern_run(spec, expected_binary, expected_build):
    require(spec.get('evidence_format') == FORMAT and expected_build in CORES
            and expected_binary == CORES[expected_build], 'modern format/core mismatch')
    deny_noncore(spec, 'modern selection')
    require(spec.get('ledger_scope') == 'core' and spec.get('core_ledger_eligible') is True,
            'modern selection must explicitly be core')
    receipt_spec = spec['primary_receipt']
    digest = receipt_spec['sha256']
    require(digest in AUTHORIZED_RECEIPT_SHA256, 'modern receipt is not authorized in source')
    receipt = obj(receipt_spec['path'], digest, 'modern primary receipt')
    deny_noncore(receipt, 'modern receipt')
    require(receipt.get('schema') == RECEIPT_SCHEMA and receipt.get('decision') == 'accept-reviewed-core-case-evidence'
            and receipt.get('ledger_scope') == 'core' and receipt.get('core_ledger_eligible') is True
            and receipt.get('base_commit') == 'b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf'
            and receipt.get('subject_execution_on_host') is False, 'modern receipt authority differs')
    key = spec['receipt_run']
    require(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9_-]+', key), 'invalid run key')
    run = receipt['runs'][key]
    deny_noncore(run, 'modern receipt run')
    require(run['build'] == expected_build and run['candidate_sha256'] == expected_binary
            and spec['name'] == run['name'] and spec['groups'] == run['groups']
            and spec['ids'] == run['selected_ids'] and not spec.get('exclude_ids'), 'receipt selection differs')
    ids = run['selected_ids']; cases = run['cases']
    require(isinstance(ids, list) and ids and len(set(ids)) == len(ids)
            and set(ids) == set(cases) and all(cases[x]['status'] in ('PASS','FAIL') for x in ids),
            'receipt case selection/status invalid')
    directory = Path(spec['path'])
    require(directory.is_absolute() and str(directory.resolve(strict=True)) == run['source_result'], 'result path differs')
    p = obj(directory/'provenance.json', run['provenance_sha256'], 'modern provenance')
    require((directory/'provenance.sha256').read_text().split()[0] == run['provenance_sha256'], 'provenance sidecar differs')
    artifact_inventory(directory, p)
    deny_noncore(p, 'modern provenance')
    uuid = run['vm_uuid']; batch = run['batch']
    require(p.get('operation') == 'terminal213-run' and p.get('status') == 'completed'
            and p.get('qualification') == 'complete-evidence-not-product-pass'
            and p.get('candidate') == expected_build and p.get('candidate_sha256') == expected_binary
            and p.get('vm_uuid') == uuid and p.get('batch') == batch
            and p.get('selected_case_ids') == ids and p.get('root_fixtures_allowed') is False
            and p.get('host_mounts') == [] and p.get('guest_summary_state') == 'validated', 'modern provenance mismatch')
    unchanged = ('candidate_unchanged','candidate_snapshot_unchanged','prepared_unchanged',
                 'prepared_manifest_unchanged','prepared_sidecar_unchanged','image_lock_unchanged',
                 'provisioning_unchanged','authentication_receipts_unchanged','controller_unchanged',
                 'module_unchanged','namespace_baseline_unchanged','host_schema_unchanged',
                 'case_index_unchanged','guest_unchanged','terminal_unchanged','lifecycle167_unchanged',
                 'suites_unchanged','helpers_unchanged','guest_unit_proofs_unchanged',
                 'compatibility_module_unchanged','compatibility_inputs_unchanged',
                 'compatibility_evidence_unchanged','evaluation_properties_unchanged','evidence_unchanged',
                 'guest_units_proven_quiescent','scope_proven','overlay_discarded')
    require(all(p.get(k) is True for k in unchanged), 'modern integrity or lifecycle flags differ')
    for prefix in ('core', 'workspace_core'):
        before, after = p[prefix+'_before'], p[prefix+'_after']
        names = {Path(k).name: v for k,v in before.items()}
        require(before == after and len(before) == 2 and names == {'bash-static': CORES['static'], 'bash': CORES['dynamic']},
                'modern core build before/after differs')
    core = Path(spec['core_binary_path'])
    require(core.is_absolute() and str(core) in p['workspace_core_before']
            and p['workspace_core_before'][str(core)] == expected_binary and file_sha(core) == expected_binary
            and file_sha(directory/'candidate.snapshot') == expected_binary, 'modern core bytes differ')
    plan = obj(run['plan_path'], run['plan_sha256'], 'modern plan')
    launch = obj(run['launch_path'], run['launch_sha256'], 'modern launch')
    require(plan['build'] == expected_build and plan['scenario'] == batch and plan['output'] == run['source_result']
            and plan['candidate_sha256'] == expected_binary and plan['root_fixtures_allowed'] is False
            and plan['source_freeze_sha256'] == run['freeze_sha256'] and launch['plan_sha256'] == run['plan_sha256'],
            'modern plan differs')
    for flag, value in (('--candidate',expected_build),('--batch',batch),('--output',run['source_result']),
                        ('--expected-controller-sha256',p['controller_sha256'])):
        require(option(launch['argv'], flag) == value, 'modern launch differs: '+flag)
    control = Path(plan['source_control'])
    require(control.is_absolute() and control.name == 'control', 'modern frozen control path invalid')
    freeze = obj(control.parent/'freeze.json', run['freeze_sha256'], 'modern freeze')
    inventory = obj(control.parent/'control-files.json', freeze['inventories']['control-files.json'], 'modern source inventory')
    require(freeze['controller_sha256'] == p['controller_sha256'], 'frozen controller differs')
    for saved, source in (('controller.py','tests/parity-vm/vm.py'),
                          ('standard_terminal213.py','tests/parity-vm/standard_terminal213.py'),
                          ('terminal213_schema.py','tests/parity-vm/terminal213_schema.py')):
        require(file_sha(directory/saved) == inventory[source], 'frozen controller source differs: '+source)
    require(file_sha(directory/'controller.py') == p['controller_sha256']
            and file_sha(directory/'standard_terminal213.py') == p['module_sha256']
            and file_sha(directory/'terminal213_schema.py') == p['host_schema_sha256']
            and file_sha(directory/'standard_syslog208.py') == p['namespace_baseline_module_sha256'],
            'modern saved source provenance mismatch')
    index = obj(directory/'case-index-213.json', p['case_index_sha256'], 'modern case index')
    require(index.get('schema') == 'terminal213-source-case-index-v1'
            and index['batches'][batch]['selected_case_ids'] == ids
            and index['batches'][batch]['product_case_ids'] == p['product_case_ids']
            and index['batches'][batch]['control_case_ids'] == p['control_case_ids']
            and p['case_evidence']['selected_order'] == ids
            and p['canonical_case_sha256'] == {cid:index['canonical_case_sha256'][cid] for cid in ids}
            and index['suites_sha256'] == p['suite_sha256'] and index['helpers_sha256'] == p['helper_sha256']
            and all(index['canonical_case_sha256'][cid] == cases[cid]['case_sha256'] for cid in ids), 'modern index mismatch')
    indexed_definitions = {}
    for name, expected in index['suites_sha256'].items():
        require('/' not in name and name.endswith('.json'), 'invalid indexed suite name')
        source = 'tests/parity-vm/suites/'+name
        require(source in inventory and inventory[source] == expected
                and file_sha(control/source) == expected, 'frozen suite source differs: '+name)
        for definition in json.loads((control/source).read_bytes())['cases']:
            cid = definition['id']
            require(cid not in indexed_definitions, 'duplicate indexed case')
            indexed_definitions[cid] = definition
    require(all(cid in indexed_definitions and canonical(indexed_definitions[cid]) == cases[cid]['case_sha256']
                for cid in ids), 'indexed source case differs')
    pinned(run['review_path'], run['review_sha256'], 'primary-reviewed raw assessment')
    require(file_sha(directory/'payload.tar') == p['payload_sha256'] == run['payload_sha256']
            and file_sha(directory/'evidence.tar') == p['evidence_validation']['archive_sha256'] == run['evidence_sha256'],
            'modern archive hash mismatch')
    with tarfile.open(directory/'payload.tar','r:') as archive:
        members = tar_members(archive)
        require(all(m.isfile() for m in members), 'modern payload contains non-files')
        require(sha(safe_member(archive,'candidate')) == expected_binary, 'modern payload candidate differs')
        fixture_raw = safe_member(archive,'harness/suites/optional-frozen.json')
        fixture = json.loads(fixture_raw)
        require(sha(fixture_raw) == p['frozen_fixture_sha256'] and fixture['schema'] == 1, 'modern fixture differs')
        definitions = {c['id']:c for c in fixture['cases']}
        require(len(definitions) == len(fixture['cases']) and set(definitions) == set(ids), 'modern fixture selection differs')
        for cid in ids:
            c = definitions[cid]; deny_noncore(c, 'modern case')
            require(c['group'] in run['groups'] and canonical(c) == cases[cid]['case_sha256']
                    and c.get('privilege') != 'root', 'modern case definition differs')
            for helper, h in c.get('helpers_sha256',{}).items():
                require(sha(safe_member(archive,'harness/'+helper)) == h == index['helpers_sha256'][helper], 'modern helper differs')
        for member in members:
            name = member.name
            if name in ('candidate','harness/suites/optional-frozen.json'): continue
            require(name.startswith(('harness/','loadable-parity/')), 'unrecognized payload source')
            source = ('tests/parity-vm/'+name.removeprefix('harness/') if name.startswith('harness/') else 'tests/'+name)
            require(source in inventory and sha(safe_member(archive,name)) == inventory[source], 'payload source differs: '+name)
    return _finish(spec, run, p, directory, uuid, ids, cases, definitions, fixture_raw, digest, expected_binary)

def _finish(spec, run, p, directory, uuid, ids, cases, definitions, fixture_raw, receipt_hash, binary):
    identity = p['identity']; readback = identity['attestation']['readback']
    token_hex = (uuid+'\n').encode('ascii').hex()
    require(identity.get('marker_matches') is True and identity.get('product_uuid_matches') is True
            and identity.get('host_shared_mounts') == [] and readback['token'] == uuid
            and readback['marker_hex'] == readback['dmi_hex'] == readback['attestation_hex'] == token_hex
            and all(readback[k].get('uid') == 0 and readback[k].get('gid') == 0
                    and readback[k].get('mode') == 0o444 and readback[k].get('nlink') == 1
                    and readback[k].get('type') == 'regular' for k in ('marker','attestation'))
            and p['runtime_network']['canary_accepted'] == 0, 'modern identity/canary differs')
    ns = obj(directory/'namespace-proof-208.json',p['namespace_proof_sha256'],'modern namespace')
    attest = obj(directory/'namespace-attestation-208.json',p['namespace_attestation_sha256'],'modern namespace attestation')
    parent = obj(directory/'parent-namespace.json',p['parent_namespace_sha256'],'modern parent namespace')
    privilege = obj(directory/'privilege-proof.json',p['privilege_proof_sha256'],'modern privilege')
    require(ns == p['namespace_proof']['evaluation'] and parent == p['namespace_proof']['parent']
            and ns['schema'] == 'bashos-syslog208-namespace-v1'
            and attest['schema'] == 'bashos-syslog-namespace-attestation-v1'
            and ns['token'] == ns['dmi_uuid'] == attest['token'] == uuid
            and ns['proc_interfaces'] == ns['sysfs_interfaces'] == ['lo']
            and ns['uid'] == ns['euid'] == 0 and ns['pid1_uid'] == ['0']*4
            and ns['namespaces'] == attest['namespaces'] and ns['outer_namespaces'] == attest['outer_namespaces']
            and all(ns['outer_namespaces'][k] == parent[k] and ns['namespaces'][k] != parent[k] for k in ('mnt','net','pid'))
            and ns['attestation']['sha256'] == p['namespace_attestation_sha256']
            and all(ns['attestation'].get(k) == v for k,v in {'uid':0,'gid':0,'mode':0o444,'nlink':1}.items()),
            'modern namespace proof differs')
    require(privilege == p['privilege_proof'] and privilege['vm_uuid'] == uuid
            and (privilege['uid'],privilege['euid'],privilege['gid'],privilege['egid']) == (2000,2000,2000,2000)
            and privilege['groups'] == [] and privilege['cap_eff'] == '0000000000000000'
            and privilege['no_new_privs'] == '1', 'modern privilege proof differs')
    summary_raw = pinned(directory/'guest-summary.json',p['guest_summary_sha256'],'modern summary')
    require(sha(summary_raw) == run['summary_sha256'] and (directory/'summary.json').read_bytes() == summary_raw,
            'modern summary copy differs')
    summary = json.loads(summary_raw)
    checks = {'selfcheck-'+x for x in CHECKS}; rows = summary['cases']
    require(summary['vm_uuid'] == uuid and summary['binary_sha256'] == binary
            and summary['selected_case_ids'] == sorted(ids) and summary['root_fixtures_allowed'] is False
            and summary['isolation']['links'] == ['lo'] and summary['isolation']['vm_uuid_matches'] is True
            and len(rows) == len(ids)+len(checks) and len({x['id'] for x in rows}) == len(rows)
            and {x['id'] for x in rows} == set(ids)|checks, 'modern summary selection differs')
    by_id = {r['id']:r for r in rows}
    require(all(by_id[c]['group'] == 'selfcheck' and by_id[c]['status'] == 'PASS' for c in checks)
            and set(p['evidence_validation']['selfchecks']) == checks, 'modern selfchecks differ')
    counts = {k:sum(r['status'] == k for r in rows) for k in ('PASS','FAIL','ERROR','SKIP','DEFERRED','MIGRATED','COLLECTED')}
    require(counts == summary['summary'] == p['evidence_validation']['summary']
            and p['evidence_validation']['selected_ids'] == sorted(ids)
            and p['evidence_validation']['fixture_sha256'] == sha(fixture_raw)
            and p['guest_exit_status'] == (1 if counts['FAIL'] else 0), 'modern summary totals differ')
    output = []
    with tarfile.open(directory/'evidence.tar','r:') as archive:
        tar_members(archive)
        require(safe_member(archive,'results/summary.json') == summary_raw, 'modern archived summary differs')
        for cid in checks:
            raw = json.loads(safe_member(archive,'results/selfcheck/'+cid.removeprefix('selfcheck-')+'.json'))
            require(raw == {k:v for k,v in by_id[cid].items() if k != 'kind'}, 'modern selfcheck raw differs')
        for cid in ids:
            row = by_id[cid]; accepted = cases[cid]
            require(row['status'] == accepted['status'] and row['group'] == definitions[cid]['group']
                    and row.get('harness_error') is None and p['case_evidence']['cases'][cid]['framework_status'] == row['status'],
                    'modern reviewed status differs: '+cid)
            raw = safe_member(archive,'results/'+cid+'/candidate.json')
            require(sha(raw) == accepted['raw_sha256'], 'modern raw case differs: '+cid)
            data = json.loads(raw)
            require(data.get('error') is None and data.get('harness_error') is None
                    and data.get('stray_processes') == [] and isinstance(data.get('status'),int)
                    and data.get('setup',{}).get('status') == 0 and data['setup'].get('error') is None
                    and data['setup'].get('stray_processes') == [], 'modern raw case incomplete: '+cid)
            require(accepted['raw_status'] == data['status']
                    and p['case_evidence']['cases'][cid]['sides']['candidate']['raw_status'] == data['status'],
                    'modern raw process status differs: '+cid)
            output.append({'record':row,'definition':definitions[cid],'sources':{},'run':spec['name']})
    cp = p['compatibility']; cp_raw = pinned(directory/'compat/raw.json',cp['raw_sha256'],'modern compatibility data')
    compat = json.loads(cp_raw); handoff_raw = pinned(directory/'compat/handoff.json',cp['handoff_sha256'],'modern compatibility handoff')
    handoff = json.loads(handoff_raw)
    require(compat['schema'] == 'bashos-compat252-raw-v1' and compat['availability_trees_empty'] is True
            and compat['case_directories_absent'] is True and handoff == cp['handoff']
            and (directory/'compat/handoff-guest.json').read_bytes() == handoff_raw
            and (directory/'compat/handoff-after.json').read_bytes() == handoff_raw
            and handoff['schema'] == 'bashos-compat252-handoff-v1' and handoff['status'] == 'PASS'
            and handoff['service_exit'] == 0 and handoff['canary_absent'] is True
            and handoff['vm_uuid'] == uuid and handoff['candidate_sha256'] == binary
            and handoff['fixture_sha256'] == sha(fixture_raw) and handoff['selected_ids'] == sorted(ids)
            and handoff['controller_sha256'] == p['controller_sha256'] and handoff['service_data_sha256'] == sha(cp_raw),
            'modern compatibility data differs')
    protected = compat['protected']
    compat_ns_bytes = base64.b64decode(protected['compat252-namespace.json'],validate=True)
    compat_root_bytes = base64.b64decode(protected['compat252-rootproof.json'],validate=True)
    compat_ns = json.loads(compat_ns_bytes); compat_root = json.loads(compat_root_bytes)
    compat_parent = json.loads((directory/'compat/parent-namespace.json').read_bytes())
    require(sha(compat_root_bytes) == handoff['namespace_proof_sha256']
            and compat_parent == parent and cp['parent_sha256'] == p['parent_namespace_sha256']
            and compat_ns['schema'] == 'bashos-syslog-namespace-attestation-v1'
            and compat_root['schema'] == 'bashos-syslog208-namespace-v1'
            and compat_ns['token'] == compat_root['token'] == compat_root['dmi_uuid'] == uuid
            and compat_root['attestation']['sha256'] == sha(compat_ns_bytes)
            and all(compat_root['attestation'].get(k) == v for k,v in {'uid':0,'gid':0,'mode':0o444,'nlink':1}.items())
            and compat_root['uid'] == compat_root['euid'] == 0 and compat_root['pid1_uid'] == ['0']*4
            and compat_root['proc_interfaces'] == compat_root['sysfs_interfaces'] == ['lo']
            and compat_root['namespaces'] == compat_ns['namespaces']
            and compat_root['outer_namespaces'] == compat_ns['outer_namespaces']
            and all(compat_root['outer_namespaces'][k] == parent[k]
                    and compat_root['namespaces'][k] != parent[k] for k in ('mnt','net','pid')),
            'modern compatibility namespace differs')
    expected_canary = {'PASS':0, 'FAIL':0, 'ERROR':0, 'SKIP':0, 'DEFERRED':0, 'MIGRATED':1}
    require(handoff['original_summary'] == handoff['canary_summary'] == expected_canary
            and cp['checked']['original_summary'] == cp['checked']['canary_summary'] == expected_canary,
            'modern compatibility canary summary differs')
    for kind in ('original','canary'):
        raw_report = base64.b64decode(compat['files'][kind+'/report.json'],validate=True)
        report = json.loads(raw_report)
        require(report['summary'] == expected_canary and len(report['cases']) == 1
                and report['cases'][0]['status'] == 'MIGRATED'
                and base64.b64decode(compat['files'][kind+'/availability/stdout'],validate=True) == b'builtin\n'
                and base64.b64decode(compat['files'][kind+'/availability/stderr'],validate=True) == b'',
                'modern compatibility canary raw differs')
    require(len(handoff['availability']) == 2 and all(item == {'status':0,
            'stdout_sha256':sha(b'builtin\n'),'stderr_sha256':sha(b'')} for item in handoff['availability']),
            'modern compatibility availability differs')
    sources = [pinned(directory/('compat/sources-'+name+'.json'),p['guest_source_attestation_after'],'modern guest source')
               for name in ('before','after-service','after-evaluator')]
    require(sources[0] == sources[1] == sources[2] and handoff['source_attestation_sha256'] == sha(sources[0]),
            'modern source attestations differ')
    source = json.loads(sources[0])
    require(source['files']['candidate']['sha256'] == binary and source['files']['fixture']['sha256'] == sha(fixture_raw)
            and {k:v['sha256'] for k,v in source['files'].items()} == handoff['source_sha256']
            and all(v['uid'] == 0 and v['gid'] == 0 and v['nlink'] == 1 and not (v['mode'] & 0o022)
                    for v in source['files'].values()), 'modern guest source bindings differ')
    evunit = 'bashos-evaluation-'+uuid[:8]+'.service'; cpunit = 'bashos-optional-'+uuid[:8]+'-reference.service'
    ep = p['guest_unit_proofs']['run.log.unit-proof.json']; cph = p['compatibility_unit_proofs']['run.log.unit-proof.json']
    require(handoff['service_proof_sha256'] == cph, 'modern compatibility proof binding differs')
    evproof = unit_proof(directory/'run.log.unit-proof.json',ep,uuid,evunit,p['guest_exit_status'])
    cpproof = unit_proof(directory/'compat/run.log.unit-proof.json',cph,uuid,cpunit,0)
    require(run.get('unit_proof_checks') == {'evaluator':evproof,'compatibility':cpproof},
            'modern unit proofs differ from primary receipt')
    raw_properties = base64.b64decode(protected['compat252-unit.properties'],validate=True).decode('ascii')
    pairs = [line.split('=',1) for line in raw_properties.splitlines()]
    require(all(len(pair) == 2 for pair in pairs) and len(dict(pairs)) == len(pairs)
            and dict(pairs) == cp['checked']['properties'], 'modern compatibility raw unit properties differ')
    require(p['evaluation_properties'] == {'Id':evunit,'ControlGroup':'/system.slice/'+evunit,
            'KillMode':'control-group','NoNewPrivileges':'yes','RestrictSUIDSGID':'yes'}
            and cp['checked']['properties'] == {'Id':cpunit,'ControlGroup':'/system.slice/'+cpunit,
            'KillMode':'control-group','NoNewPrivileges':'yes','RestrictSUIDSGID':'no'}, 'modern unit properties differ')
    teardown = obj(directory/'vm/teardown.json',run['teardown_sha256'],'modern teardown')
    scope = 'parity-vm-'+uuid+'.scope'; boot = teardown['scope_boot_observation']['state']; after = teardown['scope_after']; events = teardown['cgroup_events']
    empty = events.get('removed') is True and events.get('raw_ascii') is None
    if events.get('removed') is False and isinstance(events.get('raw_ascii'),str):
        lines = events['raw_ascii'].splitlines()
        empty = lines.count('populated 0') == 1 and not any(x.startswith('populated ') and x != 'populated 0' for x in lines)
    require(teardown == p['teardown'] and teardown['vm_uuid'] == uuid and teardown['scope_unit'] == scope
            and teardown['clean_poweroff'] is True and teardown['forced_stop'] is False
            and teardown['qemu_exit_status'] == 0 and teardown['poweroff_request'] == run['poweroff_request']
            and teardown['scope_quiescent'] is True and teardown['proof_durable'] is True and empty
            and boot['id'] == scope and boot['active'] == 'active' and boot['load'] == 'loaded'
            and boot['group'] == teardown['scope_cgroup'] and after['id'] in ('',scope)
            and (after['load'] == 'not-found' or after['active'] in ('inactive','failed'))
            and after['group'] == '' and not (directory/'overlay.qcow2').exists(), 'modern VM teardown differs')
    return output, {'name':spec['name'],'groups':run['groups'],'selected_records':len(output),
                    'evidence_format':FORMAT,'candidate_sha256':binary,'vm_uuid':uuid,
                    'primary_receipt_sha256':receipt_hash,'receipt_run':spec['receipt_run'],
                    'provenance_sha256':run['provenance_sha256'],'evidence_sha256':run['evidence_sha256'],
                    'units':{'evaluator':evproof,'compatibility':cpproof},'teardown':teardown,'overlay_discarded':True}
