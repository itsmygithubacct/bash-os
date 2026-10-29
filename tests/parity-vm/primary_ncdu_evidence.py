#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read only a primary-accepted 294 ncdu restoration pair as inert data.

A source-pinned primary receipt is mandatory; the placeholder deliberately
fails closed until primary adjudication and integration. The 303 review is an
independent raw review, not itself primary acceptance.
"""
import base64
import json
import tarfile
from pathlib import Path

from primary_controller_evidence import CHECKS, canonical, deny_noncore, file_sha, pinned, require, safe_member, sha, tar_members, unit_proof

FORMAT = 'primary-qualified-ncdu294-v1'
PRIMARY_RECEIPT_SHA256 = '005d2356753053be73faf3975f1cb49fefe6295a8281859588df92cd3b10aca9'
FREEZE = '3ea406c3e7df04057215b5ea221d8a565475afd1af60fe94850d855d94ff4641'
CONTROLS = '120f49433acd7f44b71d7a3f255346463056268ee05b3089f26371b173623b06'
PAIR = 'dd90410d7383b6f5cc15711cfd656e7bde15d5ab53f6caabe88cc462f81be3e6'
RENDITION = 'a1da960cb0a79e1e5b4721adcfa0bb80681043098305f752d2b1cfeee0a2820d'
SCREEN = '20f5f16598a56f34652ee6242fa46b18fb8f06880903383f97ae228e97958793'
CASES = {
    'migration-terminal213-ncdu-visible-restore-q': '9a82a5ff8965ba213cbe972a553c737a357d39fa93286ef32db0bcfb96600c17',
    'migration-terminal213-ncdu-visible-restore-escape': 'c0bb431691e03a11e69a8ed725eddd5512e7cfa15d6a58b6d07d2118ec05ad25',
    'migration-terminal213-ncdu-visible-restore-ctrl-c': '308d64bf8506ddc2639f453be0dd29f6c998fd893417ba014b465086bbfe3562',
}
CORES = {'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
         'dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
RUNS = {
 'static': {'vm_uuid':'dcf140ce-4ffe-49c4-8e04-2ad9ef2bd7bb', 'provenance_sha256':'456f423fff5c28a43b3bdb01cbe047998f9a17c83598c78fff0fc956ac808950', 'evidence_sha256':'cb76e31f1bee5de732322d142bdd3442bc1a5011032ad99a2df84a192818512b', 'ready_sha256':'5f353049b0dfd7ffa02ad94b1a00921af73ced839f412aa1b104f78223eab741'},
 'dynamic': {'vm_uuid':'20e79bcd-e6ab-4884-a8f6-706b51814561', 'provenance_sha256':'7e9396e560181756bf0ad0832f43385d112c567b877d6ecb2f70bd742decea87', 'evidence_sha256':'1749caee3b371bd436ef47b531b28cf500a082c78e1265401eef779355cf3724', 'ready_sha256':'ec4526c3b1d75eb073eafe006cad7904f1914d2de2113b5b6c74e21609ce3ba1'},
}


def load_qualified_ncdu_run(spec, expected_binary, expected_build):
    require(spec.get('evidence_format') == FORMAT and expected_build in RUNS
            and expected_binary == CORES[expected_build], 'ncdu build or format differs')
    deny_noncore(spec, 'ncdu selection')
    require(spec.get('ledger_scope') == 'core' and spec.get('core_ledger_eligible') is True,
            'ncdu core scope required')
    require(isinstance(PRIMARY_RECEIPT_SHA256, str) and len(PRIMARY_RECEIPT_SHA256) == 64,
            'ncdu primary product acceptance has not been pinned')
    rp = spec['primary_receipt']
    require(rp['sha256'] == PRIMARY_RECEIPT_SHA256, 'ncdu primary receipt pin differs')
    receipt = json.loads(pinned(rp['path'], PRIMARY_RECEIPT_SHA256, 'ncdu primary acceptance'))
    deny_noncore(receipt, 'ncdu receipt')
    require(receipt.get('schema') == 'bashos-terminal294-ncdu-primary-acceptance-v1'
            and receipt.get('decision') == 'accept-six-restoration-observations-for-core-integration'
            and receipt.get('ledger_scope') == 'core' and receipt.get('core_ledger_eligible') is True
            and receipt.get('source_freeze_sha256') == FREEZE
            and receipt.get('controls_acceptance_sha256') == CONTROLS
            and receipt.get('pair_sha256') == PAIR and receipt.get('rendition_sha256') == RENDITION
            and receipt.get('runs') == RUNS and receipt.get('base_commit') == 'b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf'
            and receipt.get('requirement') == {'topic':'ncdu/interactive-browser-pty','id':'r5','behavior':'q/ESC/^C exits and restores the screen and termios'}
            and receipt.get('subject_behavior_executed_on_host') is False, 'ncdu receipt authority differs')
    require(spec.get('groups') == ['terminal'] and spec.get('ids') == sorted(CASES)
            and not spec.get('exclude_ids') and spec.get('name') == 'terminal294-ncdu-restore-' + expected_build,
            'ncdu selection differs')
    pair = json.loads(pinned(spec['pair_review']['path'], PAIR, 'ncdu paired review'))
    rendition = json.loads(pinned(spec['rendition_review']['path'], RENDITION, 'ncdu rendition review'))
    freeze = json.loads(pinned(spec['source_freeze']['path'], FREEZE, 'ncdu frozen source'))
    require(spec['pair_review']['sha256'] == PAIR and spec['rendition_review']['sha256'] == RENDITION
            and spec['source_freeze']['sha256'] == FREEZE and pair['source_freeze_sha256'] == FREEZE
            and pair['controls_acceptance_sha256'] == CONTROLS
            and freeze['pins']['cases'].items() >= CASES.items(), 'ncdu review/source pins differ')
    acceptance = json.loads(pinned(spec['controls_acceptance']['path'], CONTROLS, 'ncdu controls acceptance'))
    require(spec['controls_acceptance']['sha256'] == CONTROLS
            and acceptance.get('decision') == 'accept-controls-only'
            and acceptance.get('source_freeze_sha256') == FREEZE, 'ncdu controls acceptance differs')
    source_root = Path(spec['source_freeze']['path']).parent
    inventory = json.loads(pinned(source_root/'control-files.json', freeze['inventories']['control-files.json'], 'ncdu source inventory'))
    for name in ('tests/parity-vm/suites/migration-terminal213-ncdu-restore.json',
                 'tests/parity-vm/helpers/terminal213_guard.py', 'tests/parity-vm/vm.py',
                 'tests/parity-vm/standard_terminal213.py'):
        require(file_sha(source_root/'control'/name) == inventory[name], 'ncdu frozen source differs: '+name)
    run = RUNS[expected_build]
    paired = pair['runs'][expected_build]
    require(all(paired[k] == v for k, v in run.items()) and paired['candidate_sha256'] == expected_binary,
            'ncdu paired review differs')
    directory = Path(spec['path'])
    primary = receipt['primary_checks'][expected_build]
    require(directory.is_absolute() and str(directory.resolve(strict=True)) == primary['source_result']
            and directory.name == 'ncdu-restore-' + expected_build
            and primary.get('artifact_inventory_verified') is True and primary.get('payload_source_files_verified') == 12, 'ncdu run path or primary review differs')
    prov = json.loads(pinned(directory/'provenance.json', run['provenance_sha256'], 'ncdu provenance'))
    deny_noncore(prov, 'ncdu provenance')
    require(prov.get('status') == 'completed' and prov.get('qualification') == 'complete-evidence-not-product-pass'
            and prov.get('operation') == 'terminal213-run' and prov.get('batch') == 'ncdu-restore'
            and prov.get('candidate') == expected_build and prov.get('candidate_sha256') == expected_binary
            and prov.get('vm_uuid') == run['vm_uuid'] and prov.get('root_fixtures_allowed') is False
            and prov.get('host_mounts') == [] and prov.get('guest_summary_state') == 'validated'
            and prov.get('guest_units_proven_quiescent') is True and prov.get('scope_proven') is True
            and prov.get('overlay_discarded') is True and prov.get('guest_exit_status') == 0,
            'ncdu provenance is incomplete')
    require(all(prov.get(k) is True for k in ('candidate_unchanged','candidate_snapshot_unchanged',
            'prepared_unchanged','controller_unchanged','module_unchanged','suites_unchanged',
            'helpers_unchanged','guest_unit_proofs_unchanged','evidence_unchanged')),
            'ncdu retained artifact identity differs')
    identity = prov['identity']
    readback = identity['attestation']['readback']
    marker_hex = (run['vm_uuid'] + '\n').encode('ascii').hex()
    require(identity.get('marker_matches') is True and identity.get('product_uuid_matches') is True
            and readback.get('token') == run['vm_uuid']
            and readback.get('marker_hex') == readback.get('dmi_hex') == readback.get('attestation_hex') == marker_hex
            and all(readback[k].get('uid') == 0 and readback[k].get('gid') == 0
                    and readback[k].get('mode') == 0o444 and readback[k].get('nlink') == 1
                    and readback[k].get('type') == 'regular' for k in ('marker','attestation'))
            and identity.get('host_shared_mounts') == [] and prov['runtime_network'].get('canary_accepted') == 0,
            'ncdu guest identity or network isolation differs')
    core = prov['workspace_core_before']
    core_paths = {Path(path).name: path for path in core}
    require(core == prov['workspace_core_after'] and len(core) == 2
            and set(core_paths) == {'bash-static', 'bash'}
            and all(Path(path).is_absolute() for path in core)
            and Path(core_paths['bash-static']).parent == Path(core_paths['bash']).parent
            and core[core_paths['bash-static']] == CORES['static']
            and core[core_paths['bash']] == CORES['dynamic']
            and spec['core_binary_path'] == core_paths['bash-static' if expected_build == 'static' else 'bash']
            and prov['core_before'] == prov['core_after']
            and sorted(prov['core_before'].values()) == sorted(CORES.values()), 'ncdu core before/after differs')
    namespace = json.loads(pinned(directory/'namespace-proof-208.json', prov['namespace_proof_sha256'], 'ncdu namespace'))
    attestation = json.loads(pinned(directory/'namespace-attestation-208.json', prov['namespace_attestation_sha256'], 'ncdu namespace attestation'))
    parent = json.loads(pinned(directory/'parent-namespace.json', prov['parent_namespace_sha256'], 'ncdu parent namespace'))
    privilege = json.loads(pinned(directory/'privilege-proof.json', prov['privilege_proof_sha256'], 'ncdu privilege'))
    require(namespace.get('token') == namespace.get('dmi_uuid') == attestation.get('token') == run['vm_uuid']
            and namespace.get('proc_interfaces') == namespace.get('sysfs_interfaces') == ['lo']
            and namespace.get('schema') == 'bashos-syslog208-namespace-v1'
            and namespace.get('uid') == namespace.get('euid') == 0 and namespace.get('pid1_uid') == ['0'] * 4
            and namespace['attestation'].get('uid') == namespace['attestation'].get('gid') == 0
            and namespace['attestation'].get('mode') == 0o444 and namespace['attestation'].get('nlink') == 1
            and attestation.get('schema') == 'bashos-syslog-namespace-attestation-v1'
            and namespace['namespaces'] == attestation['namespaces'] and namespace['outer_namespaces'] == attestation['outer_namespaces']
            and all(namespace['outer_namespaces'][k] == parent[k] and namespace['namespaces'][k] != parent[k] for k in ('mnt','net','pid'))
            and prov['namespace_proof']['evaluation'] == namespace and prov['namespace_proof']['parent'] == parent
            and namespace['attestation']['sha256'] == prov['namespace_attestation_sha256'], 'ncdu namespace proof differs')
    require(privilege == prov['privilege_proof'] and privilege.get('vm_uuid') == run['vm_uuid']
            and (privilege.get('uid'),privilege.get('euid'),privilege.get('gid'),privilege.get('egid')) == (2000,2000,2000,2000)
            and privilege.get('groups') == [] and privilege.get('no_new_privs') == '1'
            and privilege.get('cap_eff') == '0000000000000000', 'ncdu privilege proof differs')
    vmid = run['vm_uuid']; eval_unit = 'bashos-evaluation-'+vmid[:8]+'.service'
    compat_unit = 'bashos-optional-'+vmid[:8]+'-reference.service'
    evhash = prov['guest_unit_proofs']['run.log.unit-proof.json']; cphash = prov['compatibility_unit_proofs']['run.log.unit-proof.json']
    evaluator_proof = unit_proof(directory/'run.log.unit-proof.json', evhash, vmid, eval_unit, 0)
    compat_proof = unit_proof(directory/'compat/run.log.unit-proof.json', cphash, vmid, compat_unit, 0)
    require(primary['units'] == {'evaluator':evaluator_proof, 'compatibility':compat_proof}, 'ncdu primary unit proof differs')
    require(prov['evaluation_properties'] == {'Id':eval_unit,'ControlGroup':'/system.slice/'+eval_unit,'KillMode':'control-group','NoNewPrivileges':'yes','RestrictSUIDSGID':'yes'}
            and prov['compatibility']['checked']['properties'] == {'Id':compat_unit,'ControlGroup':'/system.slice/'+compat_unit,'KillMode':'control-group','NoNewPrivileges':'yes','RestrictSUIDSGID':'no'}, 'ncdu unit properties differ')
    cp = prov['compatibility']
    handoff_raw = pinned(directory/'compat/handoff.json', cp['handoff_sha256'], 'ncdu compatibility handoff')
    handoff = json.loads(handoff_raw)
    require((directory/'compat/handoff-guest.json').read_bytes() == handoff_raw
            and (directory/'compat/handoff-after.json').read_bytes() == handoff_raw
            and handoff == cp['handoff'] and handoff.get('status') == 'PASS' and handoff.get('canary_absent') is True
            and handoff.get('vm_uuid') == vmid and handoff.get('candidate_sha256') == expected_binary
            and handoff.get('service_proof_sha256') == cphash and handoff.get('service_exit') == 0
            and handoff.get('fixture_sha256') == prov['frozen_fixture_sha256']
            and handoff.get('selected_ids') == sorted(list(CASES) + ['migration-terminal213-control-key','migration-terminal213-control-screen'])
            and handoff.get('source_attestation_sha256') == prov['guest_source_attestation_after'], 'ncdu compatibility handoff differs')
    teardown = prov['teardown']
    recorded_teardown = json.loads(pinned(directory/'vm/teardown.json', prov['artifacts']['vm/teardown.json']['sha256'], 'ncdu teardown'))
    require(recorded_teardown == teardown and primary.get('poweroff_request') == teardown['poweroff_request']
            and primary.get('scope_quiescent') is True, 'ncdu durable teardown object differs')
    require(teardown.get('vm_uuid') == run['vm_uuid'] and teardown.get('qemu_exit_status') == 0
            and teardown.get('forced_stop') is False and teardown.get('scope_quiescent') is True
            and teardown.get('proof_durable') is True and teardown.get('cgroup_events',{}).get('removed') is True
            and teardown.get('poweroff_request') == (255 if expected_build == 'static' else 0)
            and not (directory/'overlay.qcow2').exists(), 'ncdu teardown incomplete')
    require(file_sha(directory/'candidate.snapshot') == expected_binary
            and file_sha(spec['core_binary_path']) == expected_binary
            and file_sha(directory/'evidence.tar') == run['evidence_sha256']
            and file_sha(directory/'payload.tar') == prov['payload_sha256'], 'ncdu artifact hash differs')
    ready = json.loads(pinned(spec['independent_ready']['path'], run['ready_sha256'], 'ncdu independent review'))
    require(ready['candidate_sha256'] == expected_binary and ready['vm_uuid'] == run['vm_uuid']
            and ready['provenance_sha256'] == run['provenance_sha256']
            and ready['evidence_sha256'] == run['evidence_sha256']
            and ready['source_freeze_sha256'] == FREEZE and ready['controls_acceptance_sha256'] == CONTROLS,
            'ncdu independent review binding differs')
    review_dir = Path(spec['independent_ready']['path']).parent
    require(ready.get('schema') == 'bashos-terminal303-ncdu-restore-'+expected_build+'-ready-v1'
            and ready.get('state') == 'ADDITIVE_RAW_REVIEW_READY_FOR_PRIMARY_ADJUDICATION'
            and ready.get('subject_or_host_behavior_executed') is False, 'ncdu READY state differs')
    audit = json.loads(pinned(review_dir/'assessment.json', ready['assessment_sha256'], 'ncdu review assessment'))
    for name, field in (('raw-inventory.json','raw_inventory_sha256'),
                        ('artifact-files.json','file_inventory_sha256'), ('MANIFEST.sha256','manifest_sha256'), ('REVIEW.md','review_sha256')):
        pinned(review_dir/name, ready[field], 'ncdu review '+name)
    inventory = json.loads(pinned(review_dir/'artifact-files.json', ready['file_inventory_sha256'], 'ncdu review file inventory'))
    require(inventory.get('schema') == 'bashos-terminal303-product-file-inventory-v1'
            and set(inventory['files']) == {'REVIEW.md','assessment.json','raw-inventory.json','review-restore303.py','seal-restore303.py'},
            'ncdu review source inventory differs')
    for name, item in inventory['files'].items():
        path = review_dir/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item['bytes']
                and format(path.stat().st_mode & 0o7777, '04o') == item['mode']
                and file_sha(path) == item['sha256'], 'ncdu review file differs: '+name)
    require(audit.get('requirement') == 'ncdu/interactive-browser-pty/r5' and audit.get('vm_uuid') == vmid
            and audit.get('candidate_sha256') == expected_binary and audit.get('provenance_sha256') == run['provenance_sha256']
            and audit.get('evidence_sha256') == run['evidence_sha256'] and audit.get('source_freeze_sha256') == FREEZE
            and audit.get('primary_controls_receipt_sha256') == CONTROLS and audit.get('controls_local_key_and_screen') == 'PASS'
            and set(audit.get('mandatory_selfchecks_passed',[])) == {'selfcheck-'+x for x in CHECKS}
            and audit['service_proofs']['evaluator']['proof_sha256'] == evhash
            and audit['service_proofs']['compatibility']['proof_sha256'] == cphash
            and audit['teardown']['poweroff_request'] == teardown['poweroff_request'], 'ncdu review audit differs')
    require(set(audit['cases']) == set(CASES) and all(audit['cases'][cid]['framework_status'] == 'PASS'
            and audit['cases'][cid]['raw_status'] == 0 and audit['cases'][cid]['completed_steps'] == list(range(6))
            and audit['cases'][cid]['raw_replay_primary_cells_and_cursor_match'] is True
            and audit['cases'][cid]['screen_sha256'] == SCREEN
            and audit['cases'][cid]['input_hex'] == ['0a', {'q':'71','escape':'1b','ctrl-c':'03'}[cid.removeprefix('migration-terminal213-ncdu-visible-restore-')]]
            and audit['cases'][cid]['termios_before_after_identical'] is True for cid in CASES), 'ncdu review case audit differs')
    summary = json.loads(pinned(directory/'guest-summary.json', prov['guest_summary_sha256'], 'ncdu summary'))
    require(summary['binary_sha256'] == expected_binary and len(summary['cases']) == 18
            and all(row['status'] == 'PASS' for row in summary['cases'])
            and {r['id'] for r in summary['cases'] if r['id'].startswith('selfcheck-')} == {'selfcheck-'+x for x in CHECKS},
            'ncdu summary or selfchecks differ')
    rows = {r['id']:r for r in summary['cases']}
    controls = {'migration-terminal213-control-key', 'migration-terminal213-control-screen'}
    require(len(rows) == 18 and set(rows) == set(CASES) | controls | {'selfcheck-'+x for x in CHECKS}
            and all(rows[c]['group'] == 'terminal' and rows[c]['status'] == 'PASS' for c in set(CASES) | controls),
            'ncdu product or local control records differ')
    require(prov.get('product_case_ids') == list(CASES) and prov.get('control_case_ids') == sorted(controls)
            and all(prov['canonical_case_sha256'].get(cid) == digest for cid, digest in CASES.items())
            and prov['evidence_validation']['archive_sha256'] == run['evidence_sha256'],
            'ncdu provenance case mapping differs')
    require(set(primary['cases']) == set(CASES) and all(primary['cases'][cid] == {
            'status':'PASS', 'exit_input_hex':{'q':'71','escape':'1b','ctrl-c':'03'}[cid.removeprefix('migration-terminal213-ncdu-visible-restore-')],
            'raw_screen_sha256':SCREEN, 'all_steps_reached':True, 'termios_restored':True} for cid in CASES),
            'ncdu primary case evidence differs')
    with tarfile.open(directory/'payload.tar', 'r:') as archive:
        tar_members(archive)
        fixture_raw = safe_member(archive, 'harness/suites/optional-frozen.json')
        require(sha(fixture_raw) == prov['frozen_fixture_sha256'], 'ncdu frozen fixture differs')
        fixture = json.loads(fixture_raw)
        definitions = {c['id']:c for c in fixture['cases'] if c['id'] in CASES}
        require(set(definitions) == set(CASES) and all(canonical(definitions[k]) == v for k,v in CASES.items()),
                'ncdu case definitions differ')
        require(sha(safe_member(archive, 'harness/helpers/terminal213_guard.py')) ==
                'dea91736a54538ae758c4b416d0eb48b2fd4a4ba331af789967c2de0ccf769c6', 'ncdu guard differs')
    with tarfile.open(directory/'evidence.tar', 'r:') as archive:
        tar_members(archive)
        for cid in CASES:
            raw = json.loads(safe_member(archive, 'results/'+cid+'/candidate.json'))
            stream = base64.b64decode(raw['screen_base64'], validate=True)
            key = cid.removeprefix('migration-terminal213-ncdu-visible-restore-')
            reviewed = rendition['runs'][expected_build]['cases'][key]
            require(sha(stream) == SCREEN == reviewed['raw_screen_sha256']
                    and reviewed['character_and_reverse_cells_equal'] is True and reviewed['cursor_equal'] is True
                    and raw['status'] == 0 and raw['signal'] is None and raw['error'] is None
                    and raw['harness_error'] is None and raw['terminal_restored'] is True
                    and raw['termios_before'] == raw['termios_after'], 'ncdu restoration data differs')
    return ([{'record':rows[cid], 'definition':definitions[cid], 'sources':{}, 'run':spec['name']} for cid in sorted(CASES)],
            {'name':spec['name'], 'groups':['terminal'], 'selected_records':3, 'evidence_format':FORMAT,
             'candidate_sha256':expected_binary, 'vm_uuid':run['vm_uuid'], 'primary_receipt_sha256':PRIMARY_RECEIPT_SHA256,
             'provenance_sha256':run['provenance_sha256'], 'evidence_sha256':run['evidence_sha256'],
             'review_sha256':run['ready_sha256'], 'poweroff_request':teardown['poweroff_request']})
