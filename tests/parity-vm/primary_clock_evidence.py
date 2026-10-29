#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the one primary-accepted clock342 receipt as inert, source-bound data.

This adapter deliberately does not replay 315's raw behavioral review. Its
receipt digest is a reviewed source trust anchor, not a digital signature.
"""
import base64
import json
import re
import stat
import tarfile
from pathlib import Path

from primary_controller_evidence import (
    CHECKS, canonical, deny_noncore, file_sha, pinned, require, safe_member,
    sha, tar_members, unit_proof,
)

CLOCK_RECEIPT_SHA256 = '8f34d1fd8422734a55f533bc332025772eb68c55504df593224f5d48967ce0a0'
CLOCK_FREEZE_SHA256 = 'b78962a627801aa3d9507a8aec19e22fba492ed31f3e210b2b97dd59a7858b78'
CONTROL_ACCEPTANCE_SHA256 = 'a577c0c16f91beb0fd90639c669a983870b19da71d96c962b9016cab12ec27a1'
REVIEW_SHA256 = '90390fc1705da3e10512b2f238ce2584859379e5feb94eb66b95a3bff8138914'
FORMAT = 'primary-qualified-clock342-v1'
CORES = {'static': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
         'dynamic': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
PRODUCT_REQUIREMENTS = {
    'migration-clock254-domain-boottime': 'bashclock/clock_domain_reads/r1',
    'migration-clock254-domain-monotonic': 'bashclock/clock_domain_reads/r1',
    'migration-clock254-domain-realtime': 'bashclock/clock_domain_reads/r1',
    'migration-clock254-boundary-large-epoch': 'bashclock/clock_domain_reads/r3',
    'migration-clock254-boundary-max-nanos': 'bashclock/clock_domain_reads/r3',
    'migration-clock254-boundary-negative-epoch': 'bashclock/clock_domain_reads/r3',
    'migration-clock254-boundary-zero': 'bashclock/clock_domain_reads/r3',
    'migration-clock254-since-borrow': 'bashclock/since_arithmetic/r2',
    'migration-clock254-since-exact-zero': 'bashclock/since_arithmetic/r3',
    'migration-clock254-since-future-fraction': 'bashclock/since_arithmetic/r3',
    'migration-clock254-since-future-integer': 'bashclock/since_arithmetic/r3',
    'migration-clock254-since-clock-error': 'bashclock/since_arithmetic/r5',
}


def artifact_membership(directory, provenance):
    """Verify the retained artifact inventory as bytes; never hash an overlay.

    This is an integrity check, not a second interpretation of the raw traces;
    complete behavioral validation belongs to the pinned 315 review.
    """
    directory = Path(directory)
    overlay = directory/'overlay.qcow2'
    require(not overlay.exists() and not overlay.is_symlink(), 'clock overlay is retained')
    inventory = provenance['artifacts']
    require(isinstance(inventory, dict), 'missing original artifact inventory')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*')
              if p.relative_to(directory).as_posix() not in ('provenance.json', 'provenance.sha256')}
    require(actual == set(inventory), 'original clock artifact membership changed')
    for name, expected in inventory.items():
        path = directory / name
        info = path.lstat()
        require(format(stat.S_IMODE(info.st_mode), '04o') == expected['mode'],
                'clock artifact mode differs: ' + name)
        if expected['type'] == 'file':
            require(stat.S_ISREG(info.st_mode) and info.st_size == expected['bytes']
                    and file_sha(path) == expected['sha256'], 'clock artifact file differs: ' + name)
        elif expected['type'] == 'directory':
            require(stat.S_ISDIR(info.st_mode), 'clock artifact directory differs: ' + name)
        else:
            raise ValueError('unsupported clock artifact type: ' + name)


def review_data(accepted, provenance, expected_build, cid, expected_binary):
    """Bind the already accepted 315 review and its small retained diagnostics."""
    path = Path(accepted['ready_path'])
    ready = json.loads(pinned(path, accepted['ready_sha256'], 'clock independent review'))
    require(accepted['source_review_sha256'] == accepted['ready_sha256']
            and ready.get('schema') == 'bashos-clock315-product-ready-v1'
            and ready.get('state') == 'READY_FOR_PRIMARY_PRODUCT_REVIEW'
            and ready.get('source_only_review') is True
            and ready.get('injected_sample_is_not_kernel_or_libc_observation') is True
            and ready.get('case_id') == cid and ready.get('candidate') == expected_build
            and ready.get('vm_uuid') == accepted['vm_uuid']
            and ready.get('independent_verdict') == accepted['classification']
            and ready.get('mismatches') == accepted['mismatches']
            and ready.get('provenance_sha256') == accepted['provenance_sha256']
            and ready.get('evidence_sha256') == accepted['evidence_sha256']
            and ready.get('result_diagnostic_sha256') == accepted['result_sha256']
            and ready.get('requirement_key') == PRODUCT_REQUIREMENTS[cid]
            and ready.get('supporting_control_only') is False
            and ready.get('freeze_sha256') == CLOCK_FREEZE_SHA256
            and ready.get('control_acceptance_sha256') == CONTROL_ACCEPTANCE_SHA256,
            'clock independent review identity differs')
    directory = path.parent
    require((directory/'READY.sha256').read_text() == accepted['ready_sha256'] + '  READY.json\n',
            'clock independent review sidecar differs')
    inventory = json.loads(pinned(directory/'ARTIFACTS.json', ready['artifact_inventory_sha256'],
                                  'clock review artifact inventory'))
    require(inventory.get('schema') == 'bashos-clock315-product-artifacts-v1'
            and set(inventory['files']) == {'audit.json', 'inbound-inventory.json',
                 'clock254-control.json', 'clock254-result.json', 'REVIEW.md'},
            'clock review artifact list differs')
    actual = {p.name for p in directory.iterdir()}
    require(actual == set(inventory['files']) | {'ARTIFACTS.json','READY.json','READY.sha256'},
            'clock review artifact membership changed')
    for name, entry in inventory['files'].items():
        data_path = directory/name
        info = data_path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == entry['bytes']
                and format(stat.S_IMODE(info.st_mode), '04o') == entry['mode']
                and file_sha(data_path) == entry['sha256'], 'clock review artifact differs: ' + name)
    audit = json.loads((directory/'audit.json').read_bytes())
    obs = audit.get('observation', {})
    require(audit.get('schema') == 'bashos-clock288-product-audit-315-v1'
            and audit.get('candidate') == expected_build and audit.get('candidate_sha256') == expected_binary
            and audit.get('case_id') == cid and audit.get('vm_uuid') == accepted['vm_uuid']
            and audit.get('case_sha256') == provenance['canonical_case_sha256']
            and audit.get('provenance_sha256') == accepted['provenance_sha256']
            and audit.get('evidence_sha256') == accepted['evidence_sha256']
            and audit.get('payload_sha256') == provenance['payload_sha256']
            and audit.get('source_only_review') is True and audit.get('clean_poweroff_scope_removed') is True
            and audit.get('synthetic_injection_not_kernel_libc_result') is True
            and audit.get('independent_verdict') == audit.get('framework_status')
                == audit.get('fixture_classification') == accepted['classification']
            and obs.get('classification') == accepted['classification']
            and obs.get('requirement_key') == PRODUCT_REQUIREMENTS[cid]
            and obs.get('mismatches') == accepted['mismatches']
            and obs.get('stdout_base64') == accepted['observed_stdout_base64']
            and obs.get('result_sha256') == accepted['result_sha256']
            and obs.get('control_sha256') == provenance['case_evidence']['control_sha256'],
            'clock independent review audit differs')
    require(set(audit.get('selfcheck_ids', [])) == {'selfcheck-'+x for x in CHECKS}
            and len(audit['selfcheck_ids']) == 13, 'clock reviewed selfchecks differ')
    result_raw = (directory/'clock254-result.json').read_bytes()
    control_raw = (directory/'clock254-control.json').read_bytes()
    require(sha(result_raw) == accepted['result_sha256']
            and sha(control_raw) == provenance['case_evidence']['control_sha256'],
            'clock diagnostic digest differs')
    result, control = json.loads(result_raw), json.loads(control_raw)
    require(result.get('schema') == 'bashos-clock254-result-v1'
            and result.get('classification') == accepted['classification']
            and result.get('token') == accepted['vm_uuid']
            and result.get('case') == cid.removeprefix('migration-clock254-')
            and result.get('control_sha256') == sha(control_raw)
            and control.get('classification') == 'CONTROL_PASS' and control.get('token') == accepted['vm_uuid']
            and result.get('trace', {}).get('stdout_base64') == accepted['observed_stdout_base64'],
            'clock retained diagnostic classification differs')
    return ready, audit


def load_qualified_clock_run(spec, expected_binary, expected_build):
    require(spec.get('evidence_format') == FORMAT, 'wrong clock evidence format')
    deny_noncore(spec, 'clock selection')
    require(spec.get('core_ledger_eligible') is True and spec.get('ledger_scope') == 'core'
            and expected_build in CORES and expected_binary == CORES[expected_build],
            'explicit recorded core build required')
    receipt_pin = spec.get('primary_receipt', {})
    require(isinstance(receipt_pin, dict) and receipt_pin.get('sha256') == CLOCK_RECEIPT_SHA256,
            'clock receipt pin is not the accepted source authority')
    receipt = json.loads(pinned(receipt_pin['path'], CLOCK_RECEIPT_SHA256, 'clock primary receipt'))
    deny_noncore(receipt, 'clock primary receipt')
    require(receipt.get('schema') == 'bashos-clock288-primary-acceptance-v1'
            and receipt.get('decision') == 'accept-26-bounded-product-observations-for-reviewed-integration'
            and receipt.get('core_ledger_eligible') is True and receipt.get('ledger_scope') == 'core'
            and receipt.get('source_freeze_sha256') == CLOCK_FREEZE_SHA256
            and receipt.get('control_acceptance_sha256') == CONTROL_ACCEPTANCE_SHA256
            and receipt.get('independent_ready_sha256') == REVIEW_SHA256,
            'clock primary receipt authority differs')
    run_id = spec.get('receipt_run')
    require(isinstance(run_id, str) and re.fullmatch(r'[A-Za-z0-9_-]+', run_id) is not None
            and run_id in receipt.get('runs', {}), 'unknown clock receipt selection')
    accepted = receipt['runs'][run_id]
    deny_noncore(accepted, 'accepted clock run')
    cid, vm_uuid = accepted['case'], accepted['vm_uuid']
    require(cid in PRODUCT_REQUIREMENTS and accepted.get('requirement') == PRODUCT_REQUIREMENTS[cid]
            and accepted.get('build') == expected_build and accepted.get('candidate_sha256') == expected_binary
            and run_id == expected_build + '-' + cid and spec.get('name') == 'clock342-' + run_id
            and accepted.get('classification') in ('PASS','FAIL'), 'clock build, label or core case differs')
    require(spec.get('groups') == ['shell'] and spec.get('ids') == [cid] and not spec.get('exclude_ids'),
            'clock selection differs from accepted case')
    directory = Path(spec['path'])
    require(directory.is_absolute() and str(directory.resolve(strict=True)) == accepted['source_result'],
            'clock original result path differs')
    freeze_pin = spec.get('source_freeze', {})
    require(isinstance(freeze_pin, dict) and freeze_pin.get('sha256') == CLOCK_FREEZE_SHA256,
            'clock source freeze pin differs')
    freeze_path = Path(freeze_pin['path'])
    freeze = json.loads(pinned(freeze_path, CLOCK_FREEZE_SHA256, 'clock source freeze'))
    require(freeze.get('schema') == 'bashos-clock287-primary-source-freeze-v1'
            and freeze.get('candidate_sha256', {}).get(expected_build) == expected_binary,
            'clock source freeze identity differs')
    source_root = freeze_path.parent
    index = json.loads(pinned(source_root/'clock254-index.json', freeze['clock_index_sha256'], 'clock index'))
    require(index['case_sha256'] == freeze['case_sha256'] and cid in index['product_ids'], 'clock case index differs')
    provenance = json.loads(pinned(directory/'provenance.json', accepted['provenance_sha256'], 'clock provenance'))
    require((directory/'provenance.sha256').read_text() == accepted['provenance_sha256'] + '  provenance.json\n',
            'clock provenance sidecar differs')
    deny_noncore(provenance, 'clock provenance')
    require(provenance.get('operation') == 'clock254-run' and provenance.get('status') == 'completed'
            and provenance.get('qualification') == 'complete-evidence-not-product-pass'
            and provenance.get('candidate') == expected_build and provenance.get('case') == cid
            and provenance.get('candidate_sha256') == expected_binary and provenance.get('vm_uuid') == vm_uuid
            and provenance.get('selected_case_ids') == [cid] and provenance.get('canonical_case_sha256') == freeze['case_sha256'][cid]
            and provenance.get('controller_sha256') == freeze['controller_sha256']
            and provenance.get('module_sha256') == freeze['module_sha256']
            and provenance.get('case_index_sha256') == freeze['clock_index_sha256']
            and provenance.get('specification_sha256') == freeze['clock_spec_sha256']
            and provenance.get('qualification267_primary_receipt_sha256') == freeze['compatibility_qualification_sha256']
            and provenance.get('qualification267_sha256') == freeze['compatibility_provenance_sha256'][expected_build]
            and provenance.get('root_fixtures_allowed') is False and provenance.get('host_mounts') == []
            and provenance.get('identity', {}).get('marker_matches') is True
            and provenance.get('identity', {}).get('product_uuid_matches') is True
            and not provenance.get('identity', {}).get('host_shared_mounts')
            and provenance.get('runtime_network', {}).get('canary_accepted') == 0,
            'clock original provenance identity differs')
    require(all(provenance.get(key) is True for key in (
        'candidate_unchanged','candidate_snapshot_unchanged','prepared_unchanged','controller_unchanged',
        'module_unchanged','suite_unchanged','helper_unchanged','host_validator_unchanged',
        'guest_unit_proofs_unchanged','compatibility_unit_proofs_unchanged',
        'compatibility_raw_unchanged','compatibility_handoff_unchanged','evidence_unchanged',
        'compat_unit_quiescence_proven','evaluation_unit_quiescence_proven','unit_quiescence_proven','scope_proven',
        'overlay_discarded')), 'clock source or lifecycle not proven')
    for prefix in ('core','workspace_core'):
        before, after = provenance[prefix+'_before'], provenance[prefix+'_after']
        names = {Path(path).name: value for path, value in before.items()}
        require(before == after and set(names) == {'bash','bash-static'} and len(before) == 2
                and names['bash-static' if expected_build == 'static' else 'bash'] == expected_binary,
                'clock original core build changed')
    recorded = [path for path, value in provenance['workspace_core_before'].items()
                if Path(path).name == ('bash-static' if expected_build == 'static' else 'bash') and value == expected_binary]
    core_path = Path(spec['core_binary_path'])
    require(len(recorded) == 1 and core_path.is_absolute() and str(core_path) == recorded[0]
            and file_sha(core_path) == expected_binary, 'clock configured core binary differs')
    artifact_membership(directory, provenance)
    overlay = directory/'overlay.qcow2'
    require(not overlay.exists() and not overlay.is_symlink(), 'clock overlay is retained')

    summary_raw = pinned(directory/'guest-summary.json', provenance['guest_summary_sha256'], 'clock guest summary')
    summary = json.loads(summary_raw)
    deny_noncore(summary, 'clock guest summary')
    require(summary.get('vm_uuid') == vm_uuid and summary.get('binary_sha256') == expected_binary
            and summary.get('selected_case_ids') == [cid] and summary.get('root_fixtures_allowed') is False
            and summary.get('isolation', {}).get('links') == ['lo']
            and summary.get('isolation', {}).get('vm_uuid_matches') is True
            and provenance.get('guest_summary_state') == 'validated', 'clock summary identity differs')
    checks = {'selfcheck-'+name for name in CHECKS}
    rows = summary['cases']
    require(len(rows) == 14 and len({x['id'] for x in rows}) == 14
            and {x['id'] for x in rows} == checks | {cid}
            and set(provenance['evidence_validation']['selfchecks']) == checks
            and all(x['status'] == 'PASS' for x in rows if x['id'] in checks), 'clock mandatory selfchecks differ')
    selected = [x for x in rows if x['id'] == cid and x['group'] == 'shell']
    require(len(selected) == 1 and selected[0]['status'] == accepted['classification']
            and provenance.get('case_evidence') == accepted['case_evidence']
            and provenance['case_evidence']['framework_status'] == accepted['classification']
            and provenance['case_evidence']['observation']['classification'] == accepted['classification'],
            'clock product classification differs')
    require(provenance['guest_exit_status'] == (0 if accepted['classification'] == 'PASS' else 1),
            'clock framework exit differs')
    counts = {name:sum(row['status'] == name for row in rows)
              for name in ('PASS','FAIL','ERROR','SKIP','DEFERRED','MIGRATED','COLLECTED')}
    require(summary['summary'] == provenance['evidence_validation']['summary'] == counts,
            'clock summary counts differ')
    require(file_sha(directory/'payload.tar') == provenance['payload_sha256']
            and file_sha(directory/'evidence.tar') == accepted['evidence_sha256']
                == provenance['evidence_validation']['archive_sha256']
            and file_sha(directory/'candidate.snapshot') == expected_binary, 'clock archived data changed')
    with tarfile.open(directory/'payload.tar', 'r:') as archive:
        members = tar_members(archive)
        require(all(m.isfile() for m in members), 'clock payload contains unexpected directory')
        fixture_raw = safe_member(archive,'harness/suites/optional-frozen.json')
        fixture = json.loads(fixture_raw)
        require(fixture.get('schema') == 1 and len(fixture['cases']) == 1
                and sha(fixture_raw) == provenance['frozen_fixture_sha256'], 'clock frozen fixture differs')
        case = fixture['cases'][0]
        deny_noncore(case, 'clock case')
        require(case['id'] == cid and case['group'] == 'shell' and case['driver'] == 'plain'
                and canonical(case) == freeze['case_sha256'][cid]
                and case.get('helpers_sha256') == index['helper_sha256'], 'clock case definition differs')
        for helper, digest in index['helper_sha256'].items():
            require(sha(safe_member(archive,'harness/'+helper)) == digest, 'clock helper payload differs')
    require(provenance['evidence_validation']['fixture_sha256'] == sha(fixture_raw)
            and provenance['evidence_validation']['selected_ids'] == [cid], 'clock fixture provenance differs')
    ready, audit = review_data(accepted, provenance, expected_build, cid, expected_binary)
    require(audit['observation']['request_clock_id_observed'] == accepted['case_evidence']['observation']['clock_id_observed']
            and audit['observation']['exit_status'] == accepted['case_evidence']['observation']['candidate_exit'],
            'clock reviewed trace outcome differs')

    compatibility = provenance['compatibility']
    compat_raw = pinned(directory/'compat/raw.json', compatibility['raw_sha256'], 'clock compatibility raw')
    handoff_raw = pinned(directory/'compat/handoff.json', compatibility['handoff_sha256'], 'clock compatibility handoff')
    handoff = json.loads(handoff_raw)
    require((directory/'compat/handoff-guest.json').read_bytes() == handoff_raw
            and (directory/'compat/handoff-after.json').read_bytes() == handoff_raw
            and compatibility['handoff'] == handoff and handoff.get('status') == 'PASS'
            and handoff.get('service_exit') == 0 and handoff.get('canary_absent') is True
            and handoff.get('vm_uuid') == vm_uuid and handoff.get('selected_ids') == [cid]
            and handoff.get('candidate_sha256') == expected_binary
            and handoff.get('fixture_sha256') == sha(fixture_raw)
            and handoff.get('controller_sha256') == provenance['controller_sha256']
            and handoff.get('service_data_sha256') == sha(compat_raw), 'clock compatibility handoff differs')
    eval_unit = 'bashos-evaluation-'+vm_uuid[:8]+'.service'
    compat_unit = 'bashos-optional-'+vm_uuid[:8]+'-reference.service'
    require(provenance['evaluation_properties'] == {'Id':eval_unit,'ControlGroup':'/system.slice/'+eval_unit,
            'KillMode':'control-group','NoNewPrivileges':'yes','RestrictSUIDSGID':'yes'}
            and compatibility['checked']['properties'] == {'Id':compat_unit,'ControlGroup':'/system.slice/'+compat_unit,
            'KillMode':'control-group','NoNewPrivileges':'yes','RestrictSUIDSGID':'no'}, 'clock unit properties differ')
    ep = provenance['guest_unit_proofs']['run.log.unit-proof.json']
    cp = provenance['compatibility_unit_proofs']['run.log.unit-proof.json']
    require(handoff['service_proof_sha256'] == cp and audit['evaluation_unit']['sha256'] == ep
            and audit['compatibility_unit']['sha256'] == cp, 'clock unit proof binding differs')
    evaluator = unit_proof(directory/'run.log.unit-proof.json', ep, vm_uuid, eval_unit, provenance['guest_exit_status'])
    service = unit_proof(directory/'compat/run.log.unit-proof.json', cp, vm_uuid, compat_unit, 0)
    namespace = json.loads(pinned(directory/'namespace-proof-208.json', provenance['namespace_proof_sha256'], 'clock namespace proof'))
    privilege = json.loads(pinned(directory/'privilege-proof.json', provenance['privilege_proof_sha256'], 'clock privilege proof'))
    require(namespace.get('token') == namespace.get('dmi_uuid') == vm_uuid
            and namespace.get('proc_interfaces') == namespace.get('sysfs_interfaces') == ['lo']
            and privilege.get('vm_uuid') == vm_uuid
            and (privilege.get('uid'),privilege.get('euid'),privilege.get('gid'),privilege.get('egid')) == (2000,2000,2000,2000)
            and privilege.get('groups') == [] and privilege.get('no_new_privs') == '1'
            and privilege.get('cap_eff') == '0000000000000000', 'clock namespace or privilege differs')
    teardown = json.loads((directory/'vm/teardown.json').read_bytes())
    require(teardown == provenance['teardown'] and teardown.get('vm_uuid') == vm_uuid
            and teardown.get('clean_poweroff') is True and teardown.get('forced_stop') is False
            and teardown.get('qemu_exit_status') == 0 and teardown.get('scope_quiescent') is True
            and teardown.get('proof_durable') is True and teardown.get('cgroup_events', {}).get('removed') is True,
            'clock VM teardown differs')
    return ([{'record':selected[0], 'definition':case, 'sources':{}, 'run':spec['name']}],
            {'name':spec['name'], 'groups':spec['groups'], 'selected_records':1,
             'evidence_format':FORMAT, 'primary_receipt_sha256':CLOCK_RECEIPT_SHA256,
             'receipt_run':run_id, 'candidate_sha256':expected_binary, 'core_binary_path':str(core_path),
             'case_definition_sha256':canonical(case), 'vm_uuid':vm_uuid, 'selfcheck_ids':sorted(checks),
             'requirement':PRODUCT_REQUIREMENTS[cid], 'independent_review_sha256':accepted['ready_sha256'],
             'result_sha256':accepted['result_sha256'], 'provenance_sha256':accepted['provenance_sha256'],
             'evidence_sha256':accepted['evidence_sha256'], 'units':{'evaluator':evaluator,'compatibility':service},
             'teardown':teardown, 'overlay_discarded':True,
             'injection_scope':'synthetic callsite; not a kernel/vDSO/libc return'})
