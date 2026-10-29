#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read primary-qualified controller records as inert data, preserving original evidence.

This v1 adapter anchors the primary-accepted cluster282 receipt digest in
reviewed source. A configuration may select its location but cannot authorize
a different receipt. Another family needs its own reviewed adapter and pin.
"""
import base64
import hashlib
import json
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath

PRIMARY_RECEIPT_SHA256 = '30518fc55e23ab31f447c1a9961ae34c19cee18844b40f3021bde20366ad1678'
RECEIPT_SCHEMA = 'bashos-cluster282-primary-acceptance-v1'
DECISION = 'accept-runtime-evidence-and-six-bounded-requirement-updates-for-integration'
CHECKS = {
    'bounded-output', 'bounded-time', 'invalid-oracle-is-error',
    'candidate-mismatch-is-fail', 'network-isolation', 'orphan-cleanup',
    'detached-orphan-cleanup', 'scratch-isolation', 'migration-is-metadata-252',
    'setup-classification', 'diagnostic-capture', 'file-size-allowance',
    'syscall-sequence-observer',
}
HASH_KEYS = {
    'candidate_raw_sha256', 'case_events_sha256', 'case_result_sha256',
    'compatibility_raw_sha256', 'evidence_tar_sha256', 'handoff_sha256',
    'launch_sha256', 'payload_sha256', 'plan_sha256', 'provenance_sha256',
    'setup_events_sha256', 'setup_sha256', 'summary_sha256', 'teardown_sha256',
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def file_sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()

def read(path):
    return json.loads(Path(path).read_bytes())

def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True).encode())

def pinned(path, expected, label):
    path = Path(path)
    require(path.is_absolute() and re.fullmatch(r'[0-9a-f]{64}', expected or '') is not None,
            'invalid ' + label + ' pin')
    data = path.read_bytes()
    require(sha(data) == expected, label + ' hash mismatch')
    return data

def deny_noncore(item, label):
    require(isinstance(item, dict), label + ' is not an object')
    if 'core_ledger_eligible' in item:
        require(item['core_ledger_eligible'] is True, label + ' is not core eligible')
    if 'ledger_scope' in item:
        require(item['ledger_scope'] == 'core', label + ' is not core scoped')
    require('optional' not in item or item['optional'] is False,
            label + ' is optional-only or has an invalid optional flag')

def option(argv, name):
    require(isinstance(argv, list) and argv.count(name) == 1, 'invalid launch ' + name)
    i = argv.index(name)
    require(i + 1 < len(argv), 'missing launch ' + name)
    return argv[i + 1]

def safe_member(archive, name):
    item = archive.getmember(name)
    require(item.isfile() and item.size <= 16 * 1024**2, 'invalid archive member: ' + name)
    return archive.extractfile(item).read()

def tar_members(archive):
    members = archive.getmembers()
    require(len({m.name for m in members}) == len(members), 'duplicate archive members')
    for member in members:
        name = PurePosixPath(member.name)
        require(not name.is_absolute() and '..' not in name.parts
                and str(name) == member.name and (member.isfile() or member.isdir()),
                'unsafe archive member')
    return members

def proof_text(proof, key):
    value = proof[key]
    require(value['returncode'] == 0 and value['stderr_hex'] == '', 'failed proof command: ' + key)
    return bytes.fromhex(value['stdout_hex']).decode('ascii')

def unit_proof(path, expected_hash, vm_uuid, expected_unit, expected_transport):
    proof = json.loads(pinned(path, expected_hash, 'unit proof'))
    group = '/system.slice/' + expected_unit
    require(proof['schema'] == 'bashos-guest-unit-quiescence-v1'
            and proof['vm_uuid'] == vm_uuid and proof['unit'] == expected_unit
            and proof['cgroup'] == group and proof['quiescent'] is True
            and proof['transport_finished'] is True
            and proof['transport_returncode'] == expected_transport, 'unit proof identity/status mismatch')
    def properties(key):
        lines = proof_text(proof, key).splitlines()
        pairs = [line.split('=', 1) for line in lines]
        require(all(len(pair) == 2 for pair in pairs) and len(dict(pairs)) == len(lines),
                'invalid unit properties')
        return dict(pairs)
    before, after = properties('unit_before'), properties('unit_after')
    require(before == {'Id': expected_unit, 'ControlGroup': group, 'LoadState': 'loaded',
                       'ActiveState': 'active'}, 'unit was not observed live')
    require(after.get('Id') in ('', expected_unit) and after.get('ControlGroup') in ('', group)
            and (after.get('LoadState') == 'not-found' or after.get('ActiveState') in ('inactive', 'failed')),
            'unit was not observed inactive')
    b = proof_text(proof, 'events_before').splitlines()
    a = proof_text(proof, 'events_after').splitlines()
    require(b.count('populated 1') == 1 and not any(x.startswith('populated ') and x != 'populated 1' for x in b),
            'unit cgroup was not populated')
    require(a == ['__CGROUP_REMOVED__'] or
            (a.count('populated 0') == 1 and not any(x.startswith('populated ') and x != 'populated 0' for x in a)),
            'unit cgroup was not empty')
    require(proof['release']['returncode'] == 0 and type(proof['stop']['returncode']) is int
            and (proof['stop']['returncode'] == 0 or after.get('LoadState') == 'not-found'),
            'unit release/stop unsupported')
    return {'unit': expected_unit, 'proof_sha256': expected_hash,
            'transport_returncode': proof['transport_returncode'],
            'stop_returncode': proof['stop']['returncode']}

def artifact_inventory(directory, provenance):
    inventory = provenance['artifacts']
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*')
              if p.relative_to(directory).as_posix() not in
              ('provenance.json', 'provenance.sha256')}
    require(actual == set(inventory), 'original artifact membership changed')
    for name, expected in inventory.items():
        rel = PurePosixPath(name)
        require(not rel.is_absolute() and '..' not in rel.parts and str(rel) == name,
                'unsafe provenance artifact')
        path = directory / name
        info = path.lstat()
        require(format(stat.S_IMODE(info.st_mode), '04o') == expected['mode'], 'artifact mode mismatch: ' + name)
        if expected['type'] == 'file':
            require(stat.S_ISREG(info.st_mode) and info.st_size == expected['bytes']
                    and file_sha(path) == expected['sha256'], 'artifact changed: ' + name)
        elif expected['type'] == 'directory':
            require(stat.S_ISDIR(info.st_mode), 'artifact directory changed: ' + name)
        else:
            raise ValueError('unexpected provenance artifact type')

def load_qualified_run(spec, expected_binary, expected_build):
    require(spec.get('evidence_format') == 'primary-qualified-controller-v1',
            'missing controller evidence version')
    deny_noncore(spec, 'selection')
    require(spec.get('core_ledger_eligible') is True and spec.get('ledger_scope') == 'core'
            and expected_build in ('static', 'dynamic'), 'explicit core build selection required')
    pin = spec['primary_receipt']
    require(isinstance(pin, dict) and pin.get('sha256') == PRIMARY_RECEIPT_SHA256,
            'primary receipt pin is not the accepted cluster282 authority')
    receipt = json.loads(pinned(pin['path'], PRIMARY_RECEIPT_SHA256, 'primary receipt'))
    deny_noncore(receipt, 'primary receipt')
    require(receipt.get('schema') == RECEIPT_SCHEMA and receipt.get('decision') == DECISION,
            'unrecognized or unaccepted primary receipt')
    run_id = spec['receipt_run']
    require(isinstance(run_id, str) and re.fullmatch(r'[A-Za-z0-9_-]+', run_id) is not None,
            'invalid receipt selection')
    require(spec.get('name') == 'cluster282-' + run_id,
            'selection run label differs from accepted receipt')
    accepted = receipt['runs'][run_id]
    deny_noncore(accepted, 'accepted run')
    directory = Path(spec['path'])
    require(directory.is_absolute() and str(directory.resolve(strict=True)) == accepted['source_result'],
            'original result directory differs from receipt')
    require(accepted['candidate'] == expected_build and accepted['candidate_sha256'] == expected_binary
            and accepted['status'] in ('PASS', 'FAIL') and accepted['selfcheck_pass'] == 13,
            'receipt does not accept this core build/status')
    cid, vm_uuid = accepted['case_id'], accepted['vm_uuid']
    require(spec['groups'] == ['shell'] and spec['ids'] == [cid] and not spec.get('exclude_ids'),
            'selection differs from accepted case')
    hashes = accepted['source_hashes']
    require(set(hashes) == HASH_KEYS, 'incomplete receipt source hash chain')
    provenance = json.loads(pinned(directory/'provenance.json', hashes['provenance_sha256'], 'provenance'))
    require((directory/'provenance.sha256').read_text().split()[0] == hashes['provenance_sha256'],
            'provenance sidecar differs')
    deny_noncore(provenance, 'provenance')
    require(provenance['operation'] == 'cluster237-run' and provenance['status'] == 'completed'
            and provenance['qualification'] == 'complete-evidence-not-product-pass'
            and provenance['candidate'] == expected_build
            and provenance['candidate_sha256'] == expected_binary
            and provenance['vm_uuid'] == vm_uuid and provenance['selected_case_ids'] == [cid]
            and provenance['canonical_case_sha256'] == accepted['case_sha256']
            and provenance['root_fixtures_allowed'] is False and not provenance['host_mounts']
            and provenance['identity']['marker_matches'] is True
            and provenance['identity']['product_uuid_matches'] is True
            and not provenance['identity']['host_shared_mounts']
            and provenance['runtime_network']['canary_accepted'] == 0,
            'controller provenance identity mismatch')
    require(all(provenance.get(k) is True for k in (
        'candidate_unchanged', 'candidate_snapshot_unchanged', 'prepared_unchanged',
        'controller_unchanged', 'module_unchanged', 'suite_unchanged', 'helper_unchanged',
        'guest_unit_proofs_unchanged', 'compatibility_unit_proofs_unchanged',
        'compatibility_raw_unchanged', 'compatibility_handoff_unchanged', 'evidence_unchanged')),
        'source or artifact was not recorded unchanged')
    for prefix in ('core', 'workspace_core'):
        before, after = provenance[prefix+'_before'], provenance[prefix+'_after']
        names = {Path(path).name: value for path, value in before.items()}
        require(before == after and set(names) == {'bash', 'bash-static'} and len(before) == 2
                and names['bash-static' if expected_build == 'static' else 'bash'] == expected_binary,
                'candidate is not the recorded core build')
    expected_name = 'bash-static' if expected_build == 'static' else 'bash'
    recorded_paths = [path for path, value in provenance['workspace_core_before'].items()
                      if Path(path).name == expected_name and value == expected_binary]
    core_path = Path(spec['core_binary_path'])
    require(len(recorded_paths) == 1 and core_path.is_absolute()
            and str(core_path) == recorded_paths[0] and file_sha(core_path) == expected_binary,
            'configured candidate is not the recorded workspace core binary')
    artifact_inventory(directory, provenance)
    require(provenance['overlay_discarded'] is True and not (directory/'overlay.qcow2').exists(),
            'owned overlay disposition differs')

    batch = directory.parent.parent
    plan = json.loads(pinned(batch/('plan-'+run_id+'.json'), hashes['plan_sha256'], 'plan'))
    launch = json.loads(pinned(batch/('launch-'+run_id+'.json'), hashes['launch_sha256'], 'launch'))
    require(plan['build'] == expected_build and plan['scenario'] == provenance['scenario']
            and plan['candidate_sha256'] == expected_binary and plan['output'] == accepted['source_result']
            and plan['source_freeze_sha256'] == receipt['source_freeze_sha256']
            and launch['plan_sha256'] == hashes['plan_sha256'], 'plan binding differs')
    argv = launch['argv']
    require(option(argv, '--candidate') == expected_build and option(argv, '--scenario') == provenance['scenario']
            and option(argv, '--output') == accepted['source_result']
            and option(argv, '--expected-controller-sha256') == provenance['controller_sha256'],
            'launch binding differs')
    control = Path(plan['source_control'])
    require(control.is_absolute() and control.name == 'control', 'invalid frozen control path')
    freeze = json.loads(pinned(control.parent/'freeze.json', receipt['source_freeze_sha256'], 'source freeze'))
    files = json.loads(pinned(control.parent/'control-files.json',
                              freeze['inventories']['control-files.json'], 'frozen source inventory'))
    require(freeze['controller_sha256'] == provenance['controller_sha256']
            and freeze['module_sha256'] == provenance['module_sha256']
            and freeze['compatibility_qualification_sha256'] == provenance['compatibility_qualification_sha256'],
            'controller source freeze differs')
    for name, source in (('controller.py', 'tests/parity-vm/vm.py'),
                         ('standard_cluster237.py', 'tests/parity-vm/standard_cluster237.py')):
        require(file_sha(directory/name) == files[source], 'saved controller source differs')

    summary_raw = pinned(directory/'guest-summary.json', hashes['summary_sha256'], 'guest summary')
    summary = json.loads(summary_raw)
    deny_noncore(summary, 'guest summary')
    require(summary['vm_uuid'] == vm_uuid and summary['binary_sha256'] == expected_binary
            and summary['selected_case_ids'] == [cid] and summary['root_fixtures_allowed'] is False
            and summary['isolation']['links'] == ['lo'] and summary['isolation']['vm_uuid_matches'] is True
            and provenance['guest_summary_sha256'] == hashes['summary_sha256']
            and provenance['guest_summary_state'] == 'validated', 'summary binding differs')
    require(file_sha(directory/'payload.tar') == hashes['payload_sha256'] == provenance['payload_sha256']
            and file_sha(directory/'evidence.tar') == hashes['evidence_tar_sha256']
            == provenance['evidence_validation']['archive_sha256'], 'archive hash mismatch')
    with tarfile.open(directory/'payload.tar', 'r:') as archive:
        members = tar_members(archive)
        require(all(m.isfile() for m in members), 'unexpected payload directory')
        require(sha(safe_member(archive, 'candidate')) == expected_binary
                and file_sha(directory/'candidate.snapshot') == expected_binary, 'core candidate bytes differ')
        fixture_raw = safe_member(archive, 'harness/suites/optional-frozen.json')
        fixture = json.loads(fixture_raw)
        require(fixture.get('schema') == 1 and len(fixture['cases']) == 1
                and sha(fixture_raw) == provenance['frozen_fixture_sha256'], 'frozen case differs')
        case = fixture['cases'][0]
        deny_noncore(case, 'case')
        require(case['id'] == cid and case['group'] == 'shell'
                and canonical(case) == accepted['case_sha256'], 'case definition hash differs')
        for member in members:
            name = member.name
            if name in ('candidate', 'harness/suites/optional-frozen.json'):
                continue
            if name.startswith('harness/'):
                source = 'tests/parity-vm/' + name.removeprefix('harness/')
            elif name.startswith('loadable-parity/'):
                source = 'tests/' + name
            else:
                raise ValueError('unrecognized frozen payload source: ' + name)
            require(source in files and sha(safe_member(archive, name)) == files[source],
                    'payload source differs: ' + name)
        for helper, expected in case.get('helpers_sha256', {}).items():
            require(sha(safe_member(archive, 'harness/' + helper)) == expected,
                    'case helper differs')
    require(provenance['evidence_validation']['fixture_sha256'] == sha(fixture_raw)
            and provenance['evidence_validation']['selected_ids'] == [cid], 'fixture provenance differs')
    self_ids = {'selfcheck-'+x for x in CHECKS}
    records = summary['cases']
    require(len(records) == 14 and {r['id'] for r in records} == self_ids | {cid},
            'candidate or selfcheck set differs')
    rows = [r for r in records if r['id'] == cid and r['group'] == case['group']]
    checks = [r for r in records if r['group'] == 'selfcheck']
    require(len(rows) == 1 and rows[0]['status'] == accepted['status']
            and len(checks) == 13 and {r['id'] for r in checks} == self_ids
            and all(r['status'] == 'PASS' for r in checks)
            and set(provenance['evidence_validation']['selfchecks']) == self_ids
            and provenance['case_evidence']['selfchecks']['statuses'] == {name: 'PASS' for name in self_ids},
            'candidate/selfcheck status mismatch')
    counts = {name: sum(row.get('status') == name for row in records) for name in
              ('PASS', 'FAIL', 'ERROR', 'SKIP', 'DEFERRED', 'MIGRATED', 'COLLECTED')}
    require(summary['summary'] == provenance['evidence_validation']['summary'] == counts,
            'summary status counts differ')
    with tarfile.open(directory/'evidence.tar', 'r:') as archive:
        tar_members(archive)
        require(safe_member(archive, 'results/summary.json') == summary_raw, 'archived summary differs')
        for row in checks:
            saved = json.loads(safe_member(archive, 'results/selfcheck/'+row['id'].removeprefix('selfcheck-')+'.json'))
            require(saved == {k:v for k,v in row.items() if k != 'kind'}, 'selfcheck raw differs')
        candidate_raw = safe_member(archive, 'results/'+cid+'/candidate.json')
    require(sha(candidate_raw) == hashes['candidate_raw_sha256'], 'candidate raw differs')
    candidate = json.loads(candidate_raw)
    require(candidate['status'] in (0, 1) and (candidate['status'] == 0) == (accepted['status'] == 'PASS')
            and candidate['status'] == provenance['guest_exit_status']
            and not candidate.get('error') and not candidate.get('harness_error')
            and candidate['stray_processes'] == [] and candidate['setup']['status'] == 0
            and not candidate['setup'].get('error') and candidate['setup']['stray_processes'] == [],
            'candidate execution is incomplete or status differs')
    diagnostics = candidate['diagnostics']
    decoded = {
        'setup_sha256': base64.b64decode(diagnostics['cluster238-setup.json']['base64'], validate=True),
        'setup_events_sha256': base64.b64decode(diagnostics['cluster238-setup-events.jsonl']['base64'], validate=True),
        'case_result_sha256': base64.b64decode(diagnostics['cluster238-result.json']['base64'], validate=True),
        'case_events_sha256': base64.b64decode(candidate['tree']['cluster238-events.jsonl']['base64'], validate=True),
    }
    for key, data in decoded.items():
        require(sha(data) == hashes[key], 'retained case data differs: ' + key)
    saved_case = provenance['case_evidence']['cases'][cid]
    for receipt_key, saved_key in (('candidate_raw_sha256', 'raw_sha256'), ('setup_sha256', 'setup_sha256'),
                                   ('setup_events_sha256', 'setup_events_sha256'),
                                   ('case_result_sha256', 'result_sha256'), ('case_events_sha256', 'events_sha256')):
        require(saved_case[saved_key] == hashes[receipt_key], 'case provenance hash differs')
    require(saved_case['framework_status'] == saved_case['fixture_classification'] == accepted['status']
            and json.loads(decoded['case_result_sha256'])['classification'] == accepted['status'],
            'case classification differs')

    compat_raw = pinned(directory/'compat/raw.json', hashes['compatibility_raw_sha256'], 'compatibility raw')
    handoff_raw = pinned(directory/'compat/handoff.json', hashes['handoff_sha256'], 'compatibility handoff')
    handoff = json.loads(handoff_raw)
    compat = json.loads(compat_raw)
    require(compat['schema'] == 'bashos-compat252-raw-v1'
            and compat['availability_trees_empty'] is True and compat['case_directories_absent'] is True
            and provenance['compatibility']['raw_sha256'] == sha(compat_raw)
            and provenance['compatibility']['handoff_sha256'] == sha(handoff_raw)
            and provenance['compatibility']['handoff'] == handoff
            and (directory/'compat/handoff-guest.json').read_bytes() == handoff_raw
            and (directory/'compat/handoff-after.json').read_bytes() == handoff_raw
            and handoff['vm_uuid'] == vm_uuid and handoff['candidate_sha256'] == expected_binary
            and handoff['fixture_sha256'] == sha(fixture_raw) and handoff['selected_ids'] == [cid]
            and handoff['controller_sha256'] == provenance['controller_sha256']
            and handoff['host_module_sha256'] == provenance['compatibility_module_sha256']
            and handoff['service_data_sha256'] == sha(compat_raw) and handoff['status'] == 'PASS'
            and handoff['service_exit'] == 0 and handoff['canary_absent'] is True
            and len(handoff['availability']) == 2
            and all(a == {'status': 0, 'stdout_sha256': sha(b'builtin\n'),
                          'stderr_sha256': sha(b'')} for a in handoff['availability']),
            'compatibility receipt differs')
    ep_hash = provenance['guest_unit_proofs']['run.log.unit-proof.json']
    cp_hash = provenance['compatibility_unit_proofs']['run.log.unit-proof.json']
    require(handoff['service_proof_sha256'] == cp_hash, 'compatibility unit binding differs')
    evaluator = unit_proof(directory/'run.log.unit-proof.json', ep_hash, vm_uuid,
                           'bashos-evaluation-'+vm_uuid[:8]+'.service', candidate['status'])
    compatibility = unit_proof(directory/'compat/run.log.unit-proof.json', cp_hash, vm_uuid,
                               'bashos-optional-'+vm_uuid[:8]+'-reference.service', 0)
    teardown = json.loads(pinned(directory/'vm/teardown.json', hashes['teardown_sha256'], 'VM teardown'))
    scope = 'parity-vm-'+vm_uuid+'.scope'
    require(teardown == provenance['teardown'] and teardown['vm_uuid'] == vm_uuid
            and teardown['scope_unit'] == scope and teardown['clean_poweroff'] is True
            and teardown['forced_stop'] is False and teardown['qemu_exit_status'] == 0
            and teardown['poweroff_request'] == accepted['poweroff_request']
            and teardown['qemu_exit_status'] == accepted['qemu_exit_status']
            and teardown['scope_quiescent'] is True and teardown['proof_durable'] is True
            and provenance['scope_proven'] is True and provenance['guest_units_proven_quiescent'] is True,
            'VM teardown differs')
    boot, after, events = teardown['scope_boot_observation']['state'], teardown['scope_after'], teardown['cgroup_events']
    empty = events.get('removed') is True and events.get('raw_ascii') is None
    if events.get('removed') is False and isinstance(events.get('raw_ascii'), str):
        lines = events['raw_ascii'].splitlines()
        empty = lines.count('populated 0') == 1 and not any(x.startswith('populated ') and x != 'populated 0' for x in lines)
    require(boot['id'] == scope and boot['active'] == 'active' and boot['load'] == 'loaded'
            and boot['group'] == teardown['scope_cgroup']
            and after['id'] in ('', scope) and (after['load'] == 'not-found' or after['active'] in ('inactive', 'failed'))
            and events['path'] == '/sys/fs/cgroup'+teardown['scope_cgroup']+'/cgroup.events' and empty
            and Path(teardown['disk']).resolve() == (directory/'overlay.qcow2').resolve(),
            'VM scope/disk proof differs')
    name = spec.get('name', directory.name)
    selected = [{'record': rows[0], 'definition': case, 'sources': {}, 'run': name}]
    metadata = {'name': name, 'groups': spec['groups'], 'selected_records': 1,
                'evidence_format': 'primary-qualified-controller-v1',
                'primary_receipt_sha256': pin['sha256'], 'receipt_run': run_id,
                'candidate_sha256': expected_binary, 'core_binary_path': str(core_path),
                'case_definition_sha256': accepted['case_sha256'],
                'vm_uuid': vm_uuid, 'selfcheck_ids': sorted(self_ids),
                'artifacts_sha256': dict(hashes), 'units': {'evaluator': evaluator, 'compatibility': compatibility},
                'teardown': teardown, 'overlay_discarded': provenance['overlay_discarded']}
    return selected, metadata
