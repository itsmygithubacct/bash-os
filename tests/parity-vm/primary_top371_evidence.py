#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned top v3 primary-receipted evidence reader, operating on inert data."""
import base64
import json
import tarfile
from pathlib import Path
from primary_controller_evidence import (CHECKS, artifact_inventory, canonical, deny_noncore,
    file_sha, pinned, require, safe_member, sha, tar_members, unit_proof)
from primary_top_typed import classify

FORMAT='primary-qualified-top371-v1'
PRIMARY_RECEIPT_SHA256='f9009dc4327b89c7d2682d16a826fc85f5a2f1f411e0f7a19729b7eb3b36a1d4'
FREEZE='a77bd816479118940cd2438727bc17517b3ddced1c200d4fa2fa2e46be91702d'
RAW_REVIEW='a7cd100fc1f49e75424947efd57204a81275582d281b421ea6570e63f345b27d'
IMAGE='9f8841a2a756268f3785232e713e56f5ac91157d116c37b14dbcb1ddcde17457'
CORES={'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
       'dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
RUNS = {'fifo_dynamic': {'all_artifacts_verified': True,
                  'build': 'dynamic',
                  'candidate_sha256': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
                  'canonical_case_sha256': {'migration-terminal213-control-screen': 'f0d9f117200702a2683f2ecf64d1eead814d09372ff0d22f4b230ddd67d2d2f4',
                                            'migration-terminal213-top-fifo-control': 'c305ce6b3fa88c2ac0effed0f0891017534f4948889a9dd3676e37ef1b2ad262',
                                            'migration-terminal213-top-fifo-redraw': '23d58dccac902c61f1eb1b60ed9e5c1cd9b19f7249eee66056b090b636fb7094',
                                            'migration-terminal213-top-frame-control': '6176d1c57a54b80e70ce1cd06e59d383b6199d870fb4c8c2bc8baa6fd72b5c07'},
                  'current_scope_cgroup_wrapper_absent': True,
                  'evidence_sha256': '553afeece51ee3b03155cbff139278f2058c3d6f6e05043d7727863624f874e7',
                  'observations': [{'case_id': 'migration-terminal213-top-fifo-redraw',
                                    'input_hex': [],
                                    'outcome': 'PASS',
                                    'raw_error': None,
                                    'reached': 'three visible frames and four source-bound samples',
                                    'requirement': 'r1',
                                    'status': 0,
                                    'unreached': []}],
                  'payload_sha256': '81316968760c9bd3a3f3fe5f5871e71d6e1b3e995f24ad2b358d0e10af1efa78',
                  'product_ids': ['migration-terminal213-top-fifo-redraw'],
                  'provenance_sha256': 'a24ed1e285375e3ca9a1a9c8916bffb19eff538856751ea219e0075355433563',
                  'selected_ids': ['migration-terminal213-control-screen',
                                   'migration-terminal213-top-fifo-control',
                                   'migration-terminal213-top-frame-control',
                                   'migration-terminal213-top-fifo-redraw'],
                  'source_payload_verified': True,
                  'summary_sha256': '9e92d06f0c2b4f7d2d3c1a9c5c3eb465f46b875a7f53aad0df3e7bf4fed7539d',
                  'teardown_sha256': '0de07ad5e8c7bf7c1fd1c08fa94897beacf6413895c1c8afa386bd12290841ef',
                  'units': {'compatibility': {'proof_sha256': '350534e9c297949349fecdf1dcf1f29dcd3e830f073e1d896f28f53f43791ef3',
                                              'stop_returncode': 5,
                                              'transport_returncode': 0,
                                              'unit': 'bashos-optional-fe01e3ce-reference.service'},
                            'evaluator': {'proof_sha256': 'ae88991198b05bc9c24c1dc66bfc93c51cf99795b181e10eb91c076db5262280',
                                          'stop_returncode': 5,
                                          'transport_returncode': 0,
                                          'unit': 'bashos-evaluation-fe01e3ce.service'}},
                  'vm_uuid': 'fe01e3ce-fd7d-428e-b415-5a5c99ac9f93'},
 'fifo_static': {'all_artifacts_verified': True,
                 'build': 'static',
                 'candidate_sha256': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
                 'canonical_case_sha256': {'migration-terminal213-control-screen': 'f0d9f117200702a2683f2ecf64d1eead814d09372ff0d22f4b230ddd67d2d2f4',
                                           'migration-terminal213-top-fifo-control': 'c305ce6b3fa88c2ac0effed0f0891017534f4948889a9dd3676e37ef1b2ad262',
                                           'migration-terminal213-top-fifo-redraw': '23d58dccac902c61f1eb1b60ed9e5c1cd9b19f7249eee66056b090b636fb7094',
                                           'migration-terminal213-top-frame-control': '6176d1c57a54b80e70ce1cd06e59d383b6199d870fb4c8c2bc8baa6fd72b5c07'},
                 'current_scope_cgroup_wrapper_absent': True,
                 'evidence_sha256': 'fa5897b59bef059d98ea6b17830d3ddefe553e607dff7d59d3bb8a26811aea49',
                 'observations': [{'case_id': 'migration-terminal213-top-fifo-redraw',
                                   'input_hex': [],
                                   'outcome': 'PASS',
                                   'raw_error': None,
                                   'reached': 'three visible frames and four source-bound samples',
                                   'requirement': 'r1',
                                   'status': 0,
                                   'unreached': []}],
                 'payload_sha256': 'f74831434e90b67a90369b0a10d68ab8b7f604d7044e8ce6d8b7af994a69efeb',
                 'product_ids': ['migration-terminal213-top-fifo-redraw'],
                 'provenance_sha256': 'af66acbc2ac885cf6756ef84143bc85743d431251c139c9ee2d5300a40dae4e0',
                 'selected_ids': ['migration-terminal213-control-screen',
                                  'migration-terminal213-top-fifo-control',
                                  'migration-terminal213-top-frame-control',
                                  'migration-terminal213-top-fifo-redraw'],
                 'source_payload_verified': True,
                 'summary_sha256': '79fdcdeffa9916c8f0f3c2861824e0ff7324454d261f4c25d56cbaff4aac7909',
                 'teardown_sha256': '39c36c3cc59685eb7dab66259d5a57c60e9e60779487345a72114fba78cc646f',
                 'units': {'compatibility': {'proof_sha256': '00171672476dd8c505c180313a1f49f3eaf39b28be05c655532fef90e14dbe33',
                                             'stop_returncode': 5,
                                             'transport_returncode': 0,
                                             'unit': 'bashos-optional-c595c5f7-reference.service'},
                           'evaluator': {'proof_sha256': '9bd84c140f1187d23eb814e5c914ca0b2420fb45b978d0ceca26341b52c13328',
                                         'stop_returncode': 5,
                                         'transport_returncode': 0,
                                         'unit': 'bashos-evaluation-c595c5f7.service'}},
                 'vm_uuid': 'c595c5f7-6dd6-4376-8a73-3fa0c05a020e'},
 'prompt_dynamic': {'all_artifacts_verified': True,
                    'build': 'dynamic',
                    'candidate_sha256': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
                    'canonical_case_sha256': {'migration-terminal213-control-key': 'a446780ceba49b73bb9c2a5ad3b469d228cc37443d79fb8c35b16ab3c0d57331',
                                              'migration-terminal213-top-delay-invalid': 'e8d0bc82478b15ddaf3d740ee629e09ca1deae523cc4766f4ace7e3378ccff50',
                                              'migration-terminal213-top-delay-valid': 'ca42d93685619c17b8b2b2d8e582209a2f62cb163df93dbbbdeb2cb44f7f0baa',
                                              'migration-terminal213-top-sort-prompt-invalid': '233da64e48840d91b70c4ac8822a2d548fb054006592ad2504dd6702151cb887',
                                              'migration-terminal213-top-sort-prompt-valid': '7d7f446a88e30f3556de445a01d6788059f1f005966c2b50256c7f8abf1c72da'},
                    'current_scope_cgroup_wrapper_absent': True,
                    'evidence_sha256': '0e8d038e63231698deb64c9230f290f800ff73ce2e68b0d427b04f1b6b7a7a8a',
                    'observations': [{'case_id': 'migration-terminal213-top-delay-valid',
                                      'input_hex': ['6e', '330d', '71'],
                                      'outcome': 'PASS',
                                      'raw_error': None,
                                      'reached': 'n-valid input and response',
                                      'requirement': 'r2',
                                      'status': 0,
                                      'unreached': []},
                                     {'case_id': 'migration-terminal213-top-delay-invalid',
                                      'input_hex': ['6e', '300d', '71'],
                                      'outcome': 'PASS',
                                      'raw_error': None,
                                      'reached': 'n-invalid input and response',
                                      'requirement': 'r2',
                                      'status': 0,
                                      'unreached': []},
                                     {'case_id': 'migration-terminal213-top-sort-prompt-valid',
                                      'input_hex': ['6f'],
                                      'outcome': 'FAIL',
                                      'raw_error': 'PTY wall-clock limit waiting for step 2 screen: no row matches '
                                                   "'(?i)sort[^\\\\n]*:'",
                                      'reached': 'missing sort prompt after o',
                                      'requirement': 'r2',
                                      'status': 137,
                                      'unreached': ['sort value', 'response', 'q']},
                                     {'case_id': 'migration-terminal213-top-sort-prompt-invalid',
                                      'input_hex': ['4f'],
                                      'outcome': 'FAIL',
                                      'raw_error': 'PTY wall-clock limit waiting for step 2 screen: no row matches '
                                                   "'(?i)sort[^\\\\n]*:'",
                                      'reached': 'missing sort prompt after O',
                                      'requirement': 'r2',
                                      'status': 137,
                                      'unreached': ['sort value', 'response', 'q']}],
                    'payload_sha256': '83acdc0c90bac944ce7dde04955311016abd1e4f24ff393d4fbf471f0f856770',
                    'product_ids': ['migration-terminal213-top-delay-valid',
                                    'migration-terminal213-top-delay-invalid',
                                    'migration-terminal213-top-sort-prompt-valid',
                                    'migration-terminal213-top-sort-prompt-invalid'],
                    'provenance_sha256': '051234b681f9381ccb514788a95a2af4b55afb5a1d0241b398a9191e137d4bea',
                    'selected_ids': ['migration-terminal213-control-key',
                                     'migration-terminal213-top-delay-valid',
                                     'migration-terminal213-top-delay-invalid',
                                     'migration-terminal213-top-sort-prompt-valid',
                                     'migration-terminal213-top-sort-prompt-invalid'],
                    'source_payload_verified': True,
                    'summary_sha256': 'ea240079992c27c6e58823a8c5a1112eb8935506d0fab18669d4bcdc9f2b955e',
                    'teardown_sha256': '72cce0c8d939d776f85df81205484f616d8403acfeb8f75bcfc3e7d8577ba897',
                    'units': {'compatibility': {'proof_sha256': '44727392a9669fb25e49afbcf85f55b75f1202bd5f0dcc8957ec9e1379ad0419',
                                                'stop_returncode': 5,
                                                'transport_returncode': 0,
                                                'unit': 'bashos-optional-4ce51db9-reference.service'},
                              'evaluator': {'proof_sha256': 'f7317eb708ba6415631fed3ba51736310db34ba87614f5277add9478bcfa6dc8',
                                            'stop_returncode': 0,
                                            'transport_returncode': 1,
                                            'unit': 'bashos-evaluation-4ce51db9.service'}},
                    'vm_uuid': '4ce51db9-ddef-48de-a62a-0a448da2aa68'},
 'prompt_static': {'all_artifacts_verified': True,
                   'build': 'static',
                   'candidate_sha256': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
                   'canonical_case_sha256': {'migration-terminal213-control-key': 'a446780ceba49b73bb9c2a5ad3b469d228cc37443d79fb8c35b16ab3c0d57331',
                                             'migration-terminal213-top-delay-invalid': 'e8d0bc82478b15ddaf3d740ee629e09ca1deae523cc4766f4ace7e3378ccff50',
                                             'migration-terminal213-top-delay-valid': 'ca42d93685619c17b8b2b2d8e582209a2f62cb163df93dbbbdeb2cb44f7f0baa',
                                             'migration-terminal213-top-sort-prompt-invalid': '233da64e48840d91b70c4ac8822a2d548fb054006592ad2504dd6702151cb887',
                                             'migration-terminal213-top-sort-prompt-valid': '7d7f446a88e30f3556de445a01d6788059f1f005966c2b50256c7f8abf1c72da'},
                   'current_scope_cgroup_wrapper_absent': True,
                   'evidence_sha256': 'f5ea4092749e4bfe87108472bf8a2f9a5fa462f33b9878e6bc12491ab0cddc49',
                   'observations': [{'case_id': 'migration-terminal213-top-delay-valid',
                                     'input_hex': ['6e', '330d', '71'],
                                     'outcome': 'PASS',
                                     'raw_error': None,
                                     'reached': 'n-valid input and response',
                                     'requirement': 'r2',
                                     'status': 0,
                                     'unreached': []},
                                    {'case_id': 'migration-terminal213-top-delay-invalid',
                                     'input_hex': ['6e', '300d', '71'],
                                     'outcome': 'PASS',
                                     'raw_error': None,
                                     'reached': 'n-invalid input and response',
                                     'requirement': 'r2',
                                     'status': 0,
                                     'unreached': []},
                                    {'case_id': 'migration-terminal213-top-sort-prompt-valid',
                                     'input_hex': ['6f'],
                                     'outcome': 'FAIL',
                                     'raw_error': 'PTY wall-clock limit waiting for step 2 screen: no row matches '
                                                  "'(?i)sort[^\\\\n]*:'",
                                     'reached': 'missing sort prompt after o',
                                     'requirement': 'r2',
                                     'status': 137,
                                     'unreached': ['sort value', 'response', 'q']},
                                    {'case_id': 'migration-terminal213-top-sort-prompt-invalid',
                                     'input_hex': ['4f'],
                                     'outcome': 'FAIL',
                                     'raw_error': 'PTY wall-clock limit waiting for step 2 screen: no row matches '
                                                  "'(?i)sort[^\\\\n]*:'",
                                     'reached': 'missing sort prompt after O',
                                     'requirement': 'r2',
                                     'status': 137,
                                     'unreached': ['sort value', 'response', 'q']}],
                   'payload_sha256': '0387d0b6f82efa0c64e5525d3ad496333e7e4736b6166d9144be1c47d39f13f6',
                   'product_ids': ['migration-terminal213-top-delay-valid',
                                   'migration-terminal213-top-delay-invalid',
                                   'migration-terminal213-top-sort-prompt-valid',
                                   'migration-terminal213-top-sort-prompt-invalid'],
                   'provenance_sha256': '54b9b1833e89ef4dae603d47cb38fc0b9a72c9317c3a8c1d3a3eccf38c8f5605',
                   'selected_ids': ['migration-terminal213-control-key',
                                    'migration-terminal213-top-delay-valid',
                                    'migration-terminal213-top-delay-invalid',
                                    'migration-terminal213-top-sort-prompt-valid',
                                    'migration-terminal213-top-sort-prompt-invalid'],
                   'source_payload_verified': True,
                   'summary_sha256': 'be5f5442864a1608e9d55f9a0b5af191c99b018f5f2dc1c3b379527be524dd5b',
                   'teardown_sha256': '8276a800e02194b899632cf55992d80e8fc07694bde85153c274ad2b4d1417ac',
                   'units': {'compatibility': {'proof_sha256': 'c6d01225a2cd7f71d1a9d27d2934c468aa4994da89bbc9e794b7df23d1039ad8',
                                               'stop_returncode': 5,
                                               'transport_returncode': 0,
                                               'unit': 'bashos-optional-6cc1778e-reference.service'},
                             'evaluator': {'proof_sha256': '717f6eeb11b6fcca746d9ee28bbedabc83373afa830df81673b5b5800cea51ab',
                                           'stop_returncode': 0,
                                           'transport_returncode': 1,
                                           'unit': 'bashos-evaluation-6cc1778e.service'}},
                   'vm_uuid': '6cc1778e-2c27-4eb1-a4d4-b17bd416d136'}}

def load_qualified_top371_run(spec, expected_binary, expected_build):
    require(expected_build in CORES and expected_binary==CORES[expected_build] and spec.get('evidence_format')==FORMAT,'top build/format differs')
    deny_noncore(spec,'top selection')
    require(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True,'top scope differs')
    kind=spec.get('top_batch');require(kind in ('prompt','fifo'),'unknown top batch')
    name=kind+'_'+expected_build;accepted=RUNS[name]
    require(spec.get('name')=='top-v3-'+kind+'-'+expected_build and spec.get('groups')==['terminal']
            and spec.get('ids')==sorted(accepted['product_ids']) and not spec.get('exclude_ids'), 'top selection must contain exact product IDs only')
    require(spec.get('primary_receipt',{}).get('sha256')==PRIMARY_RECEIPT_SHA256,'top receipt pin differs')
    receipt=json.loads(pinned(spec['primary_receipt']['path'],PRIMARY_RECEIPT_SHA256,'top primary receipt'))
    deny_noncore(receipt,'top receipt')
    require(receipt.get('schema')=='bashos-top-v3-primary-acceptance-v1'
            and receipt.get('decision')=='accept-bounded-top-redraw-and-prompt-observations'
            and receipt.get('topic')=='top/interactive-pty-contract' and receipt.get('requirements')==['r1','r2']
            and receipt.get('ledger_scope')=='core' and receipt.get('core_ledger_eligible') is True
            and receipt.get('subject_execution_on_host') is False and receipt.get('source_freeze_sha256')==FREEZE
            and receipt.get('raw_review_sha256')==RAW_REVIEW and set(receipt.get('runs',{}))==set(RUNS)
            and all({k:v for k,v in receipt['runs'][n].items() if k!='source_result'}==RUNS[n] for n in RUNS),'top receipt authority differs')
    accepted=receipt['runs'][name]
    review=json.loads(pinned(receipt['raw_review_path'],RAW_REVIEW,'top primary raw review'))
    require(review.get('schema')=='bashos-top-v3-four-run-data-review-v1'
            and review.get('state')=='RAW_EVIDENCE_PROPOSAL_PENDING_PRIMARY_RECEIPT'
            and set(review.get('typed_observations',{}))==set(RUNS)
            and review['typed_observations'][name]==accepted['observations'],'top receipt/raw review differs')
    freeze=json.loads(pinned(receipt['source_freeze_path'],FREEZE,'top source freeze'))
    require(freeze.get('controller_sha256')=='2fa69a27f45c6005577a75aa9811482519b065acfd213d2c2525c9908cfa2681'
            and freeze.get('module_sha256')=='2010247df38f7fa6359320531765dd61aae39abc6b584533d4121d6ecff33b07'
            and freeze.get('case_index_sha256')=='0aff29e89a72a44f81618209a1bcec141ae701af2f53e9741b9e493d4a9af8ba', 'top source pins differ')
    freeze_root=Path(receipt['source_freeze_path']).parent
    inventory=json.loads(pinned(freeze_root/'control-inventory.json',freeze['control_inventory_sha256'],'top source inventory'))
    sources=['guest.py','terminal.py','schema.py','helpers/terminal213_guard.py']
    if kind=='fifo': sources.append('helpers/top_fifo_frames.py')
    for source in sources:
        rel='tests/parity-vm/'+source;path=freeze_root/'control'/rel;item=inventory[rel]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size==item['bytes']
                and format(path.stat().st_mode & 0o7777,'04o')==item['mode'] and file_sha(path)==item['sha256'],
                'top frozen payload source differs: '+source)
    directory=Path(spec['path']);require(directory.is_absolute() and str(directory.resolve(strict=True))==accepted['source_result']
            and accepted['build']==expected_build and accepted['candidate_sha256']==expected_binary
            and accepted['all_artifacts_verified'] is True and accepted['source_payload_verified'] is True
            and accepted['current_scope_cgroup_wrapper_absent'] is True,'top accepted run differs')
    prov=json.loads(pinned(directory/'provenance.json',accepted['provenance_sha256'],'top provenance'))
    deny_noncore(prov,'top provenance');vmid=accepted['vm_uuid']
    require(prov.get('status')=='completed' and prov.get('qualification')=='complete-evidence-not-product-pass'
            and prov.get('operation')=='terminal213-run' and prov.get('batch')==('top-prompt' if kind=='prompt' else 'top-fifo')
            and prov.get('candidate')==expected_build and prov.get('candidate_sha256')==expected_binary
            and prov.get('vm_uuid')==vmid and prov.get('guest_exit_status')==(1 if kind=='prompt' else 0)
            and prov.get('root_fixtures_allowed') is False and prov.get('host_mounts')==[]
            and prov.get('guest_summary_state')=='validated' and prov.get('image_identity',{}).get('sha256')==IMAGE
            and all(prov.get(k) is True for k in ('guest_units_proven_quiescent','scope_proven','overlay_discarded',
                'candidate_unchanged','candidate_snapshot_unchanged','prepared_unchanged','controller_unchanged',
                'module_unchanged','suites_unchanged','helpers_unchanged','guest_unit_proofs_unchanged','evidence_unchanged')),
            'top provenance incomplete')
    require(prov.get('controller_sha256')==freeze['controller_sha256'] and prov.get('module_sha256')==freeze['module_sha256']
            and prov.get('case_index_sha256')==freeze['case_index_sha256']
            and prov.get('product_case_ids')==accepted['product_ids'] and prov.get('selected_case_ids')==accepted['selected_ids']
            and all(prov.get('canonical_case_sha256',{}).get(k)==v for k,v in accepted['canonical_case_sha256'].items()),'top provenance source/case differs')
    identity=prov['identity'];att=identity['attestation']['readback'];token=(vmid+'\n').encode().hex()
    require(identity.get('marker_matches') is True and identity.get('product_uuid_matches') is True
            and identity.get('host_shared_mounts')==[] and att.get('token')==vmid
            and att.get('marker_hex')==att.get('dmi_hex')==att.get('attestation_hex')==token
            and all(att[x].get('uid')==att[x].get('gid')==0 and att[x].get('mode')==0o444
                    and att[x].get('nlink')==1 and att[x].get('type')=='regular' for x in ('marker','attestation'))
            and prov['runtime_network'].get('canary_accepted')==0,'top guest identity/isolation differs')
    core=prov['workspace_core_before']
    core_paths={Path(path).name:path for path in core}
    require(core==prov['workspace_core_after'] and len(core)==2 and set(core_paths)=={'bash-static','bash'}
        and all(Path(path).is_absolute() for path in core)
        and Path(core_paths['bash-static']).parent==Path(core_paths['bash']).parent
        and core[core_paths['bash-static']]==CORES['static'] and core[core_paths['bash']]==CORES['dynamic']
        and spec['core_binary_path']==core_paths['bash-static' if expected_build=='static' else 'bash']
        and prov['core_before']==prov['core_after'] and sorted(prov['core_before'].values())==sorted(CORES.values()),'top core snapshot differs')
    ns=json.loads(pinned(directory/'namespace-proof-208.json',prov['namespace_proof_sha256'],'top namespace'))
    attestation=json.loads(pinned(directory/'namespace-attestation-208.json',prov['namespace_attestation_sha256'],'top namespace attestation'))
    parent=json.loads(pinned(directory/'parent-namespace.json',prov['parent_namespace_sha256'],'top parent namespace'))
    privilege=json.loads(pinned(directory/'privilege-proof.json',prov['privilege_proof_sha256'],'top privilege'))
    require(ns.get('schema')=='bashos-syslog208-namespace-v1' and ns.get('token')==ns.get('dmi_uuid')==attestation.get('token')==vmid
            and ns.get('proc_interfaces')==ns.get('sysfs_interfaces')==['lo'] and ns.get('uid')==ns.get('euid')==0
            and ns.get('pid1_uid')==['0']*4 and attestation.get('schema')=='bashos-syslog-namespace-attestation-v1'
            and ns['attestation'].get('uid')==ns['attestation'].get('gid')==0 and ns['attestation'].get('mode')==0o444
            and ns['attestation'].get('nlink')==1 and ns['attestation']['sha256']==prov['namespace_attestation_sha256']
            and ns['namespaces']==attestation['namespaces'] and ns['outer_namespaces']==attestation['outer_namespaces']
            and all(ns['outer_namespaces'][k]==parent[k] and ns['namespaces'][k]!=parent[k] for k in ('mnt','net','pid'))
            and prov['namespace_proof']['evaluation']==ns and prov['namespace_proof']['parent']==parent, 'top namespace differs')
    require(privilege==prov['privilege_proof'] and privilege.get('vm_uuid')==vmid
            and (privilege.get('uid'),privilege.get('euid'),privilege.get('gid'),privilege.get('egid'))==(2000,)*4
            and privilege.get('groups')==[] and privilege.get('no_new_privs')=='1' and privilege.get('cap_eff')=='0000000000000000','top privilege differs')
    ev=accepted['units']['evaluator'];cp=accepted['units']['compatibility']
    require(unit_proof(directory/'run.log.unit-proof.json',ev['proof_sha256'],vmid,ev['unit'],ev['transport_returncode'])==ev
            and unit_proof(directory/'compat/run.log.unit-proof.json',cp['proof_sha256'],vmid,cp['unit'],cp['transport_returncode'])==cp
            and prov['guest_unit_proofs']['run.log.unit-proof.json']==ev['proof_sha256']
            and prov['compatibility_unit_proofs']['run.log.unit-proof.json']==cp['proof_sha256'],'top unit proofs differ')
    teardown=json.loads(pinned(directory/'vm/teardown.json',accepted['teardown_sha256'],'top teardown'))
    require(teardown==prov['teardown'] and teardown.get('vm_uuid')==vmid and teardown.get('proof_durable') is True
            and teardown.get('scope_quiescent') is True and teardown.get('cgroup_events',{}).get('removed') is True
            and teardown.get('forced_stop') is False and teardown.get('qemu_exit_status')==0
            and teardown.get('scope_after',{}).get('id')=='parity-vm-'+vmid+'.scope'
            and teardown['scope_after'].get('active')=='inactive' and teardown['scope_after'].get('group')==''
            and not (directory/'overlay.qcow2').exists(),'top teardown differs')
    require(file_sha(directory/'candidate.snapshot')==expected_binary and file_sha(spec['core_binary_path'])==expected_binary
            and file_sha(directory/'evidence.tar')==accepted['evidence_sha256']
            and file_sha(directory/'payload.tar')==accepted['payload_sha256']==prov['payload_sha256'],'top selected artifacts differ')
    artifact_inventory(directory,prov)
    summary=json.loads(pinned(directory/'guest-summary.json',accepted['summary_sha256'],'top summary'))
    require(prov['guest_summary_sha256']==accepted['summary_sha256'] and summary['binary_sha256']==expected_binary,'top summary differs')
    rows={r['id']:r for r in summary['cases']};require(len(rows)==len(summary['cases']) and set(rows)==set(accepted['selected_ids'])|{'selfcheck-'+x for x in CHECKS}
            and all(rows['selfcheck-'+x]['status']=='PASS' for x in CHECKS),'top summary membership or selfchecks differ')
    with tarfile.open(directory/'payload.tar','r:') as tar:
        tar_members(tar);fixture_raw=safe_member(tar,'harness/suites/optional-frozen.json')
        require(sha(fixture_raw)==prov['frozen_fixture_sha256'],'top fixture bytes differ')
        fixture=json.loads(fixture_raw);defs={c['id']:c for c in fixture['cases'] if c['id'] in accepted['selected_ids']}
        require(set(defs)==set(accepted['selected_ids']) and all(canonical(defs[k])==v for k,v in accepted['canonical_case_sha256'].items()),'top canonical case differs')
        for source in sources:
            require(sha(safe_member(tar,'harness/'+source))==inventory['tests/parity-vm/'+source]['sha256'],
                    'top payload source differs: '+source)
        require(inventory['tests/parity-vm/helpers/terminal213_guard.py']['sha256']=='dea91736a54538ae758c4b416d0eb48b2fd4a4ba331af789967c2de0ccf769c6','top guard differs')
    obs={x['case_id']:x for x in accepted['observations']};require(set(obs)==set(accepted['product_ids']),'top observation membership differs')
    with tarfile.open(directory/'evidence.tar','r:') as tar:
        tar_members(tar)
        def raw(cid):return json.loads(safe_member(tar,'results/'+cid+'/candidate.json'))
        controls={cid:{'framework_status':rows[cid]['status'],'raw':raw(cid)} for cid in accepted['selected_ids'] if cid not in accepted['product_ids']}
        for cid in accepted['product_ids']:
            raw_record=raw(cid);base64.b64decode(raw_record['screen_base64'],validate=True)
            verdict=(review['runs'][name]['data_review']['cases'][cid]['result'] if kind=='prompt'
                     else review['runs'][name]['data_review']['result'])
            typed=json.loads(json.dumps(classify(cid,raw_record,rows[cid]['status'],controls,independent_data_verdict=verdict).to_dict()))
            require(typed==obs[cid] and rows[cid]['status']==typed['outcome'],'top raw/typed primary observation differs')
    return ([{'record':rows[cid], 'definition':defs[cid], 'sources':{}, 'run':spec['name']} for cid in sorted(accepted['product_ids'])],
        {'name':spec['name'],'groups':['terminal'],'selected_records':len(accepted['product_ids']),'evidence_format':FORMAT,
         'candidate_sha256':expected_binary,'vm_uuid':vmid,'primary_receipt_sha256':PRIMARY_RECEIPT_SHA256,
         'provenance_sha256':accepted['provenance_sha256'],'evidence_sha256':accepted['evidence_sha256']})
