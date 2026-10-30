#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RTC saved-data boundary proposal. No primary RTC product receipt is authorized.

The diagnostic function checks fixed saved inputs but returns no ledger evidence.
The public loaders intentionally fail closed until primary receipts and their actual
schemas, complete raw adjudications, and current-scope proofs are source reviewed.
"""
import json, math, re, stat, tarfile
from pathlib import Path, PurePosixPath
from primary_controller_evidence import CHECKS, canonical, deny_noncore, file_sha, pinned, require, safe_member, sha, tar_members, unit_proof

CALENDAR_PROFILE={'batch': 'rtc-calendar',
 'cases': {'devices-hwclock-adj-calibration-r1': '9b43dffd5df7330832bc46e957b97b50a97fef0276536f470a61a3693e4bd9bf',
           'devices-hwclock-adj-drift-tail-r1': 'd19b116f7a630a034e4589a27d2cdae4c1f47bb53a6c285693e569e09dcb0d06',
           'devices-hwclock-adj-infinity-r1': '59d0df53e4610f0746d543666cd647e5a7ac823f04d3f407f07b90c295921d90',
           'devices-hwclock-adj-integer-overflow-r1': '83ae2308cdcc3ede60c065465e40c06a6e606f972f9f00658b3a4bffb7a383a5',
           'devices-hwclock-adj-missing-r1': 'cf146522678ae0a8bae83ecb435a759b59becf96c198d63e54ade20bfef6accc',
           'devices-hwclock-adj-mode-r1': 'e1f49b64c043aac12932db7633a126ba1e05e4c45e380cb6f5070125ea2b5288',
           'devices-hwclock-adj-nan-r1': 'eb13937203f5f14352153b2f52b3032d30c22944e3c1e9675b336d295c38d8b8',
           'devices-hwclock-adj-nul-r1': '696e091e59786c28727e19b3df8610171255e133ae568c148be6da2b5cd568dd',
           'devices-hwclock-adj-trailing-r1': 'b36bff89f8674e79a144b70c7ea356153a383e6842c5894dd52081498a1af498',
           'devices-hwclock-adj-valid-r1': '91dab9c3a8d0d9514af4a178a0ab3d614360f45409530c857cee6429a34bbb55',
           'devices-hwclock-epoch-2038-after-r1': '13c34170914579f9f65c3ed11af3af4fe5bae468c158073eec97e8bad420ce28',
           'devices-hwclock-epoch-2038-before-r1': 'bbce9e60f6e9c0f481dd58e269c24e604e151642905b644dfa3f279d56fe7632',
           'devices-hwclock-epoch-invalid-r1': 'b7592f1cacebb7666a75f108ee530fbdcc99046434e8864e6162011d5da8d571',
           'devices-hwclock-epoch-leap-r1': '602c71524d5f08995b64ed303266d7ab5654e21c289ba075b94c9a80c4fad765',
           'devices-hwclock-epoch-pre-r1': 'b5b82862f2862380d8ab574e183518caebd27ae2608be014a9a77441e089d067',
           'devices-hwclock-show-invalid-day-r1': '9fa430382cffa2114bd5877de2bc0e6a10d9248e8e8950b2ba8efcf91a855070',
           'devices-hwclock-show-invalid-month-r1': '2b0b593bb61a5139a709be89876318a5717ee218e0777a5c4898696849e14dfd',
           'devices-hwclock-show-leap-local-r1': 'a4f1347423552b61d271ec4f540eed11a233b3dfb9bca1f984c9c7ca983de9d5',
           'devices-hwclock-show-leap-utc-r1': '335a60102722628a0896e294782bff39b8bc28e972641e0f833a21efdc6c0ab1',
           'devices-hwclock-show-ordinary-local-r1': '1aec917e2889d7b23a784849eef287f6f70da25bdc9fcf1935566676824d6b2f',
           'devices-hwclock-show-ordinary-utc-r1': '75a6c961a750b48f7043e68ee15adf79cc01aa1b8f20ebbe5c1dccdef55b1bf5'},
 'consumer': '62aa886c8d31ca898cfe761e069c6353322ef913cb3beb1d11251af622b8ecb0',
 'control_inventory': '05fe0c4b84dd08a113a6193032acfe84551e340bd2bc4f9daba9a02d48133ec8',
 'decision': 'accept-calendar-v9-for-bounded-nonroot-qualification',
 'ids': ['devices-hwclock-show-ordinary-utc-r1',
         'devices-hwclock-show-leap-local-r1',
         'devices-hwclock-show-leap-utc-r1',
         'devices-hwclock-show-ordinary-local-r1',
         'devices-hwclock-show-invalid-month-r1',
         'devices-hwclock-show-invalid-day-r1',
         'devices-hwclock-epoch-pre-r1',
         'devices-hwclock-epoch-leap-r1',
         'devices-hwclock-epoch-2038-before-r1',
         'devices-hwclock-epoch-2038-after-r1',
         'devices-hwclock-epoch-invalid-r1',
         'devices-hwclock-adj-valid-r1',
         'devices-hwclock-adj-missing-r1',
         'devices-hwclock-adj-nan-r1',
         'devices-hwclock-adj-infinity-r1',
         'devices-hwclock-adj-integer-overflow-r1',
         'devices-hwclock-adj-calibration-r1',
         'devices-hwclock-adj-mode-r1',
         'devices-hwclock-adj-nul-r1',
         'devices-hwclock-adj-drift-tail-r1',
         'devices-hwclock-adj-trailing-r1'],
 'image_receipt': 'b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6',
 'index': 'da45e1180bf42a46891ef6ae3933270df91f96463b0bbb90b8b85de7544d0494',
 'result_inventory': '9c4cffd823c17d678cc0573b0a568c9728dda9fb4d6ca2dfa072b5721058d96c',
 'runs': {'dynamic': {'candidate': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
                      'fixture': 'a166db33e98ce6c8a1f23da87263b6750030b82a1693b7f295392e21a09a878e',
                      'index': 'da45e1180bf42a46891ef6ae3933270df91f96463b0bbb90b8b85de7544d0494',
                      'record': '1a3b14fdd7b4498d28bdc9df1b459967664ed8d7de9c19036c5ad126764dbb51',
                      'uuid': 'd67b0b05-7996-4ec8-b926-91a915031743'},
          'static': {'candidate': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
                     'fixture': 'a166db33e98ce6c8a1f23da87263b6750030b82a1693b7f295392e21a09a878e',
                     'index': 'da45e1180bf42a46891ef6ae3933270df91f96463b0bbb90b8b85de7544d0494',
                     'record': '2fa5e5b3a69c2efe5bb8a56d646332900801374785c78cdd1cd424b860e4acd7',
                     'uuid': 'aeb68cc3-9c48-4eed-a9cd-dcf2604e994f'}},
 'source_accept': '486cbee2730a2cc696c43d6527aac439fe8626d87c7af96ce47d32d9b1718307',
 'source_inventory': '51a55a18ab4aa22d6bbdae3f7e677f05ffcbb69aaac34fc525989ad85a9599dd'}
CALENDAR_AUTHORIZED_RECEIPTS=frozenset({'b4e8ccb6763593f8c7123c0e121ffce28e5b676a158e87443ab4093eca469f1c'})
IMAGE_SHA='08442265e7135133c25936899ffc1cc19530b339b216c35a3ad42e072eee668a'
MANIFEST_SHA='b7fdb3c8df4f38d9f5d988858731950c6c24229e874eeab18fe5951b40b34569'
CORES={'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab','dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}

def decode_json(data):
    """Reject duplicate keys at every depth and non-finite numeric values."""
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out: raise ValueError('duplicate JSON key: '+key)
            out[key]=value
        return out
    def reject_constant(value): raise ValueError('invalid JSON number: '+value)
    def finite_float(value):
        result=float(value)
        if not math.isfinite(result): raise ValueError('nonfinite JSON number')
        return result
    return json.loads(data,object_pairs_hook=unique,parse_constant=reject_constant,parse_float=finite_float)

def _profile(key):
    require(key=='calendar','unknown RTC profile')
    return CALENDAR_PROFILE

def _inventory(root,items):
    require(root.is_dir() and isinstance(items,dict) and items,'result inventory missing')
    require({p.relative_to(root).as_posix() for p in root.rglob('*')}==set(items),'result inventory membership differs')
    for name,expected in items.items():
        rel=PurePosixPath(name); require(not rel.is_absolute() and '..' not in rel.parts and str(rel)==name,'unsafe result path')
        p=root/name; st=p.lstat(); require(format(stat.S_IMODE(st.st_mode),'04o')==expected['mode'],'result mode differs: '+name)
        if expected['type']=='directory': require(stat.S_ISDIR(st.st_mode),'result directory differs: '+name)
        elif expected['type']=='file': require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==expected['bytes'] and file_sha(p)==expected['sha256'],'result bytes differ: '+name)
        else: raise ValueError('unsupported result kind')

# Canonical complete copied-control path, type and mode inventory from the
# frozen accepted source; file contents remain bound by control-files.json.
CONTROL_TREE_SHA256 = '721e9b33b4f65e1a9516831bd77c53bad0029e1f870beaca460c20f03169641a'
def _control_tree(root):
    require(root.is_dir() and not root.is_symlink(), 'control root differs')
    entries = {}
    for path in root.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode): kind = 'directory'
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1: kind = 'file'
        else: raise ValueError('unsupported control tree member')
        entries[path.relative_to(root).as_posix()] = {'type':kind, 'mode':format(stat.S_IMODE(info.st_mode),'04o')}
    require(canonical(entries)==CONTROL_TREE_SHA256, 'complete copied control tree differs')
    return entries

def _source(p,receipt,spec):
    source_accept=Path(receipt['source_acceptance_path']); require(source_accept.is_absolute(),'source acceptance path must be absolute')
    root=source_accept.parent; source_inventory=Path(spec['source_inventory_path']); require(source_inventory.is_absolute() and source_inventory.name=='freeze-inventory.json','source inventory path differs'); src=source_inventory.parent
    accept=decode_json(pinned(source_accept,p['source_accept'],'source acceptance'))
    require(accept['schema']=='bashos-primary-device-source-acceptance-v1' and accept['decision']==p['decision'] and accept['approved_batches']==[p['batch']] and accept['approved_case_count']==len(p['ids']) and accept['root_fixtures_allowed'] is False and accept['runtime_results_pending'] is True and accept['consumer_sha256']==p['consumer'] and accept['source_inventory_sha256']==p['source_inventory'] and accept['copied_control_inventory_sha256']==p['control_inventory'] and accept['image_receipt_sha256']==p['image_receipt'],'source acceptance scope differs')
    image=decode_json(pinned(spec['image_receipt_path'],p['image_receipt'],'image acceptance'))
    require(image['schema']=='bashos-device-kernel-image-acceptance-v1' and image['decision']=='accept-image-qualification' and image['product_coverage'] is False,'image acceptance differs')
    frozen=decode_json(pinned(src/'freeze-inventory.json',p['source_inventory'],'source inventory'))
    require(isinstance(frozen['files'],dict) and frozen['files'],'source inventory empty')
    external = {name for name, entry in frozen['files'].items() if 'path' in entry}
    require(external == {'calendar-observer', 'system-sequence'}, 'frozen external source membership differs')
    supplied = spec.get('source_artifacts')
    require(isinstance(supplied, dict) and set(supplied) == external, 'external source paths missing or extra')
    local_names = set(frozen['files']) - external
    require({x.name for x in src.iterdir()} == local_names | {'freeze-inventory.json'}, 'frozen source membership differs')
    for name,entry in frozen['files'].items():
        rel=PurePosixPath(name)
        require(not rel.is_absolute() and len(rel.parts)==1 and str(rel)==name, 'unsafe frozen source name')
        path=Path(supplied[name]) if name in external else src/name
        require(path.is_absolute(), 'frozen source path must be absolute')
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==entry['bytes'] and file_sha(path)==entry['sha256'],'frozen source differs: '+name)
    control=decode_json(pinned(root/'control-files.json',p['control_inventory'],'copied control inventory'))
    _control_tree(root/'control')
    require({x.relative_to(root/'control').as_posix() for x in (root/'control').rglob('*') if x.is_file()}==set(control),'copied control inventory membership differs')
    for name,digest in control.items():
        rel=PurePosixPath(name);require(not rel.is_absolute() and '..' not in rel.parts and str(rel)==name,'unsafe control path')
        source_path=root/'control'/name; info=source_path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and file_sha(source_path)==digest,'copied control differs: '+name)
    index=decode_json(pinned(src/'device-index.json',p['index'],'device index'))
    require(index['batches'][p['batch']]==p['ids'] and {k:index['cases'][k] for k in p['ids']}==p['cases'],'index case pins differ')
    return root,control

def _run(p,build,root,control,manifest,review):
    run=p['runs'][build]; path=root/'results'/(build+'-'+p['batch']); _inventory(path,manifest)
    rec=decode_json(pinned(path/'evidence-record.json',run['record'],'saved evidence record')); u=run['uuid']
    require(review['state']=='completed' and review['build']==build and review['record_sha256']==run['record'] and review['vm_uuid']==u and review['candidate_sha256']==CORES[build] and set(review['case_results'])==set(p['ids']),'diagnostic raw review binding differs')
    require(rec['schema']=='device-consumer-evidence-v2' and rec['status']=='completed' and rec['qualification']=='framework-complete-device-adjudication-required' and rec['guest_summary_state']=='captured-unvalidated' and rec['product_acceptance'] is False and rec['root_fixtures_allowed'] is False and rec['candidate_sha256']==CORES[build]==run['candidate'] and rec['selected_case_ids']==p['ids'] and rec['vm_uuid']==u and rec['consumer_sha256']==p['consumer'] and rec['index_sha256']==p['index'] and rec['image_acceptance_sha256']==p['image_receipt'] and rec['image_sha256']==IMAGE_SHA and rec['manifest_sha256']==MANIFEST_SHA and rec['fixture_sha256']==run['fixture'],'record source/build/selection differs')
    flags=('scope_proven','guest_units_quiescent','overlay_discarded','candidate_unchanged','candidate_snapshot_unchanged','image_unchanged','manifest_unchanged','inventory_unchanged','consumer_unchanged','classifier_unchanged','staging_source_unchanged','staging_evidence_unchanged','vm_source_unchanged','payload_unchanged','index_unchanged','schema_unchanged','acceptance_unchanged','variant_unchanged','suites_unchanged','helpers_unchanged','compat_source_unchanged','namespace_source_unchanged','evaluation_source_unchanged','selfcheck_sources_unchanged','evidence_unchanged','compat_evidence_unchanged')
    require(all(rec.get(k) is True for k in flags) and rec['guest_status']==0 and not (path/'overlay.qcow2').exists() and not (path/'prepared.snapshot.qcow2').exists(),'integrity/disposal differs')
    require(file_sha(path/'candidate.snapshot')==CORES[build] and file_sha(path/'payload.tar')==rec['payload_sha256'] and file_sha(path/'evidence.tar')==rec['evidence_validation']['archive_sha256'],'candidate/archive differs')
    identity=rec['identity'];rb=identity['attestation']['readback'];token=(u+'\n').encode().hex()
    require(identity['marker_matches'] is True and identity['product_uuid_matches'] is True and identity['host_shared_mounts']==[] and rb['schema']=='bashos-vm-identity-attestation-v1' and rb['token']==u and rb['marker_hex']==rb['dmi_hex']==rb['attestation_hex']==token and all(rb[k].get('uid')==0 and rb[k].get('gid')==0 and rb[k].get('mode')==0o444 and rb[k].get('nlink')==1 and rb[k].get('type')=='regular' for k in ('marker','attestation')),'identity differs')
    ns=decode_json(pinned(path/'namespace-proof-208.json',rec['namespace_proof_sha256'],'namespace'));outer=decode_json(pinned(path/'parent-namespace.json',rec['parent_namespace_sha256'],'parent namespace'));att=decode_json(pinned(path/'namespace-attestation-208.json',rec['namespace_attestation_sha256'],'namespace attestation'));priv=decode_json(pinned(path/'privilege-proof.json',rec['privilege_proof_sha256'],'privilege'))
    require(ns==rec['namespace_proof']['evaluation'] and outer==rec['namespace_proof']['parent'] and ns['schema']=='bashos-syslog208-namespace-v1' and att['schema']=='bashos-syslog-namespace-attestation-v1' and ns['token']==ns['dmi_uuid']==att['token']==u and ns['uid']==ns['euid']==outer['uid']==outer['euid']==0 and ns['pid1_uid']==['0']*4 and ns['attestation']['sha256']==rec['namespace_attestation_sha256'] and all(ns['attestation'].get(k)==v for k,v in {'uid':0,'gid':0,'mode':0o444,'nlink':1}.items()) and ns['namespaces']==att['namespaces'] and ns['outer_namespaces']==att['outer_namespaces'] and ns['proc_interfaces']==ns['sysfs_interfaces']==['lo'] and all(isinstance(ns['namespaces'][k],str) and re.fullmatch(k+r':\[[0-9]+\]',ns['namespaces'][k]) and ns['namespaces'][k]!=outer[k] and ns['outer_namespaces'][k]==outer[k] for k in ('pid','net','mnt')),'namespace differs')
    require(priv==rec['privilege_proof'] and priv['vm_uuid']==u and (priv['uid'],priv['euid'],priv['gid'],priv['egid'])==(2000,2000,2000,2000) and priv['groups']==[] and priv['cap_eff']=='0000000000000000' and priv['no_new_privs']=='1','privilege differs')
    decode_json(pinned(path/'run.log.unit-proof.json',rec['guest_unit_proofs']['run.log.unit-proof.json'],'unit JSON'))
    unit_proof(path/'run.log.unit-proof.json',rec['guest_unit_proofs']['run.log.unit-proof.json'],u,'bashos-evaluation-'+u[:8]+'.service',0)
    comp=rec['compatibility']; decode_json(pinned(path/'compat/run.log.unit-proof.json',comp['proof_hashes']['run.log.unit-proof.json'],'compatibility unit JSON'))
    unit_proof(path/'compat/run.log.unit-proof.json',comp['proof_hashes']['run.log.unit-proof.json'],u,'bashos-optional-'+u[:8]+'-reference.service',0)
    handoff=comp['handoff'];require(handoff['schema']=='bashos-compat252-handoff-v1' and handoff['status']=='PASS' and handoff['vm_uuid']==u and handoff['selected_ids']==sorted(p['ids']) and handoff['candidate_sha256']==CORES[build] and handoff['canary_absent'] is True and handoff['service_exit']==0,'compatibility handoff differs')
    td=decode_json((path/'vm/teardown.json').read_bytes());group=td['scope_cgroup'];scope='parity-vm-'+u+'.scope'
    require(td==rec['teardown'] and td['vm_uuid']==u and td['scope_unit']==scope and td['scope_boot_observation']['state']=={'id':scope,'load':'loaded','active':'active','group':group} and td['scope_after']['load']=='not-found' and td['scope_after']['active']=='inactive' and td['cgroup_events']['removed'] is True and td['clean_poweroff'] is True and td['forced_stop'] is False and td['qemu_exit_status']==0 and td['poweroff_request']==0 and td['scope_quiescent'] is True and td['proof_durable'] is True,'scope/teardown differs')
    with tarfile.open(path/'payload.tar') as t:
        members=tar_members(t);require(all(x.isfile() for x in members),'non-file payload member');fixture_raw=safe_member(t,'harness/suites/optional-frozen.json');fixture=decode_json(fixture_raw);defs=fixture['cases']
        require(sha(fixture_raw)==rec['fixture_sha256'] and sha(safe_member(t,'candidate'))==CORES[build] and [x['id'] for x in defs]==p['ids'] and all(canonical(x)==p['cases'][x['id']] and x.get('privilege') is None and not x.get('optional') for x in defs),'payload fixture differs')
        for m in members:
            if m.name in ('candidate','harness/suites/optional-frozen.json'):continue
            require(m.name.startswith(('harness/','loadable-parity/')),'unexpected payload member')
            name=('tests/parity-vm/'+m.name[len('harness/'):] if m.name.startswith('harness/') else 'tests/'+m.name)
            require(name in control and control[name]==sha(safe_member(t,m.name)),'payload source differs: '+m.name)
    summary=decode_json(pinned(path/'guest-summary.json',rec['guest_summary_sha256'],'summary'));rows=summary['cases'];by={x['id']:x for x in rows};checks={'selfcheck-'+x for x in CHECKS}
    require(summary['vm_uuid']==u and summary['binary_sha256']==CORES[build] and summary['selected_case_ids']==sorted(p['ids']) and len(rows)==len(by)==len(p['ids'])+13 and set(by)==checks|set(p['ids']) and all(by[x]['status']=='PASS' for x in checks),'summary controls/selection differs')
    with tarfile.open(path/'evidence.tar') as t:
        tar_members(t);require(safe_member(t,'results/summary.json')==(path/'guest-summary.json').read_bytes(),'archived summary differs')
        for x in checks:require(decode_json(safe_member(t,'results/selfcheck/'+x.removeprefix('selfcheck-')+'.json'))=={k:v for k,v in by[x].items() if k!='kind'},'archived selfcheck differs')
        for cid in p['ids']:
            raw_bytes=safe_member(t,'results/'+cid+'/candidate.json');raw=decode_json(raw_bytes);require(sha(raw_bytes)==review['case_results'][cid]['raw_sha256'] and by[cid]['status']==review['case_results'][cid]['framework_status'] and by[cid]['group']=='shell' and by[cid]['status'] in ('PASS','FAIL') and type(raw['status']) is int,'raw case/summary differs')
    return {'build':build,'vm_uuid':u,'record_sha256':run['record'],'cases':len(p['ids']),'selfchecks':13}

def inspect_saved_pair(receipt,spec,review):
    """Revalidate fixed data for both builds; no independent authority."""
    p=_profile('calendar');root,control=_source(p,receipt,spec)
    inv=decode_json(pinned(spec['result_inventory_path'],p['result_inventory'],'independent result inventory'))
    require(inv['schema']=='rtc-result-inventory-diagnostic-v1' and set(inv['runs'])=={'static','dynamic'} and p['runs']['static']['uuid']!=p['runs']['dynamic']['uuid'],'paired inventory/identity differs')
    require(review['schema']=='rtc-calendar-v9-paired-raw-review-v1' and review['source_acceptance_sha256']==p['source_accept'] and review['state']=='source-and-saved-data-only-primary-adjudication-required' and review['subject_execution'] is False and set(review['builds'])=={'static','dynamic'},'primary raw review scope differs')
    return [_run(p,b,root,control,inv['runs'][b],review['builds'][b]) for b in ('static','dynamic')]

# No RTC product authority has been issued. A future activation changes only this
# registry after the exact primary receipt and this contract have been reviewed.
CALENDAR_FORMAT='primary-qualified-device-v8-rtc-calendar-v1'
RECEIPT_SCHEMA='bashos-device-v8-primary-receipt-v1'
DECISION='accept-reviewed-core-case-evidence'
RAW_REVIEW_SHA='5b274eaa494bcfab248211d9d5b0143b902f67669c5a9e3005d9c0f7e65ae60d'
CHECKER_SHA='f04cd876099a77bfa859e78b1b93d01bf5c99827fc02911b08a625e1b164ae70'
LIMITATIONS=[
 'RTC and clock replies are synthetic and do not establish physical RTC modification or a real host clock effect.',
 'Framework status is not by itself independent candidate attribution; rely on the full paired raw review and preserve reached failures and incomplete cases.',
 'Root fixtures remain held; retain prior evidence and unproved original requirements.',
]

def _receipt_calendar(receipt,spec):
    """Validate a receipt object after its bytes have passed source authority."""
    p=_profile('calendar');root=Path(receipt['source_acceptance_path']).parent;deny_noncore(receipt,'RTC calendar receipt')
    fields={'schema','decision','ledger_scope','core_ledger_eligible','base_commit','subject_execution_on_host','utc','primary_reviewer','source_acceptance_path','source_acceptance_sha256','source_inventory_sha256','copied_control_inventory_sha256','consumer_sha256','device_index_sha256','image_receipt_sha256','review_path','review_sha256','reviewer_source_path','reviewer_source_sha256','runs','coverage_note','limitations'}
    require(set(receipt)==fields and receipt['schema']==RECEIPT_SCHEMA and receipt['decision']==DECISION and receipt['ledger_scope']=='core' and receipt['core_ledger_eligible'] is True and receipt['base_commit']=='b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf' and receipt['subject_execution_on_host'] is False and isinstance(receipt['utc'],str) and receipt['utc'] and isinstance(receipt['primary_reviewer'],str) and receipt['primary_reviewer'] and isinstance(receipt['coverage_note'],str) and receipt['coverage_note'] and receipt['limitations']==LIMITATIONS,'RTC calendar receipt scope or bounds differ')
    require(receipt['source_acceptance_sha256']==p['source_accept'] and receipt['source_inventory_sha256']==p['source_inventory'] and receipt['copied_control_inventory_sha256']==p['control_inventory'] and receipt['consumer_sha256']==p['consumer'] and receipt['device_index_sha256']==p['index'] and receipt['image_receipt_sha256']==p['image_receipt'],'RTC calendar receipt sources differ')
    checker=receipt['reviewer_source_path']; review_path=receipt['review_path']
    require(receipt['review_sha256']==RAW_REVIEW_SHA and receipt['reviewer_source_sha256']==CHECKER_SHA,'RTC calendar primary audit binding differs')
    pinned(checker,CHECKER_SHA,'RTC calendar raw checker');review=decode_json(pinned(review_path,RAW_REVIEW_SHA,'RTC calendar primary raw audit'))
    require(set(receipt['runs'])=={'rtc-calendar-static','rtc-calendar-dynamic'},'RTC calendar paired run membership differs')
    inspect_saved_pair(receipt,spec,review)
    for build in ('static','dynamic'):
        item=receipt['runs']['rtc-calendar-'+build];expected=p['runs'][build];path=root/'results'/(build+'-rtc-calendar');r=decode_json(pinned(path/'evidence-record.json',expected['record'],'RTC calendar record'));v=review['builds'][build];u=expected['uuid']
        scope='ControlGroup=\nId=parity-vm-'+u+'.scope\nLoadState=not-found\nActiveState=inactive\n'
        require(set(item)=={'name','build','batch','selected_ids','groups','candidate_sha256','source_result','vm_uuid','record_sha256','payload_sha256','evidence_sha256','summary_sha256','teardown_sha256','cases','current_scope_raw','wrapper_absent','cgroup_absent'} and item['name']=='device-v8-rtc-calendar-'+build and item['build']==build and item['batch']=='rtc-calendar' and item['selected_ids']==p['ids'] and item['groups']==['shell'] and item['candidate_sha256']==CORES[build] and item['source_result']==str(path) and item['vm_uuid']==u and item['record_sha256']==expected['record'] and item['payload_sha256']==r['payload_sha256'] and item['evidence_sha256']==r['evidence_validation']['archive_sha256'] and item['summary_sha256']==r['guest_summary_sha256'] and item['teardown_sha256']==file_sha(path/'vm/teardown.json') and item['current_scope_raw']==scope and item['wrapper_absent'] is True and item['cgroup_absent'] is True and set(item['cases'])==set(p['ids']),'RTC calendar receipt run binding differs')
        summary=decode_json((path/'guest-summary.json').read_bytes());by={x['id']:x for x in summary['cases']}
        with tarfile.open(path/'evidence.tar') as t:
            tar_members(t)
            for cid in p['ids']:
                raw_bytes=safe_member(t,'results/'+cid+'/candidate.json');raw=decode_json(raw_bytes);actual=item['cases'][cid];obs=v['case_results'][cid];row=by[cid]
                require(actual=={'case_sha256':p['cases'][cid],'raw_sha256':sha(raw_bytes),'raw_status':raw['status'],'status':row['status'],'classification':obs['classification'],'group':row['group']} and obs['raw_sha256']==sha(raw_bytes) and obs['framework_status']==row['status'] and obs['classification']=='BOUNDED_PASS' and obs['controls_verified'] is True and row['status']=='PASS' and row['group']=='shell','RTC calendar receipt case/raw attribution differs: '+cid)
        require(v['status_counts']=={'BOUNDED_PASS':21,'REACHED_FAIL':0,'INCOMPLETE':0},'RTC calendar full audit counts differ')
    return p,receipt['runs']

def load_qualified_rtc_calendar(spec,expected_binary,expected_build):
    """Read only primary-authorized core evidence; never accept runtime authority."""
    require(expected_build in CORES and expected_binary==CORES[expected_build] and isinstance(spec,dict) and spec.get('evidence_format')==CALENDAR_FORMAT,'RTC calendar build/format differs')
    deny_noncore(spec,'RTC calendar selection');p=_profile('calendar')
    require(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==p['ids'] and not spec.get('exclude_ids') and spec.get('receipt_run')=='rtc-calendar-'+expected_build and spec.get('name')=='device-v8-rtc-calendar-'+expected_build,'RTC calendar selection differs')
    pin=spec.get('primary_receipt');require(isinstance(pin,dict) and set(pin)=={'path','sha256'} and pin['sha256'] in CALENDAR_AUTHORIZED_RECEIPTS,'RTC primary product receipt is not authorized in source')
    receipt=decode_json(pinned(pin['path'],pin['sha256'],'RTC calendar primary receipt'));p,runs=_receipt_calendar(receipt,spec)
    run=runs[spec['receipt_run']];root=Path(spec['path']);require(root.is_absolute() and str(root.resolve(strict=True))==run['source_result'] and Path(spec['core_binary_path']).is_absolute() and file_sha(spec['core_binary_path'])==expected_binary,'RTC calendar selected result or core binary differs')
    summary=decode_json((root/'guest-summary.json').read_bytes());by={x['id']:x for x in summary['cases']}
    with tarfile.open(root/'payload.tar') as t:
        tar_members(t);defs={c['id']:c for c in decode_json(safe_member(t,'harness/suites/optional-frozen.json'))['cases']}
    selected=[{'record':by[cid],'definition':defs[cid],'sources':{},'run':spec['name']} for cid in p['ids']]
    return selected,{'name':spec['name'],'groups':['shell'],'selected_records':len(selected),'evidence_format':CALENDAR_FORMAT,'primary_receipt_sha256':pin['sha256'],'candidate_sha256':expected_binary,'vm_uuid':run['vm_uuid'],'record_sha256':run['record_sha256'],'evidence_sha256':run['evidence_sha256'],'limitations':receipt['limitations']}
