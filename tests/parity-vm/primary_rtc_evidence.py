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

EFFECTS_PROFILE={'batch': 'rtc-effects',
 'cases': {'devices-hwclock-adjust-last-zero-r1': '821047e17575a8979ac2012e2d6a91de4b83d9365aac0cc1bdd4ba4a5d95f18a',
           'devices-hwclock-adjust-negative-r1': '9fc6efa2c76a8a3addcab17e268946e3c08be5e69900fd4e168b9e46e493b7f5',
           'devices-hwclock-adjust-noadjfile-r1': '8411b6da1b238dace4e8e0b284a3e2c30eff1b7432dfc76cf6e58f9e55d43ac4',
           'devices-hwclock-adjust-positive-r1': '7d7e933dfd2c7383bae07d69dc7800298c4f9841a43c8b4d6439b56522470320',
           'devices-hwclock-adjust-subsecond-r1': '4f25d760a790ddc81fb38d1e6a4b380e52dd97b4ece5f229a25aed116880335d',
           'devices-hwclock-rename-error-r1': 'c456471974d644956ef352006bb1b4bf90b6f4da9bfa1653fc38c5f127832c8e',
           'devices-hwclock-rtc-close-error-r1': '39ee68c68aa4b44e83c948874ab1484a762ac3db34e5d0418e47388fd5d68be6',
           'devices-hwclock-rtc-open-error-r1': '64121b06ca74021791afee4487752614538e280946f1b061415367338221ce1b',
           'devices-hwclock-rtc-read-error-r1': '73c2adf88e5a2ea7f079be1caa23848964d648782bf216f5c3b142c6d4d5ff0e',
           'devices-hwclock-rtc-write-error-r1': '45f446b56dfac2f2993a36ad7f5eec9349e4c4f7755007a053295aeac73f1693',
           'devices-hwclock-systohc-local-r1': '773b19d6db17b88e7823c872c179f11c046b60fa831436e954f9ae035303ba0a',
           'devices-hwclock-systohc-noadjfile-r1': 'd91e187189e3deefe8c940ba6c6596734ec34c54e6a594fff7ff6a8091465f41',
           'devices-hwclock-systohc-utc-r1': '44e1afa4f8a9fa0d2da35c822b525cb4214d22db3c581e157af741c491327cb9',
           'devices-hwclock-temp-close-error-r1': '245667ae2161d3a5f26689233d9453d344280c87223a40cbaa477335f38f09a0',
           'devices-hwclock-temp-open-error-r1': '1f3e5ca7cb3acfecd90763276e90921870398bb11d31492126d45f72742dbc78',
           'devices-hwclock-temp-write-error-r1': 'b0745983f5b959345ae5277190a729a9ae640cdeadce337eb2616c038f918abc'},
 'consumer': '273d564058239c61db5e6a175600465e6bef4e3c1db1f68b30d5fecc5b36e5f7',
 'control_inventory': '00c7c38cec47fc5f2f225969e4d170af6dbe780f3428f2b70b603738f2180a93',
 'decision': 'accept-device-consumer-v8-for-bounded-nonroot-rtc-effects-qualification',
 'ids': ['devices-hwclock-adjust-positive-r1',
         'devices-hwclock-adjust-negative-r1',
         'devices-hwclock-adjust-subsecond-r1',
         'devices-hwclock-adjust-last-zero-r1',
         'devices-hwclock-adjust-noadjfile-r1',
         'devices-hwclock-systohc-utc-r1',
         'devices-hwclock-systohc-local-r1',
         'devices-hwclock-systohc-noadjfile-r1',
         'devices-hwclock-rtc-open-error-r1',
         'devices-hwclock-rtc-read-error-r1',
         'devices-hwclock-rtc-close-error-r1',
         'devices-hwclock-rtc-write-error-r1',
         'devices-hwclock-temp-open-error-r1',
         'devices-hwclock-temp-write-error-r1',
         'devices-hwclock-temp-close-error-r1',
         'devices-hwclock-rename-error-r1'],
 'image_receipt': 'b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6',
 'index': '4432874e4c66d423d470aca55c49905ce83a168829cf67e4e456d68986265f1a',
 'result_inventory': '1f81a4776bb3e1596399afaf4037cab6d4c3ab3350d770e8768e43766eca4de1',
 'runs': {'dynamic': {'candidate': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
                      'fixture': 'e8848c14e9877b001068d6edaf405173087e67a3675809cd7e0cc97bf28175b7',
                      'index': '4432874e4c66d423d470aca55c49905ce83a168829cf67e4e456d68986265f1a',
                      'record': 'f5568652be347d7e57a798d528f9554ccd38fb2898dbf2cab696720669a2cfde',
                      'uuid': '264cb12e-15d6-4abe-9c62-b05bfa897eab'},
          'static': {'candidate': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
                     'fixture': 'e8848c14e9877b001068d6edaf405173087e67a3675809cd7e0cc97bf28175b7',
                     'index': '4432874e4c66d423d470aca55c49905ce83a168829cf67e4e456d68986265f1a',
                     'record': '1724c3b0d307bf891f666b76b452284986f06d89d751f1ab28afe23dd6a68e52',
                     'uuid': '1cbca443-1047-474d-a188-f6d6d9c95949'}},
 'source_accept': 'fc560abb7abd5c588f71ab2e27d35f43dc1cdf4600f72e07ec50e508e3d641e3',
 'source_inventory': 'b15ec9af6054bad35bc649113c73834149b00d84d4953d3e33269e00e13d620d'}
EFFECTS_AUTHORIZED_RECEIPTS=frozenset({'9dc5e8b35710f08c8782d6cafe9406a99309736198aaf356c08f856465eb8f0f'})
CALENDAR_AUTHORIZED_RECEIPTS=frozenset()
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
    require(key=='effects','unknown RTC profile')
    return EFFECTS_PROFILE

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
CONTROL_TREE_SHA256 = '60d778efd8ae9ee229edf55f03af1bec74cd7e9e858c2a3c6adcaca1b8addc2a'
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
    for name,entry in frozen['files'].items():
        path=Path(entry['path']) if 'path' in entry else src/name
        require(path.is_file() and path.stat().st_size==entry['bytes'] and file_sha(path)==entry['sha256'],'frozen source differs: '+name)
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
    p=_profile('effects');root,control=_source(p,receipt,spec)
    inv=decode_json(pinned(spec['result_inventory_path'],p['result_inventory'],'independent result inventory'))
    require(inv['schema']=='rtc-result-inventory-diagnostic-v1' and set(inv['runs'])=={'static','dynamic'} and p['runs']['static']['uuid']!=p['runs']['dynamic']['uuid'],'paired inventory/identity differs')
    require(review['schema']=='rtc-effects-paired-raw-review-v1' and review['source_acceptance_sha256']==p['source_accept'] and review['state']=='source-and-saved-data-only-primary-adjudication-required' and review['subject_execution'] is False and set(review['builds'])=={'static','dynamic'},'primary raw review scope differs')
    return [_run(p,b,root,control,inv['runs'][b],review['builds'][b]) for b in ('static','dynamic')]

# No RTC product authority has been issued. A future activation changes only this
# registry after the exact primary receipt and this contract have been reviewed.
EFFECTS_FORMAT='primary-qualified-device-v8-rtc-effects-v1'
RECEIPT_SCHEMA='bashos-device-v8-primary-receipt-v1'
DECISION='accept-reviewed-core-case-evidence'
RAW_REVIEW_SHA='c0e18c7658207960fd9ed8457a0b92884567407e6e4bb6cd3511f00db7573df3'
CHECKER_SHA='75e015ffc87dcd14dbfb8ebfd5fd199fa08871246d433fa92d3530cd05dd7b84'
LIMITATIONS=[
 'RTC and clock replies are synthetic and do not establish physical RTC modification or a real host clock effect.',
 'Filesystem effects are observed in guest scratch only.',
 'Synthetic close EIO skips real close; it does not demonstrate descriptor cleanup following a real close failure.',
 'Framework status is not by itself independent candidate attribution; rely on the full paired raw review and preserve reached failures and incomplete cases.',
 'Root fixtures remain held; retain prior evidence and unproved original requirements.',
]

def _receipt_effects(receipt,spec):
    """Validate a receipt object after its bytes have passed source authority."""
    p=_profile('effects');root=Path(receipt['source_acceptance_path']).parent;deny_noncore(receipt,'RTC effects receipt')
    fields={'schema','decision','ledger_scope','core_ledger_eligible','base_commit','subject_execution_on_host','utc','primary_reviewer','source_acceptance_path','source_acceptance_sha256','source_inventory_sha256','copied_control_inventory_sha256','consumer_sha256','device_index_sha256','image_receipt_sha256','review_path','review_sha256','reviewer_source_path','reviewer_source_sha256','runs','coverage_note','limitations'}
    require(set(receipt)==fields and receipt['schema']==RECEIPT_SCHEMA and receipt['decision']==DECISION and receipt['ledger_scope']=='core' and receipt['core_ledger_eligible'] is True and receipt['base_commit']=='b561888e4a2ee10366bc61fe85bc8aeee2b6fdcf' and receipt['subject_execution_on_host'] is False and isinstance(receipt['utc'],str) and receipt['utc'] and isinstance(receipt['primary_reviewer'],str) and receipt['primary_reviewer'] and isinstance(receipt['coverage_note'],str) and receipt['coverage_note'] and receipt['limitations']==LIMITATIONS,'RTC effects receipt scope or bounds differ')
    require(receipt['source_acceptance_sha256']==p['source_accept'] and receipt['source_inventory_sha256']==p['source_inventory'] and receipt['copied_control_inventory_sha256']==p['control_inventory'] and receipt['consumer_sha256']==p['consumer'] and receipt['device_index_sha256']==p['index'] and receipt['image_receipt_sha256']==p['image_receipt'],'RTC effects receipt sources differ')
    checker=receipt['reviewer_source_path']; review_path=receipt['review_path']
    require(receipt['review_sha256']==RAW_REVIEW_SHA and receipt['reviewer_source_sha256']==CHECKER_SHA,'RTC effects primary audit binding differs')
    pinned(checker,CHECKER_SHA,'RTC effects raw checker');review=decode_json(pinned(review_path,RAW_REVIEW_SHA,'RTC effects primary raw audit'))
    require(set(receipt['runs'])=={'rtc-effects-static','rtc-effects-dynamic'},'RTC effects paired run membership differs')
    inspect_saved_pair(receipt,spec,review)
    for build in ('static','dynamic'):
        item=receipt['runs']['rtc-effects-'+build];expected=p['runs'][build];path=root/'results'/(build+'-rtc-effects');r=decode_json(pinned(path/'evidence-record.json',expected['record'],'RTC effects record'));v=review['builds'][build];u=expected['uuid']
        scope='ControlGroup=\nId=parity-vm-'+u+'.scope\nLoadState=not-found\nActiveState=inactive\n'
        require(set(item)=={'name','build','batch','selected_ids','groups','candidate_sha256','source_result','vm_uuid','record_sha256','payload_sha256','evidence_sha256','summary_sha256','teardown_sha256','cases','current_scope_raw','wrapper_absent','cgroup_absent'} and item['name']=='device-v8-rtc-effects-'+build and item['build']==build and item['batch']=='rtc-effects' and item['selected_ids']==p['ids'] and item['groups']==['shell'] and item['candidate_sha256']==CORES[build] and item['source_result']==str(path) and item['vm_uuid']==u and item['record_sha256']==expected['record'] and item['payload_sha256']==r['payload_sha256'] and item['evidence_sha256']==r['evidence_validation']['archive_sha256'] and item['summary_sha256']==r['guest_summary_sha256'] and item['teardown_sha256']==file_sha(path/'vm/teardown.json') and item['current_scope_raw']==scope and item['wrapper_absent'] is True and item['cgroup_absent'] is True and set(item['cases'])==set(p['ids']),'RTC effects receipt run binding differs')
        summary=decode_json((path/'guest-summary.json').read_bytes());by={x['id']:x for x in summary['cases']}
        with tarfile.open(path/'evidence.tar') as t:
            tar_members(t)
            for cid in p['ids']:
                raw_bytes=safe_member(t,'results/'+cid+'/candidate.json');raw=decode_json(raw_bytes);actual=item['cases'][cid];obs=v['case_results'][cid];row=by[cid]
                require(actual=={'case_sha256':p['cases'][cid],'raw_sha256':sha(raw_bytes),'raw_status':raw['status'],'status':row['status'],'classification':obs['classification'],'group':row['group']} and obs['raw_sha256']==sha(raw_bytes) and obs['framework_status']==row['status'] and obs['classification']=='BOUNDED_PASS' and obs['controls_verified'] is True and row['status']=='PASS' and row['group']=='shell','RTC effects receipt case/raw attribution differs: '+cid)
        require(v['status_counts']=={'BOUNDED_PASS':16,'REACHED_FAIL':0,'INCOMPLETE':0},'RTC effects full audit counts differ')
    return p,receipt['runs']

def load_qualified_rtc_effects(spec,expected_binary,expected_build):
    """Read only primary-authorized core evidence; never accept runtime authority."""
    require(expected_build in CORES and expected_binary==CORES[expected_build] and isinstance(spec,dict) and spec.get('evidence_format')==EFFECTS_FORMAT,'RTC effects build/format differs')
    deny_noncore(spec,'RTC effects selection');p=_profile('effects')
    require(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==p['ids'] and not spec.get('exclude_ids') and spec.get('receipt_run')=='rtc-effects-'+expected_build and spec.get('name')=='device-v8-rtc-effects-'+expected_build,'RTC effects selection differs')
    pin=spec.get('primary_receipt');require(isinstance(pin,dict) and set(pin)=={'path','sha256'} and pin['sha256'] in EFFECTS_AUTHORIZED_RECEIPTS,'RTC primary product receipt is not authorized in source')
    receipt=decode_json(pinned(pin['path'],pin['sha256'],'RTC effects primary receipt'));p,runs=_receipt_effects(receipt,spec)
    run=runs[spec['receipt_run']];root=Path(spec['path']);require(root.is_absolute() and str(root.resolve(strict=True))==run['source_result'] and Path(spec['core_binary_path']).is_absolute() and file_sha(spec['core_binary_path'])==expected_binary,'RTC effects selected result or core binary differs')
    summary=decode_json((root/'guest-summary.json').read_bytes());by={x['id']:x for x in summary['cases']}
    with tarfile.open(root/'payload.tar') as t:
        tar_members(t);defs={c['id']:c for c in decode_json(safe_member(t,'harness/suites/optional-frozen.json'))['cases']}
    selected=[{'record':by[cid],'definition':defs[cid],'sources':{},'run':spec['name']} for cid in p['ids']]
    return selected,{'name':spec['name'],'groups':['shell'],'selected_records':len(selected),'evidence_format':EFFECTS_FORMAT,'primary_receipt_sha256':pin['sha256'],'candidate_sha256':expected_binary,'vm_uuid':run['vm_uuid'],'record_sha256':run['record_sha256'],'evidence_sha256':run['evidence_sha256'],'limitations':receipt['limitations']}

def load_qualified_rtc_calendar(*args,**kwargs):
    raise ValueError('RTC calendar primary receipt and raw adjudication not yet reviewed')
