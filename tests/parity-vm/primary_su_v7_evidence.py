#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Receipt-gated SU v7 bounded evidence reader; accepts only the pinned primary receipt."""
import json, stat, tarfile
from pathlib import Path,PurePosixPath
from primary_controller_evidence import require,sha,file_sha,pinned,canonical,safe_member,tar_members,deny_noncore

IDS = ['su-bounded-absent-device-noexec-r1', 'su-bounded-owned-fork-eagain-r1', 'su-bounded-owned-wait-echild-r1']
CASE_HASHES = {'su-bounded-absent-device-noexec-r1': 'fa2fd5d2f1a80fcb511ffa0d45355a86ee0d2236f655c455eecfe0b40c8666bb',
 'su-bounded-owned-fork-eagain-r1': 'fd3a4edc41db8202044bf8460c0aaba7653fab8eaa6b5c86ae0242962f3a0ff9',
 'su-bounded-owned-wait-echild-r1': '973de275c78dceec135ec432fa52bef0f8da7ab7762a3c67a11ae8ec3fa02abb'}
RUNS = {'dynamic': {'candidate': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2',
             'evidence': '27aa716d48b56eb2c7cccaec1f5bf3c385ca813b6396fca0374268c8cf7d175f',
             'payload': 'b65cc3dea67c654d5af85ebba527e4b34737176da302cae85e00e75266930c18',
             'quiescence': '4a9c2ccb5cdc6b6650c4ab62068bc6d9739a1fe2c6ee1854c55b2ce77c50aedf',
             'raw': {'su-bounded-absent-device-noexec-r1': '9bb57bed00cee845c670970d893ec3ff7ebe6dae6e23b5f3743389e67528779c',
                     'su-bounded-owned-fork-eagain-r1': '5d225ec28d491ea13e8cbc5e981c6179cbac76020269b449500f05982f6577f9',
                     'su-bounded-owned-wait-echild-r1': '0f7b8b1c289a9fdb28c387fecc311d4aa4a65bb8ff2c95db111249d98dd15852'},
             'record': 'edee57545bc9c991eeee138ffda069595ba5683393f54c77254f0861afc79364',
             'summary': '29b0e2afd24556e0d8c48e08a39a42dc045fa27fdbc10f2ce21482e958a5d37b',
             'teardown': '96bee65148f3f96449145d5058f74233110eb1167c066828567c3e21d76b9ac3',
             'uuid': '1e86c996-06f7-447f-b816-f4ab51b43d4c'},
 'static': {'candidate': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab',
            'evidence': '052e601a6ed6b85d262e1df7d15f87158621d52cdfb895a130f50a80fda0711d',
            'payload': 'c5c9c9c6f26b4e770dacc81abb4870b3114d8dd47b044090f5745249cd533805',
            'quiescence': 'f170676e7f7ab35088fa0b0d09be7eb2cf9b79cce1f0fe80194a2593966821e7',
            'raw': {'su-bounded-absent-device-noexec-r1': 'd3c141f7c5d3411f33ab79e6983fd91e3d362d89ec0533d7bcb04801c0ecd56d',
                    'su-bounded-owned-fork-eagain-r1': '6945243e15907c8d1fc64da7825b6339e0d80948a9430202b5e1fb53d93a8cdf',
                    'su-bounded-owned-wait-echild-r1': '7fd9ee296b31cead6c1326788c6a4e55ccdbaa6a28dab20af3bf794435ddd70c'},
            'record': 'fd423a88064aa546a348adcc093aa1ea3b67f92865b644e8e3cde9ce2f3a4284',
            'summary': '2aabe0fe8937ba32b04eb9db9679fbbaeef40933b7251b999a9fb3ff2aac5022',
            'teardown': 'f933abaab55d30ffe6f7232278c8ea387d87a2ec06c91ce7f9a4da5a46ef08eb',
            'uuid': 'e9f3868c-2fba-493d-97ce-032c9d0adb45'}}
FREEZE = '856bad5bbbd56dc3215bc093be89a67f3eb7394abeed9ede72e3312e113d76f6'
SOURCE_ACCEPT = '94313f66655e7678690ada4af380dbd1b45f2edd49badfbc15b222763ad681f5'
AUDIT = '407492764b87aa33e0f54be90bbb0ee63738414de5817248417a79415483858a'
CHECKER = 'becd71c4172884d4d04a5b927a9bcf925adddc99bd0d9d4f14410b6bd7a03789'
FORMAT = 'primary-qualified-su-v7-bounded-v1'
LIMITATIONS = ['Fork and wait errors are synthetic seccomp notification injections; this is bounded behavior only.',
 'Noexec tracing acknowledges PR_SET_DUMPABLE without applying it; no general dumpability or authentication '
 'claim follows.',
 'The wait proof establishes same-parent collection only, not normal child success.',
 'No full-topic or other requirement coverage follows from these three cases.']
AUTHORIZED_RECEIPTS = frozenset({'f64b9faade4d3dbce6d174e75da958244cc3bf585b093af2dd1f1d11f4e7fdec'})

def decode(data):
    def unique(pairs):
        out={}
        for k,v in pairs:
            require(k not in out,'duplicate JSON key');out[k]=v
        return out
    def bad(_):raise ValueError('non-finite JSON number')
    return json.loads(data,object_pairs_hook=unique,parse_constant=bad)

def inventory(root,items):
    require(isinstance(items,dict) and items and root.is_dir(),'inventory missing')
    require({p.relative_to(root).as_posix() for p in root.rglob('*') if p.relative_to(root).as_posix() not in ('provenance.json','provenance.sha256')}==set(items),'inventory membership')
    for name,meta in items.items():
        path=PurePosixPath(name);require(not path.is_absolute() and '..' not in path.parts and str(path)==name,'inventory path')
        p=root/name;s=p.lstat();require(format(stat.S_IMODE(s.st_mode),'04o')==meta['mode'],'inventory mode')
        if meta['type']=='file':require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==meta['bytes'] and file_sha(p)==meta['sha256'],'inventory file')
        elif meta['type']=='directory':require(stat.S_ISDIR(s.st_mode),'inventory directory')
        else:raise ValueError('inventory node')

def check_current(path,expected,record,root):
    q=decode(pinned(path,expected['quiescence'],'current quiescence'));u=expected['uuid'];scope='parity-vm-'+u+'.scope';cmd=q['scope_command']
    require(q['schema']=='primary-current-owned-quiescence-v1' and q['vm_uuid']==u and q['scope']==scope and q['record_sha256']==expected['record'] and q['teardown_sha256']==expected['teardown'] and q['wrapper_pid']==record['teardown']['wrapper_pid'] and Path(q['result']).name==root.name and q['cgroup_absent'] is q['wrapper_absent'] is q['overlay_absent'] is True,'current quiescence')
    require(cmd=={'stdout':'ControlGroup=\nId='+scope+'\nLoadState=not-found\nActiveState=inactive\n','stderr':'','returncode':0},'scope current proof')

def validate_receipt(receipt,spec):
    fields={'schema','decision','ledger_scope','core_ledger_eligible','subject_execution_on_host','primary_reviewer','utc','source_acceptance_sha256','source_freeze_sha256','raw_audit_sha256','raw_checker_sha256','runs','limitations'}
    require(set(receipt)==fields and receipt['schema']=='bashos-su-v7-primary-receipt-v1' and receipt['decision']=='accept-bounded-su-v7-case-evidence' and receipt['ledger_scope']=='core' and receipt['core_ledger_eligible'] is True and receipt['subject_execution_on_host'] is False and type(receipt['primary_reviewer']) is str and bool(receipt['primary_reviewer']) and type(receipt['utc']) is str and bool(receipt['utc']) and receipt['limitations']==LIMITATIONS,'receipt scope')
    require(receipt['source_acceptance_sha256']==SOURCE_ACCEPT and receipt['source_freeze_sha256']==FREEZE and receipt['raw_audit_sha256']==AUDIT and receipt['raw_checker_sha256']==CHECKER and receipt['runs']==RUNS,'receipt evidence pins')
    accept=decode(pinned(spec['source_acceptance_path'],SOURCE_ACCEPT,'source acceptance'));require(accept['decision']=='accept-source-and-bounded-vm-plan' and accept['freeze_sha256']==FREEZE and accept['product_coverage'] is False and accept['root_fixtures_allowed'] is False,'source acceptance')
    pinned(spec['raw_checker_path'],CHECKER,'raw checker');audit=decode(pinned(spec['raw_audit_path'],AUDIT,'primary raw audit'))
    require(audit['schema']=='su-v7-raw-data-only-review-v2' and audit['source_freeze_sha256']==FREEZE and audit['subject_execution'] is False and audit['primary_adjudication']=='pending' and set(audit['builds'])==set(RUNS),'audit scope')
    for b,r in RUNS.items():
        a=audit['builds'][b];require(a['vm_uuid']==r['uuid'] and a['provenance_sha256']==r['record'] and a['evidence_tar_sha256']==r['evidence'] and a['payload_sha256']==r['payload'] and a['controls']==14 and a['unit_and_teardown']=='verified saved proofs' and set(a['cases'])==set(IDS),'audit run')
        for cid in IDS:require(a['cases'][cid]=={'classification':'BOUNDED_PASS','status':1,'observer_completed':True,'raw_sha256':r['raw'][cid],'framework_status':'PASS'},'audit case')
    return audit

def load_qualified_su_v7(spec,expected_binary,expected_build):
    require(expected_build in RUNS and expected_binary==RUNS[expected_build]['candidate'] and isinstance(spec,dict) and spec.get('evidence_format')==FORMAT,'build/format');deny_noncore(spec,'SU selection')
    require(spec.get('ledger_scope')=='core' and spec.get('core_ledger_eligible') is True and spec.get('groups')==['shell'] and spec.get('ids')==IDS and not spec.get('exclude_ids') and spec.get('name')=='su-v7-'+expected_build and spec.get('receipt_run')==expected_build,'selection')
    pin=spec.get('primary_receipt');require(isinstance(pin,dict) and set(pin)=={'path','sha256'} and pin['sha256'] in AUTHORIZED_RECEIPTS,'SU primary receipt is not source authorized')
    receipt=decode(pinned(pin['path'],pin['sha256'],'primary receipt'));validate_receipt(receipt,spec)
    require(set(spec['run_paths'])==set(RUNS) and set(spec['quiescence_paths'])==set(RUNS),'paired paths')
    for b,v in RUNS.items():
        other=Path(spec['run_paths'][b]);require(other.is_absolute() and other.name=='su-bounded-'+b,'paired path')
        provenance=decode(pinned(other/'provenance.json',v['record'],'paired provenance'));require(file_sha(other/'vm/teardown.json')==v['teardown'] and not (other/'overlay.qcow2').exists(),'paired teardown')
        check_current(spec['quiescence_paths'][b],v,provenance,other)
    root=Path(spec['path']);require(root.resolve()==Path(spec['run_paths'][expected_build]).resolve(),'selected path differs');require(root.is_absolute() and root.name=='su-bounded-'+expected_build and root.is_dir() and Path(spec['core_binary_path']).is_absolute() and file_sha(spec['core_binary_path'])==expected_binary,'result/core selection');r=RUNS[expected_build]
    p=decode(pinned(root/'provenance.json',r['record'],'provenance'));require((root/'provenance.sha256').read_text().split()[0]==r['record'],'provenance sidecar');inventory(root,p['artifacts'])
    require(p['status']=='completed' and p['qualification']=='complete-evidence-not-product-pass' and p['candidate']==expected_build and p['candidate_sha256']==expected_binary and p['vm_uuid']==r['uuid'] and p['selected_case_ids']==p['product_case_ids']==IDS and p['control_case_ids']==[] and p['root_fixtures_allowed'] is False and p['host_mounts']==[] and p['payload_sha256']==r['payload'] and p['evidence_validation']['archive_sha256']==r['evidence'] and p['guest_summary_sha256']==r['summary'],'saved provenance')
    require(file_sha(root/'candidate.snapshot')==expected_binary and file_sha(root/'payload.tar')==r['payload'] and file_sha(root/'evidence.tar')==r['evidence'] and file_sha(root/'vm/teardown.json')==r['teardown'] and not (root/'overlay.qcow2').exists(),'archive or lifecycle')
    check_current(spec['quiescence_paths'][expected_build],r,p,root)
    summary_bytes=pinned(root/'summary.json',r['summary'],'summary');require((root/'guest-summary.json').read_bytes()==summary_bytes,'guest summary');summary=decode(summary_bytes);rows=summary['cases'];by={x['id']:x for x in rows};require(len(rows)==len(by)==17 and summary['binary_sha256']==expected_binary and summary['vm_uuid']==r['uuid'] and [x['id'] for x in rows[14:]]==IDS and all(x['status']=='PASS' and x['group']=='selfcheck' for x in rows[:14]),'selected rows and controls')
    with tarfile.open(root/'payload.tar') as t:
        tar_members(t);defs=decode(safe_member(t,'harness/suites/optional-frozen.json'))['cases'];require([x['id'] for x in defs]==IDS and all(canonical(x)==CASE_HASHES[x['id']] for x in defs),'case definitions')
    with tarfile.open(root/'evidence.tar') as t:
        tar_members(t);require(safe_member(t,'results/summary.json')==summary_bytes,'archived summary')
        for cid in IDS:
            data=safe_member(t,'results/'+cid+'/candidate.json');raw=decode(data);row=by[cid];require(sha(data)==r['raw'][cid] and row['status']=='PASS' and row['group']=='shell' and row['kind']=='contract' and raw['status']==0 and raw.get('error') is None and raw.get('harness_error') is None and raw.get('decoder_error') is None,'raw selected case')
    selected=[{'record':by[cid],'definition':defs[i],'sources':{},'run':spec['name']} for i,cid in enumerate(IDS)]
    return selected,{'name':spec['name'],'groups':['shell'],'selected_records':3,'evidence_format':FORMAT,'primary_receipt_sha256':pin['sha256'],'candidate_sha256':expected_binary,'vm_uuid':r['uuid'],'record_sha256':r['record'],'evidence_sha256':r['evidence'],'limitations':LIMITATIONS}
