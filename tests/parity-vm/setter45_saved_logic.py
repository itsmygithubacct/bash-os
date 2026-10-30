"""Data-only functions extracted from pinned primary checker; path portability change documented."""
import base64,datetime,hashlib,io,json,re,stat,struct,tarfile,uuid
from pathlib import Path,PurePosixPath
C=R=PACK=None
SAFE_FILES=None
STATIC='a2da5864919002481ca9e212dfb022c39d776cbb8181084b4151924dfe0d7cef'
CORES={'static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab','dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2'}
def sha(b):return hashlib.sha256(b).hexdigest()

def read(p):return p.read_bytes()

def fh(p):return sha(read(p))

def j(p):return json.loads(read(p))

def need(x,msg):
 if not x:raise ValueError(msg)

def member(t,n):
 m=t.getmember(n);need(m.isfile() and 0<=m.size<64*1024**2,'invalid member '+n);b=t.extractfile(m).read(m.size+1);need(len(b)==m.size,'truncated '+n);return b

def open_tar(p,expected):
 b=read(p);need(sha(b)==expected,'archive snapshot hash differs');t=tarfile.open(fileobj=io.BytesIO(b),mode='r:');xs=t.getmembers();need(len(xs)==len({x.name for x in xs}),'duplicate tar path')
 for x in xs:
  z=PurePosixPath(x.name);need(not z.is_absolute() and '..' not in z.parts and str(z)==x.name and (x.isfile() or x.isdir()),'unsafe tar path')
 return t

def diag(raw,n):
 d=raw['diagnostics'][n];need(not d.get('missing') and d.get('truncated') is False and not d.get('error'),'diagnostic missing '+n);b=base64.b64decode(d['base64'],validate=True);need(len(b)==d['captured_bytes'],'diagnostic size '+n);return b

def require(condition, message):
    if not condition:
        raise ValueError(message)

def pinned(path, expected, label):
    path = Path(path)
    require(path.is_absolute() and re.fullmatch(r'[0-9a-f]{64}', expected or '') is not None,
            'invalid ' + label + ' pin')
    data = path.read_bytes()
    require(sha(data) == expected, label + ' hash mismatch')
    return data

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

def inspect(build,cases,index,freeze):
 path=R/'results'/(build+'-setter-fork');record=path/'evidence-record.json'
 if not record.exists():
  pending={'state':'PENDING','build':build,'no_verdict':True}
  if path.is_dir():pending['partial_raw_preserved']=True
  return pending
 if build=='static':need(fh(record)==STATIC,'static evidence record pin')
 p=j(record);result={'state':p.get('status'),'record_sha256':fh(record),'build':build,'case_results':{},'no_primary_receipt':True}
 need(p.get('status')=='completed','run incomplete; preserve raw without qualification')
 need(p['qualification']=='framework-complete-device-adjudication-required' and p['product_acceptance'] is False and p['root_fixtures_allowed'] is False and p['candidate_sha256']==CORES[build] and p['selected_case_ids']==[x['id'] for x in cases],'run selection')
 need(p['image_sha256']=='08442265e7135133c25936899ffc1cc19530b339b216c35a3ad42e072eee668a' and p['manifest_sha256']=='b7fdb3c8df4f38d9f5d988858731950c6c24229e874eeab18fe5951b40b34569','image digest');need(p['consumer_sha256']==fh(PACK/'fork-consumer.py') and p['index_sha256']==fh(PACK/'device-index.json') and p['device_schema_sha256']==fh(PACK/'device_schema.py') and p['image_acceptance_sha256']=='b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6','source or image pins')
 expected_flags={'acceptance_unchanged','candidate_snapshot_unchanged','candidate_unchanged','classifier_unchanged','compat_evidence_unchanged','compat_source_unchanged','consumer_unchanged','evaluation_source_unchanged','evidence_unchanged','helpers_unchanged','image_unchanged','index_unchanged','inventory_unchanged','manifest_unchanged','namespace_source_unchanged','payload_unchanged','schema_unchanged','selfcheck_sources_unchanged','staging_evidence_unchanged','staging_source_unchanged','suites_unchanged','variant_unchanged','vm_source_unchanged'}
 need(all(p.get(k) is True for k in expected_flags) and p['scope_proven'] is True and p['guest_units_quiescent'] is True and p['overlay_discarded'] is True,'infrastructure flags')
 need(fh(path/'candidate.snapshot')==CORES[build] and fh(path/'payload.tar')==p['payload_sha256'] and fh(path/'evidence.tar')==p['evidence_validation']['archive_sha256'] and fh(path/'guest-summary.json')==p['guest_summary_sha256'] and fh(path/'device-classification.json')==p['device_classification_sha256'],'run artifact hashes')
 vmid=p['vm_uuid'];need(str(uuid.UUID(vmid))==vmid,'vm uuid');ident=p['identity'];rb=ident['attestation']['readback'];marker=(vmid+'\n').encode().hex();need(ident['marker_matches'] is True and ident['product_uuid_matches'] is True and ident['host_shared_mounts']==[] and rb['marker_hex']==rb['dmi_hex']==rb['attestation_hex']==marker and p['network']['canary_accepted']==0,'guest identity/network')
 need(all(rb[k]['uid']==rb[k]['gid']==0 and rb[k]['mode']==0o444 and rb[k]['nlink']==1 and rb[k]['type']=='regular' for k in ('marker','attestation')),'identity ownership')
 n=j(path/'namespace-proof-208.json');a=j(path/'namespace-attestation-208.json');parent=j(path/'parent-namespace.json');need(fh(path/'namespace-proof-208.json')==p['namespace_proof_sha256'] and fh(path/'namespace-attestation-208.json')==p['namespace_attestation_sha256'] and fh(path/'parent-namespace.json')==p['parent_namespace_sha256'] and n['attestation']['sha256']==fh(path/'namespace-attestation-208.json'),'namespace pins')
 need(n['token']==a['token']==n['dmi_uuid']==vmid and n['uid']==n['euid']==0 and n['pid1_uid']==['0']*4 and n['namespaces']==a['namespaces'] and n['outer_namespaces']==a['outer_namespaces'] and all(n['outer_namespaces'][k]==parent[k] and n['namespaces'][k]!=parent[k] for k in ('mnt','net','pid')) and n['proc_interfaces']==n['sysfs_interfaces']==['lo'],'namespace boundary')
 privilege=j(path/'privilege-proof.json');need(fh(path/'privilege-proof.json')==p['privilege_proof_sha256'] and privilege['vm_uuid']==vmid and privilege['uid']==privilege['euid']==privilege['gid']==privilege['egid']==2000 and privilege['cap_eff']=='0000000000000000' and privilege['groups']==[] and privilege['no_new_privs']=='1','UID/caps')
 need(type(p['guest_status']) is int and p['guest_status'] in (0,1),'evaluation transport status');unit_proof(path/'run.log.unit-proof.json',p['guest_unit_proofs']['run.log.unit-proof.json'],vmid,'bashos-evaluation-'+vmid[:8]+'.service',p['guest_status']);unit_proof(path/'compat/run.log.unit-proof.json',p['compatibility']['proof_hashes']['run.log.unit-proof.json'],vmid,'bashos-optional-'+vmid[:8]+'-reference.service',0)
 td=j(path/'vm/teardown.json');need(td==p['teardown'] and td['vm_uuid']==vmid and td['proof_durable'] is True and td['scope_quiescent'] is True and td['clean_poweroff'] is True and td['forced_stop'] is False and td['qemu_exit_status']==0 and td['poweroff_request']==0 and td['scope_after']['load']=='not-found' and td['scope_after']['active']=='inactive' and td['cgroup_events']['removed'] is True and not (path/'overlay.qcow2').exists(),'VM teardown')
 scope='parity-vm-'+vmid+'.scope';need(td['scope_unit']==scope and td['scope_boot_observation']['state']=={'id':scope,'load':'loaded','active':'active','group':td['scope_cgroup']} and td['scope_after']['id'] in ('',scope) and td['cgroup_events']['path']=='/sys/fs/cgroup'+td['scope_cgroup']+'/cgroup.events' and Path(td['disk']).name=='overlay.qcow2','scope or overlay provenance')
 staging=p['staging'];need(staging['status']==0 and staging['source_sha256']==fh(path/'guest-staging-clean.py') and staging['stdout_sha256']==fh(path/'staging.stdout') and staging['stderr_sha256']==fh(path/'staging.stderr'),'staging binding')
 need(read(path/'staging.stderr')==b'','staging stderr');st=[json.loads(line) for line in read(path/'staging.stdout').splitlines()];image_receipt=j(C/'primary-kernel-route12-001/primary-image-acceptance.json');gates=[]
 for label in ('install','verify'):
  token=image_receipt['current_scope_checks'][label]['uuid'];gates+=['.bashos-gate-'+token+'-bashos-evaluation-'+token[:8]+'.service','.bashos-gate-'+token+'-bashos-optional-'+token[:8]+'-collect.service']
 need(len(st)==3 and [x['schema'] for x in st]==['device-staging-inventory-v1','device-staging-gates-v1','device-staging-ready-v1'] and all(x['token']==vmid for x in st) and set(st[0]['allowed_gates'])==set(st[0]['output'])==set(st[1]['gates'])==set(st[2]['removed_gates'])==set(staging['removed_gates'])==set(gates) and st[2]['output']['mode']==448,'staging provenance')
 for g in gates:
  d=st[0]['output'][g];r=st[1]['gates'][g]['release'];need((d['uid'],d['gid'],d['mode'],d['type'])==(0,0,448,16384) and (r['uid'],r['gid'],r['mode'],r['size'],r['nlink'],r['type'])==(0,0,256,0,1,32768),'staging gate metadata')
 comp=p['compatibility'];handoff=j(path/'compat/handoff.json');need(fh(path/'compat/handoff.json')==comp['handoff_sha256']==fh(path/'compat/handoff-guest.json')==fh(path/'compat/handoff-after.json') and handoff['vm_uuid']==vmid and handoff['candidate_sha256']==CORES[build] and handoff['fixture_sha256']==p['fixture_sha256'] and handoff['canary_absent'] is True and fh(path/'compat/raw.json')==comp['raw_sha256'] and comp['status']==0 and comp['checked']['original_summary']['MIGRATED']==1 and comp['checked']['canary_summary']['MIGRATED']==1 and all(v['status']==0 for v in comp['checked']['availability']),'compatibility handoff')

 with open_tar(path/'payload.tar',p['payload_sha256']) as t:
  need(sha(member(t,'candidate'))==CORES[build],'payload candidate');suite=member(t,'harness/suites/optional-frozen.json');need(sha(suite)==p['fixture_sha256'] and json.loads(suite)['cases']==cases,'payload cases')
  control={name:item['sha256'] for name,item in j(R/'staged-source-manifest.json')['entries'].items() if item['type']=='file'}
  for name in ('guest.py','network.py','schema.py','selfcheck.py','terminal.py','helpers/system-seccomp.py','helpers/system-sequence.py','helpers/compat252-receipt.py','helpers/compat252-worker.py',*sorted(index['helpers'])):
   expected=index['helpers'].get(name) if name.startswith('helpers/') and name in index['helpers'] else control['tests/parity-vm/'+name]
   need(sha(member(t,'harness/'+name))==expected,'payload helper '+name)
  need(sha(member(t,'loadable-parity/runner.py'))==control['tests/loadable-parity/runner.py'],'payload runner')
  for m in t.getmembers():
   if m.isdir():continue
   name=m.name
   if name in ('candidate','harness/suites/optional-frozen.json'):continue
   if name.startswith('harness/'):source='tests/parity-vm/'+name[len('harness/'):]
   elif name.startswith('loadable-parity/'):source='tests/'+name
   else:raise ValueError('unexpected payload path '+name)
   need(source in control and sha(member(t,name))==control[source],'payload source mismatch '+name)

 summary=j(path/'guest-summary.json');rows=summary['cases'];controls=[x for x in rows if x.get('group')=='selfcheck'];selected=[x for x in rows if x.get('id') in p['selected_case_ids']]
 need(summary['binary_sha256']==CORES[build] and summary['vm_uuid']==vmid and summary['root_fixtures_allowed'] is False and set(summary['selected_case_ids'])==set(p['selected_case_ids']) and len(controls)==13 and {x['id'] for x in controls}==set(p['evidence_validation']['selfchecks']) and all(x['status']=='PASS' for x in controls) and len(selected)==len(cases) and len(rows)==13+len(cases) and len({x['id'] for x in rows})==13+len(cases),'control/selection summary')
 need(p['guest_status']==(1 if any(x['status']=='FAIL' for x in selected) else 0),'evaluation return/summary mismatch')
 with open_tar(path/'evidence.tar',p['evidence_validation']['archive_sha256']) as t:
  need(member(t,'results/summary.json')==read(path/'guest-summary.json'),'archived summary')
  for row in controls:
   v=json.loads(member(t,'results/selfcheck/'+row['id'].removeprefix('selfcheck-')+'.json'));need(all(v.get(k)==row.get(k) for k in ('id','group','status','detail')),'selfcheck mismatch')
  for case in cases:
   cid=case['id'];row=next(x for x in selected if x['id']==cid);need(row['group']=='shell' and row['kind']=='contract' and row['covers']==case['covers'],'case summary binding');feature=json.loads(member(t,'results/'+cid+'/feature-checks.json'));need('user_notif' in feature['seccomp-notify']['actions_avail'],'seccomp notification unavailable');rawbytes=member(t,'results/'+cid+'/candidate.json');raw=json.loads(rawbytes);recorded={'raw_sha256':sha(rawbytes),'framework_status':row['status'],'framework_differences':row.get('differences',[]),'framework_harness_error':row.get('harness_error')}
   try:
    examine(raw,case,recorded);recorded['framework_status']=row['status']
    if row['status'] not in ('PASS','FAIL'):recorded['classification']='INCOMPLETE';recorded['reason']='framework ERROR/SKIP'
    elif row['status']=='FAIL' and recorded['classification']=='BOUNDED_PASS':recorded['classification']='INCOMPLETE';recorded['reason']='framework FAIL retained; mismatch not independently attributable by this checker'
   except (ValueError,KeyError,TypeError,IndexError,UnicodeError,json.JSONDecodeError) as exc:
    recorded['classification']='REACHED_FAIL' if recorded.get('controls_verified') and recorded.get('candidate_reached') and recorded.get('candidate_mismatches') else 'INCOMPLETE';recorded['reason']='further evidence incomplete: '+str(exc)
   result['case_results'][cid]=recorded
 result.update({'vm_uuid':vmid,'candidate_sha256':CORES[build],'evidence_tar_sha256':fh(path/'evidence.tar'),'payload_sha256':fh(path/'payload.tar'),'guest_summary_sha256':fh(path/'guest-summary.json'),'selfchecks_pass':13,'static_control_counts':len(controls),'saved_unit_and_teardown':'verified','artifact_hashes':{name:fh(path/name) for name in SAFE_FILES[build]},'status_counts':{s:sum(v['classification']==s for v in result['case_results'].values()) for s in ('BOUNDED_PASS','REACHED_FAIL','INCOMPLETE')}})
 return result

def examine(raw,case,out):
 need(raw.get('error') is None and not raw.get('harness_error') and raw['stray_processes']==[],'outer harness error')
 setup=raw['setup'];need(setup['status']==0 and setup.get('error') is None and setup['stray_processes']==[] and base64.b64decode(setup['stdout_base64'],validate=True)==b'uclamp positive control ok\n' and setup['stderr_base64']=='','native preflight setup')
 pre=json.loads(diag(raw,'uclamp-control.json'))
 need([x['label'] for x in pre]==['independent-util-linux-control','independent-reset-control','independent-command-control'],'preflight controls')
 need([x['operation']['status'] for x in pre]==[0,0,7] and all(x['operation']['stderr']=='' for x in pre),'preflight status')
 need((pre[0]['after']['util_min'],pre[0]['after']['util_max'])==(100,900) and (pre[1]['after']['util_min'],pre[1]['after']['util_max'])==(0,1024) and (pre[2]['after']['attr']['util_min'],pre[2]['after']['attr']['util_max'])==(100,800) and pre[2]['after']['argv']==['a b',''],'preflight readbacks')
 report=json.loads(diag(raw,'setter-report.json'));e=report['events'];need(report['mode']=='fork' and report['control_valid'] is True,'native control validity')
 n=e['native_task']['pid'];c=e['candidate_task']['pid'];u=e['native_util_linux_task']['pid'];births=e['owned_birth_bindings'];need(len({n,c,u})==3 and set(births)==set(map(str,(n,c,u))),'three independent owned tasks')
 for pid in (n,c,u):
  b=births[str(pid)];i=b['identity'];need(b['pidfd_alive'] is True and i['pid']==pid and i['uid']==2000 and type(i['start_ticks']) is int and i['start_ticks']>0 and type(i['ppid']) is int and i['ppid']>1,'owned birth identity')
 need(len({v['identity']['ppid'] for v in births.values()})==1,'common fixture parent')
 def request(event,pid):
  need(len(event['trace'])==1,'single setter event');v=event['trace'][0];need(v['syscall']=='sched_setattr' and v['reply']=='continue' and v['arg0']==pid,'setter target')
  mem=v['memory1'];b=bytes.fromhex(mem['hex']);need(mem['length']==mem['requested']==len(b)==56,'setter raw bytes');need(struct.unpack_from('<I',b)[0]==56,'sched_attr size')
  return {'flags':struct.unpack_from('<Q',b,8)[0],'min':struct.unpack_from('<I',b,48)[0],'max':struct.unpack_from('<I',b,52)[0]}
 nr=request(e['native'],n);ur=request(e['native_util_linux_fork'],u)
 need(e['native']['status']==e['native_util_linux_fork']['status']==0 and e['native']['stderr']==e['native_util_linux_fork']['stderr']=='','native status')
 need(nr==e['native_request']=={'flags':0x71,'min':100,'max':800} and ur==e['native_util_linux_request'],'native request consistency')
 before=e['before_native'];after=e['after_native'];native=json.loads(e['native']['stdout']);need(not before['flags']&1 and after['flags']&1 and (before['util_min'],before['util_max'])==(100,800) and (after['util_min'],after['util_max'])==(100,800),'native clear/set and clamps')
 need(all(before[k]==after[k] for k in ('policy','nice','priority','runtime','deadline','period')),'native unrelated attributes')
 need(native['before']==before and native['after']==after and native['pid']==n and native['request_flags']==0x71 and native['identity_before']==native['identity_after']==births[str(n)]['identity'] and native['pidfd_alive'] is True,'independent direct readback')
 need(e['native_owned_after']==births[str(n)] and e['native_util_linux_owned_after']==births[str(u)],'native live identity')
 nf=e['native_fork'];need(type(nf['pid']) is int and nf['pid'] not in (n,c,u) and (nf['child_attr']['util_min'],nf['child_attr']['util_max'])==(0,1024),'native child self-read')
 before=e['before_candidate'];precall=e['candidate_before_invocation'];need(not before['flags']&1 and (before['util_min'],before['util_max'])==(100,800) and precall=={'attr':before,'owned':births[str(c)]} and e['candidate_precondition']=={'reset_bit_clear':True,'owned':births[str(c)]},'candidate clear-bit and live precondition')
 out['controls_verified']=True;event=e.get('candidate');need(isinstance(event,dict),'candidate absent');out['candidate_reached']=True
 need(event['argv'][event['argv'].index('--')+1:]==['/opt/bashos-parity/candidate','--noprofile','--norc','-c','uclampset "$@"','setter','-R','-m','100','-M','800','-p',str(c)],'exact candidate invocation')
 out['candidate_status']=event['status'];out['candidate_mismatches']=[k for k,good in {'status':event['status']==0,'stderr':event['stderr']==''}.items() if not good]
 cr=request(event,c);need(cr==e['candidate_request'] and e['candidate_owned_after']==births[str(c)],'candidate request/live binding');cf=e['candidate_fork'];need(type(cf['pid']) is int and cf['pid'] not in (n,c,u,nf['pid']),'candidate fork identity')
 checks={'status':event['status']==0,'stderr':event['stderr']=='','reset_on_fork_flag':bool(cr['flags']&1),'parent_flag_readback':bool(e['after_candidate']['flags']&1),'child_default':(cf['child_attr']['util_min'],cf['child_attr']['util_max'])==(0,1024)}
 out['candidate_mismatches']=[k for k,v in checks.items() if not v];out['request_flags']=cr['flags'];out['parent_reset_bit']=bool(e['after_candidate']['flags']&1);out['child_clamps']=[cf['child_attr']['util_min'],cf['child_attr']['util_max']];out['native_util_linux_flags']=ur['flags']
 need(report['candidate_checks']==checks and not report.get('incomplete'),'saved assertion or later observer incompleteness')
 if out['candidate_mismatches']:out['classification']='REACHED_FAIL';return
 need(raw['status']==0 and base64.b64decode(raw['stdout_base64'],validate=True)==case['stdout'].encode() and base64.b64decode(raw['stderr_base64'],validate=True)==case['stderr'].encode(),'outer success')
 out['classification']='BOUNDED_PASS'
