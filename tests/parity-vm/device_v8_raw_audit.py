#!/usr/bin/env python3
"""Read-only paired UCLAMP raw-data review; no guest/source imports or product authority."""
import base64,hashlib,json,pathlib,stat,tarfile,sys
SRC='9f58c8ab4414ef7278a43a99d1b7f5c18e4563e9eede450fe292e979412601b2';INV='b15ec9af6054bad35bc649113c73834149b00d84d4953d3e33269e00e13d620d';IMAGE='08442265e7135133c25936899ffc1cc19530b339b216c35a3ad42e072eee668a';MAN='b7fdb3c8df4f38d9f5d988858731950c6c24229e874eeab18fe5951b40b34569';RECEIPT='b660f5a562cbd89190ac21d0b007a363d59db368ef24db4e15691a7532c481d6'
CORES={'dynamic':'6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2','static':'2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab'}
IDS=['devices-uclamp-query-r1','devices-uclamp-setter-r1','devices-uclamp-command-r1']
def require(x,msg):
 if not x:raise ValueError(msg)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(p,limit=64*1024**2):
 s=p.lstat();require(stat.S_ISREG(s.st_mode) and s.st_size<limit and s.st_nlink==1,'unsafe/big file: '+str(p));return p.read_bytes()
def js(p):return json.loads(read(p))
def diag(raw,name):
 d=raw['diagnostics'][name];require(d.get('truncated') is False and type(d.get('captured_bytes')) is int,'invalid diagnostic '+name);b=base64.b64decode(d['base64'],validate=True);require(len(b)==d['captured_bytes'] and len(b)<1024**2,'bad diagnostic bytes '+name);return b
def unit(p,token,unit,expected):
 require(sha(p)==expected,'unit proof digest');x=js(p);require(x['vm_uuid']==token and x['unit']==unit and x['quiescent'] is True and x['transport_finished'] is True and x['transport_returncode']==0,'unit quiescence')
 bef=dict(line.split('=',1) for line in bytes.fromhex(x['unit_before']['stdout_hex']).decode().splitlines());aft=dict(line.split('=',1) for line in bytes.fromhex(x['unit_after']['stdout_hex']).decode().splitlines());be=bytes.fromhex(x['events_before']['stdout_hex']).splitlines();ae=bytes.fromhex(x['events_after']['stdout_hex']).splitlines()
 require(all(x[k]['returncode']==0 for k in ('unit_before','events_before','unit_after','events_after','release')) and (x['stop']['returncode']==0 or aft['LoadState']=='not-found'),'unit raw command status')
 require(bef['Id']==unit and bef['ActiveState']=='active' and bef['ControlGroup']==x['cgroup'] and b'populated 1' in be and (aft['LoadState']=='not-found' or aft['ActiveState'] in ('inactive','failed')) and (ae==[b'__CGROUP_REMOVED__'] or b'populated 0' in ae),'unit raw proof')
def archive(path):
 t=tarfile.open(path,'r:');members=t.getmembers();names=[m.name for m in members];require(len(names)==len(set(names)) and all((m.isfile() or m.isdir()) and not m.issym() and not m.islnk() and not m.name.startswith('/') and '..' not in pathlib.PurePosixPath(m.name).parts and m.size<64*1024**2 for m in members),'archive shape');return t
def raw(t,name):
 m=t.getmember(name);require(m.isfile() and m.size<64*1024**2,'archive member invalid');return t.extractfile(m).read()
def cases_for(t):
 suite=json.loads(raw(t,'harness/suites/optional-frozen.json'));require(set(c['id'] for c in suite['cases'])==set(IDS),'suite selection')
 idx=js(W/'device-index.json');
 for c in suite['cases']:require(hashlib.sha256(json.dumps(c,sort_keys=True,separators=(',',':')).encode()).hexdigest()==idx['cases'][c['id']],'case definition')
 require(hashlib.sha256(raw(t,'harness/helpers/devices-uclamp-observer-r1.py')).hexdigest()==idx['helpers']['helpers/devices-uclamp-observer-r1.py'],'observer hash')
 return suite['cases']
def control(d):
 a=json.loads(diag(d,'uclamp-control.json'));require([x['label'] for x in a]==['independent-util-linux-control','independent-reset-control','independent-command-control'],'native controls')
 require([x['operation']['status'] for x in a]==[0,0,7],'native control status');require([(x['after']['util_min'],x['after']['util_max']) for x in a[:2]]==[(100,900),(0,1024)] and (a[2]['after']['attr']['util_min'],a[2]['after']['attr']['util_max'])==(100,800) and a[2]['after']['argv']==['a b',''],'native control data')
 require(json.loads(a[2]['operation']['stdout'])==a[2]['after'] and all(x['operation']['stderr']=='' for x in a),'native control output')
def check_case(rawcase,kind):
 require(rawcase['status']==0 and not rawcase.get('error') and not rawcase.get('harness_error') and rawcase['setup']['status']==0 and not rawcase['setup'].get('error') and not rawcase.get('stray_processes'),'case setup/status')
 control(rawcase)
 if kind=='query':
  before=json.loads(diag(rawcase,'uclamp-before.json'));e=json.loads(diag(rawcase,'uclamp-events.json'));ref=json.loads(diag(rawcase,'uclamp-reference.json'));w=json.loads(diag(rawcase,'uclamp-check.json'));pid=w['target_pid'];expected=f"python3 ({pid}) util_clamp: min: {before['util_min']} max: {before['util_max']}\n";require(w['mode']=='query' and w['pass'] is True and len(e)==1 and e[0]['label']=='query' and e[0]['after']==before,'query readback');op=e[0]['operation'];require(op['argv'][-2:]==['-p',str(pid)] and op['status']==0 and op['stdout']==expected and op['stderr']=='' and ref['argv']==['/usr/bin/uclampset','-p',str(pid)] and ref['status']==0 and ref['stdout']==expected,'query outputs')
 elif kind=='setter':
  before=json.loads(diag(rawcase,'uclamp-before.json'));e=json.loads(diag(rawcase,'uclamp-events.json'));refs=json.loads(diag(rawcase,'uclamp-reference.json'));w=json.loads(diag(rawcase,'uclamp-check.json'));pid=w['target_pid'];require(w['mode']=='setter' and w['pass'] is True and len(e)==len(refs)==5,'setter witnesses');vals=[(100,before['util_max']),(100,800),(200,700),(0,1024),(0,1024)];args=[['-m','100'],['-M','800'],['-m','200','-M','700'],['-m','-1','-M','-1'],['-m','900','-M','100']];prior=before
  for i,(row,ref,want,opts) in enumerate(zip(e,refs,vals,args)):
   op=row['operation'];after=row['after'];require(row['label']==str(i) and op['argv'][-len(opts)-2:]==opts+['-p',str(pid)] and op['status']==(1 if i==4 else 0) and (after['util_min'],after['util_max'])==want,'setter operation');require(all(after[k]==prior[k] for k in ('policy','nice','priority','runtime','deadline','period')),'unrelated scheduler attr');
   if i==4:require(bool(op['stderr']) and after==prior,'rejected update mutated')
   else:require(ref['operation']['status']==0 and (ref['after']['util_min'],ref['after']['util_max'])==want and ref['operation']['argv'][0]=='/usr/bin/uclampset','native setter reference')
   prior=after
 else:
  before=json.loads(diag(rawcase,'cmd-before.json'));after=json.loads(diag(rawcase,'cmd-after.json'));child=json.loads(diag(rawcase,'cmd-child.out'));require(before==after and (child['attr']['util_min'],child['attr']['util_max'])==(100,800) and child['argv']==['a b',''],'command child/parent');require(diag(rawcase,'cmd-child.status')==b'7\n' and diag(rawcase,'cmd-child.err')==b'' and diag(rawcase,'cmd-missing.status')==b'127\n' and bool(diag(rawcase,'cmd-missing.err')) and diag(rawcase,'cmd-builtin.status')==b'0\n' and diag(rawcase,'cmd-builtin.out')==b'builtin result\n' and diag(rawcase,'cmd-builtin.err')==b'','command statuses and dispatch')

def audit(run_root, source_root, image_receipt):
 global P,W,R
 P=pathlib.Path(run_root);W=pathlib.Path(source_root);R=pathlib.Path(image_receipt)
 for p,h in ((P/'primary-source-acceptance.json',SRC),(W/'freeze-inventory.json',INV),(R,RECEIPT)):require(sha(p)==h,'source/image authority digest')
 a=js(P/'primary-source-acceptance.json');require(a['approved_batches']==['uclamp'] and a['source_inventory_sha256']==INV and a['image_receipt_sha256']==RECEIPT and a['root_fixtures_allowed'] is False,'source scope')
 f=js(W/'freeze-inventory.json')
 for n,x in f['files'].items():
  q=pathlib.Path(x['path']);require(q.stat().st_size==x['bytes'] and sha(q)==x['sha256'],'source inventory '+n)
 require(sha(P/'control-files.json')==a['copied_control_inventory_sha256'],'control inventory digest');idx=js(P/'control-files.json');actual={x.relative_to(P/'control').as_posix() for x in (P/'control').rglob('*') if x.is_file()};require(actual==set(idx),'control membership')
 for name,h in idx.items():require(sha(P/'control'/name)==h,'control source '+name)
 receipt=js(R);require(receipt['prepared_sha256']==IMAGE and receipt['prepared_manifest_sha256']==MAN and receipt['product_coverage'] is False,'image receipt scope')
 result={};uuids=[]
 for build,candidate in CORES.items():
  p=P/'results'/(build+'-uclamp');x=js(p/'evidence-record.json');token=x['vm_uuid'];uuids.append(token)
  require(x['status']=='completed' and x['qualification']=='framework-complete-device-adjudication-required' and x['product_acceptance'] is False and x['root_fixtures_allowed'] is False and x['candidate_sha256']==candidate and x['image_sha256']==IMAGE and x['manifest_sha256']==MAN and x['image_acceptance_sha256']==RECEIPT and x['consumer_sha256']==a['consumer_sha256'] and x['guest_status']==0,'run identity/status')
  for k in ('scope_proven','guest_units_quiescent','overlay_discarded','candidate_unchanged','image_unchanged','manifest_unchanged','inventory_unchanged','staging_source_unchanged','staging_evidence_unchanged','evidence_unchanged','compat_evidence_unchanged','selfcheck_sources_unchanged'):require(x.get(k) is True,'postcheck '+k)
  td=js(p/'vm/teardown.json');require(td==x['teardown'] and td['vm_uuid']==token and td['clean_poweroff'] is True and td['forced_stop'] is False and td['scope_quiescent'] is True and td['proof_durable'] is True,'teardown')
  for n in ('evidence.tar','guest-summary.json','privilege-proof.json','namespace-proof-208.json','namespace-attestation-208.json','evaluation-properties.txt'):require(sha(p/n)==x['diagnostic_capture'][n]['sha256'],'captured artifact '+n)
  require(sha(p/'staging.stdout')==x['staging']['stdout_sha256'] and sha(p/'staging.stderr')==x['staging']['stderr_sha256'] and read(p/'staging.stderr')==b'','staging evidence');st=[json.loads(z) for z in read(p/'staging.stdout').splitlines()];gates=[]
  for label in ('install','verify'):
   tok=receipt['current_scope_checks'][label]['uuid'];gates += ['.bashos-gate-'+tok+'-bashos-evaluation-'+tok[:8]+'.service','.bashos-gate-'+tok+'-bashos-optional-'+tok[:8]+'-collect.service']
  require(len(st)==3 and [z['schema'] for z in st]==['device-staging-inventory-v1','device-staging-gates-v1','device-staging-ready-v1'] and all(z['token']==token for z in st) and set(st[0]['allowed_gates'])==set(st[0]['output'])==set(st[1]['gates'])==set(st[2]['removed_gates'])==set(gates) and st[2]['output']['mode']==448,'staging gates')
  for g in gates:
   o=st[0]['output'][g];rel=st[1]['gates'][g]['release'];require((o['uid'],o['gid'],o['mode'],o['type'])==(0,0,448,16384) and (rel['uid'],rel['gid'],rel['mode'],rel['size'],rel['nlink'],rel['type'])==(0,0,256,0,1,32768),'gate metadata')
  priv=js(p/'privilege-proof.json');require(priv=={'vm_uuid':token,'uid':2000,'euid':2000,'gid':2000,'egid':2000,'groups':[],'cap_eff':'0000000000000000','no_new_privs':'1'},'privilege proof')
  net=x['network'];require(net['canary_accepted']==0 and net['host_canary']!='connected' and net['public_tcp']!='connected' and not isinstance(net['dns'],list),'network isolation')
  ns=js(p/'namespace-proof-208.json');at=js(p/'namespace-attestation-208.json');parent=js(p/'parent-namespace.json');require(ns['token']==token==at['token'] and ns['dmi_uuid']==token and ns['uid']==ns['euid']==0 and ns['namespaces']==at['namespaces'] and ns['outer_namespaces']==at['outer_namespaces'] and all(ns['namespaces'][k]!=parent[k] and ns['outer_namespaces'][k]==parent[k] for k in ('pid','net','mnt')) and ns['proc_interfaces']==ns['sysfs_interfaces']==['lo'],'namespace proof')
  require(ns['attestation']['sha256']==sha(p/'namespace-attestation-208.json') and ns['attestation']['uid']==ns['attestation']['gid']==0 and ns['attestation']['mode']==292,'namespace attestation')
  unit(p/'run.log.unit-proof.json',token,'bashos-evaluation-'+token[:8]+'.service',x['guest_unit_proofs']['run.log.unit-proof.json']);comp=x['compatibility'];unit(p/'compat/run.log.unit-proof.json',token,comp['unit'],comp['proof_hashes']['run.log.unit-proof.json']);handoff=js(p/'compat/handoff.json');require(sha(p/'compat/handoff.json')==comp['handoff_sha256']==sha(p/'compat/handoff-guest.json')==sha(p/'compat/handoff-after.json') and handoff['vm_uuid']==token and handoff['candidate_sha256']==candidate and handoff['fixture_sha256']==x['fixture_sha256'] and handoff['canary_absent'] is True,'compat handoff')
  require(sha(p/'compat/raw.json')==comp['raw_sha256'] and comp['status']==0 and comp['checked']['original_summary']['MIGRATED']==1 and comp['checked']['canary_summary']['MIGRATED']==1 and all(y['status']==0 for y in comp['checked']['availability']),'compatibility raw/controls')
  for n in ('before','after-service','after-evaluator'):require(sha(p/'compat'/('sources-'+n+'.json'))==comp['source_attestation_sha256'],'compat source attest')
  require(sha(p/'payload.tar')==x['payload_sha256'] and sha(p/'evidence.tar')==x['evidence_validation']['archive_sha256'],'payload/evidence digest')
  with archive(p/'payload.tar') as t:
   require(hashlib.sha256(raw(t,'candidate')).hexdigest()==candidate and hashlib.sha256(raw(t,'harness/suites/optional-frozen.json')).hexdigest()==x['fixture_sha256'],'payload bindings');cases_for(t)
  with archive(p/'evidence.tar') as t:
   sm=json.loads(raw(t,'results/summary.json'));require(raw(t,'results/summary.json')==read(p/'guest-summary.json') and sm['vm_uuid']==token and sm['binary_sha256']==candidate and sm['fixture_sha256']=={'optional-frozen.json':x['fixture_sha256']},'summary identity');rows=sm['cases'];sel=[r for r in rows if r['id'] in IDS];controls=[r for r in rows if r.get('group')=='selfcheck'];require(len(sel)==3 and all(r['status']=='PASS' for r in sel) and len(controls)==13 and {r['id'] for r in controls}==set(x['evidence_validation']['selfchecks']) and all(r['status']=='PASS' for r in controls),'case and controls')
   for c in controls:
    r=json.loads(raw(t,'results/selfcheck/'+c['id'][len('selfcheck-'):]+'.json'));require(r=={k:v for k,v in c.items() if k!='kind'},'selfcheck raw')
   for kind in ('query','setter','command'):check_case(json.loads(raw(t,'results/devices-uclamp-'+kind+'-r1/candidate.json')),kind)
  result[build]={'vm_uuid':token,'archive_sha256':sha(p/'evidence.tar'),'payload_sha256':sha(p/'payload.tar'),'record_sha256':sha(p/'evidence-record.json'),'three_cases_raw_verified':True,'native_controls_per_case':True}
 require(len(set(uuids))==2,'reused VM UUID')
 return json.loads(json.dumps({'schema':'paired-uclamp-raw-review-v1','state':'raw-checks-passed-pending-primary-adjudication','source_acceptance_sha256':SRC,'image_receipt_sha256':RECEIPT,'builds':result,'limitations':['No product or ledger decision.','Query child is observed with sched_getattr by the parent observer; child-self readback is not retained.','No syscall witness for reset flag or query no-write filter; uncovered original clauses remain unresolved.','Native and kernel/observer execution semantics are source-bound; EOPNOTSUPP not exercised.']},indent=2))
