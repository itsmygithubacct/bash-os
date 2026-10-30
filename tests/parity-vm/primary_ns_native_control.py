#!/usr/bin/env python3
"""Portable data-only, control-only receipt gate for one pinned evidence packet.

All filesystem roots come from private configuration. No control is returned as
an executable candidate case. The authority registry accepts only the exact
reviewed primary-issued receipt pinned in source.
"""
import base64,datetime,hashlib,json,re
from pathlib import Path, PurePosixPath
AUTHORIZED_RECEIPT_SHA256=frozenset({'34580c1d60f750e0dcf84da6159fd2b7796da406eb6e6ec33b478274c2cf36d9'})
EXPECTED={'control_case_id': 'migration-ns-native-caller-inodes-r1', 'control_case_sha256': '3bc3fb8df4c93f572ae92500ee313b21dd8827920b5b511af9f313f272e84dcb', 'launcher_sha256': '368b8807794eb99bfe7e271eb0792d3221832e00f16f9a1373396f71fc1b8a35', 'paired_raw_review_sha256': 'dc7afe08415454f461a291af8f2d949fcf3bd96c04ffba99783f14b0b969e16b', 'primary_source_acceptance_sha256': '7dde6f5f29cb9e8c75a45689cfab8c86896467f9c08d5c93e403ac2baf393a86', 'runs': {'dynamic': {'build': 'dynamic', 'candidate_sha256': '6f0e188ae4509e660fe472ae9d7ba368846c0161184556d5d925d5c527b8e0e2', 'compatibility_unit_proof_sha256': '71579df7c90faaf1a724dc3ca1e3da9eeb6d94e728fa3af0073554219d893019', 'evaluator_unit_proof_sha256': 'b5280253891e6221c6163a5524c7cd11fb88eed42951b8749514717ee3ab8e53', 'evidence_sha256': '34f642ba738a45408d854fcb66bba59dec0b03daa5f0e5cda4eb38b538acbb9e', 'launch_sha256': '12250df6b8fb210df4b37f8e84e072ba66c76ea3e15b326a613b1c6a6147beaf', 'native_case_record_sha256': 'fe539d2a4699c58d3c16e58d3dc9e08a095d732ebc83aef01c2099cc13d62997', 'native_sha256': '5cac0dd17eb05ec64a35b97361bd491db8e28ac679a0106f4a41e6800696fa2e', 'payload_sha256': '4c77906d5083a52f3e7ab61b9607b22ce801de795878cafb629706f7ece341a7', 'plan_sha256': 'e2d8d7112dd9f7ee36957d684fc5203cf09b56e24e08cf191a3f4ddabaa369a3', 'provenance_sha256': '5edf25ee501deb7344e2dcd98f1b22bdf9f63dd0d64373bbfc17979b5d81b1e0', 'scope_cgroup': '/user.slice/user-1000.slice/user@1000.service/app.slice/parity-vm-d2d32045-c9aa-4e88-b6e1-611c265dbc96.scope', 'scope_unit': 'parity-vm-d2d32045-c9aa-4e88-b6e1-611c265dbc96.scope', 'summary_sha256': '33a05e6a3f6db139d696925e661aa91a548e271aa06eb6d25aec52e9b20129d0', 'teardown_sha256': '92e09bf9bff59dfa9b8c7683870bd81693c96be769b73cbb75b0ab8c6a0c7619', 'vm_uuid': 'd2d32045-c9aa-4e88-b6e1-611c265dbc96', 'controller_pid': 1188060, 'controller_starttime': 1652431, 'vm_wrapper_pid': 1188609}, 'static': {'build': 'static', 'candidate_sha256': '2511208dea53bf380088ca242ea5b26029ebfeceb1794d87fc42fde4df8f22ab', 'compatibility_unit_proof_sha256': '751aa0b3dbfcb11e493949405e30863c7210ef3e860b813ffe8ecf7b1c54fb13', 'evaluator_unit_proof_sha256': '7120e22aa939ee99a33f890aab3213c42f153039051ed169a59254c9ff382b20', 'evidence_sha256': '79d5b96a0d5961da37ad2078627cf58d88643b6c011b1b653fcfe7739b146b4c', 'launch_sha256': 'fdb384884fca545a25361f2ced7f901e4cac117bcbdaa5d5c7dee7fff90678d1', 'native_case_record_sha256': '0d4b7fb35036ff07466c6d1a80e2d53d702f713dd69f029606d5298f429d2bb8', 'native_sha256': '7c4ca1b6ceb8a5550beb4b467bc27a83ca8e802501f680cb0ec44fde5713dc3e', 'payload_sha256': '068f1172ad856f2987c344abeac577cf304083ca31601c40fb0866b2ce4d7a89', 'plan_sha256': '32f9dd7225f14524cb0c81c76a695ee241080c9f655043f9393f916ce0f83fb9', 'provenance_sha256': '89e1d9a1a1fe2b0419f9015cfa77c88f94af481f779b4ba9dfe1490b945c95c1', 'scope_cgroup': '/user.slice/user-1000.slice/user@1000.service/app.slice/parity-vm-0de825ee-743c-4c54-b4c4-f4248aaded6d.scope', 'scope_unit': 'parity-vm-0de825ee-743c-4c54-b4c4-f4248aaded6d.scope', 'summary_sha256': '19c35507d1a65b38687c3e8e8eed776a7f12d87a0bb644ac480a86727bc06819', 'teardown_sha256': '4107a624a94e6ab89899fd479aee955780c7777fbc2ce10ba9dc80c8108dc5ad', 'vm_uuid': '0de825ee-743c-4c54-b4c4-f4248aaded6d', 'controller_pid': 1164633, 'controller_starttime': 1606092, 'vm_wrapper_pid': 1166195}}, 'schema': 'ns-native-control-expected-pins-v1', 'source_freeze_sha256': 'd611181258813a8b4cd9602fd9023429b86661bec45a19041aa8c1440a420002'}
NAMES=('user','mnt','net','ipc','uts','cgroup')
def require(ok,msg):
 if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def exact(x,keys,label):require(type(x) is dict and set(x)==set(keys),label+' fields')
def resolve_file(root,relative):
 require(type(relative) is str and relative and not PurePosixPath(relative).is_absolute() and all(x not in ('.','..') for x in PurePosixPath(relative).parts),'unsafe relative path')
 path=(root/relative).resolve();require(path.is_relative_to(root) and path.is_file(),'artifact outside configured root or absent');return path
def pinned(root,relative,digest):
 data=resolve_file(root,relative).read_bytes();require(sha(data)==digest,'artifact digest mismatch');return data
def check_native(raw,expected_hash):
 require(sha(raw)==expected_hash,'native observations hash mismatch');d=json.loads(raw);require(d['schema']=='native-caller-inode-v1' and d['complete'] is True and d['all_expected'] is True and set(d['runs'])==set(NAMES),'native control incomplete')
 for n in NAMES:
  r=d['runs'][n];require(r['returncode']==0 and r['timed_out'] is False,'native result '+n);lines=r['stdout'].splitlines();require(len(lines)==2,'native raw snapshots '+n);a,b=map(json.loads,lines);require(a==r['before'] and b==r['after'] and a['phase']=='before' and b['phase']=='after' and a['request']==b['request']==n,'snapshot binding '+n);require(type(a['pid']) is int and a['pid']>0 and type(a['starttime']) is int and a['starttime']>0 and a['pid']==b['pid'] and a['starttime']==b['starttime'],'native birth '+n)
  for phase,s in [('before',a),('after',b)]:
   mapped=not(n=='user' and phase=='before');require(s['uid']==s['euid']==(0 if mapped else 2000),'uid '+n);rows=[list(map(int,x.split())) for x in s['uid_map'].splitlines()];require(rows==[[0,2000,1]] if mapped else any(x<=2000<x+z and y+2000-x==2000 for x,y,z in rows),'uid map '+n);require(set(s['namespaces'])==set(NAMES) and all(re.fullmatch(re.escape(k)+r':\[[0-9]+\]',s['namespaces'][k]) for k in NAMES),'namespace links '+n)
  changes={k:a['namespaces'][k]!=b['namespaces'][k] for k in NAMES};want={k:k==n for k in NAMES};require(changes==want==r['changes']==r['expected_changes'] and r['matches'] is True,'native changes '+n)
def validate_shape(receipt):
 keys=('schema','decision','primary_reviewer','control_only','candidate_behavior_count','covers','source_freeze_sha256','launcher_sha256','primary_source_acceptance_sha256','paired_raw_review_sha256','control_case_id','control_case_sha256','runs');exact(receipt,keys,'receipt');require(receipt['schema']=='bashos-native-namespace-control-receipt-v1' and receipt['decision']=='accept-reviewed-control-only' and type(receipt['primary_reviewer']) is str and receipt['primary_reviewer'].strip(),'receipt identity');require(receipt['control_only'] is True and type(receipt['candidate_behavior_count']) is int and receipt['candidate_behavior_count']==0 and receipt['covers']==[],'not control-only')
 for k in ('source_freeze_sha256','launcher_sha256','primary_source_acceptance_sha256','paired_raw_review_sha256','control_case_id','control_case_sha256'):require(type(receipt[k]) is str and receipt[k]==EXPECTED[k],'receipt pin '+k)
 exact(receipt['runs'],('static','dynamic'),'builds')
 for build in ('static','dynamic'):
  r=receipt['runs'][build];pin=EXPECTED['runs'][build];exact(r,tuple(pin)+('control_status','selfchecks_passed','current_scope_attestation'),'run '+build)
  for k,v in pin.items():require(canonical(r[k])==canonical(v),'run pin '+k)
  require(r['control_status']=='PASS' and type(r['selfchecks_passed']) is int and r['selfchecks_passed']==13,'control status')
  a=r['current_scope_attestation'];exact(a,('checked_at_utc','scope_show','cgroup_absent','vm_wrapper_pid_absent'),'scope');require(type(a['checked_at_utc']) is str and a['checked_at_utc'].endswith('Z'),'scope time');datetime.datetime.fromisoformat(a['checked_at_utc'][:-1]+'+00:00');require(a['cgroup_absent'] is True and a['vm_wrapper_pid_absent'] is True and type(a['scope_show']) is str and len(a['scope_show'])<=4096,'scope absence');pairs={}
  for line in a['scope_show'].splitlines():
   k,sep,v=line.partition('=');require(bool(sep) and k not in pairs,'scope record');pairs[k]=v
  require(pairs.get('Id')==pin['scope_unit'] and pairs.get('ControlGroup')=='' and pairs.get('LoadState')=='not-found' and pairs.get('ActiveState')=='inactive','scope identity')
 require(receipt['runs']['static']['vm_uuid']!=receipt['runs']['dynamic']['vm_uuid'],'reused VM')
def verify(config,build):
 """Return nothing on verified receipt; raise on any missing/untrusted proof."""
 require(build in ('static','dynamic'),'invalid build');exact(config,('artifact_root','receipt','source_dir','source_acceptance','paired_audit','run_dir'),'private control configuration');root=Path(config['artifact_root']);require(root.is_absolute(),'artifact root must be absolute');root=root.resolve();require(root.is_dir(),'artifact root missing');raw=resolve_file(root,config['receipt']).read_bytes();require(sha(raw) in AUTHORIZED_RECEIPT_SHA256,'control receipt not issued and source-authorized');receipt=json.loads(raw);validate_shape(receipt)
 pinned(root,config['source_acceptance'],EXPECTED['primary_source_acceptance_sha256']);pinned(root,config['paired_audit'],EXPECTED['paired_raw_review_sha256']);pinned(root,config['source_dir']+'/freeze.json',EXPECTED['source_freeze_sha256']);pinned(root,config['source_dir']+'/launch-ns-inodes.py',EXPECTED['launcher_sha256'])
 for b,pin in EXPECTED['runs'].items():
  folder=config['run_dir']+'/results/native-inodes-'+b+'/'
  for n,k in [('payload.tar','payload_sha256'),('evidence.tar','evidence_sha256'),('summary.json','summary_sha256'),('run.log.unit-proof.json','evaluator_unit_proof_sha256'),('compat/run.log.unit-proof.json','compatibility_unit_proof_sha256')]:pinned(root,folder+n,pin[k])
  provenance=json.loads(pinned(root,folder+'provenance.json',pin['provenance_sha256']));teardown=json.loads(pinned(root,folder+'vm/teardown.json',pin['teardown_sha256']))
  require(provenance['teardown']==teardown and provenance['vm_uuid']==teardown['vm_uuid']==pin['vm_uuid'] and teardown['scope_unit']==pin['scope_unit'] and teardown['scope_cgroup']==pin['scope_cgroup'] and type(teardown['wrapper_pid']) is int and teardown['wrapper_pid']==pin['vm_wrapper_pid'],'VM teardown identity')
  case=json.loads(pinned(root,folder+'partial-records/results/migration-ns-native-caller-inodes-r1/candidate.json',pin['native_case_record_sha256']));v=case['diagnostics']['native-inodes.json'];require(v.get('truncated') is False and 'base64' in v,'native diagnostics absent');data=base64.b64decode(v['base64'],validate=True);require(v['captured_bytes']==len(data),'native capture length');check_native(data,pin['native_sha256'])
  pinned(root,config['run_dir']+'/plan-native-inodes-'+b+'.json',pin['plan_sha256'])
  launch=json.loads(pinned(root,config['run_dir']+'/launch-native-inodes-'+b+'.json',pin['launch_sha256']))
  require(type(launch['pid']) is int and type(launch['starttime']) is int and launch['pid']==pin['controller_pid'] and launch['starttime']==pin['controller_starttime'] and launch['plan_sha256']==pin['plan_sha256'],'launch controller identity')
 return {'kind':'CONTROL_ONLY','candidate_behavior_count':0,'build':build}
def status(configuration,build):
 """Missing, malformed, unpinned and changed artifacts cannot grant support."""
 try:
  controls=configuration.get('control_receipts',{});require(type(controls) is dict,'control receipts config');verify(controls['ns-native-inodes-r2'],build);return True
 except (OSError,KeyError,TypeError,ValueError,UnicodeError):return False
