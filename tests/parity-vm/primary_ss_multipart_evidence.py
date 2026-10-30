#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only portable SS multipart reader gated by the exact primary-issued receipt."""
import hashlib,json,pathlib,types
import primary_modern_evidence as modern
from primary_controller_evidence import pinned,require
FORMAT='primary-qualified-ss-multipart-v1'
AUTHORIZED_RECEIPT_SHA256=frozenset({'6d5b3a3d0039456f1a994ad79532163e171b581713e7435d8d32d5787f1f8d4e'})
GENERIC_SOURCE_SHA256='87f56ed376c4396272f2abf4d99f7c8419d6b3d04bf98b07514817e42a0d1d3a'
CID='migration-ss-netlink-multipart-boundaries-r3'
CASE='0753af2a2b17d430a5be85bc87525d1d94b5109b62c34e25e1d4aeba2bbf29ea'
V4_READY='f9535f2430098bbfcd465a66842367062916799614f08205d377a8655b1e68b0'
PAIR_REVIEW='6b943d0c483ab3f8eae282d29468d7d0b21c3c3d280420f2a2b59f441e90cf95'
STATIC_DISPOSITION='3f531454e70fa436b4a6b0789e0ba7f7a49c61514d06eee00a5090199efa8aa8'
DYNAMIC_CURRENT='e165802b71ff37f22651348f0d32221271b973efd4b293423df36fa6ce0aa8e9'
PINS={'static':{'uuid':'1c496449-1821-4025-8a80-93dcb6485428','provenance':'09b635f84e181759f972b704a222f507f3ccbe20244b47e81885c46c7c891e84','poweroff':255,'lifecycle':STATIC_DISPOSITION},'dynamic':{'uuid':'5fb90558-815a-460a-bdd9-8ac5382c7809','provenance':'9ae3db666314621fb9a71b8b29ec4ae34c7f29a4560c0610e292bca7b8a049d8','poweroff':0,'lifecycle':DYNAMIC_CURRENT}}

def _artifact(spec,key,digest):
 items=spec['artifacts'];root=pathlib.Path(items['root']);require(root.is_absolute(),'SS artifact root must be absolute');name=pathlib.PurePosixPath(items[key]);require(not name.is_absolute() and '..' not in name.parts and str(name)==items[key],'unsafe SS artifact path');path=root.joinpath(*name.parts);return json.loads(pinned(path,digest,'SS '+key))

def load_qualified_ss_multipart(spec,expected_binary,expected_build):
 require(spec.get('evidence_format')==FORMAT and expected_build in PINS,'SS format/build differs')
 digest=spec['primary_receipt']['sha256'];require(digest in AUTHORIZED_RECEIPT_SHA256,'SS receipt is not source-authorized')
 pin=PINS[expected_build];receipt=json.loads(pinned(spec['primary_receipt']['path'],digest,'SS primary receipt'));runs=receipt['runs'];require(set(runs)=={'ss-multipart-v3-static','ss-multipart-v3-dynamic'} and {v['build'] for v in runs.values()}=={'static','dynamic'},'SS paired receipt run set')
 key='ss-multipart-v3-'+expected_build;run=runs[key];require(spec['receipt_run']==key and run['build']==expected_build and run['selected_ids']==[CID] and spec['ids']==[CID] and run['cases'][CID]['case_sha256']==CASE and run['vm_uuid']==pin['uuid'] and run['provenance_sha256']==pin['provenance'] and run['poweroff_request']==pin['poweroff'],'SS receipt case/run binding')
 review=_artifact(spec,'paired_review',PAIR_REVIEW);require(review['decision']=='PAIRED_SAVED_DATA_REVIEW_ACCEPTED_NO_AUTHORITY' and review['paired_reviewer_v5_ready_sha256']=='aa2972920c1ad00a377a36bfc7e4c8d2a6a6f6e2ad4afee23191a224c7733e74' and review['static_disposition_sha256']==STATIC_DISPOSITION,'SS independent paired review')
 life=_artifact(spec,'lifecycle',pin['lifecycle']);require(life['vm_uuid']==pin['uuid'] and pathlib.Path(life['result_path']).resolve()==pathlib.Path(run['source_result']).resolve() and life['poweroff_request']==pin['poweroff'] and life['product_coverage'] is False,'SS lifecycle identity')
 if expected_build=='static':
  require(life['schema']=='bashos-exact-vm-lifecycle-primary-disposition-v1' and life['decision']=='accept-observed-serial-powerdown-and-owned-quiescence-with-unexplained-ssh-255' and life['hashes']['provenance.json']==pin['provenance'] and life['separate_qemu_exit_event_claimed'] is False and life['current']['cgroup_absent'] is True and life['current']['wrapper_absent'] is True and life['current']['overlay_absent'] is True and life['current']['exact_uuid_qemu_matches']==[],'SS exact static disposition')
 else:
  require(life['schema']=='primary-exact-owned-current-and-unit-review-v1' and life['record_sha256']==pin['provenance'] and life['cgroup_absent'] is True and life['wrapper_absent'] is True and life['overlay_absent'] is True and life['exact_uuid_qemu_matches']==[],'SS exact dynamic current proof')
 require(hashlib.sha256(pathlib.Path(modern.__file__).read_bytes()).hexdigest()==GENERIC_SOURCE_SHA256,'SS generic reader source changed; re-review required')
 # Give this invocation alone the already source-authorized receipt. The real
 # generic module global never changes, so unrelated calls cannot inherit it.
 namespace=dict(modern.load_qualified_modern_run.__globals__);namespace['AUTHORIZED_RECEIPT_SHA256']=frozenset({digest})
 loader=types.FunctionType(modern.load_qualified_modern_run.__code__,namespace,modern.load_qualified_modern_run.__name__,modern.load_qualified_modern_run.__defaults__,modern.load_qualified_modern_run.__closure__)
 translated=dict(spec);translated['evidence_format']=modern.FORMAT;selected,metadata=loader(translated,expected_binary,expected_build)
 require(len(selected)==1 and selected[0]['record']['status']==run['cases'][CID]['status'],'SS generic result differs');metadata['evidence_format']=FORMAT;metadata['ss_lifecycle_sha256']=pin['lifecycle'];metadata['ss_paired_review_sha256']=PAIR_REVIEW;return selected,metadata
