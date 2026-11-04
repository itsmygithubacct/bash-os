#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only independent projection of fixture newAccount wire evidence."""
import base64, hashlib, json, re, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

def require(value,why):
    if not value:raise ValueError(why)
def unique(pairs):
    d={}
    for k,v in pairs:
        require(k not in d,'duplicate JSON member');d[k]=v
    return d
def unb64(s):
    require(isinstance(s,str) and re.fullmatch(r'[A-Za-z0-9_-]*',s) is not None,'invalid base64url')
    return base64.b64decode(s+'='*(-len(s)%4),altchars=b'-_',validate=True)
def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
def fixture_jwk():
    n=ec.derive_private_key(1,ec.SECP256R1()).public_key().public_numbers()
    return {'crv':'P-256','kty':'EC','x':b64(n.x.to_bytes(32,'big')),'y':b64(n.y.to_bytes(32,'big'))}
def verify(wire,url,nonce,content_type):
    require(content_type=='application/jose+json','content type')
    data=json.loads(wire,object_pairs_hook=unique);require(isinstance(data,dict) and set(data)=={'protected','payload','signature'},'flattened JWS shape')
    h=json.loads(unb64(data['protected']),object_pairs_hook=unique);require(isinstance(h,dict),'protected object')
    require(h.get('alg')=='ES256' and h.get('jwk')==fixture_jwk() and 'kid' not in h,'algorithm or account JWK')
    require(h.get('url')==url and isinstance(nonce,str) and h.get('nonce')==nonce,'URL or nonce')
    unb64(data['payload']);sig=unb64(data['signature']);require(len(sig)==64,'ES256 signature length')
    key=ec.derive_private_key(1,ec.SECP256R1()).public_key()
    key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),(data['protected']+'.'+data['payload']).encode('ascii'),ec.ECDSA(hashes.SHA256()))
def project(port,label):
    log=json.loads(Path('acme-%d.json'%port).read_text('utf-8'));require(isinstance(log,list) and len(log)<=200,'invalid bounded peer log')
    expected='http://127.0.0.1:%d/acme/new-acct'%port;last_nonce=None;head=False;head_ok=False;seen=0
    for e in log:
        if e.get('method')=='HEAD' and e.get('path')=='/acme/new-nonce':head=True
        if e.get('method')=='RESPONSE':
            last_nonce=e.get('response_nonce')
            if e.get('path')=='/acme/new-nonce' and e.get('status')==200 and head:head_ok=True
        if e.get('method')=='POST' and e.get('path')=='/acme/new-acct':
            require(head_ok,'successful newNonce HEAD absent');wire=base64.b64decode(e['wire_b64'],validate=True);require(len(wire)<65536,'wire too large')
            verify(wire,expected,last_nonce,e.get('content_type'));seen+=1
    require(seen==1,'expected one account POST');print('r3-wire-'+label+'-ok')
def selftest():
    key=ec.derive_private_key(1,ec.SECP256R1());h={'alg':'ES256','jwk':fixture_jwk(),'url':'http://127.0.0.1:5810/acme/new-acct','nonce':'fixture-nonce'};a=b64(json.dumps(h,sort_keys=True).encode());b=b64(b'{}');r,s=utils.decode_dss_signature(key.sign((a+'.'+b).encode(),ec.ECDSA(hashes.SHA256())));sig=r.to_bytes(32,'big')+s.to_bytes(32,'big');wire=json.dumps({'protected':a,'payload':b,'signature':b64(sig)});verify(wire,h['url'],h['nonce'],'application/jose+json')
    changed_alg=dict(h,alg='HS256');changed_jwk=dict(h,jwk={'kty':'EC','crv':'P-256','x':'bad','y':'bad'})
    wrong_header=lambda v:json.dumps({'protected':b64(json.dumps(v).encode()),'payload':b,'signature':b64(sig)})
    for bad,url,nonce,ct in ((wire,h['url'],'wrong','application/jose+json'),(wire,h['url']+'/wrong',h['nonce'],'application/jose+json'),(wire,h['url'],h['nonce'],'text/plain'),(json.dumps({'protected':a,'payload':b,'signature':b64(bytes([sig[0]^1])+sig[1:])}),h['url'],h['nonce'],'application/jose+json'),(wrong_header(changed_alg),h['url'],h['nonce'],'application/jose+json'),(wrong_header(changed_jwk),h['url'],h['nonce'],'application/jose+json'),('{}',h['url'],h['nonce'],'application/jose+json')):
        try:verify(bad,url,nonce,ct)
        except Exception:continue
        raise AssertionError('invalid JWS accepted')
    print('r3-wire-negative-controls-ok')
if __name__=='__main__':
    try:
        if sys.argv[1]=='selftest' and len(sys.argv)==2:selftest()
        elif sys.argv[1]=='project' and len(sys.argv)==4 and sys.argv[3] in ('reference','candidate'):project(int(sys.argv[2]),sys.argv[3])
        else:raise ValueError('invalid projector invocation')
    except Exception as exc:
        print('r3-wire-incomplete: '+type(exc).__name__+': '+str(exc),file=sys.stderr);sys.exit(1)
