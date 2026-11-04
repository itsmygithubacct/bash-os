#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only projection of pre-provisioned fixture authority and response."""
import hashlib,json,os,re,stat,sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec

def need(x,s):
    if not x:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def read_regular(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o400 and 0<a.st_size<=limit,'unsafe fixture authority file')
        data=b''
        while len(data)<a.st_size:
            x=os.read(fd,a.st_size-len(data));need(bool(x),'short read');data+=x
        b=os.fstat(fd);need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns),'authority file changed')
        return data
    finally:os.close(fd)
def unique(pairs):
    d={}
    for k,v in pairs:need(k not in d,'duplicate JSON key');d[k]=v
    return d
def anchor():
    pem=read_regular('fixture-ca-5810.pem',16384);proof=json.loads(read_regular('fixture-ca-5810.json',4096),object_pairs_hook=unique)
    need(set(proof)=={'anchor_sha256','issuer_sha256','origin'} and proof['origin']=='pre-request-fixture-authority','authority proof')
    need(all(isinstance(proof[k],str) and re.fullmatch('[0-9a-f]{64}',proof[k]) for k in ('anchor_sha256','issuer_sha256')),'invalid digest')
    need(sha(pem)==proof['anchor_sha256'],'anchor differs from pre-request authority')
    ca=x509.load_pem_x509_certificate(pem);need(ca.subject==ca.issuer and ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,'not fixture CA')
    ca.public_key().verify(ca.signature,ca.tbs_certificate_bytes,ec.ECDSA(ca.signature_hash_algorithm))
    return pem,proof
def finish(token,mode):
    pem,proof=anchor();need(token==proof['anchor_sha256']+':'+proof['issuer_sha256'],'authority changed since preflight')
    log=json.loads(Path('acme-5810.json').read_text('utf-8'));need(isinstance(log,list) and len(log)<=256,'invalid bounded authority log')
    responses=[e for e in log if e.get('method')=='RESPONSE' and e.get('path')=='/acme/cert/1' and e.get('status')==200];need(len(responses)==1,'certificate response missing')
    raw=responses[0]['response_body'].encode();parts=raw.split(b'-----END CERTIFICATE-----');need(len(parts)==3 and not parts[-1].strip(),'expected leaf and authority chain')
    leaf,issuer=[x509.load_pem_x509_certificate(x+b'-----END CERTIFICATE-----\n') for x in parts[:2]]
    need(sha(issuer.public_bytes(serialization.Encoding.PEM))==proof['issuer_sha256'],'issued chain not from pre-request fixture authority')
    need(leaf.issuer==issuer.subject and issuer.subject==issuer.issuer,'issuer mismatch')
    issuer.public_key().verify(issuer.signature,issuer.tbs_certificate_bytes,ec.ECDSA(issuer.signature_hash_algorithm))
    issuer.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,ec.ECDSA(leaf.signature_hash_algorithm))
    need(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)==['fixture.test'],'issued SAN mismatch')
    if mode=='trusted':
        need(proof['anchor_sha256']==proof['issuer_sha256'] and pem==issuer.public_bytes(serialization.Encoding.PEM),'not the separately provisioned authority')
        need(Path('issued/fullchain.pem').read_bytes()==raw,'stored chain differs from authority response')
        key=serialization.load_pem_private_key(Path('issued/privkey.pem').read_bytes(),password=None)
        need(key.public_key().public_numbers()==leaf.public_key().public_numbers(),'issued private key mismatch')
        print('fixture-anchor-ok')
    else:
        need(mode=='wrong' and proof['anchor_sha256']!=proof['issuer_sha256'],'negative anchor is not independent')
        need(not os.path.lexists('issued/fullchain.pem') and not os.path.lexists('issued/privkey.pem'),'untrusted chain was published')
        print('fixture-untrusted-anchor-rejected')
if __name__=='__main__':
    try:
        if len(sys.argv)==2 and sys.argv[1]=='prepare':
            _,p=anchor();print(p['anchor_sha256']+':'+p['issuer_sha256'])
        elif len(sys.argv)==4 and sys.argv[1]=='finish':finish(sys.argv[2],sys.argv[3])
        else:raise ValueError('invalid trust projection invocation')
    except Exception as e:
        print('fixture-trust-incomplete: '+type(e).__name__+': '+str(e),file=sys.stderr);sys.exit(1)
