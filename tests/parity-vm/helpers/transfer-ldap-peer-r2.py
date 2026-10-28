#!/usr/bin/python3
"""VM-only, one-connection LDAP peer and independent RFC 4511/4532 checks."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import uuid


HOME = Path('/tmp/parity-home')
BIND = bytes.fromhex('302502010160200201030413636e3d616c6963652c64633d6578616d706c658006733363726574')
SEARCH = bytes.fromhex('3030020101632b040564633d65780a01020a0100020100020100010100a3070402636e040178300a0402636e04046d61696c')
ENTRY3 = bytes.fromhex('301f020103641a040564633d65783011300f0402636e310904034164610402426f')


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        case = Path('/tmp/parity-case')
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(HOME)
                or Path.cwd().resolve() != case or case.stat().st_uid != 2000
                or HOME.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def tlv(tag, body):
    assert len(body) < 128
    return bytes([tag, len(body)]) + body


def message(mid, tag, body):
    return tlv(0x30, tlv(2, bytes([mid])) + tlv(tag, body))


def result(mid, tag, code=0, diagnostic=b'', value=None):
    body = tlv(0x0a, bytes([code])) + tlv(4,b'') + tlv(4,diagnostic)
    if value is not None:
        body += tlv(0x8b,value)
    return message(mid,tag,body)


def entry(mid, dn, name, values):
    attrs = tlv(0x30, tlv(4,name) + tlv(0x31,b''.join(tlv(4,v) for v in values)))
    return message(mid,0x64,tlv(4,dn)+tlv(0x30,attrs))


def ext(mid, oid):
    return message(mid,0x77,tlv(0x80,oid.encode()))


def selfcheck():
    assert entry(3,b'dc=ex',b'cn',[b'Ada',b'Bo']) == ENTRY3
    assert result(3,0x65) == bytes.fromhex('300c02010365070a010004000400')
    assert len(BIND)==39 and BIND[5] == 0x60 and b'cn=alice,dc=example' in BIND
    assert len(SEARCH)==50 and SEARCH[5] == 0x63 and b'dc=ex' in SEARCH
    assert ext(2,'1.3.6.1.4.1.4203.1.11.3').hex() == '301e02010277198017312e332e362e312e342e312e343230332e312e31312e33'
    print('BER vectors control ok')


def material():
    p=HOME/'tls'; p.mkdir(mode=0o700)
    for label, cn in (('server','localhost'),('other','other-ca')):
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
            '-subj','/CN='+cn,'-addext','subjectAltName=DNS:localhost,DNS:override.fixture',
            '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(p/(label+'.key')),
            '-out',str(p/(label+'.pem'))], stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=20)
    verified=subprocess.run(['/usr/bin/openssl','verify','-CAfile',str(p/'server.pem'),str(p/'server.pem')],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10)
    (p/'verification.json').write_text(json.dumps({
        'status':verified.returncode,'stdout':verified.stdout.decode(errors='replace'),
        'stderr':verified.stderr.decode(errors='replace')},sort_keys=True)+'\n')
    print('TLS fixture certificate self-verifies')


def exact(conn,n):
    out=b''
    while len(out)<n:
        chunk=conn.recv(n-len(out))
        if not chunk:
            if out: raise ValueError('EOF inside LDAP message')
            return None
        out+=chunk
    return out


def read_message(conn):
    head=exact(conn,2)
    if head is None: return None
    if head[0]!=0x30: raise ValueError('non-SEQUENCE LDAP message')
    if head[1]&0x80:
        n=head[1]&0x7f
        if n<1 or n>2: raise ValueError('invalid BER length')
        longlen=exact(conn,n)
        if longlen is None: raise ValueError('EOF in length')
        size=int.from_bytes(longlen,'big'); head+=longlen
    else: size=head[1]
    if size>4096: raise ValueError('oversized fixture message')
    body=exact(conn,size)
    if body is None or len(body)<4 or body[:2]!=b'\x02\x01': raise ValueError('bad fixture LDAP envelope')
    return head+body


def serve(scenario):
    assert os.getuid()!=0
    result_file=HOME/'peer-result.json'; port_file=HOME/'peer-port'
    record={'accepted':False,'requests':[],'closed':False,'tls':'none','sni':None,'peer_error':None}
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(('127.0.0.1',0)); sock.listen(1); sock.settimeout(4)
    port_file.write_text(str(sock.getsockname()[1]))
    conn=None
    try:
        try: conn,_=sock.accept()
        except socket.timeout: return
        record['accepted']=True; conn.settimeout(4)
        tls_context=None
        if scenario.startswith('tls-'):
            tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(HOME/'tls/server.pem',HOME/'tls/server.key')
            def sni_callback(_sock,name,_context): record['sni']=name
            tls_context.set_servername_callback(sni_callback)
            try:
                conn=tls_context.wrap_socket(conn,server_side=True)
                record['tls']='ok'
            except (ssl.SSLError,OSError) as exc:
                record['tls']='failed'; record['tls_error']=str(exc)
                return
        while True:
            packet=read_message(conn)
            if packet is None:
                record['closed']=True; break
            record['requests'].append(packet.hex())
            mid, op=packet[4], packet[5]
            if op==0x42:
                continue
            if op==0x60:
                code=49 if scenario=='bind-invalid' else 0
                conn.sendall(result(mid,0x61,code,b'invalid credentials' if code else b''))
            elif op==0x77 and b'1.3.6.1.4.1.1466.20037' in packet:
                if scenario=='starttls-handshake-failure':
                    conn.sendall(result(mid,0x78)); record['tls']='peer-closed-before-handshake'; break
                conn.sendall(result(mid,0x78,53,b'fixture refuses StartTLS'))
            elif op==0x77:
                conn.sendall(result(mid,0x78,value=b'dn:cn=alice,dc=example'))
            elif op==0x63:
                if scenario=='search-error':
                    conn.sendall(result(mid,0x65,32,b'fixture no such object'))
                else:
                    first=entry(mid,b'dc=ex',b'cn',[b'Ada',b'Bo'])
                    second=entry(mid,b'cn=two,dc=ex',b'cn',[b'Ce'])
                    for data in (first[:2],first[2:7],first[7:],second[:5],second[5:],result(mid,0x65)):
                        conn.sendall(data); time.sleep(.01)
            else:
                break
    except (OSError,ValueError,ssl.SSLError) as exc:
        record['peer_error']=str(exc)
    finally:
        if conn is not None: conn.close()
        sock.close()
        result_file.write_text(json.dumps(record,sort_keys=True)+'\n')


def check(scenario):
    r=json.loads((HOME/'peer-result.json').read_text())
    if r['peer_error']:
        raise ValueError('peer error: '+r['peer_error'])
    packets=[bytes.fromhex(x) for x in r['requests']]
    if scenario=='invalid-filter':
        assert not r['accepted'] and not packets
    elif scenario.startswith('search-'):
        expected=bytearray(SEARCH)
        if scenario=='search-base': expected[16]=0
        elif scenario=='search-one': expected[16]=1
        assert packets==[bytes(expected)] and r['closed']
        out=(HOME/'client.out').read_text()
        if scenario=='search-error': assert out=='resultCode: 32\ndiagnosticMessage: fixture no such object\n'
        else: assert out=='dn: dc=ex\ncn: Ada\ncn: Bo\ndn: cn=two,dc=ex\ncn: Ce\nresultCode: 0\n'
    elif scenario in ('tls-untrusted','tls-wrong-name'):
        assert r['accepted'] and r['tls']=='failed' and not packets
    else:
        start = scenario.startswith('starttls-')
        bindid=2 if start else 1
        expected_bind=bytearray(BIND); expected_bind[4]=bindid
        start_req=ext(1,'1.3.6.1.4.1.1466.20037')
        who=ext(bindid+1,'1.3.6.1.4.1.4203.1.11.3')
        if scenario in ('starttls-required-refusal','starttls-handshake-failure'):
            assert packets==[start_req]
        elif scenario=='bind-invalid':
            assert packets==[bytes(expected_bind)] and r['closed']
        else:
            expected=([start_req] if start else [])+[bytes(expected_bind),who]
            if packets and packets[-1][5]==0x42: packets.pop()
            assert packets==expected and r['closed']
            assert (HOME/'client.out').read_text()=='resultCode: 0\ndn:cn=alice,dc=example\n'
        if scenario=='tls-default': assert r['tls']=='ok' and r['sni']=='localhost'
        if scenario=='tls-override': assert r['tls']=='ok' and r['sni']=='override.fixture'
        if scenario=='tls-insecure': assert r['tls']=='ok'
    print('peer=ok')


if __name__=='__main__':
    require_guest()
    if sys.argv[1]=='selfcheck': selfcheck()
    elif sys.argv[1]=='material': material()
    elif sys.argv[1]=='serve': serve(sys.argv[2])
    elif sys.argv[1]=='check': check(sys.argv[2])
    else: raise SystemExit('bad action')
