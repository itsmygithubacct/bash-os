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
    assert result(1,0x61,0) == bytes.fromhex('300c02010161070a010004000400')
    assert result(1,0x61,49,b'invalid credentials') == bytes.fromhex('301f020101611a0a013104000413')+b'invalid credentials'
    assert result(2,0x78,value=b'dn:cn=alice,dc=example') == bytes.fromhex('3024020102781f0a0100040004008b16')+b'dn:cn=alice,dc=example'
    assert result(1,0x78,53,b'fixture refuses StartTLS') == bytes.fromhex('3024020101781f0a013504000418')+b'fixture refuses StartTLS'
    assert result(1,0x78,0) == bytes.fromhex('300c02010178070a010004000400')
    assert result(3,0x65,32,b'fixture no such object') == bytes.fromhex('3022020103651d0a012004000416')+b'fixture no such object'
    assert entry(3,b'cn=two,dc=ex',b'cn',[b'Ce']) == bytes.fromhex('3021020103641c040c')+b'cn=two,dc=ex'+bytes.fromhex('300c300a0402636e310404024365')
    send_controls()
    print('BER vectors control ok')


def material():
    p=HOME/'tls'; p.mkdir(mode=0o700)
    for label, cn in (('server','localhost'),('other','other-ca')):
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
            '-subj','/CN='+cn,'-addext','subjectAltName=DNS:localhost,DNS:override.fixture',
            '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(p/(label+'.key')),
            '-out',str(p/(label+'.pem'))], stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=20)
    controls=[]
    for label,ca,host,wanted in (('trusted','server','localhost',0),('untrusted','other','localhost',1),
                                  ('wrong-name','server','wrong.fixture',1)):
        argv=['/usr/bin/openssl','verify','-verify_hostname',host,'-CAfile',str(p/(ca+'.pem')),str(p/'server.pem')]
        verified=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        controls.append({'label':label,'argv':argv,'status':verified.returncode,
                         'stdout':verified.stdout.decode(errors='replace'),'stderr':verified.stderr.decode(errors='replace')})
        if (verified.returncode==0)!=(wanted==0): raise ValueError('certificate '+label+' control failed')
    (p/'verification.json').write_text(json.dumps({'controls':controls},sort_keys=True)+'\n')
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



def send_piece(conn, data, rows, label):
    # send() returns only locally accepted bytes; no peer-receipt claim follows.
    offset=0
    while offset<len(data):
        attempt=data[offset:]
        row={'label':label,'attempt_hex':attempt.hex(),'started_ns':time.monotonic_ns(),
             'accepted':0,'error':None}
        rows.append(row)
        try:
            n=conn.send(attempt)
            row['accepted']=n
            if n<=0: raise OSError('zero-length send')
            offset+=n
        except (OSError,ssl.SSLError) as exc:
            row['error']=type(exc).__name__+': '+str(exc)
            raise
        finally: row['ended_ns']=time.monotonic_ns()


def send_response(conn, record, mid, name, packet, boundaries=None):
    row={'message_id':mid,'type':name,'ber_hex':packet.hex(),'writes':[]}
    record['responses'].append(row)
    parts=boundaries if boundaries is not None else [packet]
    if b''.join(parts)!=packet: raise ValueError('response fragments differ from BER')
    for index,part in enumerate(parts):
        send_piece(conn,part,row['writes'],'fragment-'+str(index))
        if len(parts)>1: time.sleep(.01)


def send_controls():
    class Fake:
        def __init__(self,fail): self.fail=fail; self.n=0
        def send(self,b):
            self.n+=1
            if self.fail and self.n==2: raise BrokenPipeError('controlled error')
            return min(2,len(b))
    rows=[]; send_piece(Fake(False),b'abcde',rows,'short-success')
    assert [r['accepted'] for r in rows]==[2,2,1] and all(r['error'] is None for r in rows)
    bad=[]
    try: send_piece(Fake(True),b'abcde',bad,'short-error')
    except BrokenPipeError: pass
    else: raise AssertionError('error control did not fail')
    assert [r['accepted'] for r in bad]==[2,0] and bad[-1]['error'].startswith('BrokenPipeError')
    a,b=socket.socketpair(); actual=[]
    try:
        send_piece(a,b'control',actual,'socketpair'); received=b.recv(7)
        assert received==b'control'
    finally: a.close(); b.close()
    (HOME/'send-control.json').write_text(json.dumps({'partial':rows,'error':bad,
        'socket_send':actual,'socket_received_hex':received.hex()},sort_keys=True)+'\n')


class ObservedTLS:
    """SSLObject with explicitly logged ciphertext transport and plaintext reads."""
    def __init__(self,raw,context,record):
        self.raw=raw; self.record=record; self.incoming=ssl.MemoryBIO(); self.outgoing=ssl.MemoryBIO()
        self.obj=context.wrap_bio(self.incoming,self.outgoing,server_side=True)
    def flush(self):
        while self.outgoing.pending:
            b=self.outgoing.read(); send_piece(self.raw,b,self.record['tls_wire'],'ciphertext-send')
    def feed(self):
        t=time.monotonic_ns()
        try:
            data=self.raw.recv(16384)
            self.record['tls_wire'].append({'label':'ciphertext-recv','bytes_hex':data.hex(),
                'started_ns':t,'ended_ns':time.monotonic_ns(),'error':None})
        except OSError as exc:
            self.record['tls_wire'].append({'label':'ciphertext-recv','bytes_hex':'',
                'started_ns':t,'ended_ns':time.monotonic_ns(),'error':type(exc).__name__+': '+str(exc)})
            raise
        if data: self.incoming.write(data)
        else: self.incoming.write_eof()
    def handshake(self):
        while True:
            try: self.obj.do_handshake(); self.flush(); break
            except ssl.SSLWantReadError: self.flush(); self.feed()
            except ssl.SSLWantWriteError: self.flush()
        self.record['tls_version']=self.obj.version(); self.record['tls_cipher']=self.obj.cipher()
    def recv(self,n):
        while True:
            try:
                data=self.obj.read(n); self.flush()
                self.record['tls_plaintext_reads'].append(data.hex())
                return data
            except ssl.SSLWantReadError: self.flush(); self.feed()
            except ssl.SSLWantWriteError: self.flush()
            except (ssl.SSLZeroReturnError,ssl.SSLEOFError): return b''
    def send(self,data):
        while True:
            try:
                n=self.obj.write(data); self.flush(); return n
            except ssl.SSLWantReadError: self.flush(); self.feed()
            except ssl.SSLWantWriteError: self.flush()
    def close(self): self.raw.close()


def serve(scenario):
    assert os.getuid()!=0
    result_file=HOME/'peer-result.json'; port_file=HOME/'peer-port'
    record={'accepted':False,'requests':[],'closed':False,'tls':'none','sni':None,'peer_error':None,'responses':[],
            'tls_wire':[],'tls_plaintext_reads':[]}
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
                conn=ObservedTLS(conn,tls_context,record)
                conn.handshake()
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
                send_response(conn,record,mid,'BindResponse',result(mid,0x61,code,b'invalid credentials' if code else b''))
            elif op==0x77 and b'1.3.6.1.4.1.1466.20037' in packet:
                if scenario=='starttls-handshake-failure':
                    send_response(conn,record,mid,'StartTLS-success',result(mid,0x78));
                    conn.settimeout(1.5)
                    try:
                        received=conn.recv(16384)
                        record['starttls_post_response_hex']=received.hex()
                        if received.startswith(b'0'): record['peer_error']='plaintext LDAP after StartTLS success'
                    except (socket.timeout,OSError) as exc:
                        record['starttls_post_response_error']=type(exc).__name__+': '+str(exc)
                    record['tls']='peer-closed-before-handshake'; break
                send_response(conn,record,mid,'StartTLS-refusal',result(mid,0x78,53,b'fixture refuses StartTLS'))
            elif op==0x77:
                send_response(conn,record,mid,'WhoAmI-ExtendedResponse',result(mid,0x78,value=b'dn:cn=alice,dc=example'))
            elif op==0x63:
                if scenario=='search-error':
                    send_response(conn,record,mid,'SearchResultDone-32',result(mid,0x65,32,b'fixture no such object'))
                else:
                    first=entry(mid,b'dc=ex',b'cn',[b'Ada',b'Bo'])
                    second=entry(mid,b'cn=two,dc=ex',b'cn',[b'Ce'])
                    send_response(conn,record,mid,'SearchResultEntry-1',first,[first[:2],first[2:7],first[7:]])
                    send_response(conn,record,mid,'SearchResultEntry-2',second,[second[:5],second[5:]])
                    send_response(conn,record,mid,'SearchResultDone-0',result(mid,0x65))
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
