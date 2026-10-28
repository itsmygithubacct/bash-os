#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Independent OpenSSL NTS-KE peer and client in the disposable parity VM."""
import base64
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import uuid


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker))!=marker.lower(): raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('wrong uid')
        if Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home': raise ValueError('wrong scratch directory')
    except (OSError,ValueError,UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: '+str(exc))


require_guest()
HOME=Path('/tmp/parity-home')
GUARD=r'''[[ $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r v </sys/class/dmi/id/sys_vendor || exit 125
IFS= read -r u </etc/bashos-parity-vm || exit 125
[[ $v == QEMU && $u =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
'''
LABEL=b'EXPORTER-network-time-security'
REQUEST=bytes.fromhex('80010002000080040002000f80000000')
COOKIE0=bytes.fromhex('0102030405060708')
COOKIE1=bytes.fromhex('a1a2a3a4a5a6a7a8')


def check(ok,message):
    if not ok: raise RuntimeError(message)


def rec(kind,body): return struct.pack('!HH',kind,len(body))+body


def records(data):
    result=[];pos=0
    while pos<len(data):
        check(pos+4<=len(data),'truncated record header')
        kind,n=struct.unpack_from('!HH',data,pos);pos+=4
        check(pos+n<=len(data),'truncated record body')
        result.append((kind,data[pos:pos+n]));pos+=n
        if kind & 0x7fff==0:
            check(pos==len(data),'bytes after end-of-message')
            return result
    raise RuntimeError('missing end-of-message')


def response(mode):
    if mode=='error':return rec(0x8002,struct.pack('!H',3))+rec(0x8000,b'')
    if mode=='critical':return rec(0x8011,b'x')+rec(0x8000,b'')
    return (rec(0x8001,struct.pack('!H',0))+rec(0x8004,struct.pack('!H',15))+
            rec(5,COOKIE0)+rec(5,COOKIE1)+rec(6,b'127.0.0.1')+
            rec(7,struct.pack('!H',1234))+rec(0x8000,b''))


def interpret(data):
    rows=records(data);result={'cookies':[]}
    for kind,body in rows:
        typ=kind & 0x7fff
        if typ==0: break
        if typ==1: check(body==b'\x00\x00','unexpected next protocol');result['protocol']=0
        elif typ==2: check(len(body)==2,'invalid error record');return {'error':struct.unpack('!H',body)[0]}
        elif typ==4: check(body==b'\x00\x0f','unexpected AEAD');result['aead']=15
        elif typ==5: result['cookies'].append(body.hex())
        elif typ==6: result['host']=body.decode('ascii')
        elif typ==7: check(len(body)==2,'bad port');result['port']=struct.unpack('!H',body)[0]
        elif kind & 0x8000: return {'critical':typ}
    return result


class OpenSSL:
    def __init__(self,server,trace):
        self.lib=ctypes.CDLL('libssl.so.3');self.trace=trace;self.server=server;self.session=None;self.callback=None
        def fn(name,restype,args):
            f=getattr(self.lib,name);f.restype=restype;f.argtypes=args;return f
        fn('TLS_server_method',ctypes.c_void_p,[]);fn('TLS_client_method',ctypes.c_void_p,[])
        fn('SSL_CTX_new',ctypes.c_void_p,[ctypes.c_void_p]);fn('SSL_CTX_free',None,[ctypes.c_void_p])
        fn('SSL_CTX_ctrl',ctypes.c_long,[ctypes.c_void_p,ctypes.c_int,ctypes.c_long,ctypes.c_void_p])
        fn('SSL_CTX_use_certificate_file',ctypes.c_int,[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int])
        fn('SSL_CTX_use_PrivateKey_file',ctypes.c_int,[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int])
        fn('SSL_CTX_load_verify_locations',ctypes.c_int,[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p])
        fn('SSL_CTX_set_verify',None,[ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p])
        fn('SSL_new',ctypes.c_void_p,[ctypes.c_void_p]);fn('SSL_free',None,[ctypes.c_void_p])
        fn('SSL_set_fd',ctypes.c_int,[ctypes.c_void_p,ctypes.c_int]);fn('SSL_accept',ctypes.c_int,[ctypes.c_void_p]);fn('SSL_connect',ctypes.c_int,[ctypes.c_void_p])
        fn('SSL_ctrl',ctypes.c_long,[ctypes.c_void_p,ctypes.c_int,ctypes.c_long,ctypes.c_void_p])
        fn('SSL_set1_host',ctypes.c_int,[ctypes.c_void_p,ctypes.c_char_p])
        fn('SSL_set_alpn_protos',ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint])
        fn('SSL_get_servername',ctypes.c_char_p,[ctypes.c_void_p,ctypes.c_int])
        fn('SSL_version',ctypes.c_int,[ctypes.c_void_p]);fn('SSL_read',ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]);fn('SSL_write',ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int])
        fn('SSL_export_keying_material',ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_char_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int])
        method=self.lib.TLS_server_method() if server else self.lib.TLS_client_method()
        self.ctx=self.lib.SSL_CTX_new(method);check(self.ctx,'SSL_CTX_new failed')
        check(self.lib.SSL_CTX_ctrl(self.ctx,123,0x0304,None)==1,'cannot require TLS 1.3')
        if server:
            check(self.lib.SSL_CTX_use_certificate_file(self.ctx,str(HOME/'server.pem').encode(),1)==1,'server cert load failed')
            check(self.lib.SSL_CTX_use_PrivateKey_file(self.ctx,str(HOME/'server.key').encode(),1)==1,'server key load failed')
            callback_type=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_ubyte),ctypes.POINTER(ctypes.c_ubyte),ctypes.c_uint,ctypes.c_void_p)
            def choose(_ssl,out,outlen,offered,n,_arg):
                data=ctypes.string_at(offered,n);trace['alpn_offered_hex']=data.hex();pos=0
                while pos<len(data):
                    length=data[pos];pos+=1
                    if pos+length>len(data): return 2
                    if data[pos:pos+length]==b'ntske/1':
                        out[0]=ctypes.cast(offered,ctypes.c_void_p).value+pos;outlen[0]=length
                        trace['alpn_selected']='ntske/1';return 0
                    pos+=length
                return 2
            self.callback=callback_type(choose)
            fn('SSL_CTX_set_alpn_select_cb',None,[ctypes.c_void_p,callback_type,ctypes.c_void_p])
            self.lib.SSL_CTX_set_alpn_select_cb(self.ctx,self.callback,None)
        else:
            check(self.lib.SSL_CTX_load_verify_locations(self.ctx,str(HOME/'ca.pem').encode(),None)==1,'CA load failed')
            self.lib.SSL_CTX_set_verify(self.ctx,1,None)

    def handshake(self,sock):
        self.session=self.lib.SSL_new(self.ctx);check(self.session,'SSL_new failed')
        check(self.lib.SSL_set_fd(self.session,sock.fileno())==1,'SSL_set_fd failed')
        if not self.server:
            host=ctypes.create_string_buffer(b'trace.test');self.host=host
            check(self.lib.SSL_ctrl(self.session,55,0,ctypes.cast(host,ctypes.c_void_p))==1,'SNI setup failed')
            check(self.lib.SSL_set1_host(self.session,b'trace.test')==1,'hostname verifier setup failed')
            wire=ctypes.create_string_buffer(b'\x07ntske/1');self.wire=wire
            check(self.lib.SSL_set_alpn_protos(self.session,wire,8)==0,'ALPN setup failed')
        ok=self.lib.SSL_accept(self.session) if self.server else self.lib.SSL_connect(self.session)
        check(ok==1,'TLS handshake failed')
        version=self.lib.SSL_version(self.session)
        if self.server: self.trace['tls_version']=hex(version)
        check(version==0x0304,'not TLS 1.3')
        if self.server:
            name=self.lib.SSL_get_servername(self.session,0)
            self.trace['sni']=name.decode() if name else None

    def write(self,data):
        buf=ctypes.create_string_buffer(data)
        check(self.lib.SSL_write(self.session,buf,len(data))==len(data),'SSL_write failed')

    def read_message(self):
        data=bytearray()
        while len(data)<1024:
            buf=ctypes.create_string_buffer(1024);n=self.lib.SSL_read(self.session,buf,len(buf))
            check(n>0,'SSL_read failed');data+=buf.raw[:n]
            try:
                records(data);return bytes(data)
            except RuntimeError as exc:
                if str(exc) not in ('truncated record header','truncated record body','missing end-of-message'): raise
        raise RuntimeError('NTS transcript exceeded bound')

    def exporter(self,direction):
        context=ctypes.create_string_buffer(bytes([0,0,0,15,direction]));out=ctypes.create_string_buffer(32)
        check(self.lib.SSL_export_keying_material(self.session,out,32,LABEL,len(LABEL),context,5,1)==1,'TLS exporter failed')
        return out.raw

    def close(self):
        if self.session:self.lib.SSL_free(self.session);self.session=None
        if self.ctx:self.lib.SSL_CTX_free(self.ctx);self.ctx=None


def parse_stdout(data):
    rows={}
    for line in data.decode('ascii').splitlines():
        key,sep,value=line.partition('=');check(bool(sep) and key not in rows,'unexpected output line');rows[key]=value
    return rows


def control():
    sample=response('good');parsed=interpret(sample)
    wrong=bytearray(sample);wrong[5]=1
    try:interpret(bytes(wrong));rejected=False
    except RuntimeError:rejected=True
    checks={'request_wire':REQUEST.hex()=='80010002000080040002000f80000000',
            'good_parse':parsed=={'protocol':0,'aead':15,'cookies':[COOKIE0.hex(),COOKIE1.hex()],'host':'127.0.0.1','port':1234},
            'wrong_protocol_rejected':rejected,'error_parse':interpret(response('error'))=={'error':3},
            'critical_parse':interpret(response('critical'))=={'critical':17}}
    (HOME/'nts-control.json').write_text(json.dumps({'request_hex':REQUEST.hex(),'response_hex':sample.hex(),'parsed':parsed,'checks':checks},indent=2)+'\n')
    check(all(checks.values()),'NTS record control failed');print('NTS wire controls ok')


def exercise(side,shell,scenario):
    trace={'side':side,'scenario':scenario,'events':[]};listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10);port=listener.getsockname()[1]
    check(listener.getsockname()[0]=='127.0.0.1','not loopback')
    def peer():
        tls=None
        try:
            conn,address=listener.accept();trace['peer_address']=list(address);trace['events'].append('accept')
            check(address[0]=='127.0.0.1','non-loopback peer');conn.setblocking(True)
            tls=OpenSSL(True,trace);tls.handshake(conn);trace['events'].append('handshake')
            request=tls.read_message();trace['request_hex']=request.hex();trace['events'].append('request')
            trace['server_c2s']=tls.exporter(0).hex();trace['server_s2c']=tls.exporter(1).hex()
            answer=response(scenario);trace['response_hex']=answer.hex();tls.write(answer);trace['events'].append('response')
            tls.close();tls=None;conn.close()
        except Exception as exc:trace['peer_error']=repr(exc)
        finally:
            if tls:tls.close()
            listener.close()
    thread=threading.Thread(target=peer,daemon=True);thread.start()
    client_result={}
    try:
        if side=='reference':
            sock=socket.create_connection(('127.0.0.1',port),timeout=8);sock.setblocking(True)
            client=OpenSSL(False,client_result)
            try:
                client.handshake(sock);client.write(REQUEST);answer=client.read_message()
                client_result.update(response_hex=answer.hex(),parsed=interpret(answer),
                    c2s=client.exporter(0).hex(),s2c=client.exporter(1).hex(),status=0)
            finally:client.close();sock.close()
        else:
            body=GUARD+'crypto nts-ke "127.0.0.1:$1" -c "$2" -s trace.test --timeout 5000 --emit-keys\n'
            command=[shell,'--noprofile','--norc','-c',body,'nts-fixture',str(port),str(HOME/'ca.pem')]
            p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            client_result={'command':command,'status':p.returncode,
                           'stdout_base64':base64.b64encode(p.stdout[:65536]).decode(),
                           'stderr_base64':base64.b64encode(p.stderr[:65536]).decode()}
            if scenario=='good' and p.returncode==0:client_result['fields']=parse_stdout(p.stdout)
    except Exception as exc:client_result['error']=repr(exc)
    thread.join(10);trace['peer_finished']=not thread.is_alive();trace['client']=client_result
    base={'peer_finished':not thread.is_alive(),'no_peer_error':'peer_error' not in trace,
          'sni':trace.get('sni')=='trace.test','alpn':trace.get('alpn_selected')=='ntske/1',
          'exact_request':trace.get('request_hex')==REQUEST.hex(),
          'exact_response':trace.get('response_hex')==response(scenario).hex(),
          'event_order':trace['events']==['accept','handshake','request','response']}
    if side=='reference':
        parsed=client_result.get('parsed')
        if scenario=='good':
            base.update(reference_parse=parsed==interpret(response('good')),
                        reference_c2s=client_result.get('c2s')==trace.get('server_c2s') and bool(client_result.get('c2s')),
                        reference_s2c=client_result.get('s2c')==trace.get('server_s2c') and bool(client_result.get('s2c')))
        else:base['reference_rejects']=parsed==({'error':3} if scenario=='error' else {'critical':17})
    elif scenario=='good':
        fields=client_result.get('fields',{})
        base.update(client_status=client_result.get('status')==0,
                    aead=fields.get('aead')=='15',host=fields.get('ntp_server')=='127.0.0.1',port=fields.get('ntp_port')=='1234',
                    cookies=fields.get('cookies')=='2' and fields.get('cookie0')==COOKIE0.hex() and fields.get('cookie1')==COOKIE1.hex(),
                    c2s=fields.get('c2s')==trace.get('server_c2s') and bool(fields.get('c2s')),
                    s2c=fields.get('s2c')==trace.get('server_s2c') and bool(fields.get('s2c')))
    else:
        diagnostic=base64.b64decode(client_result.get('stderr_base64',''))
        expected=b'nts-ke: server returned error code 3' if scenario=='error' else b'nts-ke: unrecognized critical record 17'
        base.update(client_nonzero=client_result.get('status')==1,
                    stdout_empty=base64.b64decode(client_result.get('stdout_base64',''))==b'',diagnostic=expected in diagnostic)
    trace['checks']=base
    (HOME/'nts-observation.json').write_text(json.dumps(trace,sort_keys=True,indent=2)+'\n')
    check(all(base.values()),'NTS fixture mismatch: '+repr(base));print('nts-'+scenario+': ok')


if sys.argv[1:]==['--control']:control()
elif len(sys.argv)==4 and sys.argv[1] in ('candidate','reference') and sys.argv[3] in ('good','error','critical'):
    side,shell,scenario=sys.argv[1:]
    if side=='candidate' and shell!='/opt/bashos-parity/candidate':raise SystemExit('candidate path refused')
    if side=='reference' and shell!='/opt/bash-5.3.15/bin/bash':raise SystemExit('reference path refused')
    exercise(side,shell,scenario)
else:raise SystemExit('invalid invocation')
