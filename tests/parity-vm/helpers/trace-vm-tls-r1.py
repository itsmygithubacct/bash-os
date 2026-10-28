#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guarded loopback-only TLS peer with an independent OpenSSL client side."""
import base64
import json
import os
from pathlib import Path
import socket
import ssl
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
REQUEST=b'fixture request\n'
RESPONSE=b'fixture response\n'


def exercise(side,shell,scenario):
    version=ssl.TLSVersion.TLSv1_2 if scenario=='tls12' else ssl.TLSVersion.TLSv1_3
    negative=scenario in ('wrong-ca','wrong-sni')
    server_name='wrong.trace.test' if scenario=='wrong-sni' else 'trace.test'
    ca=HOME/('wrong-ca.pem' if scenario=='wrong-ca' else 'ca.pem')
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version=server.maximum_version=version
    server.load_cert_chain(str(HOME/'server.pem'),str(HOME/'server.key'))
    record={'scenario':scenario,'side':side,'events':[],'request_base64':'','response_base64':'','sni':None,'tls_version':None}
    def on_sni(_sock,name,_ctx):
        record['sni']=name;record['events'].append('sni')
    server.set_servername_callback(on_sni)
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(10)
    port=listener.getsockname()[1]
    if listener.getsockname()[0]!='127.0.0.1': raise RuntimeError('loopback binding failed')
    def peer():
        try:
            raw,address=listener.accept();record['events'].append('accept');record['peer_address']=list(address)
            if address[0]!='127.0.0.1': raise RuntimeError('non-loopback peer')
            raw.settimeout(8)
            with server.wrap_socket(raw,server_side=True) as stream:
                record['events'].append('handshake');record['tls_version']=stream.version()
                received=bytearray()
                while len(received)<len(REQUEST):
                    part=stream.recv(len(REQUEST)-len(received))
                    if not part: break
                    received.extend(part)
                record['request_base64']=base64.b64encode(received).decode()
                record['events'].append('request')
                if bytes(received)==REQUEST:
                    stream.sendall(RESPONSE);record['response_base64']=base64.b64encode(RESPONSE).decode()
                    record['events'].append('response')
                    try: stream.unwrap();record['events'].append('close_notify')
                    except (OSError,ssl.SSLError) as exc: record['close_error']=repr(exc)
        except (OSError,ssl.SSLError,RuntimeError) as exc:
            record['peer_error']=repr(exc)
        finally:
            listener.close()
    thread=threading.Thread(target=peer,daemon=True);thread.start()
    if side=='reference':
        command=['/usr/bin/openssl','s_client','-quiet','-verify_return_error','-verify_hostname',server_name,
                 '-CAfile',str(ca),'-servername',server_name,'-connect','127.0.0.1:'+str(port)]
    else:
        body=GUARD+'crypto tls connect "127.0.0.1:$1" -c "$2" -s "$3" --read-timeout 5000\n'
        command=[shell,'--noprofile','--norc','-c',body,'tls-fixture',str(port),str(ca),server_name]
    p=subprocess.run(command,input=REQUEST,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    thread.join(10)
    record.update(command=command,status=p.returncode,client_stdout_base64=base64.b64encode(p.stdout[:65536]).decode(),
                  client_stderr_base64=base64.b64encode(p.stderr[:65536]).decode(),peer_finished=not thread.is_alive(),
                  input_base64=base64.b64encode(REQUEST).decode())
    if negative:
        checks={'peer_finished':not thread.is_alive(),'sni':record['sni']==server_name,'client_nonzero':p.returncode!=0,
                'no_stdout':p.stdout==b'','no_application_data':record['request_base64']==''}
    else:
        checks={'peer_finished':not thread.is_alive(),'sni':record['sni']==server_name,'client_zero':p.returncode==0,
                'tls_version':record['tls_version']==('TLSv1.2' if version==ssl.TLSVersion.TLSv1_2 else 'TLSv1.3'),
                'request':record['request_base64']==base64.b64encode(REQUEST).decode(),
                'response':p.stdout==RESPONSE,'event_order':record['events'][:4]==['accept','sni','handshake','request'] and 'response' in record['events']}
    record['checks']=checks
    (HOME/'tls-observation.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    if not all(checks.values()): raise AssertionError('TLS mismatch: '+repr(checks))
    print(scenario+': ok')


if len(sys.argv)!=4 or sys.argv[1] not in ('candidate','reference') or sys.argv[3] not in ('tls12','tls13','wrong-ca','wrong-sni'):
    raise SystemExit('invalid invocation')
side,shell,scenario=sys.argv[1:]
if side=='candidate' and shell!='/opt/bashos-parity/candidate': raise SystemExit('candidate path refused')
if side=='reference' and shell!='/opt/bash-5.3.15/bin/bash': raise SystemExit('reference path refused')
exercise(side,shell,scenario)
