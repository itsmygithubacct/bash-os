#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only RTSP/RTP fixture. Wire helpers adapted from tests/sol-rtspcat-loopback.py."""
import base64
import hashlib
import json
import os
import re
import shlex
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
import uuid

SPS, PPS = b'\x67\x42\x00\x1e\xab', b'\x68\xce\x06\xe2'
SC = b'\0\0\0\1'
DIAG = Path(os.environ.get('HOME', '.')) / 'rtsp-trace.json'
OBSERVER = '/opt/bashos-parity/harness/helpers/protocol-wire-rtsp-receipt-r6.py'
RECEIPT = Path(os.environ.get('HOME', '.')) / 'rtsp-receipt.json'
LIMIT = 32768
PEER_BYTE_BUDGET = 65536
TRACE_FILE_BUDGET = 600000
SIGCHECK = r'''sig_snapshot() { local line; while IFS= read -r line; do case "$line" in SigIgn:*|SigCgt:*) printf '%s\n' "$line";; esac; done </proc/$$/status; }
trap ':' PIPE; before=$(trap -p PIPE); sig_before=$(sig_snapshot);
printf 'trap=%s\n%s\n' "$before" "$sig_before" > "$HOME/rtsp-signal-before.txt"; '''
SIGAFTER = r'''trap_after=$(trap -p PIPE); sig_after=$(sig_snapshot);
printf 'trap=%s\n%s\n' "$trap_after" "$sig_after" > "$HOME/rtsp-signal-after.txt"; '''


def check(value, message):
    if not value: raise AssertionError(message)


def unit(*nals):
    body = b''.join(SC + n for n in nals)
    return struct.pack('!I', len(body)) + body


def packet(seq, ts, payload, marker=True, flags=0x80):
    return struct.pack('!BBHII', flags, 96 | (0x80 if marker else 0), seq, ts, 0x12345678) + payload


def wire(payload, channel=4):
    return b'$' + bytes([channel]) + struct.pack('!H', len(payload)) + payload


def stap(*nals):
    return b'\x78' + b''.join(struct.pack('!H', len(n)) + n for n in nals)


def send_media(conn, data, trigger, events):
    """Retain bytes accepted by each local socket send, including failures.

    Successful local sends do not themselves prove peer delivery or receipt.
    """
    if len(data)>LIMIT or sum(e.get('requested_length',0) for e in events)+len(data)>PEER_BYTE_BUDGET:
        raise ObservationError('peer send capture budget exceeded')
    event = {'trigger': trigger, 'requested_length': len(data), 'requested_hex': data.hex(),
             'started_monotonic': time.monotonic(), 'chunks': [], 'outcome': 'in-progress'}
    events.append(event)
    offset = 0
    try:
        while offset < len(data):
            check(len(event['chunks']) < 512, 'media send count exceeds capture limit')
            before = time.monotonic()
            sent = conn.send(data[offset:])
            check(isinstance(sent, int) and 0 < sent <= len(data) - offset, 'media send made no progress')
            chunk = data[offset:offset + sent]
            event['chunks'].append({'offset': offset, 'length': sent, 'bytes_hex': chunk.hex(),
                                    'started_monotonic': before, 'finished_monotonic': time.monotonic()})
            offset += sent
        event['outcome'] = 'complete'
    except Exception as exc:
        event['outcome'] = 'error'
        event['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        event['accepted_length'] = offset
        event['accepted_hex'] = data[:offset].hex()
        event['finished_monotonic'] = time.monotonic()



def auth_control(trace):
    basic='Basic '+base64.b64encode(b'user:pass').decode()
    check(basic=='Basic dXNlcjpwYXNz','Basic positive control')
    check(basic!='Basic '+base64.b64encode(b'user:wrong').decode(),'Basic negative control')
    md5=lambda text: hashlib.md5(text.encode()).hexdigest()
    ha1=md5('Mufasa:testrealm@host.com:Circle Of Life')
    ha2=md5('GET:/dir/index.html')
    value=md5(ha1+':dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:'+ha2)
    altered=md5(ha1+':dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:'+md5('POST:/dir/index.html'))
    trace['authentication_controls']={'basic':basic,'digest_ha1':ha1,'digest_ha2':ha2,
       'digest':value,'altered_method_digest':altered,'published_expected':'6629fae49393a05397450978507c4ef1'}
    check(ha1=='939e7578ed9e3c518a452acee763bce9' and ha2=='39aff3a2bab6126f332b942af96d3366', 'Digest intermediate controls')
    check(value=='6629fae49393a05397450978507c4ef1' and altered!=value,'Digest positive/negative control')


def listener_control(trace):
    server=socket.socket(); server.bind(('127.0.0.1',0)); server.listen(1);server.settimeout(2)
    record={'ready_ns':time.monotonic_ns(),'address':server.getsockname(),'events':[]};trace['listener_control']=record
    client=socket.socket(); client.settimeout(2)
    try:
        before=time.monotonic_ns();client.connect(server.getsockname())
        record['events'].append({'kind':'control-connect','started_ns':before,'finished_ns':time.monotonic_ns()})
        writes=[];send_media(client,b'listener-control','listener-control',writes);record['writes']=writes
        before=time.monotonic_ns();conn,peer=server.accept()
        with conn:
            conn.settimeout(2);data=b'';reads=[]
            while len(data)<len(b'listener-control'):
                chunk=conn.recv(32);reads.append({'bytes_hex':chunk.hex(),'time_ns':time.monotonic_ns()})
                if not chunk:break
                data+=chunk
            record['events'].append({'kind':'accept','started_ns':before,'finished_ns':time.monotonic_ns(),
                                     'peer':peer,'bytes_hex':data.hex(),'reads':reads})
        check(data==b'listener-control','positive listener control failed')
    finally: client.close();server.close()


class ObservationError(Exception): pass


def observer_argv(shell,script,ports):
    return [sys.executable,OBSERVER,'observe',str(RECEIPT),','.join(str(p) for p in ports),
            '--',shell,'--noprofile','--norc','-c',script]


def receipt_summary(servers,trace,scenario):
    if not RECEIPT.is_file(): raise ObservationError('owned-child receipt log missing')
    record=json.loads(RECEIPT.read_text());trace['receipt_file_status']={'complete':record.get('complete'),'error':record.get('error'),
         'child_pid':record.get('child_pid'),'terminal':record.get('terminal')}
    if not record.get('complete'): raise ObservationError('owned-child receipt observer incomplete: '+str(record.get('error')))
    summary=[]; issues=[]
    for server in servers:
        port=server.port
        conns=[x for x in record['connections'] if x['port']==port]
        received=b''.join(bytes.fromhex(e.get('bytes_hex','')) for e in record['events']
                          if e.get('kind') in ('read','recvfrom') and any(c['id']==e.get('connection_id') for c in conns))
        sent=b''.join(bytes.fromhex(e.get('accepted_hex','')) for e in server.wire_sends)
        row={'port':port,'connections':conns,'peer_accepted_hex':sent.hex(),'candidate_read_hex':received.hex(),
             'peer_accepted_length':len(sent),'candidate_read_length':len(received),
             'received_matches_sent_prefix':sent.startswith(received),
             'unread_peer_accepted_length':max(0,len(sent)-len(received)),'send_segments':[]}
        summary.append(row);trace['receipt_correlations']=summary
        if any(e.get('kind')=='accept' for e in server.lifecycle) and not conns:
            issues.append('accepted connection absent from observer')
        if not row['received_matches_sent_prefix']:issues.append('peer/candidate byte streams differ')
        offset=0
        for event in server.wire_sends:
            accepted=event.get('accepted_length',0);requested=event.get('requested_length',0)
            seen=max(0,min(accepted,len(received)-offset))
            needed=requested
            if scenario=='sps-repeat' and event['trigger']=='PLAY':
                # The third packet is intentionally outside -n 2; require the first two.
                blob=bytes.fromhex(event['requested_hex']);pos=0
                for _ in range(2):
                    if pos+4>len(blob) or blob[pos]!=36:raise ObservationError('invalid control packet framing')
                    pos+=4+int.from_bytes(blob[pos+2:pos+4],'big')
                needed=pos
            segment={'trigger':event['trigger'],'stream_offset':offset,'requested':requested,'accepted':accepted,
                     'candidate_read':seen,'required_for_assertion':needed,'outcome':event.get('outcome')}
            row['send_segments'].append(segment);offset+=accepted
            if event.get('outcome')!='complete' or accepted<needed:
                issues.append('peer source send incomplete: '+event['trigger'])
            elif seen<needed:
                issues.append('candidate receipt not observed for required input: '+event['trigger'])
    if issues:
        trace['receipt_incomplete_reasons']=issues
        raise ObservationError('; '.join(issues))


def control():
    sample = unit(SPS, PPS, b'\x65test')
    trace = {'scenario': 'control', 'sample_hex': sample.hex()}
    auth_control(trace); listener_control(trace)
    check(struct.unpack('!I', sample[:4])[0] == len(sample) - 4 and sample[4:] == SC + SPS + SC + PPS + SC + b'\x65test', 'framing positive control')
    changed = bytearray(sample); changed[-1] ^= 1
    trace['changed_hex'] = bytes(changed).hex()
    check(bytes(changed) != sample and bytes(changed)[4:] != sample[4:], 'framing negative control')
    p = packet(7, 9, b'\x61sample')
    wrapped = wire(p)
    trace['rtp_hex'] = p.hex(); trace['interleaved_hex'] = wrapped.hex()
    check(wrapped[:4] == b'$\x04' + struct.pack('!H', len(p)) and wrapped[4:] == p, 'interleaved control')
    class ShortSink:
        def __init__(self, fail=False): self.writes = []; self.fail = fail
        def send(self, value):
            if self.fail and self.writes: raise BrokenPipeError('synthetic short-send failure')
            piece = bytes(value[:3]); self.writes.append(piece); return len(piece)
    sink = ShortSink(); events = []
    send_media(sink, wrapped, 'control', events)
    check(b''.join(sink.writes) == wrapped and bytes.fromhex(events[0]['accepted_hex']) == wrapped,
          'short-send capture lost media bytes')
    check(len(events[0]['chunks']) > 1 and events[0]['outcome'] == 'complete',
          'short-send boundaries were not retained')
    failed = ShortSink(fail=True); failed_events = []
    try: send_media(failed, wrapped, 'failure-control', failed_events)
    except BrokenPipeError: pass
    else: raise AssertionError('send failure control did not fail')
    check(failed_events[0]['outcome'] == 'error' and
          failed_events[0]['accepted_hex'] == wrapped[:3].hex() and
          failed_events[0]['accepted_length'] == 3,
          'partial-send failure control lost accepted bytes')
    trace['media_send_control'] = events; trace['media_failure_control'] = failed_events
    encoded=(json.dumps(trace,indent=2)+'\n').encode()
    if len(encoded)>200000:raise ObservationError('oracle control budget exceeded')
    DIAG.write_bytes(encoded)
    print('rtsp-control=ok')


class Server:
    def __init__(self, data=b'', auth=None, keepalive=False, error=None, hold=False, eof=False):
        self.data, self.auth, self.keepalive, self.error, self.hold, self.eof = data, auth, keepalive, error, hold, eof
        self.records, self.errors, self.media_sends = [], [], []
        self.wire_sends, self.raw_requests, self.lifecycle = [], [], []
        self.request_bytes = 0
        self.timing = {}
        self.sock = socket.socket(); self.sock.bind(('127.0.0.1', 0)); self.sock.listen(1); self.sock.settimeout(4)
        self.port = self.sock.getsockname()[1]
        self.lifecycle.append({'kind':'listen','port':self.port,'time_ns':time.monotonic_ns()})
        self.url = 'rtsp://127.0.0.1:%d/stream' % self.port
        self.client_url = self.url.replace('://', '://user:pass@') if auth else self.url
        self.thread = threading.Thread(target=self.serve, daemon=True); self.thread.start()

    def read_request(self, f):
        if len(self.raw_requests)>=128:raise ObservationError('request event budget exceeded')
        event={'started_ns':time.monotonic_ns(),'lines':[],'outcome':'in-progress'}
        self.raw_requests.append(event)
        try:
            line=f.readline(8193); event['lines'].append({'bytes_hex':line.hex(),'time_ns':time.monotonic_ns()})
            self.request_bytes+=len(line)
            if self.request_bytes>PEER_BYTE_BUDGET:raise ObservationError('request capture budget exceeded')
            if not line: event['outcome']='eof';return None
            check(len(line)<8193,'request line too long')
            parts=line.decode('ascii').rstrip('\r\n').split(' ')
            check(len(parts)==3 and parts[2]=='RTSP/1.0','invalid RTSP request line')
            headers={}
            for _ in range(100):
                line=f.readline(8193);event['lines'].append({'bytes_hex':line.hex(),'time_ns':time.monotonic_ns()})
                self.request_bytes+=len(line)
                if self.request_bytes>PEER_BYTE_BUDGET:raise ObservationError('request capture budget exceeded')
                check(bool(line) and len(line)<8193,'truncated request headers')
                if line==b'\r\n':break
                k,v=line.decode('ascii').split(':',1);headers[k.lower()]=v.strip()
            else: raise AssertionError('too many request headers')
            event['outcome']='complete'
            record={'method':parts[0],'uri':parts[1],'headers':headers,'received_monotonic':time.monotonic(),
                    'raw_hex':b''.join(bytes.fromhex(x['bytes_hex']) for x in event['lines']).hex()}
            self.records.append(record);return record
        except Exception as exc:
            event['outcome']='error';event['error']=type(exc).__name__+': '+str(exc);raise
        finally: event['finished_ns']=time.monotonic_ns()

    def reply(self, conn, req, extra='', body=b''):
        hdr=('RTSP/1.0 200 OK\r\nCSeq: '+req['headers']['cseq']+'\r\n'+extra+'Content-Length: %d\r\n\r\n'%len(body)).encode('ascii')
        send_media(conn,hdr+body,'response-'+req['method'],self.wire_sends)

    def authorize(self, req):
        a = req['headers'].get('authorization', '')
        if self.auth == 'basic':
            check(a == 'Basic ' + base64.b64encode(b'user:pass').decode(), 'Basic authorization mismatch')
        elif self.auth == 'digest':
            check(a.startswith('Digest '), 'Digest authorization missing')
            fields = {k: quoted or token for k, quoted, token in re.findall(r'(\w+)=(?:"([^"]*)"|([^, ]+))', a)}
            check(fields.get('username') == 'user' and fields.get('realm') == 'fixture' and fields.get('nonce') == 'fixed-nonce' and fields.get('uri') == req['uri'], 'Digest identity/URI mismatch')
            check(fields.get('qop') == 'auth' and re.fullmatch(r'[0-9a-fA-F]{8}', fields.get('nc', '')) is not None and fields.get('cnonce'), 'Digest qop fields missing')
            md5 = lambda text: hashlib.md5(text.encode()).hexdigest()
            ha1 = md5('user:fixture:pass'); ha2 = md5(req['method'] + ':' + req['uri'])
            expected = md5(ha1 + ':fixed-nonce:' + fields['nc'] + ':' + fields['cnonce'] + ':auth:' + ha2)
            check(fields.get('response') == expected, 'Digest response hash mismatch')
        else: check(not a, 'unexpected Authorization')

    def serve(self):
        try:
            started=time.monotonic_ns();conn, peer = self.sock.accept()
            self.lifecycle.append({'kind':'accept','started_ns':started,'finished_ns':time.monotonic_ns(),'peer':peer,'local':conn.getsockname()})
            with conn:
                conn.settimeout(5)
                f = conn.makefile('rb'); challenged = False; cseq = 0
                while True:
                    req = self.read_request(f)
                    if req is None: break
                    method, uri, h = req['method'], req['uri'], req['headers']
                    cseq += 1; check(h.get('cseq') == str(cseq), 'CSeq did not increase by one')
                    expected_uri = self.url + '/trackID=1' if method == 'SETUP' else self.url
                    check(uri == expected_uri, 'unexpected URI for ' + method)
                    if self.error and len(self.records) == 1:
                        bad = {'bad-status': b'NOT-RTSP 200 OK\r\nContent-Length: 0\r\n\r\n',
                               'bad-header': b'RTSP/1.0 200 OK\r\nMalformed header\r\nContent-Length: 0\r\n\r\n',
                               'bad-length': b'RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n'}[self.error]
                        send_media(conn,bad,'malformed-'+self.error,self.wire_sends)
                        # Any subsequent request means the malformed response was accepted.
                        try: self.read_request(f)
                        except (ConnectionResetError, socket.timeout): pass
                        break
                    if self.auth and not challenged:
                        challenge = ('Basic realm="fixture"' if self.auth == 'basic' else
                                     'Digest realm="fixture", nonce="fixed-nonce", qop="auth", algorithm="MD5"')
                        send_media(conn,('RTSP/1.0 401 Unauthorized\r\nCSeq: '+h['cseq']+'\r\nWWW-Authenticate: '+challenge+'\r\nContent-Length: 0\r\n\r\n').encode(),'challenge-'+self.auth,self.wire_sends)
                        challenged = True; continue
                    self.authorize(req)
                    if method in ('PLAY', 'GET_PARAMETER', 'TEARDOWN'):
                        check(h.get('session') == 'fixture-session', 'missing session')
                    if method == 'OPTIONS': self.reply(conn, req)
                    elif method == 'DESCRIBE':
                        check(h.get('accept') == 'application/sdp', 'missing SDP accept')
                        sdp = ('v=0\r\nm=audio 0 RTP/AVP 0\r\na=control:audio\r\n'
                               'm=video 0 RTP/AVP 97 96\r\na=control:trackID=1\r\n'
                               'a=rtpmap:97 JPEG/90000\r\na=rtpmap:96 H264/90000\r\n'
                               'a=fmtp:96 packetization-mode=1;sprop-parameter-sets=' + base64.b64encode(SPS).decode() + ',' + base64.b64encode(PPS).decode() + '\r\n').encode()
                        self.reply(conn, req, 'Content-Base: ' + self.url + '/\r\n', sdp)
                    elif method == 'SETUP':
                        check(uri == self.url + '/trackID=1' and h.get('transport') == 'RTP/AVP/TCP;unicast;interleaved=0-1', 'track URI or requested transport mismatch')
                        self.reply(conn, req, 'Session: fixture-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n')
                    elif method == 'PLAY':
                        self.reply(conn, req)
                        self.timing['play_reply_sent_monotonic'] = time.monotonic()
                        if not (self.keepalive or self.hold):
                            send_media(conn, self.data, 'PLAY', self.wire_sends)
                            self.media_sends.append(self.wire_sends[-1])
                            if self.eof:
                                event={'kind':'shutdown-write','started_ns':time.monotonic_ns()};self.lifecycle.append(event)
                                try: conn.shutdown(socket.SHUT_WR);event['outcome']='ok'
                                except OSError as exc: event['outcome']=type(exc).__name__+': '+str(exc);raise
                                finally: event['finished_ns']=time.monotonic_ns()
                    elif method == 'GET_PARAMETER':
                        received=req['received_monotonic']
                        previous=self.timing.get('last_keepalive_start',self.timing.get('play_reply_sent_monotonic'))
                        delta=received-previous if previous is not None else None
                        self.timing.setdefault('keepalive_intervals_seconds',[]).append(delta)
                        self.timing.setdefault('keepalive_received_monotonic',[]).append(received)
                        self.timing['last_keepalive_start']=received
                        check(delta is not None and .70<=delta<=2.25,'keepalive outside the one-second interval bound')
                        self.reply(conn,req)
                        if len(self.timing['keepalive_intervals_seconds'])>=3:
                            send_media(conn,self.data,'GET_PARAMETER-3',self.wire_sends);self.media_sends.append(self.wire_sends[-1])
                    elif method == 'TEARDOWN': break
                    else: raise AssertionError('unexpected method ' + method)
                f.close()
        except (ConnectionResetError, BrokenPipeError) as exc:
            self.lifecycle.append({'kind':'peer-close-error','error':type(exc).__name__+': '+str(exc),'time_ns':time.monotonic_ns()})
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ': ' + str(exc))
        finally:
            self.lifecycle.append({'kind':'listener-close','time_ns':time.monotonic_ns()})
            self.sock.close()

    def finish(self):
        self.thread.join(9)
        check(not self.thread.is_alive(), 'RTSP peer did not stop')
        check(not self.errors, 'RTSP peer error: ' + repr(self.errors))


def data_for(scenario):
    a, b, c = b'\x61one', b'\x61two', b'\x65idr'
    if scenario in ('happy', 'basic', 'digest', 'keepalive', 'output-fd', 'output-full', 'output-closed', 'output-pipe', 'repeat'):
        return wire(packet(1, 1, c)), unit(SPS, PPS, c), 1
    if scenario == 'single': return wire(packet(1, 1, a)), unit(a), 1
    if scenario == 'stap': return wire(packet(1, 1, stap(a, b))), unit(a, b), 1
    if scenario == 'fu':
        return wire(packet(1, 1, b'\x7c\x85abc', False)) + wire(packet(2, 1, b'\x7c\x45def')), unit(SPS, PPS, b'\x65abcdef'), 1
    if scenario == 'marker-timestamp':
        return wire(packet(1, 1, a)) + wire(packet(2, 2, b, False)) + wire(packet(3, 3, b'\x61three')), unit(a) + unit(b), 2
    if scenario == 'sps-repeat':
        return wire(packet(1, 1, c)) + wire(packet(2, 2, b'\x65more')) + wire(packet(3, 3, b'\x61extra')), unit(SPS, PPS, c) + unit(SPS, PPS, b'\x65more'), 2
    if scenario == 'eof-partial': return wire(packet(1, 1, b'\x61unfinished', False)), b'', 0
    bad = {
        'rtp-version': packet(1, 1, b'\x61bad', flags=0x40),
        'rtp-extension': packet(1, 1, b'\x00\x00\xff\xff', flags=0x90),
        'rtp-padding': packet(1, 1, b'\x61bad\xff', flags=0xa0),
        'rtp-stap': packet(1, 1, b'\x78\x00\x10short'),
        'rtp-fu': packet(1, 1, b'\x7c\x45without-start'),
    }
    if scenario in bad:
        return wire(bad[scenario]) + wire(packet(2, 2, b'\x61recovered')), unit(b'\x61recovered'), 0
    return b'', b'', 0


def invoke(shell, server, scenario, data_expected, count):
    args = '-n %d -k 0 -t 2' % count if count else '-k 0 -t 2'
    if scenario == 'keepalive': args = '-n 1 -k 1 -t 6'
    url = shlex.quote(server.client_url)
    base = 'rtspcat ' + url + ' ' + args
    pass_fds = ()
    pipe_write = None
    if scenario == 'output-fd': script = base + ' -o 3 3>output.bin'
    elif scenario == 'output-full': script = base + ' -o 3 3>/dev/full'
    elif scenario == 'output-closed': script = base + ' -o 99'
    elif scenario == 'output-pipe':
        readfd, pipe_write = os.pipe(); os.close(readfd); pass_fds = (pipe_write,)
        script = SIGCHECK + base + ' -o %d; r=$?; printf \"%%s\\n\" \"$r\" > \"$HOME/rtsp-builtin-status.txt\"; ' % pipe_write + SIGAFTER + '[[ $r == 1 && $trap_after == "$before" && $sig_after == "$sig_before" ]] || exit 90; printf "shell-alive\\n"'
    else: script = base
    start = time.monotonic()
    try:
        proc = subprocess.run(observer_argv(shell,script,[server.port]), capture_output=True, timeout=28, pass_fds=pass_fds)
    finally:
        if pipe_write is not None: os.close(pipe_write)
    elapsed = time.monotonic() - start
    return proc, elapsed


def invalid(shell, scenario, trace):
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(.1)
    port=listener.getsockname()[1]
    record={'port':port,'ready_ns':time.monotonic_ns(),'events':[]};trace['listener']=record
    stop=threading.Event();armed=threading.Event()
    def observe():
        while True:
            event={'kind':'accept','started_ns':time.monotonic_ns()}
            armed.set()
            try:
                conn,peer=listener.accept();event['outcome']='accepted';event['peer']=peer;conn.close()
            except socket.timeout:event['outcome']='timeout'
            except OSError as exc:
                event['outcome']='error';event['error']=type(exc).__name__+': '+str(exc)
            finally:
                event['finished_ns']=time.monotonic_ns();record['events'].append(event)
            if event['outcome']=='error' or stop.is_set():break
    thread=threading.Thread(target=observe,daemon=True);thread.start()
    option={'invalid-n':'-n nope','invalid-o':'-o nope','invalid-k':'-k nope','invalid-t':'-t nope','invalid-url':''}[scenario]
    url='rtsp://127.0.0.1:%d/stream'%port
    if scenario=='invalid-url':url='rtsp://127.0.0.1:%dx/stream'%port
    proc=None
    try:
        if not armed.wait(2):raise ObservationError('listener observer did not start')
        record['candidate_started_ns']=time.monotonic_ns()
        proc=subprocess.run([shell,'--noprofile','--norc','-c','rtspcat '+shlex.quote(url)+' '+option],capture_output=True,timeout=5)
        record['candidate_finished_ns']=time.monotonic_ns()
    finally:
        stop.set();thread.join(2);listener.close()
    if thread.is_alive() or any(e['outcome']=='error' for e in record['events']):raise ObservationError('listener observation failed')
    if not record['events']:raise ObservationError('no timed accept or timeout event')
    connected=any(e['outcome']=='accepted' for e in record['events'])
    trace['result']={'status':proc.returncode,'stdout_hex':proc.stdout[:LIMIT].hex(),'stderr':proc.stderr[:LIMIT].decode('utf8','replace'),
                     'stderr_hex':proc.stderr[:LIMIT].hex(),'stdout_length':len(proc.stdout),'stderr_length':len(proc.stderr),
                     'stdout_truncated':len(proc.stdout)>LIMIT,'stderr_truncated':len(proc.stderr)>LIMIT,'connected':connected}
    check(proc.returncode==2 and bool(proc.stderr) and not connected and not proc.stdout,'invalid argument did not fail with usage status before connecting')


def repeated(shell, trace):
    data, expected, _ = data_for('repeat')
    servers = [Server(data), Server(data)]
    script = SIGCHECK
    for server in servers:
        script += 'rtspcat ' + shlex.quote(server.client_url) + ' -n 1 -k 0 -t 2 -o 3 3>>output.bin || exit 91; '
    script += SIGAFTER + '[[ $trap_after == "$before" && $sig_after == "$sig_before" ]] || exit 92; printf "shell-alive\\n"'
    proc=None
    try:
        proc=subprocess.run(observer_argv(shell,script,[x.port for x in servers]),capture_output=True,timeout=28)
    finally:
        for server in servers:server.thread.join(9)
        trace['requests']=[x.records for x in servers];trace['peer_errors']=[x.errors for x in servers]
        trace['timing']=[x.timing for x in servers];trace['media_sends']=[x.media_sends for x in servers]
        trace['wire_sends']=[x.wire_sends for x in servers];trace['raw_requests']=[x.raw_requests for x in servers]
        trace['lifecycle']=[x.lifecycle for x in servers]
        if proc is not None:trace['candidate_raw']={'status':proc.returncode,'stdout_hex':proc.stdout[:LIMIT].hex(),'stderr_hex':proc.stderr[:LIMIT].hex(), 'stdout_length':len(proc.stdout),'stderr_length':len(proc.stderr),'stdout_truncated':len(proc.stdout)>LIMIT,'stderr_truncated':len(proc.stderr)>LIMIT}
    receipt_summary(servers,trace,'repeat')
    for server in servers:server.finish()
    trace['result'] = {'status': proc.returncode, 'stdout_hex': proc.stdout[:LIMIT].hex(), 'stderr': proc.stderr[:LIMIT].decode('utf8', 'replace')}
    if Path('output.bin').is_file():
        output=Path('output.bin').read_bytes();trace['fd_hex']=output[:LIMIT].hex();trace['fd_length']=len(output);trace['fd_truncated']=len(output)>LIMIT
    else:trace['fd_hex']=None
    check(proc.returncode == 0 and proc.stdout == b'shell-alive\n' and Path('output.bin').read_bytes() == expected * 2, 'repeated calls or shell SIGPIPE restoration failed')
    for s in servers: check([r['method'] for r in s.records] == ['OPTIONS', 'DESCRIBE', 'SETUP', 'PLAY', 'TEARDOWN'], 'repeated-session sequence mismatch')


def main(shell, scenario):
    trace = {'scenario': scenario}
    try:
        if scenario.startswith('invalid-'): invalid(shell, scenario, trace)
        elif scenario == 'repeat': repeated(shell, trace)
        else:
            data, expected, count = data_for(scenario)
            error = scenario if scenario in ('bad-status', 'bad-header', 'bad-length') else None
            server = Server(data, auth=scenario if scenario in ('basic', 'digest') else None,
                            keepalive=scenario == 'keepalive', error=error, hold=scenario == 'timeout',
                            eof=scenario == 'eof-partial' or scenario.startswith('rtp-'))
            proc=None; elapsed=None
            try: proc,elapsed=invoke(shell,server,scenario,expected,count)
            finally:
                server.thread.join(9)
                trace['requests']=server.records;trace['peer_errors']=server.errors;trace['timing']=server.timing
                trace['media_sends']=server.media_sends;trace['wire_sends']=server.wire_sends
                trace['raw_requests']=server.raw_requests;trace['lifecycle']=server.lifecycle
                if proc is not None:
                    trace['result']={'status':proc.returncode,'stdout_hex':proc.stdout[:LIMIT].hex(),
                                     'stderr':proc.stderr[:LIMIT].decode('utf8','replace'),
                                     'stderr_hex':proc.stderr[:LIMIT].hex(),'stdout_length':len(proc.stdout),'stderr_length':len(proc.stderr),
                                     'stdout_truncated':len(proc.stdout)>LIMIT,'stderr_truncated':len(proc.stderr)>LIMIT,
                                     'elapsed':elapsed,'expected_hex':expected.hex()}
            receipt_summary([server],trace,scenario)
            server.finish()
            methods = [r['method'] for r in server.records]
            if error:
                check(proc.returncode != 0 and not proc.stdout and len(methods) == 1, 'malformed response was accepted or advanced to a later request')
            elif scenario == 'timeout':
                check(proc.returncode != 0 and not proc.stdout and 1.5 <= elapsed < 6 and b'timeout' in proc.stderr.lower(), 'stalled stream was not bounded')
            elif scenario == 'eof-partial' or scenario.startswith('rtp-'):
                check(proc.returncode != 0 and proc.stdout == expected, 'malformed/incomplete RTP emitted wrong bytes or failed to signal EOF')
            elif scenario in ('output-full', 'output-closed'):
                check(proc.returncode != 0 and not proc.stdout and bool(proc.stderr), 'write failure not reported')
            elif scenario == 'output-fd':
                content = Path('output.bin').read_bytes(); trace['fd_hex'] = content[:LIMIT].hex();trace['fd_length']=len(content);trace['fd_truncated']=len(content)>LIMIT
                check(proc.returncode == 0 and not proc.stdout and content == expected, 'explicit output fd or stdout mismatch')
            elif scenario == 'output-pipe':
                pipe_status=Path(os.environ['HOME'])/'rtsp-builtin-status.txt'
                trace['builtin_status_text']=pipe_status.read_text() if pipe_status.is_file() else None
                check(trace['builtin_status_text']=='1\n' and proc.returncode==0 and proc.stdout==b'shell-alive\n', 'builtin pipe status, shell survival or SIGPIPE restoration mismatch')
            else:
                check(proc.returncode == 0 and proc.stdout == expected, 'framed output or exit status mismatch')
            if not error:
                wanted = ['OPTIONS', 'DESCRIBE', 'SETUP', 'PLAY'] + (['GET_PARAMETER'] * 3 if scenario == 'keepalive' else []) + ['TEARDOWN']
                if scenario in ('basic', 'digest'): wanted.insert(0, 'OPTIONS')
                check(methods == wanted, 'handshake/session/teardown request sequence mismatch')
        print('rtsp-' + scenario + '=ok')
    except Exception as exc:
        trace['classification'] = 'INVALID_OBSERVATION' if isinstance(exc,(ObservationError,subprocess.TimeoutExpired)) or any(x in repr(trace.get('peer_errors',[])) for x in ('ObservationError','TimeoutError','OSError')) else 'REVIEW_REACHED_ASSERTION_AND_CONTROLS'
        trace['error'] = type(exc).__name__ + ': ' + str(exc)
        print('rtsp fixture failed: ' + trace['error'], file=sys.stderr)
        raise SystemExit(1)
    finally:
        capture_incomplete=False
        for name in ('rtsp-signal-before.txt', 'rtsp-signal-after.txt', 'rtsp-builtin-status.txt'):
            path = Path(os.environ.get('HOME', '.')) / name
            if path.is_file():
                data=path.read_bytes()
                trace[name]={'bytes_hex':data[:LIMIT].hex(),'length':len(data),'truncated':len(data)>LIMIT}
                if len(data)>LIMIT:
                    capture_incomplete=True;trace['classification']='INVALID_OBSERVATION';trace['error']='signal or status capture exceeds bound'
        encoded=(json.dumps(trace,indent=2)+'\n').encode()
        if len(encoded)>TRACE_FILE_BUDGET:
            DIAG.write_text(json.dumps({'scenario':scenario,'classification':'INVALID_OBSERVATION',
                'error':'trace exceeds capture budget','required_bytes':len(encoded)})+'\n')
            raise SystemExit(125)
        DIAG.write_bytes(encoded)
        if capture_incomplete:raise SystemExit(125)


def require_guest():
    try:
        marker_path=Path('/etc/bashos-parity-vm');meta=marker_path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode & 0o022:raise ValueError('marker ownership/mode')
        marker=marker_path.read_text().strip()
        if str(uuid.UUID(marker))!=marker:raise ValueError('noncanonical UUID')
        args=Path('/proc/1/cmdline').read_bytes().split(b'\0')
        uidline=next(line for line in Path('/proc/1/status').read_text().splitlines() if line.startswith('Uid:')).split()
        if uidline[1:3]!=['0','0'] or b'/opt/bashos-parity/harness/guest.py' not in args:raise ValueError('PID 1 is not the root evaluator')
        pos=args.index(b'--vm-token')
        if args[pos+1].decode()!=marker:raise ValueError('PID 1 token does not match marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000:raise ValueError('unexpected uid')
        if Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home':raise ValueError('scratch mismatch')
        for path in (Path('/tmp/parity-case'),Path('/tmp/parity-home')):
            meta=path.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=2000:raise ValueError('scratch ownership mismatch')
    except (OSError,ValueError,StopIteration,IndexError) as exc:
        raise SystemExit('disposable-VM RTSP helper guard: '+str(exc))


if __name__ == '__main__':
    require_guest()
    if len(sys.argv) == 2 and sys.argv[1] == 'control': control()
    elif len(sys.argv) == 3: main(sys.argv[1], sys.argv[2])
    else: raise SystemExit('usage: helper control | helper SHELL SCENARIO')
