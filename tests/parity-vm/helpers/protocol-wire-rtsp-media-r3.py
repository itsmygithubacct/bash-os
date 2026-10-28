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
LIMIT = 32768
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
    check(len(data) <= LIMIT, 'media exceeds capture limit')
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


def control():
    sample = unit(SPS, PPS, b'\x65test')
    trace = {'scenario': 'control', 'sample_hex': sample.hex()}
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
    DIAG.write_text(json.dumps(trace, indent=2) + '\n')
    print('rtsp-control=ok')


class Server:
    def __init__(self, data=b'', auth=None, keepalive=False, error=None, hold=False, eof=False):
        self.data, self.auth, self.keepalive, self.error, self.hold, self.eof = data, auth, keepalive, error, hold, eof
        self.records, self.errors, self.media_sends = [], [], []
        self.timing = {}
        self.sock = socket.socket(); self.sock.bind(('127.0.0.1', 0)); self.sock.listen(1); self.sock.settimeout(4)
        self.url = 'rtsp://127.0.0.1:%d/stream' % self.sock.getsockname()[1]
        self.client_url = self.url.replace('://', '://user:pass@') if auth else self.url
        self.thread = threading.Thread(target=self.serve, daemon=True); self.thread.start()

    def read_request(self, f):
        line = f.readline(8193)
        if not line: return None
        check(len(line) < 8193, 'request line too long')
        parts = line.decode('ascii').rstrip('\r\n').split(' ')
        check(len(parts) == 3 and parts[2] == 'RTSP/1.0', 'invalid RTSP request line')
        headers = {}
        for _ in range(100):
            line = f.readline(8193)
            check(bool(line) and len(line) < 8193, 'truncated request headers')
            if line == b'\r\n': break
            k, v = line.decode('ascii').split(':', 1); headers[k.lower()] = v.strip()
        else: raise AssertionError('too many request headers')
        record = {'method': parts[0], 'uri': parts[1], 'headers': headers,
                  'received_monotonic': time.monotonic()}
        self.records.append(record)
        return record

    def reply(self, conn, req, extra='', body=b''):
        hdr = ('RTSP/1.0 200 OK\r\nCSeq: ' + req['headers']['cseq'] + '\r\n' + extra + 'Content-Length: %d\r\n\r\n' % len(body)).encode('ascii')
        conn.sendall(hdr + body)

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
            conn, _ = self.sock.accept()
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
                        conn.sendall(bad)
                        # Any subsequent request means the malformed response was accepted.
                        try: self.read_request(f)
                        except (ConnectionResetError, socket.timeout): pass
                        break
                    if self.auth and not challenged:
                        challenge = ('Basic realm="fixture"' if self.auth == 'basic' else
                                     'Digest realm="fixture", nonce="fixed-nonce", qop="auth", algorithm="MD5"')
                        conn.sendall(('RTSP/1.0 401 Unauthorized\r\nCSeq: ' + h['cseq'] + '\r\nWWW-Authenticate: ' + challenge + '\r\nContent-Length: 0\r\n\r\n').encode())
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
                            send_media(conn, self.data, 'PLAY', self.media_sends)
                            if self.eof: conn.shutdown(socket.SHUT_WR)
                    elif method == 'GET_PARAMETER':
                        received = req['received_monotonic']
                        started = self.timing.get('play_reply_sent_monotonic')
                        self.timing['keepalive_received_monotonic'] = received
                        if started is not None:
                            self.timing['keepalive_elapsed_seconds'] = received - started
                        check(started is not None and .70 <= received - started <= 2.25,
                              'keepalive outside the one-second interval bound')
                        self.reply(conn, req); send_media(conn, self.data, 'GET_PARAMETER', self.media_sends)
                    elif method == 'TEARDOWN': break
                    else: raise AssertionError('unexpected method ' + method)
                f.close()
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ': ' + str(exc))
        finally: self.sock.close()

    def finish(self):
        self.thread.join(7)
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
    if scenario == 'keepalive': args = '-n 1 -k 1 -t 3'
    url = shlex.quote(server.client_url)
    base = 'rtspcat ' + url + ' ' + args
    pass_fds = ()
    pipe_write = None
    if scenario == 'output-fd': script = base + ' -o 3 3>output.bin'
    elif scenario == 'output-full': script = base + ' -o 3 3>/dev/full'
    elif scenario == 'output-closed': script = base + ' -o 99'
    elif scenario == 'output-pipe':
        readfd, pipe_write = os.pipe(); os.close(readfd); pass_fds = (pipe_write,)
        script = SIGCHECK + base + ' -o %d; r=$?; ' % pipe_write + SIGAFTER + '[[ $r == 1 && $trap_after == "$before" && $sig_after == "$sig_before" ]] || exit 90; printf "shell-alive\\n"'
    else: script = base
    start = time.monotonic()
    try:
        proc = subprocess.run([shell, '--noprofile', '--norc', '-c', script], capture_output=True, timeout=8, pass_fds=pass_fds)
    finally:
        if pipe_write is not None: os.close(pipe_write)
    elapsed = time.monotonic() - start
    return proc, elapsed


def invalid(shell, scenario, trace):
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(.35)
    port = listener.getsockname()[1]
    option = {'invalid-n': '-n nope', 'invalid-o': '-o nope', 'invalid-k': '-k nope', 'invalid-t': '-t nope', 'invalid-url': ''}[scenario]
    url = 'rtsp://127.0.0.1:%d/stream' % port
    if scenario == 'invalid-url': url = 'rtsp://127.0.0.1:%dx/stream' % port
    proc = subprocess.run([shell, '--noprofile', '--norc', '-c', 'rtspcat ' + shlex.quote(url) + ' ' + option], capture_output=True, timeout=3)
    connected = False
    try:
        conn, _ = listener.accept(); connected = True; conn.close()
    except socket.timeout: pass
    finally: listener.close()
    trace['result'] = {'status': proc.returncode, 'stdout_hex': proc.stdout[:LIMIT].hex(), 'stderr': proc.stderr[:LIMIT].decode('utf8', 'replace'), 'connected': connected}
    check(proc.returncode == 2 and bool(proc.stderr) and not connected and not proc.stdout, 'invalid argument did not fail with usage status before connecting')


def repeated(shell, trace):
    data, expected, _ = data_for('repeat')
    servers = [Server(data), Server(data)]
    script = SIGCHECK
    for server in servers:
        script += 'rtspcat ' + shlex.quote(server.client_url) + ' -n 1 -k 0 -t 2 -o 3 3>>output.bin || exit 91; '
    script += SIGAFTER + '[[ $trap_after == "$before" && $sig_after == "$sig_before" ]] || exit 92; printf "shell-alive\\n"'
    try: proc = subprocess.run([shell, '--noprofile', '--norc', '-c', script], capture_output=True, timeout=8)
    finally:
        try:
            for server in servers: server.finish()
        finally:
            trace['requests'] = [s.records for s in servers]; trace['peer_errors'] = [s.errors for s in servers]
            trace['timing'] = [s.timing for s in servers]
            trace['media_sends'] = [s.media_sends for s in servers]
    trace['result'] = {'status': proc.returncode, 'stdout_hex': proc.stdout[:LIMIT].hex(), 'stderr': proc.stderr[:LIMIT].decode('utf8', 'replace')}
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
            try: proc, elapsed = invoke(shell, server, scenario, expected, count)
            finally:
                try: server.finish()
                finally:
                    trace['requests'] = server.records; trace['peer_errors'] = server.errors
                    trace['timing'] = server.timing
                    trace['media_sends'] = server.media_sends
            trace['result'] = {'status': proc.returncode, 'stdout_hex': proc.stdout[:LIMIT].hex(), 'stderr': proc.stderr[:LIMIT].decode('utf8', 'replace'), 'elapsed': elapsed, 'expected_hex': expected.hex()}
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
                content = Path('output.bin').read_bytes(); trace['fd_hex'] = content[:LIMIT].hex()
                check(proc.returncode == 0 and not proc.stdout and content == expected, 'explicit output fd or stdout mismatch')
            elif scenario == 'output-pipe':
                check(proc.returncode == 0 and proc.stdout == b'shell-alive\n', 'broken pipe killed shell or SIGPIPE disposition was not restored')
            else:
                check(proc.returncode == 0 and proc.stdout == expected, 'framed output or exit status mismatch')
            if not error:
                wanted = ['OPTIONS', 'DESCRIBE', 'SETUP', 'PLAY'] + (['GET_PARAMETER'] if scenario == 'keepalive' else []) + ['TEARDOWN']
                if scenario in ('basic', 'digest'): wanted.insert(0, 'OPTIONS')
                check(methods == wanted, 'handshake/session/teardown request sequence mismatch')
        print('rtsp-' + scenario + '=ok')
    except Exception as exc:
        trace['error'] = type(exc).__name__ + ': ' + str(exc)
        print('rtsp fixture failed: ' + trace['error'], file=sys.stderr)
        raise SystemExit(1)
    finally:
        for name in ('rtsp-signal-before.txt', 'rtsp-signal-after.txt'):
            path = Path(os.environ.get('HOME', '.')) / name
            if path.is_file():
                trace[name] = path.read_bytes()[:LIMIT].decode('utf8', 'replace')
        DIAG.write_text(json.dumps(trace, indent=2) + '\n')


def require_guest():
    """Fail closed before helper behavior; the guest evaluator checks UUID equality."""
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        parsed = uuid.UUID(marker)
        if str(parsed) != marker.lower():
            raise ValueError('non-canonical VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
        if os.getuid() != 2000 or os.geteuid() != 2000:
            raise ValueError('unexpected guest uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('unexpected guest scratch directory')
    except (OSError, ValueError) as exc:
        raise SystemExit('disposable-VM guard refused helper: ' + str(exc))


if __name__ == '__main__':
    require_guest()
    if len(sys.argv) == 2 and sys.argv[1] == 'control': control()
    elif len(sys.argv) == 3: main(sys.argv[1], sys.argv[2])
    else: raise SystemExit('usage: helper control | helper SHELL SCENARIO')
