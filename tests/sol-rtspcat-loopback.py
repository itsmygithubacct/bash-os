#!/usr/bin/env python3
"""Deterministic RTSP/TCP fixture. Never contacts anything but owned loopback sockets.
No builds. Run with --binary out/bash-sol-rtspcat; --standalone for sanitizer.
The exported helpers also give bench/sol-rtspcat.py an independent byte oracle.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import tempfile
import threading

SPS, PPS = b'\x67\x42\x00\x1e\xab', b'\x68\xce\x06\xe2'
SC = b'\0\0\0\1'


def unit(*nals):
    data = b''.join(SC + n for n in nals)
    return struct.pack('!I', len(data)) + data


def rtp(seq, ts, payload, marker=True, flags=0x80, pt=96):
    return struct.pack('!BBHII', flags, pt | (128 if marker else 0), seq & 65535, ts, 0x12345678) + payload


def wire(packet, channel=0):
    return b'$' + bytes([channel]) + struct.pack('!H', len(packet)) + packet


def stap(*nals):
    return b'\x78' + b''.join(struct.pack('!H', len(n)) + n for n in nals)


def good_stream(count=3, channel=0):
    packets, expected = [], []
    seq = 65534
    for i in range(count):
        ts = 9000 + i * 3000
        nal = b'\x65' + struct.pack('!I', i) + b'fixture-payload' * 8
        if i % 3 == 0:
            packets.append(wire(rtp(seq, ts, nal), channel)); seq += 1
            expected.append(unit(SPS, PPS, nal))
        elif i % 3 == 1:
            packets.extend([wire(rtp(seq, ts, b'\x7c\x85' + nal[1:39], False), channel),
                            wire(rtp(seq+1, ts, b'\x7c\x05' + nal[39:82], False), channel),
                            wire(rtp(seq+2, ts, b'\x7c\x45' + nal[82:]), channel)])
            seq += 3
            expected.append(unit(SPS, PPS, nal))
        else:
            packets.append(wire(rtp(seq, ts, stap(SPS, PPS, nal)), channel)); seq += 1
            expected.append(unit(SPS, PPS, nal))
    return b''.join(packets), b''.join(expected)


class Server:
    def __init__(self, data=b'', auth=None, channel=0, eof=False, keepalive=False,
                 bad_length=None, sdp=None, silent=False, stream_reply=None, split=False, challenge=None, control=None):
        self.data, self.auth, self.channel, self.eof = data, auth, channel, eof
        self.challenge, self.control, self.nc = challenge, control, 0
        self.keepalive, self.bad_length, self.silent = keepalive, bad_length, silent
        self.stream_reply, self.split = stream_reply, split
        self.sdp = sdp
        self.methods, self.errors, self.challenges = [], [], 0
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0)); self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.url = f'rtsp://127.0.0.1:{self.port}/stream'
        self.client_url = self.url.replace('://', '://user:pass@') if auth else self.url
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def request(self, f):
        line = f.readline(10000)
        if not line:
            return None
        parts = line.decode().rstrip('\r\n').split(' ')
        assert len(parts) == 3 and parts[2] == 'RTSP/1.0', line
        headers = {}
        while True:
            line = f.readline(10000)
            assert line, 'truncated request'
            if line == b'\r\n':
                break
            k, v = line.decode().split(':', 1)
            headers[k.lower()] = v.strip()
        return parts[0], parts[1], headers

    def reply(self, conn, headers, code=200, extra='', body=b''):
        data = (f'RTSP/1.0 {code} Fixture\r\nCSeq: {headers["cseq"]}\r\n' + extra +
                f'Content-Length: {len(body)}\r\n\r\n').encode() + body
        if self.split:
            for i in range(0, len(data), 7):
                conn.sendall(data[i:i+7])
        else:
            conn.sendall(data)

    def authorized(self, method, uri, headers):
        a = headers.get('authorization', '')
        if self.auth == 'basic':
            assert a == 'Basic ' + base64.b64encode(b'user:pass').decode(), a
        elif self.auth in ('digest', 'qop'):
            assert a.startswith('Digest '), a
            fields = dict((k, v or u) for k, v, u in re.findall(r'(\w+)=(?:"([^"]*)"|([^, ]+))', a))
            assert fields['username'] == 'user' and fields['realm'] == 'fixture'
            assert fields['nonce'] == 'fixed-nonce' and fields['uri'] == uri
            md5 = lambda x: hashlib.md5(x.encode()).hexdigest()
            a1, a2 = md5('user:fixture:pass'), md5(f'{method}:{uri}')
            if self.auth == 'qop':
                assert fields['qop'] == 'auth' and int(fields['nc'], 16) == self.nc + 1
                self.nc += 1
                assert fields['opaque'] == 'fixture-opaque'
                expected = md5(f'{a1}:fixed-nonce:{fields["nc"]}:{fields["cnonce"]}:auth:{a2}')
            else:
                expected = md5(f'{a1}:fixed-nonce:{a2}')
            assert fields['response'] == expected, (fields, expected)
        else:
            assert not a, a

    def serve(self):
        try:
            self.sock.settimeout(10)
            conn, _ = self.sock.accept()
            with conn:
                conn.settimeout(8)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                f = conn.makefile('rb')
                cseq = 0
                while True:
                    req = self.request(f)
                    if req is None:
                        break
                    method, uri, h = req
                    assert 'user:' not in uri and uri in (self.url, self.control or self.url + '/trackID=1'), uri
                    assert int(h['cseq']) == cseq + 1, h
                    cseq += 1
                    if self.auth and not self.challenges:
                        scheme = 'Basic realm="fixture"' if self.auth == 'basic' else 'Digest realm="fixture", nonce="fixed-nonce"' + (', qop="auth-int, auth", algorithm="MD5", opaque="fixture-opaque"' if self.auth == 'qop' else '')
                        scheme = self.challenge or scheme
                        self.reply(conn, h, 401, f'WWW-Authenticate: {scheme}\r\n', b'challenge')
                        self.challenges += 1
                        continue
                    self.authorized(method, uri, h)
                    self.methods.append(method)
                    if method in ('PLAY', 'GET_PARAMETER', 'TEARDOWN'):
                        assert h.get('session') == 'fixture-session', h
                    if method == 'OPTIONS':
                        self.reply(conn, h)
                    elif method == 'DESCRIBE':
                        assert h.get('accept') == 'application/sdp'
                        if self.bad_length is not None:
                            conn.sendall(f'RTSP/1.0 200 Fixture\r\nCSeq: {cseq}\r\nContent-Length: {self.bad_length}\r\n\r\n'.encode())
                            conn.shutdown(socket.SHUT_WR)
                            break
                        sdp = self.sdp if self.sdp is not None else ('v=0\r\nm=audio 0 RTP/AVP 0\r\na=control:audio\r\n'
                              'm=video 0 RTP/AVP 97 96\r\na=control:trackID=1\r\na=rtpmap:97 JPEG/90000\r\na=rtpmap:96 H264/90000\r\n'
                              'a=fmtp:96 packetization-mode=1;sprop-parameter-sets=' + base64.b64encode(SPS).decode() + ',' + base64.b64encode(PPS).decode() + '\r\n'
                              'm=audio 0 RTP/AVP 8\r\na=control:audio2\r\n').encode()
                        self.reply(conn, h, extra=f'Content-Base: {self.url}/\r\n', body=sdp)
                    elif method == 'SETUP':
                        assert uri == (self.control or self.url + '/trackID=1'), uri
                        assert h['transport'] == 'RTP/AVP/TCP;unicast;interleaved=0-1'
                        self.reply(conn, h, extra=f'Session: fixture-session;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved={self.channel}-{self.channel+1}\r\n')
                    elif method == 'PLAY':
                        assert h.get('range') == 'npt=0.000-'
                        self.reply(conn, h)
                        if self.keepalive or self.silent:
                            continue
                        if self.stream_reply:
                            conn.sendall(self.stream_reply)
                        conn.sendall(self.data)
                        if self.eof:
                            conn.shutdown(socket.SHUT_WR)
                    elif method == 'GET_PARAMETER':
                        # RTP preceding the RTSP reply exercises the shared TCP parser.
                        conn.sendall(wire(b'ignored RTCP', self.channel + 1))
                        self.reply(conn, h, body=b'keepalive-body')
                        conn.sendall(self.data)
                    elif method == 'TEARDOWN':
                        break
                    else:
                        raise AssertionError(method)
                f.close()
        except (ConnectionResetError, BrokenPipeError):
            # A client which rejects malformed control input may close immediately.
            pass
        except Exception as exc:
            self.errors.append(repr(exc))
        finally:
            self.sock.close()

    def finish(self):
        self.thread.join(12)
        assert not self.thread.is_alive(), 'fixture thread did not finish'
        assert not self.errors, self.errors


def invoke(binary, server, args=(), standalone=False, shell_suffix='', stdout=None, timeout=12):
    command = [binary, server.client_url, *args] if standalone else [binary, '--noprofile', '--norc', '-c',
        'PATH=; rtspcat ' + shlex.quote(server.client_url) + ' ' + shlex.join(args) + shell_suffix]
    proc = subprocess.run(command, stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, 'PATH': ''}, timeout=timeout)
    server.finish()
    return proc


def run_suite(binary, standalone=False):
    cases = []
    def check(name, data, expected, args=('-n', '1'), status=0, teardown=True, **kw):
        client_timeout = kw.pop('client_timeout', 12)
        server = Server(data, **kw)
        p = invoke(binary, server, args, standalone, timeout=client_timeout)
        if kw.get('silent'):
            assert b'timeout' in p.stderr, p.stderr
        assert p.returncode == status, (name, p.returncode, p.stderr)
        assert p.stdout == expected, (name, len(p.stdout), len(expected), p.stdout[:100], expected[:100])
        if teardown:
            assert server.methods == ['OPTIONS', 'DESCRIBE', 'SETUP', 'PLAY'] + (['GET_PARAMETER'] if kw.get('keepalive') else []) + ['TEARDOWN'], server.methods
        cases.append(name)
        print('PASS', name, flush=True)

    data, expected = good_stream(3)
    for auth in (None, 'basic', 'digest', 'qop'):
        check('packetization/auth-' + str(auth), data, expected, ('-n', '3'), auth=auth, split=True)
    data, expected = good_stream(3, 4)
    check('negotiated-channel-and-rtcp', wire(b'rtcp', 5) + data, expected, ('-n', '3'), channel=4)
    data, expected = good_stream(3)
    check('n-exact-marker', data, expected[:len(unit(SPS, PPS, b'\x65' + struct.pack('!I', 0) + b'fixture-payload' * 8))])
    check('keepalive-idle-auth-body', *good_stream(1), ('-n', '1', '-k', '1', '-t', '3'), auth='qop', keepalive=True)
    check('stream-timeout', b'', b'', ('-t', '1'), status=1, silent=True, client_timeout=3)
    check('eof-complete', *good_stream(3), (), status=1, eof=True)
    check('n-zero-unlimited', *good_stream(3), ('-n', '0', '-k', '0'), status=1, eof=True)
    check('eof-incomplete-au', wire(rtp(1, 1, b'\x61unfinished', False)), b'', (), status=1, eof=True)
    check('eof-incomplete-fu', wire(rtp(1, 1, b'\x7c\x85start', False)), b'', (), status=1, eof=True)
    check('truncated-interleaved-header', b'$\0\0', b'', (), status=1, eof=True)
    check('truncated-interleaved-body', b'$\0\0\x20partial', b'', (), status=1, eof=True)
    check('timestamp-boundary-n', wire(rtp(1, 1, b'\x61one', False)) + wire(rtp(2, 2, b'\x61two')), unit(b'\x61one'))
    check('partial-sps-before-idr', wire(rtp(1, 1, stap(SPS, b'\x65idr'))), unit(SPS, PPS, b'\x65idr'))
    check('partial-pps-before-idr', wire(rtp(1, 1, stap(PPS, b'\x65idr'))), unit(PPS, SPS, b'\x65idr'))
    malformed = {
        'loss-fu': wire(rtp(1, 1, b'\x7c\x85abc', False)) + wire(rtp(3, 1, b'\x7c\x45def')),
        'reordered-fu': wire(rtp(1, 1, b'\x7c\x85abc', False)) + wire(rtp(3, 1, b'\x7c\x45ghi')) + wire(rtp(2, 1, b'\x7c\x05def', False)),
        'timestamp-abandons-fu': wire(rtp(1, 1, b'\x7c\x85abc', False)) + wire(rtp(2, 2, b'\x7c\x45ghi')),
        'stap-invalid-tail': wire(rtp(1, 1, stap(b'\x61good') + b'\0\x10short')),
        'stap-zero': wire(rtp(1, 1, b'\x78\0\0')),
        'stap-trailing-byte': wire(rtp(1, 1, stap(b'\x61good') + b'\0')),
        'stap-nested': wire(rtp(1, 1, stap(b'\x78bad'))),
        'truncated-rtp': wire(b'\x80\xe0\0'),
        'rtp-extension': wire(rtp(1, 1, b'\0\0\xff\xff', flags=0x90)),
        'rtp-csrc': wire(rtp(1, 1, b'a', flags=0x8f)),
        'padding-zero': wire(rtp(1, 1, b'\x61bad\0', flags=0xa0)),
        'padding-overflow': wire(rtp(1, 1, b'\x61bad\xff', flags=0xa0)),
        'fu-both-flags': wire(rtp(1, 1, b'\x7c\xc5bad')),
        'fu-marker-incomplete': wire(rtp(1, 1, b'\x7c\x85bad')),
        'fu-wrong-type': wire(rtp(1, 1, b'\x7c\x85abc', False)) + wire(rtp(2, 1, b'\x7c\x41def')),
        'unsupported-nal': wire(rtp(1, 1, b'\x79bad')),
    }
    for name, prefix in malformed.items():
        # Recovery uses a continuous next sequence to avoid concealing a false flush
        # through a second sequence gap at the timestamp boundary.
        last = 3 if name in ('loss-fu', 'reordered-fu') else 2 if name in ('timestamp-abandons-fu', 'fu-wrong-type') else 1
        rec = wire(rtp(last + 1, 3, b'\x61recovered'))
        check(name, prefix + rec, unit(b'\x61recovered'))
    check('duplicate-and-late', wire(rtp(1, 1, b'\x61one')) * 2 + wire(rtp(0, 0, b'\x61late')) + wire(rtp(2, 2, b'\x61two')), unit(b'\x61one') + unit(b'\x61two'), ('-n', '2'))
    check('duplicate-fu-fragment', wire(rtp(1, 1, b'\x7c\x85abc', False)) * 2 + wire(rtp(2, 1, b'\x7c\x45def')), unit(SPS, PPS, b'\x65abcdef'))
    check('rtp-extension-padding-valid', wire(rtp(1, 1, b'\x12\x34\0\x01abcd\x61ok\0\0\0\x04', flags=0xb0)), unit(b'\x61ok'))
    for length in ('-1', '65536', '999999999999999999999999', 'junk', '2oops', '0\r\nContent-Length: 0'):
        check('bad-content-length-' + repr(length), b'', b'', (), status=1, teardown=False, bad_length=length)
    check('oversize-stream-headers', b'', b'', (), status=1, stream_reply=b'RTSP/1.0 200 OK\r\nX: ' + b'x' * 9000 + b'\r\n\r\n')
    check('bad-keepalive-length', b'', b'', (), status=1, stream_reply=b'RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n')
    check('keepalive-failure', b'', b'', (), status=1, stream_reply=b'RTSP/1.0 401 Denied\r\n\r\n')
    # Bounded growth: neither a missing marker nor endless FU may grow unbounded.
    for fu in (False, True):
        payload = b'x' * 60000
        packets = []
        for i in range(145):
            pl = (b'\x7c' + (b'\x85' if i == 0 else b'\x05') if fu else b'\x61') + payload
            packets.append(wire(rtp(i, 1, pl, False)))
        check('bounded-' + ('fu' if fu else 'au'), b''.join(packets), b'', (), status=1)
    for ci, challenge in enumerate(('Digest realm="fixture", nonce="fixed-nonce", algorithm=SHA-256',
                      'Digest realm="fixture", nonce="fixed-nonce", qop="auth-int"',
                      'Digest realm="' + 'x' * 128 + '", nonce="fixed-nonce"',
                      'Digest realm="fixture", nonce="unterminated')):
        check('reject-unsupported-digest-' + str(ci), b'', b'', (), status=1, teardown=False, auth='digest', challenge=challenge)
    # A long absolute track URL caused the former authenticated request copy
    # to exceed its 2048-byte destination. Keep the oracle on the wire.
    long_server = Server(good_stream(1)[0], auth='digest')
    long_server.control = long_server.url + '/' + 't' * 930
    long_server.sdp = ('m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:' + long_server.control + '\r\n').encode()
    proc = invoke(binary, long_server, ['-n', '1'], standalone)
    # No SDP parameter sets in this one: the IDR is emitted as received.
    idr = b'\x65' + struct.pack('!I', 0) + b'fixture-payload' * 8
    assert proc.returncode == 0 and proc.stdout == unit(idr), (proc.returncode, proc.stderr)
    cases.append('long-authenticated-control-url'); print('PASS', cases[-1], flush=True)
    server = Server(good_stream(3)[0])
    with tempfile.TemporaryFile() as target:
        command = [binary, server.client_url, '-n', '3', '-o', str(target.fileno())] if standalone else [binary, '-c', 'PATH=; rtspcat ' + shlex.quote(server.client_url) + f' -n 3 -o {target.fileno()}']
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(target.fileno(),), timeout=12)
        target.seek(0)
        assert proc.returncode == 0 and proc.stdout == b'' and target.read() == good_stream(3)[1], proc.stderr
    server.finish()
    cases.append('explicit-output-fd'); print('PASS', cases[-1], flush=True)
    for fd in ('9999', '1'):
        server = Server(good_stream(1)[0])
        args = ['-n', '1', '-o', fd]
        if fd == '1':
            with open('/dev/full', 'wb') as full:
                proc = invoke(binary, server, args, standalone, stdout=full)
        else:
            proc = invoke(binary, server, args, standalone)
        assert proc.returncode == 1 and b'write to fd' in proc.stderr, proc.stderr
        cases.append('output-failure-' + fd); print('PASS', cases[-1], flush=True)
    for args in (['-n', '-1'], ['-n', 'no'], ['-o', '-1'], ['-k', '1x'], ['-t', '0'], ['-t', '99999999999'], ['-z'], ['extra'], ['-n'], ['-o'], ['-k'], ['-t']):
        cmd = [binary, 'invalid', *args] if standalone else [binary, '-c', 'PATH=; rtspcat invalid ' + shlex.join(args)]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        assert p.returncode == 2, (args, p.returncode, p.stderr)
        cases.append('invalid-option-' + repr(args)); print('PASS', cases[-1], flush=True)
    for url in ('http://127.0.0.1/x', 'rtsp:///x', 'rtsp://127.0.0.1:12oops/x', 'rtsp://127.0.0.1:65536/x', 'rtsp://127.0.0.1/a\r\nInjected:x', 'rtsp://127.0.0.1/' + 'x' * 600):
        cmd = [binary, url] if standalone else [binary, '-c', 'PATH=; rtspcat ' + shlex.quote(url)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        assert proc.returncode == 1 and proc.stdout == b'', (url, proc.returncode, proc.stderr)
        cases.append('invalid-url-' + repr(url[:35])); print('PASS', cases[-1], flush=True)
    if not standalone:
        repeated(binary)
        cases.append('repeated-in-one-shell-state-fd-output')
    return cases


def repeated(binary):
    with tempfile.TemporaryDirectory(prefix='sol-rtspcat-') as directory:
        output = Path(directory) / 'output'
        script = 'PATH=; trap : PIPE; before=$(trap -p PIPE); '
        servers = []
        # Actual shell process stays alive at the barriers for FD snapshots.
        proc = subprocess.Popen([binary, '--noprofile', '--norc'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.stdin.write(b'PATH=; printf "ready\\n"\n'); proc.stdin.flush()
        assert proc.stdout.readline() == b'ready\n'
        fd_before = len(os.listdir(f'/proc/{proc.pid}/fd'))
        for i in range(24):
            server = Server(good_stream(1)[0], auth=('digest' if i % 2 else None))
            servers.append(server)
            # Alternate failed and successful outputs without creating a subshell.
            target = '/dev/full' if i % 3 == 0 else str(output)
            wanted = 1 if i % 3 == 0 else 0
            script += f'rtspcat {shlex.quote(server.client_url)} -n 1 >{shlex.quote(target)}; [[ $? == {wanted} ]] || exit 90; '
        for _ in range(8):
            server = Server(bad_length='-1'); servers.append(server)
            script += f'rtspcat {shlex.quote(server.client_url)} >/dev/null; [[ $? == 1 ]] || exit 93; '
        script += '[[ $(trap -p PIPE) == "$before" ]] || exit 91; printf "done\\n"\n'
        proc.stdin.write(script.encode()); proc.stdin.flush()
        assert proc.stdout.readline() == b'done\n'
        fd_after = len(os.listdir(f'/proc/{proc.pid}/fd'))
        assert fd_after == fd_before, (fd_before, fd_after)
        assert output.read_bytes() == good_stream(1)[1]
        # Closed pipe: keep the parent shell alive and preserve its signal trap.
        server = Server(good_stream(1)[0]); servers.append(server)
        readfd, writefd = os.pipe(); os.close(readfd)
        # A separate invocation inherits the pipe FD; the command itself catches EPIPE.
        p = subprocess.run([binary, '-c', 'PATH=; trap : PIPE; rtspcat ' + shlex.quote(server.client_url) + f' -n 1 -o {writefd}; r=$?; [[ $r == 1 ]] || exit 92; printf alive'], pass_fds=(writefd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(writefd)
        assert p.returncode == 0 and p.stdout == b'alive', (p.returncode, p.stderr)
        proc.stdin.write(b'exit 0\n'); proc.stdin.flush()
        stdout, stderr = proc.communicate(timeout=12)
        assert proc.returncode == 0, (proc.returncode, stderr)
        for server in servers:
            server.finish()
        print('PASS repeated-in-one-shell-state-fd-output', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--report')
    args = parser.parse_args()
    cases = run_suite(str(Path(args.binary).resolve()), args.standalone)
    if args.report:
        Path(args.report).write_text(json.dumps({'status': 'pass', 'cases': cases, 'count': len(cases)}, indent=2) + '\n')
    print(f'PASS {len(cases)} cases')


if __name__ == '__main__':
    main()
