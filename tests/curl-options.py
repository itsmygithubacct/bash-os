#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the curl builtin's request options with curl itself.

Usage: python3 tests/curl-options.py [BINARY]
Serves HTTP, HTTPS and an HTTP proxy on 127.0.0.1 and runs each case through
the builtin (empty PATH) and through /usr/bin/curl. A case passes when both
produce the same exit status and output and the server saw the same request
(method, target, body and the headers that matter for the option). Covers
-I, -v, -F, -T, -G with --data-urlencode, --json, --retry, -x (plain and
CONNECT), --compressed, --http2, -r and -C.
"""

import base64
import datetime
import email.parser
import email.policy
import gzip
import http.server
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
REAL = '/usr/bin/curl'
FULL = bytes(range(256)) * 40
seen = []          # requests recorded by the origin servers
proxied = []       # request lines recorded by the proxy
flaky = {}
checks = failures = 0


def authority(tmp):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'curl-options test authority')])

    def builder(subject, key):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=2)))

    ca = (builder(ca_name, ca_key)
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')]), leaf_key)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                           critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (tmp / 'ca.pem').write_bytes(ca.public_bytes(pem))
    (tmp / 'leaf.pem').write_bytes(leaf.public_bytes(pem))
    (tmp / 'leaf.key').write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    return tmp / 'ca.pem', tmp / 'leaf.pem', tmp / 'leaf.key'


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def version_string(self):
        return 'origin'

    def date_time_string(self, timestamp=None):
        return 'Thu, 01 Jan 2026 00:00:00 GMT'

    def reply(self, status, body=b'', headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def handle_any(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            body = b''
            while True:
                size = int(self.rfile.readline().split(b';')[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b'\r\n', b''):
                        pass
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
        record = {'method': self.command, 'path': self.path, 'body': body,
                  'headers': {k.lower(): v for k, v in self.headers.items()}}
        seen.append(record)
        path = self.path.split('?')[0]
        if path == '/echo':
            out = json.dumps({'method': self.command, 'path': self.path,
                              'type': self.headers.get('Content-Type'),
                              'accept': self.headers.get('Accept'),
                              'body': body.decode('latin-1')}, sort_keys=True).encode()
            self.reply(200, out, [('Content-Type', 'application/json'), ('X-Test', 'one')])
        elif path == '/gzip':
            self.reply(200, gzip.compress(FULL, mtime=0), [('Content-Encoding', 'gzip')])
        elif path == '/deflate':
            self.reply(200, zlib.compress(FULL), [('Content-Encoding', 'deflate')])
        elif path == '/range':
            rng = self.headers.get('Range')
            if rng and rng.startswith('bytes='):
                first, _, last = rng[6:].partition('-')
                first = int(first)
                if first >= len(FULL):
                    self.reply(416, b'', [('Content-Range', f'bytes */{len(FULL)}')])
                    return
                last = int(last) if last else len(FULL) - 1
                part = FULL[first:last + 1]
                self.reply(206, part, [('Content-Range', f'bytes {first}-{last}/{len(FULL)}')])
            else:
                self.reply(200, FULL)
        elif path == '/norange':
            self.reply(200, FULL)
        elif path.startswith('/flaky/'):
            key = path
            flaky[key] = flaky.get(key, 0) + 1
            if flaky[key] <= 2:
                self.reply(503, b'busy\n', [('Retry-After', '0')])
            else:
                self.reply(200, b'ok after %d\n' % flaky[key])
        elif path == '/always503':
            self.reply(503, b'down\n')
        elif path == '/redirect':
            self.reply(302, b'', [('Location', '/echo')])
        else:
            self.reply(200, b'plain body\n', [('X-Path', self.path)])

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = handle_any


class Quiet(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass   # a client may drop a connection mid-request (refusal cases)


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = self.request.recv(1)
            if not chunk:
                return
            head += chunk
        lines = head.decode('latin-1').split('\r\n')
        method, target, _ = lines[0].split(' ', 2)
        auth = next((l.split(':', 1)[1].strip() for l in lines[1:] if l.lower().startswith('proxy-authorization:')), None)
        proxied.append((method, target, auth))
        if method == 'CONNECT':
            host, port = target.rsplit(':', 1)
            upstream = socket.create_connection((host, int(port)))
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            pipes = [self.request, upstream]
            while True:
                ready, _, _ = select.select(pipes, [], [], 10)
                if not ready:
                    break
                done = False
                for s in ready:
                    data = s.recv(65536)
                    if not data:
                        done = True
                        break
                    (upstream if s is self.request else self.request).sendall(data)
                if done:
                    break
            upstream.close()
            return
        # Absolute-form request: forward it to the origin.
        rest = target.split('://', 1)[1]
        hostport, _, path = rest.partition('/')
        host, port = hostport.rsplit(':', 1)
        length = next((int(l.split(':', 1)[1]) for l in lines[1:] if l.lower().startswith('content-length:')), 0)
        body = self.rfile.read(length) if length else b''
        kept = [l for l in lines[1:] if l and not l.lower().startswith(('proxy-', 'connection:'))]
        request = f'{method} /{path} HTTP/1.1\r\n' + ''.join(l + '\r\n' for l in kept) + 'Connection: close\r\n\r\n'
        upstream = socket.create_connection((host, int(port)))
        upstream.sendall(request.encode('latin-1') + body)
        while True:
            data = upstream.recv(65536)
            if not data:
                break
            self.request.sendall(data)
        upstream.close()


def run(args, real, cwd, data=None):
    env = {'HOME': str(cwd), 'LC_ALL': 'C'}
    if real:
        cmd = [REAL, *args]
        env['PATH'] = '/usr/bin:/bin'
    else:
        cmd = [binary, '--noprofile', '--norc', '-c', 'curl "$@"', 'curl', *args]
        env['PATH'] = ''
    return subprocess.run(cmd, cwd=cwd, capture_output=True, input=data, timeout=60, env=env)


def check(name, ok, detail=''):
    global checks, failures
    checks += 1
    if not ok:
        failures += 1
        print(f'FAIL {name}: {detail}')


def compare(name, args, cwd, data=None, request_keys=('method', 'path', 'body'), headers=(),
            stderr_has=(), files=(), setup=None):
    """Run ARGS through both curls; compare status, stdout, files and requests."""
    results = []
    for real in (True, False):
        if setup:
            setup()
        del seen[:]
        result = run(args, real, cwd, data)
        requests = [tuple([r[k] for k in request_keys] + [r['headers'].get(h) for h in headers]) for r in seen]
        contents = [(cwd / f).read_bytes() if (cwd / f).exists() else None for f in files]
        results.append((result.returncode, result.stdout, requests, contents, result.stderr))
    want, got = results
    check(name, want[:4] == got[:4],
          f'\n  curl:    {want[0]} {want[1][:300]!r} {want[2]} {[c[:40] if c else c for c in want[3]]}'
          f'\n  builtin: {got[0]} {got[1][:300]!r} {got[2]} {[c[:40] if c else c for c in got[3]]}'
          f'\n  builtin stderr: {got[4][:400]!r}')
    for needle in stderr_has:
        check(f'{name} stderr {needle!r}', needle.encode() in got[4], got[4][:400])
    return got


def main():
    if not os.access(REAL, os.X_OK):
        print(f'SKIP curl options: {REAL} is not installed')
        return 0
    with tempfile.TemporaryDirectory(prefix='bash-os-curl-') as name:
        tmp = Path(name)
        ca, leaf, key = authority(tmp)
        plain = Quiet(('127.0.0.1', 0), Origin)
        secure = Quiet(('127.0.0.1', 0), Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf, key)
        secure.socket = context.wrap_socket(secure.socket, server_side=True)
        proxy = Proxy(('127.0.0.1', 0), ProxyHandler)
        for server in (plain, secure, proxy):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        H = f'http://127.0.0.1:{plain.server_address[1]}'
        S = f'https://127.0.0.1:{secure.server_address[1]}'
        P = f'http://127.0.0.1:{proxy.server_address[1]}'
        work = tmp / 'work'
        work.mkdir()
        (work / 'up.txt').write_bytes(b'uploaded\x00bytes\n')
        (work / 'blob.bin').write_bytes(bytes(range(256)))
        (work / 'body.json').write_bytes(b'{"from":"file"}')

        # -I / --head: the response head is the output.
        compare('head', ['-sI', f'{H}/echo'], work)
        compare('head long', ['-s', '--head', f'{H}/plain'], work)
        compare('head follow', ['-sIL', f'{H}/redirect'], work)
        compare('head to file', ['-sI', '-o', 'head.out', f'{H}/echo'], work, files=['head.out'])
        compare('head and data', ['-sI', '-d', 'a=b', f'{H}/echo'], work)

        # -v: request and response heads on stderr; stdout unchanged.
        compare('verbose', ['-sv', f'{H}/echo'], work,
                stderr_has=['> GET /echo HTTP/1.1', '< HTTP/1.1 200 OK', '< X-Test: one'])
        compare('verbose long', ['-s', '--verbose', '-o', '/dev/null', f'{H}/plain'], work,
                stderr_has=['> GET /plain HTTP/1.1'])

        # -F: compare the parts the server parsed.
        def parts(result):
            body = seen[-1]['body'] if seen else b''
            ctype = seen[-1]['headers'].get('content-type', '') if seen else ''
            message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                b'Content-Type: ' + ctype.encode() + b'\r\n\r\n' + body)
            return [(p.get_param('name', header='content-disposition'), p.get_filename(),
                     p.get_content_type() if p.get('Content-Type') else None, p.get_payload(decode=True))
                    for p in message.iter_parts()] if message.is_multipart() else None
        for spec in (['-F', 'a=b'], ['-F', 'a=b', '-F', 'c=d e'], ['-F', 'file=@up.txt'],
                     ['-F', 'file=@blob.bin;type=application/x-test'],
                     ['-F', 'file=@up.txt;filename=renamed.txt'], ['-F', 'text=<up.txt'],
                     ['--form', 'k=v', '-F', 'f=@body.json'], ['-F', 'a=1;type=text/x-mine']):
            got = []
            for real in (True, False):
                del seen[:]
                result = run(['-s', *spec, f'{H}/echo'], real, work)
                got.append((result.returncode, seen[-1]['method'] if seen else None, parts(result)))
            check(f'form {spec}', got[0] == got[1], f'\n  curl:    {got[0]}\n  builtin: {got[1]}')
        compare('form and data', ['-s', '-F', 'a=b', '-d', 'c=d', f'{H}/echo'], work)
        compare('form missing file', ['-s', '-F', 'a=@missing', f'{H}/echo'], work)

        # -T: PUT the file; a URL without a file part gets its name.
        compare('upload', ['-s', '-T', 'up.txt', f'{H}/put/target'], work)
        compare('upload dir url', ['-s', '-T', 'up.txt', f'{H}/put/'], work)
        compare('upload bare host', ['-s', '--upload-file', 'blob.bin', H], work)
        compare('upload stdin', ['-s', '-T', '-', f'{H}/put/stdin'], work, data=b'from stdin\n')
        compare('upload with -X', ['-s', '-X', 'POST', '-T', 'up.txt', f'{H}/put/x'], work)

        # -G and --data-urlencode.
        compare('get query', ['-s', '-G', '-d', 'a=1', '-d', 'b=2', f'{H}/echo'], work)
        compare('get query appended', ['-s', '--get', '--data-urlencode', 'q=a b&c', f'{H}/echo?x=1'], work)
        for form in ('q=a b', '=a b', 'plain text', 'q@up.txt', '@body.json', 'k=é~-._*'):
            compare(f'urlencode {form!r}', ['-s', '--data-urlencode', form, f'{H}/echo'], work,
                    headers=('content-type',))
        compare('get head', ['-sIG', '-d', 'a=1', f'{H}/echo'], work)

        # --json.
        for spec in (['--json', '{"a":1}'], ['--json', '@body.json'], ['--json', '[1,', '--json', '2]'],
                     ['--json', '{}', '-H', 'Content-Type: text/x-mine'], ['--json', '{}', '-X', 'PUT']):
            compare(f'json {spec}', ['-s', *spec, f'{H}/echo'], work, headers=('content-type', 'accept'))

        # --retry: two 503s, then success.
        for i, extra in enumerate(([], ['--retry-delay', '1'], ['--retry-max-time', '30'])):
            def reset(i=i):
                flaky.pop(f'/flaky/{i}', None)
            compare(f'retry {extra}', ['-s', '--retry', '2', *extra, f'{H}/flaky/{i}'], work, setup=reset)
        def reset_short():
            flaky.pop('/flaky/short', None)
        compare('retry exhausted', ['-s', '--retry', '1', f'{H}/flaky/short'], work, setup=reset_short)
        compare('retry exhausted fail', ['-sf', '--retry', '1', f'{H}/always503'], work)
        compare('retry warning', ['--retry', '1', '-o', 'retry-body', f'{H}/always503'], work,
                stderr_has=['Will retry in'], files=['retry-body'],
                setup=lambda: (work / 'retry-body').unlink(missing_ok=True))
        compare('retry no transient', ['-s', '--retry', '3', f'{H}/plain'], work)

        # -x/--proxy: absolute-form forwarding, CONNECT tunnels and refusals.
        for real in (True, False):
            del proxied[:]
            result = run(['-s', '-x', P, f'{H}/echo?via=proxy'], real, work)
            check(f'proxy http real={real}', result.returncode == 0 and b'"path": "/echo?via=proxy"' in result.stdout
                  and proxied and proxied[0][:2] == ('GET', f'{H}/echo?via=proxy'), (result, proxied))
            del proxied[:]
            auth_proxy = P.replace('http://', 'http://user:pw@')
            result = run(['-s', '--proxy', auth_proxy, f'{H}/plain'], real, work)
            check(f'proxy auth real={real}', result.returncode == 0 and proxied and
                  proxied[0][2] == 'Basic ' + base64.b64encode(b'user:pw').decode(), (result, proxied))
            del proxied[:]
            result = run(['-s', '--cacert', str(ca), '-x', P, f'{S}/echo'], real, work)
            check(f'proxy connect real={real}', result.returncode == 0 and b'"method": "GET"' in result.stdout
                  and proxied and proxied[0][:2] == ('CONNECT', S.split('//')[1]), (result, proxied))
        compare('proxy refused', ['-s', '-x', 'http://127.0.0.1:1', f'{H}/plain'], work)
        compare('proxy empty', ['-s', '--proxy', '', f'{H}/plain'], work)

        # --compressed.
        compare('compressed gzip', ['-s', '--compressed', f'{H}/gzip'], work)
        compare('compressed deflate', ['-s', '--compressed', f'{H}/deflate'], work)
        compare('compressed plain', ['-s', '--compressed', f'{H}/plain'], work)
        compare('gzip without compressed', ['-s', f'{H}/gzip'], work)
        compare('compressed https', ['-s', '--compressed', '--cacert', str(ca), f'{S}/gzip'], work)

        # --http2: an HTTP/1.1 exchange is the fallback curl also takes.
        compare('http2 plain', ['-s', '--http2', f'{H}/plain'], work, request_keys=('method', 'path'))
        compare('http2 https', ['-s', '--http2', '--cacert', str(ca), f'{S}/plain'], work,
                request_keys=('method', 'path'))

        # -r and -C.
        for rng in ('0-9', '100-', '10-20', '5000-'):
            compare(f'range {rng}', ['-s', '-r', rng, f'{H}/range'], work)
        compare('range long', ['-s', '--range', '0-3', f'{H}/range'], work)
        def partial():
            (work / 'part.bin').write_bytes(FULL[:1000])
        compare('continue dash', ['-s', '-C', '-', '-o', 'part.bin', f'{H}/range'], work,
                files=['part.bin'], setup=partial)
        compare('continue offset', ['-s', '-C', '1000', '-o', 'part.bin', f'{H}/range'], work,
                files=['part.bin'], setup=partial)
        compare('continue long', ['-s', '--continue-at', '-', '-o', 'part.bin', f'{H}/range'], work,
                files=['part.bin'], setup=partial)
        def complete():
            (work / 'part.bin').write_bytes(FULL)
        compare('continue complete', ['-s', '-C', '-', '-o', 'part.bin', f'{H}/range'], work,
                files=['part.bin'], setup=complete)
        compare('continue unsupported', ['-s', '-C', '-', '-o', 'part.bin', f'{H}/norange'], work,
                files=['part.bin'], setup=partial)
        def absent():
            (work / 'part.bin').unlink(missing_ok=True)
        compare('continue new file', ['-s', '-C', '-', '-o', 'part.bin', f'{H}/range'], work,
                files=['part.bin'], setup=absent)
        compare('continue bad', ['-s', '-C', 'x', f'{H}/range'], work)

        for server in (plain, secure, proxy):
            server.shutdown()
    print(f'curl options: {checks} checks, {failures} failed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
