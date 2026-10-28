#!/usr/bin/python3
"""Guarded, bounded loopback HTTP repository with independent control probes."""
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import platform
import signal
import sys
import time
import urllib.parse
import uuid

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
REPO = HOME / 'repository'


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.geteuid() != 2000 or os.environ.get('HOME') != str(HOME)
                or Path.cwd().resolve() != CASE or CASE.stat().st_uid != 2000
                or HOME.stat().st_uid != 2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def allowed():
    arch = platform.machine()
    if not arch or any(not (ch.isalnum() or ch in '_-') for ch in arch):
        raise ValueError('invalid architecture')
    return {f'/repository/{arch}/{name}': REPO / arch / name for name in
            ('INDEX', 'INDEX.sig', 'fixtureprobe-2.pkg', 'fixtureprobe-2.pkg.sig',
             'fixtureprobe-2.pkg.delta', 'fixtureprobe-2.pkg.delta.sig')}


def event(record):
    with (HOME / 'repo-http-events.jsonl').open('a', encoding='utf-8') as out:
        out.write(json.dumps(record, sort_keys=True) + '\n')


class Server(http.server.HTTPServer):
    timeout = .2
    allow_reuse_address = False

    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(2)
        return conn, addr


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        control = self.headers.get('X-Parity-Control') == '1'
        if path == '/__fixture_shutdown__' and control:
            body, code = b'fixture shutdown\n', 200
            self.server.stopped = True
        elif path in allowed():
            item = allowed()[path]
            if item.is_file() and not item.is_symlink():
                body, code = item.read_bytes(), 200
            else:
                body, code = b'not found\n', 404
        else:
            body, code = b'not found\n', 404
        event({'method': self.command, 'path': self.path, 'control': control,
               'status': code, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
               'peer': self.client_address[0], 'host': self.headers.get('Host', '')})
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        self.wfile.write(body)


def serve():
    report = {'stopped': False, 'error': None, 'address': '127.0.0.1'}
    server = None
    try:
        server = Server(('127.0.0.1', 0), Handler)
        server.stopped = False
        (HOME / 'repo-http-port').write_text(str(server.server_port) + '\n')
        deadline = time.monotonic() + 45
        while not server.stopped and time.monotonic() < deadline:
            server.handle_request()
        report['stopped'] = server.stopped
        if not server.stopped:
            report['error'] = 'server deadline'
    except (OSError, ValueError) as exc:
        report['error'] = repr(exc)
    finally:
        if server is not None:
            server.server_close()
        (HOME / 'repo-http-result.json').write_text(json.dumps(report, sort_keys=True) + '\n')
    return 0 if report['stopped'] and report['error'] is None else 1


def request(port, path):
    if not 1024 <= port <= 65535:
        raise ValueError('invalid loopback port')
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        conn.request('GET', path, headers={'X-Parity-Control': '1'})
        response = conn.getresponse()
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('HTTP control response too large')
        return response.status, data
    finally:
        conn.close()


def control(port):
    results = []
    for path, item in allowed().items():
        if item.name.endswith('.delta') or item.name.endswith('.delta.sig'):
            continue
        status, body = request(port, path)
        expected = item.read_bytes()
        results.append({'path': path, 'status': status, 'size': len(body),
                        'sha256': hashlib.sha256(body).hexdigest(), 'exact': body == expected})
    print(json.dumps(results, sort_keys=True))
    return 0 if all(r['status'] == 200 and r['exact'] for r in results) else 1


def stop(port):
    status, body = request(port, '/__fixture_shutdown__')
    print(json.dumps({'status': status, 'body': body.decode(errors='replace')}))
    return 0 if status == 200 and body == b'fixture shutdown\n' else 1


if __name__ == '__main__':
    require_guest()
    try:
        if sys.argv[1:] == ['serve']:
            sys.exit(serve())
        if len(sys.argv) == 3 and sys.argv[1] in ('control', 'stop'):
            sys.exit((control if sys.argv[1] == 'control' else stop)(int(sys.argv[2])))
        raise ValueError('unexpected helper arguments')
    except (OSError, ValueError, IndexError) as exc:
        print('fixture HTTP peer: ' + str(exc), file=sys.stderr)
        sys.exit(90)
