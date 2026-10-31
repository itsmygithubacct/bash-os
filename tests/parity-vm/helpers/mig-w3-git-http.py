#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Loopback smart-HTTP git peer (CGI to git-http-backend) for disposable parity-VM fixtures.

  serve PORT ROOT LOG [DEADLINE]   serve repositories under ROOT until GET /__stop__ or DEADLINE seconds
  summary LOG                      print the distinct "METHOD target" pairs that were served (sorted)
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse
import uuid

BACKEND = '/usr/lib/git-core/git-http-backend'


def require_guest():
    try:
        uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
    except (OSError, ValueError) as exc:
        raise SystemExit('fixture requires disposable parity VM: ' + str(exc))


def serve(port, root, log, deadline=30):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *a):
            pass

        def body(self):
            if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
                data = b''
                while True:
                    size = int(self.rfile.readline().strip() or b'0', 16)
                    if size == 0:
                        self.rfile.readline(); break
                    data += self.rfile.read(size); self.rfile.readline()
                return data
            return self.rfile.read(int(self.headers.get('Content-Length', '0')))

        def handle_any(self):
            parts = urllib.parse.urlsplit(self.path)
            if parts.path == '/__stop__':
                self.server.stopped = True
                self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers(); return
            data = self.body() if self.command == 'POST' else b''
            env = {'PATH': '/usr/bin:/bin', 'GIT_PROJECT_ROOT': root, 'GIT_HTTP_EXPORT_ALL': '1', 'REQUEST_METHOD': self.command,
                   'PATH_INFO': parts.path, 'QUERY_STRING': parts.query, 'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                   'CONTENT_LENGTH': str(len(data)), 'REMOTE_USER': 'fixture', 'REMOTE_ADDR': '127.0.0.1',
                   'HOME': os.environ.get('HOME', '/tmp'), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
            for h, e in (('Git-Protocol', 'HTTP_GIT_PROTOCOL'), ('Content-Encoding', 'HTTP_CONTENT_ENCODING'), ('Accept', 'HTTP_ACCEPT')):
                if self.headers.get(h): env[e] = self.headers[h]
            proc = subprocess.run([BACKEND], input=data, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            head, _, out = proc.stdout.partition(b'\r\n\r\n')
            if not _:
                head, _, out = proc.stdout.partition(b'\n\n')
            status = 200; headers = []
            for line in head.decode('latin1').splitlines():
                k, _, v = line.partition(':')
                if k.lower() == 'status': status = int(v.split()[0])
                elif k: headers.append((k, v.strip()))
            with open(log, 'a') as f:
                f.write(json.dumps({'method': self.command, 'path': parts.path, 'query': parts.query, 'status': status}) + '\n')
            self.send_response(status)
            for k, v in headers: self.send_header(k, v)
            self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)

        do_GET = do_POST = handle_any

    srv = http.server.HTTPServer(('127.0.0.1', port), Handler)
    srv.timeout = 0.2; srv.stopped = False
    Path(log + '.ready').write_text('ready\n')
    end = time.monotonic() + float(deadline)
    while not srv.stopped and time.monotonic() < end:
        srv.handle_request()
    srv.server_close()


def summary(log):
    seen = set()
    for line in Path(log).read_text().splitlines():
        r = json.loads(line)
        path = r['path'].rsplit('/', 1)[-1]
        seen.add('%s %s%s %d' % (r['method'], path, ('?' + r['query']) if r['query'] else '', r['status']))
    print('\n'.join(sorted(seen)))


if __name__ == '__main__':
    require_guest()
    a = sys.argv[1:]
    if a[0] == 'serve': serve(int(a[1]), a[2], a[3], *a[4:5])
    elif a[0] == 'summary': summary(a[1])
    else: raise SystemExit('unknown command')
