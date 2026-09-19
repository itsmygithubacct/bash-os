#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Clone, fetch, push and list refs over HTTP, against git's own server.

Usage: python3 tests/git-http.py [BINARY]

The conversation is the same protocol the other tests check over a pipe;
what is new is the envelope, so what it is checked against is git's
`http-backend`, run here behind a small CGI server on the loopback
address. Nothing outside this machine is contacted.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash')
if not binary.is_absolute():
    binary = (ROOT/binary).resolve()
GIT = shutil.which('git')
if not GIT:
    raise SystemExit('git-http: real git is required as the reference')
checks = 0

ENV = {'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Http Author', 'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000',
       'GIT_COMMITTER_NAME': 'Http Committer', 'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
       'GIT_COMMITTER_DATE': '1750000100 +0000'}


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


def git(directory, *args, check_status=True, env=None):
    result = subprocess.run([GIT, '-C', str(directory), *map(str, args)],
                            capture_output=True, timeout=300,
                            env={**os.environ, **ENV, 'HOME': str(directory), **(env or {})})
    if check_status:
        assert result.returncode == 0, (args, result.returncode, result.stderr[:400])
    return result


def bgit(*args, cwd, status=0):
    """Run the git builtin with an empty PATH, as a bash-os user would."""
    result = subprocess.run(
        [str(binary), '--noprofile', '--norc', '-c', 'PATH=; git "$@"', 'git', *map(str, args)],
        capture_output=True, timeout=300, cwd=str(cwd),
        env={**ENV, 'HOME': str(cwd), 'PATH': ''})
    assert result.returncode == status, (args, result.returncode,
                                         result.stdout[:200], result.stderr[:400])
    return result


def serve(root):
    """git http-backend behind an HTTP server, as git's own tests run it."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def backend(self, body=b''):
            path, _, query = self.path.partition('?')
            env = {
                'GIT_PROJECT_ROOT': str(root),
                'GIT_HTTP_EXPORT_ALL': '1',
                'PATH_INFO': path,
                'QUERY_STRING': query,
                'REQUEST_METHOD': self.command,
                'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                'CONTENT_LENGTH': str(len(body)),
                'REMOTE_ADDR': self.client_address[0],
                'REMOTE_USER': 'someone',
                'PATH': os.environ.get('PATH', ''),
                **ENV,
            }
            if self.headers.get('Git-Protocol'):
                env['GIT_PROTOCOL'] = self.headers['Git-Protocol']
            done = subprocess.run([GIT, 'http-backend'], input=body,
                                  capture_output=True, env=env, timeout=300)
            head, sep, payload = done.stdout.partition(b'\r\n\r\n')
            if not sep:
                head, sep, payload = done.stdout.partition(b'\n\n')
            status, headers = 200, []
            for line in head.replace(b'\r\n', b'\n').split(b'\n'):
                if not line:
                    continue
                name, _, value = line.partition(b':')
                if name.decode().strip().lower() == 'status':
                    status = int(value.split()[0])
                else:
                    headers.append((name.decode().strip(), value.decode().strip()))
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self.backend()

        def do_POST(self):
            self.backend(self.rfile.read(int(self.headers.get('Content-Length', 0))))

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


with tempfile.TemporaryDirectory(prefix='git-http-') as name:
    tmp = Path(name)
    served = tmp/'served'
    served.mkdir()
    repo = tmp/'repo'
    repo.mkdir()
    git(repo, 'init', '-q', '-b', 'main')
    (repo/'a.txt').write_text('one\n')
    git(repo, 'add', 'a.txt')
    git(repo, 'commit', '-q', '-m', 'the first commit')
    git(repo, 'branch', 'other')
    git(repo, 'tag', '-a', 'v1', '-m', 'an annotated tag')
    git(tmp, 'clone', '-q', '--bare', str(repo), str(served/'far.git'))
    git(served/'far.git', 'config', 'http.receivepack', 'true')

    server = serve(served)
    url = f'http://127.0.0.1:{server.server_address[1]}/far.git'
    try:
        # What the far end has, asked for over HTTP: git's answer and this
        # build's, which are the same answer.
        theirs = git(tmp, 'ls-remote', '--symref', url).stdout
        ours = bgit('ls-remote', '--symref', url, cwd=tmp).stdout
        check(ours == theirs, 'ls-remote over http', ours[:200], theirs[:200])

        # A clone over HTTP, against git's clone of the same URL.
        reference = tmp/'reference'
        git(tmp, 'clone', '-q', url, str(reference))
        mine = tmp/'mine'
        cloned = bgit('clone', url, str(mine), cwd=tmp)
        check(b"Cloning into" in cloned.stderr, 'it says what it is doing',
              cloned.stderr[:200])
        check(git(mine, 'log', '--format=%H %s').stdout
              == git(reference, 'log', '--format=%H %s').stdout, 'cloned over http')
        check(git(mine, 'for-each-ref', '--format=%(refname)').stdout
              == git(reference, 'for-each-ref', '--format=%(refname)').stdout,
              'with the refs git lays down')
        check(git(mine, 'fsck', '--no-progress', '--strict').returncode == 0,
              'and nothing missing behind them')
        check((mine/'a.txt').read_text() == 'one\n', 'and a working tree')

        # The far end moves, and a fetch over HTTP brings only that.
        (repo/'a.txt').write_text('one\ntwo\n')
        git(repo, 'commit', '-q', '-am', 'the second commit')
        git(repo, 'push', '-q', str(served/'far.git'), 'main')
        fetched = bgit('fetch', cwd=mine)
        check(f'From {url}'.encode() in fetched.stderr, 'fetch says where from',
              fetched.stderr[:200])
        check(git(mine, 'rev-parse', 'refs/remotes/origin/main').stdout
              == git(served/'far.git', 'rev-parse', 'main').stdout,
              'and brought the branch up to date')

        # And a push over HTTP moves the far end.
        git(mine, 'merge', '-q', '--ff-only', 'origin/main')
        (mine/'a.txt').write_text('one\ntwo\nthree\n')
        git(mine, 'commit', '-q', '-am', 'the third commit')
        pushed = bgit('push', 'origin', 'main', cwd=mine)
        check(f'To {url}'.encode() in pushed.stderr, 'push says where to',
              pushed.stderr[:200])
        check(git(served/'far.git', 'rev-parse', 'main').stdout
              == git(mine, 'rev-parse', 'main').stdout, 'and the far end moved')
        check(git(served/'far.git', 'fsck', '--no-progress', '--strict').returncode == 0,
              'with everything it needs')
        again = bgit('push', 'origin', 'main', cwd=mine)
        check(b'Everything up-to-date' in again.stderr, 'and nothing the next time',
              again.stderr[:200])

        # A history too big to explode arrives as a pack, over HTTP as over
        # anything else.
        big = tmp/'big'
        big.mkdir()
        git(big, 'init', '-q', '-b', 'main')
        for revision in range(40):
            (big/'a.txt').write_text(f'{revision}\n' * (revision + 1))
            (big/'b.txt').write_text(f'other {revision}\n')
            git(big, 'add', '.')
            git(big, 'commit', '-q', '-m', f'commit {revision}')
        git(tmp, 'clone', '-q', '--bare', str(big), str(served/'big.git'))
        big_url = f'http://127.0.0.1:{server.server_address[1]}/big.git'
        big_clone = tmp/'big-clone'
        bgit('clone', big_url, str(big_clone), cwd=tmp)
        packs = sorted((big_clone/'.git/objects/pack').glob('*.pack'))
        check(len(packs) == 1, 'a big clone keeps its pack', [p.name for p in packs])
        loose = [path for path in (big_clone/'.git/objects').iterdir()
                 if path.is_dir() and len(path.name) == 2]
        check(not loose, 'and explodes nothing', loose)
        check(git(big_clone, 'log', '--format=%H').stdout
              == git(big, 'log', '--format=%H').stdout, 'with the whole history')
        check(git(big_clone, 'fsck', '--no-progress', '--strict').returncode == 0,
              'which git reads out of the pack')

        # An address with nothing behind it is refused, not half-cloned.
        missing = f'http://127.0.0.1:{server.server_address[1]}/nothing.git'
        result = bgit('ls-remote', missing, cwd=tmp, status=128)
        check(b'fatal:' in result.stderr and b'nothing.git' in result.stderr,
              'a URL with no repository behind it', result.stderr[:200])
    finally:
        server.shutdown()

print(f'git-http: {checks} checks passed')
