#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check pkg's in-process signature checks and its remote fetch through curl.

Usage: python3 tests/pkg-signify.py [BINARY]
Builds a small Bash loadable against the prepared build tree, packs and signs
it in signify format with throwaway Ed25519 keys, and runs pkg with an empty
PATH, so neither an external bashsignify nor an external curl can take part.
"""

import base64
import functools
import hashlib
import http.server
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
version = subprocess.check_output(
    ['bash', '-c', '. config/versions.sh; printf %s "$BASH_SRC_VERSION"'], cwd=ROOT, text=True)
build_tree = ROOT / 'build' / f'bash-{version}'
arch = platform.machine()
checks = 0

LOADABLE = r'''
#include <config.h>
#include <stdio.h>
#include "loadables.h"

static int
pkgprobe_builtin (WORD_LIST *list)
{
    (void) list;
    printf ("pkgprobe loaded\n");
    return EXECUTION_SUCCESS;
}

static char *pkgprobe_doc[] = { "Report that a pkg-installed loadable runs.", (char *) NULL };
struct builtin pkgprobe_struct = {
    "pkgprobe", pkgprobe_builtin, BUILTIN_ENABLED, pkgprobe_doc, "pkgprobe", 0
};
'''


class Key:
    def __init__(self, directory, name):
        self.private = Ed25519PrivateKey.generate()
        self.keynum = os.urandom(8)
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = directory / f'{name}.pub'
        self.pub.write_text('untrusted comment: pkg test public key\n' +
                            base64.b64encode(b'Ed' + self.keynum + public).decode() + '\n')

    def sign(self, target, sig=None):
        sig = Path(sig or f'{target}.sig')
        raw = self.private.sign(Path(target).read_bytes())
        sig.write_text('untrusted comment: pkg test signature\n' +
                       base64.b64encode(b'Ed' + self.keynum + raw).decode() + '\n')
        return sig


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def run(script, *args, env, status=0, stdout=None, stderr=None):
    global checks
    result = subprocess.run(
        [binary, '--noprofile', '--norc', '-c', 'PATH=; ' + script, '_', *map(str, args)],
        capture_output=True, text=True, timeout=60,
        env={'LC_ALL': 'C', 'HOME': str(env['HOME']), **{k: str(v) for k, v in env.items()}})
    assert result.returncode == status, (script, result.returncode, result.stdout, result.stderr)
    if stdout is not None:
        assert result.stdout == stdout, (script, result.stdout, result.stderr)
    if stderr is not None:
        assert stderr in result.stderr, (script, stderr, result.stderr)
    checks += 1
    return result


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


with tempfile.TemporaryDirectory(prefix='pkg-signify-') as directory:
    tmp = Path(directory)
    trusted = tmp / 'trusted'
    trusted.mkdir()
    publisher = Key(trusted, 'publisher')
    stranger = Key(tmp, 'stranger')
    env = {'HOME': tmp, 'BASHSIGNIFY_TRUSTED_KEYS_DIR': trusted,
           'BASHSIGNIFY_REVOKED_KEYS': tmp / 'no-revocations'}

    # A small loadable. pkg refuses DT_NEEDED dependencies other than glibc's own.
    source = tmp / 'pkgprobe.c'
    source.write_text(LOADABLE)

    def make_package(label, *link):
        stage = tmp / f'stage-{label}'
        (stage / 'loadable').mkdir(parents=True)
        shared = stage / 'loadable' / 'pkgprobe.so'
        subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-fPIC', '-shared', '-nostdlib',
                        '-DHAVE_CONFIG_H', f'-I{build_tree}', f'-I{build_tree}/include',
                        f'-I{build_tree}/builtins', f'-I{build_tree}/examples/loadables',
                        str(source), '-o', str(shared), *link], check=True)
        (stage / 'MANIFEST').write_text(
            f'type: loadable\nname: pkgprobe\nversion: 1.0\nbuiltin: pkgprobe\n'
            f'abi: bash-5.3\narch: {arch}\nsha256: {sha256(shared)}\n')
        built = tmp / label / f'pkgprobe_1.0_{arch}.pkg'
        built.parent.mkdir()
        run('pkg pack "$1" "$2"', stage, built, env=env)
        publisher.sign(built)
        return built

    package = make_package('plain')

    # Verification with an empty PATH: good, untrusted, revoked, tampered.
    run('pkg verify "$1"', package, env=env, stdout='verify pkgprobe\tpackage=ok\n')
    run('pkg verify "$1"', make_package('libm', '-Wl,--no-as-needed', '-lm'), env=env,
        stdout='verify pkgprobe\tpackage=ok\n')
    run('pkg verify "$1"', make_package('libc', '-Wl,--no-as-needed', '-lc'), env=env,
        stdout='verify pkgprobe\tpackage=ok\n')
    run('pkg verify "$1"', make_package('libz', '-Wl,--no-as-needed', '-lz'), env=env, status=1,
        stderr='non-bundled shared library dependency: libz.so.1')
    foreign = tmp / 'foreign.pkg'
    shutil.copy(package, foreign)
    stranger.sign(foreign)
    run('pkg verify "$1"', foreign, env=env, status=1, stderr='no trusted key matching keynum')
    revoked = tmp / 'revoked'
    revoked.write_text('# retired publisher keys\n\n' + publisher.keynum.hex().upper() + '  # rotated\n')
    run('pkg verify "$1"', package, env={**env, 'BASHSIGNIFY_REVOKED_KEYS': revoked},
        status=1, stderr='has been revoked')
    tampered = tmp / 'tampered.pkg'
    data = bytearray(package.read_bytes())
    data[len(data) // 2] ^= 1
    tampered.write_bytes(bytes(data))
    shutil.copy(f'{package}.sig', f'{tampered}.sig')
    run('pkg verify "$1"', tampered, env=env, status=1, stderr='does not match its signature')

    # Malformed signature files are refused before any key lookup.
    good = Path(f'{package}.sig').read_text().splitlines()
    decoded = base64.b64decode(good[1])
    for label, text, message in (
            ('one line', good[1] + '\n', 'is not in signify format'),
            ('no comment prefix', 'comment\n' + good[1] + '\n', 'is not in signify format'),
            ('short', good[0] + '\n' + base64.b64encode(decoded[:-1]).decode() + '\n',
             'wrong length'),
            ('not base64', good[0] + '\n' + good[1][:-4] + '!!!!\n', 'wrong length'),
            ('not Ed25519', good[0] + '\n' + base64.b64encode(b'Sm' + decoded[2:]).decode() + '\n',
             'is not an Ed25519')):
        broken = tmp / f'broken-{label.replace(" ", "-")}.pkg'
        shutil.copy(package, broken)
        Path(f'{broken}.sig').write_text(text)
        run('pkg verify "$1"', broken, env=env, status=1, stderr=message)
    unsigned = tmp / 'unsigned.pkg'
    shutil.copy(package, unsigned)
    run('pkg verify "$1"', unsigned, env=env, status=1, stderr='no signature for')
    run('pkg verify "$1"', package, env={**env, 'BASHSIGNIFY_TRUSTED_KEYS_DIR': tmp / 'absent'},
        status=1, stderr='(the built-in keys; ')

    # A signed per-arch repository served over HTTP, fetched by the curl builtin.
    # pkg names its mirror after the URL's last path segment, so a source needs
    # a path below the host.
    served = tmp / 'www'
    repo = served / 'bash-os'
    (repo / arch).mkdir(parents=True)
    shutil.copy(package, repo / arch / package.name)
    shutil.copy(f'{package}.sig', repo / arch / f'{package.name}.sig')
    index = repo / arch / 'INDEX'
    index.write_text(
        f'pkg-loadable-v1 name=pkgprobe version=1.0 builtin=pkgprobe abi=bash-5.3 '
        f'arch={arch} package={package.name} sha256={sha256(package)} sig={package.name}.sig '
        f'deps=-\n')
    publisher.sign(index)
    server = http.server.ThreadingHTTPServer(
        ('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(served)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        sources = tmp / 'sources.list'
        sources.write_text(f'http://127.0.0.1:{server.server_address[1]}/bash-os\n')
        root = tmp / 'root'
        root.mkdir()
        run('pkg update --root "$1" --sources "$2" --remote-insecure', root, sources, env=env)
        mirrored = list((root / 'var/lib/pkg/repos').rglob('INDEX'))
        assert mirrored, 'update --remote-insecure mirrored no INDEX'
        run('pkg install pkgprobe --root "$1" --sources "$2"', root, sources, env=env)
        run('pkg load pkgprobe --root "$1" && pkgprobe', root, env=env,
            stdout=f'loaded pkgprobe\tpkgprobe\t{root}/usr/lib/bash-os/loadables/pkgprobe.so\n'
                   'pkgprobe loaded\n')
        # A repository whose INDEX signature no longer matches is not mirrored.
        index.write_text(index.read_text() + '# changed after signing\n')
        fresh = tmp / 'fresh-root'
        fresh.mkdir()
        run('pkg update --root "$1" --sources "$2" --remote-insecure', fresh, sources, env=env,
            status=1)
    finally:
        server.shutdown()

print(f'pkg-signify: {checks} checks passed')
