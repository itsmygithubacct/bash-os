#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the package producer, the release signer, and pkg installing a release.

Usage: python3 tests/packages.py [BINARY]
Builds a handful of packages against out/bash-shell and the bash tree its
build left behind, so ./build.sh --profile shell must be the latest build.
BINARY (default out/bash) runs pkg with an empty PATH against the signed
release served over HTTP. Each installed builtin must then behave in
out/bash-shell, which has no builtins of its own, exactly as the same builtin
compiled into BINARY does.
"""

import functools
import hashlib
import http.server
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
shell = str(ROOT / 'out/bash-shell')
BUILD = ROOT / 'config/build-packages.py'
SIGN = ROOT / 'config/sign-packages.py'
arch = platform.machine()
# A plain command, one defined in a sibling's source, one with helpers, one
# that needs glibc's static atexit, bash's own examples with build.sh's
# fixups, one registered only through build.sh's builtin table, one that
# needs libm, and a pair that require each other.
NAMES = ['seq', 'col', 'cksum', 'crypto', 'head', 'mkdir', 'wc', 'awk', 'sudo', 'doas']
CASES = {
    'seq': 'seq -s, 5',
    'wc': "printf 'a b\\nc\\n' | wc",
    'awk': "awk 'BEGIN { printf \"%.4f\\n\", atan2(0, -1) }'",
    'col': "printf 'a\\bb\\n' | col -b",
    'cksum': 'printf abc | cksum',
    'crypto': 'printf abc | crypto sha256',
    'head': "printf '1\\n2\\n3\\n' | head -n 2",
    'mkdir': 'mkdir -p "$1/a/b" && [[ -d $1/a/b ]] && echo made',
}
checks = 0


def check(condition, *detail):
    global checks
    assert condition, detail
    checks += 1


def tool(script, *args, status=0, expect=None):
    result = subprocess.run([sys.executable, str(script), *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True, timeout=900)
    check(result.returncode == status, script.name, args, result.returncode, result.stdout, result.stderr)
    if expect is not None:
        check(expect in result.stdout + result.stderr, expect, result.stdout, result.stderr)
    return result


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


with tempfile.TemporaryDirectory(prefix='packages-') as directory:
    tmp = Path(directory)

    # The producer: every package built, gated, laid out as pkg expects, and
    # the same bytes on a second build.
    first, second = tmp / 'first', tmp / 'second'
    tool(BUILD, '--version', '1.0', '--out', first, *NAMES)
    report = [line.split('\t') for line in (first / 'build-report.tsv').read_text().splitlines()]
    check(sorted(row[0] for row in report) == sorted(NAMES) and all(row[1] == 'built' for row in report),
          report)
    records = (first / 'INDEX').read_text().splitlines()
    check(len(records) == len(NAMES), records)
    for record in records:
        fields = dict(word.split('=', 1) for word in record.split()[1:])
        name, package = fields['name'], first / fields['package']
        check(record.startswith('pkg-loadable-v1 ') and fields['deps'] == '-' and
              fields['sig'] == package.name + '.sig' and fields['arch'] == arch, record)
        check(sha256(package.read_bytes()) == fields['sha256'], record)
        with tarfile.open(package) as archive:
            members = archive.getmembers()
            check([(m.name, m.mode, m.mtime, m.uid, m.gid) for m in members] ==
                  [('MANIFEST', 0o644, 0, 0, 0), (f'loadable/{name}.so', 0o755, 0, 0, 0)], members)
            manifest = archive.extractfile('MANIFEST').read().decode()
            body = archive.extractfile(f'loadable/{name}.so').read()
        check(f'sha256: {sha256(body)}\n' in manifest and
              f'mode: /usr/lib/bash-os/loadables/{name}.so 0755\n' in manifest, manifest)
        shared = tmp / f'{name}.so'
        shared.write_bytes(body)
        needed = re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]',
                            subprocess.run(['readelf', '-d', str(shared)], capture_output=True, text=True).stdout)
        check(needed == (['libm.so.6'] if name == 'awk' else []), name, needed)
    tool(BUILD, '--version', '1.0', '--out', second, *NAMES)
    check(sorted(p.name for p in first.iterdir()) == sorted(p.name for p in second.iterdir()))
    for path in first.iterdir():
        check(path.read_bytes() == (second / path.name).read_bytes(), f'{path.name} is not reproducible')

    tool(BUILD, '--out', tmp / 'unknown', 'nosuchcommand', status=1,
         expect='not in config/bash-loadables.list')
    if (ROOT / 'out/bash-static').is_file():
        tool(BUILD, '--bash', ROOT / 'out/bash-static', '--out', tmp / 'static', 'seq', status=1,
             expect='statically linked')
    (tmp / 'stray').mkdir()
    (tmp / 'stray' / 'notes.txt').write_text('kept\n')
    tool(BUILD, '--out', tmp / 'stray', 'seq', status=1, expect='did not write')
    check((tmp / 'stray' / 'notes.txt').read_text() == 'kept\n')

    # The signer: a key that is never replaced, a flat signed release, and
    # refusals for a used directory and a package changed after its build.
    keys = tmp / 'keys'
    tool(SIGN, 'keygen', keys, 'publisher')
    check((keys / 'publisher.sec').stat().st_mode & 0o777 == 0o600)
    tool(SIGN, 'keygen', keys, 'publisher', status=1, expect='refusing to replace')
    release = tmp / 'release'
    tool(SIGN, 'release', '--key', keys / 'publisher.sec', '--out', release, first)
    packages = sorted(p.name for p in first.glob('*.pkg'))
    check(sorted(p.name for p in release.iterdir()) ==
          sorted(packages + [p + '.sig' for p in packages] + ['INDEX', 'INDEX.sig', 'SHA256SUMS']))
    for line in (release / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ')
        check(sha256((release / name).read_bytes()) == digest, line)
    tool(SIGN, 'release', '--key', keys / 'publisher.sec', '--out', release, first, status=1,
         expect='is not empty')
    tampered = tmp / 'tampered'
    shutil.copytree(first, tampered)
    with open(tampered / packages[0], 'ab') as handle:
        handle.write(b'\0')
    tool(SIGN, 'release', '--key', keys / 'publisher.sec', '--out', tmp / 'refused', tampered, status=1,
         expect='does not match the sha256')

    # pkg: update from the served release, install every package by name,
    # and run the builtins from the minimal shell.
    trusted = tmp / 'trusted'
    trusted.mkdir()
    shutil.copy(keys / 'publisher.pub', trusted)
    env = {'LC_ALL': 'C', 'HOME': str(tmp), 'BASHSIGNIFY_TRUSTED_KEYS_DIR': str(trusted),
           'BASHSIGNIFY_REVOKED_KEYS': str(tmp / 'no-revocations')}

    def pkg(script, *args, stdout=None):
        result = subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; ' + script, '_',
                                 *map(str, args)], capture_output=True, text=True, timeout=120, env=env)
        check(result.returncode == 0, script, result.returncode, result.stdout, result.stderr)
        check('warning' not in result.stderr, script, result.stderr)
        if stdout is not None:
            check(result.stdout == stdout, script, result.stdout, result.stderr)

    served = tmp / 'www'
    shutil.copytree(release, served / 'bash-os')
    server = http.server.ThreadingHTTPServer(
        ('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(served)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        sources = tmp / 'sources.list'
        sources.write_text(f'http://127.0.0.1:{server.server_address[1]}/bash-os\n')
        root = tmp / 'root'
        root.mkdir()
        pkg('pkg update --root "$1" --sources "$2" --remote-insecure', root, sources)
        for name in NAMES:
            pkg('pkg install "$3" --root "$1" --sources "$2"', root, sources, name)
    finally:
        server.shutdown()
    installed = root / 'usr/lib/bash-os/loadables'
    for name in NAMES:
        check((installed / f'{name}.so').stat().st_mode & 0o777 == 0o755, name)

    for name, body in CASES.items():
        results = []
        for runner, prefix in ((binary, ''), (shell, f'enable -f "$2/{name}.so" {name} || exit 99; ')):
            workdir = Path(tempfile.mkdtemp(dir=tmp))
            result = subprocess.run([runner, '--noprofile', '--norc', '-c', 'PATH=; ' + prefix + body,
                                     '_', str(workdir), str(installed)], capture_output=True, timeout=60)
            results.append((result.returncode, result.stdout))
        check(results[0] == results[1] and results[0][0] == 0, name, results)
    pkg('for n in sudo doas; do enable -f "$1/$n.so" $n; [[ $(type -t $n) == builtin ]] || exit 1; done',
        installed)
    pkg('pkg load seq --root "$1" && seq 2', root,
        stdout=f'loaded seq\tseq\t{installed}/seq.so\n1\n2\n')

    # The layout bash-os publishes: one signed INDEX naming each package by
    # URL in a release per architecture. The INDEX also lists a package for
    # another architecture, whose release is not served, so update succeeds
    # only if pkg leaves that record alone.
    foreign = tmp / 'foreign'
    foreign.mkdir()
    seq_package = next(first.glob('seq_*.pkg'))
    alien = foreign / seq_package.name.replace(f'_{arch}.pkg', '_alien.pkg')
    shutil.copy(seq_package, alien)
    (foreign / 'INDEX').write_text(
        f'pkg-loadable-v1 name=seq version=1.0 builtin=seq abi=bash-5.3 arch=alien '
        f'package={alien.name} sha256={sha256(alien.read_bytes())} sig={alien.name}.sig deps=-\n')
    hosted = tmp / 'hosted'
    hosted.mkdir()
    server = http.server.ThreadingHTTPServer(
        ('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(hosted)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        split = tmp / 'split'
        tool(SIGN, 'release', '--key', keys / 'publisher.sec', '--out', split,
             '--asset-url', f'http://127.0.0.1:{port}/packages-{{version}}-{{arch}}', first, foreign)
        check(sorted(p.name for p in split.iterdir()) == sorted(['INDEX', 'INDEX.sig', 'SHA256SUMS', 'alien', arch]))
        check(all(f' url=http://127.0.0.1:{port}/packages-1.0-' in line and ' package=' not in line
                  for line in (split / 'INDEX').read_text().splitlines()))
        shutil.copytree(split / arch, hosted / f'packages-1.0-{arch}')
        (hosted / 'packages').mkdir()
        for name in ('INDEX', 'INDEX.sig'):
            shutil.copy(split / name, hosted / 'packages' / name)
        split_sources = tmp / 'split-sources.list'
        split_sources.write_text(f'http://127.0.0.1:{port}/packages\n')
        split_root = tmp / 'split-root'
        split_root.mkdir()
        pkg('pkg update --root "$1" --sources "$2" --remote-insecure', split_root, split_sources)
        pkg('pkg install seq --root "$1" --sources "$2"', split_root, split_sources)
    finally:
        server.shutdown()
    check((split_root / 'usr/lib/bash-os/loadables/seq.so').read_bytes() == (installed / 'seq.so').read_bytes())

print(f'packages: {checks} checks passed')
