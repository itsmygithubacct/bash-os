#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check optional interpreter cache integrity, with optional real prefixes."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'config'))
import installation_cache

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--perl-prefix', type=Path)
parser.add_argument('--python-prefix', type=Path)
args = parser.parse_args()
target = subprocess.check_output([os.environ.get('CC', 'cc'), '-dumpmachine'], text=True).strip()
checks = 0


def check_flags(kind, prefix, good=True):
    global checks
    result = subprocess.run([sys.executable, str(ROOT/f'config/build-{kind}.py'),
                             '--prefix', str(prefix), '--flags'],
                            capture_output=True, text=True, timeout=120)
    assert (result.returncode == 0) == good, (kind, result.returncode, result.stdout, result.stderr)
    assert 'Traceback' not in result.stderr, result.stderr
    checks += 1
    if good:
        # These records go into a single exported environment variable.
        assert len(result.stdout.encode()) < 65536, len(result.stdout)
        return json.loads(result.stdout)


@contextmanager
def saved(path):
    """Move the original aside so even hardlinks and metadata survive a test."""
    with tempfile.TemporaryDirectory(prefix='.interpreter-cache-', dir=path.parent) as directory:
        backup = Path(directory)/'original'
        path.rename(backup)
        try:
            yield backup
        finally:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
            backup.rename(path)


def damage_files(kind, prefix, names):
    for name in names:
        path = prefix/name
        with saved(path) as backup:
            check_flags(kind, prefix, False)
            data = backup.read_bytes()
            # Same-size corruption must also be detected.
            path.write_bytes(bytes([data[0] ^ 1])+data[1:] if data else b'x')
            path.chmod(backup.stat().st_mode & 0o7777)
            check_flags(kind, prefix, False)
        check_flags(kind, prefix)


with tempfile.TemporaryDirectory(prefix='interpreter-cache-test-') as directory:
    for kind in ('perl', 'python'):
        prefix = Path(directory)/kind
        files = {'lib/runtime.a': b'archive', 'include/extra.h': b'header',
                 'share/licenses/LICENSE': b'notice', 'bin/runtime': b'program',
                 'lib/stdlib/encoding/module': b'stdlib',
                 'data/share/stdlib/encoding/module': b'package data'}
        for name, data in files.items():
            path = prefix/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (prefix/'bin/runtime').chmod(0o755)
        (prefix/'bin/interpreter').symlink_to('runtime')
        (prefix/'lib/empty').mkdir()
        marker_name = f'bash-os-{kind}.json'
        marker = prefix/marker_name
        record = dict(identity=dict(target=target), flags={}, config={}, checksums={
            'lib/runtime.a': hashlib.sha256(files['lib/runtime.a']).hexdigest()})
        # Old records cover archives but omit modules and package data.
        marker.write_text(json.dumps(record))
        check_flags(kind, prefix, False)
        record['installation'] = installation_cache.write_manifest(prefix, marker_name)
        marker.write_text(json.dumps(record))
        check_flags(kind, prefix)
        damage_files(kind, prefix, files)
        for name in ('bin/interpreter', 'lib/empty'):
            with saved(prefix/name):
                check_flags(kind, prefix, False)
            check_flags(kind, prefix)
        with saved(prefix/'bin/interpreter'):
            (prefix/'bin/interpreter').symlink_to('../lib/runtime.a')
            check_flags(kind, prefix, False)
        with saved(prefix/'lib/stdlib') as backup:
            (prefix/'lib/stdlib').symlink_to(backup, target_is_directory=True)
            check_flags(kind, prefix, False)
        (prefix/'bin/runtime').chmod(0o644)
        check_flags(kind, prefix, False)
        (prefix/'bin/runtime').chmod(0o755)
        # Imports may create new bytecode, and users may add modules.
        (prefix/'lib/stdlib/__pycache__').mkdir()
        (prefix/'lib/stdlib/__pycache__/new.pyc').write_bytes(b'generated')
        check_flags(kind, prefix)
        manifest = prefix/installation_cache.MANIFEST
        damage_files(kind, prefix, [manifest.name, marker.name])
        with saved(manifest) as backup:
            changed = json.loads(backup.read_text())
            changed['entries']['../outside'] = changed['entries'].pop('lib/runtime.a')
            manifest.write_text(json.dumps(changed))
            old_marker = marker.read_bytes()
            record['installation']['sha256'] = installation_cache.digest(manifest)
            marker.write_text(json.dumps(record))
            check_flags(kind, prefix, False)
            marker.write_bytes(old_marker)
        check_flags(kind, prefix)

for kind, prefix in (('perl', args.perl_prefix), ('python', args.python_prefix)):
    if prefix is None:
        continue
    prefix = prefix.resolve()
    record = check_flags(kind, prefix)
    if kind == 'perl':
        stdlib = Path(record['config']['privlib']).relative_to(prefix)
        names = [stdlib/'JSON/PP.pm', stdlib/'unicore/version',
                 Path(record['config']['archlib']).relative_to(prefix)/'CORE/embed.h',
                 Path('share/licenses/perl/Artistic')]
    else:
        version = '.'.join(record['identity']['package']['version'].split('.')[:2])
        names = [Path(f'lib/python{version}/json/__init__.py'),
                 Path(f'data/share/bashpython/lib/python{version}/json/__init__.py'),
                 Path(f'include/python{version}/object.h'), Path('share/licenses/python/LICENSE')]
    damage_files(kind, prefix, names)
    check_flags(kind, prefix)

print(f'interpreter-cache: {checks} checks passed')
