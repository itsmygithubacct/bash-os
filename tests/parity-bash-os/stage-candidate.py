#!/usr/bin/env python3
"""Stage the compiled candidate and interpreter runtime data without executing it."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path('/src')
IMAGE = Path('/image')
spec = importlib.util.spec_from_file_location('catalog', ROOT / 'config/loadables.py')
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
full = catalog.parse_list(ROOT / 'config/bash-loadables.list')
optional = catalog.parse_list(ROOT / 'config/bash-loadables-optional.list')
manifest = json.loads((ROOT / 'out/bash-parity-static.manifest.json').read_text())
assert set(manifest['names']) == full.keys() | optional.keys()
assert manifest['static'] is True
binary = ROOT / 'out/bash-parity-static'
assert 'INTERP' not in subprocess.check_output(['readelf', '-l', str(binary)], text=True)
assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest['binary_sha256']


def copy(source, target):
    target = IMAGE / str(target).lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o644)
    return target


copy(binary, '/bin/bash-os').chmod(0o755)
for name in ('bash', 'sh'):
    (IMAGE / 'bin' / name).symlink_to('bash-os')
commands = IMAGE / 'usr/lib/bash-os/bin'
commands.mkdir(parents=True)
for name in ('bash', 'sh', 'bash-os'):
    (commands / name).symlink_to('/bin/bash-os')
copy(ROOT / 'out/bash-parity-static.loadables.list', '/usr/share/bash-os/loadables.list')
for script in ('inventory.sh', 'smoke.sh'):
    copy(ROOT / 'tests/parity-bash-os' / script, '/usr/share/bash-os/' + script)
copy(ROOT / 'config/bash-loadables.list', '/usr/share/bash-os/catalog/full.list')
copy(ROOT / 'config/bash-loadables-optional.list', '/usr/share/bash-os/catalog/optional.list')
copy(ROOT / 'config/versions.sh', '/usr/share/bash-os/catalog/versions.sh')
for name in ('perl', 'python', 'uv'):
    copy(ROOT / f'config/{name}.json', f'/usr/share/bash-os/catalog/{name}.json')

# Perl's compiled-in @INC uses this exact prefix. Only build archives are omitted.
shutil.copytree('/usr/lib/bash-os/perl/lib', IMAGE / 'usr/lib/bash-os/perl/lib',
                symlinks=True, ignore=shutil.ignore_patterns('*.a', '*.o'))
# The package runtime data uses the same CPython home embedded in bash-os.
shutil.copytree('/usr/lib/bash-os/python/data/share/bashpython',
                IMAGE / 'usr/lib/bash-os/python', symlinks=True)
copy('/uv-data/libexec/uv/uv', '/usr/lib/bash-os/libexec/uv/uv').chmod(0o755)
for name in ('perl', 'python'):
    shutil.copytree(f'/usr/lib/bash-os/{name}/share/licenses/{name}',
                    IMAGE / f'usr/share/doc/bash-os/{name}')
shutil.copytree('/build-deps/share/licenses', IMAGE / 'usr/share/doc/bash-os/dependencies')
copy(ROOT / 'LICENSE', '/usr/share/doc/bash-os/LICENSE')
copy(ROOT / 'docs/PROVENANCE.md', '/usr/share/doc/bash-os/PROVENANCE.md')
copy(ROOT / 'docs/sol-sed-regex-LGPL-2.1.txt', '/usr/share/doc/bash-os/sed-regex-LGPL-2.1.txt')
versions = (ROOT / 'config/versions.sh').read_text()
version = re.search(r'^BASH_SRC_VERSION=([0-9.]+)$', versions, re.M).group(1)
copy(ROOT / f'build/bash-{version}/COPYING', '/usr/share/doc/bash-os/GNU-BASH-COPYING')
for path in (ROOT / 'loadables').rglob('*'):
    if path.is_file() and any(word in path.name.lower() for word in ('license', 'copying', 'notice', 'artistic')):
        copy(path, '/usr/share/doc/bash-os/' + str(path.relative_to(ROOT)))
os_release = f'NAME="bash-os parity userland"\nID=bash-os\nVERSION_ID="{manifest["bashos_version"]}"\n'
os_file = IMAGE / 'usr/lib/os-release'
os_file.parent.mkdir(parents=True, exist_ok=True)
os_file.write_text(os_release)
(IMAGE / 'etc').mkdir(exist_ok=True)
(IMAGE / 'etc/os-release').symlink_to('../usr/lib/os-release')
receipt = {'schema': 1, 'qualification': 'source build and catalog accounting; behavioral parity is separate',
           'project_version': manifest['bashos_version'], 'target': manifest['target'],
           'binary_sha256': manifest['binary_sha256'], 'binary_bytes': manifest['bytes'],
           'full_count': len(full), 'optional_count': len(optional), 'names': manifest['names'],
           'inputs_sha256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in sorted(set([ROOT / 'Dockerfile.parity-bash-os', ROOT / 'VERSION',
                                                      *ROOT.glob('build*.sh'),
                                                      *(ROOT / 'config').rglob('*'),
                                                      *(ROOT / 'patches').rglob('*'),
                                                      *(ROOT / 'loadables').rglob('*'),
                                                      *(ROOT / 'tests/parity-bash-os').rglob('*')]))
                             if path.is_file() and '__pycache__' not in path.parts}}
(IMAGE / 'usr/share/bash-os/build.json').write_text(json.dumps(receipt, indent=2)+'\n')
# Source files can have a private checkout umask; runtime data must be readable.
for path in IMAGE.rglob('*'):
    if not path.is_symlink():
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
