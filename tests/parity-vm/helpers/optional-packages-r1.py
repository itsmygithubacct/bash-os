#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Stage and verify the optional bashperl, bashpython and uv packages.

The packages are built outside the repository (docs/packages.md) and are not
tracked. A fixture run receives them through `vm.py run --references DIR`:

    DIR/optional-packages/packages/NAME_VERSION_ARCH.pkg   the packages as built
    DIR/optional-packages/packages/INDEX                   build-packages.sh's index
    DIR/optional-packages/root/                            bashpython and uv as `pkg install --root` leaves them

which the guest sees under /opt/bashos-parity/reference-data. The tracked
optional-packages-r1.lock.json beside this file pins every package, loadable
and installed tree by size and SHA-256. bashperl is staged as a package only:
its module path is compiled in, so it runs only when installed at the default
root, and the lock records the tree that installation must produce.

    optional-packages-r1.py stage --packages OUT --dest DIR [--write-lock]
        Host only. Copy the packages from OUT (build-packages.sh's output
        directory), unpack each into DIR/optional-packages/root, and compare
        the result with the lock. --write-lock records a new build instead.
    optional-packages-r1.py verify [--dest DIR] [NAME ...]
        Host or guest. Recompute sizes and digests for NAME (default: every
        package) and exit 98 with a CONTROL-FAILED line on any difference.

Neither command runs a package, a loadable or the candidate shell. `stage`
reads only archive members named by MANIFEST and refuses anything else.
"""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import shutil
import sys
import tarfile

HERE = Path(__file__).resolve().parent
LOCK = HERE / 'optional-packages-r1.lock.json'
GUEST = Path('/opt/bashos-parity/reference-data')
NAMES = ('bashperl', 'bashpython', 'uv')
ROOTED = ('bashpython', 'uv')
PREFIX = 'usr/lib/bash-os'
STATE = 'var/lib/pkg/installed'
CONTROL = 98


class Problem(Exception):
    pass


def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pinned(path):
    if path.is_symlink() or not path.is_file():
        raise Problem(f'{path}: missing or not a regular file')
    return {'bytes': path.stat().st_size, 'sha256': file_digest(path)}


def installed_files(root, name):
    """Every file one package owns under an installed root, as sorted lock lines."""
    owned = [root / PREFIX / 'loadables' / f'{name}.so']
    for top in ('libexec', 'share'):
        base = root / PREFIX / top / name
        if base.is_symlink():
            raise Problem(f'{base}: symbolic link')
        if base.is_dir():
            owned += sorted(base.rglob('*'))
    state = root / STATE / name
    if state.is_dir():
        owned += sorted(state.rglob('*'))
    lines, size = [], 0
    for path in owned:
        if path.is_symlink():
            raise Problem(f'{path}: symbolic link')
        if path.is_dir():
            continue
        if not path.is_file():
            raise Problem(f'{path}: missing or not a regular file')
        info = path.stat()
        size += info.st_size
        mode = '0755' if info.st_mode & 0o111 else '0644'
        lines.append(f'{path.relative_to(root).as_posix()} {mode} {info.st_size} {file_digest(path)}\n')
    return sorted(lines), size


def describe(root, name, package):
    lines, size = installed_files(root, name)
    return {'package': {'name': f'packages/{package.name}', **pinned(package)},
            'loadable': {'name': f'{PREFIX}/loadables/{name}.so', **pinned(root / PREFIX / 'loadables' / f'{name}.so')},
            'installed': {'files': len(lines), 'bytes': size,
                          'tree_sha256': hashlib.sha256(''.join(lines).encode()).hexdigest()}}


def manifest_fields(text):
    fields, data = {}, []
    for line in text.splitlines():
        key, separator, value = line.partition(': ')
        if not separator:
            raise Problem('MANIFEST: malformed line')
        if key == 'data':
            path, mode, digest = value.split(' ')
            data.append((path, int(mode, 8), digest))
        else:
            fields[key] = value
    return fields, data


def unpack(package, name, root):
    """Lay one package out under ROOT as `pkg install --root ROOT` does."""
    raw = package.read_bytes()
    if raw[:6] == b'\xfd7zXZ\x00':
        raw = lzma.decompress(raw, format=lzma.FORMAT_XZ)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = {member.name: member for member in archive}
        if len(members) != len(archive.getmembers()) or not all(m.isfile() for m in members.values()):
            raise Problem(f'{package.name}: duplicate or non-regular members')
        manifest = archive.extractfile(members['MANIFEST']).read()
        fields, data = manifest_fields(manifest.decode())
        loadable = f'loadable/{name}.so'
        if (fields.get('name') != name or fields.get('builtin') != name or fields.get('type') != 'loadable'
                or set(members) != {'MANIFEST', loadable, *(path for path, _, _ in data)}):
            raise Problem(f'{package.name}: MANIFEST does not describe the archive')
        body = archive.extractfile(members[loadable]).read()
        if hashlib.sha256(body).hexdigest() != fields['sha256']:
            raise Problem(f'{package.name}: loadable digest differs from MANIFEST')
        outputs = [(root / PREFIX / 'loadables' / f'{name}.so', body, 0o755)]
        for path, mode, digest in data:
            parts = Path(path).parts
            if (len(parts) < 3 or parts[0] not in ('libexec', 'share') or parts[1] != name
                    or '..' in parts or mode not in (0o644, 0o755)):
                raise Problem(f'{package.name}: unexpected data path or mode: {path}')
            content = archive.extractfile(members[path]).read()
            if hashlib.sha256(content).hexdigest() != digest or members[path].mode != mode:
                raise Problem(f'{package.name}: {path} differs from MANIFEST')
            outputs.append((root / PREFIX / path, content, mode))
        outputs += [(root / STATE / name / 'MANIFEST', manifest, 0o644),
                    (root / STATE / name / 'sha256', fields['sha256'].encode(), 0o644)]
    for path, content, mode in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
    return fields


def stage(args):
    base = args.dest / 'optional-packages'
    if base.exists():
        if not (base / 'packages').is_dir() or not (base / 'root').is_dir():
            raise Problem(f'{base}: not a staging directory this tool wrote')
        shutil.rmtree(base)
    (base / 'packages').mkdir(parents=True)
    index = args.packages / 'INDEX'
    shutil.copyfile(index, base / 'packages/INDEX')
    lock = {'schema': 1, 'guest': str(GUEST / 'optional-packages'), 'packages': {}}
    for name in NAMES:
        found = sorted(args.packages.glob(f'{name}_*.pkg'))
        if len(found) != 1:
            raise Problem(f'{args.packages}: expected exactly one {name}_VERSION_ARCH.pkg')
        package = base / 'packages' / found[0].name
        shutil.copyfile(found[0], package)
        root = base / ('root' if name in ROOTED else 'unstaged')
        fields = unpack(package, name, root)
        if file_digest(package) not in index.read_text():
            raise Problem(f'{package.name}: INDEX does not list this package')
        lock['packages'][name] = {'version': fields['version'], 'arch': fields['arch'], 'abi': fields['abi'],
                                  'staged_root': name in ROOTED, **describe(root, name, package)}
    shutil.rmtree(base / 'unstaged')
    lock['index'] = {'name': 'packages/INDEX', **pinned(base / 'packages/INDEX')}
    for path in (base, *base.rglob('*')):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    if args.write_lock:
        LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + '\n')
        print(f'optional-packages: wrote {LOCK.name}')
    elif lock != json.loads(LOCK.read_text()):
        raise Problem(f'{base}: staged packages differ from {LOCK.name}; rebuild notes are in docs/parity-vm.md')
    total = sum(path.stat().st_size for path in base.rglob('*') if path.is_file())
    print(f'optional-packages: staged {", ".join(NAMES)} in {base} ({total} bytes)')


def verify(dest, names):
    lock = json.loads(LOCK.read_text())
    base = dest / 'optional-packages'
    if not base.is_dir():
        raise Problem(f'{base}: not staged; pass the staging directory with vm.py run --references')
    unknown = [name for name in names if name not in lock['packages']]
    if unknown:
        raise Problem('not in the lock: ' + ', '.join(unknown))
    for name in names or sorted(lock['packages']):
        expected = lock['packages'][name]
        package = base / expected['package']['name']
        if expected['staged_root']:
            actual = describe(base / 'root', name, package)
        else:
            actual = {'package': {'name': expected['package']['name'], **pinned(package)}}
        for part in actual:
            if actual[part] != expected[part]:
                raise Problem(f'{name}: {part} differs from the lock: expected {expected[part]}, found {actual[part]}')
    if not names and pinned(base / lock['index']['name']) != {k: lock['index'][k] for k in ('bytes', 'sha256')}:
        raise Problem('packages/INDEX differs from the lock')
    return lock


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    staging = commands.add_parser('stage')
    staging.add_argument('--packages', type=Path, required=True)
    staging.add_argument('--dest', type=Path, required=True)
    staging.add_argument('--write-lock', action='store_true')
    checking = commands.add_parser('verify')
    checking.add_argument('--dest', type=Path, default=GUEST)
    checking.add_argument('names', nargs='*')
    args = parser.parse_args()
    try:
        if args.command == 'stage':
            stage(args)
        else:
            lock = verify(args.dest, args.names)
            for name in args.names or sorted(lock['packages']):
                print(f'optional-packages: {name} {lock["packages"][name]["version"]} matches the lock')
    except (Problem, OSError, KeyError, ValueError, tarfile.TarError, lzma.LZMAError) as problem:
        print(f'CONTROL-FAILED optional packages: {problem}', file=sys.stderr)
        return CONTROL
    return 0


if __name__ == '__main__':
    sys.exit(main())
