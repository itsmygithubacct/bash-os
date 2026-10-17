#!/usr/bin/env python3
"""A cache hit must leave a usable executable, manifest set, and configured tree."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_cache', ROOT / 'config/build-cache.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)

with tempfile.TemporaryDirectory(prefix='bashos-cache-test-') as directory:
    root = Path(directory)
    binary, tree = root / 'bash', root / 'tree'
    tree.mkdir()
    selection = {'names': ['seq'], 'list': 'seq|Print sequences\n', 'tag': 'sample'}
    files = {
        binary: b'complete executable\n',
        root / 'bash.stamp': b'input-stamp\n',
        root / 'bash.loadables.list': selection['list'].encode(),
        root / 'bash.manifest.txt': b'build record\n',
        tree / '.bash-os-stamp': b'input-stamp\n',
        **{tree / name: b'configured\n' for name in
           ('config.h', 'Makefile', 'builtins/Makefile', 'bash')},
    }
    files[root / 'bash.manifest.json'] = json.dumps({
        **selection, 'bytes': len(files[binary]),
        'binary_sha256': hashlib.sha256(files[binary]).hexdigest(),
    }).encode()
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    binary.chmod(0o700)
    check = lambda: cache.valid(binary, tree, 'input-stamp', selection)
    assert check()
    for path, data in files.items():
        path.unlink()
        assert not check(), f'missing {path.name} accepted'
        path.write_bytes(data)
        binary.chmod(0o700)
    for path, data in files.items():
        if path in (tree / name for name in ('config.h', 'Makefile', 'builtins/Makefile', 'bash')):
            continue
        path.write_bytes(b'')
        assert not check(), f'empty {path.name} accepted'
        path.write_bytes(data)
    binary.chmod(0o600)
    assert not check(), 'nonexecutable binary accepted'
    binary.chmod(0o700)
    binary.write_bytes(b'x' * len(files[binary]))
    assert not check(), 'changed binary of the same size accepted'
    binary.write_bytes(files[binary])
    (tree / '.bash-os-stamp').write_text('another-profile\n')
    assert not check(), 'tree from another build accepted'
    (tree / '.bash-os-stamp').write_bytes(files[tree / '.bash-os-stamp'])
    assert not cache.valid(binary, tree, 'input-stamp', {**selection, 'names': []})
    assert check()
print('build-cache: missing outputs, corruption, executable mode, and tree identity verified')
