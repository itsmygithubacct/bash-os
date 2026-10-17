#!/usr/bin/env python3
"""Dependency cache hits require the recorded headers and archive contents."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_deps', ROOT / 'config/build-deps.py')
deps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deps)

with tempfile.TemporaryDirectory(prefix='deps-cache-test-') as directory:
    root = Path(directory)
    files = {'lib/libsample.a': b'archive', 'include/sample.h': b'header'}
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    identity = {'target': 'x86_64-test', 'ar': '/usr/bin/ar', 'ranlib': '/usr/bin/ranlib'}
    previous = {**identity, 'checksums': {
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    check = lambda: deps.cache_valid(root, previous, identity, ['libsample.a'])
    assert check()
    assert not deps.cache_valid(root, identity, identity, ['libsample.a']), 'legacy marker accepted'
    for name, data in files.items():
        path = root / name
        path.write_bytes(b'x' * len(data))
        assert not check(), f'changed {name} accepted'
        path.unlink()
        assert not check(), f'missing {name} accepted'
        path.write_bytes(data)
    assert not deps.cache_valid(root, previous, {**identity, 'ar': '/other/ar'}, ['libsample.a'])
    assert not deps.cache_valid(root, previous, identity, ['missing.a'])
    assert check()
print('dependency-cache: headers, archives, tool identity, and legacy marker invalidation verified')
