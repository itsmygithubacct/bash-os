#!/usr/bin/env python3
"""uv publication preserves unrelated data and a working tree on failure."""
import importlib.util
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fetch_uv', ROOT / 'config/fetch-uv.py')
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)

with tempfile.TemporaryDirectory(prefix='fetch-uv-test-') as directory:
    root = Path(directory)
    out = root / 'out'
    target = fetch.publish(b'old program', out)
    assert target.read_bytes() == b'old program' and target.stat().st_mode & 0o777 == 0o755
    fetch.publish(b'updated program', out)
    assert target.read_bytes() == b'updated program'

    note = out / 'notes.txt'
    note.write_text('keep me')
    try:
        fetch.publish(b'bad update', out)
    except SystemExit as error:
        assert 'unmanaged output' in str(error)
    else:
        raise AssertionError('unrelated output was replaced')
    assert note.read_text() == 'keep me' and target.read_bytes() == b'updated program'
    note.unlink()

    linked = root / 'linked'
    linked.symlink_to(out, target_is_directory=True)
    try:
        fetch.publish(b'bad update', linked)
    except SystemExit as error:
        assert 'unmanaged output' in str(error)
    else:
        raise AssertionError('symlink output was replaced')
    assert linked.is_symlink() and target.read_bytes() == b'updated program'

    original = Path.rename
    def rename(path, destination):
        if path.name == 'data':
            raise OSError('injected publication failure')
        return original(path, destination)
    with patch.object(Path, 'rename', rename):
        try:
            fetch.publish(b'bad update', out)
        except OSError as error:
            assert str(error) == 'injected publication failure'
        else:
            raise AssertionError('publication failure was lost')
    assert target.read_bytes() == b'updated program'
    assert not list(root.glob('.uv-*'))
print('fetch-uv: replacement, unmanaged output, symlink refusal, and rollback verified')
