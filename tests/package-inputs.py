#!/usr/bin/env python3
"""Producer boundaries: package data, release identity, and all-or-nothing signing."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'config' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


producer, signer = load('build-packages'), load('sign-packages')
checks = 0


def refuse(call, message):
    global checks
    try:
        call()
    except SystemExit as error:
        assert message in str(error), (message, error)
    else:
        raise AssertionError('invalid input was accepted')
    checks += 1


with tempfile.TemporaryDirectory(prefix='package-inputs-') as directory:
    root = Path(directory)
    data = root / 'data'
    (data / 'share/seq').mkdir(parents=True)
    (data / 'share/seq/readme').write_text('regular data\n')
    assert producer.data_members('seq', data) == [('share/seq/readme', b'regular data\n', 0o644)]
    for name in ('has space', 'has\nnewline', 'has\ttab', 'has\x7fdelete'):
        bad = data / 'share/seq' / name
        bad.write_text('bad manifest name')
        refuse(lambda: producer.data_members('seq', data), 'MANIFEST paths')
        bad.unlink()
    for relative in ('', 'share', 'share/seq'):
        current = data / relative
        moved = root / 'saved'
        current.rename(moved)
        current.symlink_to(moved, target_is_directory=True)
        refuse(lambda: producer.data_members('seq', data), '--data')
        current.unlink()
        moved.rename(current)
    bad = data / 'share/seq/link'
    bad.symlink_to(data / 'share/seq/readme')
    refuse(lambda: producer.data_members('seq', data), 'only regular files')
    bad.unlink()
    bad = data / 'share/seq/fifo'
    os.mkfifo(bad)
    refuse(lambda: producer.data_members('seq', data), 'only regular files')
    bad.unlink()
    bad = data / 'libexec'
    bad.write_text('not a directory')
    refuse(lambda: producer.data_members('seq', data), 'only libexec/seq/')
    bad.unlink()

    keys, source = root / 'keys', root / 'source'
    source.mkdir()
    with redirect_stdout(io.StringIO()):
        signer.keygen(keys, 'publisher')
    key = keys / 'publisher.sec'
    assert key.stat().st_mode & 0o777 == 0o600
    (keys / 'linked.pub').symlink_to(root / 'absent')
    refuse(lambda: signer.keygen(keys, 'linked'), 'refusing to replace')
    assert not (keys / 'linked.sec').exists() and not (root / 'absent').exists()

    def record(name, version='1.0~rc1', package=None, body=b'fixture object'):
        filename = package or f'{name}_{version}_x86_64.pkg'
        (source / filename).write_bytes(body)
        return (f'pkg-loadable-v1 name={name} version={version} builtin={name} '
                f'abi=bash-5.3 arch=x86_64 package={filename} '
                f'sha256={hashlib.sha256(body).hexdigest()} sig={filename}.sig deps=-\n')

    valid = record('seq')
    (source / 'INDEX').write_text(valid)
    mask = os.umask(0o027)
    try:
        with redirect_stdout(io.StringIO()):
            signer.release(key, root / 'release', [source], 'https://example.test/{version}/{arch}')
    finally:
        os.umask(mask)
    release = root / 'release'
    assert release.stat().st_mode & 0o777 == 0o750
    assert (release / 'INDEX').stat().st_mode & 0o777 == 0o640
    assert 'url=https://example.test/1.0~rc1/x86_64/' in (release / 'INDEX').read_text()
    assert (release / '1.0~rc1-x86_64/seq_1.0~rc1_x86_64.pkg.sig').is_file()

    # Fail after one package has been written: no incomplete public release.
    bad = record('wc')
    (source / 'wc_1.0~rc1_x86_64.pkg').write_bytes(b'changed')
    (source / 'INDEX').write_text(valid + bad)
    for existing in (False, True):
        out = root / ('empty' if existing else 'missing')
        if existing:
            out.mkdir(mode=0o750)
            out.chmod(0o750)
        refuse(lambda: signer.release(key, out, [source]), 'does not match the sha256')
        assert out.is_dir() == existing
        if existing:
            assert not list(out.iterdir()) and out.stat().st_mode & 0o777 == 0o750
    assert not list(root.glob('.release-*'))

    (source / 'INDEX').write_text(valid + record('wc', package='seq_1.0~rc1_x86_64.pkg'))
    refuse(lambda: signer.release(key, root / 'collision', [source]), 'package must be named')
    assert not (root / 'collision').exists()
    (source / 'INDEX').write_text(valid + valid)
    refuse(lambda: signer.release(key, root / 'duplicate', [source]), 'a second seq package')
    assert not (root / 'duplicate').exists()

print(f'package-inputs: {checks} refusal cases, valid data, tilde versions, and umask preserved')
