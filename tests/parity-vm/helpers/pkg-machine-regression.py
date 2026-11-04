#!/usr/bin/python3
"""Create signed machine-mismatch controls inside the parity VM only."""
import hashlib
from pathlib import Path
import sys
import tarfile

# Reuse the VM guard, independent archive encoder and signing controls.
sys.path.insert(0, '/opt/bashos-parity/harness/helpers')
import importlib.util
spec = importlib.util.spec_from_file_location('pkg_fixture', '/opt/bashos-parity/harness/helpers/transfer-pkg-fixtures-r2.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.require_guest()
base = fixture.BASE
elf = (base / 'probe.so').read_bytes()
identity = (base / 'publisher.key', base / 'publisher.der', fixture.KEYID, b'')
for name, machine, arch in [('bad-machine-any', 183, 'any'),
                             ('bad-machine-zero', 0, None)]:
    body = bytearray(elf)
    body[18:20] = machine.to_bytes(2, 'little')
    body = bytes(body)
    mf = fixture.manifest(body, arch=arch)
    target = base / (name + '.pkg')
    fixture.archive(target, [('MANIFEST', mf, 0o644),
                             ('loadable/fixtureprobe.so', body, 0o755)])
    fixture.sign(target, identity)
    with tarfile.open(target, 'r:') as tar:
        actual = tar.extractfile('loadable/fixtureprobe.so').read()
        manifest = tar.extractfile('MANIFEST').read()
    assert int.from_bytes(actual[18:20], 'little') == machine
    assert hashlib.sha256(actual).hexdigest().encode() in manifest
    if arch:
        assert ('arch: ' + arch + '\n').encode() in manifest
