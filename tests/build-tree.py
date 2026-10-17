#!/usr/bin/env python3
"""A published configured tree must rebuild without its former staging directory."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('relocate_build', ROOT / 'config/relocate-build.py')
relocator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relocator)

with tempfile.TemporaryDirectory(prefix='bashos-relocation-test-') as directory:
    root = Path(directory)
    source, destination = root / '.stage/bash-5.3', root / 'bash-5.3'
    source.mkdir(parents=True)
    (source / 'config.h').write_text('configured header\n')
    (source / 'bashversion').write_text('#!/bin/sh\nprintf "version ok\\n"\n')
    (source / 'bashversion').chmod(0o700)
    contents = f'BUILD_DIR = {source}\nall: $(BUILD_DIR)/config.h\n\t@$(BUILD_DIR)/bashversion\n'
    for name in ('Makefile', 'lib/sh/Makefile', 'po/Makefile.in', 'examples/loadables/Makefile.inc'):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    # Its generated config.status is itself a recipe for a future Makefile.
    (source / 'config.status').write_text(f"#!/bin/sh\ncat > Makefile <<'END'\n{contents}END\n")
    (source / 'bash').write_bytes(b'unchanged binary\0' + str(source).encode())
    timestamp = (source / 'Makefile').stat().st_mtime_ns
    relocator.relocate(source, destination)
    assert (source / 'Makefile').stat().st_mtime_ns == timestamp
    assert (source / 'bash').read_bytes() == b'unchanged binary\0' + str(source).encode()
    source.rename(destination)
    source.parent.rmdir()
    for generated in destination.rglob('Makefile*'):
        assert str(source) not in generated.read_text()
    for regenerate in (False, True):
        if regenerate:
            subprocess.run(['sh', 'config.status'], cwd=destination, check=True)
        result = subprocess.run(['make', '--no-print-directory'], cwd=destination,
                                capture_output=True, text=True)
        assert result.returncode == 0 and result.stdout == 'version ok\n', result
print('build-tree: relocated Makefiles, config.status regeneration, and binary preservation verified')
