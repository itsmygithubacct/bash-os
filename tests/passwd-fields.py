#!/usr/bin/env python3
"""Keep empty passwd fields in their assigned columns."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())

with tempfile.TemporaryDirectory(prefix='bash-os-passwd-') as directory:
    root = Path(directory)
    (root / 'passwd').write_text(
        'alice:x:1000:1000::/srv/test-users/alice:/bin/bash\n'
        'bob:x:1001:1001:Bob:/srv/test-users/bob:\n'
        'malformed:x:1002:1002:only-six-fields\n')
    (root / 'shadow').write_text(
        'alice:!:20000:0:99999:7:::\n'
        'bob:!:20000:0:99999:7:::\n')
    environment = dict(os.environ, LC_ALL='C', TZ='UTC',
                       PHCLIB_PASSWD=str(root / 'passwd'),
                       PHCLIB_SHADOW=str(root / 'shadow'))

    def run(*args):
        result = subprocess.run(
            [binary, '--noprofile', '--norc', '-c', 'PATH=; "$@"', '_', *args],
            env=environment, capture_output=True, timeout=15)
        assert result.returncode == 0, (args, result.returncode, result.stderr)
        return result.stdout

    assert run('passwd', 'list', '-l') == (
        b'alice:1000:1000:/srv/test-users/alice:/bin/bash\n'
        b'bob:1001:1001:/srv/test-users/bob:\n')
    info = run('passwd', 'info', 'alice')
    assert b'home=/srv/test-users/alice shell=/bin/bash' in info, info
    info = run('passwd', 'info', 'bob')
    assert b'home=/srv/test-users/bob shell=/bin/bash' in info, info
    assert run('login', 'lookup', 'alice') == (
        b'1000:1000:/srv/test-users/alice:/bin/bash:\n')

print('passwd: empty fields and malformed records handled correctly')
