#!/usr/bin/env python3
"""Keep empty passwd fields in their assigned columns."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())

with tempfile.TemporaryDirectory(prefix='bash-os-passwd-') as directory:
    root = Path(directory)
    (root / 'passwd').write_text(
        'alice:x:1000:1000::/srv/test-users/alice:/bin/bash\n'
        'bob:x:1001:1001:Bob:/srv/test-users/bob:\n'
        'malformed:x:1002:1002:only-six-fields\n'
        'emptyuid:x::100::/srv/test-users/empty:/bin/sh\n'
        'emptygid:x:101:::/srv/test-users/emptyg:/bin/sh\n'
        'baduid:x:abc:100::/srv/test-users/bad:/bin/sh\n'
        'rootish:x:0:0:root:/root:/bin/sh\n')
    (root / 'shadow').write_text(
        'alice:!:20000:0:99999:7:::\n'
        'bob:!:20000:0:99999:7:::\n'
        'emptyuid:!:20000:0:99999:7:::\n'
        'emptygid:!:20000:0:99999:7:::\n'
        'baduid:!:20000:0:99999:7:::\n'
        'rootish:!:20000:0:99999:7:::\n')
    environment = dict(os.environ, LC_ALL='C', TZ='UTC',
                       PHCLIB_PASSWD=str(root / 'passwd'),
                       PHCLIB_SHADOW=str(root / 'shadow'))

    def run(*args, rc=0):
        script = 'PATH=; "$@"'
        if module := os.environ.get('PASSWD_TEST_LOADABLE'):
            script = 'enable -f ' + shlex.quote(module) + ' passwd || exit; ' + script
        result = subprocess.run(
            [binary, '--noprofile', '--norc', '-c', script, '_', *args],
            env=environment, capture_output=True, timeout=15)
        assert result.returncode == rc, (args, result.returncode, result.stderr, result.stdout)
        return result.stdout

    assert run('passwd', 'list', '-l') == (
        b'alice:1000:1000:/srv/test-users/alice:/bin/bash\n'
        b'bob:1001:1001:/srv/test-users/bob:\n'
        b'emptyuid::100:/srv/test-users/empty:/bin/sh\n'
        b'emptygid:101::/srv/test-users/emptyg:/bin/sh\n'
        b'baduid:abc:100:/srv/test-users/bad:/bin/sh\n'
        b'rootish:0:0:/root:/bin/sh\n')
    info = run('passwd', 'info', 'alice')
    assert b'home=/srv/test-users/alice shell=/bin/bash' in info, info
    info = run('passwd', 'info', 'bob')
    assert b'home=/srv/test-users/bob shell=/bin/bash' in info, info
    assert run('login', 'lookup', 'alice') == (
        b'1000:1000:/srv/test-users/alice:/bin/bash:\n')
    # An empty or non-numeric id is not uid 0 or gid 0.
    assert b'uid=0' not in run('passwd', 'info', 'emptyuid', rc=1)
    assert b'gid=0' not in run('passwd', 'info', 'emptygid', rc=1)
    assert b'uid=0' not in run('passwd', 'info', 'baduid', rc=1)
    rootish = run('passwd', 'info', 'rootish')
    assert b'uid=0 gid=0' in rootish, rootish

print('passwd: empty fields and malformed records handled correctly')
