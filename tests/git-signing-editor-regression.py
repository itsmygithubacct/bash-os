#!/usr/bin/env python3
"""Guest-only reference comparison for OpenPGP signing and editor failure."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = {**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
       'GIT_AUTHOR_NAME': 'Author', 'GIT_AUTHOR_EMAIL': 'author@example.test',
       'GIT_COMMITTER_NAME': 'Committer', 'GIT_COMMITTER_EMAIL': 'committer@example.test',
       'GIT_AUTHOR_DATE': '1750000000 +0000', 'GIT_COMMITTER_DATE': '1750000100 +0000'}

with tempfile.TemporaryDirectory(prefix='sign-editor-') as temp:
    root = Path(temp)
    signer = root / 'fake-gpg'
    signer.write_text('''#!/bin/sh
printf '%s\\n' "$@" > "$CAPTURE.args"
cat > "$CAPTURE.payload"
printf '[GNUPG:] SIG_CREATED D 1 8 00 0 TESTKEY\\n' >&2
printf '%s\\n' '-----BEGIN PGP SIGNATURE-----' '' 'ZmFrZQ==' '-----END PGP SIGNATURE-----'
''')
    signer.chmod(0o755)
    results = []
    for candidate in (False, True):
        repo = root / ('candidate' if candidate else 'reference')
        repo.mkdir()
        child_env = {**env, 'HOME': str(repo), 'CAPTURE': str(repo / 'capture')}
        def run(*args):
            command = ([binary, '--noprofile', '--norc', '-c', 'git "$@"', 'git']
                       if candidate else ['git'])
            return subprocess.run(command + list(args), cwd=repo, env=child_env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert run('init', '-q', '-b', 'main').returncode == 0
        (repo / 'file').write_text('content\n')
        assert run('add', 'file').returncode == 0
        result = run('-c', 'gpg.format=openpgp', '-c', f'gpg.program={signer}',
                     '-c', 'user.signingkey=fixture-key', 'commit', '-q', '-S', '-m', 'signed')
        assert result.returncode == 0, (candidate, result.stderr)
        obj = run('cat-file', 'commit', 'HEAD')
        assert obj.returncode == 0
        capture = repo / 'capture'
        args = capture.with_suffix('.args').read_bytes()
        payload = capture.with_suffix('.payload').read_bytes()
        (repo / 'file').write_text('changed\n')
        assert run('add', 'file').returncode == 0
        failed = run('-c', 'core.editor=false', 'commit')
        failed_signer = root / 'failed-gpg'
        failed_signer.write_text('#!/bin/sh\nexit 1\n')
        failed_signer.chmod(0o755)
        rejected = run('-c', f'gpg.program={failed_signer}', 'commit', '-q', '-S', '-m', 'rejected')
        assert rejected.returncode == 128, (candidate, rejected.stderr)
        assert run('cat-file', 'commit', 'HEAD').stdout == obj.stdout
        results.append((obj.stdout, args, payload, failed.returncode, failed.stdout, failed.stderr))
    assert results[0] == results[1], results
    assert results[0][3] == 1
print('git signing/editor regression: reference comparison passed')
