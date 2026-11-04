#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Versioned candidate-only hook control, inside the attested parity guest."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

SOURCES = {
    'dmesg-hook.py': '6d76b29ee1ca900cc3ddcd0c80872cf58d877c94771a2c6583877f5dfd6fff1c',
    'guest.py': 'f03af0128fdecc553f31e1065b5648d4c1403c85d673a9fd759b7767ea423b1a',
}
FILTER_SHA = '16e931bf4c2933b468c6d9484a6b0c9258135901fe084d5a229a83f677757aac'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root = Path('/opt/bashos-parity')
    home = Path('/tmp/parity-home')
    source = root / 'qualification-limits'
    helper = root / 'harness/helpers/system-seccomp.py'
    for name, expected in SOURCES.items():
        if sha(source / name) != expected:
            raise RuntimeError('driver source pin differs: ' + name)
    if sha(helper) != FILTER_SHA:
        raise RuntimeError('seccomp helper pin differs')
    output = home / 'dmesg-hook-r2.json'
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
           'BASHOS_QUALIFICATION_GUEST': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    r = subprocess.run(['/usr/bin/python3', str(source / 'dmesg-hook.py'),
                        str(root / 'candidate'), str(helper), '/usr/bin/dmesg', str(output)],
                       env=env, capture_output=True, timeout=45)
    report = json.loads(output.read_text()) if output.is_file() else {}
    (home / 'dmesg-hook-r2-transport.json').write_text(json.dumps({
        'status': r.returncode, 'stdout_hex': r.stdout.hex(), 'stderr_hex': r.stderr.hex(),
        'sources': SOURCES, 'filter_sha256': FILTER_SHA,
        'candidate_sha256': sha(root / 'candidate')}, indent=2) + '\n')
    expected = {'PASS': 0, 'FAIL': 1, 'ERROR': 125}.get(report.get('result'))
    if expected is None or r.returncode != expected or r.stdout or r.stderr:
        raise RuntimeError('missing/inconsistent controlled hook observation')
    print(report['result'])
    return expected


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(125)
