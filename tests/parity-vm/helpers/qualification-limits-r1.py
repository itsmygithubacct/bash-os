#!/usr/bin/env python3
"""Run pinned qualification drivers inside the ordinary disposable VM boundary."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root = Path('/opt/bashos-parity')
    home = Path('/tmp/parity-home')
    spec = json.loads((Path('/tmp/parity-case') / 'qualification-inputs.json').read_text())
    for name, expected in spec['sources'].items():
        path = root / name
        if not path.resolve().is_relative_to(root) or sha(path) != expected:
            raise RuntimeError('qualification source differs: ' + name)
    assets = home / 'qualification-assets'
    assets.mkdir(mode=0o700)
    for name, expected in spec['assets'].items():
        if Path(name).name != name:
            raise RuntimeError('invalid artifact name')
        source = root / 'reference-data' / name
        if sha(source) != expected:
            raise RuntimeError('qualification artifact differs: ' + name)
        target = assets / name
        shutil.copyfile(source, target)
        target.chmod(0o700)
    output = home / 'qualification-report.json'
    candidate = str(root / 'candidate')
    artifact = lambda name: str(assets / name)
    commands = {
        'unicode': ['unicode-interface.py', candidate, artifact('GraphemeBreakTest.txt'), str(output)],
        'wgetch': ['wgetch-interface.py', candidate, str(output)],
        'tput': ['tput-interface.py', candidate, '/usr/bin/tput', str(output)],
        'dmesg': ['dmesg-interface.py', candidate, str(output)],
        'unload': ['signalfd-unload.py', artifact('bash-stock'), artifact('bashpoll.so'),
                   artifact('bashpoll-omitted-hook.so'), str(output)],
        'key-clock': ['wgetch-cases.py', artifact('wgetch-original'), artifact('wgetch-runtime'), str(output)],
        'decoder': ['dmesg-record-cases.py', artifact('dmesg-record-probe'), str(output)],
        'grapheme-control': ['unicode-corpus.py', artifact('GraphemeBreakTest.txt'),
                             artifact('grapheme-real'), artifact('grapheme-truncating'), str(output)],
    }
    command = commands[sys.argv[1]]
    command[0] = str(root / 'qualification-limits' / command[0])
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
           'BASHOS_QUALIFICATION_GUEST': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run(['/usr/bin/python3', *command], env=env, capture_output=True, timeout=50)
    report = json.loads(output.read_text()) if output.exists() else {}
    (home / 'qualification-transport.json').write_text(json.dumps({
        'driver_status': result.returncode, 'stdout_hex': result.stdout.hex(),
        'stderr_hex': result.stderr.hex(), 'candidate_sha256': sha(root / 'candidate'),
        'sources': spec['sources'], 'assets': spec['assets']}, indent=2) + '\n')
    status = report.get('result')
    expected = {'PASS': 0, 'FAIL': 1, 'ERROR': 125}.get(status)
    if expected is None or result.returncode != expected or result.stdout or result.stderr:
        raise RuntimeError('incomplete or inconsistent qualification result')
    print(status)
    return expected


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(125)
