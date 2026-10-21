#!/usr/bin/env python3
"""A build records the release VERSION in both of its manifests.

Usage: build-version.py BINARY
"""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1])
version = (ROOT / 'VERSION').read_text().strip()
assert re.fullmatch(r'\d+\.\d+\.\d+', version), f'VERSION is not MAJOR.MINOR.PATCH: {version!r}'

manifest = json.loads(binary.with_name(binary.name + '.manifest.json').read_text())
assert manifest.get('bashos_version') == version, \
    f"manifest.json bashos_version {manifest.get('bashos_version')!r} != VERSION {version!r}"

lines = binary.with_name(binary.name + '.manifest.txt').read_text().splitlines()
assert f'bash-os {version}' in lines, f'manifest.txt has no "bash-os {version}" line'

print(f'{binary.name}: manifests record bash-os {version}')
