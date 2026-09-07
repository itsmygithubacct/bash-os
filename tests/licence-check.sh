#!/usr/bin/env bash
# Check the project's MIT sources and the explicit third-party licence inventory.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
python3 - <<'PY'
import json
from pathlib import Path
import re
manifest=json.loads(Path('config/helpers.json').read_text())['helpers']
problems=[]
allowed={'MIT','ISC','Public domain','Apache-2.0','LGPL-2.1',
         'BSD-2-Clause OR CC0-1.0','BSD-3-Clause','MIT AND Unicode-DFS-2016'}
for directory in Path('loadables').glob('_*'):
    if directory.is_dir() and directory.name not in manifest:
        problems.append(f'unregistered helper: {directory}')
for name, entry in manifest.items():
    directory=Path('loadables')/name
    notice=directory/entry['notice']
    for extra in entry.get('additional_notices', []):
        if not (directory/extra).is_file(): problems.append(f'missing additional notice: {directory/extra}')
    if entry['license'] not in allowed: problems.append(f'unknown licence for {name}')
    if not directory.is_dir() or not notice.is_file() or not notice.read_text().strip():
        problems.append(f'missing licence notice: {notice}')
count=0
for file in [*Path('loadables').rglob('*'), *Path('tests').glob('*.c')]:
    if not file.is_file() or file.suffix not in ['.c','.h','.data']: continue
    count+=1
    if len(file.parts)>2 and file.parts[1] in manifest: continue
    if not re.search(r'SPDX-License-Identifier: MIT|MIT License|\bMIT\b|Permission is hereby granted, free of charge',file.read_text()):
        problems.append(f'no MIT licence marker: {file}')
if not Path('LICENSE').is_file(): problems.append('LICENSE missing')
for problem in problems: print(problem)
print(f'licence-check: {count} files, {len(problems)} problems')
raise SystemExit(bool(problems))
PY
