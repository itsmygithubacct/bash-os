#!/usr/bin/env bash
# Check the project's MIT sources and the explicit third-party licence inventory.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
python3 - <<'PY'
import json
from pathlib import Path
import re
manifest=json.loads(Path('config/helpers.json').read_text())['helpers']
vendored_doc=json.loads(Path('config/vendored-files.json').read_text())
problems=[]
allowed={'MIT','ISC','Public domain','Apache-2.0','LGPL-2.1','LGPL-2.1-or-later',
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
vendored=set()
entries=vendored_doc.get('files') if isinstance(vendored_doc, dict) else None
if not isinstance(entries, list):
    problems.append('vendored inventory has no files list')
    entries=[]
for entry in entries:
    if not isinstance(entry, dict):
        problems.append('vendored inventory row is not an object')
        continue
    path=Path(entry.get('path') or '')
    notice=Path(entry.get('notice') or '')
    key=path.as_posix()
    if not entry.get('path') or not entry.get('source') or not entry.get('licence') or not entry.get('notice'):
        problems.append(f'incomplete vendored row: {key or entry}')
    if key in vendored: problems.append(f'duplicate vendored file: {key}')
    if entry.get('licence') not in allowed: problems.append(f'unknown licence for {key}')
    if not notice.is_file() or not notice.read_text().strip():
        problems.append(f'missing licence notice: {notice}')
    if not path.is_file() or 'Copyright' not in path.read_text(errors='replace'):
        problems.append(f'missing upstream copyright: {path}')
    vendored.add(key)
count=0
for file in [*Path('loadables').rglob('*'), *Path('tests').glob('*.c')]:
    if not file.is_file() or file.suffix not in ['.c','.h','.data']: continue
    count+=1
    if file.as_posix() in vendored: continue
    if len(file.parts)>2 and file.parts[1] in manifest: continue
    # Userspace mirrors of the kernel module's ABI keep its licence; the
    # syscall note lets userspace include them.
    if (re.fullmatch(r'loadables/common/_bashos_[a-z0-9_]+_uapi\.h', file.as_posix()) and
            file.read_text().startswith('/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */')):
        continue
    if not re.search(r'SPDX-License-Identifier: MIT|MIT License|\bMIT\b|Permission is hereby granted, free of charge',file.read_text()):
        problems.append(f'no MIT licence marker: {file}')
if not Path('LICENSE').is_file(): problems.append('LICENSE missing')
# The kernel module is a separate GPL-2.0-only work built against a kernel tree.
kernel_allowed={'GPL-2.0-only','GPL-2.0-only WITH Linux-syscall-note','MIT'}
for module in Path('kernel').glob('*'):
    if not module.is_dir(): continue
    if not (module/'COPYING').is_file(): problems.append(f'missing licence notice: {module}/COPYING')
    for file in module.rglob('*'):
        if not file.is_file() or not (file.suffix in ['.c','.h'] or file.name == 'Kconfig' or file.name.startswith('Makefile')): continue
        count+=1
        found=re.search(r'SPDX-License-Identifier: (.+?)(?: \*/)?$', file.read_text().split('\n', 1)[0])
        if not found or found.group(1).strip() not in kernel_allowed:
            problems.append(f'no kernel SPDX licence identifier: {file}')
for problem in problems: print(problem)
print(f'licence-check: {count} files, {len(problems)} problems')
raise SystemExit(bool(problems))
PY
