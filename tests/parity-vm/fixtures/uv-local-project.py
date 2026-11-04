#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only: compare a packaged uv builtin with its pinned upstream helper.

Usage: uv-local-project.py CANDIDATE REFERENCE_SHELL HELPER STATIC|MODULE [MODULE_PATH]
The coordinator must install HELPER at the builtin's compiled-in path for
STATIC, or beside MODULE_PATH at ../libexec/uv/uv for MODULE. Run inside a
fresh network-isolated guest with the authenticated package artifacts.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


def main():
    if len(sys.argv) not in (5, 6) or sys.argv[4] not in ('STATIC', 'MODULE'):
        raise SystemExit('invalid fixture arguments')
    candidate, reference, helper = (str(Path(p).resolve(strict=True)) for p in sys.argv[1:4])
    mode = sys.argv[4]
    if (mode == 'MODULE') != (len(sys.argv) == 6):
        raise SystemExit('MODULE requires exactly one module path')
    if mode == 'MODULE':
        module = Path(sys.argv[5]).resolve(strict=True)
        if (module.parent / '../libexec/uv/uv').resolve(strict=True) != Path(helper):
            raise SystemExit('module sibling helper differs from reference helper')
    else:
        module = ''
        if Path('/usr/lib/bash-os/libexec/uv/uv').resolve(strict=True) != Path(helper):
            raise SystemExit('compiled-in helper differs from reference helper')

    with tempfile.TemporaryDirectory(prefix='uv-project-', dir=os.getcwd()) as tmp:
        root = Path(tmp)
        home = root / 'home'
        home.mkdir()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
               'UV_OFFLINE': '1', 'UV_NO_CONFIG': '1',
               'UV_PYTHON_DOWNLOADS': 'never', 'UV_CACHE_DIR': str(root / 'cache')}
        scripts = {
            'candidate': 'if [[ $2 == MODULE ]]; then enable -f "$3" uv || exit 91; fi\n'
                         '[[ $(type -t uv) == builtin ]] || exit 92\n'
                         'uv init --bare --vcs none --python /usr/bin/python3 tinyproj\n',
            'reference': '"$1" init --bare --vcs none --python /usr/bin/python3 tinyproj\n',
        }
        trees = {}
        for side, shell in (('reference', reference), ('candidate', candidate)):
            work = root / side
            work.mkdir()
            run = subprocess.run([shell, '--noprofile', '--norc', '-c', scripts[side],
                                  'uv-fixture', helper, mode, str(module)], cwd=work,
                                 env=env, capture_output=True, timeout=30)
            if run.returncode != 0:
                raise SystemExit(f'{side} status {run.returncode}; stdout={run.stdout!r}; stderr={run.stderr!r}')
            project = work / 'tinyproj'
            entries = sorted(p.relative_to(project).as_posix() for p in project.rglob('*'))
            if entries != ['pyproject.toml'] or not (project / 'pyproject.toml').is_file():
                raise SystemExit(f'{side} unexpected project tree: {entries!r}')
            content = (project / 'pyproject.toml').read_bytes()
            if tomllib.loads(content.decode('utf-8')).get('project', {}).get('name') != 'tinyproj':
                raise SystemExit(f'{side} incorrect project name')
            trees[side] = content
        if trees['candidate'] != trees['reference']:
            raise SystemExit('candidate and upstream pyproject.toml differ')
    print('uv-local-project-upstream-r1: PASS')


if __name__ == '__main__':
    main()
