#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Negative controls for the matched-workload repository oracles."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workloads', ROOT/'bench/sol-git.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


def rejected(callback):
    try:
        callback()
    except AssertionError:
        return
    raise AssertionError('oracle missed deliberate corruption')


with tempfile.TemporaryDirectory(prefix='sol-git-oracles-') as name:
    root = Path(name)
    env = dict(PATH='', HOME=name, LC_ALL='C', TZ='UTC',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_TEMPLATE_DIR=str(w.template(root)))
    empty = root/'empty'
    w.reference(root, env, 'init', '-q', '-b', 'main', empty)
    w.init_oracle(empty, env)
    files, commits = map(int, sys.argv[1:]) if len(sys.argv) > 1 else (100, 10)
    fixture = w.Fixture(files, commits)
    repo = root/'repo'
    w.materialize(repo, fixture, env, dirty=True)
    check = lambda: w.state_oracle(repo, env, fixture)
    check()

    target = repo/'f000000'
    original = target.read_bytes()
    target.write_bytes(b'wrong contents\n')
    rejected(check)
    target.write_bytes(original)

    target.chmod(0o755)
    rejected(check)
    target.chmod(0o644)

    oid, raw = w.object_record('blob', b'unexpected unreachable object\n')
    extra = repo/'.git/objects'/oid[:2]/oid[2:]
    extra.parent.mkdir(exist_ok=True)
    extra.write_bytes(zlib.compress(raw))
    rejected(check)
    extra.unlink()

    blob_id = w.object_record('blob', fixture.files['f000000'])[0]
    target = repo/'.git/objects'/blob_id[:2]/blob_id[2:]
    original = target.read_bytes()
    target.write_bytes(zlib.compress(w.object_record('blob', b'substituted\n')[1]))
    rejected(check)
    target.write_bytes(original)

    index = repo/'.git/index'
    original = index.read_bytes()
    w.reference(repo, env, 'update-index', '--cacheinfo',
                f'100755,{blob_id},f000000')
    rejected(check)
    index.write_bytes(original)

    (repo/'.git/refs/heads/main').write_text(fixture.commits[-2]+'\n')
    rejected(check)
    (repo/'.git/refs/heads/main').write_text(fixture.head+'\n')
    check()
    env.update(w.ssh_fixture(root))
    output, _ = w.execute(Path('/bin/bash'), 'git',
                          ['clone', '-q', f'fixture:{repo}', root/'clone'],
                          root, env, False)
    assert output == b''
    w.state_oracle(root/'clone', env, fixture, clone=True)

print('sol-git-oracles: reference init/state/protocol clone accepted; six corruptions detected')
