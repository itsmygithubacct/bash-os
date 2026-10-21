#!/usr/bin/env python3
"""Git 2.47.3 listing parity for the index cases the coordinator returned.

The oracle is /usr/bin/git under the probe's clean environment. The index
path length is pinned: one version-4 fixture's listing depends on it.
"""
import argparse
import hashlib
import io
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--case', choices=['v1-over-refusal', 'v2-mismatch'], required=True)
a = p.parse_args()
binary = str(Path(a.binary).resolve())
FIX = Path(__file__).resolve().parent / 'fixtures' / 'sol-index-parity'

# Index path strlen 80 selects the measured pool alignment for a 20-entry
# version-4 index whose repository path is 13 bytes shorter.
INDEX_LEN = 80
SUFFIX = '/mutants/m00895.index'
assert len(SUFFIX) == 21
WORK_LEN = INDEX_LEN - len(SUFFIX)

V1 = [
    ('m00268.index', 'r-split', False),
    ('m00316.index', 'r-split', False),
    ('m00652.index', 'r-split', False),
    ('m00765.index', 'r-split', False),
    ('m01704.index', 'r-split', False),
    ('m02204.index', 'r-split', False),
    ('m02076.index', 'r-split', False),
    ('m00025.index', 'r-sparse', True),
    ('m01385.index', 'r-sparse', True),
    ('m02222.index', 'r-sparse', True),
    ('m02313.index', 'r-sparse', True),
    ('m02334.index', 'r-sparse', True),
    ('m02526.index', 'r-sparse', True),
    ('m00895.index', 'r-plain', False),
    ('v4-varint-overflow-first.index', 'crafted-repo', False),
    ('v4-varint-overflow-second.index', 'crafted-repo', False),
]


def unpack(archive, dest):
    raw = subprocess.check_output(['/usr/bin/zstd', '-dc', str(archive)])
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        tar.extractall(dest, filter='data')


def listing_of(stdout):
    lines = []
    for row in stdout.split(b'\0'):
        if not row:
            continue
        meta, pathb = row.split(b'\t', 1)
        if pathb == b'':
            pathb = b'./'
        lines.append(meta + b' ' + pathb + b'\n')
    return b''.join(lines)


def base_env(work):
    return {
        'PATH': '/usr/bin:/bin',
        'HOME': str(work),
        'LC_ALL': 'C',
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_AUTHOR_NAME': 'a',
        'GIT_AUTHOR_EMAIL': 'a@b.invalid',
        'GIT_COMMITTER_NAME': 'a',
        'GIT_COMMITTER_EMAIL': 'a@b.invalid',
        'GIT_AUTHOR_DATE': '1700000000 +0000',
        'GIT_COMMITTER_DATE': '1700000000 +0000',
    }


def make_work():
    prefix = '/tmp/'
    tag = 'p%d' % os.getpid()
    n = WORK_LEN - len(prefix)
    assert n > len(tag)
    work = Path(prefix + tag + ('x' * (n - len(tag))))
    assert len(str(work)) == WORK_LEN
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    return work


def run_index(repo, index_path, env):
    script = 'PATH=; index read ' + shlex.quote(str(index_path))
    return subprocess.run(
        [binary, '--noprofile', '--norc', '-c', script],
        cwd=repo, env=env, capture_output=True)


def git_ls(repo, index_path, env):
    git_env = dict(env)
    git_env['GIT_INDEX_FILE'] = str(index_path)
    return subprocess.run(
        ['/usr/bin/git', '-C', str(repo), 'ls-files', '--stage', '-z'],
        env=git_env, capture_output=True)


def check_v1(work, env, failures):
    mutants = work / 'mutants'
    mutants.mkdir()
    for name, repo_name, sparse_err in V1:
        src = FIX / 'indexes' / name
        dst = mutants / name
        dst.write_bytes(src.read_bytes())
        if name == 'm00895.index':
            assert len(str(dst)) == INDEX_LEN, len(str(dst))
        repo = work / repo_name
        git = git_ls(repo, dst, env)
        assert git.returncode == 0, (name, git.returncode, git.stderr)
        expected = listing_of(git.stdout)
        got = run_index(repo, dst, env)
        ok = got.returncode == 0 and got.stdout == expected
        if sparse_err:
            ok = ok and b'error: invalid object 040000 ' in got.stderr
            ok = ok and b'error: Could not read ' in got.stderr
        if not ok:
            failures.append((name, got.returncode, len(got.stdout), len(expected)))
            print('FAIL', name, 'builtin', got.returncode, 'out', len(got.stdout), 'git', len(expected))
        else:
            print('match', name, len(got.stdout))


def check_v2(work, env, failures):
    mutants = work / 'mutants'
    mutants.mkdir(exist_ok=True)
    groups = [
        ('v2-expand', 'r-sparse', 'list'),
        ('v2-link-zero', 'r-split', 'fatal'),
        ('v2-link-nonzero', 'r-split', 'fatal'),
        ('v2-empty-subtree', 'r-sparse', 'fatal'),
        ('v2-untr-page', 'r-work', 'crash'),
    ]
    for folder, repo_name, kind in groups:
        repo = work / repo_name
        for src in sorted((FIX / 'indexes' / folder).glob('*.index')):
            dst = mutants / src.name
            dst.write_bytes(src.read_bytes())
            git = git_ls(repo, dst, env)
            got = run_index(repo, dst, env)
            if kind == 'list':
                expected = listing_of(git.stdout)
                ok = git.returncode == 0 and got.returncode == 0 and got.stdout == expected
            elif kind == 'fatal':
                fatal = b'\n'.join(line for line in git.stderr.splitlines() if line.startswith(b'fatal: '))
                ok = (git.returncode == 128 and git.stdout == b'' and
                      got.returncode == 1 and got.stdout == b'' and
                      fatal and fatal in got.stderr.splitlines())
            else:
                ok = (git.returncode != 0 and git.stdout == b'' and
                      got.returncode == 1 and got.stdout == b'' and
                      got.returncode < 128)
            if not ok:
                failures.append((src.name, kind, got.returncode, git.returncode,
                                 len(got.stdout), got.stderr.decode('latin1')[:180],
                                 git.stderr.decode('latin1')[:180]))
                print('FAIL', src.name, kind, 'builtin', got.returncode, 'git', git.returncode)
            else:
                print('match', src.name, kind, got.returncode)


def main():
    work = make_work()
    try:
        unpack(FIX / 'probe-repos.tar.zst', work)
        unpack(FIX / 'crafted-repo.tar.zst', work)
        env = base_env(work)
        failures = []
        if a.case == 'v1-over-refusal':
            check_v1(work, env, failures)
        else:
            check_v2(work, env, failures)
        assert not failures, failures
        print('PASS', a.case)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
