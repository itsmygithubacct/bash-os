#!/usr/bin/env python3
"""Git 2.47.3 listing parity for the index cases the coordinator returned.

Normal runs compare the builtin with expected-git-2.47.3.json. SOL_INDEX_GIT
selects the live oracle and defaults to git on PATH. When that oracle reports
exactly "git version 2.47.3", the run also checks the oracle against the
record. Any other version skips that cross-check and still checks the builtin.
A kind overrun live difference is printed and does not fail the run: git's
result for that shape depends on allocator memory and the index path length.
The builtin check against the record stays strict. Every other kind still
fails when live git 2.47.3 drifts.
--record rewrites the record and refuses any other version.

The index path length is pinned: one version-4 fixture's listing depends on it.
"""
import argparse
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

FIX = Path(__file__).resolve().parent / 'fixtures' / 'sol-index-parity'
RECORD = FIX / 'expected-git-2.47.3.json'
ORACLE_VERSION = 'git version 2.47.3'
EMPTY_SHA = hashlib.sha256(b'').hexdigest()

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

GROUPS = [
    ('v2-expand', 'r-sparse', 'list'),
    ('v2-link-zero', 'r-split', 'fatal'),
    ('v2-link-nonzero', 'r-split', 'fatal'),
    ('v2-empty-subtree', 'r-sparse', 'fatal'),
    ('v2-untr-page', 'r-work', 'crash'),
    ('v3-split-literal', 'r-split', 'overrun'),
    ('v3-untr-list', 'r-work', 'list'),
    ('v3-untr-hang', 'r-work', 'hang'),
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


def resolve_oracle():
    raw = os.environ.get('SOL_INDEX_GIT')
    if raw:
        path = Path(raw)
        if not path.is_file():
            raise SystemExit('SOL_INDEX_GIT is not a file')
        return str(path.resolve())
    found = shutil.which('git')
    if not found:
        raise SystemExit('git is not on PATH')
    return str(Path(found).resolve())


def version_line(oracle):
    proc = subprocess.run([oracle, '--version'], capture_output=True)
    if proc.returncode != 0:
        raise SystemExit('git --version failed')
    return proc.stdout.decode('latin1').strip()


def run_index(binary, repo, index_path, env):
    script = 'PATH=; index read ' + shlex.quote(str(index_path))
    return subprocess.run(
        [binary, '--noprofile', '--norc', '-c', script],
        cwd=repo, env=env, capture_output=True)


def run_git(oracle, repo, index_path, env, hang):
    git_env = dict(env)
    git_env['GIT_INDEX_FILE'] = str(index_path)
    argv = [oracle, '-C', str(repo), 'ls-files', '--stage', '-z']
    if hang:
        argv = ['timeout', '2'] + argv
    return subprocess.run(argv, env=git_env, capture_output=True)


def observe(proc):
    listing = listing_of(proc.stdout)
    fatal = [line for line in proc.stderr.splitlines() if line.startswith(b'fatal: ')]
    return {
        'exit': proc.returncode,
        'listing_sha256': hashlib.sha256(listing).hexdigest(),
        'listing_length': len(listing),
        'fatal': [line.decode('latin1') for line in fatal],
        'position_for': b'fatal: position for ' in proc.stderr,
        '_stdout': proc.stdout,
        '_fatal': fatal,
    }


def public_obs(obs):
    return {key: obs[key] for key in (
        'exit', 'listing_sha256', 'listing_length', 'fatal', 'position_for')}


def install_shared(work):
    shared = FIX / 'indexes' / 'v3-split-literal' / (
        'sharedindex.a7ea1d81ba0bd4f843cf259a78e3211a2e520135')
    gitdir = work / 'r-split' / '.git'
    if shared.is_file() and gitdir.is_dir():
        (gitdir / shared.name).write_bytes(shared.read_bytes())


def place(work, src, name):
    mutants = work / 'mutants'
    mutants.mkdir(exist_ok=True)
    dst = mutants / name
    dst.write_bytes(src.read_bytes())
    if name == 'm00895.index':
        assert len(str(dst)) == INDEX_LEN, len(str(dst))
    return dst


def git_side_ok(kind, proc, obs):
    fatal = b'\n'.join(obs['_fatal'])
    if kind == 'list':
        return proc.returncode == 0
    if kind == 'fatal':
        return proc.returncode == 128 and proc.stdout == b'' and bool(fatal)
    if kind == 'overrun':
        return (proc.returncode == 128 and proc.stdout == b'' and
                b'fatal: position for ' in proc.stderr)
    if kind == 'hang':
        return proc.returncode == 124 and proc.stdout == b''
    if kind == 'crash':
        return proc.returncode != 0 and proc.stdout == b''
    raise AssertionError(kind)


def joined_fatal(entry):
    return b'\n'.join(line.encode('latin1') for line in entry['fatal'])


def builtin_ok(kind, entry, got, sparse_err):
    fatal = joined_fatal(entry)
    empty = (entry['listing_length'] == 0 and
             entry['listing_sha256'] == EMPTY_SHA)
    if kind == 'list':
        digest = hashlib.sha256(got.stdout).hexdigest()
        ok = (entry['exit'] == 0 and got.returncode == 0 and
              digest == entry['listing_sha256'] and
              len(got.stdout) == entry['listing_length'])
        if sparse_err:
            ok = ok and b'error: invalid object 040000 ' in got.stderr
            ok = ok and b'error: Could not read ' in got.stderr
        return ok
    if kind == 'fatal':
        return (entry['exit'] == 128 and empty and
                got.returncode == 1 and got.stdout == b'' and
                fatal and fatal in got.stderr.splitlines())
    if kind == 'overrun':
        return (entry['exit'] == 128 and empty and entry['position_for'] is True and
                got.returncode == 1 and got.stdout == b'' and got.returncode < 128)
    if kind == 'hang':
        return (entry['exit'] == 124 and empty and
                got.returncode == 1 and got.stdout == b'' and got.returncode < 128)
    if kind == 'crash':
        return (entry['exit'] != 0 and empty and
                got.returncode == 1 and got.stdout == b'' and got.returncode < 128)
    raise AssertionError(kind)


def live_ok(kind, proc, obs, entry):
    got = public_obs(obs)
    if got != {key: entry[key] for key in got}:
        return False
    if kind != 'list' and proc.stdout != b'':
        return False
    return True


def load_record():
    if not RECORD.is_file():
        raise SystemExit('record missing: tests/fixtures/sol-index-parity/expected-git-2.47.3.json')
    data = json.loads(RECORD.read_text())
    if data.get('git_version') != '2.47.3':
        raise SystemExit('record is not git 2.47.3')
    entries = data.get('entries')
    if not isinstance(entries, dict) or not entries:
        raise SystemExit('record has no entries')
    return entries


def record_all(oracle, work, env):
    install_shared(work)
    entries = {}

    def capture(key, repo, dst, kind):
        if key in entries:
            raise SystemExit('duplicate record key %s' % key)
        proc = run_git(oracle, repo, dst, env, kind == 'hang')
        obs = observe(proc)
        if not git_side_ok(kind, proc, obs):
            raise SystemExit('cannot record %s kind %s exit %s stdout %s' % (
                key, kind, proc.returncode, len(proc.stdout)))
        entries[key] = public_obs(obs)
        print('record', key, kind, obs['exit'], obs['listing_length'])

    for name, repo_name, _sparse in V1:
        src = FIX / 'indexes' / name
        dst = place(work, src, name)
        capture(name, work / repo_name, dst, 'list')
    for folder, repo_name, kind in GROUPS:
        repo = work / repo_name
        for src in sorted((FIX / 'indexes' / folder).glob('*.index')):
            dst = place(work, src, src.name)
            capture('%s/%s' % (folder, src.name), repo, dst, kind)
    payload = {'git_version': '2.47.3', 'entries': entries}
    text = json.dumps(payload, indent=2, sort_keys=True) + '\n'
    forbidden = ('/tmp', '/home', '/usr', '192.168')
    if any(piece in text for piece in forbidden):
        raise SystemExit('record would contain an absolute path')
    RECORD.write_text(text)
    print('recorded', len(entries))


def check_case(binary, case, oracle, live, work, env, entries):
    install_shared(work)
    failures = []

    def check(key, repo, dst, kind, sparse_err):
        entry = entries.get(key)
        if not isinstance(entry, dict):
            failures.append(key)
            print('FAIL', key, 'missing record')
            return
        reasons = []
        if live:
            proc = run_git(oracle, repo, dst, env, kind == 'hang')
            obs = observe(proc)
            if kind == 'overrun':
                if not live_ok(kind, proc, obs, entry):
                    print('NOTE', key, 'overrun live git differs from the record;',
                          'the builtin check stays strict',
                          'exit', obs['exit'], 'out', len(proc.stdout))
            elif not live_ok(kind, proc, obs, entry):
                reasons.append('drift')
        got = run_index(binary, repo, dst, env)
        if not builtin_ok(kind, entry, got, sparse_err):
            reasons.append('builtin')
        if reasons:
            failures.append(key)
            print('FAIL', key, kind, ','.join(reasons), 'builtin', got.returncode,
                  'record', entry['exit'], 'out', len(got.stdout))
        else:
            print('match', key, kind, got.returncode)

    if case == 'v1-over-refusal':
        for name, repo_name, sparse_err in V1:
            src = FIX / 'indexes' / name
            dst = place(work, src, name)
            check(name, work / repo_name, dst, 'list', sparse_err)
    elif case == 'v3-split-literal':
        selected = [row for row in GROUPS if row[0] == 'v3-split-literal']
    elif case == 'v3-untr':
        selected = [row for row in GROUPS if row[0].startswith('v3-untr')]
    else:
        selected = [row for row in GROUPS if row[0].startswith('v2-')]
    if case != 'v1-over-refusal':
        for folder, repo_name, kind in selected:
            repo = work / repo_name
            for src in sorted((FIX / 'indexes' / folder).glob('*.index')):
                dst = place(work, src, src.name)
                check('%s/%s' % (folder, src.name), repo, dst, kind, False)
    assert not failures, failures
    print('PASS', case)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--record', action='store_true')
    p.add_argument('--binary')
    p.add_argument('--case', choices=['v1-over-refusal', 'v2-mismatch',
                                     'v3-split-literal', 'v3-untr'])
    a = p.parse_args()
    if a.record:
        if a.binary or a.case:
            p.error('--record does not take --binary or --case')
    elif not a.binary or not a.case:
        p.error('--binary and --case are required')
    oracle = resolve_oracle()
    reported = version_line(oracle)
    if a.record:
        if reported != ORACLE_VERSION:
            raise SystemExit('refusing to record: oracle reports %r' % reported)
    elif reported != ORACLE_VERSION:
        shown = reported[len('git version '):] if reported.startswith('git version ') else reported
        print('oracle git %s is not 2.47.3: checking the builtin against recorded 2.47.3 results' % shown)
    work = make_work()
    try:
        unpack(FIX / 'probe-repos.tar.zst', work)
        unpack(FIX / 'crafted-repo.tar.zst', work)
        env = base_env(work)
        if a.record:
            record_all(oracle, work, env)
        else:
            check_case(str(Path(a.binary).resolve()), a.case, oracle,
                       reported == ORACLE_VERSION, work, env, load_record())
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
