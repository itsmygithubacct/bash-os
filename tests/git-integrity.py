#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject malformed Git objects, packs, and paths before using their data.

Usage: python3 tests/git-integrity.py [BINARY]

All malformed objects are written directly into disposable repositories;
outside-file sentinels also live inside the fixture's temporary directory.
"""

import hashlib
from pathlib import Path
import shutil
import shlex
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve()
GIT = shutil.which('git')
checks = 0


def check(condition, *context):
    global checks
    assert condition, context
    checks += 1


with tempfile.TemporaryDirectory(prefix='git-integrity-') as directory:
    tmp = Path(directory)
    repo = tmp/'repo'
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(tmp), 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    subprocess.run([GIT, 'init', '-q', '-b', 'main', str(repo)],
                   env=env, check=True)

    def run(*args, command='git', stdin=b'', extra_env=None):
        return subprocess.run(
            [str(BINARY), '--noprofile', '--norc', '-c',
             'PATH=; "$@"', command, command, *map(str, args)],
            cwd=repo, env={**env, **(extra_env or {})}, input=stdin,
            capture_output=True, timeout=20)

    def object_bytes(data):
        oid = hashlib.sha1(data).hexdigest()
        target = repo/'.git/objects'/oid[:2]/oid[2:]
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(zlib.compress(data))
        return oid

    def obj(kind, data):
        return object_bytes(kind.encode() + b' ' + str(len(data)).encode()
                            + b'\0' + data)

    def tree(name, oid, mode=b'100644'):
        return obj('tree', mode + b' ' + name + b'\0' + bytes.fromhex(oid))

    def index_bytes(path, oid):
        name = path.encode()
        entry = (struct.pack('>10I', 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 0)
                 + bytes.fromhex(oid) + struct.pack('>H', min(len(name), 4095))
                 + name)
        entry += b'\0' * (8 - len(entry) % 8)
        body = b'DIRC' + struct.pack('>II', 2, 1) + entry
        return body + hashlib.sha1(body).digest()

    blob = obj('blob', b'replacement\n')
    safe_tree = tree(b'kept', blob)
    result = run('read-tree', safe_tree)
    check(result.returncode == 0, 'valid read-tree', result.stderr)
    index = repo/'.git/index'
    original_index = index.read_bytes()
    escaped = tmp/'escaped'
    escaped.write_bytes(b'outside sentinel\n')
    original_config = (repo/'.git/config').read_bytes()

    # Tree entries may not smuggle an index path, a parent, or .git through
    # read-tree into restore. Rejection must precede index replacement.
    bad_names = (b'../escaped', b'.git/config', b'.GiT/config', b'a/../../escaped',
                 b'/absolute', b'', b'.', b'..', b'.git')
    for name in bad_names:
        bad = tree(name, blob)
        result = run('read-tree', bad)
        check(result.returncode != 0, 'read-tree accepted unsafe name', name)
        check(index.read_bytes() == original_index, 'read-tree changed index', name)
        result = run('restore', '--source=' + bad, '--worktree', '--', '.')
        check(result.returncode != 0, 'restore accepted unsafe name', name)
        check(escaped.read_bytes() == b'outside sentinel\n', 'escaped tree', name)
        check((repo/'.git/config').read_bytes() == original_config,
              'tree changed administrative file', name)

    # A nested directory named .git is rejected before descending into it.
    bad = tree(b'.git', tree(b'config', blob), b'40000')
    check(run('read-tree', bad).returncode != 0, 'nested .git tree accepted')
    check(index.read_bytes() == original_index, 'nested tree changed index')

    bad_paths = ('../escaped', '.git/config', '.GiT/config', 'a/../../escaped',
                 '/absolute', '', '.', '..', 'a//b', 'a/./b', 'a/')
    for path in bad_paths:
        index.write_bytes(index_bytes(path, blob))
        result = run('read', index, command='index')
        check(result.returncode != 0, 'index reader accepted unsafe path', path)
        result = run('restore', '--worktree', '--', '.')
        check(result.returncode != 0, 'restore accepted unsafe index', path)
        check(escaped.read_bytes() == b'outside sentinel\n', 'escaped index', path)
        index.write_bytes(original_index)
        result = run('update-index', '--add', '--cacheinfo',
                     f'100644,{blob},{path}')
        check(result.returncode != 0, 'update-index accepted unsafe path', path)
        check(index.read_bytes() == original_index, 'unsafe cacheinfo changed index', path)
        result = run('write', index, command='index',
                     stdin=f'100644 {blob} 0 {path}\n'.encode())
        check(result.returncode != 0, 'index writer accepted unsafe path', path)
        check(index.read_bytes() == original_index, 'unsafe write changed index', path)

    # Lexically safe paths can still escape through an existing parent
    # symlink. Both writing and removing a tracked file must stay inside.
    outside = tmp/'outside'
    outside.mkdir()
    victim = outside/'victim'
    victim.write_bytes(b'outside sentinel\n')
    (repo/'link').symlink_to(outside, target_is_directory=True)
    nested = tree(b'link', tree(b'victim', blob), b'40000')
    result = run('restore', '--source=' + nested, '--worktree', '--', '.')
    check(result.returncode != 0, 'restore followed parent symlink', result.stderr)
    check(victim.read_bytes() == b'outside sentinel\n', 'symlink checkout escaped')
    index.write_bytes(index_bytes('link/victim', blob))
    empty = obj('tree', b'')
    run('restore', '--source=' + empty, '--staged', '--worktree', '--', '.')
    check(victim.read_bytes() == b'outside sentinel\n', 'symlink removal escaped')

    for patch in (
        b'diff --git a/link/victim b/link/victim\n'
        b'--- a/link/victim\n+++ b/link/victim\n@@ -1 +1 @@\n'
        b'-outside sentinel\n+replacement\n',
        b'diff --git a/link/victim b/link/victim\n'
        b'deleted file mode 100644\n--- a/link/victim\n+++ /dev/null\n'
        b'@@ -1 +0,0 @@\n-outside sentinel\n',
        b'diff --git a/link/new b/link/new\nnew file mode 100644\n'
        b'--- /dev/null\n+++ b/link/new\n@@ -0,0 +1 @@\n+replacement\n',
    ):
        result = run('apply', stdin=patch)
        check(result.returncode != 0, 'apply followed parent symlink', result.stderr)
        check(victim.read_bytes() == b'outside sentinel\n', 'patch escaped symlink')
        check(not (outside/'new').exists(), 'patch created file outside worktree')

    # An unsafe destination later in the patch is rejected in the planning
    # pass, before an earlier safe addition can be written.
    patch = (b'diff --git a/new-safe b/new-safe\nnew file mode 100644\n'
             b'--- /dev/null\n+++ b/new-safe\n@@ -0,0 +1 @@\n+safe\n'
             b'diff --git a/link/new b/link/new\nnew file mode 100644\n'
             b'--- /dev/null\n+++ b/link/new\n@@ -0,0 +1 @@\n+unsafe\n')
    for args in (('apply', '--check'), ('apply',)):
        result = run(*args, stdin=patch)
        check(result.returncode != 0, 'unsafe multi-file patch accepted', args)
        check(not (repo/'new-safe').exists(), 'unsafe patch partially applied', args)

    # Replacing a leaf symlink with a regular tracked file is safe and
    # should still work. Its target is never truncated.
    index.write_bytes(original_index)
    (repo/'kept').symlink_to(victim)
    patch = (b'diff --git a/kept b/kept\n--- a/kept\n+++ b/kept\n'
             b'@@ -1 +1 @@\n-outside sentinel\n+replacement\n')
    result = run('apply', stdin=patch)
    check(result.returncode != 0, 'apply accepted a leaf symlink', result.stderr)
    check((repo/'kept').is_symlink(), 'refused apply replaced a leaf symlink')
    check(victim.read_bytes() == b'outside sentinel\n', 'apply changed leaf target')
    result = run('restore', '--worktree', '--', 'kept')
    check(result.returncode == 0, 'leaf symlink restore', result.stderr)
    check(not (repo/'kept').is_symlink(), 'leaf symlink was retained')
    check((repo/'kept').read_bytes() == b'replacement\n', 'wrong restored bytes')
    check(victim.read_bytes() == b'outside sentinel\n', 'leaf target changed')
    check(not list((repo/'.git').rglob('*.lock')), 'failed operation leaked a lock')

    for data in (b'blob \0', b'blob 01\0x', b'blob 18446744073709551616\0',
                 b'blob 36893488147419103233\0x', b'blob 2\0x', b'blob 1\0xyz'):
        oid = object_bytes(data)
        for command, args in (('git', ('cat-file', '-p', oid)),
                              ('obj', ('cat', oid))):
            result = run(*args, command=command)
            check(result.returncode != 0, 'accepted malformed loose object', data, command)
            check(not result.stdout, 'printed malformed object content', data, command)

    # Packs have a valid outer checksum, isolating validation of their
    # advertised sizes, delta varints, and reconstructed payload lengths.
    def pack(entries, count=None, suffix=b''):
        body = (b'PACK' + struct.pack('>II', 2, len(entries) if count is None else count)
                + b''.join(entries) + suffix)
        return body + hashlib.sha1(body).digest()

    base_oid = hashlib.sha1(b'blob 1\0a').digest()
    base = b'\x31' + zlib.compress(b'a')
    malformed = [
        ('short object', pack([b'\x32' + zlib.compress(b'a')])),
        ('long object', pack([b'\x30' + zlib.compress(b'a')])),
        ('invalid type', pack([b'\x51' + zlib.compress(b'a')])),
        ('trailing data', pack([base], suffix=b'x')),
        ('impossible count', pack([], count=0xffffffff)),
        ('object size overflow', pack([b'\xb1' + b'\x80' * 8 + b'\x10'
                                      + zlib.compress(b'a')])),
    ]
    for label, delta in (
        ('short delta output', b'\x01\x02\x01b'),
        ('overflow source size', b'\x81' + b'\x80' * 8 + b'\x02\x01\x01b'),
        ('overflow target size', b'\x01\x81' + b'\x80' * 8 + b'\x02\x01b'),
        ('unterminated delta size', b'\x01' + b'\x80' * 10),
    ):
        malformed.append((label, pack([base, bytes([0x70 | len(delta)])
                                      + base_oid + zlib.compress(delta)])))

    def offset_bytes(value):
        out = [value & 127]
        value >>= 7
        while value:
            value -= 1
            out.append(128 | (value & 127))
            value >>= 7
        return bytes(reversed(out))

    malformed.append(('overflow base offset', pack([
        base, b'\x64' + offset_bytes((1 << 64) + len(base))
        + zlib.compress(b'\x01\x01\x01b')
    ])))
    for number, (label, data) in enumerate(malformed):
        path = tmp/f'invalid-{number}.pack'
        path.write_bytes(data)
        target = path.with_suffix('.idx')
        result = run('index-pack', '-o', target, path)
        check(result.returncode != 0, 'index-pack accepted malformed pack', label)
        check(not target.exists(), 'invalid pack published an index', label)

    # The implicit copy size is 64 KiB, but an explicit three-byte size
    # may copy up to 0xffffff bytes. Do not reject ordinary large deltas
    # while bounding malformed size claims.
    large = b'a' * (1 << 20)
    large_oid = hashlib.sha1(b'blob 1048576\0' + large).digest()
    # Encode 1048576 in an object header and in the delta's two sizes.
    large_base = b'\xb0\x80\x80\x04' + zlib.compress(large)
    delta = b'\x80\x80\x40\x81\x80\x40\xc0\x10\x01b'
    valid_pack = tmp/'large-copy.pack'
    valid_pack.write_bytes(pack([large_base, b'\x7a' + large_oid + zlib.compress(delta)]))
    ours = tmp/'large-copy.idx'
    reference = tmp/'large-copy-reference.idx'
    result = run('index-pack', '-o', ours, valid_pack)
    check(result.returncode == 0, 'rejected large delta copy', result.stderr)
    result = subprocess.run([GIT, 'index-pack', '-o', str(reference), str(valid_pack)],
                            env=env, capture_output=True, timeout=20)
    check(result.returncode == 0, 'reference rejected large-copy fixture', result.stderr)
    check(ours.read_bytes() == reference.read_bytes(), 'large-copy index differs from git')

    # A .git directory without HEAD, refs, and objects is not a repository.
    fake = tmp/'fake'
    (fake/'.git').mkdir(parents=True)
    result = run('-C', fake, 'rev-parse', '--git-dir')
    check(result.returncode != 0, 'accepted empty .git directory')
    result = run('--git-dir=' + str(fake/'.git'), 'rev-parse', '--git-dir')
    check(result.returncode != 0, 'accepted explicit invalid git directory')

    # A failed ref/config write must neither replace another writer's lock
    # nor leave a new lock behind. All identities are fixture-only.
    commit = obj('commit', f'tree {safe_tree}\nauthor Test <test@example.test> '
                 '1 +0000\ncommitter Test <test@example.test> 1 +0000\n\nfixture\n'.encode())
    for lock_path, args in (
        (repo/'.git/refs/heads/locked.lock', ('update-ref', 'refs/heads/locked', commit)),
        (repo/'.git/config.lock', ('config', 'review.test', 'blocked')),
    ):
        lock_path.write_bytes(b'another writer\n')
        result = run(*args)
        check(result.returncode != 0, 'ignored another writer lock', args)
        check(lock_path.read_bytes() == b'another writer\n', 'removed foreign lock', args)
        lock_path.unlink()
    check(not (repo/'.git/refs/heads/locked').exists(), 'failed ref write published')
    check((repo/'.git/config').read_bytes() == original_config, 'failed config write published')

    # Global options and temporary assignments stay inside the git child,
    # including after command failure.
    script = ('PATH=; before=$PWD; '
              'git -C "$1" --git-dir="$1/.git" --work-tree="$1" invalid-command '
              '>/dev/null 2>&1; '
              '[[ $PWD == "$before" && ${GIT_DIR-unset} == unset '
              '&& ${GIT_WORK_TREE-unset} == unset ]] || exit 1; '
              'GIT_DIR="$1/.git" git rev-parse --git-dir >/dev/null || exit 2; '
              '[[ ${GIT_DIR-unset} == unset ]]')
    result = subprocess.run([str(BINARY), '--noprofile', '--norc', '-c',
                             script, 'git-isolation', str(repo)],
                            cwd=tmp, env=env, capture_output=True, timeout=20)
    check(result.returncode == 0, 'git leaked cwd/environment', result.stderr)

    # A local transport helper gets the remote's context, not the caller's
    # object store, worktree, index, or alternate directories.
    (repo/'.git/refs/heads/main').write_text(commit + '\n')
    helper = tmp/'upload-check'
    helper.write_text('#!/bin/sh\n'
                      'test -z "${GIT_DIR-}${GIT_WORK_TREE-}${GIT_INDEX_FILE-}'
                      '${GIT_OBJECT_DIRECTORY-}${GIT_ALTERNATE_OBJECT_DIRECTORIES-}" '
                      '|| exit 42\n'
                      f'exec {shlex.quote(GIT)} upload-pack "$@"\n')
    helper.chmod(0o755)
    result = run('ls-remote', '--upload-pack=' + str(helper), repo,
                 extra_env={'GIT_DIR': str(repo/'.git'), 'GIT_WORK_TREE': str(repo),
                            'GIT_INDEX_FILE': str(tmp/'unused-index'),
                            'GIT_OBJECT_DIRECTORY': str(repo/'.git/objects'),
                            'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(repo/'.git/objects')})
    check(result.returncode == 0, 'local helper inherited repository environment', result.stderr)
    check(commit.encode() + b'\trefs/heads/main\n' in result.stdout,
          'local helper returned wrong refs', result.stdout)

print(f'git-integrity: {checks} checks passed')
