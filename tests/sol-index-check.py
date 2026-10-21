#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The index builtin against host git, on private repositories.

Every expectation comes from git itself or from an independent parser of
the index format written here, never from the builtin's own earlier output:

  read      `git ls-files --stage -z` over indexes git wrote (small, 20000
            and 110000 entries, long and unusual paths, conflict stages,
            version 3, every optional extension), and refusal of what git
            cannot read without support this command lacks (split, sparse,
            version 4)
  integrity every truncation and every single-byte change of a small index,
            structural damage under a recomputed trailer, and a seeded
            mutation run whose accepted results git must also accept with
            the same entries
  write     byte-identical files to git's for the same entries, path
            bytes kept exactly, git's mode normalization, refusals
  index-info  scripted and seeded random record streams applied by git and
            by the builtin to copies of one index: same exit class, and on
            success byte-identical files
  add/remove/update-stat  entries compared field by field with git
            update-index --add / --force-remove / --refresh
  atomicity an existing lock, an unwritable directory and injected write,
            short write, fdatasync, close and rename failures: the index
            is unchanged and no lock or temporary file is left

usage: sol-index-check.py --binary out/bash --shim faults.so [--loader
       load.sh --asan libasan.so] [--output report.json]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument('--binary', default='out/bash')
parser.add_argument('--shim', required=True, help='tests/sol-index-faults.c built as a library')
parser.add_argument('--loader', help='BASH_ENV script enabling a sanitized index builtin')
parser.add_argument('--asan', help='libasan to preload with --loader')
parser.add_argument('--output')
parser.add_argument('--seed', type=int, default=20261020)
args = parser.parse_args()
BINARY = str(Path(args.binary).resolve())
SHIM = str(Path(args.shim).resolve())
GIT = shutil.which('git')
assert GIT, 'host git is the oracle and is required'
assert Path(SHIM).is_file(), f'missing fault library {SHIM}'
results = []
failures = 0


def q(value):
    return shlex.quote(str(value))


class Failure(AssertionError):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


def case(name):
    def wrap(fn):
        global failures
        started = time.monotonic()
        try:
            detail = fn() or {}
            results.append({'case': name, 'status': 'pass', 'seconds': round(time.monotonic()-started, 3), **detail})
        except Exception as error:  # every failure is reported, none skipped
            failures += 1
            results.append({'case': name, 'status': 'fail', 'error': repr(error)[:4000]})
            print(f'FAIL {name}: {error!r}'[:4000], file=sys.stderr)
        return fn
    return wrap


def git(root, *argv, data=None, index=None, check_rc=True, extra_env=None):
    env = {**os.environ, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_AUTHOR_NAME': 'a', 'GIT_AUTHOR_EMAIL': 'a@b',
           'GIT_COMMITTER_NAME': 'a', 'GIT_COMMITTER_EMAIL': 'a@b'}
    env.pop('GIT_INDEX_FILE', None)
    env.pop('LD_PRELOAD', None)
    if index is not None:
        env['GIT_INDEX_FILE'] = str(index)
    if extra_env:
        env.update(extra_env)
    r = subprocess.run([GIT, '-C', str(root), *map(str, argv)], input=data,
                       capture_output=True, timeout=120, env=env)
    if check_rc:
        check(r.returncode == 0, (argv, r.stderr[:2000]))
    return r


def bash(script, cwd, data=None, fault=None, env=None, empty_path=True):
    """Run SCRIPT in the binary from a file, so it may be any size."""
    e = {k: v for k, v in os.environ.items() if not k.startswith('SOL_INDEX_')}
    e['LC_ALL'] = 'C'
    preload = []
    if args.loader:
        e['BASH_ENV'] = str(Path(args.loader).resolve())
        e['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
        e['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        if args.asan:
            preload.append(args.asan)
    if fault:
        preload.append(SHIM)
        e['SOL_INDEX_FAULT'] = fault[0]
        e['SOL_INDEX_FAULT_LOG'] = str(fault[1])
    if preload:
        e['LD_PRELOAD'] = ':'.join(preload)
    if env:
        e.update(env)
    prefix = '[ "$(type -t index)" = builtin ] || exit 97\n'
    if empty_path:
        prefix += 'PATH=\n'
    with tempfile.NamedTemporaryFile('wb', suffix='.sh', dir=work) as f:
        f.write((prefix+script).encode() if isinstance(script, str) else prefix.encode()+script)
        f.flush()
        r = subprocess.run([BINARY, '--noprofile', '--norc', f.name], cwd=cwd,
                           input=data, capture_output=True, timeout=300, env=e)
    check(b'AddressSanitizer' not in r.stderr and b'runtime error:' not in r.stderr
          and b'LeakSanitizer' not in r.stderr, r.stderr[:4000])
    check(r.returncode != 97, 'index is not a builtin in this shell')
    return r


# ---- an independent reader of the index format ---------------------------

def parse_index(raw):
    """Entries of an index as git defines the format, or raise."""
    check(raw[:4] == b'DIRC', 'magic')
    version, count = struct.unpack('>II', raw[4:12])
    check(hashlib.sha1(raw[:-20]).digest() == raw[-20:], 'trailer')
    off, entries = 12, []
    for _ in range(count):
        fields = struct.unpack('>10I', raw[off:off+40])
        sha = raw[off+40:off+60].hex()
        flags, = struct.unpack('>H', raw[off+60:off+62])
        head = 62
        flags2 = 0
        if version >= 3 and flags & 0x4000:
            flags2, = struct.unpack('>H', raw[off+62:off+64])
            head = 64
        end = raw.index(b'\0', off+head)
        path = raw[off+head:end]
        size = head+len(path)
        off += size+(8-size % 8)
        entries.append(dict(ctime=fields[0:2], mtime=fields[2:4], dev=fields[4], ino=fields[5],
                            mode=fields[6], uid=fields[7], gid=fields[8], size=fields[9],
                            sha=sha, stage=(flags >> 12) & 3, flags=flags, flags2=flags2, path=path))
    return version, entries, raw[off:-20]


def ls_files(root, index):
    """`git ls-files --stage -z`, as (mode, sha, stage, path) tuples."""
    out = git(root, 'ls-files', '--stage', '-z', index=index).stdout
    rows = []
    for record in out.split(b'\0')[:-1]:
        meta, path = record.split(b'\t', 1)
        mode, sha, stage = meta.split(b' ')
        rows.append((mode, sha, stage, path))
    return rows


def listing(rows):
    return b''.join(b'%s %s %s %s\n' % row for row in rows)


def make_index(root, index, records, z=False):
    data = b''.join(r+(b'\0' if z else b'\n') for r in records)
    git(root, '-c', 'index.version=2', 'update-index', *(['-z'] if z else []),
        '--index-info', data=data, index=index)
    return Path(index).read_bytes()


def blob(root, data):
    return git(root, 'hash-object', '-w', '--stdin', data=data).stdout.strip()


def leftovers(directory):
    return sorted(p.name for p in Path(directory).iterdir()
                  if p.name.endswith('.lock') or '.tmp' in p.name)


def fd_count_script():
    return 'fds=(/proc/$$/fd/*); echo "fds=${#fds[@]}"\n'


work = Path(tempfile.mkdtemp(prefix='sol-index-check.'))
root = work/'repo'
git(work, 'init', '-q', '--object-format=sha1', root)
SHA = [blob(root, b'content %d\n' % i) for i in range(64)]
ZERO = b'0'*40


def rec(mode, sha, path, stage=None, kind=None):
    head = mode if isinstance(mode, bytes) else str(mode).encode()
    middle = b' '+kind if kind else b''
    tail = b'' if stage is None else b' %d' % stage
    return head+middle+b' '+sha+tail+b'\t'+path


# ---- read ------------------------------------------------------------------

@case('read: small git index, list synonym, -V array, repeated in one shell')
def _():
    idx = work/'small.index'
    make_index(root, idx, [rec(100644, SHA[i], b'entry-%05d' % i) for i in range(6)]
               + [rec(100755, SHA[9], b'run.sh'), rec(120000, SHA[10], b'link'),
                  rec(160000, SHA[11], b'sub')])
    expected = listing(ls_files(root, idx))
    script = f'index read {q(idx)} > a\nindex list {q(idx)} > b\n'
    script += f'index read {q(idx)} -V rows\nprintf "%s\\n" "${{rows[@]}}" > c\n'
    script += f'index read -V rows2 {q(idx)}\nprintf "%s\\n" "${{rows2[@]}}" > d\n'
    script += f'for i in {{1..40}}; do index read {q(idx)} > e$i || exit 3; done\n'
    script += fd_count_script()
    r = bash(script, work)
    check(r.returncode == 0, r.stderr)
    for name in ['a', 'b', 'c', 'd'] + [f'e{i}' for i in range(1, 41)]:
        check((work/name).read_bytes() == expected, name)
    return {'entries': 9, 'repeats': 40}


@case('read: 20000 and 110000-entry git indexes, cold and warm, match ls-files')
def _():
    out = {}
    for count in (20000, 110000):
        idx = work/f'big{count}.index'
        make_index(root, idx, [rec(100644, SHA[i % 64], b'dir%03d/file-%06d.txt' % (i % 251, i))
                                for i in range(count)])
        expected = listing(ls_files(root, idx))
        r = bash(f'index read {q(idx)} > big1\nindex read {q(idx)} > big2\n'
                 f'index read {q(idx)} -V rows\necho ${{#rows[@]}} > n\n', work)
        check(r.returncode == 0, r.stderr)
        check((work/'big1').read_bytes() == expected, f'{count} first')
        check((work/'big2').read_bytes() == expected, f'{count} second')
        check((work/'n').read_text().strip() == str(count), 'array length')
        out[f'bytes_{count}'] = idx.stat().st_size
    return out


@case('read: long and unusual path bytes, beyond 0xFFF, 8 KiB and the 64 KiB buffer')
def _():
    idx = work/'paths.index'
    names = [b'x'*n for n in (1, 7, 8, 4094, 4095, 4096, 5000, 9000, 70000)]
    names += [b' lead', b'trail ', b'tab\tin', b'cr\r', b'quote"s', b'back\\slash',
              b'\xc3\xa9t\xc3\xa9', b'nl\nin', b'dir/sub dir/f', b'-dash', b'*star']
    records = [rec(100644, SHA[i], name) for i, name in enumerate(names)]
    make_index(root, idx, records, z=True)
    rows = ls_files(root, idx)
    check(sorted(r[3] for r in rows) == sorted(names), 'git kept every path')
    r = bash(f'index read {q(idx)} > out\nindex read {q(idx)} -V rows\n'
             'printf "%s\\0" "${rows[@]}" > arr\n', work)
    check(r.returncode == 0, r.stderr)
    check((work/'out').read_bytes() == listing(rows), 'stdout listing')
    check((work/'arr').read_bytes() == b''.join(b'%s %s %s %s\0' % row for row in rows), 'array')
    return {'longest': max(map(len, names))}


@case('read: conflict stages in git order, mode printed as six octal digits')
def _():
    idx = work/'stages.index'
    make_index(root, idx, [rec(100644, SHA[3], b'p', 3), rec(100644, SHA[1], b'p', 1),
                           rec(100755, SHA[2], b'p', 2), rec(100644, SHA[4], b'q'),
                           rec(100644, SHA[5], b'p', 2)])
    rows = ls_files(root, idx)
    check([r[2] for r in rows] == [b'1', b'2', b'3', b'0'], rows)
    r = bash(f'index read {q(idx)}', work)
    check(r.returncode == 0 and r.stdout == listing(rows), r.stdout)
    return {}


@case('read: version 3 (intent-to-add) and every optional extension git writes')
def _():
    repo = work/'extrepo'
    git(work, 'init', '-q', repo)
    for i in range(4):
        (repo/f'f{i}').write_text(f'{i}\n')
    (repo/'d').mkdir()
    (repo/'d'/'x').write_text('x\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'one')
    (repo/'new').write_text('new\n')
    git(repo, 'add', '-N', 'new')
    raw = (repo/'.git'/'index').read_bytes()
    version, entries, _ = parse_index(raw)
    check(version == 3 and any(e['flags2'] for e in entries), 'git wrote v3 with flags2')
    expected = listing(ls_files(repo, repo/'.git'/'index'))
    r = bash('index read .git/index', repo)
    check(r.returncode == 0 and r.stdout == expected, (r.stdout, r.stderr))
    before = raw
    stamp = (repo/'.git'/'index').stat().st_mtime_ns
    r = bash('index --index-info .git/index', repo, data=b'')
    check(r.returncode == 0, r.stderr)
    check((repo/'.git'/'index').read_bytes() == before and
          (repo/'.git'/'index').stat().st_mtime_ns == stamp, 'v3 no-op untouched')
    r = bash('index add .git/index ' + SHA[0].decode() + ' f0', repo)
    check(r.returncode == 0, r.stderr)
    _, after_entries, _ = parse_index((repo/'.git'/'index').read_bytes())
    check([(e['path'], e['flags2']) for e in after_entries if e['flags2']] ==
          [(e['path'], e['flags2']) for e in entries if e['flags2']], 'v3 flags preserved')
    check(not leftovers(repo/'.git'), 'v3 lock released')
    # Restore this unrelated-edit fixture before the extension/merge fixture.
    (repo/'.git'/'index').write_bytes(before)
    # TREE, REUC, UNTR, EOIE, IEOT
    git(repo, 'rm', '-q', '--cached', 'new')
    git(repo, 'write-tree')
    git(repo, 'checkout', '-qb', 'side')
    (repo/'f1').write_text('side\n')
    git(repo, 'commit', '-qam', 'side')
    git(repo, 'checkout', '-q', 'master' if git(repo, 'rev-parse', '--verify', '-q', 'master', check_rc=False).returncode == 0 else 'main')
    (repo/'f1').write_text('main\n')
    git(repo, 'commit', '-qam', 'main')
    git(repo, 'merge', 'side', check_rc=False)
    (repo/'f1').write_text('resolved\n')
    git(repo, 'add', 'f1')
    git(repo, '-c', 'core.untrackedCache=true', '-c', 'index.recordEndOfIndexEntries=true',
        '-c', 'index.recordOffsetTable=true', '-c', 'index.threads=2', 'update-index',
        '--untracked-cache', '--index-version', '2')
    git(repo, '-c', 'core.untrackedCache=true', '-c', 'index.recordEndOfIndexEntries=true',
        '-c', 'index.recordOffsetTable=true', '-c', 'index.threads=2', 'status', '--porcelain')
    raw = (repo/'.git'/'index').read_bytes()
    _, _, ext = parse_index(raw)
    found = set()
    while len(ext) >= 8:
        sig, size = ext[:4], struct.unpack('>I', ext[4:8])[0]
        found.add(sig.decode())
        ext = ext[8+size:]
    check({'TREE', 'REUC', 'UNTR'} <= found, found)
    expected = listing(ls_files(repo, repo/'.git'/'index'))
    r = bash('index read .git/index', repo)
    check(r.returncode == 0 and r.stdout == expected, (r.stdout, r.stderr))
    return {'extensions': sorted(found)}


@case('read: split index, sparse index and version 4 are refused, not misread')
def _():
    out = {}
    repo = work/'splitrepo'
    git(work, 'init', '-q', repo)
    (repo/'a').write_text('a\n')
    git(repo, 'add', 'a')
    git(repo, 'update-index', '--split-index')
    check(any(p.name.startswith('sharedindex.') for p in (repo/'.git').iterdir()), 'split index made')
    r = bash('index read .git/index', repo)
    check(r.returncode == 1 and r.stdout == b'' and r.stderr.strip(), r.stderr)
    out['split_message'] = r.stderr.decode(errors='replace').strip()[-120:]
    repo = work/'sparserepo'
    git(work, 'init', '-q', repo)
    for d in ('d', 'e'):
        (repo/d).mkdir()
        (repo/d/'f').write_text(d)
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'x')
    git(repo, 'sparse-checkout', 'init', '--cone', '--sparse-index')
    git(repo, 'sparse-checkout', 'set', 'd')
    r = bash('index read .git/index', repo)
    check(r.returncode == 1 and r.stdout == b'', r.stderr)
    out['sparse_message'] = r.stderr.decode(errors='replace').strip()[-120:]
    idx = work/'v4.index'
    git(root, '-c', 'index.version=4', 'update-index', '--index-info',
        data=rec(100644, SHA[0], b'a/b')+b'\n', index=idx)
    check(struct.unpack('>I', idx.read_bytes()[4:8])[0] == 4, 'git wrote v4')
    r = bash(f'index read {q(idx)}', work)
    check(r.returncode == 1 and r.stdout == b'' and b'version 4' in r.stderr, r.stderr)
    return out


@case('read: output failures leave the shell stdout usable; usage and variable errors')
def _():
    idx, big = work/'small.index', work/'big20000.index'
    script = f'index read {q(idx)} > /dev/full; echo "small=$?"\n'
    script += f'index read {q(big)} > /dev/full; echo "big=$?"\n'
    script += f'index read {q(idx)} >&-; echo "closed=$?"\n'
    script += f'index read {q(idx)} > /dev/null; echo "after=$?"\n'
    script += 'index; echo "none=$?"\nindex read; echo "nopath=$?"\n'
    script += f'index read {q(idx)} extra; echo "extra=$?"\nindex bogus; echo "verb=$?"\n'
    script += f'index read {q(idx)} -V; echo "noname=$?"\nindex read {q(idx)} -V 1bad; echo "badname=$?"\n'
    script += f'readonly RO=keep; index read {q(idx)} -V RO; echo "ro=$?:$RO"\n'
    script += f'index read {q(idx)} -Q; echo "flag=$?"\nindex read {q(work)}; echo "dir=$?"\n'
    script += f'index read {q(work/"missing")}; echo "missing=$?"\n'
    script += 'v=(old); index read ' + q(work/'missing') + ' -V v; echo "kept=${v[0]}"\n'
    r = bash(script, work)
    got = dict(line.split('=', 1) for line in r.stdout.decode().split())
    check(got == {'small': '1', 'big': '1', 'closed': '1', 'after': '0', 'none': '2',
                  'nopath': '2', 'extra': '2', 'verb': '2', 'noname': '2', 'badname': '2',
                  'ro': '1:keep', 'flag': '2', 'dir': '1', 'missing': '1', 'kept': 'old'},
          (got, r.stderr))
    check(r.stderr.count(b'write error') >= 3, r.stderr)
    return {}


# ---- integrity ---------------------------------------------------------------

def run_reads(paths, cwd):
    """Read each index in one shell; return {name: (status, stdout)}."""
    script = ''.join(f'index read {q(p)} > {q(str(p)+".out")} 2>/dev/null; echo "$?" > {q(str(p)+".rc")}\n'
                     for p in paths)
    r = bash(script, cwd)
    check(r.returncode == 0, r.stderr)
    return {p: (int(Path(str(p)+'.rc').read_text()), Path(str(p)+'.out').read_bytes()) for p in paths}


@case('integrity: every truncation and every single-byte change of a small index is refused')
def _():
    good = make_index(root, work/'tiny.index', [rec(100644, SHA[0], b'alpha'),
                                                 rec(100755, SHA[1], b'dir/beta', 0),
                                                 rec(100644, SHA[2], b'gamma', 2)])
    d = work/'damage'
    d.mkdir()
    paths = []
    for n in range(len(good)):
        p = d/f'trunc{n}'
        p.write_bytes(good[:n])
        paths.append(p)
    for i in range(len(good)):
        p = d/f'flip{i}'
        b = bytearray(good)
        b[i] ^= 0x01 if i % 2 else 0x80
        p.write_bytes(bytes(b))
        paths.append(p)
    p = d/'appended'
    p.write_bytes(good+b'\0')
    paths.append(p)
    results_ = run_reads(paths, work)
    bad = [str(p) for p, (rc, out) in results_.items() if rc != 1 or out]
    check(not bad, bad[:5])
    return {'variants': len(paths)}


def craft(entries, version=2, ext=b'', count=None):
    body = b'DIRC'+struct.pack('>II', version, len(entries) if count is None else count)
    for e in entries:
        body += e
    body += ext
    return body+hashlib.sha1(body).digest()


def entry(path, stage=0, mode=0o100644, flags_extra=0, flags2=None, pathlen=None, pad=None, sha=None):
    path = path if isinstance(path, bytes) else path.encode()
    flags = (stage << 12) | (min(len(path), 0xFFF) if pathlen is None else pathlen) | flags_extra
    e = struct.pack('>10I', 0, 0, 0, 0, 0, 0, mode, 0, 0, 0)+(sha or bytes.fromhex(SHA[0].decode()))
    e += struct.pack('>H', flags)
    if flags2 is not None:
        e += struct.pack('>H', flags2)
    e += path+b'\0'
    while len(e) % 8:
        e += b'\0' if pad is None else pad
    return e


@case('integrity: structural damage under a valid trailer is refused')
def _():
    d = work/'crafted'
    d.mkdir()
    variants = {
        'count-high': craft([entry('a')], count=2),
        'count-huge': craft([entry('a')], count=0xFFFFFFFF),
        'pathlen-short': craft([entry('abc', pathlen=2)]),
        'pathlen-long': craft([entry('abc', pathlen=5)]),
        'pad-nonzero': craft([entry('abcdefgh', pad=b'\x01')]),
        'v2-extended': craft([entry('a', flags_extra=0x4000)]),
        'v3-flags2-unknown': craft([entry('a', flags_extra=0x4000, flags2=0x0001)], 3),
        'unordered': craft([entry('b'), entry('a')]),
        'repeated': craft([entry('a'), entry('a')]),
        'repeated-stage': craft([entry('a', 2), entry('a', 2)]),
        'stage-down': craft([entry('a', 3), entry('a', 1)]),
        'stage-zero-after': craft([entry('a', 2), entry('a', 0)]),
        'ext-truncated': craft([entry('a')], ext=b'TREE'+struct.pack('>I', 40)+b'\0'*8),
        'ext-short-header': craft([entry('a')], ext=b'TRE'),
        'ext-lowercase': craft([entry('a')], ext=b'zzzz'+struct.pack('>I', 0)),
        'ext-link': craft([entry('a')], ext=b'link'+struct.pack('>I', 20)+b'\0'*20),
        'ext-sdir': craft([entry('a')], ext=b'sdir'+struct.pack('>I', 0)),
        'junk-after': craft([entry('a')], ext=b'\0'*5),
        'path-dotgit': craft([entry('.git/config')]),
        'path-dotGIT': craft([entry('x/.GIT/y')]),
        'path-dotdot': craft([entry('a/../b')]),
        'path-dot': craft([entry('./a')]),
        'path-empty-component': craft([entry('a//b')]),
        'path-trailing-slash': craft([entry('a/')]),
        'path-absolute': craft([entry('/etc/passwd')]),
        'path-empty': craft([entry('')]),
        'version-1': craft([entry('a')], 1),
        'version-5': craft([entry('a')], 5),
        'magic': b'DIRX'+craft([entry('a')])[4:-20],
    }
    variants['magic'] += hashlib.sha1(variants['magic']).digest()
    accepted = {'stage-zero-then-two': craft([entry('a', 0), entry('a', 2)]),
                'ext-upper-unknown': craft([entry('a')], ext=b'ZZZZ'+struct.pack('>I', 3)+b'abc'),
                'v3-skip-worktree': craft([entry('a', flags_extra=0x4000, flags2=0x4000)], 3),
                'empty': craft([])}
    paths = {}
    for name, raw in {**variants, **accepted}.items():
        p = d/name
        p.write_bytes(raw)
        paths[name] = p
    got = run_reads(list(paths.values()), work)
    wrong = [n for n in variants if got[paths[n]] != (1, b'')]
    check(not wrong, wrong)
    for n in accepted:
        rc, out = got[paths[n]]
        check(rc == 0, n)
        check(out == listing(ls_files(root, paths[n])), n)
    return {'refused': len(variants), 'accepted': len(accepted)}


@case('integrity: seeded mutations; anything accepted git reads to the same entries')
def _():
    rng = random.Random(args.seed)
    base = make_index(root, work/'mut-base.index',
                      [rec(100644, SHA[i], p) for i, p in enumerate(
                          [b'a', b'b/c', b'b/d', b'e f', b'g'*20])]+[rec(100644, SHA[9], b'h', 2)])
    d = work/'mutations'
    d.mkdir()
    paths = []
    for n in range(500):
        body = bytearray(base[:-20])
        for _ in range(rng.randint(1, 4)):
            choice = rng.random()
            i = rng.randrange(len(body))
            if choice < 0.6:
                body[i] = rng.randrange(256)
            elif choice < 0.8:
                del body[i:i+rng.randint(1, 8)]
            else:
                body[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        raw = bytes(body)+hashlib.sha1(bytes(body)).digest()
        p = d/f'm{n}'
        p.write_bytes(raw)
        paths.append(p)
    got = run_reads(paths, work)
    accepted = 0
    for p in paths:
        rc, out = got[p]
        check(rc in (0, 1), (p, rc))
        if rc == 0:
            accepted += 1
            r = git(root, 'ls-files', '--stage', '-z', index=p, check_rc=False)
            check(r.returncode == 0, (p, r.stderr))
            check(out == listing(ls_files(root, p)), p)
        else:
            check(out == b'', p)
    return {'mutations': len(paths), 'accepted': accepted}


# ---- write -------------------------------------------------------------------

@case('write: byte-identical to git for the same entries; ls-files output accepted')
def _():
    records = [rec(100644, SHA[i], b'f%03d' % i, i % 4 if i % 5 == 0 else 0) for i in range(50)]
    records += [rec(100755, SHA[51], b'zz/exec'), rec(120000, SHA[52], b'zz/link'),
                rec(160000, SHA[53], b'zz/mod')]
    ref = make_index(root, work/'w-ref.index', records)
    listing_ = listing(ls_files(root, work/'w-ref.index'))
    tabbed = git(root, 'ls-files', '--stage', index=work/'w-ref.index').stdout
    shuffled = b''.join(sorted(listing_.splitlines(True), key=lambda l: hashlib.sha1(l).digest()))
    (work/'l1').write_bytes(listing_)
    (work/'l2').write_bytes(tabbed)
    (work/'l3').write_bytes(shuffled)
    r = bash('index write w1 < l1 && index write w2 < l2 && index write w3 < l3 && index read w1 > r1', work)
    check(r.returncode == 0, r.stderr)
    for name in ('w1', 'w2', 'w3'):
        check((work/name).read_bytes() == ref, name)
    check((work/'r1').read_bytes() == listing_, 'read back')
    check(not leftovers(work), leftovers(work))
    return {'entries': len(records)}


@case('write: path bytes kept exactly, git mode normalization, empty input')
def _():
    names = [b' lead', b'trail ', b'two  spaces', b'tab\there', b'cr\r', b'\xff\xfe']
    lines = b''.join(b'100644 %s 0 %s\n' % (SHA[i], n) for i, n in enumerate(names))
    lines += b'100644 %s 0\t%s\n' % (SHA[10], b'\ttab-led')
    modes = {b'100664': b'100644', b'644': b'100644', b'100700': b'100755', b'755': b'100755',
             b'120777': b'120000', b'160000': b'160000', b'40755': b'160000', b'100600': b'100644'}
    for i, m in enumerate(modes):
        lines += b'%s %s 0 mode-%d\n' % (m, SHA[20+i], i)
    (work/'pathlines').write_bytes(lines)
    r = bash('index write wp < pathlines && : | index write we', work)
    check(r.returncode == 0, r.stderr)
    rows = ls_files(root, work/'wp')
    got = {row[3]: row for row in rows}
    for n in names+[b'\ttab-led']:
        check(n in got, n)
    for i, (m, want) in enumerate(modes.items()):
        check(got[b'mode-%d' % i][0] == want, (m, got[b'mode-%d' % i]))
        # git normalizes the same mode the same way
        git(root, 'update-index', '--index-info', data=rec(m, SHA[0], b'm')+b'\n', index=work/'gm.index')
        check(ls_files(root, work/'gm.index')[0][0] == want, ('git', m))
        (work/'gm.index').unlink()
    # git writes an empty index once a change leaves it so
    empty = make_index(root, work/'empty-ref.index', [rec(100644, SHA[0], b'gone'), rec(0, ZERO, b'gone')])
    check((work/'we').read_bytes() == empty, 'empty index equals git')
    return {}


@case('write: refusals leave the file untouched; stdin read error is not EOF')
def _():
    target = work/'wt.index'
    original = make_index(root, target, [rec(100644, SHA[0], b'keep')])
    bad = [b'garbage %s 0 x\n' % SHA[0], b'100644 %s 0 x\n' % SHA[0][:39], b'100644 %s 4 x\n' % SHA[0],
           b'100644 %s 0\n' % SHA[0], b'100644 %s 0 \n' % SHA[0], b'0 %s 0 x\n' % SHA[0],
           b'100644 %s 0 .git/x\n' % SHA[0], b'100644 %s 0 a/../b\n' % SHA[0],
           b'100644 %s 0 a//b\n' % SHA[0], b'40000 %s 0 d\n' % SHA[0], b'100644 %s 0 git~1/x\n' % SHA[0],
           b'100644 %s 0 x\n100644 %s 0 x\n' % (SHA[0], SHA[1]),
           b'100644 %s 2 x\n100755 %s 2 x\n' % (SHA[0], SHA[1]), b'100644 zz%s 0 x\n' % SHA[0][2:]]
    script = ''
    for i, data in enumerate(bad):
        (work/f'bad{i}').write_bytes(data)
        script += f'index write wt.index < bad{i}; echo "$?"\n'
    script += f'index write wt.index < {q(work)}; echo "$?"\n'
    r = bash(script, work)
    codes = r.stdout.split()
    check(codes == [b'2']*len(bad)+[b'1'], (codes, r.stderr))
    check(target.read_bytes() == original and not leftovers(work), 'untouched')
    return {'refusals': len(bad)+1}


# ---- --index-info ------------------------------------------------------------

def apply_both(start, stream, z=False, name='ii'):
    """Apply STREAM to copies of START with git and with the builtin."""
    g, b = work/f'{name}-git.index', work/f'{name}-ours.index'
    for p in (g, b):
        if p.exists():
            p.unlink()
        if start is not None:
            p.write_bytes(start)
    (work/f'{name}.in').write_bytes(stream)
    gr = git(root, '-c', 'index.version=2', 'update-index', *(['-z'] if z else []), '--index-info',
             data=stream, index=g, check_rc=False)
    br = bash(f'index --index-info {"-z " if z else ""}{q(b)} < {q(work/(name+".in"))}', work)
    return gr, br, g, b


def same_outcome(start, stream, z=False, label=''):
    gr, br, g, b = apply_both(start, stream, z)
    if gr.returncode == 0:
        check(br.returncode == 0, (label, stream, br.stderr))
        # git writes nothing when nothing changed, not even a new empty index
        got = b.read_bytes() if b.exists() else None
        want = g.read_bytes() if g.exists() else None
        check(got == want, (label, stream, want and ls_files(root, g), got and ls_files(root, b)))
    else:
        check(gr.returncode == 128 and br.returncode == 2, (label, stream, gr.returncode, br.returncode, br.stderr))
        check((b.read_bytes() if b.exists() else None) == (start if start is not None else None), (label, 'changed'))
    check(not leftovers(work), leftovers(work))
    return gr.returncode == 0


@case('index-info: scripted records give git\'s exact index and exit class')
def _():
    S = SHA
    start = make_index(root, work/'ii-start.index', [rec(100644, S[0], b'p'), rec(100644, S[1], b'q', 1),
                                                     rec(100644, S[2], b'q', 3), rec(100644, S[3], b'r/s')])
    scripts = {
        'replace same stage': [rec(100644, S[5], b'p')],
        'higher stage beside 0': [rec(100644, S[5], b'p', 2)],
        'stage 0 displaces conflict': [rec(100644, S[5], b'q', 0)],
        'replace conflict stage': [rec(100755, S[5], b'q', 3)],
        'mode 0 removes all stages': [rec(0, ZERO, b'q')],
        'mode 0 any stage form': [rec(0, S[1], b'q', 2)],
        'remove missing': [rec(0, ZERO, b'nothing')],
        'file replaces directory': [rec(100644, S[6], b'r')],
        'directory replaces file': [rec(100644, S[6], b'p/x')],
        'other-stage D/F coexists': [rec(100644, S[6], b'r', 1)],
        'deep D/F': [rec(100644, S[6], b'r/s/t/u')],
        'type field': [rec(100644, S[7], b'typed', kind=b'blob'), rec(160000, S[8], b'mod', kind=b'commit')],
        'type and stage': [rec(100644, S[7], b'ts', 2, kind=b'blob')],
        'free middle text': [b'100644 any words here ' + S[9] + b'\tfree'],
        'quoted path': [rec(100644, S[9], b'"q\\tx\\101\\"\\\\"')],
        'quoted NUL ends name': [rec(100644, S[9], b'"ab\\000cd"')],
        'quoted then text': [rec(100644, S[9], b'"name" trailing')],
        'spaces kept': [rec(100644, S[9], b' lead'), rec(100644, S[9], b'trail ')],
        'CR kept': [rec(100644, S[9], b'cr\r')],
        'uppercase hex': [rec(100644, S[9].upper(), b'up')],
        'leading blank mode': [b' 100644 ' + S[9] + b'\tlb'],
        'plus mode': [b'+100644 ' + S[9] + b'\tplus'],
        'mode normalization': [rec(m, S[10], b'm' + m) for m in (b'100664', b'644', b'100700', b'120777', b'40755', b'1')],
        'ignored paths': [rec(100644, S[11], p) for p in (b'.git/x', b'a/.GIT', b'.git. ', b'git~1/x', b'.git ',
                                                         b'a/../b', b'./a', b'a//b', b'a/', b'', b'x\\.git',
                                                         b'x\\git~1\\y', b'.', b'..')],
        'symlink gitmodules': [rec(120000, S[12], p) for p in (b'.gitmodules', b'.GITMODULES', b'gitmod~1',
                                                              b'gi7eba~9', b'gitmod~5', b'.gitmodules. ',
                                                              b'.gitmodules:x', b'a/.gitmodules')],
        'regular gitmodules allowed': [rec(100644, S[12], b'.gitmodules')],
        'ordered bulk': [rec(100644, S[i % 64], b'bulk/%04d' % i) for i in range(300)],
        'reverse bulk': [rec(100644, S[i % 64], b'rev/%04d' % i) for i in reversed(range(300))],
        'add then remove then add': [rec(100644, S[1], b'z'), rec(0, ZERO, b'z'), rec(100755, S[2], b'z', 2)],
        'malformed stage 4': [rec(100644, S[1], b'ok'), rec(100644, S[1], b'x', 4)],
        'malformed two spaces': [b'100644  ' + S[1] + b'\tx'],
        'malformed short sha': [b'100644 ' + S[1][:39] + b'\tx'],
        'malformed extra token': [b'100644 ' + S[1] + b' 0 extra\tx'],
        'malformed no tab': [b'100644 ' + S[1] + b' x'],
        'malformed empty line': [rec(100644, S[1], b'ok'), b''],
        'malformed mode': [b'10064x ' + S[1] + b'\tx'],
        'malformed huge mode': [b'77777777777 ' + S[1] + b'\tx'],
        'bad quoting': [rec(100644, S[1], b'"unterminated')],
        'bad escape': [rec(100644, S[1], b'"bad\\q"')],
        'bad octal': [rec(100644, S[1], b'"o\\48"')],
    }
    outcomes = {}
    for label, records in scripts.items():
        outcomes[label] = same_outcome(start, b''.join(r+b'\n' for r in records), label=label)
    # without an existing index, and NUL-terminated records
    same_outcome(None, rec(100644, S[1], b'fresh')+b'\n', label='fresh index')
    same_outcome(start, b''.join(r+b'\0' for r in [rec(100644, S[1], b'nl\nname'), rec(100644, S[2], b'"raw"'),
                                                   rec(0, ZERO, b'p')]), z=True, label='-z')
    return {'scripts': len(scripts)+2, 'git_accepted': sum(outcomes.values())}


@case('index-info: refusal of sparse directory entries leaves the index untouched')
def _():
    start = make_index(root, work/'sp.index', [rec(100644, SHA[0], b'a')])
    gr, br, g, b = apply_both(start, rec(40000, SHA[1], b'd')+b'\n', name='sparse')
    check(br.returncode == 2 and b'sparse directory' in br.stderr and b.read_bytes() == start, br.stderr)
    return {'git_status': gr.returncode}


@case('index-info: seeded random streams match git byte for byte')
def _():
    rng = random.Random(args.seed+1)
    paths = [b'a', b'a/b', b'a/b/c', b'a/c', b'a-b', b'a.b', b'b', b'b/a', b'c', b'a b', b'ab', b'a/b-c',
             b'a/bc', b'b/a/c']
    modes = [b'100644', b'100755', b'120000', b'160000', b'100664', b'0']
    start = make_index(root, work/'rnd-start.index', [rec(100644, SHA[0], b'a/b'), rec(100644, SHA[1], b'b'),
                                                      rec(100644, SHA[2], b'c', 2)])
    accepted = 0
    for n in range(260):
        records = []
        for _ in range(rng.randint(1, 14)):
            path = rng.choice(paths)
            mode = rng.choice(modes)
            stage = rng.choice([None, None, 0, 1, 2, 3])
            kind = b'blob' if rng.random() < 0.15 else None
            sha = SHA[rng.randrange(64)] if mode != b'0' or rng.random() < 0.5 else ZERO
            if rng.random() < 0.08:
                path = b'"' + path.replace(b'/', b'\\057') + b'"'
            records.append(rec(mode, sha, path, stage, kind))
        accepted += same_outcome(start if n % 3 else None, b''.join(r+b'\n' for r in records), label=f'random {n}')
    return {'streams': 260, 'git_accepted': accepted}


@case('index-info: 20000 records in order and in reverse match git')
def _():
    forward = [rec(100644, SHA[i % 64], b'imp/%03d/%05d' % (i % 97, i)) for i in range(20000)]
    out = {}
    for label, records in (('forward', forward), ('reverse', forward[::-1])):
        started = time.monotonic()
        check(same_outcome(None, b''.join(r+b'\n' for r in records), label=label), label)
        out[label+'_seconds'] = round(time.monotonic()-started, 3)
    return out


# ---- add / remove / update-stat -----------------------------------------------

def entry_fields(raw, path):
    for e in parse_index(raw)[1]:
        if e['path'] == path and e['stage'] == 0:
            return e
    raise Failure(f'{path!r} not in index')


@case('add: entries field-for-field equal to git update-index --add')
def _():
    repo = work/'addrepo'
    git(work, 'init', '-q', repo)
    files = {'plain': (b'plain\n', 0o644), 'group': (b'group\n', 0o664), 'exec': (b'#!x\n', 0o755),
             'ownerx': (b'o\n', 0o700), 'sub/deep': (b'deep\n', 0o644)}
    for name, (body, mode) in files.items():
        (repo/name).parent.mkdir(exist_ok=True)
        (repo/name).write_bytes(body)
        (repo/name).chmod(mode)
    os.symlink('plain', repo/'link')
    old = time.time() - 100
    for name in list(files)+['link']:
        os.utime(repo/name, (old, old), follow_symlinks=False)
    shas = {n: git(repo, 'hash-object', '-w', n).stdout.strip().decode() for n in files}
    shas['link'] = git(repo, 'hash-object', '-w', '--stdin', data=b'plain').stdout.strip().decode()
    script = ''.join(f'index add ours.index {shas[n]} {q(n)}\n' for n in sorted(shas))
    r = bash(script, repo)
    check(r.returncode == 0, r.stderr)
    git(repo, 'update-index', '--add', *sorted(shas), index=repo/'git.index')
    ours, theirs = (repo/'ours.index').read_bytes(), (repo/'git.index').read_bytes()
    for n in shas:
        a, b = entry_fields(ours, n.encode()), entry_fields(theirs, n.encode())
        check(a == b, (n, a, b))
    check(ours == theirs, 'whole index identical')
    check(not leftovers(repo), leftovers(repo))
    return {'files': len(shas)}


@case('add: stages, replacement, D/F refusal and bad arguments')
def _():
    repo = work/'addrepo'
    sha = SHA[3].decode()
    idx = repo/'st.index'
    start = make_index(root, idx, [rec(100644, SHA[0], b'plain', 1), rec(100644, SHA[1], b'plain', 2),
                                   rec(100644, SHA[2], b'plain', 3), rec(100644, SHA[4], b'sub')])
    script = f'index add st.index {sha} plain 0; echo "a=$?"\n'
    r = bash(script, repo)
    check(r.stdout.split() == [b'a=0'], r.stderr)
    rows = ls_files(root, idx)
    check([(r_[3], r_[2]) for r_ in rows] == [(b'plain', b'0'), (b'sub', b'0')], rows)
    idx.write_bytes(start)
    r = bash(f'index add st.index {sha} exec 2; echo "b=$?"\nindex add st.index {sha} plain 2; echo "c=$?"\n', repo)
    rows = ls_files(root, idx)
    check([(r_[3], r_[2], r_[1]) for r_ in rows] ==
          [(b'exec', b'2', SHA[3]), (b'plain', b'1', SHA[0]), (b'plain', b'2', SHA[3]),
           (b'plain', b'3', SHA[2]), (b'sub', b'0', SHA[4])], rows)
    before = idx.read_bytes()
    script = f'index add st.index {sha} sub/deep; echo "df=$?"\n'
    script += f'index add st.index {sha} sub/deep 0 extra; echo "many=$?"\n'
    script += f'index add st.index nothex plain; echo "sha=$?"\nindex add st.index {sha} plain 7; echo "stage=$?"\n'
    script += f'index add st.index {sha} missing; echo "missing=$?"\nindex add st.index {sha} sub/; echo "dir=$?"\n'
    script += f'index add st.index {sha}; echo "few=$?"\n'
    r = bash(script, repo)
    check(r.stdout.split() == [b'df=1', b'many=2', b'sha=2', b'stage=2', b'missing=2', b'dir=2', b'few=2'],
          (r.stdout, r.stderr))
    check(b'both a file and as a directory' in r.stderr, r.stderr)
    check(idx.read_bytes() == before and not leftovers(repo), 'unchanged')
    git_df = git(repo, 'update-index', '--add', 'sub/deep', index=work/'df.index', check_rc=False)
    return {'git_df_status': git_df.returncode}


@case('remove: every stage goes, as with git update-index --force-remove')
def _():
    idx = work/'rm.index'
    records = [rec(100644, SHA[0], b'a', 1), rec(100644, SHA[1], b'a', 2), rec(100644, SHA[2], b'a', 3),
               rec(100644, SHA[3], b'a/b'), rec(100644, SHA[4], b'b')]
    make_index(root, idx, records)
    make_index(root, work/'rm-git.index', records)
    git(root, 'update-index', '--force-remove', 'a', index=work/'rm-git.index')
    r = bash('index remove rm.index a; echo "$?"\nindex remove rm.index a; echo "$?"\n'
             'index remove rm.index; echo "$?"\n', work)
    check(r.stdout.split() == [b'0', b'1', b'2'], (r.stdout, r.stderr))
    check(idx.read_bytes() == (work/'rm-git.index').read_bytes(), ls_files(root, idx))
    check(b'not in the index' in r.stderr and not leftovers(work), r.stderr)
    return {}


@case('update-stat: refreshed entry equals git --refresh and git sees the file clean')
def _():
    repo = work/'refresh'
    git(work, 'init', '-q', repo)
    (repo/'f').write_text('same\n')
    (repo/'g').write_text('other\n')
    (repo/'x').write_text('x\n')
    git(repo, 'add', 'f', 'g', 'x')
    git(repo, 'commit', '-qm', 'base')
    os.utime(repo/'.git'/'index', (time.time()-50, time.time()-50))
    (repo/'x').chmod(0o755)
    time.sleep(1.1)
    os.utime(repo/'f')
    shutil.copy2(repo/'.git'/'index', repo/'git.index')
    shutil.copy2(repo/'.git'/'index', repo/'ours.index')
    git(repo, 'update-index', '--refresh', index=repo/'git.index', check_rc=False)
    r = bash('index update-stat ours.index f; echo "$?"\nindex update-stat ours.index x; echo "$?"\n'
             'index update-stat ours.index git.index; echo "$?"\nindex update-stat ours.index nothere; echo "$?"\n'
             'index update-stat ours.index; echo "$?"\n', repo)
    check(r.stdout.split() == [b'0', b'0', b'1', b'2', b'2'], (r.stdout, r.stderr))
    a = entry_fields((repo/'ours.index').read_bytes(), b'f')
    b = entry_fields((repo/'git.index').read_bytes(), b'f')
    check(a == b, (a, b))
    check(entry_fields((repo/'ours.index').read_bytes(), b'x')['mode'] == 0o100644, 'mode kept')
    diff = git(repo, 'diff-files', '--name-only', index=repo/'ours.index').stdout
    check(b'f\n' not in diff.splitlines(True), diff)
    check(not leftovers(repo), leftovers(repo))
    return {}


@case('repeated mutations in one shell; no stamp, lock, temporary file or descriptor survives')
def _():
    d = work/'repeat'
    d.mkdir()
    (d/'f').write_text('f\n')
    old = time.time()-1000
    os.utime(d/'f', (old, old))
    sha = SHA[5].decode()
    # a fresh shell is the reference for the add
    r = bash(f'index add fresh.index {sha} f', d)
    check(r.returncode == 0, r.stderr)
    script = fd_count_script()
    script += f'index read {q(work/"big20000.index")} > /dev/null\n'
    script += f'index add after-read.index {sha} f\n'
    script += f'printf "100644 {sha} 0 f\\n" | index write w.index\n'
    for i in range(20):
        script += f'printf "100644 {SHA[i].decode()}\\tg{i}\\n" | index --index-info w.index\n'
        script += 'index remove w.index f\nindex add w.index ' + sha + ' f\nindex update-stat w.index f\n'
        script += 'index remove w.index nothere 2>/dev/null; index read w.index > /dev/null\n'
    script += fd_count_script()
    r = bash(script, d)
    check(r.returncode == 0, r.stderr)
    counts = [line for line in r.stdout.split() if line.startswith(b'fds=')]
    check(len(counts) == 2 and counts[0] == counts[1], counts)
    check((d/'after-read.index').read_bytes() == (d/'fresh.index').read_bytes(), 'no stamp from the earlier read')
    rows = ls_files(root, d/'w.index')
    check([row[3] for row in rows] == [b'f']+sorted(b'g%d' % i for i in range(20)), rows)
    check(not leftovers(d), leftovers(d))
    return {'iterations': 20}


# ---- locking and atomic failure ---------------------------------------------

VERBS = {
    'write': 'index write {i} < {d}/lines',
    'index-info': 'index --index-info {i} < {d}/info',
    'add': 'index add {i} ' + SHA[6].decode() + ' addme',
    'remove': 'index remove {i} keep',
    'update-stat': 'index update-stat {i} keep',
}


def lock_dir(name):
    d = work/name
    d.mkdir()
    (d/'lines').write_bytes(b'100644 %s 0 new\n' % SHA[1])
    (d/'info').write_bytes(rec(100644, SHA[2], b'new')+b'\n')
    (d/'keep').write_text('keep\n')
    (d/'addme').write_text('addme\n')
    return d


@case('atomicity: an existing lock is honoured by every changing verb')
def _():
    d = lock_dir('locked')
    original = make_index(root, d/'index', [rec(100644, SHA[0], b'keep')])
    (d/'index.lock').write_bytes(b'held by someone else')
    for verb, template in VERBS.items():
        r = bash(template.format(i='index', d=d), d)
        check(r.returncode == 1 and b"Unable to create" in r.stderr and b'File exists' in r.stderr, (verb, r.stderr))
        check((d/'index').read_bytes() == original, verb)
        check((d/'index.lock').read_bytes() == b'held by someone else', verb)
    (d/'index.lock').unlink()
    r = bash(VERBS['index-info'].format(i='index', d=d), d)
    check(r.returncode == 0 and not leftovers(d), r.stderr)
    # the protocol is git's own: git refuses while such a lock exists
    (d/'index.lock').write_bytes(b'')
    g = git(root, 'update-index', '--index-info', data=rec(100644, SHA[3], b'x')+b'\n', index=d/'index', check_rc=False)
    check(g.returncode != 0 and b'index.lock' in g.stderr, g.stderr)
    (d/'index.lock').unlink()
    return {'verbs': len(VERBS)}


@case('atomicity: unwritable directory and a directory as the target')
def _():
    d = lock_dir('readonly')
    original = make_index(root, d/'index', [rec(100644, SHA[0], b'keep')])
    d.chmod(0o555)
    try:
        if os.access(d, os.W_OK):
            raise Failure('running with privileges that ignore directory permissions')
        for verb, template in VERBS.items():
            r = bash(template.format(i='index', d=d), d)
            check(r.returncode == 1 and b'Permission denied' in r.stderr, (verb, r.stderr))
            check((d/'index').read_bytes() == original, verb)
    finally:
        d.chmod(0o755)
    (d/'dirtarget').mkdir()
    r = bash(VERBS['write'].format(i='dirtarget', d=d), d)
    check(r.returncode == 1 and (d/'dirtarget').is_dir() and not leftovers(d), (r.stderr, leftovers(d)))
    return {}


@case('atomicity: injected write, short-write, fdatasync, close and rename failures')
def _():
    d = lock_dir('faults')
    log = work/'fault.log'
    original = make_index(root, d/'index', [rec(100644, SHA[0], b'keep')])
    injected = 0
    for fault in ('write:/index.tmp', 'short:/index.tmp', 'fdatasync:/index.tmp', 'close:/index.tmp',
                  'rename:index'):
        for verb, template in VERBS.items():
            if log.exists():
                log.unlink()
            r = bash(template.format(i='index', d=d), d, fault=(fault, log))
            noted = log.read_text() if log.exists() else ''
            check(noted.startswith(fault.split(':')[0]), (fault, verb, 'not injected', r.stderr))
            injected += 1
            check(r.returncode == 1, (fault, verb, r.returncode, r.stderr))
            check(r.stderr.strip() != b'', (fault, verb, 'silent failure'))
            check((d/'index').read_bytes() == original, (fault, verb))
            check(not leftovers(d), (fault, verb, leftovers(d)))
    r = bash(VERBS['index-info'].format(i='index', d=d), d)
    check(r.returncode == 0 and [row[3] for row in ls_files(root, d/'index')] == [b'keep', b'new'], r.stderr)
    return {'injected': injected}


shutil.rmtree(work, ignore_errors=True)
summary = {'binary': BINARY, 'sanitized': bool(args.loader), 'git': subprocess.run(
    [GIT, '--version'], capture_output=True, text=True).stdout.strip(), 'seed': args.seed,
    'cases': results, 'passed': sum(r['status'] == 'pass' for r in results), 'failed': failures}
if args.output:
    Path(args.output).write_text(json.dumps(summary, indent=1)+'\n')
print(f'sol-index-check: {summary["passed"]} passed, {failures} failed')
sys.exit(1 if failures else 0)
