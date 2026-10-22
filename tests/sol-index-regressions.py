#!/usr/bin/env python3
"""Sequential Git-oracle regressions on owned repositories and index files."""
import argparse
import hashlib
import os
import struct
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--case', choices=['stages', 'null-id', 'v3', 'bounds'], required=True)
a = p.parse_args()
binary = str(Path(a.binary).resolve())
env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
with tempfile.TemporaryDirectory(prefix='index-regression-') as d:
    root = Path(d)
    def git(*args, data=None, index=None):
        e = dict(env)
        e.pop('LD_PRELOAD', None)
        e.pop('GIT_INDEX_FILE', None)
        if index: e['GIT_INDEX_FILE'] = str(root/index)
        r = subprocess.run(['/usr/bin/git', *args], cwd=root, env=e, input=data, capture_output=True)
        print('git', args, r.returncode, r.stderr.decode(errors='replace'))
        return r
    def index(command, data=None):
        r = subprocess.run([binary, '--noprofile', '--norc', '-c', 'PATH=; index '+command],
                           cwd=root, env=env, input=data, capture_output=True)
        print('index', command, r.returncode, r.stderr.decode(errors='replace'))
        return r
    assert git('init', '-q').returncode == 0
    oid = git('hash-object', '-w', '--stdin', data=b'fixture\n').stdout.strip()
    record = b'100644 '+oid+b'\tf\n'
    assert git('update-index', '--index-info', data=record, index='base').returncode == 0
    for name in ['ours', 'oracle']: (root/name).write_bytes((root/'base').read_bytes())
    if a.case == 'stages':
        stream = b'100644 '+oid+b' 2\tf\n'
        assert git('update-index', '--index-info', data=stream, index='oracle').returncode == 0
        assert index('--index-info ours', stream).returncode == 0
        expected = b'100644 '+oid+b' 0 f\n100644 '+oid+b' 2 f\n'
        read = index('read ours')
        assert read.returncode == 0 and read.stdout == expected, 'read must consume a successful index-info write'
        stream = b'0 '+b'0'*40+b'\tf\n'
        assert git('update-index', '--index-info', data=stream, index='oracle').returncode == 0
        assert index('--index-info ours', stream).returncode == 0
        assert (root/'ours').read_bytes() == (root/'oracle').read_bytes()
        assert index('read ours').stdout == b''
        assert index('write direct', expected).returncode == 0
        read = index('read direct')
        assert read.returncode == 0 and read.stdout == expected
    if a.case == 'null-id':
        before = (root/'ours').read_bytes()
        null = b'100644 '+b'0'*40+b'\tnew\n'
        remove = b'0 '+b'0'*40+b'\tnew\n'
        assert git('update-index', '--index-info', data=null, index='oracle').returncode != 0
        assert index('--index-info ours', null).returncode != 0, 'final null object ID must fail'
        assert (root/'ours').read_bytes() == before, 'failure must preserve the old index'
        assert not (root/'ours.lock').exists()
        assert not list(root.glob('ours.tmp*'))
        for stream in [remove, null+remove]:
            assert git('update-index', '--index-info', data=stream, index='oracle').returncode == 0
            assert index('--index-info ours', stream).returncode == 0
            assert (root/'ours').read_bytes() == (root/'oracle').read_bytes()
        assert index('write ours', b'100644 '+b'0'*40+b' 0 f\n').returncode != 0
        assert (root/'ours').read_bytes() == before
    if a.case == 'v3':
        (root/'intent').write_text('intent\n')
        assert git('add', '--intent-to-add', 'intent', index='base').returncode == 0
        assert git('update-index', '--skip-worktree', 'f', index='base').returncode == 0
        for name in ['ours', 'oracle']: (root/name).write_bytes((root/'base').read_bytes())
        before = (root/'ours').read_bytes(), (root/'ours').stat().st_mtime_ns
        assert git('update-index', '--index-info', data=b'', index='oracle').returncode == 0
        assert index('--index-info ours', b'').returncode == 0, 'valid v3 no-op must succeed'
        assert ((root/'ours').read_bytes(), (root/'ours').stat().st_mtime_ns) == before
        for stream in [b'100644 '+oid+b'\tother\n', b'0 '+b'0'*40+b'\tother\n']:
            assert git('update-index', '--index-info', data=stream, index='oracle').returncode == 0
            assert index('--index-info ours', stream).returncode == 0
            assert index('read ours').returncode == 0
            # Git's debug listing exposes both intent-to-add and skip-worktree.
            expected = git('ls-files', '--stage', '--debug', index='oracle')
            actual = git('ls-files', '--stage', '--debug', index='ours')
            assert actual.returncode == 0 and actual.stdout == expected.stdout, (actual.stdout, expected.stdout)
        assert int.from_bytes((root/'ours').read_bytes()[4:8], 'big') == 3
    if a.case == 'bounds':
        page = os.sysconf('SC_PAGE_SIZE')
        assert page > 74
        def head(flags, sha=b'\x11'*20, mode=0o100644):
            return b'\0'*24 + struct.pack('>I', mode) + b'\0'*12 + sha + struct.pack('>H', flags)
        def wrap(version, count, body):
            return b'DIRC' + struct.pack('>II', version, count) + body
        def git_ls(raw, runs):
            (root/'t.index').write_bytes(raw)
            outs = []
            for _ in range(runs):
                e = dict(env)
                e.pop('LD_PRELOAD', None)
                e['GIT_INDEX_FILE'] = str(root/'t.index')
                r = subprocess.run(['/usr/bin/git', 'ls-files', '--stage', '-z'], cwd=root, env=e, capture_output=True)
                outs.append(r)
            return outs
        def listing_of(stdout):
            lines = []
            for row in stdout.split(b'\0'):
                if not row: continue
                meta, pathb = row.split(b'\t', 1)
                if pathb == b'': pathb = b'./'
                lines.append(meta + b' ' + pathb + b'\n')
            return b''.join(lines)
        def bash_read():
            return index('read t.index')
        def expect_match(label, raw):
            oracle = git_ls(raw, 1)[0]
            assert oracle.returncode == 0, (label, oracle.returncode, oracle.stderr)
            got = bash_read()
            expected = listing_of(oracle.stdout)
            assert got.returncode == 0 and got.stdout == expected, (
                label, got.returncode, len(got.stdout), len(expected),
                hashlib.sha256(got.stdout).hexdigest(), hashlib.sha256(expected).hexdigest(), got.stderr)
            print('match', label, len(got.stdout))
        def expect_listing(label, raw, expected):
            # Git's listing of RAW is not defined (see each caller), so the
            # builtin must print EXPECTED; live git is printed for the record.
            oracle = git_ls(raw, 1)[0]
            live = listing_of(oracle.stdout) if oracle.returncode == 0 else b''
            print('git', label, 'exit', oracle.returncode, 'len', len(live),
                  'same' if live == expected else 'differs')
            got = bash_read()
            assert got.returncode == 0 and got.stdout == expected, (
                label, got.returncode, len(got.stdout), len(expected), got.stderr)
            print('match', label, len(got.stdout))
        def expect_exact_page(label, raw):
            # The file is exactly one page and the name ends at its last byte.
            # Git reads past the mapped page here (see each case). The builtin
            # lists the name from the file's own bytes.
            expect_listing(label, raw, b'100644 ' + (b'11' * 20) + b' 0 ' + raw[74:] + b'\n')
        def expect_unterminated(label, raw, *rows):
            # Git copies a declared name and the byte after it, the NUL it
            # expects there, into pool memory it does not clear
            # (mem_pool__ce_alloc in read-cache.c). When that byte is not NUL
            # the copied name has no terminator, and git's listing runs on into
            # whatever the pool holds. The builtin ends the name after the
            # copied bytes.
            expect_listing(label, raw, b''.join(
                b'100644 ' + sha + b' 0 ' + name + b'\n' for sha, name in rows))
        def expect_refuse(label, raw):
            outs = git_ls(raw, 8)
            classes = {0 if o.returncode == 0 else 1 for o in outs}
            hashes = {hashlib.sha256(o.stdout).hexdigest() for o in outs}
            print('unstable', label, 'exit_class', sorted(classes), 'hashes', len(hashes),
                  'lens', sorted({len(o.stdout) for o in outs}))
            got = bash_read()
            assert got.returncode != 0 and got.stdout == b'', (label, got.returncode, got.stdout[:40], got.stderr)
        # Name starts at offset 74. A 12-bit length of page-74 makes the next
        # header start past the mapped page. Git's listing there is undefined
        # and may stay the same; the print records this host, and the builtin
        # must still refuse.
        expect_refuse('v2-next-past-page', wrap(2, 2, head(page - 74) + b'\x10' + b'\x22'*19))
        # Version 4, count 2, 12-bit length 4000, one 0x00 strip byte and no
        # suffix. docs/sol-index.md records the git 2.47.3 evidence. A larger
        # page uses a length that still places the next header past the page.
        v4_flags = 4000 if page == 4096 else min(0xffe, page - 96)
        expect_refuse('v4-next-past-page', wrap(4, 2, head(v4_flags) + b'\x00'))
        expect_match('v2-fff-tail', wrap(2, 1, head(0xfff) + b'\x10' + b'\x22'*19))
        expect_match('v2-last-declared-past-page', wrap(2, 1, head(page - 74) + b'\x10' + b'\x22'*19))
        expect_match('v2-last-pad-past-page', wrap(2, 1, head(page - 75) + b'\x10' + b'\x22'*19))
        filled = wrap(2, 1, head(0xfff))
        filled += bytes([0x61]) * (page - len(filled))
        assert len(filled) == page and b'\0' not in filled[74:]
        # Git measures this name with strlen, which runs past the mapped page
        # into whatever memory follows.
        expect_exact_page('v2-exact-page-fff', filled)
        explicit = wrap(2, 1, head(page - 74))
        explicit += bytes([0x62]) * (page - len(explicit))
        # Git copies the declared length plus one byte, the NUL it expects
        # after the name, and that byte is past the mapped page.
        expect_exact_page('v2-exact-page-explicit', explicit)
        # Declared length 0: git copies the 0x10 after it as the name.
        expect_unterminated('v4-trailer-byte', wrap(4, 1, head(0) + b'\x00' + b'\x10' + b'\x22'*19),
                            (b'11' * 20, b'\x10'))
        expect_match('v4-ordinary', wrap(4, 1, head(1) + b'\x00' + b'a\0' + b'\x33'*20))
        expect_match('v4-early-nul', wrap(4, 1, head(5) + b'\x00' + b'ab\0cdef' + b'\x33'*10))
        expect_match('v4-ignore-first-strip', wrap(4, 1, head(2) + bytes([5]) + b'ab\0' + b'\x33'*20))
        expect_match('v4-prefix', wrap(4, 2, head(5) + b'\x00' + b'hello\0' + head(6, b'\x44'*20) + b'\x00' + b'X\0' + b'\x55'*20))
        expect_unterminated('v4-previous-length', wrap(4, 2, head(1) + b'\x00' + b'ab' + head(1, b'\x44'*20) + bytes([1]) + b'Z\0' + b'\x55'*20),
                            (b'11' * 20, b'ab'), (b'44' * 20, b'Z'))
        expect_unterminated('v2-window', wrap(2, 1, head(1) + b'aX\0' + b'\x33'*20), (b'11' * 20, b'aX'))
        expect_match('v2-embedded-nul', wrap(2, 1, head(4) + b'ab\0c\0' + b'\x33'*20))
        (root/'f').write_bytes(b'fixture\n')
        assert git('add', 'f').returncode == 0
        expect_match('v2-git-written', (root/'.git/index').read_bytes())
        assert git('update-index', '--index-version', '4').returncode == 0
        expect_match('v4-git-written', (root/'.git/index').read_bytes())
    print('PASS', a.case)
