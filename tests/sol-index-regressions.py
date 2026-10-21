#!/usr/bin/env python3
"""Sequential Git-oracle regressions on owned repositories and index files."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--case', choices=['stages', 'null-id'], required=True)
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
    print('PASS', a.case)
