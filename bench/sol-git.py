#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Matched Git workloads. Run measurements through the campaign bench gate.

No builds. Each side owns private files and object stores. Python constructs
the expected SHA-1 objects; system Git independently reads every result.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which('git')
RUSAGE = ROOT/'out/sol-git-rusage'
DESCRIPTION = b"Unnamed repository; edit this file 'description' to name the repository.\n"
EXCLUDE = (b'# git ls-files --others --exclude-from=.git/info/exclude\n'
           b"# Lines that start with '#' are comments.\n")


def template(root):
    path = root/'template'
    (path/'info').mkdir(parents=True)
    (path/'hooks').mkdir()
    (path/'description').write_bytes(DESCRIPTION)
    (path/'info/exclude').write_bytes(EXCLUDE)
    return path


def ssh_fixture(root):
    # Both clients run the same genuine upload-pack server over pipes.
    helper = root/'ssh'
    helper.write_text('#!/bin/sh\nwhile [ "$#" -gt 1 ]; do shift; done\n'
                      'case "$1" in "git-upload-pack "*) '
                      f'exec /bin/sh -c {shlex.quote("exec " + GIT + " upload-pack ")}'
                      '"${1#git-upload-pack }";; *) exit 91;; esac\n')
    helper.chmod(0o700)
    return dict(GIT_SSH_COMMAND=str(helper), GIT_SSH_VARIANT='ssh')


def init_oracle(repo, env):
    assert reference(repo, env, 'symbolic-ref', 'HEAD') == b'refs/heads/main\n'
    assert reference(repo, env, 'ls-files', '--stage') == b''
    assert reference(repo, env, 'for-each-ref') == b''
    object_oracle(repo, env, {})
    config = (b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n'
              b'\tbare = false\n\tlogallrefupdates = true\n')
    expected = {'HEAD': b'ref: refs/heads/main\n', 'config': config,
                'description': DESCRIPTION, 'info/exclude': EXCLUDE}
    actual = {p.relative_to(repo/'.git').as_posix(): p.read_bytes()
              for p in (repo/'.git').rglob('*') if p.is_file()}
    assert actual == expected, 'init metadata differs'
    directories = {p.relative_to(repo/'.git').as_posix()
                   for p in (repo/'.git').rglob('*') if p.is_dir()}
    assert directories == {'objects', 'objects/info', 'objects/pack', 'refs',
                           'refs/heads', 'refs/tags', 'info', 'hooks'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def object_record(kind, data):
    raw = kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data
    return hashlib.sha1(raw).hexdigest(), raw


class Fixture:
    def __init__(self, files, commits):
        self.objects = {}
        self.files = {f'f{i:06d}': (f'file {i}\n' + 'payload\n' * 15).encode()
                      for i in range(files)}
        self.commits = []
        for number in range(commits):
            self.files['history'] = f'commit {number}\n'.encode()
            self.tree = self.tree_for(self.files)
            parent = f'parent {self.commits[-1]}\n' if self.commits else ''
            ident = f'Fixture <fixture@example.test> {1750000000 + number} +0000'
            data = (f'tree {self.tree}\n{parent}author {ident}\ncommitter {ident}'
                    f'\n\ncommit {number}\n').encode()
            self.commits.append(self.record('commit', data))
        self.head = self.commits[-1]
        self.base_objects = dict(self.objects)
        self.changed = dict(self.files)
        self.modified = sorted(self.files)[:max(1, files // 10)]
        for name in self.modified:
            self.changed[name] += b'added\n'
        self.deleted = sorted(self.files)[-max(1, files // 20):]
        for name in self.deleted:
            del self.changed[name]
        self.changed['new-file'] = b'new\n'
        self.add_objects = dict(self.base_objects)
        for data in self.changed.values():
            oid, raw = object_record('blob', data)
            self.add_objects[oid] = raw
        self.new_tree = self.tree_for(self.changed)
        self.index = self.index_for(self.files)
        self.add_index = self.index_for(self.changed)
        self.digest = sha(b''.join(bytes.fromhex(k) + v
                                   for k, v in sorted(self.base_objects.items())))

    def record(self, kind, data):
        oid, raw = object_record(kind, data)
        self.objects[oid] = raw
        return oid

    def tree_for(self, files):
        data = b''.join(b'100644 ' + name.encode() + b'\0' +
                        bytes.fromhex(self.record('blob', contents))
                        for name, contents in sorted(files.items()))
        return self.record('tree', data)

    @staticmethod
    def index_for(files):
        return b''.join(b'100644 ' + object_record('blob', data)[0].encode() +
                        b' 0\t' + name.encode() + b'\0'
                        for name, data in sorted(files.items()))


def reference(repo, env, *args, stdin=None):
    p = subprocess.run([GIT, '-C', str(repo), *map(str, args)], env=env,
                       input=stdin, capture_output=True, timeout=180)
    assert p.returncode == 0, (args, p.returncode, p.stderr[:1000])
    return p.stdout


def materialize(repo, fixture, env, dirty=False):
    reference(repo.parent, env, 'init', '-q', '-b', 'main', repo)
    for oid, raw in fixture.base_objects.items():
        path = repo / '.git/objects' / oid[:2] / oid[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(raw))
    (repo / '.git/refs/heads/main').write_text(fixture.head + '\n')
    reference(repo, env, 'read-tree', fixture.tree)
    for name, data in fixture.files.items():
        (repo / name).write_bytes(data)
        os.utime(repo / name, (1750000000, 1750000000))
    # Populate stat fields before dirtying the tree. Old mtimes keep entries
    # outside Git's same-second racy-index rule on both implementations.
    reference(repo, env, 'update-index', '--refresh')
    if dirty:
        for name in fixture.deleted:
            (repo / name).unlink()
        for name, data in fixture.changed.items():
            if fixture.files.get(name) != data:
                (repo / name).write_bytes(data)


def object_oracle(repo, env, objects):
    # Check exact object membership, types, lengths and all bytes, including
    # unreachable history objects. --batch verifies packed delta reconstruction.
    names = reference(repo, env, 'cat-file', '--batch-all-objects',
                      '--batch-check=%(objectname)').splitlines()
    assert set(names) == {k.encode() for k in objects}, 'object set differs'
    answer = reference(repo, env, 'cat-file', '--batch',
                       stdin=b'\n'.join(names)+b'\n' if names else b'')
    at = 0
    for name in names:
        end = answer.index(b'\n', at)
        oid, kind, size = answer[at:end].split()
        size = int(size)
        content = answer[end+1:end+1+size]
        assert oid == name and object_record(kind.decode(), content) == (
            name.decode(), objects[name.decode()]), 'object data differs'
        assert answer[end+1+size:end+2+size] == b'\n'
        at = end+2+size
    assert at == len(answer)


def state_oracle(repo, env, fixture, added=False, clone=False):
    assert reference(repo, env, 'rev-parse', 'HEAD').strip().decode() == fixture.head
    assert reference(repo, env, 'rev-parse', 'HEAD^{tree}').strip().decode() == fixture.tree
    assert reference(repo, env, 'ls-files', '--stage', '-z') == (
        fixture.add_index if added else fixture.index), 'index differs'
    objects = fixture.add_objects if added else fixture.base_objects
    object_oracle(repo, env, objects)
    if added:
        assert reference(repo, env, 'write-tree').strip().decode() == fixture.new_tree
    expected = fixture.files if clone else fixture.changed
    actual = {p.name: p.read_bytes() for p in repo.iterdir() if p.name != '.git'}
    assert actual == expected, 'working tree differs'
    assert all(not p.is_symlink() and not p.stat().st_mode & 0o111
               for p in repo.iterdir() if p.name != '.git'), 'working mode differs'
    assert not list((repo / '.git').rglob('*.lock')), 'leaked lock'
    if clone:
        refs = reference(repo, env, 'for-each-ref',
                         '--format=%(refname) %(objectname) %(symref)').splitlines()
        head = fixture.head.encode()
        assert refs == [b'refs/heads/main ' + head + b' ',
                        b'refs/remotes/origin/HEAD ' + head + b' refs/remotes/origin/main',
                        b'refs/remotes/origin/main ' + head + b' '], 'clone refs differ'
        assert reference(repo, env, 'symbolic-ref', 'HEAD') == b'refs/heads/main\n'
        assert not (repo / '.git/objects/info/alternates').exists()
        packs = list((repo / '.git/objects/pack').glob('*.pack'))
        assert packs, 'clone bypassed pack protocol'
        assert all(p.stat().st_nlink == 1 for p in (repo / '.git/objects').rglob('*')
                   if p.is_file()), 'clone hardlinked objects'
        reference(repo, env, 'fsck', '--strict')


def execute(binary, side, args, cwd, env, timed):
    executable = str(binary)
    script = 'PATH=; ' + ('builtin git' if side == 'bashos' else shlex.quote(GIT)) + ' "$@"'
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryDirectory(prefix="git-usage-") as usage_dir:
        usage_path = Path(usage_dir)/"usage"
        launch = [str(RUSAGE.resolve(strict=True)), str(usage_path)] if timed else []
        start = time.perf_counter_ns() if timed else None
        p = subprocess.Popen([*launch, executable, '--noprofile', '--norc', '-c', script,
                              'workload', *map(str, args)], cwd=cwd, env=env,
                             stdout=out, stderr=err, start_new_session=True)
        def timeout(signum, frame):
            os.killpg(p.pid, signal.SIGKILL)
        previous = signal.signal(signal.SIGALRM, timeout)
        signal.alarm(180)
        try:
            _, status, usage = os.wait4(p.pid, 0)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        elapsed = (time.perf_counter_ns() - start) / 1e6 if timed else None
        p.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(), err.read()
        metrics = usage_path.read_text().split() if timed and usage_path.exists() else []
    assert p.returncode == 0, (side, args, p.returncode, stderr[:1000])
    assert not stderr, (side, args, stderr[:1000])
    if timed: assert len(metrics) == 3, 'missing native child resource report'
    return stdout, dict(wall_ms=elapsed, peak_rss_kib=int(metrics[0]) if timed else None,
                        user_s=float(metrics[1]) if timed else None,
                        system_s=float(metrics[2]) if timed else None,
                        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
                        exit_code=p.returncode, validation='pass')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--scales', default='100:10,1000:100,4000:400')
    ap.add_argument('--samples', type=int, default=7)
    ap.add_argument('--check-only', action='store_true')
    ap.add_argument('--cases', default='init,status,diff,log,add,clone')
    args = ap.parse_args()
    assert args.check_only or args.samples >= 7
    assert args.check_only or len(os.sched_getaffinity(0)) == 1, 'pin one CPU for measurement'
    binary = args.binary.resolve()
    report = dict(status='running', cases=[],
        started=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        load_average_start=os.getloadavg(), method=dict(
        warmups=0 if args.check_only else 1, samples=0 if args.check_only else args.samples,
        affinity=sorted(os.sched_getaffinity(0)),
        timing='native resource launcher + shell startup + one command; fixture/reset/oracles excluded; warm cache',
        shell='same selected Bash executable for builtin and absolute system Git',
        index='stat fields refreshed before changes; initial file mtimes fixed at 1750000000, outside racy window',
        rss='native launcher wait4 ru_maxrss, Linux KiB, maximum of shell and waited descendants; excludes Python fixture-generator inherited peak',
        clone='SSH pipe fixture to the same system Git upload-pack; protocol v2; no network'),
        source_commit=subprocess.check_output([GIT, 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        environment=dict(platform=platform.platform(), python=platform.python_version(),
                         git=subprocess.check_output([GIT, '--version']).decode().strip(),
                         bash=subprocess.check_output([binary, '--version']).decode().splitlines()[0],
                         cpu=next((s.split(':', 1)[1].strip() for s in
                                   Path('/proc/cpuinfo').read_text().splitlines()
                                   if s.startswith('model name')), 'unknown')),
        hashes={str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p):
                sha(p.read_bytes()) for p in [binary, Path(GIT), Path('/bin/bash'),
                                              Path(__file__), ROOT/'loadables/git.c',
                                              *sorted((ROOT/'loadables/_git').glob('*.[ch]'))]})
    if not args.check_only:
        report['rusage_launcher'] = dict(path=str(RUSAGE.resolve(strict=True)), sha256=sha(RUSAGE.read_bytes()), source_sha256=sha((ROOT/'bench/sol-git-rusage.c').read_bytes()))
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    try:
        with tempfile.TemporaryDirectory(prefix='sol-git-') as temporary:
            root = Path(temporary)
            (root/'home').mkdir()
            env = dict(PATH='', HOME=str(root/'home'), LC_ALL='C', TZ='UTC',
                       GIT_TEMPLATE_DIR=str(template(root)),
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                       GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='2',
                       GIT_CONFIG_KEY_0='pack.threads', GIT_CONFIG_VALUE_0='1',
                       GIT_CONFIG_KEY_1='protocol.version', GIT_CONFIG_VALUE_1='2')
            env.update(ssh_fixture(root))
            for scale in args.scales.split(','):
                files, commits = map(int, scale.split(':'))
                fixture = Fixture(files, commits)
                for case in args.cases.split(','):
                    cell = dict(workload=case, files=0 if case == 'init' else files+1,
                                commits=0 if case == 'init' else commits,
                                fixture_files=files+1, fixture_commits=commits,
                                fixture_sha256=fixture.digest,
                                objects=0 if case == 'init' else len(fixture.base_objects), status='running',
                                command=None, samples={'bashos': [], 'git': []})
                    cell['work_unit'] = ('one empty repository' if case == 'init' else
                                         f'one {case}, {files+1} tracked paths, '
                                         f'{commits} commits, {len(fixture.modified)} modifications, '
                                         f'{len(fixture.deleted)} deletions, one new file'
                                         if case != 'clone' else
                                         f'one protocol clone, {files+1} files, '
                                         f'{commits} commits, {len(fixture.base_objects)} objects')
                    report['cases'].append(cell)
                    for iteration in range(1 if args.check_only else args.samples+1):
                        for side in (['bashos', 'git'] if iteration % 2 == 0
                                     else ['git', 'bashos']):
                            work = root/'work'
                            work.mkdir()
                            repo = work/'repo'
                            if case == 'init':
                                command = ['init', '-q', '-b', 'main', repo]
                                expected = b''
                            else:
                                materialize(repo, fixture, env, dirty=case != 'clone')
                                if case == 'status':
                                    command = ['status', '--porcelain=v1', '-uno']
                                    expected = b''.join((' D ' if n in fixture.deleted else ' M ').encode()
                                                        + n.encode() + b'\n' for n in
                                                        sorted(fixture.modified+fixture.deleted))
                                elif case == 'diff':
                                    command = ['diff', '--numstat', '--no-renames']
                                    expected = b''.join((f'0\t{len(fixture.files[n].splitlines())}\t{n}\n'
                                                        if n in fixture.deleted else f'1\t0\t{n}\n').encode()
                                                       for n in sorted(fixture.modified+fixture.deleted))
                                elif case == 'log':
                                    command = ['log', '--format=%H']
                                    expected = ('\n'.join(reversed(fixture.commits))+'\n').encode()
                                elif case == 'add':
                                    command, expected = ['add', '-A'], b''
                                elif case == 'clone':
                                    command = ['clone', '-q', f'fixture:{repo}', work/'clone']
                                    expected = b''
                                else:
                                    raise ValueError(case)
                            cell['command'] = [str(c).replace(str(work), '$WORK') for c in command]
                            cell['expected_stdout_sha256'] = sha(expected)
                            output, sample = execute(binary, side, command,
                                                     repo if case not in ('init', 'clone') else work,
                                                     env, not args.check_only)
                            assert output == expected, (side, case, 'output differs', output[:1000], expected[:1000])
                            target = work/'clone' if case == 'clone' else repo
                            if case == 'init':
                                init_oracle(repo, env)
                            else:
                                state_oracle(target, env, fixture, added=case == 'add', clone=case == 'clone')
                            sample['pack_bytes'] = sum(p.stat().st_size for p in
                                                       (target/'.git/objects/pack').glob('*.pack'))
                            if iteration or args.check_only:
                                cell['samples'][side].append(sample)
                            shutil.rmtree(work)
                        save()
                    cell['status'] = 'pass'
                    if not args.check_only:
                        cell['median_ms'] = {s: statistics.median(v['wall_ms'] for v in values)
                                             for s, values in cell['samples'].items()}
                        cell['git_over_bashos'] = cell['median_ms']['git']/cell['median_ms']['bashos']
                    print(f'{scale} {case}: {cell.get("median_ms", "pass")}', flush=True)
                    save()
        report['status'] = 'pass'
    except BaseException as error:
        report['status'] = 'fail'
        report['error'] = repr(error)
        raise
    finally:
        report['ended'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report['load_average_end'] = os.getloadavg()
        save()


if __name__ == '__main__':
    main()
