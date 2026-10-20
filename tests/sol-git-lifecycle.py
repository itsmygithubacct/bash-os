#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Repeated production git calls preserve parent FDs, signals and shell state."""
import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workloads', ROOT/'bench/sol-git.py')
workloads = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workloads)
binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve()


def fd_state(pid):
    return {p.name: os.readlink(p) for p in Path(f'/proc/{pid}/fd').iterdir()}


def signal_state(pid):
    return [s for s in Path(f'/proc/{pid}/status').read_text().splitlines()
            if s.startswith(('SigBlk:', 'SigIgn:', 'SigCgt:'))]


with tempfile.TemporaryDirectory(prefix='sol-git-lifecycle-') as name:
    root = Path(name)
    env = dict(PATH='', HOME=name, LC_ALL='C', TZ='UTC',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    repo = root/'repo'
    fixture = workloads.Fixture(20, 12)
    workloads.materialize(repo, fixture, env, dirty=True)
    config_lock = repo/'.git/config.lock'
    config_lock.write_bytes(b'other writer sentinel\n')
    config_before = (repo/'.git/config').read_bytes()
    bad_helper = root/'bad-helper'
    bad_helper.write_text('#!/bin/sh\nexit 42\n')
    bad_helper.chmod(0o700)
    env['GIT_SSH_COMMAND'] = str(bad_helper)
    env['GIT_SSH_VARIANT'] = 'ssh'
    script = '''
PATH=
[[ $(type -t git) == builtin ]] || exit 1
trap ':' CHLD
saved_trap=$(trap -p CHLD)
saved_pwd=$PWD
printf 'ready\n'
while read -r command; do
  case $command in
    batch)
      for ((i=0; i<30; i++)); do
        (for ((j=0; j<2000; j++)); do :; done)& child=$!
        git status --porcelain=v1 >/dev/null || exit 2
        git log --format=%H >/dev/null || exit 3
        git diff --numstat >/dev/null || exit 4
        git -C / invalid-command >/dev/null 2>&1 && exit 5
        git ls-remote fixture:/missing >/dev/null 2>&1 && exit 6
        git config lifecycle.blocked true >/dev/null 2>&1 && exit 10
        wait "$child" || exit 7
        [[ $PWD == "$saved_pwd" && ${GIT_DIR-unset} == unset &&
           ${GIT_WORK_TREE-unset} == unset ]] || exit 8
        [[ $(trap -p CHLD) == "$saved_trap" ]] || exit 9
      done
      printf 'done\n';;
    quit) exit 0;;
  esac
done
'''
    with tempfile.TemporaryFile() as errors:
        child = subprocess.Popen([str(binary), '--noprofile', '--norc', '-c', script],
                                 cwd=repo, env=env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=errors)
        def marker(expected):
            assert select.select([child.stdout], [], [], 60)[0], 'shell timeout'
            line = child.stdout.readline()
            if line != expected:
                errors.seek(0)
                raise AssertionError((line, child.poll(), errors.read()))
        try:
            marker(b'ready\n')
            fds = fd_state(child.pid)
            signals = signal_state(child.pid)
            for _ in range(4):
                child.stdin.write(b'batch\n')
                child.stdin.flush()
                marker(b'done\n')
                assert fd_state(child.pid) == fds, 'parent leaked descriptors'
                assert signal_state(child.pid) == signals, 'parent signal state changed'
                assert not Path(f'/proc/{child.pid}/task/{child.pid}/children').read_text().strip(), 'unreaped child'
                assert config_lock.read_bytes() == b'other writer sentinel\n', 'removed foreign lock'
                assert (repo/'.git/config').read_bytes() == config_before, 'failed write changed config'
            child.stdin.write(b'quit\n')
            child.stdin.flush()
            assert child.wait(timeout=20) == 0
            errors.seek(0)
            diagnostics = errors.read()
            assert not diagnostics, ('unexpected shell diagnostics', diagnostics)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    config_lock.unlink()
    workloads.state_oracle(repo, env, fixture)
    print('lifecycle: 120 rounds, 720 git calls plus background jobs; FD/signal/child/lock/state checks passed')

    # Exact multiples of stdio buffers can fail before the final flush.
    # A later successful empty fflush must not turn a write failure into success.
    for size in (1, 4096, 8192, 65536, 65537):
        oid, raw = workloads.object_record('blob', b'x' * size)
        path = repo/'.git/objects'/oid[:2]/oid[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        with open('/dev/full', 'wb') as full:
            p = subprocess.run([str(binary), '--noprofile', '--norc', '-c',
                                'PATH=; git cat-file blob "$1"', 'full', oid],
                               cwd=repo, env=env, stdout=full, stderr=subprocess.PIPE,
                               timeout=20)
        assert p.returncode != 0, ('output failure reported success', size)
    print('output failure: five blob lengths rejected /dev/full')
