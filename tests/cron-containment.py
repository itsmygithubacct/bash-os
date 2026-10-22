#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cron spool and state stay inside a private directory the operator owns."""
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile


BINARY = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
EPOCH = '1700000000'


def private_dirs(root):
    root.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name in ('etc', 'crond', 'output', 'mail'):
        path = root / name
        path.mkdir(mode=0o700)
        paths[name] = path
    return paths


def environment(root, spool, state=None):
    dirs = private_dirs(root)
    env = {
        **os.environ,
        'LC_ALL': 'C',
        'TZ': 'UTC',
        'USER': 'fixture',
        'BASHCRON_SPOOL_DIR': str(spool),
        'BASHCRON_ETC_DIR': str(dirs['etc']),
        'BASHCRON_CROND_DIR': str(dirs['crond']),
        'BASHCRON_OUTPUT_DIR': str(dirs['output']),
        'BASHCRON_MAIL_DIR': str(dirs['mail']),
        'BASHCRON_NOW_EPOCH': EPOCH,
    }
    env.pop('BASH_ENV', None)
    env.pop('ENV', None)
    if state is None:
        env.pop('BASHCRON_STATE_FILE', None)
    else:
        env['BASHCRON_STATE_FILE'] = str(state)
    if module := os.environ.get('SPOOL_LOAD_ENV'):
        env['BASH_ENV'] = module
    if preload := os.environ.get('SPOOL_ASAN_LIB'):
        env.update(LD_PRELOAD=preload,
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def run(root, env):
    script = 'PATH=; cron run --once'
    if module := os.environ.get('CRON_TEST_LOADABLE'):
        script = 'enable -f ' + shlex.quote(module) + ' cron || exit; ' + script
    result = subprocess.run(
        [BINARY, '--noprofile', '--norc', '-c', script],
        env=env, cwd=root, capture_output=True, timeout=20)
    if b'AddressSanitizer' in result.stderr or b'runtime error:' in result.stderr:
        raise AssertionError(result.stderr)
    return result


def plant_job(directory, marker):
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    job = directory / 'due.job'
    job.write_text("# run_at=%s\nprintf '%%s\\n' ran > '%s'\n" % (EPOCH, marker))
    job.chmod(0o700)
    return job


def main():
    with tempfile.TemporaryDirectory(prefix='cron-contain-') as directory:
        root = Path(directory)

        # A private real spool runs its own due job. This is the control.
        spool = root / 'private-spool'
        spool.mkdir(mode=0o700)
        marker = root / 'private-marker'
        plant_job(spool / 'atjobs', marker)
        result = run(root, environment(root / 'private-env', spool))
        if not marker.is_file() or marker.read_bytes() != b'ran\n':
            raise SystemExit(
                'private spool did not run its own job\n'
                f'rc={result.returncode} stderr={result.stderr!r}')

        # The spool path itself is a symlink to a directory that holds a due job.
        outside = root / 'outside-spool'
        outside.mkdir(mode=0o700)
        marker = root / 'spool-link-marker'
        plant_job(outside / 'atjobs', marker)
        link = root / 'spool-link'
        link.symlink_to(outside)
        result = run(root, environment(root / 'link-env', link))
        if marker.exists():
            raise SystemExit(
                'cron followed a symlink spool and ran the outside job\n'
                f'rc={result.returncode} stderr={result.stderr!r} '
                f'stdout={result.stdout!r}')

        # Group/other-writable spool is not owner-private.
        shared = root / 'shared-spool'
        shared.mkdir(mode=0o700)
        shared.chmod(0o777)
        marker = root / 'shared-marker'
        plant_job(shared / 'atjobs', marker)
        result = run(root, environment(root / 'shared-env', shared))
        if marker.exists():
            raise SystemExit(
                'cron ran a job from a group/other-writable spool\n'
                f'mode={oct(stat.S_IMODE(shared.stat().st_mode))} '
                f'rc={result.returncode}')

        # atjobs inside an otherwise private spool is a symlink.
        owned = root / 'owned-spool'
        owned.mkdir(mode=0o700)
        jobs = root / 'outside-atjobs'
        marker = root / 'atjobs-link-marker'
        plant_job(jobs, marker)
        (owned / 'atjobs').symlink_to(jobs)
        result = run(root, environment(root / 'atjobs-env', owned))
        if marker.exists():
            raise SystemExit(
                'cron followed an atjobs symlink and ran the outside job\n'
                f'rc={result.returncode} stderr={result.stderr!r}')

        # A symlink state file is neither read nor replaced.
        sentinel = root / 'state-sentinel'
        sentinel.write_text('1\n')
        state = root / 'state-link'
        state.symlink_to(sentinel)
        quiet = root / 'quiet-spool'
        quiet.mkdir(mode=0o700)
        result = run(root, environment(root / 'state-env', quiet, state))
        if sentinel.read_bytes() != b'1\n' or not state.is_symlink():
            raise SystemExit(
                'cron followed or replaced a symlink state file\n'
                f'sentinel={sentinel.read_bytes()!r} '
                f'is_link={state.is_symlink()} rc={result.returncode} '
                f'stderr={result.stderr!r}')
        if os.readlink(state) != str(sentinel):
            raise SystemExit(f'state symlink retargeted to {os.readlink(state)}')
    print('cron: spool and state symlinks are not followed')


if __name__ == '__main__':
    main()
