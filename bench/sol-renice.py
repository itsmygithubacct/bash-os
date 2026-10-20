#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Matched absolute-priority sets to disposable child PIDs; no builds.

Run through the campaign bench gate. Every pass checks status and /proc niceness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# Both implementations use this same script and identical arguments/redirections.
SCRIPT = r'''
PATH=
IFS= read -r before < /proc/$$/stat || exit 20
before=${before##*) }
read -r -a fields <<< "$before"
parent=${fields[16]}
for ((i=0; i<$2; i++)); do
    COMMAND 19 -p "$1" >/dev/null || exit 21
    IFS= read -r record < /proc/$1/stat || exit 22
    record=${record##*) }
    read -r -a fields <<< "$record"
    [[ ${fields[16]} == 19 ]] || exit 23
done
IFS= read -r after < /proc/$$/stat || exit 24
after=${after##*) }
read -r -a fields <<< "$after"
[[ ${fields[16]} == "$parent" ]] || exit 25
printf 'ok %s 19\n' "$i"
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def batch(binary, command, count, env):
    hold_r, hold_w = os.pipe()
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(hold_w)
            os.close(ready_r)
            os.setsid()
            os.setpriority(os.PRIO_PROCESS, 0, 10)
            os.write(ready_w, b'ready')
            os.close(ready_w)
            os.read(hold_r, 1)
            os._exit(0)
        except BaseException:
            os._exit(90)
    os.close(hold_r)
    os.close(ready_w)
    try:
        assert os.read(ready_r, 5) == b'ready'
        assert os.getpriority(os.PRIO_PROCESS, pid) == 10
        started = time.perf_counter_ns()
        result = subprocess.run([binary, '--noprofile', '--norc', '-c',
                                 SCRIPT.replace('COMMAND', command), '_', str(pid), str(count)],
                                env=env, capture_output=True, timeout=120)
        elapsed = (time.perf_counter_ns() - started) / 1e9
        assert (result.returncode, result.stdout, result.stderr) == (0, f'ok {count} 19\n'.encode(), b''), result
        assert os.getpriority(os.PRIO_PROCESS, pid) == 19
        return dict(seconds=elapsed, exit_code=result.returncode,
                    stdout=result.stdout.decode(), stderr=result.stderr.decode(),
                    before=10, after=19, validated_passes=count)
    finally:
        os.close(ready_r)
        os.close(hold_w)
        _, status = os.waitpid(pid, 0)
        assert status == 0, status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--external', type=Path, default=Path('/usr/bin/renice'))
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--passes', type=int, default=1000)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert args.runs >= 7 and args.passes > 0
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'pin to one CPU (the campaign bench gate does this)'
    env = {k: v for k, v in os.environ.items()
           if k not in ('BASH_ENV', 'ENV', 'LD_PRELOAD', 'POSIXLY_CORRECT')}
    env.update(PATH='', LC_ALL='C')
    binary, external = str(args.binary.resolve()), str(args.external.resolve())
    commands = dict(builtin='renice', external=shlex.quote(external))
    parent = os.getpriority(os.PRIO_PROCESS, 0)
    assert parent <= 10, 'benchmark needs a parent niceness no greater than 10'
    report = dict(status='running', kind='compared', workload='owned-child absolute set plus independent proc query',
                  work_unit=f'{args.passes} absolute setpriority(19) operations and {args.passes} validated /proc niceness reads per batch',
                  reset='fresh owned session-leader child initialized to nice 10 for each batch; first set and all subsequent sets request 19',
                  options=['19', '-p', 'OWNED_CHILD_PID'], environment=dict(LC_ALL='C', PATH='', POSIXLY_CORRECT=None),
                  cpu_affinity=affinity, platform=platform.platform(), cpu=Path('/proc/cpuinfo').read_text().split('model name\t: ')[1].splitlines()[0],
                  versions={}, hashes={}, fixture_sha256=hashlib.sha256(SCRIPT.encode()).hexdigest(),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_diff_sha256=hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD', '--', 'loadables/renice.c'], cwd=ROOT)).hexdigest(),
                  source_dirty=bool(subprocess.check_output(['git', 'diff', 'HEAD', '--', 'loadables/renice.c'], cwd=ROOT)),
                  timing='perf_counter_ns around shell startup, validated loop, and exit; stdout command results discarded equally; no build time',
                  warmup={}, samples={name: [] for name in commands}, parent_priority=parent,
                  limitations=['Includes shared shell loop, proc-read validation and shell startup overhead.',
                               'Measures repeat absolute setters; no negative or user-wide mutations are timed.'])
    for name, path in [('binary', binary), ('external', external),
                       ('source', ROOT/'loadables/renice.c'), ('harness', Path(__file__))]:
        report['hashes'][name] = sha(path)
    for name, cmd in [('binary', [binary, '--version']), ('external', [external, '--version']), ('compiler', ['cc', '--version'])]:
        report['versions'][name] = subprocess.check_output(cmd, text=True).splitlines()[0]
    try:
        for name, command in commands.items():
            report['warmup'][name] = batch(binary, command, args.passes, env)
        for run in range(args.runs):
            order = list(commands) if run % 2 == 0 else list(reversed(commands))
            for name in order:
                report['samples'][name].append(batch(binary, commands[name], args.passes, env))
                assert os.getpriority(os.PRIO_PROCESS, 0) == parent
        report['distribution_seconds'] = {
            name: dict(min=min(times), median=statistics.median(times), max=max(times),
                       samples=times, ns_per_set_and_query=statistics.median(times)*1e9/args.passes)
            for name, rows in report['samples'].items() for times in [[row['seconds'] for row in rows]]}
        report['external_over_builtin'] = report['distribution_seconds']['external']['median'] / report['distribution_seconds']['builtin']['median']
        report['status'] = 'pass'
    except BaseException as error:
        report['status'] = 'fail'
        report['error'] = repr(error)
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'cpu_affinity', 'distribution_seconds', 'external_over_builtin')}, indent=2))


if __name__ == '__main__':
    main()
