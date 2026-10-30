#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only fork tracing controls and assertions; never attach to external tasks."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path('/opt/bashos-parity/harness/helpers')
LIMIT = 256 * 1024


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
        Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home' or
        Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
        not re.fullmatch(r'[0-9a-fA-F-]{36}', marker) or os.uname().machine != 'x86_64'):
        raise ValueError('requires isolated uid-2000 x86_64 parity guest')


def identities(text):
    match = re.fullmatch(r'C ([1-9][0-9]*) ([1-9][0-9]*) 0 0 0\nP ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([0-9]+) (-?[0-9]+)\n', text)
    if not match:
        raise ValueError('missing or malformed child/parent identity and wait records')
    child, ppid, parent, forked, waited, status, again = map(int, match.groups())
    if parent != ppid or child != forked or child != waited or child == parent or status != 23 << 8 or again != -10:
        raise ValueError('inconsistent identities or unsuccessful reap confirmation')
    return parent, child


def trace_assert(trace, parent, child, follow):
    if not trace or len(trace.encode()) > LIMIT or not trace.endswith('\n'):
        raise ValueError('empty, oversized, or incomplete trace')
    tags = [int(n) for n in re.findall(r'\[pid ([1-9][0-9]*)\]', trace)]
    if not tags or set(tags) - ({parent, child} if follow else {parent}):
        raise ValueError('missing or unexpected PID tags')
    calls = {}
    for record in re.finditer(r'\b([a-z_][a-z_0-9]*)\(', trace):
        tag = re.search(r'\[pid ([1-9][0-9]*)\] $', trace[:record.start()])
        if not tag:
            raise ValueError('untagged syscall record')
        key = (int(tag.group(1)), record.group(1))
        calls[key] = calls.get(key, 0) + 1
    expected_parent = {'execve': 1, 'getpid': 1, 'fork': 1, 'write': 1, 'exit_group': 1}
    expected_child = {'getpid': 1, 'getppid': 1, 'write': 1, 'exit_group': 1} if follow else {}
    if any(calls.get((parent, name)) != count for name, count in expected_parent.items()) or calls.get((parent, 'wait4'), 0) < 2:
        raise ValueError('missing or duplicate parent syscall observations')
    if follow:
        if any(calls.get((child, name)) != count for name, count in expected_child.items()):
            raise ValueError('missing or duplicate tagged child syscalls')
    allowed = {(parent, n) for n in (*expected_parent, 'wait4')} | {(child, n) for n in expected_child}
    if set(calls) - allowed:
        raise ValueError('unexpected syscall or child syscall without -f')
    return {'tagged_pids': sorted(set(tags)), 'parent': parent, 'child': child,
            'calls': {f'{pid}:{name}': count for (pid, name), count in calls.items()}}


def parser_controls(home):
    output = 'C 321 123 0 0 0\nP 123 321 321 5888 -10\n'
    parent, child = identities(output)
    parent_trace = ('[pid 123] execve() = 0\n[pid 123] getpid() = 123\n[pid 123] fork() = 321\n'
                    '[pid 123] wait4(321) = 321\n[pid 123] wait4(321) = -1\n'
                    '[pid 123] write() = 1\n[pid 123] exit_group(42) = ?\n')
    child_trace = ('[pid 321] getpid() = 321\n[pid 321] getppid() = 123\n'
                   '[pid 321] write() = 1\n[pid 321] exit_group(23) = ?\n')
    trace_assert(parent_trace + child_trace, parent, child, True)
    trace_assert(parent_trace, parent, child, False)
    negatives = [lambda: identities(''), lambda: identities(output.replace('321 5888', '320 5888')),
                 lambda: identities(output.replace('-10', '0')),
                 lambda: identities(output.replace('5888', '0')),
                 lambda: trace_assert('', parent, child, False),
                 lambda: trace_assert(parent_trace, parent, child, True),
                 lambda: trace_assert(parent_trace + child_trace, parent, child, False),
                 lambda: trace_assert(parent_trace + '[pid 123] getpid() = 321\n', parent, child, False),
                 lambda: trace_assert(parent_trace + 'exit_group(23) = ?\n', parent, child, False),
                 lambda: trace_assert(parent_trace + child_trace[:-1], parent, child, True),
                 lambda: trace_assert(parent_trace.replace('pid 123', 'pid 999'), parent, child, False)]
    for control in negatives:
        try:
            control()
        except ValueError:
            continue
        raise ValueError('parser accepted an invalid control')
    (home / 'parser-controls.json').write_text(json.dumps({'positive': 2, 'negative': len(negatives), 'ok': True}) + '\n')


def bounded(path):
    data = path.read_bytes()
    if len(data) > LIMIT:
        raise ValueError(str(path.name) + ' exceeds retained diagnostic limit')
    return data


def setup(home):
    parser_controls(home)
    commands = [
        ['/usr/bin/gcc', '-static', '-nostdlib', '-no-pie', '-fno-stack-protector', '-O0', '-o', 'follow-tracee', str(ROOT / 'strace-follow-reviewed.tracee.c')],
        ['/usr/bin/gcc', '-Wall', '-Wextra', '-O0', '-o', 'follow-control', str(ROOT / 'strace-follow-reviewed.control.c')],
    ]
    with (home / 'gcc.out').open('wb') as out, (home / 'gcc.err').open('wb') as err:
        for cmd in commands:
            subprocess.run(cmd, stdout=out, stderr=err, check=True, timeout=20)
    bounded(home / 'gcc.out')
    bounded(home / 'gcc.err')
    for name, command, expected in [('direct', './follow-tracee', 42), ('native', './follow-control', 0)]:
        result = subprocess.run([command], capture_output=True, timeout=12)
        (home / (name + '.out')).write_bytes(result.stdout)
        (home / (name + '.err')).write_bytes(result.stderr)
        (home / (name + '.status')).write_text(str(result.returncode) + '\n')
        if max(len(result.stdout), len(result.stderr)) > LIMIT or result.returncode != expected:
            raise ValueError(name + ' control failed or produced oversized diagnostics')
        parent, child = identities(result.stdout.decode('ascii'))
        if name == 'direct' and result.stderr:
            raise ValueError('direct control produced stderr')
        if name == 'native':
            log = result.stderr.decode('ascii')
            required = [f'FORK {parent} {child}\n', f'CALL {parent} 57 {child}\n',
                        f'CALL {child} 110 {parent}\n', f'CALL {parent} 61 {child}\n',
                        f'CALL {parent} 61 -10\n', f'EXIT {child} 23\n', f'EXIT {parent} 42\n']
            if any(log.count(record) != 1 for record in required):
                raise ValueError('native fork, syscall, wait or exit observations missing or duplicated')


def verify(home, follow):
    mode = 'follow' if follow else 'plain'
    observations, failures = {}, []
    try:
        output = bounded(home / 'candidate.out').decode('ascii')
        trace = bounded(home / 'candidate.err').decode('utf-8')
        status = int(bounded(home / 'candidate.status').decode('ascii').strip())
        parent, child = identities(output)
        observations.update({'status': status, 'parent': parent, 'child': child})
        if status != 42:
            raise ValueError('candidate did not propagate parent exit status 42')
        observations.update(trace_assert(trace, parent, child, follow))
    except (OSError, ValueError, UnicodeError) as error:
        failures.append(str(error))
    (home / 'assertions.json').write_text(json.dumps({'mode': mode, 'observations': observations, 'failures': failures}, indent=2) + '\n')
    if failures:
        print('\n'.join(failures))
        return 1
    print(mode + '-ok')
    return 0


def main():
    require_guest()
    home = Path(os.environ['HOME'])
    if sys.argv[1:] == ['setup']:
        setup(home)
        return 0
    if sys.argv[1:] in (['follow'], ['plain']):
        return verify(home, sys.argv[1] == 'follow')
    raise ValueError('expected setup, follow or plain')


if __name__ == '__main__':
    raise SystemExit(main())
