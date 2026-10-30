#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only owned fork controls and complete, bounded trace observation."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path('/opt/bashos-parity/harness/helpers')
LIMIT = 256 * 1024
MAX_HISTORIES = 64
MAX_TOKENS = 100
TAG = r'\[pid ([1-9][0-9]*)\] '
ARGS = r'(?:"(?:\\.|[^"\\\n])*"|[^()\[\]"\n])*'
ENTRY = re.compile(TAG + r'([a-z_][a-z_0-9]*)\((' + ARGS + r')\)')
EVENT = re.compile(TAG + r'(\+\+\+ (?:exec|new child [1-9][0-9]*|exited with [0-9]+) \+\+\+|--- signal [0-9]+ ---)\n')
TAIL = re.compile(r' = (\?|[0-9]+|-1 errno=[0-9]+)\n')
PTR = r'(?:NULL|0x[0-9a-f]+|[0-9]+)'
STRING = r'"(?:\\.|[^"\\\n])*"'


class TraceSearchBound(Exception):
    def __init__(self, reason, offset, histories):
        super().__init__(reason)
        self.details = {'search_bound': True, 'reason': reason, 'offset': offset,
                        'partial_histories': [{'pending': sorted(pending), 'wait_results': sorted(waits),
                                               'assignments': list(history)}
                                              for pending, waits, history in histories],
                        'partial_histories_recorded': len(histories)}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


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
    if parent != ppid or child != forked or child != waited or child == parent or status != (23 << 8) or again != -10:
        raise ValueError('inconsistent identities or unsuccessful reap confirmation')
    return parent, child


def entry_returns(pid, name, args, parent, child):
    """Validate complete fixture-specific argument shape and possible returns."""
    if name in ('getpid', 'getppid', 'fork'):
        if args:
            raise ValueError('nonempty arguments to ' + name)
        return {'getpid': {str(pid)}, 'getppid': {str(parent)}, 'fork': {str(child)}}[name]
    if name == 'execve':
        if not re.fullmatch(r'(?:"\./follow-tracee"|' + PTR + r'), ' + PTR + r', ' + PTR, args):
            raise ValueError('invalid execve arguments')
        return {'0'}
    if name == 'wait4':
        if not re.fullmatch(str(child) + r', ' + PTR + r', 0, (?:NULL|0)', args):
            raise ValueError('invalid wait4 arguments')
        # Linux may expose a restart return before SIGCHLD is delivered.
        return {str(child), '-1 errno=10', '-1 errno=512', '-1 errno=513', '-1 errno=514'}
    if name == 'write':
        text = (f'C {child} {parent} 0 0 0\n' if pid == child else
                f'P {parent} {child} {child} {23 << 8} -10\n')
        length = len(text.encode('ascii'))
        if not re.fullmatch(r'1, (?:' + PTR + '|' + STRING + r'), ' + str(length), args):
            raise ValueError('invalid write arguments')
        return {str(length)}
    if name == 'exit_group':
        if args != ('23' if pid == child else '42'):
            raise ValueError('invalid exit_group argument')
        return {'?'}
    raise ValueError('unexpected syscall ' + name)


def physical_line_failures(trace):
    failures = []
    for index, line in enumerate(trace.splitlines(keepends=True), 1):
        entry = ENTRY.match(line)
        if not (EVENT.fullmatch(line) or entry and TAIL.fullmatch(line, entry.end())):
            failures.append(index)
    return failures


def trace_assert(trace, parent, child, follow, history_limit=MAX_HISTORIES, token_limit=MAX_TOKENS):
    """Consume every byte as a complete entry, result or known event.

    Result tails have no PID; explore all compatible assignments while preserving
    at most one outstanding call per PID. Never claim a unique association when
    output permits multiple ones. A separate physical-line report is informational.
    """
    if not trace or len(trace.encode('utf-8')) > LIMIT or not trace.endswith('\n'):
        raise ValueError('empty, oversized, or incomplete trace')
    expected = {(parent, n): 1 for n in ('execve', 'getpid', 'fork', 'write', 'exit_group')}
    if follow:
        expected.update({(child, n): 1 for n in ('getpid', 'getppid', 'write', 'exit_group')})
    calls, events = {}, []
    # Keep distinct result-assignment histories even when pending states merge.
    # Pending entries carry their byte offsets, including repeated wait4 calls.
    states = [(frozenset(), frozenset(), ())]
    pos = 0
    branches = 0
    peak = 1
    tokens = 0
    child_stops = 0
    while pos < len(trace):
        tokens += 1
        if tokens > token_limit:
            raise TraceSearchBound('trace token limit', pos, states)
        event = EVENT.match(trace, pos)
        entry = ENTRY.match(trace, pos)
        tail = TAIL.match(trace, pos)
        if event:
            pid, description = int(event.group(1)), event.group(2)
            permitted = {parent} | ({child} if follow else set())
            if pid not in permitted:
                raise ValueError('event for unexpected PID')
            valid = (description == '+++ exec +++' and pid == parent or
                     description == f'+++ new child {child} +++' and pid == parent and follow or
                     description == f'+++ exited with {42 if pid == parent else 23} +++' or
                     description == '--- signal 17 ---' and pid == parent or
                     description == '--- signal 19 ---' and pid == child and follow)
            if not valid:
                raise ValueError('unexpected event: ' + description)
            if description not in ('--- signal 17 ---', '--- signal 19 ---') and [pid, description] in events:
                raise ValueError('duplicate event')
            if description == '--- signal 19 ---':
                if calls.get((parent, 'fork')) != 1 or any(p == child for p, _ in calls):
                    raise ValueError('child stop outside initial fork context')
                if child_stops >= 2:
                    raise TraceSearchBound('child initial stop limit', pos, states)
                child_stops += 1
            if description == '+++ exec +++':
                states = [(pending, waits, history) for pending, waits, history in states
                          if any(p == parent and n == 'execve' for p, n, _ in pending)]
            elif description.startswith('+++ new child '):
                states = [(pending, waits, history) for pending, waits, history in states
                          if any(p == parent and n == 'fork' for p, n, _ in pending)]
            elif description.startswith('+++ exited with '):
                if calls.get((pid, 'exit_group')) != 1:
                    raise ValueError('exit event before exit_group')
                states = [(pending, waits, history) for pending, waits, history in states
                          if all(p != pid for p, _, _ in pending)]
            if not states:
                raise ValueError('event inconsistent with pending syscalls')
            events.append([pid, description])
            pos = event.end()
        elif entry:
            pid, name, args = int(entry.group(1)), entry.group(2), entry.group(3)
            key = (pid, name)
            if key not in expected and key != (parent, 'wait4'):
                raise ValueError('unexpected PID or syscall')
            entry_returns(pid, name, args, parent, child)
            calls[key] = calls.get(key, 0) + 1
            if name == 'wait4' and calls[key] > 4:
                raise TraceSearchBound('wait4 entry limit', pos, states)
            if name != 'wait4' and calls[key] > 1:
                raise ValueError('duplicate syscall entries')
            next_states = []
            for pending, waits, history in states:
                if all(p != pid for p, _, _ in pending):
                    next_states.append((pending | {(pid, name, pos)}, waits, history))
            if not next_states:
                raise ValueError('new syscall before previous syscall completed')
            states = next_states
            pos = entry.end()
        elif tail:
            value = tail.group(1)
            next_states = []
            branched = False
            for pending, waits, history in states:
                compatible = 0
                for pid, name, entry_pos in sorted(pending):
                    # Argument validation was performed at entry; return sets do
                    # not depend on the already-validated argument text.
                    options = ({'0'} if name == 'execve' else
                               {str(pid)} if name == 'getpid' else
                               {str(parent)} if name == 'getppid' else
                               {str(child)} if name == 'fork' else
                               {str(child), '-1 errno=10', '-1 errno=512', '-1 errno=513', '-1 errno=514'} if name == 'wait4' else
                               {'?'} if name == 'exit_group' else
                               {str(len((f'C {child} {parent} 0 0 0\n' if pid == child else f'P {parent} {child} {child} {23 << 8} -10\n').encode('ascii')))})
                    if value in options:
                        compatible += 1
                        new_waits = waits | ({value} if name == 'wait4' and value in {str(child), '-1 errno=10'} else set())
                        assignment = {'entry_offset': entry_pos, 'result_offset': pos, 'pid': pid,
                                      'syscall': name, 'value': value}
                        next_states.append((pending - {(pid, name, entry_pos)}, frozenset(new_waits), history + (assignment,)))
                        if len(next_states) > history_limit:
                            raise TraceSearchBound('result history limit', pos, next_states)
                if compatible > 1:
                    branched = True
            if not next_states:
                raise ValueError('orphan or incompatible syscall result')
            if branched:
                branches += 1
            states = next_states
            peak = max(peak, len(states))
            pos = tail.end()
        else:
            raise ValueError('unconsumed or malformed trace at byte %d' % pos)
    if any(calls.get(k) != v for k, v in expected.items()) or not 2 <= calls.get((parent, 'wait4'), 0) <= 4:
        raise ValueError('missing required syscall observations')
    if child_stops and [parent, f'+++ new child {child} +++'] not in events:
        raise ValueError('child stop without a matching fork event')
    complete = [history for pending, waits, history in states
                if not pending and {str(child), '-1 errno=10'} <= waits]
    if not complete:
        raise ValueError('incomplete syscall results or missing wait results')
    # Strict physical-line shape is retained separately, not used as a proxy for
    # whether the fully consumed interleaved stream is coherent.
    return {'parent': parent, 'child': child, 'calls': {f'{p}:{n}': v for (p, n), v in calls.items()},
            'events': events, 'child_initial_stops': child_stops,
            'transient_branch_steps': branches, 'peak_live_histories': peak,
            'complete_history_count': len(complete), 'complete_histories': [list(h) for h in complete],
            'search_bound': False, 'physical_line_failures': physical_line_failures(trace),
            'all_bytes_consumed': True, 'tokens': tokens}


def parser_controls(home):
    record = {'completed': False, 'positive': [], 'negative': [], 'error': None}
    path = home / 'parser-controls.json'
    save(path, record)
    try:
        output = 'C 321 123 0 0 0\nP 123 321 321 5888 -10\n'
        parent, child = identities(output)
        c_len = len('C 321 123 0 0 0\n')
        p_len = len('P 123 321 321 5888 -10\n')
        a = '[pid 123] execve("./follow-tracee", 0x123, 0x456)'
        b = ('[pid 123] getpid() = 123\n[pid 123] fork() = 321\n'
             '[pid 123] wait4(321, 0x123, 0, NULL) = 321\n[pid 123] wait4(321, 0x123, 0, NULL) = -1 errno=10\n'
             f'[pid 123] write(1, 0x123, {p_len}) = {p_len}\n[pid 123] exit_group(42) = ?\n')
        c = (f'[pid 321] getpid() = 321\n[pid 321] getppid() = 123\n[pid 321] write(1, 0x123, {c_len}) = {c_len}\n'
             '[pid 321] exit_group(23) = ?\n')
        plain = a + ' = 0\n' + b
        follow = plain + c
        interleaved_exec = a + '[pid 123] +++ exec +++\n = 0\n' + b + c
        interleaved_calls = (a + ' = 0\n[pid 123] getpid() = 123\n[pid 123] fork()'
                             '[pid 123] +++ new child 321 +++\n[pid 321] getpid() = 321\n = 321\n'
                             '[pid 123] wait4(321, 0x123, 0, NULL)'
                             '[pid 321] getppid() = 123\n'
                             f'[pid 321] write(1, 0x123, {c_len}) = {c_len}\n[pid 321] exit_group(23) = ?\n'
                             ' = 321\n[pid 123] wait4(321, 0x123, 0, NULL) = -1 errno=10\n'
                             f'[pid 123] write(1, 0x123, {p_len}) = {p_len}\n[pid 123] exit_group(42) = ?\n')
        resolved = (a + ' = 0\n[pid 123] getpid() = 123\n[pid 123] fork()'
                    '[pid 123] +++ new child 321 +++\n[pid 321] --- signal 19 ---\n = 321\n'
                    '[pid 321] --- signal 19 ---\n[pid 321] getpid()'
                    '[pid 123] wait4(321, 0x123, 0, NULL) = 321\n'
                    '[pid 321] getppid() = 123\n'
                    f'[pid 321] write(1, 0x123, {c_len}) = {c_len}\n[pid 321] exit_group(23) = ?\n'
                    ' = 321\n[pid 123] wait4(321, 0x123, 0, NULL) = -1 errno=10\n'
                    f'[pid 123] write(1, 0x123, {p_len}) = {p_len}\n[pid 123] exit_group(42) = ?\n')
        early_stop = resolved.replace('[pid 123] +++ new child 321 +++\n[pid 321] --- signal 19 ---\n',
                                      '[pid 321] --- signal 19 ---\n[pid 123] +++ new child 321 +++\n')
        for name, value, following, histories in [
                ('plain', plain, False, 1), ('follow', follow, True, 1),
                ('exec-interleaving', interleaved_exec, True, 1),
                ('pid-interleaving-final-ambiguity', interleaved_calls, True, 2),
                ('resolved-ambiguity-child-stops', resolved, True, 1),
                ('child-stop-before-fork-event', early_stop, True, 1)]:
            result = trace_assert(value, parent, child, following)
            if 'interleaving' in name and not result['physical_line_failures']:
                raise ValueError('interleaved positive lacked physical-line finding')
            if result['complete_history_count'] != histories:
                raise ValueError(name + ' has wrong final history count')
            if name in ('resolved-ambiguity-child-stops', 'pid-interleaving-final-ambiguity') and result['transient_branch_steps'] == 0:
                raise ValueError(name + ' did not branch')
            if name == 'pid-interleaving-final-ambiguity' and result['complete_histories'][0] == result['complete_histories'][1]:
                raise ValueError('distinct attribution histories were merged')
            if name == 'resolved-ambiguity-child-stops':
                assigned = result['complete_histories'][0]
                match = [item for item in assigned if item['pid'] == child and item['syscall'] == 'getpid']
                if len(match) != 1 or match[0]['result_offset'] != value.index(' = 321\n', value.index('[pid 123] wait4')):
                    raise ValueError('resolved result was attributed to the wrong syscall')
            if name in ('resolved-ambiguity-child-stops', 'child-stop-before-fork-event') and result['child_initial_stops'] != 2:
                raise ValueError(name + ' lost child stop events')
            record['positive'].append(name)
            save(path, record)
        negatives = {
            'empty-identities': lambda: identities(''),
            'wrong-wait': lambda: identities(output.replace('321 5888', '320 5888')),
            'wrong-reap': lambda: identities(output.replace('-10', '0')),
            'wrong-child-status': lambda: identities(output.replace('5888', '0')),
            'empty-trace': lambda: trace_assert('', parent, child, False),
            'missing-child': lambda: trace_assert(plain, parent, child, True),
            'child-without-follow': lambda: trace_assert(follow, parent, child, False),
            'untagged-call': lambda: trace_assert(plain + 'exit_group(23) = ?\n', parent, child, False),
            'missing-final-newline': lambda: trace_assert(follow[:-1], parent, child, True),
            'wrong-pid': lambda: trace_assert(plain.replace('pid 123', 'pid 999'), parent, child, False),
            'truncated-interior': lambda: trace_assert(follow.replace('getppid() = 123\n', 'getppid(garbage\n'), parent, child, True),
            'stray-error': lambda: trace_assert(follow + 'strace: PTRACE_SYSCALL: failure\n', parent, child, True),
            'bad-child-args': lambda: trace_assert(follow.replace('getppid()', 'getppid(garbage)'), parent, child, True),
            'missing-result': lambda: trace_assert(follow.replace('getppid() = 123\n', 'getppid()'), parent, child, True),
            'orphan-result': lambda: trace_assert(follow + ' = 123\n', parent, child, True),
            'wrong-child-result': lambda: trace_assert(follow.replace('getppid() = 123', 'getppid() = 999'), parent, child, True),
            'wrong-child-exit': lambda: trace_assert(follow.replace('exit_group(23)', 'exit_group(24)'), parent, child, True),
            'malformed-event': lambda: trace_assert(interleaved_exec.replace('+++ exec +++', '+++ exec broken +++'), parent, child, True),
            'wrong-stop-pid': lambda: trace_assert(resolved.replace('[pid 321] --- signal 19 ---', '[pid 999] --- signal 19 ---', 1), parent, child, True),
            'parent-stop': lambda: trace_assert(resolved.replace('[pid 321] --- signal 19 ---', '[pid 123] --- signal 19 ---', 1), parent, child, True),
            'stop-after-child-syscall': lambda: trace_assert(resolved.replace('[pid 321] getppid()', '[pid 321] --- signal 19 ---\n[pid 321] getppid()'), parent, child, True),
            'stop-before-fork': lambda: trace_assert(resolved.replace('[pid 123] fork()', '[pid 321] --- signal 19 ---\n[pid 123] fork()', 1), parent, child, True),
            'stop-without-fork-event': lambda: trace_assert(resolved.replace('[pid 123] +++ new child 321 +++\n', ''), parent, child, True),
            'child-stop-without-follow': lambda: trace_assert(plain + '[pid 321] --- signal 19 ---\n', parent, child, False),
        }
        for name, control in negatives.items():
            try:
                control()
            except ValueError:
                record['negative'].append(name)
                save(path, record)
                continue
            raise ValueError('parser accepted invalid control ' + name)
        try:
            trace_assert(resolved.replace('[pid 321] getpid()', '[pid 321] --- signal 19 ---\n[pid 321] getpid()', 1), parent, child, True)
        except TraceSearchBound as error:
            if error.details['reason'] != 'child initial stop limit' or not error.details['partial_histories']:
                raise ValueError('stop bound did not retain partial attribution')
            record['positive'].append('bounded-child-stops-inconclusive')
            save(path, record)
        else:
            raise ValueError('excess stop control did not trigger search bound')
        for name, kwargs, reason in [('bounded-result-histories-inconclusive', {'history_limit': 1}, 'result history limit'),
                                     ('bounded-token-count-inconclusive', {'token_limit': 1}, 'trace token limit')]:
            try:
                trace_assert(interleaved_calls, parent, child, True, **kwargs)
            except TraceSearchBound as error:
                if error.details['reason'] != reason or not error.details['partial_histories']:
                    raise ValueError(name + ' lost partial attribution')
                record['positive'].append(name)
                save(path, record)
            else:
                raise ValueError(name + ' did not trigger search bound')
        record['completed'] = True
    except Exception as error:
        record['error'] = str(error)
        raise
    finally:
        save(path, record)


def bounded(path):
    with path.open('rb') as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError(str(path.name) + ' exceeds retained diagnostic limit')
    return data


def setup(home):
    report = {'complete': False, 'stage': 'parser', 'stages': [], 'error': None}
    report_path = home / 'setup-controls.json'
    save(report_path, report)
    def run(name, command, expected, out_path, err_path, append=False):
        stage = {'name': name, 'command': command, 'started': True, 'completed': False,
                 'status': None, 'timeout': False, 'error': None}
        report['stage'] = name
        report['stages'].append(stage)
        save(report_path, report)
        try:
            try:
                result = subprocess.run(command, capture_output=True, timeout=12)
                stdout, stderr = result.stdout, result.stderr
                stage['status'] = result.returncode
                stage['completed'] = True
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                stage['timeout'] = True
            mode = 'ab' if append else 'wb'
            for path, data in ((out_path, stdout), (err_path, stderr)):
                with path.open(mode) as stream:
                    offset = stream.tell()
                    stream.write(data)
                stage[path.name] = {'offset': offset, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            if name in ('direct', 'native'):
                (home / (name + '.status')).write_text(str(stage['status']) + '\n' if stage['completed'] else 'timeout\n')
            if stage['timeout'] or stage['status'] != expected or len(stdout) > LIMIT or len(stderr) > LIMIT:
                raise ValueError(name + ' invocation failed, timed out or exceeded diagnostic limit')
            return stdout, stderr
        except Exception as error:
            stage['error'] = str(error)
            raise
        finally:
            save(report_path, report)
    try:
        parser_controls(home)
        commands = [
            ['/usr/bin/gcc', '-static', '-nostdlib', '-no-pie', '-fno-stack-protector', '-O0', '-o', 'follow-tracee', str(ROOT / 'strace-follow-reviewed.tracee.c')],
            ['/usr/bin/gcc', '-Wall', '-Wextra', '-O0', '-o', 'follow-control', str(ROOT / 'strace-follow-reviewed.control.c')],
        ]
        for index, cmd in enumerate(commands):
            run('compile-' + str(index + 1), cmd, 0, home / 'gcc.out', home / 'gcc.err', append=index > 0)
        bounded(home / 'gcc.out')
        bounded(home / 'gcc.err')
        for name, command, expected in [('direct', './follow-tracee', 42), ('native', './follow-control', 0)]:
            stdout, stderr = run(name, [command], expected, home / (name + '.out'), home / (name + '.err'))
            parent, child = identities(stdout.decode('ascii'))
            if name == 'direct' and stderr:
                raise ValueError('direct control produced stderr')
            if name == 'native':
                log = stderr.decode('ascii')
                parent_length = len(f'P {parent} {child} {child} {23 << 8} -10\n'.encode('ascii'))
                child_length = len(f'C {child} {parent} 0 0 0\n'.encode('ascii'))
                required = [f'FORK {parent} {child}\n', f'CALL {parent} 59 -38\n', f'CALL {parent} 59 0\n',
                            f'CALL {parent} 39 -38\n', f'CALL {parent} 39 {parent}\n',
                            f'CALL {parent} 57 -38\n', f'CALL {parent} 57 {child}\n',
                            f'CALL {child} 39 -38\n', f'CALL {child} 39 {child}\n',
                            f'CALL {child} 110 -38\n', f'CALL {child} 110 {parent}\n',
                            f'CALL {parent} 61 {child}\n', f'CALL {parent} 61 -10\n',
                            f'CALL {parent} 1 -38\n', f'CALL {parent} 1 {parent_length}\n',
                            f'CALL {child} 1 -38\n', f'CALL {child} 1 {child_length}\n',
                            f'CALL {parent} 231 -38\n', f'CALL {child} 231 -38\n',
                            f'EXIT {child} 23\n', f'EXIT {parent} 42\n']
                if any(log.count(item) != 1 for item in required):
                    raise ValueError('native fork, syscall, wait or exit observations missing or duplicated')
                if not 2 <= log.count(f'CALL {parent} 61 -38\n') <= 4:
                    raise ValueError('native wait syscall entries missing or excessive')
                stop = f'STOP {child} 19 0\n'
                if log.count(stop) != 1 or log.count('STOP ') != 1:
                    raise ValueError('native initial child SIGSTOP missing, duplicated or wrong PID')
                stop_at = log.index(stop)
                fork_at = log.index(f'FORK {parent} {child}\n')
                first_child_call = log.index(f'CALL {child} ')
                if stop_at >= first_child_call:
                    raise ValueError('native child SIGSTOP did not precede first child syscall stop')
                report['native_initial_stop'] = {'parent': parent, 'child': child, 'signal': 19,
                                                 'event': 0, 'stop_offset': stop_at, 'fork_offset': fork_at,
                                                 'first_child_call_offset': first_child_call,
                                                 'fork_event_before_stop': fork_at < stop_at}
        report['stage'] = 'done'
        report['complete'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        save(report_path, report)


def verify(home, follow):
    mode = 'follow' if follow else 'plain'
    report = {'mode': mode, 'complete': False, 'files': {}, 'infrastructure_errors': [],
              'product_failures': [], 'observations': {}}
    raw = {}
    for name in ('candidate.out', 'candidate.err', 'candidate.status', 'candidate.start'):
        try:
            raw[name] = bounded(home / name)
            report['files'][name] = {'bytes': len(raw[name]), 'sha256': hashlib.sha256(raw[name]).hexdigest()}
        except (OSError, ValueError) as error:
            report['infrastructure_errors'].append(name + ': ' + str(error))
    if not report['infrastructure_errors']:
        try:
            if raw['candidate.start'] != (mode + '\n').encode():
                raise OSError('invalid invocation start marker')
            status_text = raw['candidate.status'].decode('ascii')
            if not re.fullmatch(r'(?:0|[1-9][0-9]{0,2})\n', status_text) or int(status_text) > 255:
                raise OSError('invalid invocation status record')
            report['complete'] = True
            status = int(status_text)
            report['observations']['status'] = status
            if status != 42:
                report['product_failures'].append('candidate did not propagate parent exit status 42')
            trace = None
            try:
                trace = raw['candidate.err'].decode('utf-8')
                report['observations']['physical_line_failures'] = physical_line_failures(trace)
            except UnicodeError as error:
                report['product_failures'].append('trace encoding: ' + str(error))
            try:
                parent, child = identities(raw['candidate.out'].decode('ascii'))
                report['observations'].update({'parent': parent, 'child': child})
                if trace is not None:
                    try:
                        report['observations']['trace'] = trace_assert(trace, parent, child, follow)
                    except TraceSearchBound as error:
                        report['observations']['trace'] = error.details
                        report['infrastructure_errors'].append('trace attribution search bound: ' + str(error))
                    except ValueError as error:
                        report['product_failures'].append('trace: ' + str(error))
            except (ValueError, UnicodeError) as error:
                report['product_failures'].append('identities: ' + str(error))
        except (OSError, UnicodeError) as error:
            report['infrastructure_errors'].append(str(error))
    save(home / 'assertions.json', report)
    if report['infrastructure_errors'] or report['product_failures']:
        print('observation failed; see assertions.json')
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
