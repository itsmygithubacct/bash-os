#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only preflight, controlled candidate observation and assessment."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import struct
import subprocess
import sys
import time
import zlib

from ns_guest_identity_r1 import verify as verify_guest_identity

HOME = Path('/tmp/parity-home')
LIMIT = 512 * 1024
CONTROL_RAW_LIMIT = 8 * 1024 * 1024
CONTROL_COMPRESSED_LIMIT = 320 * 1024
CONTROL_DOCUMENT_LIMIT = 512 * 1024
CONTROL_INPUTS = frozenset(('worker', 'leader', 'running', 'wrong_tracer', 'resumed',
                            'candidate_dead', 'gate_closed', 'wrong_owner', 'short_observation',
                            'insufficient_samples', 'wrong_target', 'late_stop', 'sampling_gap',
                            'capture_error'))
CONTROL_RECORDS = frozenset(('worker_record', 'leader_record', 'monitor_mismatch',
                             'missing_release', 'missing_worker_exit', 'missing_cleanup',
                             'cleanup_too_early'))
CONTROL_WIRE_TESTS = frozenset(('roundtrip', 'omitted_payload', 'corrupted_stream',
                                'omitted_input', 'omitted_record', 'corrupted_outcome'))


def guard():
    # This fixture attaches only as the unprivileged guest account. The shared
    # identity guard validates the controller-protected attestation and marker.
    if os.getuid() != 2000 or os.geteuid() != 2000 or os.uname().machine != 'x86_64':
        raise RuntimeError('requires isolated uid-2000 x86_64 parity guest')
    verify_guest_identity()


def save(name, value):
    temporary = HOME / (name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(HOME / name)


def parse_trace(text, leader, worker, parent, require_worker=True):
    """Only full line-anchored events count; no guessed pairing of fragments."""
    if not text or not text.endswith('\n') or '\0' in text:
        raise ValueError('empty, incomplete or NUL-containing trace')
    found = {'leader_call': False, 'worker_call': False, 'leader_exit': False, 'worker_exit': False}
    positions = {}
    expected = {leader: ('getpid', leader, 'leader_call')}
    if require_worker:
        expected[worker] = ('getppid', parent, 'worker_call')
    for index, line in enumerate(text.splitlines()):
        if (re.search(r'(^|:\s)strace:', line) or re.search(r'\bPTRACE_[A-Z_]+\b', line) or
                re.search(r'\bwaitpid\s*:', line) or '+++ killed by signal' in line or '+++ detached' in line):
            raise ValueError('tracer error: ' + line[:200])
        for tid, (call, value, label) in expected.items():
            prefix = '[pid %d] %s(' % (tid, call)
            if prefix in line:
                if line != '[pid %d] %s() = %d' % (tid, call, value):
                    raise ValueError('incomplete, interleaved or malformed selected syscall: ' + line[:200])
                if found['leader_exit' if tid == leader else 'worker_exit']:
                    raise ValueError('selected syscall after task exit')
                found[label] = True
                positions.setdefault(label, index)
            exit_text = '[pid %d] +++ exited with 0 +++' % tid
            if exit_text in line:
                if line != exit_text:
                    raise ValueError('malformed exit event: ' + line[:200])
                exit_label = 'leader_exit' if tid == leader else 'worker_exit'
                if found[exit_label]:
                    raise ValueError('duplicate exit event')
                found[exit_label] = True
                positions[exit_label] = index
    for who in ('leader', 'worker'):
        if found[who + '_call'] and found[who + '_exit'] and positions[who + '_call'] >= positions[who + '_exit']:
            raise ValueError(who + ' syscall occurs after exit')
    if found['worker_exit'] and found['leader_call'] and positions['worker_exit'] >= positions['leader_call']:
        raise ValueError('leader call precedes worker exit')
    return found


def parser_controls():
    # Whole events from different TIDs may interleave; selected calls are
    # serialized by the shared gates to avoid unattributable partial lines.
    good = ('[pid 101] write(1, 0x0, 0) = 0\n[pid 102] getppid() = 99\n'
            '[pid 101] close(3) = 0\n[pid 102] +++ exited with 0 +++\n'
            '[pid 101] getpid() = 101\n[pid 101] +++ exited with 0 +++\n')
    negative = {
        'truncated': good.replace('[pid 101] getpid() = 101\n', '[pid 101] getpid('),
        'diagnostic': good.replace('[pid 101] getpid() = 101', 'strace: error [pid 101] getpid() = 101'),
        'exit_in_text': good.replace('[pid 101] +++ exited with 0 +++', 'error: [pid 101] +++ exited with 0 +++'),
        'wrong_tid': good.replace('[pid 102] getppid()', '[pid 103] getppid()'),
        'wrong_order': good.replace('[pid 101] getpid() = 101\n[pid 101] +++ exited with 0 +++', '[pid 101] +++ exited with 0 +++\n[pid 101] getpid() = 101'),
        'error': good + 'strace: PTRACE_ATTACH: Operation not permitted\n',
        'worker_order': good.replace('[pid 102] getppid() = 99', '[pid 102] +++ exited with 0 +++').replace('[pid 102] +++ exited with 0 +++\n[pid 101] getpid()', '[pid 102] getppid() = 99\n[pid 101] getpid()'),
        'no_newline': good.rstrip('\n'), 'empty': '',
        'partial_return': good.replace('getpid() = 101', 'getpid() ='),
        'wrong_return': good.replace('getpid() = 101', 'getpid() = 999'),
        'late_duplicate': good + '[pid 101] getpid() = 101\n',
        'truncated_exit': good.replace('+++ exited with 0 +++', '+++ exited with 0'),
    }
    record = {'inputs': {'positive': good, **negative}, 'outcomes': {}, 'complete': False}
    try:
        outcomes = record['outcomes']
        outcomes['positive'] = parse_trace(good, 101, 102, 99)
        if not all(outcomes['positive'].values()):
            raise ValueError('positive parser control failed')
        outcomes['positive_r1'] = parse_trace(good, 101, 102, 99, False)
        if not outcomes['positive_r1']['leader_call'] or not outcomes['positive_r1']['leader_exit']:
            raise ValueError('positive r1 parser control failed')
        for label, value in negative.items():
            try:
                result = parse_trace(value, 101, 102, 99)
                outcomes[label] = result
                if all(result.values()):
                    raise ValueError('parser accepted negative control ' + label)
            except ValueError as exc:
                if str(exc).startswith('parser accepted'):
                    raise
                outcomes[label] = {'rejected': str(exc)}
        record['complete'] = True
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        save('parser-controls.json', record)


def task_status(pid, tid):
    text = Path('/proc/%d/task/%d/status' % (pid, tid)).read_text()
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    result = {key: int(fields[key].strip()) for key in ('Tgid', 'Pid', 'PPid', 'TracerPid')}
    result['State'] = fields['State'].strip()
    for key in ('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches'):
        result[key] = int(fields[key].strip())
    return result


def attributable_stall(proof, pre):
    """Require a timely observed stop sustained across the full bounded interval."""
    try:
        which = proof['stage']
        if which not in ('worker', 'leader') or proof['target_tid'] != pre[which]:
            return False
        required = (4 if which == 'worker' else 5) * 1000000000
        max_gap = 500000000
        samples = proof['samples']
        if len(samples) < 3 or samples[0]['start_ns'] < proof['wait_started_ns']:
            return False
        if (proof['deadline_ns'] != proof['wait_started_ns'] + required + 1000000000 or
                proof['timeout_ns'] != samples[-1]['end_ns'] or proof['timeout_ns'] > proof['deadline_ns']):
            return False
        baseline = None
        for index, sample in enumerate(samples):
            if (sample.get('capture_error') or sample['end_ns'] < sample['start_ns'] or
                    sample['end_ns'] - sample['start_ns'] > max_gap or
                    (index and (sample['start_ns'] < samples[index - 1]['end_ns'] or
                                sample['start_ns'] - samples[index - 1]['end_ns'] > max_gap))):
                return False
            task, leader, tracer = sample['task'], sample['leader'], sample['tracer']
            if (not sample['fixture_alive'] or not sample['tracer_alive'] or
                    task['Pid'] != pre[which] or task['Tgid'] != pre['leader'] or task['PPid'] != pre['owner_pid'] or
                    task['TracerPid'] not in (0, pre['tracer_pid']) or
                    leader['Pid'] != pre['leader'] or leader['Tgid'] != pre['leader'] or leader['PPid'] != pre['owner_pid'] or
                    tracer['Pid'] != pre['tracer_pid'] or tracer['Tgid'] != pre['tracer_pid'] or tracer['PPid'] != pre['owner_pid'] or
                    sample['shared'] != ([1, 0, 1, 1] if which == 'worker' else [1, 1, 1, 1])):
                return False
            stopped = task['TracerPid'] == pre['tracer_pid'] and task['State'].startswith('t ')
            if task['State'].startswith('t ') and not stopped:
                return False
            if baseline is None and stopped:
                baseline = index
                if sample['end_ns'] - proof['wait_started_ns'] > max_gap:
                    return False
                switches = (task['voluntary_ctxt_switches'], task['nonvoluntary_ctxt_switches'])
            elif baseline is not None and (not stopped or
                    (task['voluntary_ctxt_switches'], task['nonvoluntary_ctxt_switches']) != switches):
                return False
        if baseline is None:
            return False
        return samples[-1]['start_ns'] - samples[baseline]['end_ns'] >= required
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def stall_record_valid(record):
    try:
        proof, pre, cleanup = record['stall'], record['preconditions'], record['stall_cleanup']
        which = proof['stage']
        if proof.get('result') != 'candidate_stall' or record['monitors'][which] != proof:
            return False
        events = record['events']
        order = [entry['stage'] for entry in events]
        needed = (['worker-release', 'worker-wait', 'worker-stall-observation', 'worker-stall-cleanup']
                  if which == 'worker' else
                  ['worker-release', 'worker-wait', 'leader-release', 'fixture-completion',
                   'leader-stall-observation', 'leader-stall-cleanup'])
        positions = [order.index(name) for name in needed]
        if positions != sorted(set(positions)):
            return False
        release_event = 'worker-release' if which == 'worker' else 'leader-release'
        wait_event = 'worker-wait' if which == 'worker' else 'fixture-completion'
        times = {entry['stage']: entry['time_ns'] for entry in events}
        if (not record['worker_release'] or
                (which == 'leader' and (not record['worker_gone_before_leader_release'] or not record['leader_release'])) or
                (which == 'worker' and record.get('leader_release', False)) or
                not (times[release_event] <= proof['wait_started_ns'] <= times[wait_event] <= proof['samples'][0]['start_ns']) or
                proof['timeout_ns'] > times[which + '-stall-observation'] or
                times[which + '-stall-cleanup'] <= times[which + '-stall-observation'] or
                not cleanup['tracer_kill_requested'] or cleanup['tracer_status_after_kill'] != -signal.SIGKILL or
                not record['candidate_timeout'] or record['candidate_status_origin'] != 'cleanup_sigkill' or
                record['candidate_status'] != -signal.SIGKILL):
            return False
        return attributable_stall(proof, pre)
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def control_envelope(record):
    # The payload is the complete original control record, not a reduced summary.
    raw = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(raw) > CONTROL_RAW_LIMIT:
        raise ValueError('stall control raw size exceeds bound')
    packed = zlib.compress(raw, 9)
    if len(packed) > CONTROL_COMPRESSED_LIMIT:
        raise ValueError('stall control compressed size exceeds bound')
    return {'schema': 'strace-attach-stall-controls-zlib-v1', 'codec': 'zlib',
            'complete': record.get('complete') is True,
            'raw_bytes': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest(),
            'compressed_bytes': len(packed), 'compressed_sha256': hashlib.sha256(packed).hexdigest(),
            'payload_base64': base64.b64encode(packed).decode('ascii')}


def unique_json_object(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('duplicate stall control key')
        result[key] = value
    return result


def decode_control_envelope(envelope):
    fields = {'schema', 'codec', 'complete', 'raw_bytes', 'raw_sha256', 'compressed_bytes',
              'compressed_sha256', 'payload_base64'}
    if (not isinstance(envelope, dict) or set(envelope) not in (fields, fields | {'wire_checks'})
        or envelope.get('schema') != 'strace-attach-stall-controls-zlib-v1'
        or envelope.get('codec') != 'zlib' or envelope.get('complete') is not True
        or type(envelope.get('raw_bytes')) is not int or not 0 < envelope['raw_bytes'] <= CONTROL_RAW_LIMIT
        or type(envelope.get('compressed_bytes')) is not int or not 0 < envelope['compressed_bytes'] <= CONTROL_COMPRESSED_LIMIT):
        raise ValueError('invalid stall control envelope')
    packed = base64.b64decode(envelope['payload_base64'], validate=True)
    if len(packed) != envelope['compressed_bytes'] or hashlib.sha256(packed).hexdigest() != envelope['compressed_sha256']:
        raise ValueError('stall control compressed bytes differ')
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, CONTROL_RAW_LIMIT + 1)
    if (len(raw) > CONTROL_RAW_LIMIT or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data
        or len(raw) != envelope['raw_bytes'] or hashlib.sha256(raw).hexdigest() != envelope['raw_sha256']):
        raise ValueError('stall control uncompressed bytes differ')
    record = json.loads(raw, object_pairs_hook=unique_json_object)
    if (not isinstance(record, dict) or set(record) != {'preconditions', 'inputs', 'outcomes',
            'record_inputs', 'record_outcomes', 'complete'} or record['complete'] is not True
        or record['preconditions'] != {'leader':101, 'worker':102, 'owner_pid':99, 'tracer_pid':201}
        or not all(isinstance(record[k], dict) for k in ('inputs', 'outcomes', 'record_inputs', 'record_outcomes'))
        or set(record['inputs']) != CONTROL_INPUTS or set(record['outcomes']) != CONTROL_INPUTS
        or set(record['record_inputs']) != CONTROL_RECORDS or set(record['record_outcomes']) != CONTROL_RECORDS
        or any(record['outcomes'][k] is not (k in ('worker','leader')) for k in CONTROL_INPUTS)
        or any(record['record_outcomes'][k] is not (k in ('worker_record','leader_record')) for k in CONTROL_RECORDS)):
        raise ValueError('stall control cases or outcomes differ')
    if json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') != raw:
        raise ValueError('noncanonical stall control payload')
    return record


def control_wire_tests(record):
    envelope = control_envelope(record)
    if decode_control_envelope(envelope) != record: raise ValueError('stall control roundtrip differs')
    mutations = {}
    bad = copy.deepcopy(envelope); del bad['payload_base64']; mutations['omitted_payload'] = bad
    bad = copy.deepcopy(envelope)
    packed = base64.b64decode(bad['payload_base64'], validate=True)[:-1]
    bad.update(payload_base64=base64.b64encode(packed).decode('ascii'), compressed_bytes=len(packed),
               compressed_sha256=hashlib.sha256(packed).hexdigest())
    mutations['corrupted_stream'] = bad
    bad = copy.deepcopy(record); del bad['inputs']['late_stop']; mutations['omitted_input'] = control_envelope(bad)
    bad = copy.deepcopy(record); del bad['record_inputs']['missing_cleanup']; mutations['omitted_record'] = control_envelope(bad)
    bad = copy.deepcopy(record); bad['outcomes']['late_stop'] = True; mutations['corrupted_outcome'] = control_envelope(bad)
    for name, value in mutations.items():
        try: decode_control_envelope(value)
        except (ValueError, KeyError, TypeError, zlib.error): continue
        raise ValueError('stall control wire negative accepted: ' + name)
    return {name: True for name in CONTROL_WIRE_TESTS}


def stall_controls():
    pre = {'leader': 101, 'worker': 102, 'owner_pid': 99, 'tracer_pid': 201}
    leader = {'Pid': 101, 'Tgid': 101, 'PPid': 99, 'TracerPid': 201, 'State': 't (tracing stop)',
              'voluntary_ctxt_switches': 7, 'nonvoluntary_ctxt_switches': 2}
    tracer = {'Pid': 201, 'Tgid': 201, 'PPid': 99, 'TracerPid': 0, 'State': 'S (sleeping)'}
    def proof(stage):
        target = copy.deepcopy(leader)
        if stage == 'worker':
            target['Pid'] = 102
        threshold = (4 if stage == 'worker' else 5) * 1000000000
        sample = {'task': target, 'leader': leader, 'tracer': tracer, 'fixture_alive': True,
                  'tracer_alive': True, 'shared': [1, 0 if stage == 'worker' else 1, 1, 1]}
        samples = []
        for offset in range(0, threshold + 100000001, 100000000):
            item = copy.deepcopy(sample)
            item['start_ns'] = 1100000000 + offset
            item['end_ns'] = item['start_ns'] + 1000000
            samples.append(item)
        return {'stage': stage, 'target_tid': pre[stage], 'wait_started_ns': 1000000000,
                'deadline_ns': 1000000000 + threshold + 1000000000,
                'timeout_ns': samples[-1]['end_ns'], 'samples': samples, 'result': 'candidate_stall'}
    positive_worker, positive_leader = proof('worker'), proof('leader')
    negative = {}
    def short(x):
        x['samples'].pop()
        x['timeout_ns'] = x['samples'][-1]['end_ns']
    def few(x):
        x['samples'] = x['samples'][:1]
        x['timeout_ns'] = x['samples'][-1]['end_ns']
    def late_stop(x):
        # A late stop followed by a full interval must still be inconclusive.
        for sample in x['samples'][:6]:
            sample['task']['State'] = 'R (running)'
        for _ in range(6):
            item = copy.deepcopy(x['samples'][-1])
            item['start_ns'] += 100000000
            item['end_ns'] += 100000000
            x['samples'].append(item)
        x['timeout_ns'] = x['samples'][-1]['end_ns']
    for label, mutate in [
        ('running', lambda x: x['samples'][1]['task'].update(State='R (running)')),
        ('wrong_tracer', lambda x: x['samples'][0]['task'].update(TracerPid=202)),
        ('resumed', lambda x: x['samples'][2]['task'].update(voluntary_ctxt_switches=8)),
        ('candidate_dead', lambda x: x['samples'][0].update(tracer_alive=False)),
        ('gate_closed', lambda x: x['samples'][1]['shared'].__setitem__(0, 0)),
        ('wrong_owner', lambda x: x['samples'][2]['leader'].update(PPid=98)),
        ('short_observation', short), ('insufficient_samples', few),
        ('wrong_target', lambda x: x.update(target_tid=999)),
        ('late_stop', late_stop),
        ('sampling_gap', lambda x: x['samples'][3].update(start_ns=x['samples'][2]['end_ns'] + 500000001)),
        ('capture_error', lambda x: x['samples'][2].update(capture_error='unavailable')),
    ]:
        item = copy.deepcopy(positive_worker); mutate(item); negative[label] = item
    record = {'preconditions': pre, 'inputs': {'worker': positive_worker, 'leader': positive_leader, **negative},
              'outcomes': {}, 'complete': False}
    try:
        for label, item in record['inputs'].items():
            result = attributable_stall(item, pre)
            record['outcomes'][label] = result
            if result != (label in ('worker', 'leader')):
                raise ValueError('stall attribution control failed: ' + label)
        def full_record(item):
            which = item['stage']
            events = [('worker-release', 500000000), ('worker-wait', 800000000)]
            if which == 'worker':
                events[1] = ('worker-wait', 1100000000)
            else:
                events += [('leader-release', 900000000), ('fixture-completion', 1100000000)]
            events += [(which + '-stall-observation', item['timeout_ns'] + 1),
                       (which + '-stall-cleanup', item['timeout_ns'] + 2)]
            return {'stall': copy.deepcopy(item), 'monitors': {which: copy.deepcopy(item)}, 'preconditions': pre,
                    'events': [{'stage': name, 'time_ns': ns} for name, ns in events],
                    'worker_release': True, 'leader_release': which == 'leader',
                    'worker_gone_before_leader_release': which == 'leader',
                    'candidate_timeout': True, 'candidate_status_origin': 'cleanup_sigkill',
                    'candidate_status': -signal.SIGKILL,
                    'stall_cleanup': {'tracer_kill_requested': True, 'tracer_status_after_kill': -signal.SIGKILL}}
        full = {'worker_record': full_record(positive_worker), 'leader_record': full_record(positive_leader)}
        bad = copy.deepcopy(full['worker_record']); bad['monitors']['worker']['result'] = 'completed'; full['monitor_mismatch'] = bad
        bad = copy.deepcopy(full['worker_record']); bad['worker_release'] = False; full['missing_release'] = bad
        bad = copy.deepcopy(full['leader_record']); bad['worker_gone_before_leader_release'] = False; full['missing_worker_exit'] = bad
        bad = copy.deepcopy(full['worker_record']); bad['stall_cleanup']['tracer_kill_requested'] = False; full['missing_cleanup'] = bad
        bad = copy.deepcopy(full['worker_record']); bad['events'][-1]['time_ns'] = bad['stall']['samples'][0]['start_ns']; full['cleanup_too_early'] = bad
        record['record_inputs'] = full
        record['record_outcomes'] = {}
        for label, item in full.items():
            result = stall_record_valid(item)
            record['record_outcomes'][label] = result
            if result != (label in ('worker_record', 'leader_record')):
                raise ValueError('stall record control failed: ' + label)
        record['complete'] = True
        wire_checks = control_wire_tests(record)
    except Exception as exc:
        record['complete'] = False
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        try:
            envelope = control_envelope(record)
            if record['complete']:
                envelope['wire_checks'] = wire_checks
            encoded = (json.dumps(envelope, indent=2, sort_keys=True) + '\n').encode('ascii')
            if len(encoded) > CONTROL_DOCUMENT_LIMIT:
                raise ValueError('stall control document size exceeds bound')
            save('stall-controls.json', envelope)
        except Exception as exc:
            save('stall-controls.json', {'schema':'strace-attach-stall-controls-zlib-v1',
                 'complete':False, 'error':'control capture failed: %s: %s' % (type(exc).__name__, exc)})
            raise


def stage(record, name):
    record['stage'] = name
    record.setdefault('events', []).append({'stage': name, 'time_ns': time.monotonic_ns()})
    save('setup-controls.json', record)


def monitor_wait(record, fixture, tracer, which, wait_started_ns):
    """Sample from gate release until completion or a full observed stop interval."""
    pre = record['preconditions']
    required_ns = (4 if which == 'worker' else 5) * 1000000000
    deadline_ns = wait_started_ns + required_ns + 1000000000
    proof = {'stage': which, 'target_tid': pre[which], 'wait_started_ns': wait_started_ns,
             'deadline_ns': deadline_ns, 'samples': []}
    record.setdefault('monitors', {})[which] = proof
    task_path = Path('/proc/%d/task/%d' % (fixture.pid, pre[which]))
    while time.monotonic_ns() < deadline_ns:
        if which == 'worker' and not task_path.exists():
            proof['result'] = 'completed'
            return 'completed'
        if fixture.poll() is not None:
            if which == 'worker':
                raise ValueError('fixture exited before worker completion')
            proof['result'] = 'completed'
            return 'completed'
        sample = {'start_ns': time.monotonic_ns()}
        try:
            sample.update(fixture_alive=fixture.poll() is None, tracer_alive=tracer.poll() is None,
                          shared=shared_read('candidate'), task=task_status(fixture.pid, pre[which]),
                          leader=task_status(fixture.pid, pre['leader']), tracer=task_status(tracer.pid, tracer.pid))
        except (OSError, KeyError, ValueError) as exc:
            sample['capture_error'] = '%s: %s' % (type(exc).__name__, exc)
        sample['end_ns'] = time.monotonic_ns()
        proof['samples'].append(sample)
        proof['timeout_ns'] = sample['end_ns']
        if attributable_stall(proof, pre):
            proof['result'] = 'candidate_stall'
            record['stall'] = proof
            stage(record, which + '-stall-observation')
            return 'candidate_stall'
        time.sleep(.1)
    proof['result'] = 'inconclusive'
    stage(record, which + '-monitor-inconclusive')
    raise ValueError(which + ' timeout has inconclusive attribution')


def clean_stall(record, fixture, tracer, which):
    """Intervene only after recording the candidate-caused stop, then reap owned tasks."""
    action = {'tracer_kill_requested': False, 'fixture_kill_requested': False}
    record['stall_cleanup'] = action
    stage(record, which + '-stall-cleanup')
    if tracer.poll() is not None:
        raise ValueError('candidate exited before confirmed stall cleanup')
    action['tracer_kill_requested'] = True
    stop(tracer, True)
    action['tracer_status_after_kill'] = tracer.returncode
    if tracer.returncode != -signal.SIGKILL:
        raise ValueError('candidate exit raced with stall cleanup')
    try:
        if which == 'worker':
            task = Path('/proc/%d/task/%d' % (fixture.pid, record['preconditions']['worker']))
            deadline = time.monotonic() + 3
            while task.exists() and fixture.poll() is None and time.monotonic() < deadline:
                time.sleep(.01)
            action['worker_gone_after_tracer_kill'] = not task.exists()
            if not task.exists() and fixture.poll() is None:
                release('candidate', 1)
                action['leader_gate_released_after_kill'] = True
        try:
            fixture.wait(timeout=3)
        except subprocess.TimeoutExpired:
            action['recovery_timeout'] = True
    except (OSError, ValueError) as exc:
        action['recovery_error'] = '%s: %s' % (type(exc).__name__, exc)
    if fixture.poll() is None:
        action['fixture_kill_requested'] = True
        stop(fixture)
    action['fixture_status_after_cleanup'] = fixture.returncode
    record.update(candidate_timeout=True, candidate_status=tracer.returncode,
                  candidate_status_origin='cleanup_sigkill', fixture_status=fixture.returncode)
    return action


def shared_init(prefix):
    Path(prefix + '.shared').write_bytes(bytes(16))


def shared_read(prefix):
    return list(struct.unpack('=4i', Path(prefix + '.shared').read_bytes()))


def release(prefix, index):
    fd = os.open(prefix + '.shared', os.O_WRONLY)
    try:
        if os.pwrite(fd, struct.pack('=i', 1), index * 4) != 4:
            raise OSError('short gate write')
    finally:
        os.close(fd)
    if shared_read(prefix)[index] != 1:
        raise ValueError('gate write was not retained')


def wait_ready(prefix, fixture, tracer):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if fixture.poll() is not None:
            raise ValueError('fixture exited before ready: %s' % fixture.returncode)
        if Path(prefix + '.ready').exists():
            raw = Path(prefix + '.ready').read_text()
            if re.fullmatch(r'[0-9]+ [0-9]+\n', raw) and shared_read(prefix)[2:] == [1, 1]:
                leader, worker = map(int, raw.split())
                tids = sorted(int(p.name) for p in Path('/proc/%d/task' % fixture.pid).iterdir() if p.name.isdecimal())
                states = [task_status(fixture.pid, tid) for tid in tids]
                tracer_status = task_status(tracer.pid, tracer.pid)
                if (shared_read(prefix) != [0, 0, 1, 1] or
                        leader != fixture.pid or worker == leader or tids != sorted([leader, worker]) or
                        tracer_status['PPid'] != os.getpid() or
                        any(s['Pid'] != tid or s['Tgid'] != leader or s['PPid'] != os.getpid() or s['TracerPid'] != 0 for tid, s in zip(tids, states))):
                    raise ValueError('fixture identity, parentage or initial tracer state mismatch')
                return {'leader': leader, 'worker': worker, 'tasks': tids, 'task_statuses': states,
                        'tracer_status': tracer_status, 'ready': raw, 'shared_before': shared_read(prefix),
                        'owner_pid': os.getpid(), 'tracer_pid': tracer.pid}
        time.sleep(.01)
    raise ValueError('fixture readiness timeout')


def stop(proc, group=False):
    if proc is not None and proc.poll() is None:
        try:
            if group:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)


def native_control():
    shared_init('native')
    control = fixture = None
    record = {'complete': False, 'stage': 'start'}
    out = err = f_out = f_err = b''
    control_collected = fixture_collected = False
    try:
        control = subprocess.Popen(['./attach-fixture', 'native'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        fixture = subprocess.Popen(['./attach-fixture', 'tracee', str(control.pid), 'native'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        Path('native.pid.tmp').write_text('%d %d\n' % (fixture.pid, os.getpid()))
        Path('native.pid.tmp').replace('native.pid')
        record.update(stage='running', control_pid=control.pid, fixture_pid=fixture.pid)
        out, err = control.communicate(timeout=10)
        control_collected = True
        f_out, f_err = fixture.communicate(timeout=3)
        fixture_collected = True
        record.update(control_status=control.returncode, fixture_status=fixture.returncode)
        if (control.returncode != 0 or fixture.returncode != 0 or out or f_err or
                sorted(f_out.splitlines()) != [b'leader-done', b'worker-done'] or
                not re.search(rb'native ids=\d+,\d+ leader_getpid=[1-9]\d* worker_getppid=[1-9]\d* exits=2', err)):
            raise ValueError('native sibling attach control failed')
        record.update(complete=True, stage='complete')
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        stop(control, True)
        stop(fixture)
        if control is not None:
            if not control_collected:
                out, err = control.communicate()
            record['control_status'] = control.returncode
        if fixture is not None:
            if not fixture_collected:
                f_out, f_err = fixture.communicate()
            record['fixture_status'] = fixture.returncode
        for name, data in [('control_stdout', out), ('control_stderr', err),
                           ('fixture_stdout', f_out), ('fixture_stderr', f_err)]:
            record[name + '_base64'] = base64.b64encode(data).decode()
        save('native-control.json', record)


def candidate_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def observe(record):
    shared_init('candidate')
    tracer = fixture = None
    record.update(complete=False, error=None, outcome=None)
    stage(record, 'candidate-launch')
    try:
        with (HOME / 'candidate.out').open('wb') as out, (HOME / 'candidate.err').open('wb') as err, \
             (HOME / 'fixture.out').open('wb') as f_out, (HOME / 'fixture.err').open('wb') as f_err:
            candidate_env = dict(os.environ, PATH='/empty')
            tracer = subprocess.Popen(['/opt/bashos-parity/candidate', '--noprofile', '--norc', '-c',
                                       'IFS= read -r p || exit 97; strace -p "$p"'],
                                      stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True,
                                      env=candidate_env, preexec_fn=candidate_limit)
            fixture = subprocess.Popen(['./attach-fixture', 'tracee', str(tracer.pid), 'candidate'],
                                       stdout=f_out, stderr=f_err)
            record.update(tracer_pid=tracer.pid, fixture_pid=fixture.pid)
            stage(record, 'candidate-readiness')
            pre = wait_ready('candidate', fixture, tracer)
            record['preconditions'] = pre
            if tracer.poll() is not None:
                raise ValueError('candidate shell exited before invocation')
            tracer.stdin.write(('%d\n' % fixture.pid).encode())
            tracer.stdin.close()
            record['invoked'] = True
            stage(record, 'attach-monitor')
            samples = []
            record['tracer_samples'] = samples
            record['stable_both_attached'] = False
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                states = [task_status(fixture.pid, tid) for tid in pre['tasks']]
                sample = [s['TracerPid'] for s in states]
                if any(value not in (0, tracer.pid) for value in sample):
                    raise ValueError('unexpected tracer on fixture task')
                samples.append(sample)
                if sample == [tracer.pid, tracer.pid]:
                    reverse = [task_status(fixture.pid, tid)['TracerPid'] for tid in reversed(pre['tasks'])]
                    reverse.reverse()
                    if any(value not in (0, tracer.pid) for value in reverse):
                        raise ValueError('unexpected tracer on fixture task')
                    samples.append(reverse)
                    if reverse == [tracer.pid, tracer.pid]:
                        record['stable_both_attached'] = True
                        break
                if tracer.poll() is not None:
                    break
                time.sleep(.01)
            stage(record, 'worker-release')
            release('candidate', 0)
            record['worker_release'] = True
            worker_started = time.monotonic_ns()
            stage(record, 'worker-wait')
            if monitor_wait(record, fixture, tracer, 'worker', worker_started) == 'candidate_stall':
                clean_stall(record, fixture, tracer, 'worker')
                record['outcome'] = 'candidate_stall'
            else:
                record['worker_gone_before_leader_release'] = True
                stage(record, 'leader-release')
                release('candidate', 1)
                record['leader_release'] = True
                leader_started = time.monotonic_ns()
                stage(record, 'fixture-completion')
                if monitor_wait(record, fixture, tracer, 'leader', leader_started) == 'candidate_stall':
                    clean_stall(record, fixture, tracer, 'leader')
                    record['outcome'] = 'candidate_stall'
                if record['outcome'] != 'candidate_stall':
                    record['fixture_status'] = fixture.returncode
                    if fixture.returncode != 0:
                        raise ValueError('fixture did not exit naturally with zero status')
                    try:
                        tracer.wait(timeout=3)
                        record['candidate_timeout'] = False
                    except subprocess.TimeoutExpired:
                        record['candidate_timeout'] = True
                        stop(tracer, True)
                    record['candidate_status'] = tracer.returncode
                    record['candidate_status_origin'] = 'cleanup_sigkill' if record['candidate_timeout'] else 'natural'
                    record['outcome'] = 'completed'
        if record['outcome'] == 'completed' and ((HOME / 'fixture.err').read_bytes() or
                sorted((HOME / 'fixture.out').read_bytes().splitlines()) != [b'leader-done', b'worker-done']):
            raise ValueError('fixture output incomplete or erroneous')
        if any((HOME / name).stat().st_size >= LIMIT for name in ('candidate.out', 'candidate.err')):
            raise ValueError('candidate output hit capture size limit; observation incomplete')
        record['complete'] = True
        stage(record, 'complete')
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        raise
    finally:
        stop(tracer, True)
        stop(fixture)
        if tracer is not None:
            record['candidate_status'] = tracer.returncode
        if fixture is not None:
            record['fixture_status'] = fixture.returncode
        save('setup-controls.json', record)


def setup():
    record = {'stage': 'parser-controls', 'complete': False, 'invoked': False, 'error': None}
    save('setup-controls.json', record)
    try:
        parser_controls()
        record['stage'] = 'stall-controls'; save('setup-controls.json', record)
        stall_controls()
        record['stage'] = 'compile'; save('setup-controls.json', record)
        with (HOME / 'gcc.out').open('wb') as out, (HOME / 'gcc.err').open('wb') as err:
            subprocess.run(['/usr/bin/gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-pthread',
                            '-o', 'attach-fixture', '/opt/bashos-parity/harness/helpers/strace-attach-reviewed.c'],
                           stdout=out, stderr=err, check=True, timeout=15)
        record['stage'] = 'native-control'; save('setup-controls.json', record)
        native_control()
        observe(record)
    except Exception as exc:
        record['error'] = '%s: %s' % (type(exc).__name__, exc)
        save('setup-controls.json', record)
        raise


def verify(requirement):
    checks = {}
    failures = []
    classification = 'candidate_mismatch'
    try:
        record = json.loads((HOME / 'setup-controls.json').read_text())
        native = json.loads((HOME / 'native-control.json').read_text())
        control_bytes = (HOME / 'stall-controls.json').read_bytes()
        if len(control_bytes) > CONTROL_DOCUMENT_LIMIT: raise ValueError('stall control document exceeds bound')
        envelope = json.loads(control_bytes, object_pairs_hook=unique_json_object)
        controls = decode_control_envelope(envelope)
        if (not isinstance(envelope.get('wire_checks'), dict) or
                set(envelope['wire_checks']) != CONTROL_WIRE_TESTS or
                any(value is not True for value in envelope['wire_checks'].values())):
            raise ValueError('stall control wire checks incomplete')
        if not record['complete'] or record['error'] or not record['invoked'] or not native['complete'] or not controls['complete']:
            raise ValueError('incomplete infrastructure controls')
        pre = record['preconditions']
        trace_bytes = (HOME / 'candidate.err').read_bytes()
        candidate_out = (HOME / 'candidate.out').read_bytes()
        (HOME / 'fixture.out').read_bytes()
        (HOME / 'fixture.err').read_bytes()
        if record['outcome'] == 'candidate_stall':
            if not stall_record_valid(record):
                raise ValueError('stall attribution or cleanup record incomplete')
            checks = {'stall_attribution': True, 'candidate_did_not_stall': False}
            failures.append('candidate_stall_' + record['stall']['stage'])
        elif record['outcome'] == 'completed':
            try:
                trace = trace_bytes.decode('utf-8', 'strict')
                parsed = parse_trace(trace, pre['leader'], pre['worker'], pre['owner_pid'], requirement == 'r2')
            except (ValueError, UnicodeError) as exc:
                failures.append('candidate_trace_rejected: ' + str(exc))
                parsed = {'leader_call': False, 'leader_exit': False, 'worker_call': False, 'worker_exit': False}
            leader_index = pre['tasks'].index(pre['leader'])
            checks = {'leader_call': parsed['leader_call'], 'leader_exit': parsed['leader_exit'],
                      'leader_attached': any(sample[leader_index] == pre['tracer_pid'] for sample in record['tracer_samples']),
                      'candidate_status': record['candidate_status'] == 0 and not record['candidate_timeout'],
                      'candidate_stdout': candidate_out == b''}
            if requirement == 'r2':
                checks.update(worker_call=parsed['worker_call'], worker_exit=parsed['worker_exit'],
                              both_attached=record['stable_both_attached'])
            failures.extend(name for name, passed in checks.items() if not passed)
        else:
            raise ValueError('unknown candidate observation outcome')
    except (OSError, KeyError, TypeError, ValueError, UnicodeError, zlib.error) as exc:
        classification = 'infrastructure_error'
        failures.append('assessment_infrastructure_error: ' + str(exc))
    if not failures:
        classification = 'candidate_match'
    save('assertions.json', {'requirement': requirement, 'classification': classification, 'checks': checks, 'failures': failures})
    if failures:
        print('attach assertion failures: ' + ', '.join(failures))
        return 1
    print(requirement + '-ok')
    return 0


def main():
    guard()
    if sys.argv[1:] == ['setup']:
        setup(); return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'verify' and sys.argv[2] in ('r1', 'r2'):
        return verify(sys.argv[2])
    raise ValueError('expected setup or verify r1/r2')


if __name__ == '__main__':
    raise SystemExit(main())
