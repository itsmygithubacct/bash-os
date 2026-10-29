"""Pinned data-only terminal evidence validators; never execute subjects."""
import base64, hashlib, json, os, re, tarfile
CONTROLS = frozenset()

def require(c, condition, detail):
    if not condition:
        raise c.IncompleteEvidence(detail)

def validate_pty_trace(c, raw, case, status, side):
    """Check an exact successful trace or a failure's recorded action prefix."""
    require(c, raw.get('decoder_error') is None, 'PTY decoder failed; preserve raw behavior as incomplete')
    try:
        stream = base64.b64decode(raw['screen_base64'], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise c.IncompleteEvidence('invalid terminal screen bytes') from error
    chunks, writes, events = (raw.get('terminal181_output_chunks'), raw.get('terminal181_input_writes'), raw.get('events'))
    require(c, isinstance(chunks, list) and len(chunks) <= 8192 and isinstance(writes, list) and (len(writes) <= 4096) and isinstance(events, list), 'terminal witness lists are missing or capped')
    require(c, len(stream) < 2 * 1024 ** 2 and raw.get('terminal181_leader_birth') is not None, 'terminal capture or owned leader is incomplete')
    end = 0
    last_time = -1
    boundaries = {0}
    for item in chunks:
        require(c, isinstance(item, dict) and type(item.get('start')) is int and (type(item.get('end')) is int) and (type(item.get('monotonic_ns')) is int) and (item['start'] == end) and (end < item['end'] <= len(stream)) and (item['monotonic_ns'] >= last_time), 'terminal output chunk bounds or order differ')
        end, last_time = (item['end'], item['monotonic_ns'])
        boundaries.add(end)
    require(c, end == len(stream), 'terminal chunks do not cover captured output')
    for item in writes:
        require(c, isinstance(item, dict) and type(item.get('monotonic_ns')) is int and (type(item.get('output_offset')) is int) and (0 <= item['output_offset'] <= len(stream)) and isinstance(item.get('hex'), str), 'terminal input write is malformed')
        try:
            bytes.fromhex(item['hex'])
        except ValueError as error:
            raise c.IncompleteEvidence('invalid input hex') from error
    require(c, all((a['monotonic_ns'] <= b['monotonic_ns'] for a, b in zip(writes, writes[1:]))), 'terminal input-write times are not ordered')
    keys = {'down': (b'\x1b[B', b'\x1bOB'), 'right': (b'\x1b[C', b'\x1bOC'), 'backspace': (b'\x7f', b'\x7f'), 'enter': (b'\r', b'\r'), 'escape': (b'\x1b', b'\x1b')}
    cursor_mode = re.compile(b'\\x1b\\[\\?([0-9;]*)([hl])')
    completed, pending, last_time, last_offset, used = (0, None, -1, 0, set())
    expect_cursor = 0
    for event in events:
        require(c, isinstance(event, dict), 'terminal event is not an object')
        step, action, at, offset = (event.get('step'), event.get('action'), event.get('monotonic_ns'), event.get('offset'))
        require(c, type(step) is int and step == completed and (step < len(case['steps'])) and isinstance(action, str) and (type(at) is int) and (at >= last_time) and (type(offset) is int) and (last_offset <= offset <= len(stream)) and (offset in boundaries), 'terminal event order, time or offset differs')
        last_time, last_offset = (at, offset)
        expected_action, value = next(iter(case['steps'][step].items()))
        if action.endswith('-begin'):
            require(c, pending is None and action == expected_action + '-begin' and (expected_action in ('send', 'send_base64', 'key')), 'unexpected input begin')
            if expected_action == 'send':
                expected = value.encode()
            elif expected_action == 'send_base64':
                expected = base64.b64decode(value, validate=True)
            else:
                require(c, value in keys, 'unreviewed terminal key')
                mode = False
                for match in cursor_mode.finditer(stream[:offset]):
                    if b'1' in match.group(1).split(b';'):
                        mode = match.group(2) == b'h'
                expected = keys[value][mode]
            require(c, event.get('requested_hex') == expected.hex(), 'requested bytes differ from frozen step')
            pending = event
            continue
        require(c, action == expected_action, 'completed event differs from frozen step')
        if action in ('send', 'send_base64', 'key'):
            require(c, pending is not None and isinstance(event.get('bytes_hex'), str), 'input completion is missing')
            first, past = (pending.get('input_write_index'), event.get('input_write_past_index'))
            scrub_ids = {'migration-scrub-explicit-seeded-r3', 'migration-scrub-prompt-boundary-seeded-r3', 'migration-scrub-live-restore-independent-r1'}
            if case['id'] in scrub_ids and 'input_write_index' not in pending and ('input_write_past_index' not in event):
                first = len(used)
                past = first
                while past < len(writes) and writes[past]['monotonic_ns'] < at:
                    require(c, pending['monotonic_ns'] < writes[past]['monotonic_ns'], 'unassociated or ambiguous scrub input write')
                    past += 1
            require(c, type(first) is int and type(past) is int and (first == len(used)) and (first < past <= len(writes)), 'input-write index range is missing or inconsistent')
            matched = [(n, writes[n]) for n in range(first, past)]
            require(c, all((pending['monotonic_ns'] <= w['monotonic_ns'] <= at for _, w in matched)), 'input write times fall outside its recorded step')
            used.update((n for n, _ in matched))
            actual = ''.join((w['hex'] for _, w in matched))
            require(c, actual == pending['requested_hex'] == event['bytes_hex'] and event.get('bytes') == len(bytes.fromhex(actual)), 'input bytes or delivery record differs')
            pending = None
        else:
            require(c, pending is None, 'a prior input did not complete')
            if action == 'expect':
                try:
                    match = re.compile(value.encode()).search(stream, expect_cursor, offset)
                except (re.error, AttributeError, TypeError) as exc:
                    raise c.IncompleteEvidence('invalid expected pattern') from exc
                require(c, match is not None and type(event.get('matched_end')) is int and (match.end() == event['matched_end']), 'expected prompt does not match captured output')
                expect_cursor = match.end()
            elif action == 'screen':
                raise c.IncompleteEvidence('screen assertions are not supported by this reader')
            elif action == 'termios':
                observed = event.get('termios_observed')
                require(c, isinstance(observed, dict) and observed.get('problem') is None and isinstance(observed.get('modes'), dict) and isinstance(observed['modes'].get('flags'), list) and (type(observed.get('monotonic_ns')) is int) and (observed['monotonic_ns'] <= at), 'termios observation missing or inconsistent')
                flags = set(observed['modes']['flags'])
                require(c, all((x in flags for x in value.get('set', []))) and all((x not in flags for x in value.get('clear', []))), 'termios flags do not match selected assertion')
        completed += 1
    require(c, pending is None and len(used) == len(writes), 'partial or unassociated terminal input')
    error = raw.get('error')
    expected_status = case.get('expected_status', 0)
    if not error:
        require(c, completed == len(case['steps']), 'apparently completed terminal run omits steps')
    if status == 'PASS' or side == 'reference':
        require(c, error is None and raw.get('status') == expected_status and (completed == len(case['steps'])) and (not case.get('restore_terminal', True) or raw.get('terminal_restored') is True), 'passing terminal side lacks full observations')
    first_product_step = 2 if case['id'].startswith('migration-terminal213-ncdu-visible-restore-') else 0
    if side == 'candidate' and status == 'FAIL' and (completed <= first_product_step) and (case['id'] not in CONTROLS):
        raise c.IncompleteEvidence('no completed product observation; fixture-only prefix and raw failure retained')
    if isinstance(error, str) and 'wall-clock limit' in error:
        match = re.match('PTY wall-clock limit waiting for step ([0-9]+) (screen|expect|termios)(?=[: ]|$)', error)
        require(c, side == 'candidate' and status == 'FAIL' and (match is not None) and (int(match.group(1)) == completed) and (completed < len(case['steps'])) and (next(iter(case['steps'][completed])) == match.group(2)), 'terminal deadline is not a recorded reached assertion')
        if match.group(2) == 'termios':
            samples = raw.get('termios_observations')
            require(c, isinstance(samples, list) and any((x.get('step') == completed and x.get('outcome') == 'not-matched' and isinstance(x.get('problem'), str) and isinstance(x.get('modes'), dict) for x in samples if isinstance(x, dict))), 'failed termios observation not retained')
    return {'completed_steps': list(range(completed)), 'unreached_steps': list(range(completed, len(case['steps']))), 'raw_error': error, 'raw_status': raw.get('status'), 'framework_status': status, 'terminal_restored': raw.get('terminal_restored'), 'screen_bytes': len(stream), 'input_write_count': len(writes), 'exact_input_read_syscall_required': False}

def validate_owned_pty_control(c, archive):
    """Independently inspect recorded guest controls; missing is incomplete."""
    name = 'results/selfcheck/owned-pty-observer.json'
    member = archive.getmember(name)
    require(c, member.isfile() and 0 < member.size < 2 * 1024 ** 2, 'owned PTY control record missing')
    record = c.optional.parse_json(archive.extractfile(member).read(member.size + 1), 2 * 1024 ** 2)
    require(c, record.get('id') == 'selfcheck-owned-pty-observer' and record.get('status') == 'PASS', 'owned PTY qualification failed')
    detail = record.get('detail', {})
    for part in ('positive', 'negative', 'orphan'):
        raw = detail.get(part)
        path = 'results/selfcheck/owned-pty-' + part + '-raw.json'
        m = archive.getmember(path)
        require(c, m.isfile() and 0 < m.size < 2 * 1024 ** 2 and (c.optional.parse_json(archive.extractfile(m).read(m.size + 1), 2 * 1024 ** 2) == raw), 'owned PTY control raw mismatch: ' + part)
    pos = detail['positive']
    neg = detail['negative']
    orphan = detail['orphan']
    positive_case = {'id': 'migration-terminal213-control-owned-positive', 'restore_terminal': True, 'steps': [{'expect': 'CONTROL-ECHO-ON'}, {'termios': {'set': ['ECHO', 'ICANON']}}, {'send': '\n'}, {'expect': 'CONTROL-ECHO-OFF'}, {'termios': {'clear': ['ECHO', 'ICANON', 'ICRNL']}}, {'send_base64': 'cQ0='}, {'expect': 'CONTROL-DONE'}]}
    negative_case = {'id': 'migration-terminal213-control-owned-negative', 'restore_terminal': True, 'steps': [{'expect': 'CONTROL-NEGATIVE-READY'}, {'termios': {'clear': ['ECHO']}}]}
    validate_pty_trace(c, pos, positive_case, 'PASS', 'candidate')
    validate_pty_trace(c, neg, negative_case, 'FAIL', 'candidate')
    require(c, not pos.get('stray_processes') and (not pos.get('harness_error')) and (not neg.get('harness_error')) and any((x.get('problem') == 'ECHO is set' and x.get('outcome') == 'not-matched' for x in neg.get('termios_observations', []))), 'terminal observer controls differ')
    require(c, bool(orphan.get('error')) and (not orphan.get('harness_error')) and bool(orphan.get('stray_processes')) and all((not x.get('cleanup_error') for x in orphan['stray_processes'])), 'owned descendant cleanup control differs')
    return {'status': 'PASS', 'positive_actions': len(pos.get('events', [])), 'negative_error': neg.get('error'), 'owned_children': orphan['stray_processes']}

def validate_terminal_observations(c, archive_path, summary, cases, expected_sha, batch):
    """Read previously validated archive records; do not execute or extract them."""
    records = summary['cases']
    by_id = {row['id']: row for row in records}
    selected = [row['id'] for row in records if row['id'] in {case['id'] for case in cases}]
    require(c, selected == batch['selected_case_ids'], 'completed case order differs from fixed control-first batch')
    for cid in batch['control_case_ids']:
        require(c, by_id[cid].get('status') == 'PASS' and by_id[cid].get('covers') == [], 'a required independent control did not pass')
    if type(archive_path) is int:
        stream = os.fdopen(os.dup(archive_path), 'rb')
        stream.seek(0)
        size = os.fstat(stream.fileno()).st_size
        require(c, 0 < size < 512 * 1024 ** 2, 'owned archive size invalid')
    else:
        stream, size = c.optional.open_single(archive_path, 512 * 1024 ** 2)
    result = {}
    with stream:
        before = os.fstat(stream.fileno())
        require(c, c.optional.stream_sha(stream) == expected_sha, 'evidence changed before terminal review')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            qualification = validate_owned_pty_control(c, archive)
            for case in cases:
                cid = case['id']
                status = by_id[cid]['status']
                sides = ('candidate', 'reference') if case.get('kind', 'parity') == 'parity' else ('candidate',)
                result[cid] = {'framework_status': status, 'covers': case.get('covers', []), 'sides': {}}
                for side in sides:
                    name = 'results/' + cid + '/' + side + '.json'
                    member = archive.getmember(name)
                    require(c, member.isfile() and 0 <= member.size < 64 * 1024 ** 2, 'terminal raw result is not bounded')
                    blob = archive.extractfile(member).read(member.size + 1)
                    require(c, len(blob) == member.size, 'terminal raw result is truncated')
                    raw = c.optional.parse_json(blob, 64 * 1024 ** 2)
                    require(c, isinstance(raw, dict) and (not raw.get('harness_error')), 'terminal side is incomplete')
                    if 'setup_script' in case:
                        require(c, isinstance(raw.get('setup'), dict) and raw['setup'].get('status') == 0 and (raw['setup'].get('error') is None), 'terminal setup or side is incomplete')
                    else:
                        require(c, 'setup' not in raw, 'unexpected terminal setup record')
                    if case['driver'] == 'pty':
                        observation = validate_pty_trace(c, raw, case, status, side)
                        if cid == 'migration-terminal213-top-three-redraws':
                            observation['writer_control'] = validate_redraw_writer(c, raw, status, observation)
                    else:
                        observation = {'raw_status': raw.get('status'), 'raw_error': raw.get('error'), 'framework_status': status, 'tree_entries': len(raw.get('tree', {}))}
                        if status == 'PASS' or side == 'reference':
                            require(c, raw.get('error') is None and raw.get('status') == case.get('expected_status', 0), 'passing plain side differs from expected status')
                            for name, value in case.get('expected_files', {}).items():
                                item = raw['tree'].get(name, {})
                                expected = value['base64'] if isinstance(value, dict) else base64.b64encode(value.encode()).decode()
                                require(c, item.get('kind') == 'file' and item.get('base64') == expected, 'passing side expected file differs')
                    result[cid]['sides'][side] = observation
        stream.seek(0)
        digest = c.optional.stream_sha(stream)
        after = os.fstat(stream.fileno())
        require(c, digest == expected_sha and size == before.st_size and ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink)), 'terminal evidence changed during inspection')
    return {'selected_order': selected, 'controls': batch['control_case_ids'], 'owned_pty_qualification': qualification, 'cases': result, 'meaning': 'bounded raw evidence and action reachability; primary still adjudicates product behavior and coverage'}
