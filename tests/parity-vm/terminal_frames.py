# SPDX-License-Identifier: MIT
"""Compare observed redraws with the fixture's independently logged FIFO reads."""
import base64
import json
import re


def check_timing(case, result):
    spec = case['frame_timing']
    diagnostic = result.get('diagnostics', {}).get(spec['diagnostic'], {})
    if diagnostic.get('truncated') or not diagnostic.get('base64'):
        raise ValueError('frame source log is absent or truncated')
    source = json.loads(base64.b64decode(diagnostic['base64'], validate=True))
    records = source.get('records', [])
    if source.get('schema') != 'top-fifo-frame-v1' or source.get('state') != 'completed' or len(records) != 4:
        raise ValueError('four completed independent FIFO reads are required')
    previous = 0
    for index, record in enumerate(records, 1):
        if (record.get('index') != index or
                record.get('value') != f'0.{index:02d} 0.50 1.00 1/30 130' or
                type(record.get('write_ns')) is not int or type(record.get('reader_close_ns')) is not int or
                not previous < record['write_ns'] <= record['reader_close_ns']):
            raise ValueError('independent FIFO source sequence is invalid')
        previous = record['reader_close_ns']
    pattern = re.compile(spec['pattern'])
    frames = []
    for frame in result.get('screen_frames', []):
        match = pattern.search(frame['row'])
        if match and (not frames or frames[-1]['value'] != match.group(1)):
            frames.append({'value': match.group(1), 'monotonic_ns': frame['monotonic_ns'],
                           'output_offset': frame['output_offset']})
    expected = [record['value'].split()[0] for record in records[1:]]
    values = [frame['value'] for frame in frames]
    intervals = [(b['monotonic_ns'] - a['monotonic_ns']) / 1_000_000
                 for a, b in zip(frames, frames[1:])]
    matched = values == expected
    if matched:
        matched = all(record['write_ns'] <= frame['monotonic_ns'] <= record['reader_close_ns'] + 1_000_000_000
                      for record, frame in zip(records[1:], frames))
        matched = matched and all(abs(interval - spec['period_ms']) <= spec['tolerance_ms'] for interval in intervals)
    return {'matched': matched, 'source_values': expected, 'observed_frames': frames,
            'intervals_ms': intervals}
