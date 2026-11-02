# SPDX-License-Identifier: MIT
"""Bounded captured-byte replay of primary characters, reverse bits and cursor."""
import hashlib
import json


def render(data, points):
    grid = [[(' ', False) for _ in range(80)] for _ in range(24)]
    saved = None
    rev = False
    y = x = 0
    i = 0
    result = {}
    while i < len(data):
        if i in points:
            result[i] = {'grid': [r[:] for r in grid], 'cursor': [y, x], 'reverse': rev}
        byte = data[i]
        if byte == 27:
            assert i + 2 < len(data) and data[i + 1] == 91
            end = i + 2
            while end < len(data) and (not 64 <= data[end] <= 126):
                end += 1
            assert end < len(data)
            params = data[i + 2:end].decode('ascii')
            op = chr(data[end])
            i = end + 1
            if op == 'm':
                nums = [int(q or '0') for q in params.split(';')] if params else [0]
                k = 0
                while k < len(nums):
                    n = nums[k]
                    if n == 0:
                        rev = False
                    elif n == 7:
                        rev = True
                    elif n == 27:
                        rev = False
                    elif n in (38, 48):
                        assert k + 1 < len(nums)
                        if nums[k + 1] == 5:
                            assert k + 2 < len(nums)
                            k += 2
                        elif nums[k + 1] == 2:
                            assert k + 4 < len(nums)
                            k += 4
                        else:
                            raise AssertionError('unsupported extended color')
                    k += 1
            elif op == 'H':
                q = params.split(';') if params else []
                assert len(q) <= 2 and all((z.isdigit() or z == '' for z in q))
                y = max(0, min(23, (int(q[0] or '1') if q else 1) - 1))
                x = max(0, min(79, (int(q[1] or '1') if len(q) > 1 else 1) - 1))
            elif op == 'J':
                assert params == '2'
                grid = [[(' ', False) for _ in range(80)] for _ in range(24)]
            elif op == 'K':
                assert params in ('', '0', '2')
                if params == '2':
                    grid[y] = [(' ', False) for _ in range(80)]
                else:
                    grid[y][x:] = [(' ', False) for _ in range(80 - x)]
            elif op in ('h', 'l'):
                assert params in ('?1049', '?25')
                if params == '?1049' and op == 'h':
                    assert saved is None
                    saved = ([r[:] for r in grid], y, x, rev)
                    grid = [[(' ', False) for _ in range(80)] for _ in range(24)]
                    y = x = 0
                    rev = False
                elif params == '?1049' and op == 'l':
                    assert saved is not None
                    grid, y, x, rev = saved
                    saved = None
            else:
                raise AssertionError(('unsupported CSI', params, op))
        elif byte == 13:
            x = 0
            i += 1
        elif byte == 10:
            y = min(23, y + 1)
            i += 1
        elif 32 <= byte <= 126:
            if x >= 80:
                x = 0
                y = min(23, y + 1)
            grid[y][x] = (chr(byte), rev)
            x += 1
            i += 1
        else:
            raise AssertionError(('unsupported byte', i, byte))
    if i in points:
        result[i] = {'grid': [r[:] for r in grid], 'cursor': [y, x], 'reverse': rev}
    assert set(result) == set(points)
    return result


def restoration(raw):
    if len(raw) > 2 * 1024**2:
        raise ValueError('restoration capture exceeds its bound')
    entry, leave = b'\x1b[?1049h', b'\x1b[?1049l'
    if raw.count(entry) != 1 or raw.count(leave) != 1 or raw.index(leave) < raw.index(entry):
        return {'matched': False, 'reason': 'one alternate-screen entry and exit are required'}
    before_offset = raw.index(entry)
    try:
        states = render(raw, {before_offset, len(raw)})
    except (AssertionError, IndexError, UnicodeError) as error:
        raise ValueError('unsupported restoration replay: ' + str(error)) from error
    before, after = states[before_offset], states[len(raw)]
    def digest(state):
        return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'matched': before == after, 'before_offset': before_offset, 'after_offset': len(raw),
            'before_sha256': digest(before), 'after_sha256': digest(after),
            'before_cursor': before['cursor'], 'after_cursor': after['cursor'],
            'compared': ['characters', 'reverse', 'cursor']}
