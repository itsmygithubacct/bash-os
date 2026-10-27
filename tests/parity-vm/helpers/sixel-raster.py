#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the RGB Sixel subset used by the image fixtures, without rendering.

Independent protocol reference: DEC VT330/VT340 Graphics Programming, chapter 14
https://vt100.net/docs/vt3xx-gp/chapter14.html

This is a bounded pixel oracle, not a terminal emulator. It checks the declared
raster, RGB register definitions, six-bit columns, repeats and overprinting.
Unknown controls, undefined colors and drawn pixels outside the expected raster
are rejected. The fixtures use opaque solid colors, so omitted pixels cannot be
mistaken for a correct background.
"""
import re


def decode(data):
    start = re.match(rb'\x1bP[0-9;]*q', data)
    if not start or not data.endswith(b'\x1b\\'):
        raise ValueError('missing Sixel DCS or terminator')
    body = data[start.end():-2]
    attrs = re.match(rb'"([0-9]+);([0-9]+);([0-9]+);([0-9]+)', body)
    if not attrs:
        raise ValueError('missing raster attributes')
    pan, pad, width, height = map(int, attrs.groups())
    if (pan, pad) != (1, 1) or not (0 < width <= 2048 and 0 < height <= 2048):
        raise ValueError('unsupported or oversized raster')
    pixels = [None] * (width * height)
    colors = {}
    current = None
    x = y = 0
    index = attrs.end()

    def paint(character, count):
        nonlocal x
        if not 63 <= character <= 126 or not 0 < count <= 2048:
            raise ValueError('invalid sixel or repeat')
        if x + count > width or current not in colors:
            raise ValueError('column overflow or undefined color')
        bits = character - 63
        for bit in range(6):
            if bits & (1 << bit):
                row = y + bit
                if row >= height:
                    raise ValueError('drawn pixel exceeds raster height')
                offset = row * width + x
                pixels[offset:offset + count] = [colors[current]] * count
        x += count

    while index < len(body):
        character = body[index]
        if character == ord('#'):
            match = re.match(rb'#([0-9]+)(?:;([0-9]+);([0-9]+);([0-9]+);([0-9]+))?', body[index:])
            if not match:
                raise ValueError('invalid color selection')
            current = int(match[1])
            if not 0 <= current <= 255:
                raise ValueError('color register out of range')
            if match[2] is not None:
                space, red, green, blue = map(int, match.groups()[1:])
                if space != 2 or not all(0 <= value <= 100 for value in (red, green, blue)):
                    raise ValueError('fixture decoder requires RGB percentage colors')
                colors[current] = (red, green, blue)
            index += match.end()
        elif character == ord('!'):
            match = re.match(rb'!([0-9]+)([?-~])', body[index:])
            if not match:
                raise ValueError('invalid repeat sequence')
            paint(match[2][0], int(match[1]))
            index += match.end()
        elif character == ord('$'):
            x = 0
            index += 1
        elif character == ord('-'):
            x = 0
            y += 6
            index += 1
        elif character in (10, 13):
            index += 1
        elif 63 <= character <= 126:
            paint(character, 1)
            index += 1
        else:
            raise ValueError('unsupported control at byte %d' % index)
    return width, height, pixels


def require_uniform(data, width, height, color):
    actual_width, actual_height, pixels = decode(data)
    if (actual_width, actual_height) != (width, height):
        raise AssertionError('raster dimensions differ')
    if pixels != [color] * (width * height):
        raise AssertionError('decoded pixel raster differs')


def selfcheck():
    red, blue = (100, 0, 0), (0, 0, 100)
    prefix = b'\x1bPq"1;1;2;6#1;2;100;0;0'
    end = b'\x1b\\'
    # Handwritten DEC vectors: two repeated columns, distinct color columns,
    # overprinting after carriage return, and a one-pixel final sixel band.
    require_uniform(prefix + b'!2~' + end, 2, 6, red)
    assert decode(prefix + b'~#2;2;0;0;100~' + end)[2] == [red, blue] * 6
    assert decode(prefix + b'!2~$#2;2;0;0;100~' + end)[2] == [blue, red] * 6
    require_uniform(b'\x1bPq"1;1;2;7#1;2;100;0;0!2~-!2@' + end, 2, 7, red)
    for invalid in (prefix + b'~' + end, prefix + b'!3~' + end,
                    prefix + b'!2~', prefix + b'#2!2~' + end):
        try:
            require_uniform(invalid, 2, 6, red)
        except (ValueError, AssertionError):
            pass
        else:
            raise AssertionError('invalid raster accepted')


if __name__ == '__main__':
    selfcheck()
