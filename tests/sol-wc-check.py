#!/usr/bin/env python3
"""wc -m/-w/-L independent fixture oracles, redirections and failure contracts.

The host's pre-9.5 wc is not an oracle for invalid/nonprinting word bytes.
Unicode classifications below cover this suite's explicit characters only.
"""
import argparse
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unicodedata


def counts(data, loc, posix=False):
    # glibc's C.UTF-8 mbrtowc accepts U+110000 as one nonprinting wchar_t.
    # Python rejects it. Map this explicit fixture token to a noncharacter
    # with the same count/word/width properties before using Python's decoder.
    decoded_data = data if loc == 'C' else data.replace(b'\xf4\x90\x80\x80', b'\xf4\x8f\xbf\xbf')
    chars = decoded_data.decode('latin1' if loc == 'C' else 'utf8', errors='surrogateescape')
    spaces = set(' \t\n\r\v\f')
    if loc != 'C':
        spaces.update('\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2008\u2009\u200a\u2028\u2029\u205f\u3000')
    if not posix:
        spaces.update('\xa0' if loc == 'C' else '\xa0\u2007\u202f\u2060')
    words = 0
    inword = False
    width = maximum = 0
    for ch in chars:
        if ch in spaces:
            inword = False
        elif not inword:
            words += 1
            inword = True
        if ch in '\n\r\f':
            maximum = max(maximum, width)
            width = 0
        elif ch == '\t':
            width += 8 - width % 8
        elif loc == 'C':
            width += 32 <= ord(ch) < 127
        elif unicodedata.category(ch) not in ('Cc', 'Cs', 'Cf', 'Mn', 'Cn'):
            width += 2 if ch == '界' or ch == '\u3000' or ch == '😀' else 1
    return dict(l=data.count(b'\n'), w=words, m=sum(not 0xdc80 <= ord(c) <= 0xdcff for c in chars),
                c=len(data), L=max(maximum, width))


def selected(c, opt):
    return [c[k] for k in 'lwmcL' if k in (opt[1:] if opt else 'lwc')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=lambda p: str(Path(p).resolve()))
    args = parser.parse_args()
    checks = 0
    with tempfile.TemporaryDirectory(prefix='sol-wc-check-') as directory:
        root = Path(directory)
        fixtures = {'empty': b'', 'abcd': b'', 'ascii': b'one two\n\tthree\rwide\fend\vZ\0\x7f',
                    'unicode': 'café 界 e\u0301 😀\tX\n界\rabc\fxy'.encode(),
                    'spaces': ('a'+''.join(s+'b' for s in '\xa0\u1680\u2000\u2007\u202f\u2060\u3000\u0085\u200b\ufeff')+'\n').encode(),
                    'binary': bytes(range(256))*7,
                    'bad': b'\xff a\0b \x80\n\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80\xe2(\xa1\xc2\n',
                    'bad-eof': b'a\xe2\x82', 'binary-long': b'\xff a\0b \x80\n'*50000}
        for seq in [b'\xc2\xa0', b'\xe2\x80\x83', '界'.encode(), '😀'.encode(), b'\xe2\x82', b'\xf4\x90\x80\x80']:
            for offset in [65520, 65533, 65534, 65535, 65536, 131071]:
                fixtures[f'edge-{seq.hex()}-{offset}'] = b'a'*offset+seq+b' b\n'
        rng = random.Random(731)
        fixtures['random-tokens'] = b''.join(rng.choice([b'a', b' ', b'\0', b'\xff', b'\t', b'\n', '界'.encode(), 'e\u0301'.encode(), b'\xe2\x80\x83']) for _ in range(20000))
        for name, data in fixtures.items():
            (root/name).write_bytes(data)
        options = ['-m', '-w', '-L', '-mw', '-mL', '-wL', '-lwcmL', '']

        def run(script, argv=(), loc='C.UTF-8', posix=False, stdin=None):
            env = {**os.environ, 'LC_ALL': loc, 'PATH': ''}
            env.pop('POSIXLY_CORRECT', None)
            if posix:
                env['POSIXLY_CORRECT'] = '1'
            # Load explicitly even when POSIXLY_CORRECT makes Bash ignore BASH_ENV.
            prefix = 'enable -f "$SOL_WC_MODULE" wc || exit; ' if env.get('SOL_WC_MODULE') else ''
            return subprocess.run([args.binary, '--noprofile', '--norc', '-c', prefix+'PATH=; '+script, '_', *argv],
                                  cwd=root, env=env, input=stdin, capture_output=True, timeout=30)

        for loc in ['C', 'C.UTF-8', 'en_US.utf8']:
            probe = run('[[ $(type -t wc) == builtin ]]', loc=loc)
            assert probe.returncode == 0 and not probe.stderr, probe
            for posix in [False, True]:
                for name, data in fixtures.items():
                    expected = counts(data, loc if loc == 'C' else 'UTF8', posix)
                    for opt in options:
                        # Alternate full/empty/different input without a subshell, including
                        # decoder EOF tails and every field-selection branch.
                        command = 'wc '+opt
                        proc = run(command+' < "$1"; a=$?; '+command+' < empty; b=$?; '+command+' < unicode; c=$?; '+command+' < "$1"; d=$?; ((a==0 && b==0 && c==0 && d==0))',
                                   [name], loc, posix)
                        want = [selected(expected, opt), selected(counts(b'', loc if loc == 'C' else 'UTF8', posix), opt),
                                selected(counts(fixtures['unicode'], loc if loc == 'C' else 'UTF8', posix), opt), selected(expected, opt)]
                        got = [[int(x) for x in line.split()] for line in proc.stdout.splitlines()]
                        assert proc.returncode == 0 and not proc.stderr and got == want, (loc, posix, name, opt, proc.returncode, got, want, proc.stderr)
                        checks += 4
            # Named multi-file totals sum counts but take the maximum width.
            names = ['unicode', 'bad-eof', 'binary-long', 'empty']
            cs = [counts(fixtures[n], loc if loc == 'C' else 'UTF8') for n in names]
            total = {k: (max(c[k] for c in cs) if k == 'L' else sum(c[k] for c in cs)) for k in 'lwmcL'}
            for opt in options:
                proc = run('wc '+opt+' "$@"', names, loc)
                rows = [line.split() for line in proc.stdout.splitlines()]
                assert proc.returncode == 0 and not proc.stderr, proc
                assert [[int(x) for x in r[:-1]] for r in rows] == [selected(c, opt) for c in cs+[total]], (loc, opt, rows)
                assert [r[-1].decode() for r in rows] == names+['total']
                checks += 1
                proc = run('wc '+opt, loc=loc, stdin=fixtures['unicode'])
                assert proc.returncode == 0 and not proc.stderr and [int(x) for x in proc.stdout.split()] == selected(cs[0], opt)
                checks += 1
                for name in ['edge-e7958c-65535', 'edge-e282-65535']:
                    proc = run('wc '+opt, loc=loc, stdin=fixtures[name])
                    expected = selected(counts(fixtures[name], loc if loc == 'C' else 'UTF8'), opt)
                    assert proc.returncode == 0 and not proc.stderr and [int(x) for x in proc.stdout.split()] == expected, proc
                    checks += 1
            # Changing locale and options in one persistent shell must not cache either.
            proc = run('LC_ALL=C; wc -m < unicode; LC_ALL=C.UTF-8; wc -m < unicode; LC_ALL=C; wc -m < unicode')
            assert proc.returncode == 0 and [int(x) for x in proc.stdout.split()] == [len(fixtures['unicode']), len(fixtures['unicode'].decode()), len(fixtures['unicode'])]
            checks += 1
            proc = run('IFS= read -r line; wc -m', loc=loc, stdin=b'first\n'+fixtures['unicode'])
            assert proc.returncode == 0 and not proc.stderr and int(proc.stdout) == cs[0]['m'], proc
            checks += 1
            proc = run('wc -m - - < unicode', loc=loc)
            assert proc.returncode == 0 and not proc.stderr and [int(r.split()[0]) for r in proc.stdout.splitlines()] == [cs[0]['m'], 0, cs[0]['m']], proc
            checks += 1

        # FD cleanup and read errors, then successful recovery of stdin/stdout.
        proc = run('before=(/proc/$$/fd/*); for ((i=0;i<200;i++)); do wc -m unicode >/dev/null || exit; done; after=(/proc/$$/fd/*); ((${#before[@]}==${#after[@]}))')
        assert proc.returncode == 0 and not proc.stderr, proc
        checks += 1
        for opt in options:
            for script in ['wc '+opt+' missing', 'wc '+opt+' < .', 'wc '+opt+' <&-']:
                proc = run(script)
                assert proc.returncode != 0 and proc.stderr, (script, proc)
                checks += 1
        for opt in ['--bad', '-z', '--files0-from']:
            proc = run('wc "$1"', [opt])
            assert proc.returncode != 0 and proc.stderr, proc
            checks += 1
        for opt in options:
            proc = run('wc '+opt+' unicode > /dev/full; s=$?; wc -m < ascii; ((s!=0))')
            assert proc.returncode == 0 and b'write error' in proc.stderr and int(proc.stdout) == len(fixtures['ascii']), proc
            checks += 1
        # NUL list handling includes empty lists, a final unterminated name and
        # exact allocation boundaries. These execute the production parser.
        for data in [b'', b'unicode', b'unicode\0bad-eof\0', b'empty\0'*42+b'abcd']:
            (root/'list').write_bytes(data)
            proc = run('wc -m --files0-from=list')
            assert proc.returncode == 0 and not proc.stderr, proc
            names = [x.decode() for x in data.split(b'\0') if x]
            expected_rows = [[str(counts(fixtures[n], 'UTF8')['m']).encode(), n.encode()] for n in names]
            if len(names) > 1:
                expected_rows.append([str(sum(counts(fixtures[n], 'UTF8')['m'] for n in names)).encode(), b'total'])
            assert [line.split() for line in proc.stdout.splitlines()] == expected_rows, proc
            checks += 1
        for data in [b'\0', b'unicode\0\0']:
            (root/'list').write_bytes(data)
            proc = run('wc -m --files0-from=list')
            assert proc.returncode != 0 and b'zero-length' in proc.stderr, proc
            checks += 1
        print(f'sol-wc-check: {checks} assertions passed; C/C.UTF-8/en_US.utf8; empty PATH')


if __name__ == '__main__':
    main()
