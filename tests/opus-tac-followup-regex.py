#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""GNU tac regex parity: random Emacs-syntax patterns, window geometry,
UTF-8 locale, bounded memory and option parsing, byte-compared with GNU."""
import argparse
import os
from pathlib import Path
import random
import resource
import subprocess
import tempfile

REFERENCE = '/usr/bin/tac'


ANCHORS = ['^', '$', '\\`', "\\'", '\\<', '\\>', '\\b', '\\B']


def pattern(rng, depth=0):
    """A random GNU Emacs regex, including context-dependent characters.

    Returns (text, expanded, flagged). EXPANDED spells every repeated group
    X+ as XX*, the same language. glibc duplicates the tree for X+ and then
    mis-evaluates anchors inside the copy; FLAGGED marks a '+' applied to a
    group that may contain an anchor, where GNU can contradict EXPANDED."""
    def atom():
        r = rng.random()
        if r < .32:
            return rng.choice('ab,: x_Z0.'), None
        if r < .40:
            return '\\' + rng.choice('.*[]^$\\+?{}|()n'), None
        if r < .52:
            parts = [rng.choice(['a', 'b', ',', ':', ' ', '_', 'x-z', 'a-c', 'c-a', '[',
                                 '[:alpha:', '.', '*', '\\', '0-9', '^', '|'])
                     for _ in range(rng.randrange(1, 4))]
            head = rng.choice(['', '', '^', ']', '-', '^]', '^-'])
            tail = rng.choice(['', '', '', '-'])
            return '[' + head + ''.join(parts) + tail + ']', None
        if r < .60:
            return '\\' + rng.choice('wWsS'), None
        if r < .72:
            return rng.choice(ANCHORS), 'anchor'
        if r < .82 and depth < 3:
            inner = pattern(rng, depth + 1)
            return '\\(' + inner[0] + '\\)', ('\\(' + inner[1] + '\\)', inner[2], inner[3])
        if r < .86:
            return rng.choice('|(){}'), None
        return rng.choice(['ab', 'x', ':', '\n']), None

    branches, expanded = [], []
    flagged = anchored = False
    for _ in range(rng.choice([1, 1, 1, 2, 3])):
        items, xitems = [], []
        for _ in range(rng.randrange(0 if depth else 1, 4)):
            text, info = atom()
            ops = rng.choice(['*', '+', '?', '*', '**', '+?']) if rng.random() < .35 else ''
            xtext = text
            if info == 'anchor':
                anchored = True
            elif info:
                xtext, inner_flagged, inner_anchored = info
                flagged |= inner_flagged
                anchored |= inner_anchored
                state = 'atom'
                for op in ops:
                    unit = xtext if state == 'atom' else '\\(' + xtext + '\\)'
                    if op == '+':
                        xtext, state = unit + unit + '*', 'concat'
                        flagged |= inner_anchored
                    else:
                        xtext = (xtext if state != 'concat' else unit) + op
                        state = 'chain'
                ops_x = ''
            if not info or info == 'anchor':
                ops_x = ops
            items.append(text + ops)
            xitems.append(xtext + ops_x)
        if rng.random() < .05:
            lead = rng.choice('*+?')
            items.insert(0, lead)
            xitems.insert(0, lead)
        branches.append(''.join(items))
        expanded.append(''.join(xitems))
    if depth:
        return '\\|'.join(branches), '\\|'.join(expanded), flagged, anchored
    return '\\|'.join(branches), '\\|'.join(expanded), flagged


def gnu_literal(files, sep, before, stale=True):
    """Transcription of GNU tac 9.7 tac_seekable for a literal separator,
    including its reused buffer, assuming fresh heap memory reads as zero.
    GNU's search may compare the separator's tail with bytes beyond the
    unprinted record: leftovers of earlier reads or of a previous file.
    GNU also aborts ("memory exhausted", status 1, losing its unwritten
    output block) when a file shrank the window and a later file doubles it
    to a buffer smaller than before. Returns (output, status).
    stale=False models the builtin: real record bytes only and no abort."""
    slen = len(sep) or 1
    sepb = sep or b'\0'
    rs = 8192
    while slen >= rs // 2:
        rs *= 2
    mem = bytearray(2 * (rs + slen + 1))
    size = len(mem)
    mem[0:slen + (1 if sep else 0)] = sepb + (b'\0' if sep else b'')
    G = slen
    out = bytearray()
    for data in files:
        file_pos = len(data) - len(data) % rs
        chunk = data[file_pos:file_pos + rs]
        while not chunk and file_pos:
            file_pos -= rs
            chunk = data[file_pos:file_pos + rs]
        mem[G:G + len(chunk)] = chunk
        past = G + len(chunk)
        ms = past - (slen - 1)
        first = True
        while True:
            while True:
                ms -= 1
                if mem[ms] == sepb[0] and (slen == 1 or mem[ms + 1:ms + slen] == sepb[1:]) \
                        and (stale or ms < G or ms + slen <= past):
                    break
            if ms < G:
                if file_pos == 0:
                    out += mem[G:past]
                    break
                saved = past - G
                if saved > rs:
                    rs *= 2
                    if rs * 2 + slen + 2 < size and stale:
                        return bytes(out[:len(out) - len(out) % 8192]), 1
                    size = rs * 2 + slen + 2
                    if size > len(mem):
                        mem.extend(bytes(size - len(mem)))
                if file_pos >= rs:
                    file_pos -= rs
                else:
                    rs, file_pos = file_pos, 0
                mem[G + rs:G + rs + saved] = mem[G:G + saved]
                past = G + rs + saved
                ms = G + rs
                mem[G:G + rs] = data[file_pos:file_pos + rs]
            else:
                if not before:
                    end = ms + slen
                    if not first or end != past:
                        out += mem[end:past]
                    past, first = end, False
                else:
                    out += mem[ms:past]
                    past = ms
                ms -= slen - 1
    return bytes(out), 0


UNSUPPORTED = b'requires the GNU regex API'


def needs_glibc(text):
    """Collating or equivalence elements, "---" in a bracket, or a
    back-reference: constructs only the glibc matcher implements."""
    i = 0
    while i < len(text):
        if text[i] == '\\':
            if text[i + 1:i + 2] in list('123456789'):
                return True
            i += 2
            continue
        if text[i] == '[':
            j = i + 1
            if text[j:j + 1] == '^':
                j += 1
            if text[j:j + 1] == ']':
                j += 1
            while j < len(text) and text[j] != ']':
                if text[j:j + 2] in ('[.', '[=') or text[j:j + 3] == '---':
                    return True
                j += 1
            i = j
        i += 1
    return False


def data(rng):
    alphabet = rng.choice([b'ab\n,: x_Z0', b'ab\n\0\xff:', b'aaab', b'ab \n.Z_0,:'])
    kind = rng.random()
    if kind < .80:
        return bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 160)))
    # Sparse bytes around GNU's 8192-byte windows and their doubling.
    size = rng.choice([8191, 8192, 8193, 16383, 16385, 20000, 24577, 40000])
    out = bytearray(rng.choice([b'c', b'q']) * size)
    for _ in range(rng.randrange(1, 10)):
        at = rng.choice([8190, 8191, 8192, 8193, 16384, 16383, rng.randrange(size)])
        if at < size:
            piece = bytes(rng.choice(alphabet) for _ in range(rng.randrange(1, 5)))
            out[at:at + len(piece)] = piece[:size - at]
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=lambda s: str(Path(s).resolve()))
    ap.add_argument('--module', help='Optional replacement for sanitizer runs')
    ap.add_argument('--cases', type=int, default=4000)
    ap.add_argument('--literal-cases', type=int, default=600)
    ap.add_argument('--emulated', action='store_true',
                    help='qemu-user needs more address space than the memory checks allow')
    ap.add_argument('--portable', action='store_true',
                    help='Build without the GNU regex API: glibc-only constructs must fail')
    ap.add_argument('--seed', type=int, default=20261020)
    args = ap.parse_args()
    env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
    for name in ['POSIXLY_CORRECT', 'LANG', 'LANGUAGE']:
        env.pop(name, None)
    prefix = 'enable -f "$TAC_MODULE" tac || exit; ' if args.module else ''
    if args.module:
        env['TAC_MODULE'] = str(Path(args.module).resolve())
    checks = 0

    def run(command, options, stdin=None, script='"$@"', environment=None, timeout=300, **kw):
        p = subprocess.run([args.binary, '--noprofile', '--norc', '-c', prefix + script,
                            '_', command, *options], input=stdin,
                           env=environment or env, capture_output=True, timeout=timeout, **kw)
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        return p

    with tempfile.TemporaryDirectory(prefix='opus-tac-') as directory:
        root = Path(directory)
        env['TMPDIR'] = str(root / 'spools')
        Path(env['TMPDIR']).mkdir()

        unsupported = 0

        def compare(options, payload, mode='file', environment=None, label='', glibc=False):
            nonlocal checks, unsupported
            source = root / 'input'
            source.write_bytes(payload)
            opts = [*options, str(source)] if mode == 'file' else list(options)
            stdin = payload if mode == 'pipe' else None
            got = run('tac', opts, stdin, environment=environment)
            if args.portable and glibc:
                assert got.returncode == 1 and not got.stdout and UNSUPPORTED in got.stderr, (
                    label, options, got.returncode, got.stderr)
                unsupported += 1
                checks += 1
                return
            ref = run(REFERENCE, opts, stdin, environment=environment)
            assert (got.returncode, got.stdout) == (ref.returncode, ref.stdout), (
                label, options, mode, len(payload), payload[:60], got.returncode,
                ref.returncode, got.stdout[:120], ref.stdout[:120], got.stderr)
            assert not list(Path(env['TMPDIR']).iterdir())
            checks += 1

        # 1. Random patterns. File cases run in one persistent shell per
        # implementation (state carries across calls); pipe cases run alone.
        # The oracle is GNU on the pattern, or on its XX* spelling when a
        # group is repeated with '+'. GNU may disagree with itself on such a
        # pair only when an anchor is inside the repeated group (a glibc
        # defect); every other disagreement fails.
        rng = random.Random(args.seed)
        cases = []
        for i in range(args.cases):
            text, expanded, flagged = pattern(rng)
            before = [] if rng.random() < .6 else ['-b']
            cases.append(([*before, '-r', '-s', text], [*before, '-r', '-s', expanded],
                          flagged, data(rng)))
        work = root / 'cases'
        work.mkdir()
        for i, (options, xoptions, flagged, payload) in enumerate(cases):
            (work / f'{i}.in').write_bytes(payload)
            (work / f'{i}.args').write_bytes(b''.join(o.encode() + b'\0' for o in options))
            (work / f'{i}.xargs').write_bytes(b''.join(o.encode() + b'\0' for o in xoptions))
        # glibc's register backtracking can take exponential time on some
        # nested nullable groups; such reference runs have no oracle and are
        # reported, never counted as passes.
        loop = '''tag=$1; dir=$2; n=$3; args=args
if [[ $tag == got ]]; then cmd=(tac); else cmd=(/usr/bin/timeout -s KILL 10 /usr/bin/tac); fi
[[ $tag == xref ]] && args=xargs
for ((i=0;i<n;i++)); do
  mapfile -d '' -t a < "$dir/$i.$args"
  "${cmd[@]}" "${a[@]}" "$dir/$i.in" > "$dir/$i.$tag" 2> "$dir/$i.$tag.err"
  printf '%s\\n' "$?" > "$dir/$i.$tag.rc"
done
'''
        for tag in ['got', 'ref', 'xref']:
            p = run(tag, [str(work), str(len(cases))], script=loop, timeout=None)
            assert p.returncode == 0, p.stderr
        accepted = timeouts = defects = 0
        valid = []
        for i, (options, xoptions, flagged, payload) in enumerate(cases):
            def result(tag):
                return (work / f'{i}.{tag}').read_bytes(), (work / f'{i}.{tag}.rc').read_text()
            got, ref, xref = result('got'), result('ref'), result('xref')
            oracle = xref if xoptions != options else ref
            if args.portable and needs_glibc(options[-1]) and got[1].strip() == '1' \
                    and UNSUPPORTED in (work / f'{i}.got.err').read_bytes():
                unsupported += 1
                checks += 1
                continue
            if oracle[1].strip() == '137':
                timeouts += 1
                print('NO ORACLE (GNU timed out):', options, len(payload))
                continue
            assert got == oracle, ('random', i, options, xoptions, payload[:80], got[1],
                                   oracle[1], got[0][:120], oracle[0][:120])
            if got != ref:
                assert flagged, ('GNU disagrees with its own XX* spelling', options, payload[:80])
                defects += 1
            accepted += oracle[1].strip() == '0'
            if xoptions == options:
                valid.append((options, payload))
            checks += 1
        assert accepted > len(cases) * 3 // 4 and timeouts * 100 < len(cases), (accepted, timeouts)
        print(f'opus-tac-followup: {defects} random cases where GNU contradicts its XX* spelling')
        for options, payload in valid[:400]:
            compare(options, payload, 'pipe', label='random-pipe', glibc=needs_glibc(options[-1]))

        # The minimized glibc defects: X+ is X X* by definition; GNU agrees
        # with the builtin on the spelled-out form only.
        for text, expanded, payload in [
                ("\\(\\|\\'b\\)+", "\\(\\|\\'b\\)\\(\\|\\'b\\)*", b'.b'),
                ('\\(\\>**\\|\n\\)+', '\\(\\>**\\|\n\\)\\(\\>**\\|\n\\)*', b'\n\xff'),
                ('\\(\\`+?\\|\\s\\)+', '\\(\\`+?\\|\\s\\)\\(\\`+?\\|\\s\\)*', b'\n\n:')]:
            for before in [[], ['-b']]:
                source = root / 'input'
                source.write_bytes(payload)
                got = run('tac', [*before, '-r', '-s', text, str(source)])
                ref = run(REFERENCE, [*before, '-r', '-s', expanded, str(source)])
                assert (got.returncode, got.stdout) == (ref.returncode, ref.stdout), (text, before)
                checks += 1
            contradiction = run(REFERENCE, ['-r', '-s', text, str(source)])
            assert contradiction.stdout != ref.stdout or before, text  # still a GNU defect

        # 2. Directed cases: GNU's regex windows differ from its literal
        # scanner, so a metacharacter-free -r separator must not reuse it.
        window = bytearray(b'c' * 20000)
        window[8191:8194] = b'aaa'
        for options in [['-r', '-s', 'aa'], ['-b', '-r', '-s', 'aa'], ['-r', '-s', 'a\\{0\\}a'],
                        ['-r', '-s', 'ca'], ['-r', '-s', 'a*'], ['-r', '-s', '^c'],
                        ['-r', '-s', '\\`c'], ['-b', '-r', '-s', '\\`c'], ['-r', '-s', 'c\\B'],
                        ['-r', '-s', 'c$'], ['-r', '-s', "c\\'"]]:
            for mode in ['file', 'pipe']:
                compare(options, bytes(window), mode, label='window')
        for payload in [b'a,b::c', b'a\nb\0c\n\xfftail', b'::x,,y:', b'\0\0\n', b'']:
            for options in [['-r', '-s', '[,:]+'], ['-r', '-s', '.'], ['-r', '-s', '.+'],
                            ['-r', '-s', 'x.y'], ['-r', '-s', '.\\|\n'], ['-b', '-r', '-s', '..']]:
                compare(options, payload, label='dot')
        # Grown windows carry their size into the next file.
        grown, follow = root / 'grown', root / 'follow'
        grown.write_bytes(b'c' * 50000)
        follow.write_bytes(bytes(window))
        for options in [['-r', '-s', 'aa'], ['-r', '-s', '^c\\|aa'], ['-b', '-r', '-s', 'a\\(a\\)']]:
            got = run('tac', [*options, str(grown), str(follow)])
            ref = run(REFERENCE, [*options, str(grown), str(follow)])
            assert (got.returncode, got.stdout) == (ref.returncode, ref.stdout), options
            checks += 1
        # Back-references and other glibc-only constructs (fallback path).
        for options in [['-r', '-s', '\\(a\\)\\1'], ['-r', '-s', '\\(ab*\\)c\\1'],
                        ['-b', '-r', '-s', '\\([,:]\\)\\1'], ['-r', '-s', '[[.a.]]'],
                        ['-r', '-s', '[[=a=]b]'], ['-r', '-s', '[a---]']]:
            for payload in [b'aab::,,cabbcab', bytes(window), b'a' * 9000 + b',,' + b'b' * 9000]:
                for mode in ['file', 'pipe']:
                    compare(options, payload, mode, label='fallback', glibc=True)
        # Invalid expressions fail before reading input, as GNU's do.
        for text in ['[', '[a', '\\(', '\\)', 'a\\', '\\1', '\\(a\\)\\2', '[b-a-c]', '[[.ab.]]',
                     '\\(a\\)\\|\\1', '[]', '[^]', '[[=]']:
            got, ref = run('tac', ['-r', '-s', text], b'x'), run(REFERENCE, ['-r', '-s', text], b'x')
            assert (got.returncode, got.stdout) == (ref.returncode, ref.stdout) and got.returncode, (
                text, got.returncode, ref.returncode, got.stdout, ref.stdout)
            checks += 1

        # Literal separators: the transcribed GNU algorithm must reproduce
        # GNU, and the builtin must equal it with only real record bytes and
        # no spurious abort. Only then may the two differ.
        lrng = random.Random(args.seed + 1)
        literal_defects = {'stale': 0, 'abort': 0}
        for _ in range(args.literal_cases):
            sep = lrng.choice([b'aa', b'ab', b'aba', b'aaa', b'abab', b'::', b'\n', b'', b'xyx'])
            files = []
            for _ in range(lrng.choice([1, 1, 2, 3])):
                size = lrng.choice([0, 5, 8191, 8192, 8193, 16384, 16385, 20000, 40000,
                                    lrng.randrange(100)])
                body = bytearray(lrng.choice([b'c', b'a']) * size)
                for _ in range(lrng.randrange(0, 8)):
                    at = lrng.choice([8190, 8191, 8192, 8193, 16383, 16384, 16385,
                                      lrng.randrange(size + 1)])
                    piece = bytes(lrng.choice(b'abxy:c\n') for _ in range(lrng.randrange(1, 5)))
                    body[at:at + len(piece)] = piece
                files.append(bytes(body))
            before = lrng.random() < .5
            names = []
            for k, body in enumerate(files):
                names.append(str(root / f'literal{k}'))
                Path(names[-1]).write_bytes(body)
            options = (['-b'] if before else []) + ['-s', sep.decode()]
            got, ref = run('tac', [*options, *names]), run(REFERENCE, [*options, *names])
            modeled, actual = gnu_literal(files, sep, before), gnu_literal(files, sep, before, False)
            assert (ref.stdout, ref.returncode) == modeled, ('GNU model', options, [len(f) for f in files])
            assert (got.stdout, got.returncode) == actual, ('builtin', options, [len(f) for f in files])
            if modeled != actual:
                literal_defects['abort' if modeled[1] else 'stale'] += 1
            checks += 1
        # Pinned instances of both GNU defects.
        stale = bytearray(b'c' * 40000)
        stale[8191:8194] = b'aab'
        stale[16384] = ord('b')
        source = root / 'input'
        source.write_bytes(bytes(stale))
        got, ref = run('tac', ['-b', '-s', 'ab', str(source)]), run(REFERENCE, ['-b', '-s', 'ab', str(source)])
        assert (ref.stdout, ref.returncode) == gnu_literal([bytes(stale)], b'ab', True), 'stale model'
        assert (got.stdout, got.returncode) == gnu_literal([bytes(stale)], b'ab', True, False)
        assert got.stdout != ref.stdout     # GNU compared a byte 8192 positions away.
        checks += 1
        source.write_bytes(b'c' * 40000)
        for options in [['-s', ''], ['-r', '-s', 'x\\|y']]:
            got = run('tac', [*options, str(source), str(source)])
            ref = run(REFERENCE, [*options, str(source), str(source)])
            assert ref.returncode == 1 and b'memory exhausted' in ref.stderr, ref
            assert (got.returncode, got.stdout) == (0, b'c' * 80000), got.returncode
            checks += 1

        # 3. UTF-8: ASCII and whole-character literal separators use the
        # bounded matcher; other constructs fall back to glibc.
        utf8 = dict(env, LC_ALL='C.UTF-8')
        samples = ['é,b::c\n界', 'aébééc', b'\xc3a\xa9\xe2\x82,x'.decode('latin-1'),
                   ('x' * 8190 + 'éé' + 'y' * 9000)]
        for text in ['[,:]+', ',\\|::', 'é', 'é+', '\\(é\\|b\\)', '.', 'é*', '[é]', '\\w',
                     '\\bb', '^', 'b$', '[^,]', 'x界', 'é\\{2\\}']:
            for sample in samples:
                payload = sample.encode('latin-1') if sample.startswith('\xc3') else sample.encode()
                for before in [[], ['-b']]:
                    compare([*before, '-r', '-s', text], payload, environment=utf8, label='utf8',
                            glibc=text in ['.', 'é*', '[é]', '\\w', '\\bb', '^', '[^,]'])
        for sample in samples[:2]:
            compare(['-r', '-s', 'é'], sample.encode(), 'pipe', environment=utf8, label='utf8')

        # 4. Bounded memory: a 48 MiB record never fits under a 32 MiB address
        # space limit, so a buffering matcher would fail. GNU's output is
        # computed without the limit as an independent oracle.
        if args.emulated:
            print('SKIP address-space checks: qemu-user reserves a 128 MiB JIT buffer')
        if not args.module and not args.emulated:
            big = root / 'big'
            big.write_bytes(b'BEGIN' + b'A' * (48 * 1024 * 1024) + b'\nB\n::xyz')
            def limit_memory():
                resource.setrlimit(resource.RLIMIT_AS, (32 * 1024 * 1024,) * 2)
            for text in ['BEGIN.*END', 'x\\(y\\|q\\)z', '^B$', '::\\w+', 'A\\>', '\\`BEGIN',
                         '[:,]\\{2\\}', '\\(A\\|B\\)\\(B\\|\n\\)', 'Q*::', "z\\'"]:
                for before in [[], ['-b']]:
                    options = [*before, '-r', '-s', text]
                    expected = run(REFERENCE, [*options, str(big)])
                    assert expected.returncode == 0, text
                    actual = run('tac', [*options, str(big)], preexec_fn=limit_memory)
                    assert (actual.returncode, actual.stdout) == (0, expected.stdout), (
                        text, actual.returncode, actual.stderr)
                    checks += 1
            options = ['-r', '-s', 'BEGIN.*END']
            expected = run(REFERENCE, [*options, str(big)])
            actual = run('tac', options, big.read_bytes(), preexec_fn=limit_memory)
            assert (actual.returncode, actual.stdout) == (0, expected.stdout), actual.stderr
            assert not list(Path(env['TMPDIR']).iterdir())
            checks += 1
            big.unlink()

        # 5. GNU getopt: clustering, abbreviations, permutation, errors.
        source = root / 'input'
        source.write_bytes(b'a:b,c\nd:e\n')
        option_sets = [['-br'], ['-rb', '-s:'], ['-brs', ':'], ['-brs:'], ['-bs', ','],
                       ['--b', '--r', '--s', ':'], ['--bef', '--reg', '--sep=:'],
                       ['--separator', ','], ['--s='], ['-s', ':', 'FILE', '-b'],
                       ['FILE', '--regex', '-s[,:]'], ['--', '-b'], ['-x'], ['--bogus'],
                       ['--before=x'], ['--sep'], ['-s'], ['-bx'], ['--rege=1'], ['--', '--', 'FILE']]
        for options in option_sets:
            for posix in [False, True]:
                opts = [str(source) if o == 'FILE' else o for o in options]
                if 'FILE' not in options and options[-1:] != ['-s'] and options[-1:] != ['--sep']:
                    opts.append(str(source))
                environment = dict(env, POSIXLY_CORRECT='1') if posix else None
                got = run('tac', opts, b'', environment=environment)
                ref = run(REFERENCE, opts, b'', environment=environment)
                assert (got.returncode, got.stdout) == (ref.returncode, ref.stdout), (
                    options, posix, got.returncode, ref.returncode, got.stdout, ref.stdout, got.stderr)
                checks += 1
    print(f'opus-tac-followup: {unsupported} glibc-only cases checked for the explicit portable error')
    print(f'opus-tac-followup: literal GNU defects reproduced by the model: {literal_defects}')
    print(f'opus-tac-followup: {timeouts} random cases without a GNU oracle (reference timeout)')
    print(f'opus-tac-followup: {checks} GNU regex, window, UTF-8, memory and option checks passed')


if __name__ == '__main__':
    main()
