#!/usr/bin/env python3
"""Focused GNU parity and persistent-shell checks; does not compile anything."""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def normalize(err):
    return re.sub(rb'^.*?: line [0-9]+: ', b'', err, flags=re.M).replace(b'/usr/bin/grep:', b'grep:')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('binary')
    p.add_argument('--impl', help='standalone sanitizer harness (single-call checks only)')
    a = p.parse_args()
    binary = str(Path(a.binary).resolve())
    total = 0
    with tempfile.TemporaryDirectory(prefix='sol-grep-check-') as td:
        root = Path(td)
        data = (b'foo\nfoobar foo\nbar\na-a-a\naa\na\nab\n@\n\n'
                + 'éa aé ١\nſ K\n'.encode() + b'end')
        (root/'text').write_bytes(data)
        (root/'binary').write_bytes(b'foo\0bar\na\xffb\nfoo after\n')
        (root/'nul').write_bytes(b'a\nb\0aa\0ab\0foo\0bar\0')
        (root/'invalid').write_bytes(b'a\xffb\nfoo\n')
        (root/'patterns').write_bytes(b'foo\nbar\n')
        (root/'nul-pattern').write_bytes(b'foo\0bar\n')
        (root/'no-newline').write_bytes(b'foo')
        (root/'long').write_bytes(b'begin\n'+b'x'*300000+b'foo123\nend\n')
        (root/'straddle').write_bytes(b'x'*98302+b'foo123\nend\n')
        (root/'empty').touch()
        (root/'final-newline').write_bytes(b'a\n\0\n\0')
        (root/'explicit-utf').write_bytes('éa'.encode()+b'\xffa\0')
        def run(script, locale, impl=False):
            env = dict(os.environ, LC_ALL=locale, PATH='' if impl else '/usr/bin:/bin',
                       ASAN_OPTIONS='detect_leaks=1:exitcode=99', UBSAN_OPTIONS='halt_on_error=1:exitcode=99')
            prefix = ''
            if impl and a.impl:
                prefix = 'grep() { '+shlex.quote(str(Path(a.impl).resolve()))+' "$@"; }; '
            return subprocess.run([binary if impl and not a.impl else '/bin/bash', '-c', prefix+script],
                                  cwd=td, env=env, capture_output=True)
        def parity(script, locale='C', diagnostic=True):
            nonlocal total
            g, b = run(script, locale), run(script, locale, True)
            assert (g.returncode, g.stdout) == (b.returncode, b.stdout), (locale, script, g, b)
            if diagnostic:
                assert normalize(g.stderr) == normalize(b.stderr), (locale, script, g.stderr, b.stderr)
            else:
                assert bool(g.stderr) == bool(b.stderr), (script, g.stderr, b.stderr)
            total += 1
        for locale in ['C', 'C.UTF-8']:
            for dialect, pattern in [('-G', r'\(foo\|bar\)'), ('-E', '(foo|bar)'),
                                     ('-F', 'foo'), ('-P', r'foo|(?<=^)bar')]:
                for opts in ['', '-c', '-o', '-n -b', '-w', '-x', '-v -c', '-m1 -C1', '-q', '-l', '-L']:
                    parity(f'grep {dialect} {opts} {shlex.quote(pattern)} text', locale)
                for opts in ['', '-a', '-a -o', '-I', '-c', '-n -C1']:
                    parity(f'grep {dialect} {opts} foo binary', locale)
                parity(f'grep {dialect} -z -n -C1 a nul', locale)
            for opts, pattern in [('-o', r'(?<=foo)bar'), ('-o', r'(a)\1'), ('-x', r'(a)\1'),
                                  ('-xo', r'a\Ka'), ('-w', 'a|ab'), ('-wo', 'a|ab'),
                                  ('-wo', '@'), ('-wo', 'a.*'), ('-o', r'\w+'), ('-o', r'\d+'),
                                  ('-o', r'\p{L}+'), ('-io', 's|k'), ('-o', '(?:|é)'),
                                  ('-x', '(*UTF)a'), ('', '(?x)foo # comment'),
                                  ('-zo', '(?s)a.b'), ('-zx', '(?s)a.b'),
                                  ('-zo', '^a|b$'), ('-zwo', 'a|ab')]:
                parity(f'grep -P {opts} {shlex.quote(pattern)} '+('nul' if 'z' in opts else 'text'), locale)
            for opts in ['', '-a', '-o', '-ao', '-c']:
                parity(f'grep -P {opts} . invalid', locale)
            for pattern in ['a$', '^$', '(?m)a$', '(?m)^$']:
                parity('grep -Pzo '+shlex.quote(pattern)+' final-newline', locale)
            for pattern in ['(*UTF)a', '(*UTF)(?:|a)', '(*UTF).*?']:
                # GNU can report BADUTFOFFSET for empty (*UTF) matches in C;
                # require exact bytes/status and a diagnostic, not its wording.
                parity('grep -Pzao '+shlex.quote(pattern)+' explicit-utf', locale, diagnostic=False)
            parity("grep -P -ao 'foo.bar' binary", locale)
            parity("grep -P -ao '.' binary", locale)
            for fixture in ['long', 'straddle']:
                parity(f"grep -P -nob '(?<=x)foo[0-9]+$' {fixture}", locale)
                parity(f"grep -P -m1 -A1 -n '(?<=x)foo[0-9]+$' {fixture}", locale)
            for dialect in ['-G', '-E', '-P']:
                parity(f'grep {dialect} "[" text', locale, diagnostic=False)
            for pattern in ['(*UTF)a', '(?x)a # comment']:
                parity(f'grep -Pw {shlex.quote(pattern)} text', locale, diagnostic=False)
            parity('grep -P -e foo -e bar text', locale)
            parity('grep -P -f patterns text', locale)
            parity('grep -P -f empty text', locale)
            for dialect in ['-F', '-P']:
                parity(f'grep {dialect} -a -f nul-pattern binary', locale)
            for script in ['grep -P -f missing text', 'grep -P -f . text',
                           'grep -P foo missing text', 'grep -P -q foo missing text',
                           'grep -P -m0 "[" text', 'grep -P "(?x)foo # comment" text']:
                parity(script, locale)
        if not a.impl:
            # These run multiple calls in one shell; fresh standalone processes
            # cannot demonstrate persistent state or descriptor cleanup.
            for dialect in ['-G', '-E', '-F', '-P']:
                parity(f'{{ grep {dialect} -m1 -b .; grep {dialect} -m1 -b .; grep {dialect} -m1 -b .; }} < text')
                parity(f'grep {dialect} -m1 -b . - - - < text')
                parity(f'{{ grep {dialect} -m1 -A1 .; grep {dialect} -m1 -A1 .; }} < text')
                parity(f'for ((i=0;i<30;i++)); do grep {dialect} -c foo < text; done')
                parity(f'grep {dialect} -c foo text >/dev/full; printf "status=%s\\n" "$?"; grep {dialect} -c foo text')
                parity(f'grep {dialect} -f - text < patterns; grep {dialect} -f - text < patterns')
                parity(f'{{ grep {dialect} -m1 .; grep {dialect} -m1 .; }} < no-newline')
            parity('for ((i=0;i<50;i++)); do grep -P "[" text 2>/dev/null; grep -P -c foo text; done')
            # Inspect only this shell's own descriptors before/after calls.
            script = ('before=(/proc/$$/fd/*); for ((i=0;i<200;i++)); do '
                      'grep -P -q foo text || exit 3; grep -P "[" text 2>/dev/null; '
                      'done; after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]')
            assert run(script, 'C', True).returncode == 0
            total += 1
        # Backtracking limits are a documented native error, never a no-match.
        (root/'hard').write_bytes(b'a'*100+b'!\n')
        r = run("BASHPCRE_MATCH_LIMIT=1 grep -P '(*NO_START_OPT)(*NO_AUTO_POSSESS)(a+)+$' hard", 'C', True)
        assert r.returncode == 2 and b'PCRE match error' in r.stderr, r
        total += 1
    print(f'sol-grep-check: {total} passed (GNU stdout/status parity plus native error/state checks)')


if __name__ == '__main__':
    main()
